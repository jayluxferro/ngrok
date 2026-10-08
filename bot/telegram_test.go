package bot

// Telegram client tests (SPEC-CLUSTER20 testing strategy), against a fake
// Bot API. The headline pin is the last one: every captured sendMessage
// payload must be bare {chat_id, text} -- the whole markup-injection class
// is deleted by that absence, so the test is the gate made executable.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeTelegram records every call and answers getUpdates from a scripted
// queue. It is the unit-test sibling of the e2e helper (workstream D).
type fakeTelegram struct {
	mu      sync.Mutex
	srv     *httptest.Server
	polls   []string // offset query param per getUpdates, in order
	sends   []string // sendMessage bodies, in order
	updates [][]byte // script: each poll consumes the next slice
	err     int      // remaining polls that answer with a refusal
}

func newFakeTelegram(t *testing.T) *fakeTelegram {
	f := &fakeTelegram{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		switch {
		case strings.HasSuffix(r.URL.Path, "/getUpdates"):
			f.polls = append(f.polls, r.URL.Query().Get("offset"))
			if f.err > 0 {
				f.err--
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprint(w, `{"ok":false,"description":"internal server error"}`)
				return
			}
			var body []byte
			if len(f.updates) > 0 {
				body = f.updates[0]
				f.updates = f.updates[1:]
			} else {
				// An empty poll is a valid empty result. Rendering the nil
				// slice here once emitted `{"ok":true,"result":}` --
				// malformed JSON the poller rightly treats as an error,
				// which made the backoff test's "successful" polls keep
				// failing and the recorded wait list grow without bound.
				body = []byte("[]")
			}
			fmt.Fprintf(w, `{"ok":true,"result":%s}`, string(body))
		case strings.HasSuffix(r.URL.Path, "/sendMessage"):
			raw, _ := io.ReadAll(r.Body)
			f.sends = append(f.sends, string(raw))
			fmt.Fprint(w, `{"ok":true,"result":{"message_id":1}}`)
		default:
			fmt.Fprint(w, `{"ok":true,"result":{}}`)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeTelegram) pollOffsets() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.polls...)
}

func (f *fakeTelegram) sentMessages() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.sends...)
}

func (f *fakeTelegram) queueUpdates(batch string) {
	f.mu.Lock()
	f.updates = append(f.updates, []byte(batch))
	f.mu.Unlock()
}

func (f *fakeTelegram) failNext(n int) {
	f.mu.Lock()
	f.err = n
	f.mu.Unlock()
}

func testTelegramClient(apiBase string) *telegramClient {
	cfg := &config{
		TelegramAPI:           apiBase,
		TelegramToken:         "111:test",
		CommandTimeoutSeconds: 5,
	}
	tg := newTelegramClient(cfg)
	// The stubbed clock: backoffs and pacings record and return at once.
	tg.wait = func(ctx context.Context, d time.Duration) error { return nil }
	return tg
}

func updateJSON(id int64, chat int64, text string) string {
	return fmt.Sprintf(`{"update_id":%d,"message":{"chat":{"id":%d},"text":%q}}`, id, chat, text)
}

func TestOffsetAdvancesPastAckedUpdates(t *testing.T) {
	fake := newFakeTelegram(t)
	fake.queueUpdates(`[` + updateJSON(11, 42, "/status") + `,` + updateJSON(12, 42, "hello") + `]`)
	// The second poll answers empty: the point is what offset it asks with.
	fake.queueUpdates(`[]`)

	tg := testTelegramClient(fake.srv.URL)
	ctx, cancel := context.WithCancel(context.Background())
	go tg.runUpdates(ctx, func(u telegramUpdate) {})

	deadline := time.After(2 * time.Second)
	for len(fake.pollOffsets()) < 2 {
		select {
		case <-deadline:
			t.Fatalf("only %d polls: %v", len(fake.pollOffsets()), fake.pollOffsets())
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()

	// The second poll must ask from update_id 13: everything before it --
	// including the ignored plain text -- was acked by processing (or by
	// deciding not to process), never re-fetched.
	offsets := fake.pollOffsets()
	if offsets[0] != "" {
		t.Errorf("first poll offset = %q, want empty (cold start)", offsets[0])
	}
	if offsets[1] != "13" {
		t.Errorf("second poll offset = %q, want 13", offsets[1])
	}
}

func TestPollBacksOffOnRefusals(t *testing.T) {
	fake := newFakeTelegram(t)
	fake.failNext(3)

	tg := testTelegramClient(fake.srv.URL)
	clock := &waitRecorder{}
	tg.wait = clock.stub

	ctx, cancel := context.WithCancel(context.Background())
	go tg.runUpdates(ctx, func(u telegramUpdate) {})

	deadline := time.After(2 * time.Second)
	for {
		waits := clock.all()
		if len(waits) >= 3 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("only %d backoffs in the window: %v", len(clock.all()), clock.all())
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()

	// Assert only the three waits the injected refusals produced. The
	// recorded list is read after cancel() with no handshake against the
	// poll goroutine, so it can keep growing under load -- and
	// time.Second<<i overflows int64 from i=34 on, which once turned a
	// late snapshot into a garbage expectation. Slicing to the waits the
	// test arranged keeps the assertion about the doubling, not about
	// scheduler timing.
	waits := clock.all()
	if len(waits) < 3 {
		t.Fatalf("only %d backoffs recorded: %v", len(waits), waits)
	}
	for i, d := range waits[:3] {
		want := time.Second << uint(i)
		if want > time.Minute {
			want = time.Minute
		}
		if d != want {
			t.Fatalf("backoff[%d] = %v, want %v (waits: %v)", i, d, want, waits)
		}
	}
}

func TestSendQueueDropsAndNotices(t *testing.T) {
	fake := newFakeTelegram(t)
	tg := testTelegramClient(fake.srv.URL)

	// Overflow the 256-slot queue from the caller side: every message past
	// the cap is a counted drop, never a blocked caller.
	for i := 0; i < sendQueueCap+44; i++ {
		tg.send(42, fmt.Sprintf("msg %d", i))
	}
	if got := tg.droppedFor(42); got != 44 {
		t.Fatalf("drops = %d, want 44", got)
	}

	// The notice interval is the stubbed clock: it fires immediately and
	// every time, so runNotices delivers as fast as the fake answers.
	tg.noticeWait = func(ctx context.Context) error { return nil }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { tg.runNotices(ctx); close(done) }()

	deadline := time.After(2 * time.Second)
	for len(fake.sentMessages()) == 0 {
		select {
		case <-deadline:
			t.Fatal("no drop notice was delivered")
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	<-done

	msgs := fake.sentMessages()
	// Exactly one notice: the counters were handed to the notice, so a
	// second pass has nothing to report.
	if len(msgs) != 1 {
		t.Fatalf("got %d notices (%v), want 1", len(msgs), msgs)
	}
	if !strings.Contains(msgs[0], "44 alerts dropped") {
		t.Errorf("notice %q does not carry the drop count", msgs[0])
	}
	if tg.droppedFor(42) != 0 {
		t.Errorf("drops after notice = %d, want 0 (the counter moved into the notice)", tg.droppedFor(42))
	}
}

func TestTruncateMessageShortTextPasses(t *testing.T) {
	text := "hello tunnels"
	if got := truncateMessage(text); got != text {
		t.Errorf("truncateMessage(%q) = %q; short text must pass through untouched", text, got)
	}
}

func TestTruncateMessageCutsAtWholeLine(t *testing.T) {
	// 60 lines of 90 chars: ~5.5 KB, comfortably past the cap.
	lines := make([]string, 60)
	for i := range lines {
		lines[i] = fmt.Sprintf("%04d %s", i, strings.Repeat("x", 85))
	}
	text := strings.Join(lines, "\n")

	got := truncateMessage(text)
	if n := len([]rune(got)); n > telegramTextCap {
		t.Fatalf("truncated message is %d runes, over the %d cap", n, telegramTextCap)
	}
	if !strings.HasSuffix(got, "lines cut)") {
		t.Fatalf("truncated message has no cut footer:\n%q", got[len(got)-80:])
	}

	// Whole-line cutting: every line present in the output (except the
	// footer) must be one of the input lines, verbatim and in order.
	gotLines := strings.Split(got, "\n")
	if len(gotLines) < 2 {
		t.Fatalf("truncated message has %d lines, want kept lines plus footer", len(gotLines))
	}
	footer := gotLines[len(gotLines)-1]
	for i, line := range gotLines[:len(gotLines)-1] {
		if line != lines[i] {
			t.Fatalf("line %d was not kept verbatim:\n%q\nwant\n%q", i, line, lines[i])
		}
	}
	// The footer counts honestly: cut = total lines - kept lines.
	cutStr := strings.TrimSuffix(strings.TrimPrefix(footer, "… (+"), " lines cut)")
	cut, err := strconv.Atoi(cutStr)
	if err != nil {
		t.Fatalf("unreadable footer %q: %v", footer, err)
	}
	if cut != len(lines)-(len(gotLines)-1) {
		t.Errorf("footer claims %d lines cut, want %d", cut, len(lines)-(len(gotLines)-1))
	}
}

func TestTruncateMessageSingleHugeLineHardCuts(t *testing.T) {
	text := strings.Repeat("y", telegramTextCap*3)
	got := truncateMessage(text)
	if len([]rune(got)) != telegramTextCap {
		t.Errorf("hard-cut message is %d runes, want exactly %d", len([]rune(got)), telegramTextCap)
	}
	if !strings.HasPrefix(text, got) {
		t.Errorf("hard cut is not a prefix of the input")
	}
}

// TestSendMessageNeverCarriesParseMode is the §6 pin: every captured
// sendMessage body -- alerts, notices, command replies -- is bare
// {chat_id, text}. No markup dialect is ever claimed, so no payload can
// smuggle one.
func TestSendMessageNeverCarriesParseMode(t *testing.T) {
	fake := newFakeTelegram(t)
	tg := testTelegramClient(fake.srv.URL)

	hostile := "tunnel: `x` _bold_ *star* [link](http://x) <b>html</b>"
	for _, chat := range []int64{1, 2} {
		tg.send(chat, "[ngrok] alert "+hostile)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for range []int{0, 1} {
		tg.deliver(ctx, <-tg.outbox)
	}

	msgs := fake.sentMessages()
	if len(msgs) != 2 {
		t.Fatalf("got %d sends, want 2", len(msgs))
	}
	for i, raw := range msgs {
		var body struct {
			ChatID int64  `json:"chat_id"`
			Text   string `json:"text"`
			// The markup field is deliberately absent from the sender; the test
			// reads the raw body for it by name so even a wrongly-typed variant
			// would trip the assertion.
		}
		if err := json.Unmarshal([]byte(raw), &body); err != nil {
			t.Fatalf("send %d is not JSON: %v (%q)", i, err, raw)
		}
		if strings.Contains(raw, "parse_mode") {
			t.Errorf("send %d carries parse_mode: %q -- plain text is the whole point", i, raw)
		}
		if body.Text != "[ngrok] alert "+hostile {
			t.Errorf("send %d text = %q, want the hostile string verbatim (byte-for-byte, no re-escaping)", i, body.Text)
		}
	}
}
