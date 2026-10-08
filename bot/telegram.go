package bot

// The Telegram client (SPEC-CLUSTER20 §3). It dials out to api.telegram.org
// and binds nothing: updates arrive by long polling, replies leave through a
// single sender goroutine behind a bounded queue. Every message is plain
// text -- no markup dialect is ever declared to Telegram -- because tunnel
// urls, owner names and reject reasons are attacker-influenced strings, and
// a bot that claims no markup dialect cannot have markup injected into it.
//
// Note the asymmetry with admin.go: the admin API is read-only because that
// is what the bot's credentials allow; the Bot API write (sendMessage) is
// the bot's entire purpose. The two live in different files so the review
// gate's grep for write verbs against the admin surface reads admin.go alone.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"ngrok/version"
)

// telegramTextCap is Telegram's documented per-message character limit. The
// sender enforces it once, here, so formatters never have to think about it.
const telegramTextCap = 4096

// sendQueueCap bounds the outbox. Beyond this the bot drops and counts (the
// drop accounting below) rather than buffer without limit: a dead Telegram
// must not become unbounded memory growth on the ngrokd host.
const sendQueueCap = 256

// pollHoldSeconds is the long-poll hold the bot asks Telegram for; the HTTP
// call is budgeted the hold plus slack, not the command timeout.
const pollHoldSeconds = 50

// telegramUpdate is the slice of the getUpdates payload the bot routes on.
// Other update kinds (edits, callback queries) simply do not decode into
// Message and are skipped by the offset advance alone.
type telegramUpdate struct {
	UpdateID int64 `json:"update_id"`
	Message  *struct {
		Chat struct {
			ID int64 `json:"id"`
		} `json:"chat"`
		Text string `json:"text"`
	} `json:"message"`
}

// outgoing is one message waiting for the sender.
type outgoing struct {
	chatID int64
	text   string
}

// telegramClient talks to one bot token on one Bot API endpoint.
type telegramClient struct {
	apiBase string
	token   string
	// http deliberately has no Timeout: every call here rides a context with
	// its own bound (the long poll's hold, sendMessage's command timeout), so
	// a client-wide timeout would either duplicate or fight those.
	http *http.Client
	ua   string
	// sendTimeout bounds each sendMessage wire call.
	sendTimeout time.Duration
	// wait is the interruptible sleep, swappable in tests (backoff, pacing).
	wait func(ctx context.Context, d time.Duration) error
	// noticeWait is the drop-notice interval sleep, swappable the same way;
	// nil return means "notice due", a context error means "shutting down".
	noticeWait func(ctx context.Context) error

	outbox   chan outgoing
	doneOnce sync.Once
	done     chan struct{}

	mu       sync.Mutex
	offset   int64               // next update_id to ask for; memory only, by design
	lastSend map[int64]time.Time // per-chat last-send, for the 1 msg/s pacing
	drops    map[int64]int       // messages lost since the last drop notice, per chat
}

func newTelegramClient(cfg *config) *telegramClient {
	t := &telegramClient{
		apiBase:     strings.TrimRight(cfg.TelegramAPI, "/"),
		token:       cfg.TelegramToken,
		http:        &http.Client{},
		sendTimeout: time.Duration(cfg.CommandTimeoutSeconds) * time.Second,
		ua:          "ngrok-bot/" + version.Full(),
		outbox:      make(chan outgoing, sendQueueCap),
		done:        make(chan struct{}),
		wait: func(ctx context.Context, d time.Duration) error {
			timer := time.NewTimer(d)
			defer timer.Stop()
			select {
			case <-timer.C:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		},
		lastSend: make(map[int64]time.Time),
		drops:    make(map[int64]int),
	}
	t.noticeWait = func(ctx context.Context) error {
		timer := time.NewTimer(time.Minute)
		defer timer.Stop()
		select {
		case <-timer.C:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return t
}

// apiGet issues one read-shaped Bot API call (getMe, getUpdates) and decodes
// the envelope. Telegram answers {"ok":true,"result":...} or
// {"ok":false,"description":...} and can ride any HTTP status, so the
// envelope's ok bit is checked, not the status code alone.
func (t *telegramClient) apiGet(ctx context.Context, method string, params url.Values, into interface{}) error {
	endpoint := fmt.Sprintf("%s/bot%s/%s", t.apiBase, t.token, method)
	if len(params) > 0 {
		endpoint += "?" + params.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", t.ua)

	raw, err := t.do(req)
	if err != nil {
		return err
	}
	return decodeEnvelope(method, raw, into)
}

// do runs one request and returns the body (bounded). The bound is defensive:
// a getUpdates window is a few KB, and a confused proxy answering something
// enormous should not be able to balloon the bot's memory.
func (t *telegramClient) do(req *http.Request) ([]byte, error) {
	resp, err := t.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	return raw, nil
}

// decodeEnvelope handles the {"ok":...} wrapper shared by every Bot API
// method.
func decodeEnvelope(method string, raw []byte, into interface{}) error {
	var envelope struct {
		OK          bool            `json:"ok"`
		Description string          `json:"description"`
		Result      json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return fmt.Errorf("%s: unreadable answer: %w", method, err)
	}
	if !envelope.OK {
		return fmt.Errorf("%s: telegram refused: %s", method, envelope.Description)
	}
	if into != nil && len(envelope.Result) > 0 {
		if err := json.Unmarshal(envelope.Result, into); err != nil {
			return fmt.Errorf("%s: unexpected result shape: %w", method, err)
		}
	}
	return nil
}

// sendMessage puts one message on the wire. The write verb here is the one
// the Bot API's send path takes; nothing in this method touches the admin
// API (the read-only property lives in admin.go and is about those
// credentials, not these).
func (t *telegramClient) sendMessage(ctx context.Context, msg outgoing) error {
	body, err := json.Marshal(struct {
		ChatID int64  `json:"chat_id"`
		Text   string `json:"text"`
	}{msg.chatID, msg.text})
	if err != nil {
		return err
	}
	endpoint := fmt.Sprintf("%s/bot%s/sendMessage", t.apiBase, t.token)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", t.ua)
	req.Header.Set("Content-Type", "application/json")

	raw, err := t.do(req)
	if err != nil {
		return err
	}
	return decodeEnvelope("sendMessage", raw, nil)
}

// identify runs getMe, the startup identity check. A bot whose token nobody
// accepts would otherwise run deaf -- polling forever, answering no one --
// which is worse than not starting; the caller turns the error into a
// non-zero exit. The returned username is what the startup log names.
func (t *telegramClient) identify(ctx context.Context) (string, error) {
	var me struct {
		Username string `json:"username"`
	}
	if err := t.apiGet(ctx, "getMe", nil, &me); err != nil {
		return "", fmt.Errorf("telegram identity check failed: %w", err)
	}
	return me.Username, nil
}

// runUpdates long-polls getUpdates until ctx is cancelled, handing each
// update to handle before advancing the offset past it. Acknowledging only
// after the handler has seen the update means one is never skipped between
// fetch and dispatch. The offset is memory-only on purpose (§6: no file
// writes): a restart re-fetches the last window, which for alerts and
// commands is harmless duplication, not loss.
func (t *telegramClient) runUpdates(ctx context.Context, handle func(telegramUpdate)) {
	backoff := time.Second
	for ctx.Err() == nil {
		params := url.Values{}
		params.Set("timeout", fmt.Sprintf("%d", pollHoldSeconds))
		if off := t.currentOffset(); off > 0 {
			params.Set("offset", fmt.Sprintf("%d", off))
		}

		var updates []telegramUpdate
		// The long poll is the wait: budget the hold plus slack rather than
		// the command timeout, which is sized for the admin API.
		pollCtx, cancel := context.WithTimeout(ctx, time.Duration(pollHoldSeconds)*time.Second+30*time.Second)
		err := t.apiGet(pollCtx, "getUpdates", params, &updates)
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			logger.Warn("getUpdates failed: %v (backing off %s)", err, backoff)
			_ = t.wait(ctx, backoff)
			backoff *= 2
			if backoff > time.Minute {
				backoff = time.Minute
			}
			continue
		}
		backoff = time.Second

		for _, u := range updates {
			if u.Message != nil {
				handle(u)
			}
			// The offset advances past every fetched update, message or not:
			// Telegram's contract is offset = lowest unprocessed update_id,
			// and deciding an update is uninteresting IS processing it.
			t.setOffset(u.UpdateID + 1)
		}
	}
}

func (t *telegramClient) currentOffset() int64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.offset
}

func (t *telegramClient) setOffset(v int64) {
	t.mu.Lock()
	t.offset = v
	t.mu.Unlock()
}

// send enqueues text for chatID, truncating to Telegram's cap first so
// formatters never see the limit. A full queue is a drop that is counted and
// later surfaced (runNotices), never a blocked caller: the update loop must
// keep polling while Telegram is down.
func (t *telegramClient) send(chatID int64, text string) {
	text = truncateMessage(text)
	select {
	case t.outbox <- outgoing{chatID: chatID, text: text}:
	default:
		t.mu.Lock()
		t.drops[chatID]++
		t.mu.Unlock()
		logger.Warn("send queue full; dropping message to chat %d", chatID)
	}
}

// runSender is the single consumer of the outbox and the only goroutine that
// paces or records successful sends. One consumer is what makes the per-chat
// pacing a plain last-send check rather than a limiter framework (§3).
func (t *telegramClient) runSender(ctx context.Context) {
	defer t.doneOnce.Do(func() { close(t.done) })
	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-t.outbox:
			t.deliver(ctx, msg)
		}
	}
}

// deliver paces 1 msg/s per chat (Telegram's published guidance), then sends.
// A failed send counts as a drop for that chat -- the same counter the
// queue-full path bumps -- so one notice reports both kinds of loss.
func (t *telegramClient) deliver(ctx context.Context, msg outgoing) {
	t.mu.Lock()
	last := t.lastSend[msg.chatID]
	t.mu.Unlock()
	if gap := time.Second - time.Since(last); gap > 0 {
		if t.wait(ctx, gap) != nil {
			return
		}
	}

	sendCtx, cancel := context.WithTimeout(ctx, t.sendTimeout)
	defer cancel()
	if err := t.sendMessage(sendCtx, msg); err != nil {
		t.mu.Lock()
		t.drops[msg.chatID]++
		t.mu.Unlock()
		logger.Warn("sendMessage to chat %d failed: %v", msg.chatID, err)
		return
	}
	t.mu.Lock()
	t.lastSend[msg.chatID] = time.Now()
	t.mu.Unlock()
}

// runNotices emits the drop accounting once a minute: one "N alerts dropped"
// line per affected chat, and only if that chat lost something (the
// event_destinations precedent: loss must be visible, and visible lossily).
// A notice that cannot itself be delivered is counted back as a drop for
// that chat -- when Telegram is down the WARN log is the only record, which
// the changelog says outright instead of implying the notice always lands.
func (t *telegramClient) runNotices(ctx context.Context) {
	for ctx.Err() == nil {
		if err := t.noticeWait(ctx); err != nil {
			return
		}
		t.mu.Lock()
		if len(t.drops) == 0 {
			t.mu.Unlock()
			continue
		}
		pending := t.drops
		t.drops = make(map[int64]int)
		t.mu.Unlock()

		for chatID, n := range pending {
			sendCtx, cancel := context.WithTimeout(ctx, t.sendTimeout)
			err := t.sendMessage(sendCtx, outgoing{
				chatID: chatID,
				text:   fmt.Sprintf("[ngrok] %d alerts dropped (Telegram unreachable or queue full)", n),
			})
			cancel()
			if err != nil {
				t.mu.Lock()
				t.drops[chatID] += n
				t.mu.Unlock()
			}
		}
	}
}

// droppedTotal reports the current per-chat drop counters (test seam).
func (t *telegramClient) droppedFor(chatID int64) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.drops[chatID]
}

// truncateMessage caps text at telegramTextCap characters, cutting at the
// last whole line that fits and appending an honest footer. Cutting
// mid-line severs a url or a count exactly where a human needs it;
// whole-line cutting keeps what survives readable.
func truncateMessage(text string) string {
	if utf8.RuneCountInString(text) <= telegramTextCap {
		return text
	}

	lines := strings.Split(text, "\n")
	footer := func(cut int) string {
		return fmt.Sprintf("\n… (+%d lines cut)", cut)
	}
	// The footer's own length depends on how many lines were cut, so each
	// candidate line is measured with the footer it would actually carry.
	kept := 0
	used := 0
	for i, line := range lines {
		cut := len(lines) - i
		candidate := used + utf8.RuneCountInString(line) + utf8.RuneCountInString(footer(cut))
		if candidate > telegramTextCap {
			break
		}
		kept++
		used += utf8.RuneCountInString(line) + 1 // +1 for the joining newline
	}
	if kept == 0 {
		// A first line that cannot fit beside any footer is hard-cut; a
		// message this large is one line of something gone wrong anyway.
		return string([]rune(text)[:telegramTextCap])
	}
	return strings.Join(lines[:kept], "\n") + footer(len(lines)-kept)
}
