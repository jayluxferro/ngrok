package bot

// Routing and pump tests (SPEC-CLUSTER20 testing strategy, "bot" bullet):
// the real Bot over both fakes. The pins here are the ones a reviewer
// checks by hand otherwise: the stranger chat produces zero sends, an alert
// reaches every allowed chat, and the health latch fires on the second
// failure and reports the outage duration on recovery.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newTestBot builds a Bot over the two fakes with two allowed chats, so
// fan-out tests can tell "sent once" from "sent to every chat". The config
// goes through applyDefaults because that is the production path's shape:
// main only ever hands New a config LoadConfig has defaulted and validated.
func newTestBot(t *testing.T, adminURL, telegramAPI string) *Bot {
	t.Helper()
	cfg := &config{
		AdminURL:              adminURL,
		TelegramAPI:           telegramAPI,
		TelegramToken:         "111:test",
		CommandTimeoutSeconds: 5,
		AllowedChats:          []int64{42, 43},
	}
	cfg.applyDefaults()
	b, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func updateMsg(id int64, chat int64, text string) telegramUpdate {
	var u telegramUpdate
	raw := updateJSON(id, chat, text)
	if err := json.Unmarshal([]byte(raw), &u); err != nil {
		panic(err)
	}
	return u
}

func drainOutbox(t *testing.T, b *Bot, n int) []outgoing {
	t.Helper()
	var msgs []outgoing
	deadline := time.After(2 * time.Second)
	for len(msgs) < n {
		select {
		case m, ok := <-b.tg.outbox:
			if !ok {
				t.Fatal("outbox closed early")
			}
			msgs = append(msgs, m)
		case <-deadline:
			t.Fatalf("only %d of %d messages queued", len(msgs), n)
		}
	}
	return msgs
}

func assertNoMessages(t *testing.T, b *Bot) {
	t.Helper()
	select {
	case m := <-b.tg.outbox:
		t.Fatalf("a message was queued for chat %d: %q", m.chatID, m.text)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestAllowedChatCommandIsAnswered(t *testing.T) {
	fake := newFakeTelegram(t)
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, metricsFixture)
	}))
	defer admin.Close()

	b := newTestBot(t, admin.URL, fake.srv.URL)
	b.handleUpdate(updateMsg(1, 42, "/status"))
	msgs := drainOutbox(t, b, 1)

	if msgs[0].chatID != 42 {
		t.Errorf("reply went to chat %d, want 42", msgs[0].chatID)
	}
	// The reply is rendered from the admin read, not a canned string: both
	// markers come from the fixture's numbers.
	if !strings.Contains(msgs[0].text, "uptime: 2h44m") || !strings.Contains(msgs[0].text, "tunnels active: 3") {
		t.Errorf("reply is not rendered from the metrics snapshot:\n%s", msgs[0].text)
	}
}

func TestStrangerChatGetsZeroSends(t *testing.T) {
	// The fail-closed pin: an update from a chat outside the allowlist
	// produces no sendMessage call at all -- not a help hint, not an error,
	// not even a read of the admin API on its behalf.
	fake := newFakeTelegram(t)
	var adminHits int
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		adminHits++
		fmt.Fprint(w, metricsFixture)
	}))
	defer admin.Close()

	b := newTestBot(t, admin.URL, fake.srv.URL)
	b.handleUpdate(updateMsg(1, 999999, "/status"))
	b.handleUpdate(updateMsg(2, 999999, "/help"))
	b.handleUpdate(updateMsg(3, 999999, "free admin data please"))

	assertNoMessages(t, b)
	if got := len(fake.sentMessages()); got != 0 {
		t.Errorf("%d sendMessage calls were made for a stranger chat", got)
	}
	if adminHits != 0 {
		t.Errorf("a stranger's command caused %d admin API reads", adminHits)
	}
}

func TestNonCommandTextIgnored(t *testing.T) {
	fake := newFakeTelegram(t)
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, metricsFixture)
	}))
	defer admin.Close()

	b := newTestBot(t, admin.URL, fake.srv.URL)
	b.handleUpdate(updateMsg(1, 42, "hello there"))
	b.handleUpdate(updateMsg(2, 42, ""))
	assertNoMessages(t, b)
	if got := len(fake.sentMessages()); got != 0 {
		t.Errorf("plain text produced %d sends; the bot speaks when spoken to via commands", got)
	}
}

func TestStartAliasesHelp(t *testing.T) {
	fake := newFakeTelegram(t)
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, metricsFixture)
	}))
	defer admin.Close()

	b := newTestBot(t, admin.URL, fake.srv.URL)
	b.handleUpdate(updateMsg(1, 42, "/start"))
	msgs := drainOutbox(t, b, 1)
	if !strings.Contains(msgs[0].text, "/status") {
		t.Errorf("/start reply is not the help text:\n%s", msgs[0].text)
	}
}

func TestBudgetExhaustionRepliesOnceThenSilent(t *testing.T) {
	fake := newFakeTelegram(t)
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, metricsFixture)
	}))
	defer admin.Close()

	b := newTestBot(t, admin.URL, fake.srv.URL)
	b.cfg.CommandRatePerMin = 3
	var at time.Time = time.Unix(1700000000, 0)
	b.now = func() time.Time { return at }

	// Three commands spend the window; the fourth gets the one notice; the
	// fifth gets silence.
	for i := int64(1); i <= 3; i++ {
		b.handleUpdate(updateMsg(i, 42, "/help"))
	}
	drainOutbox(t, b, 3)

	b.handleUpdate(updateMsg(4, 42, "/help"))
	msgs := drainOutbox(t, b, 1)
	if !strings.Contains(msgs[0].text, "rate limited") {
		t.Errorf("over-budget reply = %q, want the rate-limit notice", msgs[0].text)
	}

	b.handleUpdate(updateMsg(5, 42, "/help"))
	assertNoMessages(t, b)
}

func TestAlertFansOutToEveryAllowedChat(t *testing.T) {
	fake := newFakeTelegram(t)
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveSSEFrames(w, `{"type":"auth_reject","at":"2026-02-14T10:00:00Z","reason":"invalid_token"}`)
		<-r.Context().Done()
	}))
	defer admin.Close()

	b := newTestBot(t, admin.URL, fake.srv.URL)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go b.pumpEvents(ctx)

	msgs := drainOutbox(t, b, 2)
	chats := map[int64]bool{}
	for _, m := range msgs {
		chats[m.chatID] = true
		if !strings.Contains(m.text, "[ngrok] auth rejected: invalid_token") {
			t.Errorf("alert line = %q, want the formatted auth_reject", m.text)
		}
	}
	if !chats[42] || !chats[43] {
		t.Errorf("alert did not reach every allowed chat: %v", chats)
	}
}

func TestAlertFilteredByConfiguredSet(t *testing.T) {
	// connection_open exists as a formatter but is not in the configured
	// set: it must be dropped before the sender ever sees it.
	fake := newFakeTelegram(t)
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveSSEFrames(w,
			`{"type":"connection_open","at":"2026-02-14T10:00:00Z","client_addr":"10.0.0.1","url":"https://x.example","protocol":"https"}`,
		)
		<-r.Context().Done()
	}))
	defer admin.Close()

	b := newTestBot(t, admin.URL, fake.srv.URL)
	ctx, cancel := context.WithCancel(context.Background())
	go b.pumpEvents(ctx)
	time.Sleep(100 * time.Millisecond)
	cancel()

	assertNoMessages(t, b)
}

func TestHealthWatcherLatchesAndRecovers(t *testing.T) {
	var alerts []string
	w := &healthWatcher{
		admin:     mustAdminClient(t, testAdminConfig("http://127.0.0.1:1", "", "")), // unreachable
		interval:  time.Second,
		broadcast: func(s string) { alerts = append(alerts, s) },
	}

	t0 := time.Unix(1700000000, 0)
	// One failure: noise, no alert.
	w.observe(t0, fmt.Errorf("dial: refused"))
	if len(alerts) != 0 {
		t.Fatalf("one blip alerted: %v", alerts)
	}
	// Second consecutive failure: the latch fires, once.
	w.observe(t0.Add(30*time.Second), fmt.Errorf("dial: refused"))
	if len(alerts) != 1 || !strings.Contains(alerts[0], "unreachable") {
		t.Fatalf("alerts = %v, want one unreachable alert on the second failure", alerts)
	}
	// More failures while latched: still exactly one alert (latched, not
	// repeating).
	w.observe(t0.Add(60*time.Second), fmt.Errorf("dial: refused"))
	if len(alerts) != 1 {
		t.Fatalf("latched watcher re-alerted: %v", alerts)
	}
	// Recovery names the outage duration.
	w.observe(t0.Add(90*time.Second), nil)
	if len(alerts) != 2 {
		t.Fatalf("recovery did not alert: %v", alerts)
	}
	if !strings.Contains(alerts[1], "recovered after 1m30s") {
		t.Errorf("recovery line = %q, want the outage duration", alerts[1])
	}
	// Back to healthy: another outage would alert fresh.
	w.observe(t0.Add(120*time.Second), fmt.Errorf("dial: refused"))
	w.observe(t0.Add(150*time.Second), fmt.Errorf("dial: refused"))
	if len(alerts) != 3 || !strings.Contains(alerts[2], "unreachable") {
		t.Fatalf("second outage did not alert fresh: %v", alerts)
	}
}

func TestHealthWatcherStartupDownAlertsLikeAnyOutage(t *testing.T) {
	// Startup is unlatched: a server already down at boot alerts on the
	// second failed probe exactly like a mid-run outage would.
	var alerts []string
	w := &healthWatcher{
		admin:     mustAdminClient(t, testAdminConfig("http://127.0.0.1:1", "", "")),
		interval:  time.Second,
		broadcast: func(s string) { alerts = append(alerts, s) },
	}
	t0 := time.Unix(1700000000, 0)
	w.observe(t0, fmt.Errorf("dial: refused"))
	w.observe(t0.Add(30*time.Second), fmt.Errorf("dial: refused"))
	if len(alerts) != 1 {
		t.Fatalf("alerts = %v, want the boot-time outage to alert", alerts)
	}
}

func TestRunRefusesWhenIdentityCheckFails(t *testing.T) {
	// A refused token would run the bot deaf: polling forever, answering no
	// one. Run's first act is getMe, and its error is the caller's non-zero
	// exit -- nothing starts, not even the pumps.
	refusing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"ok":false,"description":"Unauthorized"}`)
	}))
	defer refusing.Close()

	b, err := New(&config{
		AdminURL:              "http://127.0.0.1:1",
		TelegramAPI:           refusing.URL,
		TelegramToken:         "111:wrong",
		CommandTimeoutSeconds: 5,
		AllowedChats:          []int64{42},
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := b.Run(ctx); err == nil {
		t.Fatal("Run started despite a refused identity check")
	}
}
