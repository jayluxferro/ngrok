package bot

// Admin client tests (SPEC-CLUSTER20 testing strategy). The fixtures below
// are copied from the cluster-19 handlers' real JSON -- server/admin.go's
// /metrics payload map and server/observability.go's tunnelSnapshot /
// event structs -- not hand-typed from memory: the bot's parse is only as
// correct as the shapes it is tested against.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func testAdminConfig(url, token, auth string) *config {
	return &config{
		AdminURL:              url,
		AdminToken:            token,
		AdminAuth:             auth,
		CommandTimeoutSeconds: 5,
	}
}

func mustAdminClient(t *testing.T, cfg *config) *adminClient {
	t.Helper()
	a, err := newAdminClient(cfg)
	if err != nil {
		t.Fatalf("newAdminClient: %v", err)
	}
	return a
}

// metricsFixture is /metrics exactly as the handler writes it: the full key
// set including the keys the bot does not model (window_seconds,
// event_subscribers, event_destinations) -- unknown fields must be ignored,
// not fatal.
const metricsFixture = `{
  "public_connections": 7,
  "public_connections_peak": 42,
  "control_connections": 2,
  "public_conn_open_total": 1234,
  "auth_reject_count": 5,
  "rate_drop_count": 6,
  "uptime_seconds": 9876,
  "tunnels_active": 3,
  "window_seconds": 60,
  "rates": {"public_conn_open_rate_per_sec": 0.5, "rate_drop_rate_per_sec": 0, "auth_reject_rate_per_sec": 0.01},
  "event_drop_count": 9,
  "event_subscribers": 1,
  "event_destinations": []
}`

func TestMetricsParsesRealShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/metrics" {
			t.Errorf("metrics requested %q", r.URL.Path)
		}
		fmt.Fprint(w, metricsFixture)
	}))
	defer srv.Close()

	a := mustAdminClient(t, testAdminConfig(srv.URL, "", ""))
	snap, err := a.metrics(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if snap.UptimeSeconds != 9876 {
		t.Errorf("uptime_seconds = %d, want 9876", snap.UptimeSeconds)
	}
	if snap.PublicConnections != 7 || snap.PublicConnPeak != 42 {
		t.Errorf("public connections = %d peak %d, want 7/42", snap.PublicConnections, snap.PublicConnPeak)
	}
	if snap.ControlConnections != 2 {
		t.Errorf("control_connections = %d, want 2", snap.ControlConnections)
	}
	if snap.TunnelsActive != 3 {
		t.Errorf("tunnels_active = %d, want 3", snap.TunnelsActive)
	}
	if snap.AuthRejectCount != 5 || snap.RateDropCount != 6 || snap.EventDropCount != 9 {
		t.Errorf("counters = reject %d drop %d event %d, want 5/6/9", snap.AuthRejectCount, snap.RateDropCount, snap.EventDropCount)
	}
	if snap.PublicConnOpenTotal != 1234 {
		t.Errorf("public_conn_open_total = %d, want 1234", snap.PublicConnOpenTotal)
	}
	if got := snap.Rates["public_conn_open_rate_per_sec"]; got != 0.5 {
		t.Errorf("rates[public_conn_open_rate_per_sec] = %v, want 0.5", got)
	}
}

func TestMetricsToleratesUnknownFields(t *testing.T) {
	// A newer ngrokd adds keys freely; the bot's parse must not care.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"uptime_seconds": 1, "smell_the_future": {"nested": [true]}}`)
	}))
	defer srv.Close()

	a := mustAdminClient(t, testAdminConfig(srv.URL, "", ""))
	if _, err := a.metrics(context.Background()); err != nil {
		t.Fatalf("metrics refused an answer with unknown fields: %v", err)
	}
}

// tunnelsFixture is one tunnelSnapshot with every field the server marshals
// (server/observability.go's JSON tags), inside the handler's
// {"tunnels": [...]} envelope.
const tunnelsFixture = `{"tunnels": [{
  "url": "https://app.example.ngrok.app",
  "protocol": "https",
  "started_at": "2026-02-14T09:30:00Z",
  "active_connections": 2,
  "total_connections": 40,
  "bytes_in": 1000,
  "bytes_out": 2000,
  "owner": "ci-bot",
  "internal": false,
  "agent_tls": false,
  "forward_to": "",
  "claimed_port": 0,
  "pooling": true,
  "policy_attached": true
}]}`

func TestTunnelsParsesRealShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/tunnels" {
			t.Errorf("tunnels requested %q", r.URL.Path)
		}
		fmt.Fprint(w, tunnelsFixture)
	}))
	defer srv.Close()

	a := mustAdminClient(t, testAdminConfig(srv.URL, "", ""))
	rows, err := a.tunnels(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	row := rows[0]
	if row.URL != "https://app.example.ngrok.app" || row.Protocol != "https" {
		t.Errorf("url/proto = %q/%q", row.URL, row.Protocol)
	}
	if row.ActiveConnections != 2 || row.TotalConnections != 40 {
		t.Errorf("conns = %d/%d, want 2/40", row.ActiveConnections, row.TotalConnections)
	}
	if row.Owner != "ci-bot" || !row.Pooling || !row.PolicyAttached {
		t.Errorf("owner/pooling/policy = %q/%v/%v, want ci-bot/true/true", row.Owner, row.Pooling, row.PolicyAttached)
	}
}

func TestAdminAuthHeadersBothModes(t *testing.T) {
	var gotToken, gotUser, gotPass string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotToken = r.Header.Get("X-Ngrok-Admin-Token")
		gotUser, gotPass, _ = r.BasicAuth()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Both credentials at once: the admin API accepts either and the bot
	// sends both (§1) -- an operator migrating between the two schemes
	// should not have to guess which one wins on the wire.
	a := mustAdminClient(t, testAdminConfig(srv.URL, "secret-token", "ops:hunter2"))
	if _, err := a.health(context.Background()); err != nil {
		t.Fatal(err)
	}
	if gotToken != "secret-token" {
		t.Errorf("X-Ngrok-Admin-Token = %q, want secret-token", gotToken)
	}
	if gotUser != "ops" || gotPass != "hunter2" {
		t.Errorf("basic auth = %q:%q, want ops:hunter2", gotUser, gotPass)
	}
}

func TestAdminTokenOnlyMode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Ngrok-Admin-Token") == "" {
			t.Error("token header missing in token-only mode")
		}
		if u, _, ok := r.BasicAuth(); u != "" || ok {
			t.Error("basic auth sent in token-only mode")
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	a := mustAdminClient(t, testAdminConfig(srv.URL, "t", ""))
	if _, err := a.health(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestAdminErrorsNameTheStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "unauthorized")
	}))
	defer srv.Close()

	a := mustAdminClient(t, testAdminConfig(srv.URL, "wrong", ""))
	_, err := a.metrics(context.Background())
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("err = %v, want the status in the message", err)
	}
}

func TestHealthMeasuresLatency(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok\n")
	}))
	defer srv.Close()

	a := mustAdminClient(t, testAdminConfig(srv.URL, "", ""))
	took, err := a.health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if took <= 0 {
		t.Errorf("latency = %v, want > 0", took)
	}
}

// serveSSEFrames writes each frame as the server's /events does: one
// "data: {json}\n\n" block, flushed per event.
func serveSSEFrames(w http.ResponseWriter, frames ...string) {
	w.Header().Set("Content-Type", "text/event-stream")
	flusher := w.(http.Flusher)
	for _, f := range frames {
		fmt.Fprintf(w, "data: %s\n\n", f)
		flusher.Flush()
	}
}

func eventFixture(typ string) string {
	return fmt.Sprintf(`{"type":%q,"at":"2026-02-14T10:00:00Z"}`, typ)
}

func TestEventsParsesFrames(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The frames exercise the parser's edges: a keep-alive comment the
		// server may grow one day, a plain frame, a multi-line data: frame
		// (which per SSE convention joins with newline), and a non-JSON
		// payload that must be skipped, not fatal.
		serveSSEFrames(w,
			eventFixture("tunnel_open"),
			`{"type":"auth_reject","at":"2026-02-14T10:00:01Z","reason":"invalid_token"}`,
		)
		flush := w.(http.Flusher)
		fmt.Fprint(w, ": ping\n\n")
		flush.Flush()
		fmt.Fprint(w, "data: {\"type\":\"rate_limit_drop\",\n")
		fmt.Fprint(w, "data: \"continued\": true}\n\n")
		flush.Flush()
		fmt.Fprint(w, "data: not-json-at-all\n\n")
		flush.Flush()
		// Hold the stream open until the client goes away. Waiting on the
		// request context (not select{}) is what lets httptest Close return.
		<-r.Context().Done()
	}))
	defer srv.Close()

	a := mustAdminClient(t, testAdminConfig(srv.URL, "", ""))
	frames, stop, err := a.events(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer stop()

	// tunnel_open, auth_reject, then the multi-line frame joined into one
	// valid JSON payload. The non-JSON line vanishes.
	var got []eventFrame
	timeout := time.After(2 * time.Second)
	for len(got) < 3 {
		select {
		case f, ok := <-frames:
			if !ok {
				t.Fatal("frame channel closed before the expected frames arrived")
			}
			got = append(got, f)
		case <-timeout:
			t.Fatalf("timed out with %d frames: %+v", len(got), got)
		}
	}

	if got[0].Type != "tunnel_open" {
		t.Errorf("first frame type = %q, want tunnel_open", got[0].Type)
	}
	if got[1].Type != "auth_reject" {
		t.Errorf("second frame type = %q, want auth_reject", got[1].Type)
	}
	var drop struct {
		Type      string `json:"type"`
		Continued bool   `json:"continued"`
	}
	if err := json.Unmarshal(got[2].Raw, &drop); err != nil {
		t.Fatalf("multi-line data frame did not join: %v (raw %s)", err, got[2].Raw)
	}
	if drop.Type != "rate_limit_drop" || !drop.Continued {
		t.Errorf("multi-line frame decoded as %+v", drop)
	}
}

// waitRecorder is the stubbed clock for the reconnect loop: waits are
// recorded and return at once, so a test proves the backoff schedule without
// sleeping through it. The mutex is real, not ceremony: the events goroutine
// appends while the test reads.
type waitRecorder struct {
	mu    sync.Mutex
	waits []time.Duration
}

func (w *waitRecorder) stub(ctx context.Context, d time.Duration) error {
	w.mu.Lock()
	w.waits = append(w.waits, d)
	w.mu.Unlock()
	return nil
}

func (w *waitRecorder) all() []time.Duration {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]time.Duration(nil), w.waits...)
}

func TestEventsReconnectsOnEOFWithBackoff(t *testing.T) {
	var connsMu sync.Mutex
	conns := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connsMu.Lock()
		conns++
		n := conns
		connsMu.Unlock()
		if n == 1 {
			serveSSEFrames(w, eventFixture("tunnel_open"))
			return // EOF: the first connection dies after one frame
		}
		serveSSEFrames(w, eventFixture("tunnel_close"))
		<-r.Context().Done() // the second connection holds
	}))
	defer srv.Close()

	a := mustAdminClient(t, testAdminConfig(srv.URL, "", ""))
	clock := &waitRecorder{}
	a.wait = clock.stub

	frames, stop, err := a.events(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer stop()

	var types []string
	timeout := time.After(2 * time.Second)
	for len(types) < 2 {
		select {
		case f := <-frames:
			types = append(types, f.Type)
		case <-timeout:
			t.Fatalf("timed out after reconnect; got %v (waits: %v)", types, clock.all())
		}
	}

	if types[0] != "tunnel_open" || types[1] != "tunnel_close" {
		t.Errorf("frames across the reconnect = %v, want [tunnel_open tunnel_close]", types)
	}
	connsMu.Lock()
	got := conns
	connsMu.Unlock()
	if got != 2 {
		t.Errorf("connections = %d, want 2 (one EOF, one reconnect)", got)
	}
	waits := clock.all()
	if len(waits) == 0 || waits[0] != time.Second {
		t.Errorf("first backoff wait = %v, want 1s", waits)
	}
}

func TestEventsBackoffDoublesAndCaps(t *testing.T) {
	// Every connection delivers one frame then EOFs; eight frames means
	// seven reconnects, enough to walk the schedule past the 60s cap.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveSSEFrames(w, eventFixture("tunnel_open"))
	}))
	defer srv.Close()

	a := mustAdminClient(t, testAdminConfig(srv.URL, "", ""))
	clock := &waitRecorder{}
	a.wait = clock.stub

	frames, stop, _ := a.events(context.Background())
	defer stop()

	timeout := time.After(5 * time.Second)
	for got := 0; got < 8; got++ {
		select {
		case <-frames:
		case <-timeout:
			t.Fatalf("only %d frames in the window (waits: %v)", got, clock.all())
		}
	}

	waits := clock.all()
	// The frame for connection i arrives before wait[i], so the first eight
	// frames guarantee waits[0..6].
	for i := 0; i < 7; i++ {
		want := time.Second << uint(i)
		if want > time.Minute {
			want = time.Minute
		}
		if waits[i] != want {
			t.Fatalf("wait[%d] = %v, want %v (waits: %v)", i, waits[i], want, waits)
		}
	}
}

func TestEventsStopsOnCancel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveSSEFrames(w, eventFixture("tunnel_open"))
		<-r.Context().Done() // hold until the client goes away
	}))
	defer srv.Close()

	a := mustAdminClient(t, testAdminConfig(srv.URL, "", ""))
	ctx, cancel := context.WithCancel(context.Background())
	frames, stop, err := a.events(ctx)
	if err != nil {
		t.Fatal(err)
	}

	select {
	case <-frames:
	case <-time.After(2 * time.Second):
		t.Fatal("no frame on a healthy stream")
	}

	stop()
	cancel()
	// The channel closes only on cancellation (§2); give the goroutine a
	// moment, then assert.
	select {
	case _, ok := <-frames:
		if ok {
			t.Fatal("frame channel still open after cancellation")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("frame channel did not close after cancellation")
	}
}
