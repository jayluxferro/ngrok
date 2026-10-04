package server

// Tests for event export (SPEC-CLUSTER9 §4): the connection_open event, the
// hub's drop accounting, and the two destination types.
//
// The destinations are tested against real httptest servers and real files,
// for the same reason the policy tests drive real loopback TCP: "the batch
// arrived with the auth header" is an assertion about bytes a collector saw,
// not about a mock. The hub-side tests use fresh eventHub values rather than
// the global observe, so stall scenarios in one test cannot bleed drop counts
// into another (the global hub's counters only ever grow).

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"ngrok/msg"
)

func debugStack() string {
	buf := make([]byte, 1<<16)
	n := runtime.Stack(buf, true)
	return string(buf[:n])
}

// testStore is an observabilityStore without the sampler goroutine: the tests
// here read counters directly and do not want a second writer ticking under
// them.
func testStore() *observabilityStore {
	return &observabilityStore{
		started: time.Now().UTC(),
		tunnels: make(map[string]*tunnelSnapshot),
		events:  newEventHub(),
	}
}

// waitFor polls cond until it holds or the test times out. Everything the
// destinations do happens on their drain goroutines, so every assertion about
// observable state is eventually-consistent.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()

	deadline := time.Now().Add(publicTimeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s\nall goroutine stacks:\n%s", what, debugStack())
}

// ---------------------------------------------------------------------------
// connection_open and hub drop accounting

// TestConnectionOpenEventEmittedOnConnOpen pins the symmetry the event was
// added for (SPEC-CLUSTER9 §4.1): onConnClose has always announced the end of
// a public connection; onConnOpen now announces the start, with the fields a
// consumer needs to pair the two -- who connected, to which endpoint, over
// which protocol.
func TestConnectionOpenEventEmittedOnConnOpen(t *testing.T) {
	o := testStore()
	o.tunnels["https://test.ngrok.io"] = &tunnelSnapshot{URL: "https://test.ngrok.io"}
	sub := o.events.subscribe()
	defer o.events.unsubscribe(sub)

	tun := &Tunnel{url: "https://test.ngrok.io", req: &msg.ReqTunnel{Protocol: "https"}}
	o.onConnOpen(tun, "10.1.2.3:55555")

	select {
	case payload := <-sub.ch:
		var ev struct {
			Type       string `json:"type"`
			At         string `json:"at"`
			ClientAddr string `json:"client_addr"`
			URL        string `json:"url"`
			Protocol   string `json:"protocol"`
		}
		if err := json.Unmarshal(payload, &ev); err != nil {
			t.Fatalf("connection_open payload is not valid JSON: %v\n%s", err, payload)
		}
		if ev.Type != "connection_open" {
			t.Errorf("event type: expected connection_open, got %q", ev.Type)
		}
		if ev.At == "" {
			t.Error("event carries no timestamp")
		}
		if ev.ClientAddr != "10.1.2.3:55555" {
			t.Errorf("client_addr: expected 10.1.2.3:55555, got %q", ev.ClientAddr)
		}
		if ev.URL != "https://test.ngrok.io" {
			t.Errorf("url: expected https://test.ngrok.io, got %q", ev.URL)
		}
		if ev.Protocol != "https" {
			t.Errorf("protocol: expected https, got %q", ev.Protocol)
		}
	case <-time.After(publicTimeout):
		t.Fatal("onConnOpen published no event")
	}

	// The counters the site always maintained still moved: the event was
	// added alongside them, not instead of them.
	o.mu.RLock()
	defer o.mu.RUnlock()
	s := o.tunnels["https://test.ngrok.io"]
	if s.ActiveConnections != 1 || s.TotalConnections != 1 {
		t.Errorf("connection counters: expected active=1 total=1, got active=%d total=%d", s.ActiveConnections, s.TotalConnections)
	}
}

// TestEventHubDropCounterStopsWhenDrained is the drop-counter contract: a
// subscriber that stops reading loses exactly the events that did not fit, a
// subscriber keeping up loses none, and a caught-up subscriber stops losing
// events -- the counter is a backlog symptom, not a life sentence.
func TestEventHubDropCounterStopsWhenDrained(t *testing.T) {
	hub := newEventHub()
	stalled := hub.subscribeBuffered(2)
	healthy := hub.subscribeBuffered(64)
	defer hub.unsubscribe(healthy)

	for i := 0; i < 5; i++ {
		hub.publishTunnelClose(fmt.Sprintf("url-%d", i))
	}

	if got := stalled.dropped.Load(); got != 3 {
		t.Errorf("stalled subscriber: expected exactly 3 drops (5 events, queue of 2), got %d", got)
	}
	if got := healthy.dropped.Load(); got != 0 {
		t.Errorf("healthy subscriber: expected 0 drops, got %d", got)
	}
	if got := hub.droppedEvents(); got != 3 {
		t.Errorf("hub total: expected 3, got %d", got)
	}

	// Drain the stalled subscriber's queue and confirm drops stop accruing.
	for i := 0; i < 2; i++ {
		<-stalled.ch
	}
	hub.publishTunnelClose("url-x")
	hub.publishTunnelClose("url-y")

	if got := stalled.dropped.Load(); got != 3 {
		t.Errorf("stalled subscriber drained: drops kept accruing, expected 3, got %d", got)
	}
	if got := hub.droppedEvents(); got != 3 {
		t.Errorf("hub total after drain: expected 3, got %d", got)
	}
}

// TestEventHubDropTotalSurvivesUnsubscribe pins the hub-wide total: drops are
// counted when they happen, so a subscriber that drops events and leaves
// takes its evidence with it, not the hub's count of it.
func TestEventHubDropTotalSurvivesUnsubscribe(t *testing.T) {
	hub := newEventHub()
	stalled := hub.subscribeBuffered(1)

	hub.publishTunnelClose("a")
	hub.publishTunnelClose("b")
	if got := stalled.dropped.Load(); got != 1 {
		t.Fatalf("expected 1 drop on the stalled subscriber, got %d", got)
	}

	hub.unsubscribe(stalled)
	hub.publishTunnelClose("c")

	if got := hub.droppedEvents(); got != 1 {
		t.Errorf("hub total: expected the departed subscriber's drop to survive, got %d", got)
	}
	if got := hub.subscriberCount(); got != 0 {
		t.Errorf("subscriber count after unsubscribe: expected 0, got %d", got)
	}
}

// ---------------------------------------------------------------------------
// http destination

// collectorHarness is an httptest collector that records every POST it
// receives: body, auth header, and a channel to await them on.
type collectorHarness struct {
	server  *httptest.Server
	bodies  chan string
	headers chan http.Header
	count   atomic.Int64

	failFirst int // respond 500 to the first N requests
}

func newCollectorHarness(t *testing.T, failFirst int) *collectorHarness {
	t.Helper()

	h := &collectorHarness{
		bodies:    make(chan string, 64),
		headers:   make(chan http.Header, 64),
		failFirst: failFirst,
	}
	// Every request is recorded, including the failed ones: a collector
	// that answers 500 still received the bytes, and the retry test wants to
	// compare what the first, refused POST carried against the retry.
	h.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		n := h.count.Add(1)
		select {
		case h.bodies <- string(body):
		default:
		}
		select {
		case h.headers <- r.Header.Clone():
		default:
		}
		if int(n) <= h.failFirst {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(h.server.Close)
	return h
}

func destinationFor(hub *eventHub, url string, batchSize int, flush time.Duration, retry time.Duration) *httpDestination {
	d, err := newHTTPDestination(eventDestinationConfig{
		Type:          "http",
		URL:           url,
		AuthHeader:    "Authorization: Bearer collector-token",
		BatchSize:     batchSize,
		FlushInterval: flush.String(),
	}, hub)
	if err != nil {
		panic(err) // the config above is a compile-time fixture
	}
	d.retryStart = retry
	d.retryMax = retry * 4
	go d.run()
	return d
}

// TestHTTPDestinationBatchShapeAndAuthHeader drives one batch end to end:
// three events published to the hub must arrive at the collector as one POST
// whose body is a JSON array of the events, in order, with the configured
// auth header attached.
func TestHTTPDestinationBatchShapeAndAuthHeader(t *testing.T) {
	hub := newEventHub()
	h := newCollectorHarness(t, 0)
	d := destinationFor(hub, h.server.URL, 3, time.Second, 5*time.Millisecond)
	defer d.stop()

	hub.publishTunnelOpen("https://a.ngrok.io", "https")
	hub.publishConnectionOpen("10.0.0.1:1111", "https://a.ngrok.io", "https")
	hub.publishConnectionClose("https://a.ngrok.io", 10, 20)

	select {
	case body := <-h.bodies:
		var events []map[string]interface{}
		if err := json.Unmarshal([]byte(body), &events); err != nil {
			t.Fatalf("batch body is not a JSON array of events: %v\n%s", err, body)
		}
		if len(events) != 3 {
			t.Fatalf("expected a batch of 3 events, got %d:\n%s", len(events), body)
		}
		wantTypes := []string{"tunnel_open", "connection_open", "connection_close"}
		for i, ev := range events {
			if ev["type"] != wantTypes[i] {
				t.Errorf("event %d: expected type %s, got %v", i, wantTypes[i], ev["type"])
			}
			if _, ok := ev["at"]; !ok {
				t.Errorf("event %d: carries no at timestamp", i)
			}
		}
		if events[1]["client_addr"] != "10.0.0.1:1111" {
			t.Errorf("connection_open client_addr: got %v", events[1]["client_addr"])
		}
		if got := d.droppedCount(); got != 0 {
			t.Errorf("a healthy run must not drop events, got %d dropped", got)
		}
	case <-time.After(publicTimeout):
		t.Fatal("the collector never received the batch")
	}

	select {
	case hdr := <-h.headers:
		if got := hdr.Get("Authorization"); got != "Bearer collector-token" {
			t.Errorf("auth header: expected \"Bearer collector-token\", got %q", got)
		}
		if got := hdr.Get("Content-Type"); got != "application/json" {
			t.Errorf("content-type: expected application/json, got %q", got)
		}
	default:
		t.Error("the collector recorded no headers for the batch")
	}
}

// TestHTTPDestinationFlushesOnInterval covers the other half of the Keen.io
// shape: a batch smaller than batch_size must still ship when the flush
// interval passes, or low-traffic endpoints would buffer forever.
func TestHTTPDestinationFlushesOnInterval(t *testing.T) {
	hub := newEventHub()
	h := newCollectorHarness(t, 0)
	d := destinationFor(hub, h.server.URL, 100, 30*time.Millisecond, 5*time.Millisecond)
	defer d.stop()

	hub.publishTunnelOpen("https://slow.ngrok.io", "https")

	waitFor(t, "the interval flush", func() bool {
		select {
		case body := <-h.bodies:
			if !strings.Contains(body, "tunnel_open") {
				t.Fatalf("flushed batch does not contain the event: %s", body)
			}
			return true
		default:
			return false
		}
	})
}

// TestHTTPDestinationRetriesOn500 is the retry contract: a collector that
// answers 500 sees the SAME batch again after a backoff, and the destination
// stays healthy afterwards. The batch is never abandoned -- abandonment would
// be silent loss, and loss here is supposed to be visible in the drop
// counters.
func TestHTTPDestinationRetriesOn500(t *testing.T) {
	hub := newEventHub()
	h := newCollectorHarness(t, 1)
	d := destinationFor(hub, h.server.URL, 1, time.Second, 5*time.Millisecond)
	defer d.stop()

	hub.publishTunnelOpen("https://retry.ngrok.io", "https")

	var bodies []string
	waitFor(t, "the batch to be retried and accepted", func() bool {
		select {
		case b := <-h.bodies:
			bodies = append(bodies, b)
			return h.count.Load() >= 2 && len(bodies) >= 2
		default:
			return false
		}
	})

	if len(bodies) < 2 {
		t.Fatalf("expected the failed batch to be retried (2+ POSTs), saw %d", len(bodies))
	}
	for _, b := range bodies {
		if b != bodies[0] {
			t.Errorf("retry sent a different batch:\nfirst: %s\nlater: %s", bodies[0], b)
		}
	}
	if got := d.droppedCount(); got != 0 {
		t.Errorf("a retrying destination drops nothing, got %d dropped", got)
	}
}

// TestHTTPDestinationDropsWhenCollectorSlow is the backpressure contract, and
// the review gate that publish must stay non-blocking under a stalled
// destination (run with -race): with the collector parked, 1500 publishes
// must complete immediately, overflowing the 1000-slot queue, and the loss
// must show up in both the destination's counter and the hub's total.
func TestHTTPDestinationDropsWhenCollectorSlow(t *testing.T) {
	release := make(chan struct{})
	parked := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	defer parked.Close()
	defer close(release)

	hub := newEventHub()
	d, err := newHTTPDestination(eventDestinationConfig{
		Type:          "http",
		URL:           parked.URL,
		AuthHeader:    "Authorization: Bearer collector-token",
		BatchSize:     1,
		FlushInterval: time.Second.String(),
	}, hub)
	if err != nil {
		t.Fatalf("destination refused a valid config: %v", err)
	}
	d.client.Timeout = 30 * time.Millisecond // fail each POST fast, then sleep out the backoff
	d.retryStart = 500 * time.Millisecond    // hold the drain goroutine off the queue
	d.retryMax = 2 * time.Second
	go d.run()
	defer d.stop()

	start := time.Now()
	const total = 1500
	for i := 0; i < total; i++ {
		hub.publishTunnelOpen(fmt.Sprintf("https://flood-%d.ngrok.io", i), "https")
	}
	elapsed := time.Since(start)
	if elapsed > 2*time.Second {
		t.Errorf("publish blocked on the stalled destination: %d publishes took %v", total, elapsed)
	}

	// The drain goroutine consumed at most one event (its in-flight POST);
	// everything past the queue cap was dropped and counted.
	if got := d.droppedCount(); got < 400 {
		t.Errorf("destination drop counter: expected 400+ after overflowing a 1000-slot queue with %d events, got %d", total, got)
	}
	if got := hub.droppedEvents(); got < 400 {
		t.Errorf("hub drop total: expected 400+, got %d", got)
	}
	if got := d.queueDepth(); got != eventExportQueueCap {
		t.Errorf("queue depth: expected the queue parked at its cap of %d, got %d", eventExportQueueCap, got)
	}
}

// ---------------------------------------------------------------------------
// jsonl destination

// TestJSONLDestinationAppendAndLineShape: every published event must land in
// the file as exactly one valid JSON line carrying the eventHeader shape,
// regardless of type.
func TestJSONLDestinationAppendAndLineShape(t *testing.T) {
	hub := newEventHub()
	path := filepath.Join(t.TempDir(), "events.jsonl")
	d, err := newJSONLDestination(eventDestinationConfig{Type: "jsonl", Path: path}, hub)
	if err != nil {
		t.Fatalf("destination refused a valid config: %v", err)
	}
	go d.run()
	defer d.stop()

	hub.publishTunnelOpen("https://file.ngrok.io", "https")
	hub.publishAuthReject(reasonInvalidToken)

	var lines []string
	waitFor(t, "two lines in the jsonl file", func() bool {
		content, err := os.ReadFile(path)
		if err != nil {
			return false
		}
		lines = strings.Split(strings.TrimRight(string(content), "\n"), "\n")
		return len(lines) == 2
	})

	var first struct {
		Type string `json:"type"`
		At   string `json:"at"`
		URL  string `json:"url"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatalf("line 1 is not valid JSON: %v\n%s", err, lines[0])
	}
	if first.Type != "tunnel_open" || first.URL != "https://file.ngrok.io" || first.At == "" {
		t.Errorf("line 1 missing the eventHeader shape: %+v", first)
	}

	var second struct {
		Type   string `json:"type"`
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal([]byte(lines[1]), &second); err != nil {
		t.Fatalf("line 2 is not valid JSON: %v\n%s", err, lines[1])
	}
	if second.Type != "auth_reject" || second.Reason != reasonInvalidToken {
		t.Errorf("line 2: expected auth_reject/invalid_token, got %s/%s", second.Type, second.Reason)
	}

	if got := d.droppedCount(); got != 0 {
		t.Errorf("a healthy run must not drop events, got %d dropped", got)
	}
}

// TestJSONLDestinationReopensAndRecreatesFile is the reopen path: a handle
// that goes bad (log rotation closed it, the file was removed underneath us)
// must not end the destination. The next write fails, the handle is
// abandoned, and the fresh open -- O_CREATE, no O_TRUNC -- recreates the file
// and the stream continues with nothing counted lost.
func TestJSONLDestinationReopensAndRecreatesFile(t *testing.T) {
	hub := newEventHub()
	path := filepath.Join(t.TempDir(), "events.jsonl")
	d, err := newJSONLDestination(eventDestinationConfig{Type: "jsonl", Path: path}, hub)
	if err != nil {
		t.Fatalf("destination refused a valid config: %v", err)
	}
	go d.run()
	defer d.stop()

	hub.publishTunnelOpen("https://before.ngrok.io", "https")
	waitFor(t, "the first line", func() bool {
		_, err := os.Stat(path)
		return err == nil
	})

	// Kill the handle the way a log rotator would, and take the file with it.
	d.mu.Lock()
	_ = d.file.Close()
	_ = os.Remove(path)
	d.mu.Unlock()

	hub.publishTunnelOpen("https://after.ngrok.io", "https")

	var content string
	waitFor(t, "the file to be recreated with the next event", func() bool {
		data, err := os.ReadFile(path)
		if err != nil {
			return false
		}
		content = string(data)
		return strings.Contains(content, "after.ngrok.io")
	})

	if strings.Contains(content, "before.ngrok.io") {
		t.Errorf("the recreated file contains the removed file's contents:\n%s", content)
	}
	if n := strings.Count(content, "\n"); n != 1 {
		t.Errorf("expected exactly one line after recreation, got %d:\n%s", n, content)
	}
	if got := d.droppedCount(); got != 0 {
		t.Errorf("the reopen path must not lose events, got %d dropped", got)
	}
}

// TestJSONLDestinationOpenFailureIsCounted pins the other side of the jsonl
// contract: when the file cannot be opened at all, the events that arrive
// during the backoff are counted lost -- not silently vanished, not
// accumulated in memory.
func TestJSONLDestinationOpenFailureIsCounted(t *testing.T) {
	hub := newEventHub()
	// A path whose parent does not exist cannot be opened.
	path := filepath.Join(t.TempDir(), "missing-dir", "events.jsonl")
	d, err := newJSONLDestination(eventDestinationConfig{Type: "jsonl", Path: path}, hub)
	if err != nil {
		t.Fatalf("destination refused a valid config: %v", err)
	}
	d.retryStart = time.Second // hold opens apart; every event in the window is lost
	go d.run()
	defer d.stop()

	for i := 0; i < 5; i++ {
		hub.publishTunnelOpen(fmt.Sprintf("https://lost-%d.ngrok.io", i), "https")
	}

	// The counting happens on the drain goroutine, so it is eventual like
	// every other destination assertion.
	waitFor(t, "all 5 events to be counted lost", func() bool {
		return d.droppedCount() == 5
	})
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("no file should exist for a destination that never opened, stat err: %v", err)
	}
}

// ---------------------------------------------------------------------------
// config

// TestEventDestinationsConfigAccepted is the accept side of strict decoding:
// a well-formed destination list loads, and every field survives into the
// struct the destination constructors will read.
func TestEventDestinationsConfigAccepted(t *testing.T) {
	configPath := writeServerConfig(t, `
event_destinations:
  - type: http
    url: https://collector.example/ngrok
    auth_header: "Authorization: Bearer xyz"
    batch_size: 25
    flush_interval: 2s
  - type: jsonl
    path: /var/log/ngrok/events.jsonl
`)

	cfg, err := loadServerConfig(configPath)
	if err != nil {
		t.Fatalf("a valid event_destinations list failed to load: %v", err)
	}
	if len(cfg.EventDestinations) != 2 {
		t.Fatalf("expected 2 destinations, got %d", len(cfg.EventDestinations))
	}
	http_ := cfg.EventDestinations[0]
	if http_.Type != "http" || http_.URL != "https://collector.example/ngrok" ||
		http_.AuthHeader != "Authorization: Bearer xyz" || http_.BatchSize != 25 || http_.FlushInterval != "2s" {
		t.Errorf("http destination did not round-trip: %+v", http_)
	}
	jsonl := cfg.EventDestinations[1]
	if jsonl.Type != "jsonl" || jsonl.Path != "/var/log/ngrok/events.jsonl" {
		t.Errorf("jsonl destination did not round-trip: %+v", jsonl)
	}
}

// TestEventDestinationsConfigDefaults covers the optional keys: an http
// destination with only url and auth_header is accepted, and the defaults are
// applied by the constructor (batch 100, flush 5s), not by the config layer,
// which stays a faithful image of the file.
func TestEventDestinationsConfigDefaults(t *testing.T) {
	configPath := writeServerConfig(t, `
event_destinations:
  - type: http
    url: https://collector.example/ngrok
`)
	cfg, err := loadServerConfig(configPath)
	if err != nil {
		t.Fatalf("a minimal http destination failed to load: %v", err)
	}
	d, err := newHTTPDestination(cfg.EventDestinations[0], newEventHub())
	if err != nil {
		t.Fatalf("constructor refused a valid minimal config: %v", err)
	}
	defer d.stop()
	if d.batchSize != defaultEventBatchSize {
		t.Errorf("batch_size default: expected %d, got %d", defaultEventBatchSize, d.batchSize)
	}
	if d.flushEvery != defaultEventFlushEvery {
		t.Errorf("flush_interval default: expected %v, got %v", defaultEventFlushEvery, d.flushEvery)
	}
}

// TestEventDestinationsConfigRefusals is the refuse side: every malformed
// destination fails the load loudly, naming the entry, because a destination
// that half-loads is an operator who believes events are being shipped when
// they are not.
func TestEventDestinationsConfigRefusals(t *testing.T) {
	cases := []struct {
		name    string
		yaml    string
		wantErr string // substring of the expected error
	}{
		{
			name:    "unknown type",
			yaml:    "event_destinations:\n  - type: kafka\n    url: https://x.example\n",
			wantErr: `unknown type "kafka"`,
		},
		{
			name:    "http without url",
			yaml:    "event_destinations:\n  - type: http\n",
			wantErr: "type http requires url",
		},
		{
			name:    "jsonl without path",
			yaml:    "event_destinations:\n  - type: jsonl\n",
			wantErr: "type jsonl requires path",
		},
		{
			name:    "negative batch size",
			yaml:    "event_destinations:\n  - type: http\n    url: https://x.example\n    batch_size: -5\n",
			wantErr: "batch_size must be positive",
		},
		{
			name:    "zero flush interval",
			yaml:    "event_destinations:\n  - type: http\n    url: https://x.example\n    flush_interval: 0s\n",
			wantErr: "flush_interval must be positive",
		},
		{
			name:    "unparseable flush interval",
			yaml:    "event_destinations:\n  - type: http\n    url: https://x.example\n    flush_interval: banana\n",
			wantErr: "flush_interval",
		},
		{
			name:    "auth header without a colon",
			yaml:    "event_destinations:\n  - type: http\n    url: https://x.example\n    auth_header: Bearer-xyz\n",
			wantErr: `auth_header must be "Name: value"`,
		},
		{
			name:    "auth header with CR/LF",
			yaml:    "event_destinations:\n  - type: http\n    url: https://x.example\n    auth_header: \"Authorization: Bearer x\\nX-Evil: y\"\n",
			wantErr: "CR or LF",
		},
		{
			name:    "jsonl with http keys",
			yaml:    "event_destinations:\n  - type: jsonl\n    path: /tmp/e.jsonl\n    url: https://x.example\n",
			wantErr: "takes only path",
		},
		{
			name:    "misspelled key inside a destination",
			yaml:    "event_destinations:\n  - type: http\n    url: https://x.example\n    flushinterval: 5s\n",
			wantErr: "flushinterval",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			configPath := writeServerConfig(t, c.yaml)
			_, err := loadServerConfig(configPath)
			if err == nil {
				t.Fatalf("expected the load to fail, it succeeded")
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("expected the error to name %q, got: %v", c.wantErr, err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// boot wiring and /metrics surfacing

// TestStartEventExportWiresDestinations: the boot path builds one destination
// per config entry, registers it for /metrics with the right kind and target,
// and stopEventExport tears the registration down. It also pins that an empty
// list starts nothing -- the no-config behavior must be byte-identical to
// before (review gate 6).
func TestStartEventExportWiresDestinations(t *testing.T) {
	if got := len(exportedDestinationStats()); got != 0 {
		t.Fatalf("a fresh process has no destinations, got %d (a prior test leaked)", got)
	}

	path := filepath.Join(t.TempDir(), "events.jsonl")
	startEventExport([]eventDestinationConfig{
		{Type: "http", URL: "https://collector.example/ngrok", AuthHeader: "Authorization: Bearer x"},
		{Type: "jsonl", Path: path},
	})

	stats := exportedDestinationStats()
	if len(stats) != 2 {
		t.Fatalf("expected 2 registered destinations, got %d", len(stats))
	}
	if stats[0]["type"] != "http" || stats[0]["target"] != "https://collector.example/ngrok" {
		t.Errorf("http destination not surfaced correctly: %v", stats[0])
	}
	if stats[1]["type"] != "jsonl" || stats[1]["target"] != path {
		t.Errorf("jsonl destination not surfaced correctly: %v", stats[1])
	}

	stopEventExport()
	if got := len(exportedDestinationStats()); got != 0 {
		t.Errorf("stopEventExport left %d destinations registered", got)
	}
}

// TestMetricsSurfacesEventCounters walks the real admin handler (the same
// route table startAdminServer serves): the drop counters and destination
// rows must be in the /metrics payload, and the prometheus text must carry
// the counter -- review gate 5, "drop counters observable in /metrics".
func TestMetricsSurfacesEventCounters(t *testing.T) {
	// Produce a known drop on the global hub the admin handler reads: a
	// one-slot subscriber that never drains.
	stalled := observe.events.subscribeBuffered(1)
	defer observe.events.unsubscribe(stalled)
	observe.events.publishTunnelClose("metrics-probe-a")
	observe.events.publishTunnelClose("metrics-probe-b")
	if got := stalled.dropped.Load(); got == 0 {
		t.Fatal("the probe produced no drop; the assertions below would prove nothing")
	}

	srv := httptest.NewServer(adminHandler(false, nil, 0))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/metrics")
	if err != nil {
		t.Fatalf("/metrics: %v", err)
	}
	defer resp.Body.Close()
	var payload map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("/metrics is not JSON: %v", err)
	}

	drops, _ := payload["event_drop_count"].(float64)
	if drops < 1 {
		t.Errorf("event_drop_count: expected the probe's drop to be observable, got %v", payload["event_drop_count"])
	}
	subs, _ := payload["event_subscribers"].(float64)
	if subs < 1 {
		t.Errorf("event_subscribers: expected the stalled probe to be counted, got %v", payload["event_subscribers"])
	}
	if _, ok := payload["event_destinations"].([]interface{}); !ok {
		t.Errorf("event_destinations: expected an array (possibly empty), got %T", payload["event_destinations"])
	}

	presp, err := http.Get(srv.URL + "/metrics/prometheus")
	if err != nil {
		t.Fatalf("/metrics/prometheus: %v", err)
	}
	defer presp.Body.Close()
	prom, _ := io.ReadAll(presp.Body)
	if !strings.Contains(string(prom), "ngrokd_event_drop_count") {
		t.Errorf("prometheus output does not carry the event drop counter:\n%s", prom)
	}
}
