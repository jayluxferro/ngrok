package server

// Tests for the carrier_dedup telemetry surfaces (SPEC-CLUSTER23): the
// observabilityStore method that folds a finished stream's codec counters
// into the tunnel snapshot and the globals, and the three admin surfaces
// those numbers appear on (/tunnels snapshots, /metrics JSON, prometheus).
//
// The codec itself is exercised only as a black box here -- dedup/'s own
// tests pin its counter arithmetic -- so what this file owns is the folding
// and the surfacing: exact sums, the once-per-stream lock discipline under
// -race, and the JSON/prometheus names an operator's queries will spell.

import (
	"bytes"
	"encoding/json"
	"io"
	"math/rand"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"ngrok/dedup"
	"ngrok/msg"
)

// dedupTelConn is a net.Conn over a byte reader plus a recording writer --
// dedup's own memConn scaffolding, re-declared because that one is
// package-private. Single-goroutine except in the concurrency test, where
// every goroutine owns its conn outright.
type dedupTelConn struct {
	r io.Reader
	w bytes.Buffer
}

func (c *dedupTelConn) Read(p []byte) (int, error)         { return c.r.Read(p) }
func (c *dedupTelConn) Write(p []byte) (int, error)        { return c.w.Write(p) }
func (c *dedupTelConn) Close() error                       { return nil }
func (c *dedupTelConn) LocalAddr() net.Addr                { return nil }
func (c *dedupTelConn) RemoteAddr() net.Addr               { return nil }
func (c *dedupTelConn) SetDeadline(t time.Time) error      { return nil }
func (c *dedupTelConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *dedupTelConn) SetWriteDeadline(t time.Time) error { return nil }

// drivenDedupCodec returns an engaged codec that has WRITTEN write (its
// offered/framed/refs are final) and, when readWire is non-empty, read
// readWire to its end -- a clean boundary EOF, or a hard error if the wire
// is truncated or malformed, which is exactly the spread the fold has to
// handle. The result is a codec in its teardown state, ready for
// onDedupClose.
func drivenDedupCodec(t *testing.T, write, readWire []byte) *dedup.Conn {
	t.Helper()

	inner := &dedupTelConn{r: bytes.NewReader(readWire)}
	c := dedup.NewEngaged(inner)
	if len(write) > 0 {
		if _, err := c.Write(write); err != nil {
			t.Fatalf("codec write: %v", err)
		}
	}
	if len(readWire) > 0 {
		buf := make([]byte, 32*1024)
		for {
			if _, err := c.Read(buf); err != nil {
				break // clean EOF at the boundary, or the sticky desync
			}
		}
	}
	return c
}

// dedupTelWire frames body twice through a throwaway codec and returns the
// wire bytes: the second identical copy crosses as REF frames, so a reader
// of this wire exercises the reference-resolution half of the read path,
// not just literals.
func dedupTelWire(t *testing.T, body []byte) []byte {
	t.Helper()

	inner := &dedupTelConn{r: strings.NewReader("")}
	w := dedup.NewEngaged(inner)
	for i := 0; i < 2; i++ {
		if _, err := w.Write(body); err != nil {
			t.Fatalf("wire fixture write %d: %v", i, err)
		}
	}
	return append([]byte(nil), inner.w.Bytes()...)
}

// dedupTelGlobals reads the seven dedup globals as one struct, so delta
// assertions read as one line instead of seven.
type dedupTelGlobals struct{ offered, framed, refs, desyncs, readWire, readPayload, streams uint64 }

func readDedupTelGlobals() dedupTelGlobals {
	return dedupTelGlobals{
		offered:     dedupOfferedTotal.Load(),
		framed:      dedupFramedTotal.Load(),
		refs:        dedupRefsTotal.Load(),
		desyncs:     dedupDesyncsTotal.Load(),
		readWire:    dedupReadWireTotal.Load(),
		readPayload: dedupReadPayloadTotal.Load(),
		streams:     dedupStreamsTotal.Load(),
	}
}

// ---------------------------------------------------------------------------
// the fold

// TestOnDedupCloseFoldsIntoSnapshotAndGlobals pins the arithmetic of the
// aggregation: one finished stream's six counters land in the tunnel's
// snapshot fields exactly, the seven globals move by exactly that stream's
// contribution (deltas, because the globals are process-wide and other
// tests' streams legitimately share them), a second stream ACCUMULATES, and
// a stream whose tunnel row is already gone still counts in the globals.
func TestOnDedupCloseFoldsIntoSnapshotAndGlobals(t *testing.T) {
	o := testStore()
	const url = "http://dedup-fold.test"
	o.tunnels[url] = &tunnelSnapshot{URL: url}
	tun := &Tunnel{url: url, req: &msg.ReqTunnel{Protocol: "http"}}

	body := make([]byte, 12*1024)
	if _, err := rand.New(rand.NewSource(7)).Read(body); err != nil {
		t.Fatal(err)
	}
	wire := dedupTelWire(t, body)
	response := []byte("HTTP/1.1 200 OK\r\n\r\nok") // the server's write direction

	before := readDedupTelGlobals()
	c := drivenDedupCodec(t, response, wire)
	o.onDedupClose(tun, c)
	after := readDedupTelGlobals()

	s := o.tunnels[url]
	if s.DedupOffered != uint64(len(response)) {
		t.Errorf("snapshot dedup_offered = %d, want %d", s.DedupOffered, len(response))
	}
	if s.DedupFramed != c.Framed() {
		t.Errorf("snapshot dedup_framed = %d, want the codec's %d", s.DedupFramed, c.Framed())
	}
	if s.DedupRefs != 0 {
		t.Errorf("snapshot dedup_refs = %d, want 0 (one fresh response, nothing to reference)", s.DedupRefs)
	}
	if s.DedupDesyncs != 0 {
		t.Errorf("snapshot dedup_desyncs = %d, want 0 (the wire is clean)", s.DedupDesyncs)
	}
	if s.DedupReadWire != uint64(len(wire)) {
		t.Errorf("snapshot dedup_read_wire = %d, want %d (every wire byte, headers included)",
			s.DedupReadWire, len(wire))
	}
	if s.DedupReadPayload != 2*uint64(len(body)) {
		t.Errorf("snapshot dedup_read_payload = %d, want %d (two copies decoded)",
			s.DedupReadPayload, 2*len(body))
	}
	if s.DedupStreams != 1 {
		t.Errorf("snapshot dedup_streams = %d, want 1", s.DedupStreams)
	}

	if d := after.offered - before.offered; d != uint64(len(response)) {
		t.Errorf("global offered delta = %d, want %d", d, len(response))
	}
	if d := after.readWire - before.readWire; d != uint64(len(wire)) {
		t.Errorf("global read_wire delta = %d, want %d -- the agent-encoded direction is the half the write counters never saw", d, len(wire))
	}
	if d := after.streams - before.streams; d != 1 {
		t.Errorf("global streams delta = %d, want 1", d)
	}

	// A second stream on the same tunnel accumulates; and a DESYNCED stream
	// folds too -- truncation is a death the counters must book, with the
	// wire bytes that crossed before it recorded rather than discarded.
	before = readDedupTelGlobals()
	o.onDedupClose(tun, drivenDedupCodec(t, nil, nil)) // engaged but idle: still an engaged stream
	o.onDedupClose(tun, drivenDedupCodec(t, nil, wire[:len(wire)/2]))
	after = readDedupTelGlobals()

	if s.DedupStreams != 3 {
		t.Errorf("dedup_streams after three streams = %d, want 3", s.DedupStreams)
	}
	if s.DedupDesyncs != 1 {
		t.Errorf("dedup_desyncs = %d, want 1 (the truncated stream)", s.DedupDesyncs)
	}
	if s.DedupReadWire < uint64(len(wire)) {
		t.Errorf("dedup_read_wire = %d: a truncated stream's consumed bytes were discarded", s.DedupReadWire)
	}
	if d := after.streams - before.streams; d != 2 {
		t.Errorf("global streams delta over the two closes = %d, want 2", d)
	}

	// The asymmetry the method documents: the tunnel row is deleted (the
	// deregistration lost the race with this stream's teardown), and the
	// globals must still move by one engaged stream.
	o.mu.Lock()
	delete(o.tunnels, url)
	o.mu.Unlock()
	before = readDedupTelGlobals()
	o.onDedupClose(tun, drivenDedupCodec(t, response, nil))
	after = readDedupTelGlobals()
	if d := after.streams - before.streams; d != 1 {
		t.Errorf("global streams delta for a snapshot-less stream = %d, want 1 (totals must not drop streams)", d)
	}
}

// TestOnDedupCloseConcurrentStreamsUnderRace drives the fold the way
// production does: many streams tearing down at once, each on its own
// goroutine, while the sampler-shaped readers load the store lock from the
// other side. -race is the assertion about the lock discipline; the exact
// sums afterwards are the assertion that no stream's contribution was lost.
func TestOnDedupCloseConcurrentStreamsUnderRace(t *testing.T) {
	o := testStore()
	const url = "http://dedup-race.test"
	o.tunnels[url] = &tunnelSnapshot{URL: url}
	tun := &Tunnel{url: url, req: &msg.ReqTunnel{Protocol: "http"}}

	const streams = 16
	var offered, readWire uint64
	var wg sync.WaitGroup
	for i := 0; i < streams; i++ {
		body := make([]byte, 8*1024+i)
		if _, err := rand.New(rand.NewSource(int64(i))).Read(body); err != nil {
			t.Fatal(err)
		}
		wire := dedupTelWire(t, body)
		offered += uint64(len(body))
		readWire += uint64(len(wire))
		codec := drivenDedupCodec(t, nil, wire)
		wg.Add(1)
		go func() {
			defer wg.Done()
			o.onDedupClose(tun, codec)
		}()
	}
	// Concurrent readers: snapshots() takes the same lock the fold does, so
	// the race detector sees both sides of every handoff.
	var readers sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 2; i++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = o.snapshots()
				}
			}
		}()
	}

	wg.Wait()
	close(stop)
	readers.Wait()

	s := o.tunnels[url]
	if s.DedupStreams != streams {
		t.Fatalf("dedup_streams = %d, want %d", s.DedupStreams, streams)
	}
	if s.DedupOffered != 0 || s.DedupReadWire != readWire {
		t.Fatalf("folded sums drifted: offered=%d (want 0, the codecs only read) read_wire=%d (want %d)",
			s.DedupOffered, s.DedupReadWire, readWire)
	}
}

// ---------------------------------------------------------------------------
// the surfaces

// TestMetricsSurfacesDedupTelemetry walks the real admin handler: the folded
// numbers must be reachable under the exact names an operator's queries will
// spell -- snake_case in the /tunnels snapshot (flowing to the workbench
// verbatim), the *_total globals in /metrics JSON, and both the global
// counters and the per-tunnel series in prometheus. Decoding /tunnels into
// a raw map on purpose: decoding into tunnelSnapshot would let a JSON-tag
// typo pass, and the tag IS the API here.
func TestMetricsSurfacesDedupTelemetry(t *testing.T) {
	tun := &Tunnel{url: "http://dedup-telemetry.test", req: &msg.ReqTunnel{Protocol: "http"}}
	observe.onTunnelOpen(tun)
	defer observe.onTunnelClose(tun)

	body := make([]byte, 6*1024)
	if _, err := rand.New(rand.NewSource(11)).Read(body); err != nil {
		t.Fatal(err)
	}
	observe.onDedupClose(tun, drivenDedupCodec(t, nil, dedupTelWire(t, body)))

	srv := newAdminTestServer(t, nil)

	// /tunnels: the seven snake_case keys, with this stream's numbers.
	resp := adminGet(t, srv, "/tunnels")
	defer resp.Body.Close()
	var payload struct {
		Tunnels []map[string]interface{} `json:"tunnels"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("/tunnels is not JSON: %v", err)
	}
	var found map[string]interface{}
	for _, tn := range payload.Tunnels {
		if tn["url"] == tun.url {
			found = tn
			break
		}
	}
	if found == nil {
		t.Fatalf("/tunnels does not carry %s", tun.url)
	}
	want := map[string]float64{
		"dedup_offered":      0, // the codec only read
		"dedup_framed":       0,
		"dedup_refs":         0,
		"dedup_desyncs":      0,
		"dedup_read_payload": 2 * float64(len(body)),
		"dedup_streams":      1,
	}
	for k, v := range want {
		got, ok := found[k].(float64)
		if !ok {
			t.Errorf("/tunnels snapshot has no numeric %s key (got %T=%v); the JSON name is the API", k, found[k], found[k])
			continue
		}
		if got != v {
			t.Errorf("/tunnels %s = %v, want %v", k, got, v)
		}
	}
	// dedup_read_wire is asserted against the wire the fixture actually
	// produced rather than a constant, and only for "moved at all": it may
	// legitimately sit BELOW dedup_read_payload -- a REF costs 10 wire
	// bytes and decodes a whole chunk, so read_wire < read_payload is the
	// win happening, not a miscount. The exact-equality version of this
	// assert lives in the fold test, against the wire length.
	rw, ok := found["dedup_read_wire"].(float64)
	if !ok {
		t.Errorf("/tunnels snapshot has no numeric dedup_read_wire key (got %T)", found["dedup_read_wire"])
	} else if rw <= 0 {
		t.Errorf("/tunnels dedup_read_wire = %v: the read direction moved no wire bytes", rw)
	}

	// /metrics JSON: the seven globals, present and numeric. Values are not
	// pinned here -- the globals are process-wide and other tests' streams
	// share them; the fold test owns the arithmetic.
	mresp := adminGet(t, srv, "/metrics")
	defer mresp.Body.Close()
	var metrics map[string]interface{}
	if err := json.NewDecoder(mresp.Body).Decode(&metrics); err != nil {
		t.Fatalf("/metrics is not JSON: %v", err)
	}
	for _, k := range []string{
		"dedup_offered_total", "dedup_framed_total", "dedup_refs_total", "dedup_desyncs_total",
		"dedup_read_wire_total", "dedup_read_payload_total", "dedup_streams_total",
	} {
		if _, ok := metrics[k].(float64); !ok {
			t.Errorf("/metrics has no numeric %s (got %T=%v)", k, metrics[k], metrics[k])
		}
	}

	// prometheus: the global counters and the per-tunnel series, HELP and
	// TYPE lines included.
	presp := adminGet(t, srv, "/metrics/prometheus")
	defer presp.Body.Close()
	prom, _ := io.ReadAll(presp.Body)
	text := string(prom)
	for _, k := range []string{
		"ngrokd_dedup_offered_total", "ngrokd_dedup_framed_total", "ngrokd_dedup_refs_total",
		"ngrokd_dedup_desyncs_total", "ngrokd_dedup_read_wire_total", "ngrokd_dedup_read_payload_total",
		"ngrokd_dedup_streams_total",
	} {
		if !strings.Contains(text, "# TYPE "+k+" counter") {
			t.Errorf("prometheus output does not declare %s as a counter:\n%s", k, text)
		}
	}
	for _, series := range []string{
		"ngrokd_tunnel_dedup_offered", "ngrokd_tunnel_dedup_framed", "ngrokd_tunnel_dedup_refs",
		"ngrokd_tunnel_dedup_desyncs", "ngrokd_tunnel_dedup_read_wire", "ngrokd_tunnel_dedup_read_payload",
		"ngrokd_tunnel_dedup_streams",
	} {
		wantLine := series + `{url="` + tun.url + `",protocol="http"} `
		if !strings.Contains(text, wantLine) {
			t.Errorf("prometheus output does not carry the per-tunnel line %s:\n%s", wantLine, text)
		}
	}
}
