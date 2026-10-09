package server

// Tests for the server half of carrier_dedup (SPEC-CLUSTER21): the wrap site
// in registerProxyStream (codec installed pass-through, or not at all), the
// ack-then-engage order in HandlePublicConnection (the ack is on the wire
// before the codec encodes a byte), and the kill switch.
//
// Like the mux tests, everything here is in-process: the smux session runs
// over a net.Pipe pair, the server end goes through the real registerProxyStream,
// and the client end of each stream is driven by hand -- including its own
// codec, engaged after reading the StartProxy ack exactly the way the real
// client's flip point works. That hand-driven peer is what makes the ordering
// observable: the test reads the ack as RAW msg frames (an early engagement
// would have framed them) and feeds frames back immediately, before the
// server's join can be assumed to have started reading.

import (
	"bytes"
	"io"
	"math/rand"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ngrok/conn"
	"ngrok/dedup"
	"ngrok/log"
	"ngrok/msg"

	"github.com/xtaci/smux/v2"
)

// ---------------------------------------------------------------------------
// fixtures

// dedupStreamFixture is one proxy stream whose RegProxy proposed carrier_dedup,
// as both ends see it: what the pool received, and the client's RAW end of the
// stream (the test wraps it with its own codec after the ack, the way the
// client's conn.Wrap site does). streamConn is that same raw end carrying a
// test-side logger, so msg reads have the conn.Conn they ask for.
type dedupStreamFixture struct {
	ctl        *Control
	sess       *smux.Session
	proxyConn  conn.Conn
	stream     net.Conn
	streamConn conn.Conn
}

// newDedupStreamFixture opens one mux session to a fresh control and registers
// one proxy stream on it whose RegProxy carries Dedup: true.
func newDedupStreamFixture(t *testing.T, clientId string) *dedupStreamFixture {
	t.Helper()

	reg := setupTestControlRegistry(t)
	ctl := muxTestControl(t, reg, clientId)

	sess := muxTestPair(t, clientId)

	stream, err := sess.OpenStream()
	if err != nil {
		t.Fatalf("failed to open a proxy stream: %v", err)
	}

	regConn := conn.Wrap(stream, "pxy")
	t.Cleanup(func() { regConn.Close() })

	if err := msg.WriteMsg(regConn, &msg.RegProxy{ClientId: clientId, Secret: testSessionSecret(clientId), Dedup: true}); err != nil {
		t.Fatalf("failed to register the proxy stream: %v", err)
	}

	return &dedupStreamFixture{ctl: ctl, sess: sess, proxyConn: waitForProxy(t, ctl), stream: stream, streamConn: regConn}
}

// setCarrierDedupDisabled flips the kill switch for one test and restores it
// afterwards -- the same save/restore shape quic_test.go uses for quicServing.
func setCarrierDedupDisabled(t *testing.T, v bool) {
	t.Helper()

	prev := carrierDedupDisabled.Load()
	t.Cleanup(func() { carrierDedupDisabled.Store(prev) })
	carrierDedupDisabled.Store(v)
}

// captureServerLog points the server's logger at a file for the test's
// duration and returns the file's path. Server tests run sequentially (no
// t.Parallel in this package), so replacing the global logger is the
// established convention here (portclaims_test.go, security_test.go).
func captureServerLog(t *testing.T) string {
	t.Helper()

	logFile := filepath.Join(t.TempDir(), "server.log")
	log.LogTo(logFile, "DEBUG", "text")
	return logFile
}

// dedupTestBlock is a deterministic pseudo-random block: bytes whose chunk
// boundaries the CDC cuts the same way every time it sees them, which is what
// makes the repetition in the round-trip test produce REF frames on the second
// identical write.
func dedupTestBlock(t *testing.T, n int) []byte {
	t.Helper()

	rng := rand.New(rand.NewSource(1))
	block := make([]byte, n)
	if _, err := rng.Read(block); err != nil {
		t.Fatalf("failed to build the test block: %v", err)
	}
	return block
}

// ---------------------------------------------------------------------------
// negotiation and ordering

// TestCarrierDedupProposalIsFlaggedForAckButStaysRawUntilIt covers the wrap
// site's two promises: a stream whose RegProxy proposed dedup pools a
// dedupProxyConn (so the ack site can find its codec), and the codec is
// PASS-THROUGH at registration -- the StartProxy ack written through the
// pooled conn arrives as plain msg frames, which it would not if the wrap
// site had installed the codec encoding.
func TestCarrierDedupProposalIsFlaggedForAckButStaysRawUntilIt(t *testing.T) {
	f := newDedupStreamFixture(t, "client-dedup")

	dc, ok := f.proxyConn.(*dedupProxyConn)
	if !ok {
		t.Fatalf("a stream that proposed dedup pooled a %T, want *dedupProxyConn", f.proxyConn)
	}
	if dc.codec == nil {
		t.Fatal("the pooled dedup conn carries no codec")
	}

	// The ack, written the way HandlePublicConnection writes it, crosses raw:
	// the client's plain msg read -- no codec on its side either -- decodes it.
	want := msg.StartProxy{Url: "http://dedup.ngrok.test", ClientAddr: "203.0.113.7:6000", DedupAck: true}
	if err := msg.WriteMsg(f.proxyConn, &want); err != nil {
		t.Fatalf("failed to write StartProxy through the pooled conn: %v", err)
	}

	f.stream.SetReadDeadline(time.Now().Add(5 * time.Second))
	var got msg.StartProxy
	if err := msg.ReadMsgInto(f.streamConn, &got); err != nil {
		t.Fatalf("StartProxy did not arrive raw on the stream: %v", err)
	}
	f.stream.SetReadDeadline(time.Time{})

	if got != want {
		t.Fatalf("StartProxy on the stream = %+v, want %+v", got, want)
	}
}

// TestCarrierDedupAckWrittenBeforeEngageAndFramesRoundTrip is the ordering pin
// (SPEC-CLUSTER21 review gate 3) and the server-side transparency proof in one.
//
// The real HandlePublicConnection serves a public connection over the pooled
// dedup stream. The test's hand-driven client reads the ack as raw frames
// (proving the server encoded nothing before the ack was on the wire), then
// engages its own codec and feeds frames back IMMEDIATELY -- before the
// server's join could be assumed to be reading -- and the server reassembles
// them exactly. The request direction proves the engaged server encodes:
// a payload written twice crosses the second time as REF frames, and the
// client's codec reassembles the exact bytes.
func TestCarrierDedupAckWrittenBeforeEngageAndFramesRoundTrip(t *testing.T) {
	logFile := captureServerLog(t)

	setupTestRegistry(t) // tunnelRegistry, for registerTestTunnel
	f := newDedupStreamFixture(t, "client-dedup-order")

	dc, ok := f.proxyConn.(*dedupProxyConn)
	if !ok {
		t.Fatalf("a stream that proposed dedup pooled a %T, want *dedupProxyConn", f.proxyConn)
	}

	// Hand the conn back so HandlePublicConnection's GetProxy finds it: the
	// pool is a plain channel, and the test already held the conn out. But
	// first, wait for the registration to have fully finished: RegisterProxy
	// logs "Registered" on the conn AFTER the channel send, and the handout
	// below AddLogPrefixes the same conn -- two unsynchronized accesses to the
	// prefix logger's field. The log line is written after the read in
	// question, so seeing it proves the registration goroutine is done with
	// the conn. (The window exists in production too -- a GetProxy blocked on
	// the channel wakes on the send -- but only this test's immediate re-serve
	// makes it deterministic; the prefix field itself is not this lane's to
	// fix.)
	waitForFileMarker(t, logFile, "Registered")
	f.ctl.proxies <- f.proxyConn

	tun := registerTestTunnel(t, f.ctl, msg.ReqTunnel{Protocol: "tcp"})

	// The public leg is a net.Pipe rather than a TCP pair ON PURPOSE: a pipe
	// delivers one Write at a time, and this test's REF assertion needs the
	// two identical blocks to arrive at the codec as two Writes. The chunker
	// starts a fresh boundary scan on every Write (dedup/chunker.go), so
	// repetition only resolves to references when the copies arrive with the
	// same segmentation -- which is exactly how the real win shows up too (the
	// repeated prompt arrives once per request write). A TCP leg would
	// coalesce back-to-back writes and the assertion would flake on timing.
	publicClient, publicServer := net.Pipe()
	t.Cleanup(func() { publicClient.Close() })

	served := make(chan struct{})
	go func() {
		defer close(served)
		tun.HandlePublicConnection(conn.Wrap(publicServer, "pub"), nil)
	}()

	// The ack: raw msg frames on the wire, with DedupAck set. If the server
	// engaged its codec before writing this, these bytes arrive framed and
	// the read below fails -- that is the ordering being pinned.
	f.stream.SetReadDeadline(time.Now().Add(5 * time.Second))
	var startPxy msg.StartProxy
	if err := msg.ReadMsgInto(f.streamConn, &startPxy); err != nil {
		t.Fatalf("StartProxy did not arrive raw on the stream: %v", err)
	}
	if !startPxy.DedupAck {
		t.Fatal("StartProxy acked a dedup proposal without setting DedupAck")
	}

	// The client's flip point: engage only after reading the ack.
	clientCodec := dedup.NewPassThrough(f.stream)
	clientCodec.Engage()

	// Frames fed immediately after the ack -- the join's read side may not
	// even be running yet. They wait in the stream and must be reassembled,
	// not raced: an unengaged server read would see frame headers as data.
	response := []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	if _, err := clientCodec.Write(response); err != nil {
		t.Fatalf("failed to write the response frames: %v", err)
	}

	// The request direction: the same block written twice, as two Writes --
	// see the net.Pipe note above for why the segmentation is part of the
	// test. The second copy is where the table pays off and the chunks cross
	// as REFs.
	const blockSize = 12 * 1024
	block := dedupTestBlock(t, blockSize)
	request := append(append([]byte{}, block...), block...)

	// The agent side: read the request through its codec (reassembled) and
	// leave the stream to the join.
	agentDone := make(chan []byte, 1)
	go func() {
		got := make([]byte, len(request))
		_, err := io.ReadFull(clientCodec, got)
		agentDone <- got
		if err != nil {
			t.Errorf("the agent's codec never reassembled the request: %v", err)
		}
	}()

	publicClient.SetDeadline(time.Now().Add(10 * time.Second))
	for _, w := range [][]byte{block, block} {
		if _, err := publicClient.Write(w); err != nil {
			t.Fatalf("failed to write the request to the public end: %v", err)
		}
	}

	gotResponse := make([]byte, len(response))
	if _, err := io.ReadFull(publicClient, gotResponse); err != nil {
		t.Fatalf("the response frames were not reassembled to the public end: %v", err)
	}
	if !bytes.Equal(gotResponse, response) {
		t.Fatal("the response the public end received is not the bytes the agent wrote")
	}

	select {
	case got := <-agentDone:
		if !bytes.Equal(got, request) {
			t.Fatal("the request the agent's codec reassembled is not the bytes the visitor wrote")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the agent never received the request")
	}

	// Close the public end: the join unwinds, HandlePublicConnection returns,
	// and the close line is written at the join's teardown.
	publicClient.Close()

	select {
	case <-served:
	case <-time.After(10 * time.Second):
		t.Fatal("HandlePublicConnection never returned")
	}

	// The counters, read off the codec the test held: the write direction of
	// the server's codec is what it encoded toward the agent -- the request,
	// twice the block, and the second copy crossed as references. Framed
	// landing BELOW offered is the win number doing what the close line
	// reports: the repeated block cost a fraction of its bytes on the wire.
	if got := dc.codec.Offered(); got != uint64(len(request)) {
		t.Fatalf("offered = %d, want %d (the request bytes the codec accepted)", got, len(request))
	}
	if got := dc.codec.Framed(); got == 0 || got >= dc.codec.Offered() {
		t.Fatalf("framed = %d with offered = %d: the repeated block did not shrink on the wire", got, dc.codec.Offered())
	}
	if got := dc.codec.Refs(); got == 0 {
		t.Fatal("the repeated block produced no REF frames: the table never paid off")
	}

	// The close line (SPEC-CLUSTER21 §5), at the join's teardown: offered,
	// framed and refs on one line, the honest win number.
	content := waitForFileMarker(t, logFile, "carrier_dedup: offered=")
	if !strings.Contains(content, "framed=") || !strings.Contains(content, "refs=") {
		t.Fatalf("the close line is missing its figures:\n%s", content)
	}
}

// ---------------------------------------------------------------------------
// the kill switch

// TestCarrierDedupKillSwitchStopsTheAck is the big red lever (SPEC-CLUSTER21
// §4): with -disableCarrierDedup set, a stream that proposes dedup pools a
// PLAIN conn -- no codec installed -- the ack stays unset, the bytes cross
// unframed, and nothing per stream is logged about dedup at all.
func TestCarrierDedupKillSwitchStopsTheAck(t *testing.T) {
	logFile := captureServerLog(t)
	setCarrierDedupDisabled(t, true)

	f := newDedupStreamFixture(t, "client-dedup-kill")

	if _, ok := f.proxyConn.(*dedupProxyConn); ok {
		t.Fatal("the kill switch left the codec installed: a disabled feature must pool a plain conn")
	}

	// The proposal goes unacked, and the ack crosses raw.
	if err := msg.WriteMsg(f.proxyConn, &msg.StartProxy{Url: "http://kill.ngrok.test", ClientAddr: "203.0.113.7:7000"}); err != nil {
		t.Fatalf("failed to write StartProxy: %v", err)
	}

	f.stream.SetReadDeadline(time.Now().Add(5 * time.Second))
	var got msg.StartProxy
	if err := msg.ReadMsgInto(f.streamConn, &got); err != nil {
		t.Fatalf("StartProxy did not arrive on the stream: %v", err)
	}
	f.stream.SetReadDeadline(time.Time{})
	if got.DedupAck {
		t.Fatal("StartProxy confirmed a dedup proposal while the kill switch was set")
	}

	// And the stream is a byte pipe, not a framed one: what the server writes
	// arrives byte for byte, no frame headers around it.
	passThrough := "plain bytes, no framing"
	if _, err := io.WriteString(f.proxyConn, passThrough); err != nil {
		t.Fatalf("failed to write through the pooled conn: %v", err)
	}
	raw := make([]byte, len(passThrough))
	if _, err := io.ReadFull(f.stream, raw); err != nil {
		t.Fatalf("the pass-through bytes did not arrive: %v", err)
	}
	if string(raw) != passThrough {
		t.Fatalf("the stream carried %q, want the exact %q", raw, passThrough)
	}

	// Zero log noise per stream: nothing on this path names the feature. The
	// marker waited on is the pool registration line -- the one Info line a
	// registering stream does log, proving the log is live while the dedup
	// paths stay silent.
	if content := waitForFileMarker(t, logFile, "Registered"); strings.Contains(content, "carrier_dedup") {
		t.Fatalf("a killed-carrier stream logged dedup noise:\n%s", content)
	}
}

// TestCarrierDedupAbsentProposalStaysPassThrough covers the other arm of the
// wrap site's decision: a stream whose RegProxy does not propose dedup -- an
// old client, or a tunnel without the key -- pools a plain conn and would
// never be acked, whatever the kill switch is doing.
func TestCarrierDedupAbsentProposalStaysPassThrough(t *testing.T) {
	f := newMuxStreamFixture(t, "client-nodedup")

	if _, ok := f.proxyConn.(*dedupProxyConn); ok {
		t.Fatal("a stream that did not propose dedup pooled a dedup conn")
	}
}
