package client

// Tests for the udp tunnel client path (SPEC-CLUSTER8 3.2, workstream B):
//
//	public udp client <-> framed net.Pipe <-> serveProxyConnection() <->
//	udpFlow pumps <-> connected UDP socket <-> local echo server
//
// Like the http relay's tests (model_proxy_test.go), these need neither an
// ngrokd to register with nor a control channel: the server side of the proxy
// leg is one end of a net.Pipe, and the local service is a real UDP socket,
// because "the datagram arrived whole" only means something if it crossed a
// kernel socket on the way. The framing tests are pure codec tests; the pump
// tests are the integration half.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"net"
	"testing"
	"time"

	"ngrok/client/mvc"
	"ngrok/log"
	"ngrok/msg"
	"ngrok/proto"
)

// udpEchoServer starts a real UDP echo service on 127.0.0.1 and returns its
// "host:port". Every datagram it receives is sent back to its sender, so the
// pump tests can assert a full public -> proxy -> local -> proxy -> public
// round trip without any ngrok machinery besides the flow under test.
func udpEchoServer(t *testing.T) string {
	t.Helper()

	echo, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("failed to bind the UDP echo server: %v", err)
	}
	go func() {
		buf := make([]byte, proto.MaxDatagramSize)
		for {
			n, addr, err := echo.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if _, err := echo.WriteToUDP(buf[:n], addr); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() { echo.Close() })

	return echo.LocalAddr().String()
}

// udpFlowUnderTest is one in-flight udp flow as the test drives it: public is
// the end the "server" would write framed datagrams into and read them back
// from.
type udpFlowUnderTest struct {
	public   net.Conn
	finished chan struct{}
}

// startUdpFlow registers a udp tunnel on a fresh model and starts
// serveProxyConnection, exactly as the proxy path would run it -- the same
// harness shape the agent-TLS tests use (agenttls_proxy_test.go), with a
// net.Pipe standing in for the proxy conn.
func startUdpFlow(t *testing.T, localAddr string) *udpFlowUnderTest {
	t.Helper()

	tunnel := mvc.Tunnel{
		PublicUrl: "udp://tunnel.example.com:5353",
		LocalAddr: localAddr,
		Protocol:  proto.NewUdp(),
	}

	model := &ClientModel{
		Logger:  log.NewPrefixLogger("test"),
		metrics: NewClientMetrics(),
		ctl:     &agentTLSStubController{Logger: log.NewPrefixLogger("ctl")},
		tunnels: map[string]mvc.Tunnel{tunnel.PublicUrl: tunnel},
	}

	publicEnd, serverEnd := net.Pipe()
	remoteConn := &proxyTestConn{Conn: serverEnd, Logger: log.NewPrefixLogger("pxy"), id: "pxy"}
	// A deadline on the test's end means a wiring bug fails the test instead
	// of hanging it: every read and every pipe write the test does is bounded.
	// (net.Pipe supports deadlines; the flow's own teardown closes the other
	// end, which unblocks the rest.)
	publicEnd.SetDeadline(time.Now().Add(30 * time.Second))

	h := &udpFlowUnderTest{
		public:   publicEnd,
		finished: make(chan struct{}),
	}
	go func() {
		defer close(h.finished)
		model.serveProxyConnection(remoteConn, &msg.StartProxy{Url: tunnel.PublicUrl, ClientAddr: testClientAddr})
	}()

	t.Cleanup(func() {
		publicEnd.Close()
		select {
		case <-h.finished:
		case <-time.After(10 * time.Second):
			t.Errorf("serveProxyConnection did not return after the public connection was closed")
		}
	})

	return h
}

// writeDatagram frames and writes one datagram into the flow's public end.
func writeDatagram(t *testing.T, c net.Conn, payload []byte) {
	t.Helper()
	if err := proto.WriteDatagramFrame(c, payload); err != nil {
		t.Fatalf("failed to write a framed datagram: %v", err)
	}
}

// readDatagram reads one framed datagram off the flow's public end.
func readDatagram(t *testing.T, c net.Conn, buf []byte) []byte {
	t.Helper()
	n, err := proto.ReadDatagramFrame(c, buf)
	if err != nil {
		t.Fatalf("failed to read a framed datagram: %v", err)
	}
	return buf[:n]
}

// TestUdpFlowPumpsBothDirections is the core data-path test: datagrams written
// into the public end cross the real UDP leg, come back from the echo server,
// and arrive at the public end as the same datagrams. The case list pins the
// boundary property (SPEC-CLUSTER8 6.3) at its edges: the empty datagram (a
// legal UDP payload that a sloppy reader would swallow as an EOF) and one far
// above the usual path MTU.
//
// The sizes stop below 16 KiB on purpose, and the limit the framing carries is
// pinned separately (TestDatagramFrameRoundTrip, at the full 65507). The
// difference is honest: the framing is ours, and it carries 64 KiB datagrams
// whole; the local UDP leg is the kernel's, and this platform's loopback MTU
// is 16384, so a datagram above that is refused with EMSGSIZE -- where the
// pump's first-send-failure rule closes the flow quietly, which
// TestUdpFlowDeadLocalClosesQuietly pins as the specified behavior. A unit
// test that required a 64 KiB local hop would be pinning one platform's lo0
// MTU, not this protocol.
func TestUdpFlowPumpsBothDirections(t *testing.T) {
	echoAddr := udpEchoServer(t)
	h := startUdpFlow(t, echoAddr)

	payloads := [][]byte{
		[]byte("ping"),
		{}, // the empty datagram: framing must carry it as a datagram, not lose it
		bytes.Repeat([]byte("ab"), 4000),
	}

	readBuf := make([]byte, proto.MaxDatagramSize)
	for _, payload := range payloads {
		writeDatagram(t, h.public, payload)
		// Loopback UDP delivers in order, so the echo read back now is the
		// answer to exactly this datagram.
		if got := readDatagram(t, h.public, readBuf); !bytes.Equal(got, payload) {
			t.Fatalf("echoed datagram of %d bytes came back as %d bytes (first difference at %d)",
				len(payload), len(got), firstDifference(got, payload))
		}
	}

	// Back-to-back datagrams without reading in between: the two frames must
	// arrive as two, with the second's payload untouched -- a reader that
	// coalesced them would hand back payload[1] glued behind payload[0] under
	// one length prefix, and a writer that split them would fail the exact
	// length checks above.
	writeDatagram(t, h.public, payloads[0])
	writeDatagram(t, h.public, payloads[2])
	for _, want := range [][]byte{payloads[0], payloads[2]} {
		if got := readDatagram(t, h.public, readBuf); !bytes.Equal(got, want) {
			t.Fatalf("datagram boundary lost: got %d bytes, want %d", len(got), len(want))
		}
	}
}

// TestUdpFlowIdleExpiry pins the client half of SPEC-CLUSTER8 3.2's flow
// lifetime: a flow with no traffic in either direction is closed by the idle
// watcher, without the server having to end it first. The idle timeout is the
// model's var, shrunk here the way quicHandshakeTimeout is shrunk in
// quic_test.go -- a 30s wait would not be a unit test.
func TestUdpFlowIdleExpiry(t *testing.T) {
	original := udpIdleTimeout
	udpIdleTimeout = 400 * time.Millisecond
	t.Cleanup(func() { udpIdleTimeout = original })

	echoAddr := udpEchoServer(t)
	h := startUdpFlow(t, echoAddr)

	select {
	case <-h.finished:
	case <-time.After(10 * time.Second):
		t.Fatal("an idle udp flow was not closed by the client")
	}

	// Quietly means quietly: nothing was ever written back before the close.
	h.public.SetReadDeadline(time.Now().Add(time.Second))
	var probe [16]byte
	if n, err := h.public.Read(probe[:]); n > 0 {
		t.Fatalf("the idle close wrote %d bytes before closing (a 502 would be %d)", n, len(BadGateway))
	} else if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
		// EOF / closed is the expected shape of a bare close; anything else
		// suggests something answered.
		t.Fatalf("unexpected error after the idle close: %v", err)
	}
}

// TestUdpFlowIdleRefreshKeepsItAlive pins the other half of the idle contract:
// traffic in the window refreshes it, so a flow that keeps exchanging
// datagrams at intervals shorter than the timeout outlives the timeout
// several times over -- and then expires once the traffic stops. The
// exchange interval (150ms) is well under the shrunken timeout (500ms), and
// the exchanges past the 500ms mark are what prove the refresh happened; a
// watcher that ignored activity would have closed the flow before the third.
func TestUdpFlowIdleRefreshKeepsItAlive(t *testing.T) {
	original := udpIdleTimeout
	udpIdleTimeout = 500 * time.Millisecond
	t.Cleanup(func() { udpIdleTimeout = original })

	echoAddr := udpEchoServer(t)
	h := startUdpFlow(t, echoAddr)

	readBuf := make([]byte, proto.MaxDatagramSize)
	exchange := func() {
		writeDatagram(t, h.public, []byte("keepalive"))
		if got := readDatagram(t, h.public, readBuf); string(got) != "keepalive" {
			t.Fatalf("echo = %q, want %q", got, "keepalive")
		}
	}

	// Six exchanges over ~900ms: more than one full idle window has elapsed
	// since the flow was established by the fourth, so survival here is the
	// refresh working, not the timer being slow.
	for i := 0; i < 6; i++ {
		exchange()
		time.Sleep(150 * time.Millisecond)
	}

	// One more exchange succeeds after that quiet-free period, then silence.
	exchange()

	// The last exchange was activity; from here the flow must end within one
	// shrunken window plus slack.
	select {
	case <-h.finished:
	case <-time.After(10 * time.Second):
		t.Fatal("a udp flow stayed open past the idle timeout after its last datagram")
	}
}

// TestUdpFlowDeadLocalClosesQuietly covers the dead-local semantics
// (SPEC-CLUSTER8 3.2): the local service is not listening, and the flow ends
// with silence -- no 502, no bytes, ever. The mechanism is platform-dependent
// timing: on a connected socket the loopback ICMP port-unreachable from the
// first datagram surfaces as the error of a later send or receive (usually at
// once), and where it never surfaces at all the shrunken idle timer ends the
// flow the same quiet way. Both endings are the outcome under test; what must
// hold on every platform is that the close is bare.
func TestUdpFlowDeadLocalClosesQuietly(t *testing.T) {
	original := udpIdleTimeout
	udpIdleTimeout = 2 * time.Second
	t.Cleanup(func() { udpIdleTimeout = original })

	// A port that was bound and is now closed: nothing is listening.
	dead, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("failed to bind a throwaway UDP socket: %v", err)
	}
	deadAddr := dead.LocalAddr().String()
	dead.Close()

	h := startUdpFlow(t, deadAddr)

	writeDatagram(t, h.public, []byte("ping"))
	// Best-effort second datagram: by now the ICMP refusal may already have
	// ended the flow from the local read side (the same quiet close), in
	// which case this write fails and that is the outcome under test, not an
	// error.
	_ = proto.WriteDatagramFrame(h.public, []byte("ping"))

	select {
	case <-h.finished:
	case <-time.After(10 * time.Second):
		t.Fatal("a flow whose local service is dead was not closed")
	}

	// The quiet half: zero bytes went back before the close.
	h.public.SetReadDeadline(time.Now().Add(time.Second))
	var probe [64]byte
	if n, err := h.public.Read(probe[:]); n > 0 {
		t.Fatalf("the dead-local close wrote %d bytes before closing; udp callers get silence, not a 502", n)
	} else if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("unexpected error after the dead-local close: %v", err)
	}
}

// TestUdpProtocolIsRegistered pins the registration that makes a udp tunnel
// resolvable at all: the control loop looks NewTunnel.Protocol up in the
// model's protoMap, and a miss would hand the tunnel a nil protocol. The
// identity check is the protocol's whole behavior contract (SPEC-CLUSTER8
// 3.2): a udp tunnel's conn is the conn, because the framing lives in the
// pumps, not in a wrapper (see proto/udp.go).
func TestUdpProtocolIsRegistered(t *testing.T) {
	// ServerAddr is set because the constructor derives the TLS SNI from it
	// (and panics on an address without a port): the loader always normalized
	// it before reaching here.
	m := newClientModel(&Configuration{ServerAddr: "tunnel.example.com:443"}, &agentTLSStubController{Logger: log.NewPrefixLogger("ctl")})

	p, ok := m.protoMap[msg.ProtoUDP]
	if !ok {
		t.Fatal("msg.ProtoUDP is not registered in the model's protoMap; a udp NewTunnel would resolve to a nil protocol")
	}
	if p.GetName() != "udp" {
		t.Fatalf("protoMap[udp].GetName() = %q, want %q", p.GetName(), "udp")
	}

	publicEnd, serverEnd := net.Pipe()
	defer publicEnd.Close()
	defer serverEnd.Close()
	wrapped := &proxyTestConn{Conn: serverEnd, Logger: log.NewPrefixLogger("pxy"), id: "pxy"}
	if got := p.WrapConn(wrapped, mvc.ConnectionContext{}); got != wrapped {
		t.Fatal("the udp protocol wrapped the conn; it must return it unchanged")
	}
}

// firstDifference is the test's way of saying where a round trip went wrong
// without dumping 64 KiB into the failure message.
func firstDifference(a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return i
		}
	}
	return n
}

// TestDatagramFrameRoundTrip is the codec's own test (SPEC-CLUSTER8 3.1/3.2:
// both ends implement this format, so its edges are pinned here): frames
// written back to back are read back one by one, byte-exact, with nothing
// left over -- the boundary preservation property in its purest form.
func TestDatagramFrameRoundTrip(t *testing.T) {
	payloads := [][]byte{
		{},
		[]byte("x"),
		bytes.Repeat([]byte("frame"), 4096), // 20480 bytes
		bytes.Repeat([]byte{0x00}, proto.MaxDatagramSize),
	}

	var buf bytes.Buffer
	for _, payload := range payloads {
		if err := proto.WriteDatagramFrame(&buf, payload); err != nil {
			t.Fatalf("WriteDatagramFrame(%d bytes) failed: %v", len(payload), err)
		}
	}

	readBuf := make([]byte, proto.MaxDatagramSize)
	for i, want := range payloads {
		n, err := proto.ReadDatagramFrame(&buf, readBuf)
		if err != nil {
			t.Fatalf("ReadDatagramFrame(%d) failed: %v", i, err)
		}
		if n != len(want) || !bytes.Equal(readBuf[:n], want) {
			t.Fatalf("frame %d: read %d bytes, want %d (payloads differ from byte %d)", i, n, len(want), firstDifference(readBuf[:n], want))
		}
	}
	if buf.Len() != 0 {
		t.Fatalf("%d bytes left unconsumed after reading every frame", buf.Len())
	}
}

// TestDatagramFrameOversizedLengthIsAProtocolError pins the reader's refusal
// rule: a length field beyond MaxDatagramSize cannot be a datagram anyone
// sent, and the error is the protocol error (ErrDatagramTooLarge) the pump
// turns into a loud WARN and a closed flow -- not a read that would try to
// consume 4 GiB of stream.
func TestDatagramFrameOversizedLengthIsAProtocolError(t *testing.T) {
	for _, length := range []uint32{proto.MaxDatagramSize + 1, 1 << 20, math.MaxUint32} {
		var buf bytes.Buffer
		var hdr [4]byte
		binary.BigEndian.PutUint32(hdr[:], length)
		buf.Write(hdr[:])
		buf.WriteString("trailing bytes that would follow a real header")

		_, err := proto.ReadDatagramFrame(&buf, make([]byte, proto.MaxDatagramSize))
		if !errors.Is(err, proto.ErrDatagramTooLarge) {
			t.Fatalf("length %d: err = %v, want ErrDatagramTooLarge", length, err)
		}
	}
}

// TestWriteDatagramFrameRefusesOversizedPayload: the writer refuses at the
// write site what the reader would refuse at the read site, so a caller that
// somehow produced an impossible datagram learns it locally instead of
// teaching the peer's flow to die.
func TestWriteDatagramFrameRefusesOversizedPayload(t *testing.T) {
	if err := proto.WriteDatagramFrame(io.Discard, make([]byte, proto.MaxDatagramSize+1)); err == nil {
		t.Fatal("WriteDatagramFrame accepted a payload larger than MaxDatagramSize")
	}
	// The boundary itself is exactly acceptable.
	if err := proto.WriteDatagramFrame(io.Discard, make([]byte, proto.MaxDatagramSize)); err != nil {
		t.Fatalf("WriteDatagramFrame refused the maximum payload: %v", err)
	}
}
