package server

// Tests for UDP tunnels (SPEC-CLUSTER8 §3.1, §5-A).
//
// The layout follows the house style: real loopback sockets and the shared
// fixtures from registry_v2_test.go (setupTestRegistry, testControl,
// armProxyPool, readStartProxy), because the interesting parts of the flow
// path -- a datagram arriving on a real socket, the StartProxy handshake on a
// real proxy conn, a reply routed back out the public socket -- are exactly
// the parts a fake cannot stand in for. The framing tests are the one pure
// unit section: a framing bug is a bytes-in-bytes-out property.
//
// The macOS gotcha the TCP tests already document (registry_v2_test.go,
// dispatch) applies doubly here: every client socket sends to 127.0.0.1
// explicitly, never to a wildcard literal.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"ngrok/conn"
	"ngrok/log"
	"ngrok/msg"
	"ngrok/policy"
)

// ---------------------------------------------------------------------------
// fixtures

// setUdpIdleTimeout shrinks the flow idle deadline for one test and restores
// the default afterwards. The value is an atomic (udp.go) because janitor
// goroutines from earlier tests are legitimately still starting up while a
// later test rewrites it; the atomic is what keeps that a synchronization,
// not a data race.
func setUdpIdleTimeout(t *testing.T, d time.Duration) {
	t.Helper()

	prev := udpIdleTimeoutNanos.Load()
	t.Cleanup(func() { udpIdleTimeoutNanos.Store(prev) })
	udpIdleTimeoutNanos.Store(int64(d))
}

// udpClient returns a test's public client: a UDP socket bound to loopback,
// ready to send datagrams at a tunnel's public port.
func udpClient(t *testing.T) *net.UDPConn {
	t.Helper()

	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("failed to bind a test UDP client: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// sendTo writes one datagram from a client socket to a tunnel's public port,
// named by the loopback address the test means -- never the wildcard.
func sendTo(t *testing.T, c *net.UDPConn, tun *Tunnel, payload []byte) {
	t.Helper()

	port := tun.udpConn.LocalAddr().(*net.UDPAddr).Port
	if _, err := c.WriteToUDP(payload, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}); err != nil {
		t.Fatalf("failed to send a datagram to %s: %v", tun.url, err)
	}
}

// recvFrom reads one datagram from a client socket, with the payload, the
// address it arrived from (the tunnel's public endpoint -- source-port
// preservation is part of the contract this suite pins), and a failure that
// fires well before the test suite's hang threshold.
func recvFrom(t *testing.T, c *net.UDPConn, what string) ([]byte, *net.UDPAddr) {
	t.Helper()

	if err := c.SetReadDeadline(time.Now().Add(publicTimeout)); err != nil {
		t.Fatalf("failed to set a read deadline: %v", err)
	}
	buf := make([]byte, udpMaxDatagramSize)
	n, addr, err := c.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("%s never received a datagram: %v", what, err)
	}
	return buf[:n], addr
}

// expectSilence asserts that no datagram arrives within a short window: the
// assertion behind "a refused flow is dropped silently" (SPEC §3.1) -- a UDP
// caller has no protocol to be answered in, so the refusal it must observe is
// nothing at all.
func expectSilence(t *testing.T, c *net.UDPConn, what string) {
	t.Helper()

	if err := c.SetReadDeadline(time.Now().Add(250 * time.Millisecond)); err != nil {
		t.Fatalf("failed to set a read deadline: %v", err)
	}
	buf := make([]byte, 1024)
	n, _, err := c.ReadFromUDP(buf)
	if err == nil {
		t.Fatalf("%s received %d byte(s) that should have been dropped: %q", what, n, buf[:n])
	}
}

// flowCount returns the number of live flows in a tunnel's table, under the
// table's lock: tests read the table the same way the janitor does, so -race
// sees one discipline and not a lucky one.
func flowCount(tun *Tunnel) int {
	tun.flows.mu.Lock()
	defer tun.flows.mu.Unlock()
	return len(tun.flows.flows)
}

// waitFlowCount polls until the table holds exactly n flows, or fails. Flow
// lifecycle events happen on several goroutines (the reader that establishes,
// the janitor that expires), so a test that wants a settled count polls
// rather than sleeps once and hopes.
func waitFlowCount(t *testing.T, tun *Tunnel, n int, what string) {
	t.Helper()

	deadline := time.Now().Add(publicTimeout)
	for time.Now().Before(deadline) {
		if got := flowCount(tun); got == n {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("%s: flow table holds %d flows, want %d", what, flowCount(tun), n)
}

// drainFramed consumes one framed datagram from an agent conn. The datagrams
// a test's own public client sent are in flight on that conn, and every later
// assertion against it -- "no more bytes arrive", "the conn is closed" -- is
// meaningless until the flow's legitimate traffic has been read off it. For
// the same reason, anything asserting on a specific late datagram must first
// drain everything ahead of it (readFramedUntil).
func drainFramed(t *testing.T, agent conn.Conn, what string) {
	t.Helper()

	if err := agent.SetReadDeadline(time.Now().Add(publicTimeout)); err != nil {
		t.Fatalf("failed to set a read deadline: %v", err)
	}
	buf := make([]byte, udpMaxDatagramSize)
	if _, err := readFramedDatagram(agent, buf); err != nil {
		t.Fatalf("%s never delivered its datagram: %v", what, err)
	}
}

// readFramedUntil reads framed datagrams until the wanted payload arrives,
// skipping anything queued ahead of it (earlier keepalives, earlier
// datagrams of the same flow). Fails if the wanted payload never comes.
func readFramedUntil(t *testing.T, agent conn.Conn, want []byte, what string) {
	t.Helper()

	deadline := time.Now().Add(publicTimeout)
	buf := make([]byte, udpMaxDatagramSize)
	for {
		if err := agent.SetReadDeadline(time.Now().Add(time.Until(deadline))); err != nil {
			t.Fatalf("failed to set a read deadline: %v", err)
		}
		n, err := readFramedDatagram(agent, buf)
		if err != nil {
			t.Fatalf("%s: %v never arrived, read failed: %v", what, want, err)
		}
		if bytes.Equal(buf[:n], want) {
			return
		}
	}
}

// agentOf maps the StartProxy handshakes two agent conns received to the
// client addresses they name, failing if the two conns were not both asked
// to serve a flow. The flow-to-agent assignment is a scheduling order the
// test does not pin; the ClientAddr in each handshake is.
func agentsByClientAddr(t *testing.T, agents ...conn.Conn) map[string]conn.Conn {
	t.Helper()

	out := make(map[string]conn.Conn, len(agents))
	for _, a := range agents {
		sp := readStartProxy(t, a, "an agent")
		if _, dup := out[sp.ClientAddr]; dup {
			t.Fatalf("two agents were handed the flow from %s", sp.ClientAddr)
		}
		out[sp.ClientAddr] = a
	}
	return out
}

// ---------------------------------------------------------------------------
// framing

// TestUdpFramingRoundTripPinsBoundaries covers the proxy-leg framing contract
// (SPEC §5-3): datagrams go over the stream with a 4-byte big-endian length
// prefix each, and no datagram is ever coalesced with the next one or split
// across reads -- including the empty datagram and the 65507-byte maximum.
func TestUdpFramingRoundTripPinsBoundaries(t *testing.T) {
	// Sizes chosen so that coalescing and splitting both fail loudly: an
	// empty datagram between two non-empty ones, and a maximum-size datagram
	// whose content is distinct byte for byte.
	sizes := []int{7, 0, udpMaxDatagramSize}
	payloads := make([][]byte, len(sizes))
	for i, n := range sizes {
		p := make([]byte, n)
		for j := range p {
			p[j] = byte(i*31 + j*7 + 1)
		}
		payloads[i] = p
	}

	scratch := make([]byte, udpFrameLenBytes+udpMaxDatagramSize)
	var wire bytes.Buffer
	for _, p := range payloads {
		if err := writeFramedDatagram(&wire, p, scratch); err != nil {
			t.Fatalf("failed to frame a %d-byte datagram: %v", len(p), err)
		}
	}

	buf := make([]byte, udpMaxDatagramSize)
	for i, want := range payloads {
		n, err := readFramedDatagram(&wire, buf)
		if err != nil {
			t.Fatalf("failed to read framed datagram %d: %v", i, err)
		}
		if n != len(want) {
			t.Fatalf("datagram %d arrived as %d bytes, want %d (split or coalesced)", i, n, len(want))
		}
		if !bytes.Equal(buf[:n], want) {
			t.Fatalf("datagram %d content corrupted in transit", i)
		}
	}
	if wire.Len() != 0 {
		t.Fatalf("%d bytes left on the wire after the last datagram", wire.Len())
	}
}

// TestUdpFramingIsBigEndian pins the prefix byte order: the length field is
// big-endian, so a little-endian spelling of a tiny length reads as an
// enormous one and is refused rather than silently mis-sized.
func TestUdpFramingIsBigEndian(t *testing.T) {
	var wire bytes.Buffer
	prefix := make([]byte, 4)
	binary.LittleEndian.PutUint32(prefix, 3)
	wire.Write(prefix)
	wire.WriteString("abc")

	buf := make([]byte, 1024)
	_, err := readFramedDatagram(&wire, buf)
	if !errors.Is(err, errDatagramTooLarge) {
		t.Fatalf("a little-endian prefix must read as an oversized length, got: %v", err)
	}
}

// TestUdpFramingRefusesOversizedLength covers the protocol-error path: a
// length field beyond udpMaxDatagramSize cannot have come from a datagram
// anyone could have sent, and the reader must say so -- the flow's close is
// the caller's move (it has the flow), the refusal is the reader's.
func TestUdpFramingRefusesOversizedLength(t *testing.T) {
	var wire bytes.Buffer
	prefix := make([]byte, 4)
	binary.BigEndian.PutUint32(prefix, udpMaxDatagramSize+1)
	wire.Write(prefix)

	buf := make([]byte, udpMaxDatagramSize)
	if _, err := readFramedDatagram(&wire, buf); !errors.Is(err, errDatagramTooLarge) {
		t.Fatalf("a %d-byte length must be refused, got: %v", udpMaxDatagramSize+1, err)
	}

	// A truncated stream (the agent's conn died mid-frame) is an error too,
	// and never a short datagram.
	var cut bytes.Buffer
	binary.BigEndian.PutUint32(prefix, 100)
	cut.Write(prefix)
	cut.WriteString("only a few")
	if _, err := readFramedDatagram(&cut, buf); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("a stream cut mid-datagram must report EOF, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// registration and validation

// TestUdpValidationRules pins what a udp registration accepts and refuses:
// the protocol is public-only, port-routed, and nothing else -- the HTTP
// naming fields have no path that could honor them, and internal endpoints
// and forward_to chains are refused with TCP's wording adapted.
func TestUdpValidationRules(t *testing.T) {
	setupTestRegistry(t)
	ctl := testControl(t, "")

	cases := []struct {
		name    string
		req     msg.ReqTunnel
		wantErr string
	}{
		{
			name:    "a hostname is refused: udp is port-routed",
			req:     msg.ReqTunnel{Protocol: msg.ProtoUDP, Hostname: "dns.example.com"},
			wantErr: "port-routed",
		},
		{
			name:    "a subdomain is refused: udp is port-routed",
			req:     msg.ReqTunnel{Protocol: msg.ProtoUDP, Subdomain: "dns"},
			wantErr: "port-routed",
		},
		{
			name:    "internal udp endpoints are refused",
			req:     msg.ReqTunnel{Protocol: msg.ProtoUDP, Binding: msg.BindingInternal, Hostname: "dns.internal"},
			wantErr: "not supported yet",
		},
		{
			name:    "forward_to is refused for udp",
			req:     msg.ReqTunnel{Protocol: msg.ProtoUDP, ForwardTo: "https://svc.internal"},
			wantErr: "only supported for http and https",
		},
		{
			name:    "an unknown protocol is still refused",
			req:     msg.ReqTunnel{Protocol: "sctp"},
			wantErr: "not supported",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tun, err := NewTunnel(&tc.req, ctl)
			if err == nil {
				tun.Shutdown()
				t.Fatalf("NewTunnel(%+v) succeeded, want an error", tc.req)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not mention %q", err.Error(), tc.wantErr)
			}
		})
	}

	// The happy path: a plain udp registration binds a real socket and names
	// it with the port the kernel actually handed back.
	tun := registerTestTunnel(t, ctl, msg.ReqTunnel{Protocol: msg.ProtoUDP})
	if tun.udpConn == nil {
		t.Fatal("a udp tunnel must bind its public socket")
	}
	bound := tun.udpConn.LocalAddr().(*net.UDPAddr).Port
	if tun.url != fmt.Sprintf("udp://%s:%d", "ngrok.test", bound) {
		t.Fatalf("url = %q, want the actually bound port %d spelled in it", tun.url, bound)
	}
	if tun.listener != nil {
		t.Fatal("a udp tunnel must not bind a TCP listener")
	}
}

// TestUdpTunnelReturnsToCachedPort covers the affinity path: a udp client
// that comes back on the same control identity gets its old port again -- the
// cache keys are protocol-namespaced, so the udp tunnel's cached url is its
// own and never a tcp one's.
func TestUdpTunnelReturnsToCachedPort(t *testing.T) {
	setupTestRegistry(t)
	ctl := testControl(t, "")

	first := registerTestTunnel(t, ctl, msg.ReqTunnel{Protocol: msg.ProtoUDP})
	port := first.udpConn.LocalAddr().(*net.UDPAddr).Port
	first.Shutdown()

	again := registerTestTunnel(t, ctl, msg.ReqTunnel{Protocol: msg.ProtoUDP})
	if got := again.udpConn.LocalAddr().(*net.UDPAddr).Port; got != port {
		t.Fatalf("the returning client got port %d, want its old %d", got, port)
	}
}

// TestUdpRemotePortClaimsInItsOwnSpace walks the claim through the real
// registration path: a udp tunnel holding a remote port claims it in the udp
// space, where a tcp tunnel's claim on the same number neither blocks it nor
// is blocked by it.
func TestUdpRemotePortClaimsInItsOwnSpace(t *testing.T) {
	setupTestRegistry(t)
	setupPortClaims(t)
	ctl := testControl(t, "")

	// A tcp tunnel takes the number in its space first.
	tcpTun := registerTestTunnel(t, ctl, msg.ReqTunnel{Protocol: msg.ProtoTCP, RemotePort: uint16(freePort(t))})
	tcpPort := tcpTun.listener.Addr().(*net.TCPAddr).Port

	// The udp tunnel takes the same number in its own space, and holds it.
	udpTun := registerTestTunnel(t, ctl, msg.ReqTunnel{Protocol: msg.ProtoUDP, RemotePort: uint16(tcpPort)})
	if udpTun.udpConn == nil {
		t.Fatal("the udp tunnel must bind the port its space had free")
	}
	if got := portClaims.HeldBy(msg.ProtoUDP, tcpPort); got != defaultOwner {
		t.Fatalf("the udp bind must claim its port, holder %q", got)
	}

	// Another account cannot take it -- the refusal names the space.
	prevTokens := opts.authTokens
	opts.authTokens = []string{"tok-a"}
	defer func() { opts.authTokens = prevTokens }()
	other := testControl(t, "someone-else")
	_, err := NewTunnel(&msg.ReqTunnel{Protocol: msg.ProtoUDP, RemotePort: uint16(tcpPort)}, other)
	if err == nil || !strings.Contains(err.Error(), "already claimed by another auth token") {
		t.Fatalf("a second account must be refused the held udp port, got: %v", err)
	}

	udpTun.Shutdown()
	if got := portClaims.HeldBy(msg.ProtoUDP, tcpPort); got != "" {
		t.Fatalf("shutdown must release the udp claim, holder %q", got)
	}
	// The tcp claim was never disturbed by any of it.
	if got := portClaims.HeldBy(msg.ProtoTCP, tcpPort); got != defaultOwner {
		t.Fatalf("the tcp claim must have survived the udp lifecycle, holder %q", got)
	}
}

// TestUdpPoolingSharesOneSocket is TestTcpPoolingSharesOneListener in the udp
// space: the first member binds the only socket, members join without
// binding, and shutdown takes the socket down only with its creator.
func TestUdpPoolingSharesOneSocket(t *testing.T) {
	reg := setupTestRegistry(t)
	ctl := testControl(t, "")

	creator := registerTestTunnel(t, ctl, msg.ReqTunnel{Protocol: msg.ProtoUDP, Pooling: true})
	if creator.udpConn == nil {
		t.Fatal("the first pooling udp tunnel must bind the socket")
	}
	port := creator.udpConn.LocalAddr().(*net.UDPAddr).Port

	member := registerTestTunnel(t, ctl, msg.ReqTunnel{Protocol: msg.ProtoUDP, Pooling: true, RemotePort: uint16(port)})
	if member.url != creator.url {
		t.Fatalf("the member registered %s, want %s", member.url, creator.url)
	}
	if member.udpConn != nil {
		t.Fatal("a pooling member must not bind a second socket")
	}
	if got := len(reg.tunnels[creator.url].tunnels); got != 2 {
		t.Fatalf("the bucket holds %d members, want 2", got)
	}

	// A member's shutdown leaves the socket, the creator and the bucket.
	member.Shutdown()
	if got := len(reg.tunnels[creator.url].tunnels); got != 1 {
		t.Fatalf("after the member shut down the bucket holds %d members, want 1", got)
	}
	if reg.Get(creator.url) != creator {
		t.Fatal("after the member shut down the bucket no longer serves the creator")
	}

	// The last member out takes the bucket -- and the socket -- with it.
	creator.Shutdown()
	if _, ok := reg.tunnels[creator.url]; ok {
		t.Fatal("the bucket still exists after its last member shut down")
	}
}

// ---------------------------------------------------------------------------
// flow lifecycle

// TestUdpFlowRoundTripAmongTwoFlows is the integration: two public clients
// establish two flows on one tunnel, each flow's datagrams reach an agent
// with the sender's address as ClientAddr, nothing is coalesced or split on
// the way out, and a reply written into either agent's conn is routed back to
// exactly that flow's client -- from the tunnel's public port, so the reply
// looks the way UDP replies must.
func TestUdpFlowRoundTripAmongTwoFlows(t *testing.T) {
	setupTestRegistry(t)
	ctl := testControl(t, "")

	// Arm both proxy connections up front, the way every test here arms
	// them: before any goroutine that could wrap a conn of its own exists
	// (see armProxyPool's comment on the shared id generator).
	agentA, agentB := armProxyPool(t, ctl), armProxyPool(t, ctl)

	tun := registerTestTunnel(t, ctl, msg.ReqTunnel{Protocol: msg.ProtoUDP})
	publicPort := tun.udpConn.LocalAddr().(*net.UDPAddr).Port

	clientA, clientB := udpClient(t), udpClient(t)
	sendTo(t, clientA, tun, []byte("ping-a"))
	sendTo(t, clientB, tun, []byte("ping-b"))

	byClient := agentsByClientAddr(t, agentA, agentB)
	if _, ok := byClient[clientA.LocalAddr().String()]; !ok {
		t.Fatalf("no agent was handed the flow from %s (got %v)", clientA.LocalAddr(), byClient)
	}
	if _, ok := byClient[clientB.LocalAddr().String()]; !ok {
		t.Fatalf("no agent was handed the flow from %s (got %v)", clientB.LocalAddr(), byClient)
	}

	// Each flow's datagram arrives at its own agent, whole and exact: the
	// flow from a client carries that client's datagram, and nothing else's.
	for client, want := range map[*net.UDPConn][]byte{
		clientA: []byte("ping-a"),
		clientB: []byte("ping-b"),
	} {
		agent := byClient[client.LocalAddr().String()]
		buf := make([]byte, udpMaxDatagramSize)
		if err := agent.SetReadDeadline(time.Now().Add(publicTimeout)); err != nil {
			t.Fatalf("failed to set a read deadline: %v", err)
		}
		n, err := readFramedDatagram(agent, buf)
		if err != nil {
			t.Fatalf("the agent never received the flow's datagram: %v", err)
		}
		if !bytes.Equal(buf[:n], want) {
			t.Fatalf("the agent received %q, want %q", buf[:n], want)
		}
	}

	// A reply written into one flow's agent conn is routed back to that
	// flow's client only -- and from the tunnel's public port, not from some
	// ephemeral socket, so a source-port-checking client accepts it.
	pongA, pongB := []byte("pong-a"), []byte("pong-b")
	scratch := make([]byte, udpFrameLenBytes+udpMaxDatagramSize)
	if err := writeFramedDatagram(byClient[clientA.LocalAddr().String()], pongA, scratch); err != nil {
		t.Fatalf("failed to frame the reply for flow A: %v", err)
	}
	if err := writeFramedDatagram(byClient[clientB.LocalAddr().String()], pongB, scratch); err != nil {
		t.Fatalf("failed to frame the reply for flow B: %v", err)
	}

	gotA, fromA := recvFrom(t, clientA, "client A")
	if !bytes.Equal(gotA, pongA) {
		t.Fatalf("client A received %q, want %q", gotA, pongA)
	}
	if fromA.Port != publicPort {
		t.Fatalf("the reply arrived from port %d, want the tunnel's public port %d", fromA.Port, publicPort)
	}

	gotB, _ := recvFrom(t, clientB, "client B")
	if !bytes.Equal(gotB, pongB) {
		t.Fatalf("client B received %q, want %q -- the replies were misrouted", gotB, pongB)
	}

	// The observability accounting reports the same bytes the flows relayed
	// (polled: the server-side counter lags the client's recv by a scheduler
	// turn, and atomics carry no wakeup).
	wantIn := int64(len("ping-a") + len("ping-b"))
	wantOut := int64(len("pong-a") + len("pong-b"))
	deadline := time.Now().Add(publicTimeout)
	for {
		tun.flows.mu.Lock()
		in, out := int64(0), int64(0)
		for _, f := range tun.flows.flows {
			in += f.bytesIn.Load()
			out += f.bytesOut.Load()
		}
		tun.flows.mu.Unlock()
		if in == wantIn && out == wantOut {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("byte accounting = %d in / %d out, want %d / %d", in, out, wantIn, wantOut)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestUdpFlowIdleExpiry covers the flow's clock: a flow that goes silent in
// both directions is closed by the janitor -- its proxy conn closes, the
// table empties, and the per-flow admission budget is released, which a new
// flow from the same address proves by establishing under a one-flow cap.
func TestUdpFlowIdleExpiry(t *testing.T) {
	setUdpIdleTimeout(t, 400*time.Millisecond)

	prevConnLimiter := connLimiter
	connLimiter = newIPConnLimiter(1) // the expired flow must release its slot
	t.Cleanup(func() { connLimiter = prevConnLimiter })

	setupTestRegistry(t)
	ctl := testControl(t, "")

	first := armProxyPool(t, ctl)
	tun := registerTestTunnel(t, ctl, msg.ReqTunnel{Protocol: msg.ProtoUDP})

	client := udpClient(t)
	sendTo(t, client, tun, []byte("hello"))
	readStartProxy(t, first, "the agent")
	drainFramed(t, first, "the first flow")
	waitFlowCount(t, tun, 1, "the flow was never established")

	// Silence from both ends. The janitor's scan is a fraction of the idle
	// timeout, so well before the suite's standard timeout the flow must be
	// gone and the agent's conn -- closed by flow.close -- must say so.
	if err := first.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("failed to set a read deadline: %v", err)
	}
	buf := make([]byte, 16)
	if _, err := first.Read(buf); err == nil {
		t.Fatal("the expired flow's proxy conn is still open")
	}
	waitFlowCount(t, tun, 0, "the expired flow was never removed")

	// The cap was released: the same client may establish again, on a fresh
	// proxy conn.
	second := armProxyPool(t, ctl)
	sendTo(t, client, tun, []byte("again"))
	if got := readStartProxy(t, second, "the agent"); got.Url != tun.url {
		t.Fatalf("the new flow was proxied for %s, want %s", got.Url, tun.url)
	}
	waitFlowCount(t, tun, 1, "the replacement flow was never established")
}

// TestUdpFlowIdleDeadlineRefreshesOnBothDirections covers the other half of
// the idle contract: activity in EITHER direction pushes the deadline out, so
// a flow carrying a long-lived exchange is not reaped mid-conversation.
func TestUdpFlowIdleDeadlineRefreshesOnBothDirections(t *testing.T) {
	setUdpIdleTimeout(t, 400*time.Millisecond)

	for _, tc := range []struct {
		name    string
		refresh func(t *testing.T, tun *Tunnel, client *net.UDPConn, agent conn.Conn)
	}{
		{
			name: "public to agent",
			refresh: func(t *testing.T, tun *Tunnel, client *net.UDPConn, agent conn.Conn) {
				deadline := time.Now().Add(2 * udpIdleTimeout())
				for time.Now().Before(deadline) {
					sendTo(t, client, tun, []byte("keepalive"))
					time.Sleep(udpIdleTimeout() / 4)
				}
			},
		},
		{
			name: "agent to public",
			refresh: func(t *testing.T, tun *Tunnel, client *net.UDPConn, agent conn.Conn) {
				deadline := time.Now().Add(2 * udpIdleTimeout())
				scratch := make([]byte, udpFrameLenBytes+16)
				for time.Now().Before(deadline) {
					if err := writeFramedDatagram(agent, []byte("keepalive"), scratch); err != nil {
						t.Fatalf("failed to write to the agent conn: %v", err)
					}
					time.Sleep(udpIdleTimeout() / 4)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setupTestRegistry(t)
			ctl := testControl(t, "")
			agent := armProxyPool(t, ctl)
			tun := registerTestTunnel(t, ctl, msg.ReqTunnel{Protocol: msg.ProtoUDP})
			client := udpClient(t)

			sendTo(t, client, tun, []byte("start"))
			readStartProxy(t, agent, "the agent")
			waitFlowCount(t, tun, 1, "the flow was never established")

			// Keep exactly one direction busy for twice the idle timeout: a
			// deadline that only one direction refreshed would have reaped
			// this flow long ago.
			tc.refresh(t, tun, client, agent)

			if got := flowCount(tun); got != 1 {
				t.Fatalf("an actively refreshed flow was reaped: %d flows remain", got)
			}

			// And the flow still works after all that activity. Earlier
			// datagrams of the same flow may still be queued on the agent
			// conn, so read until the marker arrives.
			sendTo(t, client, tun, []byte("still-here"))
			readFramedUntil(t, agent, []byte("still-here"), "the refreshed flow")
		})
	}
}

// TestUdpShutdownTearsDownFlows pins the no-leaks gate (SPEC §5-4): a tunnel
// shutdown closes the socket, the janitor and every flow's proxy conn, and
// empties the table -- run under -race, which is where a flow whose pumps
// outlive their tunnel would show up.
func TestUdpShutdownTearsDownFlows(t *testing.T) {
	setupTestRegistry(t)
	ctl := testControl(t, "")

	agentA, agentB := armProxyPool(t, ctl), armProxyPool(t, ctl)
	tun := registerTestTunnel(t, ctl, msg.ReqTunnel{Protocol: msg.ProtoUDP})

	clientA, clientB := udpClient(t), udpClient(t)
	sendTo(t, clientA, tun, []byte("a"))
	sendTo(t, clientB, tun, []byte("b"))
	agentsByClientAddr(t, agentA, agentB)
	drainFramed(t, agentA, "flow A")
	drainFramed(t, agentB, "flow B")
	waitFlowCount(t, tun, 2, "the flows were never established")

	tun.Shutdown()

	// Every proxy conn is closed: each agent's next read fails.
	for i, agent := range []conn.Conn{agentA, agentB} {
		if err := agent.SetReadDeadline(time.Now().Add(publicTimeout)); err != nil {
			t.Fatalf("failed to set a read deadline: %v", err)
		}
		buf := make([]byte, 16)
		if _, err := agent.Read(buf); err == nil {
			t.Fatalf("flow %d's proxy conn is still open after shutdown", i)
		}
	}
	waitFlowCount(t, tun, 0, "the flow table was never emptied")

	// A datagram sent after shutdown finds nothing: no flow forms, and the
	// reader loop is gone with the socket.
	sendTo(t, clientA, tun, []byte("into-the-void"))
	expectSilence(t, clientA, "the public client")
}

// TestUdpFlowConnectVerdictDropsSilently covers the endpoint's on_tcp_connect
// phase on the flow path: a refused flow is never handed to an agent and the
// public caller observes nothing -- UDP's refusal is silence.
func TestUdpFlowConnectVerdictDropsSilently(t *testing.T) {
	setupTestRegistry(t)
	ctl := testControl(t, "")
	agent := armProxyPool(t, ctl)

	tun := registerTestTunnel(t, ctl, msg.ReqTunnel{
		Protocol: msg.ProtoUDP,
		TrafficPolicy: &policy.TrafficPolicy{OnTCPConnect: []*policy.Action{
			policyActionConfig("restrict-ips", map[string]interface{}{
				"deny": []interface{}{"127.0.0.1/32"},
			}),
		}},
	})

	client := udpClient(t)
	sendTo(t, client, tun, []byte("refused-please"))

	expectNoBytes(t, agent, "the agent")
	waitFlowCount(t, tun, 0, "the refused flow must not stay in the table")
	expectSilence(t, client, "the refused caller")
}

// TestUdpFlowAdmissionGates covers the two per-flow admission gates, each
// dropping the SECOND caller without disturbing the first: the per-IP rate
// limiter (which counts attempts) and the per-IP connection cap (which the
// established flow holds).
func TestUdpFlowAdmissionGates(t *testing.T) {
	t.Run("rate limiter", func(t *testing.T) {
		prevPublicLimiter := publicLimiter
		publicLimiter = newIPRateLimiter(1, time.Second)
		t.Cleanup(func() { publicLimiter = prevPublicLimiter })

		setupTestRegistry(t)
		ctl := testControl(t, "")
		armed := armProxyPool(t, ctl)
		tun := registerTestTunnel(t, ctl, msg.ReqTunnel{Protocol: msg.ProtoUDP})

		first, second := udpClient(t), udpClient(t)
		sendTo(t, first, tun, []byte("first"))
		readStartProxy(t, armed, "the first agent")
		drainFramed(t, armed, "the first flow")
		waitFlowCount(t, tun, 1, "the first flow was never established")

		// The second caller burns the window's last allow and is dropped
		// before any agent is asked.
		sendTo(t, second, tun, []byte("second"))
		expectNoBytes(t, armed, "the armed agent")
		expectSilence(t, second, "the rate-limited caller")
		waitFlowCount(t, tun, 1, "the refused attempt must not disturb the live flow")
	})

	t.Run("connection cap", func(t *testing.T) {
		prevConnLimiter := connLimiter
		connLimiter = newIPConnLimiter(1)
		t.Cleanup(func() { connLimiter = prevConnLimiter })

		setupTestRegistry(t)
		ctl := testControl(t, "")
		armed := armProxyPool(t, ctl)
		tun := registerTestTunnel(t, ctl, msg.ReqTunnel{Protocol: msg.ProtoUDP})

		first, second := udpClient(t), udpClient(t)
		sendTo(t, first, tun, []byte("first"))
		readStartProxy(t, armed, "the first agent")
		drainFramed(t, armed, "the first flow")
		waitFlowCount(t, tun, 1, "the first flow was never established")

		// The live flow holds the cap; the second caller is dropped, and the
		// first flow's datagrams still relay.
		sendTo(t, second, tun, []byte("second"))
		expectNoBytes(t, armed, "the armed agent")
		expectSilence(t, second, "the capped caller")
		waitFlowCount(t, tun, 1, "the capped caller must not disturb the live flow")
	})
}

// TestUdpPoolingServesFlowsRoundRobin pins per-FLOW pooling assignment: two
// agents share one public socket, and the flows established on it are handed
// out round-robin -- one each, in the order they were established.
func TestUdpPoolingServesFlowsRoundRobin(t *testing.T) {
	reg := setupTestRegistry(t)

	creatorCtl := testControl(t, "")
	memberCtl := testControl(t, "")
	creatorProxy := armProxyPool(t, creatorCtl)
	memberProxy := armProxyPool(t, memberCtl)

	creator := registerTestTunnel(t, creatorCtl, msg.ReqTunnel{Protocol: msg.ProtoUDP, Pooling: true})
	port := creator.udpConn.LocalAddr().(*net.UDPAddr).Port
	registerTestTunnel(t, memberCtl, msg.ReqTunnel{Protocol: msg.ProtoUDP, Pooling: true, RemotePort: uint16(port)})
	if got := len(reg.tunnels[creator.url].tunnels); got != 2 {
		t.Fatalf("the bucket holds %d members, want 2", got)
	}

	// Two flows, two agents: the first establishment draws from the creator's
	// pool, the second from the member's -- per FLOW, not per tunnel.
	clientA, clientB := udpClient(t), udpClient(t)
	sendTo(t, clientA, creator, []byte("one"))
	sp := readStartProxy(t, creatorProxy, "the creator's agent")
	if sp.Url != creator.url {
		t.Fatalf("the first flow was proxied for %s, want %s", sp.Url, creator.url)
	}
	sendTo(t, clientB, creator, []byte("two"))
	sp = readStartProxy(t, memberProxy, "the member's agent")
	if sp.Url != creator.url {
		t.Fatalf("the second flow was proxied for %s, want the shared url %s", sp.Url, creator.url)
	}

	// Both flows relay: the shared socket serves both agents' clients.
	byClient := map[string]conn.Conn{
		clientA.LocalAddr().String(): creatorProxy,
		clientB.LocalAddr().String(): memberProxy,
	}
	for _, client := range []*net.UDPConn{clientA, clientB} {
		agent := byClient[client.LocalAddr().String()]
		buf := make([]byte, 64)
		if err := agent.SetReadDeadline(time.Now().Add(publicTimeout)); err != nil {
			t.Fatalf("failed to set a read deadline: %v", err)
		}
		if _, err := readFramedDatagram(agent, buf); err != nil {
			t.Fatalf("a pooled member's flow never delivered its datagram: %v", err)
		}
	}
}

// TestUdpFlowConnAdapterIsHonest checks the adapter handed to the connect
// phase: it answers RemoteAddr with the flow's client and refuses to pretend
// it is a stream -- a policy action that tried to read or write it gets an
// error, not a nil-pointer panic.
func TestUdpFlowConnAdapterIsHonest(t *testing.T) {
	c := &udpFlowConn{addr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5353}, Logger: log.NewPrefixLogger("test")}

	if got := c.RemoteAddr().String(); got != "127.0.0.1:5353" {
		t.Fatalf("RemoteAddr = %q, want the flow's client", got)
	}
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("the adapter must refuse reads")
	}
	if _, err := c.Write([]byte("x")); err == nil {
		t.Fatal("the adapter must refuse writes")
	}
	if err := c.Close(); err != nil {
		t.Fatalf("close must be a no-op, got: %v", err)
	}
}
