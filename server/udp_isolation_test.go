package server

// Two-flow isolation under a stalled agent (SPEC-CLUSTER8 §3.1).
//
// TestUdpFullQueueDoesNotSustainFlow (udp_test.go) pins what a stalled agent
// leg costs its OWN flow: a client shouting into a full queue sustains
// nothing, and the flow still expires. This file pins the other dimension the
// queue exists for: what the stall costs the OTHER flows of the same port --
// which must be nothing.
//
// What a stall IS here is worth spelling out, because a UDP flow has no TCP
// shape of a stopped reader: the flow's agent->public pump reads its proxy
// conn continuously and relays into the client's socket, which a test client
// that never receives simply lets overflow -- so the leg is "stalled" in the
// sense the queue is built for (enqueue's: the flow's agent cannot keep up
// and the overflow drops), and the test holds that state the honest way, by
// feeding the flow faster than its agent leg is drained for the whole
// measurement window. One stalled flow must not tax the healthy flow sharing
// the port, and must not tear itself down early either (expiry is the
// janitor's clock, not the queue's).

import (
	"bytes"
	"fmt"
	"net"
	"testing"
	"time"

	"ngrok/conn"
	"ngrok/msg"
)

// flowFor returns the flow a client address holds in the tunnel's table, read
// under the table's lock the way the janitor reads it.
func flowFor(tun *Tunnel, client *net.UDPAddr) *udpFlow {
	tun.flows.mu.Lock()
	defer tun.flows.mu.Unlock()
	return tun.flows.flows[client.String()]
}

// armStalledProxy is armProxyPool with the proxy pair's kernel buffers pinned
// small on both ends: the smaller the leg's kernel reserve, the sooner a feed
// outpaces it and the queue is what absorbs the difference, which is the state
// under test. (The buffers do not freeze the pump -- on loopback the flow's
// own reader keeps draining into the unread end -- they only shrink the
// headroom the kernel holds before the queue takes over.)
func armStalledProxy(t *testing.T, ctl *Control) conn.Conn {
	t.Helper()

	proxyClient, proxyServer := tcpPair(t)
	for _, c := range []*net.TCPConn{proxyClient, proxyServer} {
		if err := c.SetReadBuffer(2048); err != nil {
			t.Fatalf("failed to pin a small read buffer: %v", err)
		}
		if err := c.SetWriteBuffer(2048); err != nil {
			t.Fatalf("failed to pin a small write buffer: %v", err)
		}
	}
	ctl.proxies <- conn.Wrap(proxyServer, "pxy")
	return conn.Wrap(proxyClient, "pxy")
}

// TestUdpStalledFlowDoesNotStarveHealthyFlow: flow A's agent leg is never
// read, and a feeder keeps A's 16-slot queue pinned at capacity -- every new
// datagram of A's is an overflow drop -- for the whole window in which flow B,
// healthy, round-trips. B must complete every round-trip within the ordinary
// public deadline, ten times over: a single lucky round-trip could precede the
// saturation, these cannot escape it. The tunnel's reader never blocks on a
// flow, so nothing about A's saturation is allowed to delay B beyond the
// deadlines any quiet tunnel would meet. The saturation must also be held, not
// glimpsed: the feeder is still feeding at capacity when the window ends, and
// both flows still hold their table slots.
func TestUdpStalledFlowDoesNotStarveHealthyFlow(t *testing.T) {
	setupTestRegistry(t)
	ctl := testControl(t, "")
	agentStalled, agentHealthy := armStalledProxy(t, ctl), armProxyPool(t, ctl)
	tun := registerTestTunnel(t, ctl, msg.ReqTunnel{Protocol: msg.ProtoUDP})

	clientA, clientB := udpClient(t), udpClient(t)

	// Establish both flows, and map the StartProxy handshakes to their agents
	// by the client address each names -- which agent got which flow is a
	// scheduling order the test does not pin, so the stalled LEG is identified
	// by which agent conn received it, and the client behind it is the one the
	// feeder saturates.
	sendTo(t, clientA, tun, []byte("start-a"))
	sendTo(t, clientB, tun, []byte("start-b"))
	byClient := agentsByClientAddr(t, agentStalled, agentHealthy)
	var stalledClient, healthyClient *net.UDPConn
	for _, c := range []*net.UDPConn{clientA, clientB} {
		switch byClient[c.LocalAddr().String()] {
		case agentStalled:
			stalledClient = c
		case agentHealthy:
			healthyClient = c
		}
	}
	if stalledClient == nil || healthyClient == nil {
		t.Fatalf("both flows must be established (got %v)", byClient)
	}
	healthy := byClient[healthyClient.LocalAddr().String()]
	drainFramed(t, healthy, "the healthy flow") // its start datagram off its wire
	waitFlowCount(t, tun, 2, "the two flows were never established")

	flowA := flowFor(tun, stalledClient.LocalAddr().(*net.UDPAddr))
	if flowA == nil {
		t.Fatal("the stalled flow is not in the table")
	}
	depth := func() int { return len(flowA.inbound) }

	// The feeder: datagrams from the stalled flow's client whenever the queue
	// has room, nothing when it is full -- the same shape as the sustained
	// shout TestUdpFullQueueDoesNotSustainFlow uses, held for the whole test.
	// It reports errors to the test goroutine instead of calling t.Fatalf, and
	// stops at a send budget so a broken reader fails this test instead of
	// running away.
	dest := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: tun.udpConn.LocalAddr().(*net.UDPAddr).Port}
	feedErr := make(chan error, 1)
	fedDone := make(chan int, 1)
	stopFeeder := make(chan struct{})
	go func() {
		payload := make([]byte, 8192)
		sent := 0
		for sent < 8192 { // the budget: 64 MiB without saturation
			select {
			case <-stopFeeder:
				fedDone <- sent
				return
			default:
			}
			if depth() < udpFlowQueueDepth {
				if _, err := stalledClient.WriteToUDP(payload, dest); err != nil {
					feedErr <- err
					fedDone <- sent
					return
				}
				sent++
				continue
			}
			time.Sleep(time.Millisecond)
		}
		fedDone <- sent
	}()

	// Prove the saturation before measuring B: the queue must sit at capacity
	// across a settle window, with the feeder demonstrably still feeding into
	// it -- a queue pinned full while far more than its 16 slots have been sent
	// is saturation with dropping, not a queue that happens to be full.
	saturated := func(samples int, what string) {
		t.Helper()

		full := 0
		deadline := time.Now().Add(publicTimeout)
		for time.Now().Before(deadline) {
			select {
			case err := <-feedErr:
				t.Fatalf("%s: the feeder's send failed: %v", what, err)
			case sent := <-fedDone:
				t.Fatalf("%s: the feeder exhausted its %d-datagram budget before the queue held full", what, sent)
			default:
			}
			if depth() == udpFlowQueueDepth {
				full++
				if full == samples {
					return
				}
			} else {
				full = 0
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatalf("%s: the stalled flow's queue never held a full %d slots", what, udpFlowQueueDepth)
	}
	saturated(6, "before the healthy flow's round-trips")

	// The healthy flow round-trips within an ordinary deadline while the
	// stalled flow's queue is pinned full: request in, datagram framed on the
	// agent's conn, reply framed back, and the reply received from the
	// tunnel's public port.
	scratch := make([]byte, udpFrameLenBytes+64)
	for i := 0; i < 10; i++ {
		ping := []byte(fmt.Sprintf("ping-%d", i))
		pong := []byte(fmt.Sprintf("pong-%d", i))

		sendTo(t, healthyClient, tun, ping)
		readFramedUntil(t, healthy, ping, fmt.Sprintf("the healthy flow's ping %d", i))
		if err := writeFramedDatagram(healthy, pong, scratch); err != nil {
			t.Fatalf("failed to frame the healthy flow's reply %d: %v", i, err)
		}
		got, _ := recvFrom(t, healthyClient, fmt.Sprintf("the healthy flow's round-trip %d", i))
		if !bytes.Equal(got, pong) {
			t.Fatalf("the healthy flow received %q, want %q -- the stalled flow's saturation misrouted or delayed the healthy flow's traffic", got, pong)
		}
	}

	// The stall cost the stalled flow nothing but its overflow: it still holds
	// its table slot, the queue is STILL pinned full with the feeder still
	// feeding (so the saturation outlasted the measurement window it framed),
	// and the tunnel's reader took the healthy flow's traffic throughout.
	saturated(3, "after the healthy flow's round-trips")
	if got := flowCount(tun); got != 2 {
		t.Fatalf("the flow table holds %d flows after the healthy flow's round-trips, want both", got)
	}

	close(stopFeeder)
	if sent := <-fedDone; sent < udpFlowQueueDepth {
		t.Fatalf("the feeder sent only %d datagrams -- less than one queue's worth, so the saturation was never fed at all", sent)
	}
}
