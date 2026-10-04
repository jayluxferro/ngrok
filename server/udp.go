package server

// UDP tunnels (SPEC-CLUSTER8 §3.1).
//
// A udp tunnel is a per-tunnel *net.UDPConn bound exactly the way a tcp
// tunnel binds its listener, plus a flow table that maps public client
// addresses to proxy connections. UDP has no connections, so the server
// invents the unit of admission: a FLOW is one public (ip, port) that has
// sent at least one datagram, and everything the TCP path does per accepted
// connection -- rate limit, connection cap, on_tcp_connect, GetProxy,
// StartProxy, one proxy conn per unit of traffic -- the UDP path does per
// flow, at the first datagram. Lossiness is a property we keep, not one we
// fix: no retransmission, no reordering, no fragmentation beyond the socket.
//
// Datagram framing on the proxy leg (SPEC §3.1): the proxy conn is a byte
// stream (TCP, smux, or a QUIC stream), so each datagram travels as a 4-byte
// big-endian length prefix followed by its payload. A length field beyond
// udpMaxDatagramSize is a protocol error and closes the flow -- there is no
// way to resynchronize a stream whose framing an agent broke.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"ngrok/conn"
	"ngrok/log"
	"ngrok/msg"
	"ngrok/util"
)

const (
	// udpMaxDatagramSize is the largest datagram the pipe carries: the
	// maximum payload of a UDP/IPv4 datagram (65535 - 20 IP - 8 UDP). A
	// length field beyond it cannot have come from a datagram anyone could
	// have sent, so it is a framing error, not traffic.
	udpMaxDatagramSize = 65507

	// udpReadBufferSize is the public-side read buffer: 64 KiB, one whole
	// maximum datagram plus headroom. A datagram larger than the buffer is
	// truncated by the socket read; since a legal datagram never exceeds
	// udpMaxDatagramSize, anything read past that mark is dropped as
	// truncated rather than relayed in pieces (SPEC §5-3).
	udpReadBufferSize = 64 * 1024

	// udpFrameLenBytes is the width of the proxy-leg length prefix.
	udpFrameLenBytes = 4

	// udpFlowQueueDepth bounds the datagrams a flow may hold between the
	// tunnel's reader and its proxy conn. The reader never blocks on a
	// stalled agent -- that would freeze every flow of the tunnel -- so a
	// flow whose agent cannot keep up drops its overflow, exactly as a
	// congested UDP path would.
	udpFlowQueueDepth = 16

	// udpExpiryScanDivisor picks how often the janitor looks for idle flows:
	// every fourth of the idle timeout, so a flow dies within ~25% of its
	// budget of being forgotten.
	udpExpiryScanDivisor = 4

	// maxFlowsPerUdpTunnel is the per-tunnel flow cap: at/over cap, the
	// datagram that would have to CREATE a flow is dropped (one extending an
	// existing flow always passes). Without a cap, one tunnel with a
	// wide-spoofed source flood grows flows (each a goroutine, an inbound
	// queue and a limiter slot) without bound even with every other gate
	// healthy. The default is generous for real tunnel workloads.
	maxFlowsPerUdpTunnel = 1024

	// defaultMaxUdpFlows is the process-wide default for maxUdpFlows: the
	// global ceiling on live flows across ALL tunnels.
	defaultMaxUdpFlows = 16384
)

// udpRemoteIP is remoteIP (server/ratelimit.go) for a UDP address: the
// existing helper type-asserts *net.TCPAddr and answers "" for everything
// else, which would put every UDP flow behind one limiter bucket named "".
func udpRemoteIP(addr *net.UDPAddr) string {
	if addr == nil || addr.IP == nil {
		return ""
	}
	return addr.IP.String()
}

// defaultUdpIdleTimeout is how long a flow survives with no datagram in
// either direction.
//
// It is deliberately NOT operator-configurable (no -udpIdleTimeout flag,
// nothing in server/config.go): the client mirrors the same 30s (SPEC §3.2)
// so that both ends agree a silent flow has ended. A server-side knob with no
// wire message to negotiate it would let the two ends disagree -- the agent
// would tear its half down at 30s while the server keeps the flow for 10m,
// or vice versa -- and the failure mode would be a tunnel that silently
// drops replies for reasons no configuration states. One constant, both
// ends, is the design; if it ever needs to move, it moves in the protocol.
//
// The live value sits in an atomic rather than a plain package variable
// because tests shrink it: janitor goroutines from earlier tests are
// legitimately still starting up while a later test rewrites the timeout,
// and a plain variable would be a data race the test binary must catch.
const defaultUdpIdleTimeout = 30 * time.Second

var udpIdleTimeoutNanos atomic.Int64

// udpMaxTunnelFlows is the LIVE per-tunnel flow cap. Like the idle timeout
// above, the shipped value is a constant (maxFlowsPerUdpTunnel) and the live
// value sits in an atomic because tests shrink it: a cap of 1024 would need
// 1024 real public sockets to exercise, which is exactly the kind of test
// that flakes on fd limits. Same reasoning, same precedent, same file.
var udpMaxTunnelFlows atomic.Int64

// maxUdpFlows is the LIVE process-wide flow cap across all tunnels, seeded
// from defaultMaxUdpFlows. It is an atomic (not a const) so an operator-ish
// future flag -- and the tests -- can move it without a rebuild; production
// never writes it.
var maxUdpFlows atomic.Int64

// liveUdpFlows counts live flows process-wide (created minus closed). The
// creation path reserves a slot with a CAS against maxUdpFlows -- not a plain
// Add-then-check, which would blow past the cap under a race -- and close
// returns its slot.
var liveUdpFlows atomic.Int64

// udpFlowCapDrops counts datagrams dropped because a flow cap refused to
// create their flow (per-tunnel + global, one counter: both are "no new flow
// for you"). The drop event names the IP; this counter is the cheap total.
var udpFlowCapDrops atomic.Uint64

func init() {
	udpIdleTimeoutNanos.Store(int64(defaultUdpIdleTimeout))
	udpMaxTunnelFlows.Store(maxFlowsPerUdpTunnel)
	maxUdpFlows.Store(defaultMaxUdpFlows)
}

// udpIdleTimeout is the flow idle deadline currently in force.
func udpIdleTimeout() time.Duration {
	return time.Duration(udpIdleTimeoutNanos.Load())
}

// errDatagramTooLarge is the framing error a proxy leg commits when its
// length prefix promises more than any datagram could be.
var errDatagramTooLarge = errors.New("datagram length exceeds the 65507-byte maximum")

// ---------------------------------------------------------------------------
// flow table

// udpFlowTable holds a tunnel's live flows, keyed by the client address the
// flow was established from. One mutex guards it: every operation is a single
// map step plus the flow's own bookkeeping, so a finer-grained lock buys
// nothing, and the establish/expire/close paths all read more clearly when
// the table's state is decided under one lock.
type udpFlowTable struct {
	t *Tunnel

	mu    sync.Mutex
	flows map[string]*udpFlow

	// done is closed by closeAll and ends the janitor goroutine.
	done chan struct{}

	// closeOnce makes closeAll idempotent. Shutdown is expected to tolerate
	// being called twice (the TCP path does: a second Close on a closed
	// listener and a second DelBucket are both no-ops), and a table teardown
	// that panics on the second call would break that contract.
	closeOnce sync.Once
}

func newUdpFlowTable(t *Tunnel) *udpFlowTable {
	return &udpFlowTable{
		t:     t,
		flows: make(map[string]*udpFlow),
		done:  make(chan struct{}),
	}
}

// start launches the table's janitor. It is called once, when the tunnel
// binds its public socket.
func (tbl *udpFlowTable) start() {
	go tbl.janitor()
}

// getOrCreate returns the flow for addr, establishing one when the address
// has never sent a datagram to this tunnel (or its last flow has expired or
// been refused). It returns nil when the datagram's flow was REFUSED by an
// admission gate: the caller drops the payload and nothing else happens --
// no flow entry, no establishment goroutine, no proxy conn, no queue. The
// gates moved here (before creation, on the reader's goroutine) from
// establishUdpFlow precisely so a denied datagram costs nothing: the old
// order created the flow first and admitted it after, so a spoofed-source
// flood bought a goroutine + queue + table entry per source even when every
// gate said no.
//
// A datagram that EXTENDS an existing flow skips the gates by design: the
// flow already paid admission and holds its slot; per-datagram re-gating
// would count limiter attempts per datagram (rate limits are per attempt,
// and a chatty flow would lock its own IP out mid-session) and re-acquire
// slots it already holds.
//
// The FLOW owns the admission budget from creation: the connLimiter slot,
// the public-connection count and the global flow slot are acquired here and
// released exactly once, by close. Establishment only decides whether the
// flow lives long enough to serve; its refusals (verdict, no agent) close
// the flow, which is what releases.
func (tbl *udpFlowTable) getOrCreate(addr *net.UDPAddr) *udpFlow {
	tbl.mu.Lock()
	defer tbl.mu.Unlock()

	key := addr.String()
	if f, ok := tbl.flows[key]; ok {
		return f
	}

	// --- admission gates (in order: rate, caps, connection cap) ---
	//
	// The warns here go through the PACKAGE logger, not the tunnel's prefix
	// logger: the reader goroutine starts inside register(), BEFORE NewTunnel
	// finishes adding the tunnel's log prefixes, and a datagram that lands in
	// that window would make prefix-write (NewTunnel) race prefix-read
	// (these warns) -- exactly what -race caught. The tunnel id travels in
	// the message; it is assigned before the reader exists.

	ip := udpRemoteIP(addr)
	if !publicLimiter.Load().allow(ip) {
		atomic.AddUint64(&rateDropCount, 1)
		observe.events.publishRateLimitDrop(scopePublicUDP, ip)
		if warnSampler.allow("udp-rate:" + ip) {
			log.Warn("Rate-limited UDP public flow from %s (tunnel %s)", ip, tbl.t.Id())
		}
		return nil
	}

	// Flow caps: per tunnel (the table length, exact under this lock) and
	// global (CAS slot). Both answer with the connection-cap event -- they
	// ARE capacity refusals, the flow-table flavour of them -- plus the
	// drop counter.
	if int64(len(tbl.flows)) >= udpMaxTunnelFlows.Load() {
		udpFlowCapDrops.Add(1)
		observe.events.publishConnectionCapDrop(scopePublicUDP, ip)
		if warnSampler.allow("udp-flowcap:" + ip) {
			log.Warn("Flow cap reached for tunnel %s: dropping new flow from %s", tbl.t.Id(), ip)
		}
		return nil
	}
	for {
		n := liveUdpFlows.Load()
		if n >= maxUdpFlows.Load() {
			udpFlowCapDrops.Add(1)
			observe.events.publishConnectionCapDrop(scopePublicUDP, ip)
			if warnSampler.allow("udp-flowcap:" + ip) {
				log.Warn("Global UDP flow cap reached (%d live flows): dropping new flow from %s", n, ip)
			}
			return nil
		}
		if liveUdpFlows.CompareAndSwap(n, n+1) {
			break
		}
	}

	// Roll back the global slot if the connection cap refuses below.
	if !connLimiter.Load().acquire(ip) {
		liveUdpFlows.Add(-1)
		observe.events.publishConnectionCapDrop(scopePublicUDP, ip)
		if warnSampler.allow("udp-cap:" + ip) {
			log.Warn("Connection cap reached for %s (tunnel %s)", ip, tbl.t.Id())
		}
		return nil
	}
	incPublicConns()

	f := &udpFlow{
		table:   tbl,
		client:  addr,
		inbound: make(chan []byte, udpFlowQueueDepth),
		done:    make(chan struct{}),
		Logger:  log.NewPrefixLogger(tbl.t.Id(), "udp-flow"),
	}
	tbl.flows[key] = f
	go tbl.t.establishUdpFlow(f)
	return f
}

// remove drops f from the table if it is still the flow registered for its
// address. The identity check matters: a refused or expired flow is removed
// by its close, and the next datagram from that address must be free to
// establish a fresh flow -- but that fresh flow must not be evicted by the
// earlier one's teardown arriving late.
func (tbl *udpFlowTable) remove(f *udpFlow) {
	tbl.mu.Lock()
	defer tbl.mu.Unlock()

	key := f.client.String()
	if tbl.flows[key] == f {
		delete(tbl.flows, key)
	}
}

// expireIdle closes every flow whose last ACCEPTED INBOUND datagram is older
// than udpIdleTimeout() (the 30s default, defaultUdpIdleTimeout). Outbound
// (agent) traffic does not count -- see enqueue's idle-semantics note for
// why. Expired flows are snapshotted under the lock and closed outside it:
// close takes the flow's lock and then re-enters the table to remove itself,
// and this path refuses to nest the table lock inside itself.
func (tbl *udpFlowTable) expireIdle() {
	tbl.mu.Lock()
	expired := make([]*udpFlow, 0, 4)
	deadline := time.Now().Add(-udpIdleTimeout())
	for _, f := range tbl.flows {
		f.mu.Lock()
		idle := f.lastActive.Before(deadline)
		f.mu.Unlock()
		if idle {
			expired = append(expired, f)
		}
	}
	tbl.mu.Unlock()

	for _, f := range expired {
		f.Info("UDP flow from %s expired after %s idle", f.client, udpIdleTimeout())
		f.close()
	}
}

// janitor expires idle flows until the table is torn down. Its cadence is a
// fraction of the idle timeout, so a flow's actual lifetime is bounded by its
// budget plus one scan, whatever the timeout is set to.
func (tbl *udpFlowTable) janitor() {
	tick := udpIdleTimeout() / udpExpiryScanDivisor
	if tick <= 0 {
		tick = time.Millisecond
	}
	ticker := time.NewTicker(tick)
	defer ticker.Stop()

	for {
		select {
		case <-tbl.done:
			return
		case <-ticker.C:
			tbl.expireIdle()
		}
	}
}

// closeAll tears the table down: the janitor stops, and every flow is closed
// -- proxy conns included -- so a tunnel shutdown leaks neither goroutines
// nor sockets (SPEC §5-4). Closing the tunnel's public socket first is the
// caller's job (Tunnel.Shutdown); it stops new flows from forming while this
// drains the existing ones.
func (tbl *udpFlowTable) closeAll() {
	tbl.closeOnce.Do(func() {
		tbl.mu.Lock()
		flows := make([]*udpFlow, 0, len(tbl.flows))
		for _, f := range tbl.flows {
			flows = append(flows, f)
		}
		tbl.mu.Unlock()

		close(tbl.done)
		for _, f := range flows {
			f.close()
		}
	})
}

// ---------------------------------------------------------------------------
// flow

// udpFlow is one public client's slice of a udp tunnel: the address it
// datagrams from, the proxy conn its traffic rides to the agent, and the
// idle deadline that ends both.
//
// LIFECYCLE. A flow is created by the tunnel's reader on the first ADMITTED
// datagram from an unknown address (getOrCreate runs the admission gates
// BEFORE anything exists); established (verdict, GetProxy, StartProxy) on its
// own goroutine; served by two half-pumps -- the reader funnels public
// datagrams into the flow's inbound queue and the establish goroutine frames
// them onto the proxy conn, while a dedicated goroutine frames agent
// datagrams off the proxy conn and sends them back out the public socket.
// Every closer path -- idle expiry, a dead proxy conn, tunnel shutdown, a
// refused verdict -- funnels into close, which is idempotent (sync.Once) and
// race-clean against every other participant: the done channel is the one
// "the flow has ended" fact everyone agrees on.
//
// The per-flow admission budget (connLimiter slot + public connection count +
// global flow slot) is acquired at CREATION by getOrCreate and released
// exactly once by close -- the funnel every end-of-flow path goes through --
// so a flow can never die twice against the limiter, a flow refused
// mid-establishment releases everything it holds, and a denied datagram
// never acquired anything at all.
type udpFlow struct {
	// the tunnel this flow belongs to and the table it is registered in
	table *udpFlowTable

	// client is the address this flow is pinned to, captured from the first
	// datagram's sender. Every reply goes to this address and nowhere else --
	// that pin is the flow, and it is also the amplification posture's reply
	// path (SPEC §6-5): nothing this server sends on a flow's behalf is ever
	// addressed anywhere but back to whoever established it.
	client *net.UDPAddr

	// inbound carries public datagrams from the tunnel's reader to the
	// goroutine that frames them onto the proxy conn. It is never closed:
	// close is signaled by done, so the reader's non-blocking send can never
	// race a channel close (a send on a closed channel panics, and the reader
	// must not take a lock that close holds to prevent it).
	inbound chan []byte

	// proxy is the agent conn serving this flow, nil until establishment
	// finishes arming it. Read under mu.
	mu         sync.Mutex
	proxy      conn.Conn
	lastActive time.Time

	// done is closed exactly once, by close, and is the flow's death signal
	// for both pumps.
	done chan struct{}

	// dead mirrors done for the cheap check the reader does before enqueue;
	// written under mu, read under mu.
	dead bool

	// pumps tracks the agent-bound goroutine, and bytesIn/bytesOut count
	// relayed payload bytes per direction (the observability store reports
	// them the way it reports a TCP connection's). establish waits on pumps
	// before accounting, so the counts are final when they are read; nothing
	// in the close path waits on pumps -- close must never block on the very
	// goroutine that may be calling it.
	pumps    sync.WaitGroup
	bytesIn  atomic.Int64
	bytesOut atomic.Int64

	closeOnce sync.Once

	log.Logger
}

// enqueue hands one public datagram to the flow. It never blocks: a flow
// whose queue is full drops the datagram, because the alternative --
// backpressure into the tunnel's reader -- would make one stalled agent
// freeze every flow on the port.
//
// IDLE SEMANTICS (inbound-only, accepted-ONLY): the idle deadline refreshes
// exclusively when a datagram FROM THE PUBLIC CLIENT actually ENTERS the
// queue. A datagram dropped on a full queue sustains nothing -- otherwise a
// client could keep a stalled flow (its limiter slot, its goroutines, its
// proxy conn) alive forever just by shouting into the overflow. And agent
// datagrams -- the replies -- do NOT refresh at all (serveProxyToPublic
// never touches the clock): a flow whose "client" is a spoofed source gets
// its one query answered and then idles out, with no way to keep it on life
// support through reply traffic it tricked the agent into sending. A
// legitimate NAT client sustains its flow the honest way: every request it
// sends enters the queue and pushes the deadline out.
func (f *udpFlow) enqueue(payload []byte) {
	f.mu.Lock()
	if f.dead {
		f.mu.Unlock()
		return
	}
	f.mu.Unlock()

	select {
	case f.inbound <- payload:
		// The datagram was accepted: the client is demonstrably still
		// talking to this flow, so this is the one place the clock moves.
		f.mu.Lock()
		f.lastActive = time.Now()
		f.mu.Unlock()
	default:
		// The flow's agent is not keeping up. Drop -- and refresh nothing:
		// dropped datagrams must not sustain the flow (see above). A nil
		// sampler allows everything (sampler.go), the same discipline the
		// other rejection paths use.
		if warnSampler.allow("udp-overflow:" + udpRemoteIP(f.client)) {
			f.Warn("Dropping datagram for %s: %d datagrams already queued", f.client, udpFlowQueueDepth)
		}
	}
}

// arm installs the proxy conn once establishment has written StartProxy. If
// the flow was closed while GetProxy or the handshake was in flight -- the
// janitor does not wait for establishment -- the proxy is closed again here
// rather than attached: a dead flow acquires nothing that outlives it.
func (f *udpFlow) arm(proxy conn.Conn) bool {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.dead {
		return false
	}
	f.proxy = proxy
	return true
}

// proxyConn returns the armed proxy conn, or nil.
func (f *udpFlow) proxyConn() conn.Conn {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.proxy
}

// close ends the flow: it closes the proxy conn (which is how the agent
// learns the flow ended -- there is no UDP analogue of a FIN to send it),
// removes the flow from the table, and signals both pumps through done.
// Idempotent by construction; safe to call from the janitor, either pump,
// the tunnel's shutdown, or establishment itself, in any order, any number
// of times.
func (f *udpFlow) close() {
	f.closeOnce.Do(func() {
		f.mu.Lock()
		f.dead = true
		proxy := f.proxy
		f.mu.Unlock()

		if proxy != nil {
			proxy.Close()
		}
		f.table.remove(f)
		close(f.done)

		// The flow's admission budget -- the connLimiter slot, the public
		// connection count and the global flow slot -- was acquired at
		// creation (getOrCreate) and is released here exactly once: close is
		// the one funnel every end-of-flow path goes through (idle expiry, a
		// refused verdict, a dead agent leg, tunnel shutdown). Released AFTER
		// remove/close-signaling so nothing holds the table lock while the
		// limiter's lock is taken (lock order: table -> limiter only).
		connLimiter.Load().release(udpRemoteIP(f.client))
		decPublicConns()
		liveUdpFlows.Add(-1)
	})
}

// servePublicToProxy drains the flow's inbound queue onto the proxy conn,
// framing each datagram. It runs on the establishment goroutine and returns
// only when the flow is over, which is what makes that goroutine the right
// place to release the flow's admission budget: the defers there cannot run
// while the flow is still deliverable.
func (f *udpFlow) servePublicToProxy() {
	proxy := f.proxyConn()
	if proxy == nil {
		return
	}

	// One scratch buffer per flow, reused for every datagram: framing writes
	// prefix+payload contiguously, and the buffer's lifetime is the flow's,
	// so nothing shares it and there is nothing to pool.
	scratch := make([]byte, udpFrameLenBytes+udpMaxDatagramSize)

	for {
		select {
		case <-f.done:
			return
		case payload, ok := <-f.inbound:
			if !ok {
				// inbound is never closed (see the field comment); this arm
				// exists so a future refactor that closes it fails visibly
				// here rather than hanging the flow.
				return
			}
			if err := writeFramedDatagram(proxy, payload, scratch); err != nil {
				f.Warn("Failed to forward datagram to agent: %v", err)
				f.close()
				return
			}
			f.bytesIn.Add(int64(len(payload)))
		}
	}
}

// serveProxyToPublic is the agent-bound half: framed datagrams off the proxy
// conn, out the tunnel's public socket to the flow's pinned address. Its
// failure paths -- a framing violation, a dead proxy conn, a closed public
// socket -- all end the flow: half a flow serves nobody.
func (f *udpFlow) serveProxyToPublic(public *net.UDPConn) {
	defer f.pumps.Done()
	defer f.close()

	// One read buffer per flow, sized for the largest datagram the framing
	// can legally carry.
	buf := make([]byte, udpMaxDatagramSize)
	for {
		n, err := readFramedDatagram(f.proxyConn(), buf)
		if err != nil {
			f.Debug("UDP flow from %s: agent leg ended: %v", f.client, err)
			return
		}

		// NOTE: agent datagrams deliberately do NOT refresh the idle
		// deadline (enqueue's doc explains the spoofing posture): only
		// inbound public traffic sustains a flow.
		if _, err := public.WriteToUDP(buf[:n], f.client); err != nil {
			f.Debug("UDP flow from %s: public socket closed: %v", f.client, err)
			return
		}
		f.bytesOut.Add(int64(n))
	}
}

// ---------------------------------------------------------------------------
// establishment

// establishUdpFlow runs the establishment sequence for one new flow -- the
// UDP counterpart of listenTcp's per-connection path, per FLOW instead of per
// connection (SPEC §3.1). The per-IP admission gates (rate limit, flow caps,
// connection cap) and the flow's admission budget moved UP to getOrCreate,
// at creation, so a denied datagram never creates anything; what remains here
// is what needs the flow's own context:
//
//  1. the endpoint's on_tcp_connect phase -- which needs the flow's client
//     address, and runs BEFORE any proxy conn is taken (GetProxy and
//     StartProxy are strictly below) and before anything is written back to
//     the public client (a UDP refusal is silence, SPEC §3.1);
//  2. a proxy conn from the pool introduced by StartProxy with the flow's
//     address as ClientAddr.
//
// The receiver is the tunnel that owns the public socket; the flow is served
// by whichever bucket member the round-robin picks (see below), so pooling
// spreads flows across agents exactly as TCP spreads connections.
func (t *Tunnel) establishUdpFlow(f *udpFlow) {
	defer func() {
		if r := recover(); r != nil {
			f.Error("UDP flow establishment failed with error %v", r)
			f.close()
		}
	}()

	// Hand the flow to a member of the bucket that shares this socket,
	// round-robin, so that pooling spreads flows across the agents that
	// registered the port (SPEC §3.1). A non-pooling bucket contains only us,
	// and we fall back to ourselves if our registration is already gone.
	member := t
	if tunnelRegistry != nil {
		if m := tunnelRegistry.Get(t.url); m != nil {
			member = m
		}
	}

	// The endpoint's on_tcp_connect phase (SPEC §3.3): the phase's name is
	// historical -- it governs every non-HTTP public connection, and a flow
	// is one. A UDP caller has no protocol to be answered in, so a refusal is
	// silence (SPEC §3.1): the flow is closed and the datagram that started
	// it is never relayed. member is the terminus -- forward_to is refused
	// for udp endpoints -- so policyFor(member) is the same policy the pumps
	// run.
	if v := connectVerdict(member.policyFor(member), &udpFlowConn{addr: f.client, Logger: f.Logger}); v.Deny {
		f.Info("Traffic policy refused the flow from %s: %s", f.client, v.Reason)
		f.close()
		return
	}

	// Take a proxy conn from the serving member's pool -- the same pool
	// mechanics, round-robin and refill heuristic the TCP path uses; pooling
	// assignment is per FLOW. Unlike HandlePublicConnection this is a single
	// attempt: a UDP flow whose handshake fails is dropped, and the client's
	// next datagram simply establishes a new flow -- retrying inside a dead
	// flow would hold the public datagrams queued behind a conn that never
	// comes back, which is the one thing UDP promises not to do.
	proxy, err := member.ctl.GetProxy()
	if err != nil {
		f.Warn("Failed to get proxy connection for flow from %s: %v", f.client, err)
		f.close()
		return
	}
	proxy.AddLogPrefix(member.Id())

	startPxyMsg := &msg.StartProxy{
		Url:        member.url,
		ClientAddr: f.client.String(),
	}
	if err = msg.WriteMsg(proxy, startPxyMsg); err != nil {
		proxy.Warn("Failed to write StartProxyMessage: %v", err)
		proxy.Close()
		f.close()
		return
	}

	// The flow may have been closed while we waited for the agent -- idle
	// expiry does not wait for establishment. Arm detects that and refuses;
	// the conn we took from the pool must then be returned the only way a
	// used conn can be: closed.
	if !f.arm(proxy) {
		proxy.Close()
		return
	}

	// Refill the pool behind the conn we just took, exactly as the TCP path
	// does: one conn per outstanding request, plus one when the pool is
	// empty. The pool does not care which transport answers.
	util.PanicToError(func() { member.ctl.out <- &msg.ReqProxy{} })

	// The flow has no business timing out now that its handshake is done;
	// idle expiry is the flow's clock, not the proxy conn's.
	proxy.SetDeadline(time.Time{})

	metrics.OpenConnection(member, proxy)
	observe.onConnOpen(member, f.client.String())
	startTime := time.Now()

	f.Info("New UDP flow from %s over proxy conn %s", f.client, proxy.Id())

	f.pumps.Add(1)
	go f.serveProxyToPublic(t.udpConn)
	f.servePublicToProxy()

	// The flow is over. Wait for the agent-bound pump to observe the closure
	// (close unblocked its read), so the byte counts below are final -- then
	// account the flow the way the TCP path accounts a public connection. The
	// proxy conn itself was closed by flow.close, which is what ended the
	// pump above.
	f.pumps.Wait()
	metrics.CloseConnection(member, proxy, startTime, f.bytesIn.Load(), f.bytesOut.Load())
	observe.onConnClose(member, f.bytesIn.Load(), f.bytesOut.Load())
}

// ---------------------------------------------------------------------------
// framing

// writeFramedDatagram writes one datagram to the proxy leg: a 4-byte
// big-endian length prefix followed by the payload, per SPEC §3.1. scratch
// must be at least udpFrameLenBytes+len(payload) long; the caller reuses one
// per flow.
func writeFramedDatagram(w io.Writer, payload, scratch []byte) error {
	if len(payload) > udpMaxDatagramSize {
		return fmt.Errorf("%w: %d", errDatagramTooLarge, len(payload))
	}
	binary.BigEndian.PutUint32(scratch, uint32(len(payload)))
	copy(scratch[udpFrameLenBytes:], payload)
	_, err := w.Write(scratch[:udpFrameLenBytes+len(payload)])
	return err
}

// readFramedDatagram reads one datagram from the proxy leg into buf and
// returns its length. A length prefix beyond udpMaxDatagramSize is a protocol
// error (the stream has lost its framing; there is no resynchronizing it),
// and so is any stream error -- both end the flow.
func readFramedDatagram(r io.Reader, buf []byte) (int, error) {
	var prefix [udpFrameLenBytes]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return 0, err
	}
	n := binary.BigEndian.Uint32(prefix[:])
	if n > udpMaxDatagramSize {
		return 0, fmt.Errorf("%w: %d", errDatagramTooLarge, n)
	}
	if int(n) > len(buf) {
		return 0, fmt.Errorf("%w: %d", errDatagramTooLarge, n)
	}
	if _, err := io.ReadFull(r, buf[:n]); err != nil {
		return 0, err
	}
	return int(n), nil
}

// ---------------------------------------------------------------------------
// public listener

// listenUdp drains the tunnel's public socket: one reader for the whole
// tunnel, because a UDP socket has no accept -- every datagram arrives here,
// and the flow table decides whether it extends an existing flow or starts a
// new one. The reader never blocks on a flow: establishment and framing both
// happen off this loop (see getOrCreate and enqueue).
func (t *Tunnel) listenUdp(public *net.UDPConn) {
	buf := make([]byte, udpReadBufferSize)
	for {
		n, addr, err := public.ReadFromUDP(buf)
		if err != nil {
			// not an error, we're shutting down this tunnel
			if atomic.LoadInt32(&t.closing) == 1 {
				return
			}
			t.Error("Failed to read from UDP listener: %v", err)
			return
		}

		if n > udpMaxDatagramSize {
			// The socket read truncates anything longer than the buffer; a
			// legal datagram fits, so what arrived here cannot be relayed
			// whole and is dropped, logged (SPEC §3.1).
			if warnSampler.allow("udp-oversize:" + udpRemoteIP(addr)) {
				t.Warn("Dropping %d-byte datagram from %s: exceeds the %d-byte maximum", n, addr, udpMaxDatagramSize)
			}
			continue
		}

		payload := make([]byte, n)
		copy(payload, buf[:n])
		// getOrCreate runs the admission gates for a datagram that would have
		// to CREATE a flow -- before the flow, its goroutine or its proxy conn
		// exists -- and answers nil for a refused one: the datagram is
		// dropped here and nothing was ever built for it.
		if f := t.flows.getOrCreate(addr); f != nil {
			f.enqueue(payload)
		}

		if atomic.LoadInt32(&t.closing) == 1 {
			return
		}
	}
}

// udpFlowConn adapts a flow's client address to the conn.Conn face
// connectVerdict evaluates. The connect phase reads RemoteAddr and nothing
// else (policy.Compiled.EvaluateConnect takes the address string), but the
// adapter completes the interface honestly rather than embedding a nil
// net.Conn whose every accidental use would panic: I/O on a flow is not a
// stream, and the error says so.
type udpFlowConn struct {
	log.Logger
	addr *net.UDPAddr
}

func (c *udpFlowConn) RemoteAddr() net.Addr { return c.addr }
func (c *udpFlowConn) LocalAddr() net.Addr  { return c.addr }

var errNotAStream = errors.New("a UDP flow is not a byte stream")

func (c *udpFlowConn) Read([]byte) (int, error)         { return 0, errNotAStream }
func (c *udpFlowConn) Write(b []byte) (int, error)      { return 0, errNotAStream }
func (c *udpFlowConn) Close() error                     { return nil }
func (c *udpFlowConn) SetDeadline(time.Time) error      { return nil }
func (c *udpFlowConn) SetReadDeadline(time.Time) error  { return nil }
func (c *udpFlowConn) SetWriteDeadline(time.Time) error { return nil }
func (c *udpFlowConn) Id() string                       { return "udp-flow:" + c.addr.String() }
func (c *udpFlowConn) SetType(string)                   {}
func (c *udpFlowConn) CloseRead() error                 { return nil }
