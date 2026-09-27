package server

// Regression tests for the connection-lifecycle and concurrency findings:
//
//	replaced   the replaced signal does not mutate the client id
//	Q-14       registration errors carry the ReqId and name the request
//	mechanics  the proxy retry loop closes what it discards, a pooling bucket
//	           does not outlive its listener, and a proxied conn's staleness
//	           deadline is stamped when it is handed out
//
// scriptedConn, the connection a test drives completely, lives here and is used
// by security_test.go as well (the bounded-head-read tests need a connection
// whose bytes the test chooses).

import (
	"errors"
	"fmt"
	"io"
	"net"
	"ngrok/conn"
	"ngrok/log"
	"ngrok/msg"
	"ngrok/version"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// a connection the test drives

// scriptedConn is a conn.Conn a test fully controls: it reads whatever the test
// gave it, records every deadline it was given, and fails every write (a test
// that wants a working write uses a real socket instead -- see armProxyPool).
//
// It exists for the paths that treat a conn as an opaque handle: reading a
// request head off one, and closing one that a write to it failed. Neither
// needs a peer, and both need the conn to do exactly what the test says.
type scriptedConn struct {
	log.Logger

	id string

	mu        sync.Mutex
	reader    io.Reader
	writeErr  error
	reads     int
	writes    int
	closes    int
	deadlines []time.Time
}

func newScriptedConn(reader io.Reader) *scriptedConn {
	return &scriptedConn{
		Logger:   log.NewPrefixLogger("script"),
		id:       "scripted",
		reader:   reader,
		writeErr: errors.New("the scripted conn refuses to write"),
	}
}

func (c *scriptedConn) Id() string         { return c.id }
func (c *scriptedConn) SetType(typ string) {}
func (c *scriptedConn) CloseRead() error   { return nil }

func (c *scriptedConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	c.reads++
	reader := c.reader
	c.mu.Unlock()

	if reader == nil {
		return 0, io.EOF
	}
	return reader.Read(p)
}

func (c *scriptedConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.writes++
	err := c.writeErr
	c.mu.Unlock()
	return 0, err
}

func (c *scriptedConn) Close() error {
	c.mu.Lock()
	c.closes++
	c.mu.Unlock()
	return nil
}

func (c *scriptedConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}
}

func (c *scriptedConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}
}

func (c *scriptedConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadlines = append(c.deadlines, t)
	c.mu.Unlock()
	return nil
}

func (c *scriptedConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *scriptedConn) SetWriteDeadline(t time.Time) error { return nil }

// allowWrites makes the conn's writes succeed, for the tests that care about
// what happens after a write rather than about the failure of one.
func (c *scriptedConn) allowWrites() {
	c.mu.Lock()
	c.writeErr = nil
	c.mu.Unlock()
}

func (c *scriptedConn) closeCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closes
}

func (c *scriptedConn) writeCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writes
}

func (c *scriptedConn) deadlineCalls() []time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]time.Time(nil), c.deadlines...)
}

// expectStillOpen asserts that a connection is still held open by its peer: a
// read that times out is the only outcome that says so. EOF or a reset means
// the peer closed, which for a joined connection means the join returned.
func expectStillOpen(t *testing.T, c conn.Conn, what string) {
	t.Helper()

	if err := c.SetReadDeadline(time.Now().Add(250 * time.Millisecond)); err != nil {
		t.Fatalf("failed to set a read deadline: %v", err)
	}
	if n, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatalf("%s delivered %d byte(s), want a connection held open", what, n)
	} else if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
		t.Fatalf("%s: the read ended with %v, want a timeout: the connection was closed", what, err)
	}
}

// nextControlMessage returns the next message written to a control's outbound
// channel, failing the test instead of hanging when nothing is ever written.
func nextControlMessage(t *testing.T, ctl *Control) msg.Message {
	t.Helper()

	select {
	case m := <-ctl.out:
		return m
	case <-time.After(publicTimeout):
		t.Fatal("the control was never sent a message")
		return nil
	}
}

// ---------------------------------------------------------------------------
// Replaced()

// TestReplacedDoesNotMutateTheId covers the race the replacement signal was
// built on: Replaced used to clear c.id so that the stopper's registry Del would
// miss the replacement, which meant writing a field that the affinity cache, the
// metrics, the logs and the admin snapshots all read from other goroutines. The
// id is immutable now and the replacement is a separate flag.
//
// This test is meaningful under -race (the suite runs with it): the readers
// below run concurrently with the replacement, and the write it used to do is
// exactly what the detector would flag.
func TestReplacedDoesNotMutateTheId(t *testing.T) {
	setupTestRegistry(t)
	reg := setupTestControlRegistry(t)

	live, _, resp := startTestControl(t, &msg.Auth{Version: version.Proto})
	if live == nil {
		t.Fatalf("the session under test was not established: %s", resp.Error)
	}
	replacement := testControl(t, "")

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				// the readers that exist in production: the control itself, the
				// registry the cache and the admin view go through
				_ = live.id
				if current := reg.Get(resp.ClientId); current != nil {
					_ = current.id
				}
			}
		}()
	}

	live.Replaced(replacement)

	close(stop)
	wg.Wait()

	if live.id != resp.ClientId {
		t.Fatalf("the id changed on replacement: %q, want %q", live.id, resp.ClientId)
	}
	if !live.wasReplaced() {
		t.Fatal("the control does not know it was replaced")
	}

	// and the flag is what decides: the registry refuses to let the replaced
	// control evict the one that took its id
	reg.Add(resp.ClientId, replacement)
	if err := reg.Del(resp.ClientId, live); err != nil {
		t.Fatalf("Del for a replaced control returned %v, want nil (it is not an error, just a no-op)", err)
	}
	if got := reg.Get(resp.ClientId); got != replacement {
		t.Fatal("the replaced control's Del removed its replacement from the registry")
	}
	if err := reg.Del(resp.ClientId, replacement); err != nil {
		t.Fatalf("Del for the registered control failed: %v", err)
	}
	if got := reg.Get(resp.ClientId); got != nil {
		t.Fatal("the registry kept a control that was properly removed")
	}
}

// TestReplacedControlLeavesTheRegistryToItsReplacement is the end-to-end form of
// the same rule, through the stopper: a session resumed with its secret replaces
// the live control, the old control's stopper runs, and the id stays with the
// replacement. The resume blocks until the old control's shutdown completes, so
// this is not a timing race: by the time it returns, the stopper has run.
func TestReplacedControlLeavesTheRegistryToItsReplacement(t *testing.T) {
	setupTestRegistry(t)
	reg := setupTestControlRegistry(t)

	live, _, first := startTestControl(t, &msg.Auth{Version: version.Proto})
	if live == nil {
		t.Fatalf("the first session was not established: %s", first.Error)
	}

	resumed, _, resp := startTestControl(t, &msg.Auth{
		Version:  version.Proto,
		ClientId: first.ClientId,
		Secret:   first.Secret,
	})
	if resumed == nil {
		t.Fatalf("the resume was refused: %s", resp.Error)
	}

	if got := reg.Get(first.ClientId); got != resumed {
		t.Fatal("the replaced control's shutdown took the id out of the registry")
	}
	if got := reg.Get(first.ClientId); got == live {
		t.Fatal("the registry still points at the replaced control")
	}
}

// ---------------------------------------------------------------------------
// Q-14: registration errors carry the ReqId and name the endpoint

// TestRegistrationErrorsCarryTheReqIdAndTheEndpoint covers what a client needs
// to act on a refusal: the ReqId of the ReqTunnel it sent (without it, a
// rejected tunnel is indistinguishable from one that was never answered) and
// the endpoint it named (the client may have several requests in flight, and
// the id is its only handle on them).
func TestRegistrationErrorsCarryTheReqIdAndTheEndpoint(t *testing.T) {
	setupTestRegistry(t)
	ctl := testControl(t, "")

	// a subdomain that is already taken, so the failure comes from the registry
	// with a name the client can recognize rather than from validation
	registerTestTunnel(t, ctl, msg.ReqTunnel{Protocol: "http", Subdomain: "taken"})

	cases := []struct {
		name         string
		req          msg.ReqTunnel
		wantErr      string
		wantEndpoint string
	}{
		{
			name:         "a public binding claiming an internal hostname",
			req:          msg.ReqTunnel{ReqId: "req-1", Protocol: "http", Hostname: "svc.internal"},
			wantErr:      "requires binding internal",
			wantEndpoint: "svc.internal",
		},
		{
			name:         "internal tcp, which does not exist yet",
			req:          msg.ReqTunnel{ReqId: "req-2", Protocol: "tcp", Binding: msg.BindingInternal, Hostname: "db.internal"},
			wantErr:      "not supported yet",
			wantEndpoint: "db.internal",
		},
		{
			name:         "an internal hostname that is not canonical",
			req:          msg.ReqTunnel{ReqId: "req-3", Protocol: "http", Binding: msg.BindingInternal, Hostname: "Bad.Internal"},
			wantErr:      "must be lowercase",
			wantEndpoint: "Bad.Internal",
		},
		{
			name:         "a subdomain that is already registered",
			req:          msg.ReqTunnel{ReqId: "req-4", Protocol: "http", Subdomain: "taken"},
			wantErr:      "already registered",
			wantEndpoint: "taken." + opts.domain,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := tc.req
			ctl.registerTunnel(&req)

			m := nextControlMessage(t, ctl)
			reply, ok := m.(*msg.NewTunnel)
			if !ok {
				t.Fatalf("the control was sent %T, want *msg.NewTunnel", m)
			}
			if reply.ReqId != tc.req.ReqId {
				t.Fatalf("NewTunnel.ReqId = %q, want %q: the client cannot match the answer to its request", reply.ReqId, tc.req.ReqId)
			}
			if !strings.Contains(reply.Error, tc.wantErr) {
				t.Fatalf("the refusal %q does not mention %q", reply.Error, tc.wantErr)
			}
			if !strings.Contains(reply.Error, tc.wantEndpoint) {
				t.Fatalf("the refusal %q does not name the endpoint %q", reply.Error, tc.wantEndpoint)
			}
		})
	}

	// and the acknowledgement of a good registration carries it too
	req := msg.ReqTunnel{ReqId: "req-ok", Protocol: "http", Hostname: "good.ngrok.test"}
	ctl.registerTunnel(&req)

	reply, ok := nextControlMessage(t, ctl).(*msg.NewTunnel)
	if !ok {
		t.Fatal("the control was not sent a *msg.NewTunnel")
	}
	if reply.ReqId != "req-ok" || reply.Url != "http://good.ngrok.test" || reply.Error != "" {
		t.Fatalf("NewTunnel = %+v, want the url and the request's ReqId", reply)
	}
	if ctl.tunnels != nil {
		for _, tun := range ctl.tunnels {
			tun.Shutdown()
		}
	}
}

// ---------------------------------------------------------------------------
// mechanics

// TestProxyRetryClosesWhatItDiscards covers the retry loop in
// HandlePublicConnection: a proxy conn whose StartProxy write failed is closed
// there and then, not deferred to the end of the loop. A defer in the loop piles
// one Close up per failed attempt and runs them all when the public connection
// finishes, so every dead conn -- and the registration it holds on the client --
// stays open for the entire life of the connection being retried.
//
// The discriminator is timing: the two failing conns have to be closed while the
// connection that succeeded is still being served.
func TestProxyRetryClosesWhatItDiscards(t *testing.T) {
	setupTestRegistry(t)
	ctl := testControl(t, "")

	// the two conns the loop will discard, and then the one it will use. All
	// three are in the pool before the listener exists (see armProxyPool).
	failing := []*scriptedConn{newScriptedConn(nil), newScriptedConn(nil)}
	ctl.proxies <- failing[0]
	ctl.proxies <- failing[1]
	agent := armProxyPool(t, ctl)

	tun := registerTestTunnel(t, ctl, msg.ReqTunnel{Protocol: "tcp"})

	dialTcpTunnel(t, tun)

	// the loop reached the third conn: it failed on both scripted ones first
	if got := readStartProxy(t, agent, "the agent"); got.Url != tun.url {
		t.Fatalf("StartProxy Url = %q, want %s", got.Url, tun.url)
	}
	for i, c := range failing {
		if got := c.writeCount(); got != 1 {
			t.Fatalf("conn %d was written to %d time(s), want 1 (it should have been tried once and discarded)", i, got)
		}
	}

	// The public connection is still being served -- the agent is holding the
	// other end open and nothing has been written back -- so a discard that is
	// still pending in a defer would be visible here.
	expectStillOpen(t, agent, "the agent")

	for i, c := range failing {
		if got := c.closeCount(); got != 1 {
			t.Fatalf("conn %d was closed %d time(s) while the connection that replaced it is still being served, want 1", i, got)
		}
	}
}

// TestPoolingBucketDiesWithItsCreator covers the other end of TCP pooling: the
// members share a listener they did not bind, so when the member that bound it
// shuts down, the endpoint is gone for all of them. A bucket left behind would
// keep advertising a pool -- IsPooling would invite new members -- for a port
// nothing listens on, and the orphaned members would keep reporting a tunnel
// that cannot serve a connection.
func TestPoolingBucketDiesWithItsCreator(t *testing.T) {
	reg := setupTestRegistry(t)

	creatorCtl := testControl(t, "")
	memberCtl := testControl(t, "")

	// arm every proxy connection before the listener exists (see armProxyPool)
	armProxyPool(t, creatorCtl)
	armProxyPool(t, memberCtl)

	creator := registerTestTunnel(t, creatorCtl, msg.ReqTunnel{Protocol: "tcp", Pooling: true})
	port := creator.listener.Addr().(*net.TCPAddr).Port

	member := registerTestTunnel(t, memberCtl, msg.ReqTunnel{Protocol: "tcp", Pooling: true, RemotePort: uint16(port)})
	if member.url != creator.url {
		t.Fatalf("the member registered %s, want %s", member.url, creator.url)
	}
	if !reg.IsPooling(creator.url) {
		t.Fatal("the bucket does not report itself as pooling")
	}

	creator.Shutdown()

	if _, ok := reg.tunnels[creator.url]; ok {
		t.Fatal("the bucket outlived the listener it was serving")
	}
	if reg.IsPooling(creator.url) {
		t.Fatal("the url still advertises a pool with no listener")
	}
	if atomic.LoadInt32(&member.closing) != 1 {
		t.Fatal("the orphaned member was not shut down: its endpoint is gone but it still reports a tunnel")
	}

	// the port is really gone, not just unregistered
	if c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 250*time.Millisecond); err == nil {
		c.Close()
		t.Fatal("the pooled port still accepts connections after its listener was closed")
	}

	// and the member's own shutdown does not put the bucket back
	member.Shutdown()
	if len(reg.tunnels) != 0 {
		t.Fatalf("the registry holds %d buckets after both members shut down, want 0", len(reg.tunnels))
	}
}

// TestProxyDeadlineIsStampedWhenTheConnIsHandedOut covers the staleness deadline
// on a pooled proxy conn: it is the budget for the StartProxy handshake that
// follows a handout, so it has to start at the handout. Stamped at registration
// instead, a conn that waited in the pool would be handed out with the remainder
// of its budget -- and the write that opens it would fail on a conn that is
// perfectly healthy.
func TestProxyDeadlineIsStampedWhenTheConnIsHandedOut(t *testing.T) {
	setupTestRegistry(t)
	ctl := testControl(t, "")

	proxy := newScriptedConn(nil)

	pooledAt := time.Now()
	ctl.RegisterProxy(proxy)

	if got := len(proxy.deadlineCalls()); got != 0 {
		t.Fatalf("the conn was given %d deadline(s) when it entered the pool, want 0: the clock must start when it is handed out", got)
	}

	// let it sit in the pool: a deadline started at registration would be that
	// much closer to expiring by the time it is used
	time.Sleep(30 * time.Millisecond)

	before := time.Now()
	got, err := ctl.GetProxy()
	if err != nil {
		t.Fatalf("GetProxy failed: %v", err)
	}
	if got != proxy {
		t.Fatal("GetProxy returned a different connection than the one in the pool")
	}

	deadlines := proxy.deadlineCalls()
	if len(deadlines) != 1 {
		t.Fatalf("the conn was given %d deadline(s) at handout, want exactly 1", len(deadlines))
	}
	if deadlines[0].Before(before.Add(proxyStaleDuration)) {
		t.Fatalf("the handout stamped %v, which is less than a full %v from the handout: the conn's dwell in the pool was charged against it",
			deadlines[0], proxyStaleDuration)
	}
	if deadlines[0].After(time.Now().Add(proxyStaleDuration)) {
		t.Fatalf("the handout stamped %v, which is further out than a full %v from now", deadlines[0], proxyStaleDuration)
	}

	// the deadline is the handshake budget and nothing else: the field it was
	// stamped for is the one that was measured, not a byproduct of insertion
	if pooledAt.After(before) {
		t.Fatal("the test's clock went backwards")
	}
}

// TestHandshakeDeadlineIsClearedOnceTheConnectionIsServing is the companion: the
// budget stamped at handout covers the StartProxy handshake, and it is cleared
// once that handshake is done, so a proxied connection is not timed out by the
// budget that opened it (an idle websocket is the case that matters).
//
// The conn is scripted so that both deadlines are observable: the handshake
// budget, and the cleared deadline that follows it.
func TestHandshakeDeadlineIsClearedOnceTheConnectionIsServing(t *testing.T) {
	setupTestRegistry(t)
	ctl := testControl(t, "")

	proxy := newScriptedConn(nil)
	proxy.allowWrites()
	ctl.proxies <- proxy

	tun := registerTestTunnel(t, ctl, msg.ReqTunnel{Protocol: "tcp"})

	// the scripted conn's reads are at EOF, so the join returns as soon as it
	// starts -- this test is about the two deadlines, not about the join
	_, publicServer := tcpPair(t)
	served := make(chan struct{})
	go func() {
		defer close(served)
		tun.HandlePublicConnection(conn.Wrap(publicServer, "pub"), nil)
	}()

	select {
	case <-served:
	case <-time.After(publicTimeout):
		t.Fatal("HandlePublicConnection never returned")
	}

	deadlines := proxy.deadlineCalls()
	if len(deadlines) != 2 {
		t.Fatalf("the conn was given %d deadline(s), want 2 (the handshake budget, then the cleared deadline)", len(deadlines))
	}
	if deadlines[0].IsZero() {
		t.Fatal("the conn was handed out with no deadline: nothing bounds a handshake against a peer that is gone")
	}
	if !deadlines[1].IsZero() {
		t.Fatalf("the handshake deadline (%v) was not cleared before the join: the budget outlives the handshake", deadlines[1])
	}
}
