package client

// Tests for the client's end of the multiplexed proxy transport (SPEC cluster 3,
// section 3.1).
//
// The shape of these tests mirrors the real deployment: a fake tunnel listener
// dispatches every accepted conn by its first message, exactly like
// server/main.go's tunnelListener does, so the session dial, the per-ReqProxy
// streams and the fallback dials all run against one fixture -- and the fake
// hands the test the public end of whatever proxy conn its server half served,
// which is where the requests in these tests come from.
//
// What is *not* covered here: the control channel. Reading muxCapability out of
// AuthResp and starting the watchdog happens inside control(), which needs a
// server to speak the whole control protocol to (scripts/e2e.sh covers that end
// to end). Everything the capability turns on -- dialing the session,
// publishing it, opening streams instead of dialing, reconnecting after the
// session dies, giving the slot up when the control session ends -- is below.

import (
	"bufio"
	"github.com/xtaci/smux/v2"
	"io"
	"net"
	"net/http"
	"ngrok/client/mvc"
	"ngrok/conn"
	"ngrok/log"
	"ngrok/msg"
	"sync/atomic"
	"testing"
	"time"
)

// muxTestPublicHost is the host of the tunnel url these tests proxy for: the url
// the fake server names in StartProxy, the key of the model's tunnel map and the
// Host of the public requests.
const muxTestPublicHost = "mux.ngrok.test"

// ---------------------------------------------------------------------------
// the fake server

// fakeTunnelServer stands in for the server's tunnel listener and for the mux
// session behind it. It dispatches each accepted conn by its first message, the
// way the real listener does: RegMux opens a multiplexed session whose streams
// are then served one by one, while a RegProxy on a conn of its own is a dialed
// proxy conn. Both end up in the same place -- StartProxy answered, then the
// conn handed to the test as the public connection.
type fakeTunnelServer struct {
	addr string

	// publicUrl is the tunnel the server claims to be serving, which is how the
	// client knows which of its tunnels a proxy conn belongs to.
	publicUrl string

	// regMux carries the client id of every mux conn that opened with one, and
	// sessions the server side of every mux session, in accept order.
	regMux   chan string
	sessions chan *smux.Session

	// proxies carries every proxy conn whose handshake was answered, in order.
	proxies chan *fakeProxy
}

// fakeProxy is one served proxy conn as the fake server sees it after the
// handshake: how it arrived, what it registered as, and the conn the test can
// now speak the public protocol on.
type fakeProxy struct {
	transport string // "stream" or "dialed"
	regProxy  msg.RegProxy
	public    conn.Conn
}

func startFakeTunnelServer(t *testing.T, publicUrl string) *fakeTunnelServer {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen for the fake tunnel server: %v", err)
	}
	t.Cleanup(func() { listener.Close() })

	s := &fakeTunnelServer{
		addr:      listener.Addr().String(),
		publicUrl: publicUrl,
		regMux:    make(chan string, 8),
		sessions:  make(chan *smux.Session, 8),
		proxies:   make(chan *fakeProxy, 8),
	}

	go func() {
		for {
			rawConn, err := listener.Accept()
			if err != nil {
				// the test closed the listener
				return
			}
			go s.serveConn(conn.Wrap(rawConn, "tun"))
		}
	}()

	return s
}

// serveConn reads the first message of one conn and dispatches on it, exactly
// like the real tunnel listener: the message that opens a conn is what it is.
func (s *fakeTunnelServer) serveConn(rawConn conn.Conn) {
	rawConn.SetReadDeadline(time.Now().Add(30 * time.Second))
	raw, err := msg.ReadMsg(rawConn)
	if err != nil {
		rawConn.Close()
		return
	}
	rawConn.SetReadDeadline(time.Time{})

	switch m := raw.(type) {
	case *msg.RegMux:
		s.regMux <- m.ClientId

		sess, err := smux.Server(rawConn, muxConfig())
		if err != nil {
			rawConn.Close()
			return
		}
		s.sessions <- sess
		go s.acceptStreams(sess)

	case *msg.RegProxy:
		// A conn that registered directly is a proxy conn in its own right:
		// the whole conn, not one stream of a session.
		rawConn.SetType("pxy")
		s.serveProxy(rawConn, *m, "dialed")

	default:
		rawConn.Close()
	}
}

// acceptStreams serves the streams of one session until it dies.
func (s *fakeTunnelServer) acceptStreams(sess *smux.Session) {
	for {
		stream, err := sess.AcceptStream()
		if err != nil {
			// the session was closed, by either end
			return
		}

		go func() {
			pxyConn := conn.Wrap(stream, "pxy")

			pxyConn.SetReadDeadline(time.Now().Add(30 * time.Second))
			var regProxy msg.RegProxy
			if err := msg.ReadMsgInto(pxyConn, &regProxy); err != nil {
				pxyConn.Close()
				return
			}
			pxyConn.SetReadDeadline(time.Time{})

			s.serveProxy(pxyConn, regProxy, "stream")
		}()
	}
}

// serveProxy is the server's half of the proxy handshake: the RegProxy is
// already read, so answer StartProxy and hand the conn to the test, which is now
// the public client.
func (s *fakeTunnelServer) serveProxy(pxyConn conn.Conn, regProxy msg.RegProxy, transport string) {
	startPxy := &msg.StartProxy{Url: s.publicUrl, ClientAddr: testClientAddr}
	if err := msg.WriteMsg(pxyConn, startPxy); err != nil {
		pxyConn.Close()
		return
	}

	s.proxies <- &fakeProxy{transport: transport, regProxy: regProxy, public: pxyConn}
}

// acceptRegMux reads the client id of the next mux conn that opened.
func (s *fakeTunnelServer) acceptRegMux(t *testing.T) string {
	t.Helper()

	select {
	case clientId := <-s.regMux:
		return clientId
	case <-time.After(10 * time.Second):
		t.Fatal("the fake server never saw a RegMux")
		return ""
	}
}

// acceptSession returns the server side of the next mux session.
func (s *fakeTunnelServer) acceptSession(t *testing.T) *smux.Session {
	t.Helper()

	select {
	case sess := <-s.sessions:
		return sess
	case <-time.After(10 * time.Second):
		t.Fatal("the fake server never established a mux session")
		return nil
	}
}

// acceptProxy returns the next proxy conn the fake server served.
func (s *fakeTunnelServer) acceptProxy(t *testing.T) *fakeProxy {
	t.Helper()

	select {
	case p := <-s.proxies:
		return p
	case <-time.After(10 * time.Second):
		t.Fatal("the fake server was never asked to serve a proxy conn")
		return nil
	}
}

// ---------------------------------------------------------------------------
// the client under test

// stubController is the mvc.Controller the model publishes state to. The
// interface is embedded, so a method this stub does not implement fails on the
// nil interface the moment the model starts using it rather than silently doing
// nothing; only Update is on any path these tests run.
type stubController struct {
	mvc.Controller

	// updates counts what the model published, so a test can see the proxy path
	// still drives the controller's state machine.
	updates int32
}

func (s *stubController) Update(state mvc.State) { atomic.AddInt32(&s.updates, 1) }

// muxTestModel is a ClientModel with just enough of the real one for the proxy
// path: a logger, the metrics serveProxyConnection reports through, a controller
// to publish state to, and one http tunnel whose local leg is the upstream.
// Everything here is set because serveProxyConnection touches all of it -- a
// zero ClientModel would panic on the first connection.
func muxTestModel(t *testing.T, publicUrl, upstreamAddr string) *ClientModel {
	t.Helper()

	return &ClientModel{
		Logger:  log.NewPrefixLogger("test"),
		metrics: NewClientMetrics(),
		ctl:     &stubController{},
		tunnels: map[string]mvc.Tunnel{publicUrl: httpTunnel(publicUrl, upstreamAddr)},
	}
}

// waitForSession polls the model until it publishes a mux session other than
// exclude (nil means "any session"), which is how these tests tell the first
// session from the one the watchdog brought up after it.
func waitForSession(t *testing.T, model *ClientModel, exclude *muxSession) *muxSession {
	t.Helper()

	deadline := time.Now().Add(15 * time.Second)
	for {
		if sess := model.muxSession(); sess != nil && sess != exclude {
			return sess
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for the client to publish a mux session")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// publicRoundTrip plays the public client on one served proxy conn: it sends a
// request and checks both what came back and what the upstream saw. The Host and
// the X-Forwarded-For are the tell that the bytes went through the client's relay
// and its HTTP rewrite stack, not around them.
func publicRoundTrip(t *testing.T, public conn.Conn, seen <-chan upstreamRequest) {
	t.Helper()

	// bounding every read and write means a wiring bug fails the test instead of
	// hanging it
	public.SetDeadline(time.Now().Add(30 * time.Second))

	if _, err := io.WriteString(public, getRequest(muxTestPublicHost)); err != nil {
		t.Fatalf("failed to send the request over the proxy conn: %v", err)
	}

	resp, body := readResponse(t, bufio.NewReader(public))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the public client got status %d, want 200", resp.StatusCode)
	}
	if string(body) != testUpstreamBody {
		t.Fatalf("the public client got body %q, want %q", body, testUpstreamBody)
	}

	req := upstreamObserved(t, seen)
	if req.host != muxTestPublicHost {
		t.Fatalf("the upstream saw Host %q, want %q", req.host, muxTestPublicHost)
	}
	if got := req.header.Get("X-Forwarded-For"); got != testClientIP {
		t.Fatalf("the upstream saw X-Forwarded-For %q, want %q", got, testClientIP)
	}
}

// ---------------------------------------------------------------------------
// tests

// TestProxyUsesTheMuxSessionWhenThereIsOne is the whole mux path in one test:
// dialMuxSession opens the conn and declares it with RegMux, publishing it makes
// proxy() answer a ReqProxy with a stream on it instead of dialing, the
// RegProxy/StartProxy handshake runs on that stream, and the bytes that follow
// are relayed to the upstream by the same code the dialed path uses. When the
// public connection ends, the stream -- which is the proxied connection -- ends
// with it.
func TestProxyUsesTheMuxSessionWhenThereIsOne(t *testing.T) {
	publicUrl := "http://" + muxTestPublicHost

	upstream, seen := upstreamServer(t)
	srv := startFakeTunnelServer(t, publicUrl)

	model := muxTestModel(t, publicUrl, upstream.Listener.Addr().String())
	model.serverAddr = srv.addr
	model.id = "client-mux"

	// the session the watchdog establishes once AuthResp names the capability
	sess, err := model.dialMuxSession()
	if err != nil {
		t.Fatalf("dialMuxSession failed: %v", err)
	}
	t.Cleanup(sess.Close)
	model.setMuxSession(sess)

	// the conn really was a mux conn, and it named this control session
	if got := srv.acceptRegMux(t); got != model.id {
		t.Fatalf("RegMux named %q, want %q", got, model.id)
	}
	srv.acceptSession(t)

	// answer one ReqProxy the way the handler does
	done := make(chan struct{})
	go func() {
		defer close(done)
		model.proxy()
	}()

	proxy := srv.acceptProxy(t)
	if proxy.transport != "stream" {
		t.Fatalf("the ReqProxy was answered by a %s proxy conn; with a session published it must be a mux stream", proxy.transport)
	}
	if proxy.regProxy.ClientId != model.id {
		t.Fatalf("RegProxy named %q, want %q", proxy.regProxy.ClientId, model.id)
	}

	publicRoundTrip(t, proxy.public, seen)

	// one stream is one proxied connection: hanging up on the public side ends
	// it, exactly like closing a dialed proxy conn
	proxy.public.Close()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("proxy() did not return after the public connection was closed")
	}

	// the connection was announced to the controller on both sides of the relay
	ctl := model.ctl.(*stubController)
	if got := atomic.LoadInt32(&ctl.updates); got < 2 {
		t.Fatalf("the model published %d states for one proxied connection, want at least 2", got)
	}
}

// TestProxyDialsWhenThereIsNoMuxSession is the compatibility half of the
// transport choice (SPEC 3.1): with nothing published -- a server that does not
// offer the capability, and the window before the first session is up -- proxy()
// dials a conn and runs the original handshake on it, unmodified.
func TestProxyDialsWhenThereIsNoMuxSession(t *testing.T) {
	publicUrl := "http://" + muxTestPublicHost

	upstream, seen := upstreamServer(t)
	srv := startFakeTunnelServer(t, publicUrl)

	model := muxTestModel(t, publicUrl, upstream.Listener.Addr().String())
	model.serverAddr = srv.addr
	model.id = "client-dial"

	done := make(chan struct{})
	go func() {
		defer close(done)
		model.proxy()
	}()

	proxy := srv.acceptProxy(t)
	if proxy.transport != "dialed" {
		t.Fatalf("proxy() answered with a %s proxy conn, want a dialed one when no session is published", proxy.transport)
	}
	if proxy.regProxy.ClientId != model.id {
		t.Fatalf("RegProxy named %q, want %q", proxy.regProxy.ClientId, model.id)
	}

	publicRoundTrip(t, proxy.public, seen)

	proxy.public.Close()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("proxy() did not return after the public connection was closed")
	}

	// and the fallback did not secretly open a mux conn either
	select {
	case <-srv.sessions:
		t.Fatal("the dialed path opened a mux session")
	default:
	}
}

// TestMuxWatchdogPublishesReconnectsAndStops covers the lifecycle the watchdog
// owns (SPEC 3.1): it brings up the mux conn after the capability handshake,
// publishes it, replaces it when the session dies, and closes it when the
// control session it belongs to ends so that nothing is left pointing at a dead
// transport.
func TestMuxWatchdogPublishesReconnectsAndStops(t *testing.T) {
	publicUrl := "http://" + muxTestPublicHost
	srv := startFakeTunnelServer(t, publicUrl)

	model := muxTestModel(t, publicUrl, "127.0.0.1:1")
	model.serverAddr = srv.addr
	model.id = "client-watchdog"

	stop := make(chan struct{})
	watchdogDone := make(chan struct{})
	go func() {
		defer close(watchdogDone)
		model.muxWatchdog(stop, nil)
	}()

	first := waitForSession(t, model, nil)
	if got := srv.acceptRegMux(t); got != model.id {
		t.Fatalf("RegMux named %q, want %q", got, model.id)
	}

	// the server end of the session dying is what a dropped mux conn looks like
	// from the client: the session must not stay published as live
	srv.acceptSession(t).Close()

	second := waitForSession(t, model, first)
	if got := srv.acceptRegMux(t); got != model.id {
		t.Fatalf("the reconnected mux conn named %q, want %q", got, model.id)
	}
	srv.acceptSession(t)

	// ending the control session ends the mux transport with it
	close(stop)
	select {
	case <-watchdogDone:
	case <-time.After(10 * time.Second):
		t.Fatal("the watchdog did not return after the control session ended")
	}

	if sess := model.muxSession(); sess != nil {
		t.Fatal("the watchdog left a session published after the control session ended")
	}
	if !second.sess.IsClosed() {
		t.Fatal("the watchdog did not close the mux session when the control session ended")
	}
}

// TestMuxRetryDelayIsBounded pins the reconnect backoff: the first retry is
// quick, the delay doubles per consecutive failure, and it stops at the cap so
// that a client cannot hammer a server that keeps refusing (or dropping) its mux
// conns.
func TestMuxRetryDelayIsBounded(t *testing.T) {
	want := []time.Duration{
		1 * time.Second,
		2 * time.Second,
		4 * time.Second,
		8 * time.Second,
		16 * time.Second,
		30 * time.Second,
		30 * time.Second,
		30 * time.Second,
	}

	for i, w := range want {
		attempts := i + 1
		if got := muxRetryDelay(attempts); got != w {
			t.Errorf("muxRetryDelay(%d) = %s, want %s", attempts, got, w)
		}
	}
}
