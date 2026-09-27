package server

// Tests for the multiplexed proxy transport (SPEC cluster 3, section 3.1).
//
// Everything here is in-process. A net.Pipe pair stands in for the client's
// TCP+TLS conn to the server: smux runs on both ends of it, and the server end
// goes through the real entry points -- NewMux does the registry lookup and
// starts the session, the accept loop reads RegProxy off each stream, and what
// is registered is what the control's proxy pool receives. The public listener
// and the tunnel registry are deliberately not involved: a proxy stream is a
// proxy connection, and the tests that cover public dispatch already assert the
// pool end of that path (registry_v2_test.go).

import (
	"io"
	"net"
	"ngrok/conn"
	"ngrok/msg"
	"testing"
	"time"

	"github.com/xtaci/smux/v2"
)

// ---------------------------------------------------------------------------
// fixtures

// setupTestControlRegistry installs a fresh control registry -- the way Main()
// does -- and restores the previous global when the test ends.
func setupTestControlRegistry(t *testing.T) *ControlRegistry {
	t.Helper()

	prev := controlRegistry
	t.Cleanup(func() { controlRegistry = prev })

	controlRegistry = NewControlRegistry()
	return controlRegistry
}

// testSessionSecret is the session secret the fixtures in this package present.
//
// It is derived from the client id so that each fixture has its own, and it is
// set on the control by hand rather than minted by the server: a fixture that
// forgets to install it fails closed (secretMatches refuses an empty stored
// secret) instead of accidentally authenticating against an empty one.
func testSessionSecret(clientId string) string {
	return "test-secret-" + clientId
}

// muxTestControl returns a control registered under id, backed by testControl's
// fixture (a real loopback connection, so registration and logging work). The
// control carries the secret its client would have been given at Auth time, so
// the mux handshake that names it can be accepted.
func muxTestControl(t *testing.T, reg *ControlRegistry, id string) *Control {
	t.Helper()

	ctl := testControl(t, "")
	ctl.id = id
	ctl.secret = testSessionSecret(id)
	reg.Add(id, ctl)

	return ctl
}

// muxTestPair brings up one in-process mux session: a net.Pipe pair whose
// server end goes through NewMux (RegMux, registry lookup, smux.Server, the
// accept loop) and whose client end is a plain smux client -- which is exactly
// what a real client's session is, once RegMux is out of the way.
func muxTestPair(t *testing.T, clientId string) *smux.Session {
	t.Helper()

	serverEnd, clientEnd := net.Pipe()

	go NewMux(conn.Wrap(serverEnd, "tun"), &msg.RegMux{ClientId: clientId, Secret: testSessionSecret(clientId)})

	sess, err := smux.Client(clientEnd, muxConfig())
	if err != nil {
		t.Fatalf("failed to start the client side of the mux session: %v", err)
	}

	t.Cleanup(func() {
		clientEnd.Close()
		sess.Close()
		waitForMuxDetach(t, clientId)
	})

	return sess
}

// waitForMuxDetach waits until the control no longer holds the mux session of
// the pair that just closed.
//
// The server side ends the session on its own goroutine -- it closes the conn,
// logging on the way out, and only then clears the control's reference to it --
// so a test that ends first leaves that goroutine running into the next test:
// logging into the logger the next test installed, and reading the control
// registry the next test's fixture replaces. Clearing the reference is the
// session's last act, so waiting for the slot to be empty is waiting for it.
func waitForMuxDetach(t *testing.T, clientId string) {
	t.Helper()

	if controlRegistry == nil {
		return // a test that never installed one has no control to wait for
	}
	ctl := controlRegistry.Get(clientId)
	if ctl == nil {
		return
	}

	const grace = 5 * time.Second
	deadline := time.Now().Add(grace)
	for {
		if ctl.MuxSession() == nil {
			// The session is attached by the listener goroutine, so it may not
			// have appeared yet: give the handshake a moment before believing
			// the slot is empty because nothing was ever put in it.
			time.Sleep(20 * time.Millisecond)
			if ctl.MuxSession() == nil {
				return
			}
			continue
		}

		if time.Now().After(deadline) {
			t.Errorf("the mux session did not detach from the control within %s", grace)
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// waitForProxy pops the next proxy connection the control's pool received, and
// fails the test instead of hanging when none arrives.
func waitForProxy(t *testing.T, ctl *Control) conn.Conn {
	t.Helper()

	select {
	case proxyConn := <-ctl.proxies:
		return proxyConn
	case <-time.After(5 * time.Second):
		t.Fatal("no proxy connection was registered on the control")
		return nil
	}
}

// waitForMuxSession polls the control's mux slot until want accepts what is in
// it, and returns it. Attaching happens on the listener goroutine (NewMux) and
// detaching on the session's own accept loop, so no test can assume the slot is
// already in the state it is waiting for.
func waitForMuxSession(t *testing.T, ctl *Control, want func(*MuxSession) bool) *MuxSession {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for {
		m := ctl.MuxSession()
		if want(m) {
			return m
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for the mux session (present: %t)", m != nil)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// anySession and noSession are the two states the tests wait for.
func anySession(m *MuxSession) bool { return m != nil }
func noSession(m *MuxSession) bool  { return m == nil }

// waitForSessionClosed polls the server's session until its smux session is
// closed. A replaced session is closed by the control, not by the accept loop,
// so this is the assertion that the replacement really tore it down.
func waitForSessionClosed(t *testing.T, m *MuxSession) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for !m.sess.IsClosed() {
		if time.Now().After(deadline) {
			t.Fatal("the mux session was not closed")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// muxStreamFixture is one proxy stream as both ends see it: the control that
// owns the session, the session itself (so a test can kill it), and the two
// ends of the stream -- what the pool received, and what the client holds.
type muxStreamFixture struct {
	ctl        *Control
	sess       *smux.Session
	proxyConn  conn.Conn
	streamConn conn.Conn
}

// newMuxStreamFixture opens one mux session to a fresh control and registers
// one proxy stream on it the way the client's proxyStream does: open, wrap,
// RegProxy.
func newMuxStreamFixture(t *testing.T, clientId string) *muxStreamFixture {
	t.Helper()

	reg := setupTestControlRegistry(t)
	ctl := muxTestControl(t, reg, clientId)

	sess := muxTestPair(t, clientId)

	stream, err := sess.OpenStream()
	if err != nil {
		t.Fatalf("failed to open a proxy stream: %v", err)
	}

	streamConn := conn.Wrap(stream, "pxy")
	t.Cleanup(func() { streamConn.Close() })

	if err := msg.WriteMsg(streamConn, &msg.RegProxy{ClientId: clientId, Secret: testSessionSecret(clientId)}); err != nil {
		t.Fatalf("failed to register the proxy stream: %v", err)
	}

	return &muxStreamFixture{
		ctl:        ctl,
		sess:       sess,
		proxyConn:  waitForProxy(t, ctl),
		streamConn: streamConn,
	}
}

// ---------------------------------------------------------------------------
// accepting a mux session and its streams

// TestMuxStreamRegistersAsProxyConn covers the contract a proxy stream has with
// the server: the session is attached to the control that was named in RegMux,
// the stream lands in that control's proxy pool, and StartProxy written to what
// the pool received reaches the client on the stream -- the same three things
// that happen to a dialed proxy conn.
func TestMuxStreamRegistersAsProxyConn(t *testing.T) {
	f := newMuxStreamFixture(t, "client-mux")

	if m := waitForMuxSession(t, f.ctl, anySession); m.Id() != "client-mux" {
		t.Fatalf("mux session Id() = %q, want the client id it registered as", m.Id())
	}

	startPxy := msg.StartProxy{Url: "http://mux.ngrok.test", ClientAddr: "203.0.113.7:4000"}
	if err := msg.WriteMsg(f.proxyConn, &startPxy); err != nil {
		t.Fatalf("failed to write StartProxy to the pooled stream: %v", err)
	}

	f.streamConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var got msg.StartProxy
	if err := msg.ReadMsgInto(f.streamConn, &got); err != nil {
		t.Fatalf("StartProxy did not arrive on the stream: %v", err)
	}
	f.streamConn.SetReadDeadline(time.Time{})

	if got != startPxy {
		t.Fatalf("StartProxy on the stream = %+v, want %+v", got, startPxy)
	}
}

// TestMuxStreamJoinUnwindsWhenSessionDies is the fail-closed test (SPEC 3.1,
// review gate 4): a public connection joined to a stream moves bytes in both
// directions, and when the mux session dies the join unwinds instead of leaving
// anything blocked -- which is what makes the shared failure domain of one mux
// conn acceptable.
func TestMuxStreamJoinUnwindsWhenSessionDies(t *testing.T) {
	f := newMuxStreamFixture(t, "client-mux")

	// the public connection the server would join the stream to
	publicEnd, publicServerEnd := net.Pipe()
	publicConn := conn.Wrap(publicServerEnd, "pub")
	t.Cleanup(func() { publicEnd.Close() })

	joined := make(chan struct{})
	go func() {
		defer close(joined)
		conn.Join(publicConn, f.proxyConn)
	}()

	// every read and write the test does is bounded, so a wiring bug fails the
	// test instead of hanging it
	publicEnd.SetDeadline(time.Now().Add(10 * time.Second))
	f.streamConn.SetReadDeadline(time.Now().Add(10 * time.Second))

	// public -> stream
	request := "GET / HTTP/1.1\r\n\r\n"
	if _, err := io.WriteString(publicEnd, request); err != nil {
		t.Fatalf("failed to write to the public end: %v", err)
	}

	got := make([]byte, len(request))
	if _, err := io.ReadFull(f.streamConn, got); err != nil {
		t.Fatalf("the public bytes never reached the stream: %v", err)
	}
	if string(got) != request {
		t.Fatalf("the stream received %q, want %q", got, request)
	}

	// stream -> public
	response := "HTTP/1.1 200 OK\r\n\r\nupstream"
	if _, err := f.streamConn.Write([]byte(response)); err != nil {
		t.Fatalf("failed to write to the stream: %v", err)
	}

	gotResp := make([]byte, len(response))
	if _, err := io.ReadFull(publicEnd, gotResp); err != nil {
		t.Fatalf("the stream's bytes never reached the public end: %v", err)
	}
	if string(gotResp) != response {
		t.Fatalf("the public end received %q, want %q", gotResp, response)
	}

	f.streamConn.SetReadDeadline(time.Time{})

	// kill the session: the streams die, the copies fail, and Join closes both
	// ends, so the public connection is not left hanging
	f.sess.Close()

	select {
	case <-joined:
	case <-time.After(10 * time.Second):
		t.Fatal("the join did not unwind after the mux session died")
	}
}

// TestMuxStreamRejectsAnotherClientId covers the one check only a stream can
// make: a stream is not authenticated on its own, so the client id it sends in
// RegProxy must be the one its session registered as. A stream naming somebody
// else is closed and never pooled -- it is either a bug or an attempt to borrow
// another agent's tunnels.
func TestMuxStreamRejectsAnotherClientId(t *testing.T) {
	reg := setupTestControlRegistry(t)
	ctl := muxTestControl(t, reg, "client-a")

	sess := muxTestPair(t, "client-a")

	stream, err := sess.OpenStream()
	if err != nil {
		t.Fatalf("failed to open a proxy stream: %v", err)
	}

	streamConn := conn.Wrap(stream, "pxy")
	t.Cleanup(func() { streamConn.Close() })

	// The stream names another client and presents that client's id without its
	// secret: the server rejects it on the id, so whether it would also have
	// rejected the secret never comes up (the wrong-secret case has its own
	// test, TestMuxStreamRejectsWrongSecret).
	if err := msg.WriteMsg(streamConn, &msg.RegProxy{ClientId: "client-b", Secret: testSessionSecret("client-b")}); err != nil {
		t.Fatalf("failed to write RegProxy: %v", err)
	}

	// the server closes the stream instead of registering it
	streamConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := streamConn.Read(make([]byte, 1)); err == nil {
		t.Fatal("the stream for another client id was not closed")
	}

	// and the rejection happens before the pool: nothing was registered. The
	// check is deterministic here because the close the client just observed is
	// the last thing the stream's handler does.
	select {
	case c := <-ctl.proxies:
		c.Close()
		t.Fatal("a stream for another client id was registered in the proxy pool")
	default:
	}
}

// TestRegMuxForUnknownClientIsClosed covers the listener's half of the mux
// handshake: RegMux names the control session the conn belongs to, and a conn
// that names a client the server does not know is closed rather than left
// dangling.
func TestRegMuxForUnknownClientIsClosed(t *testing.T) {
	setupTestControlRegistry(t) // empty: no client is registered

	serverEnd, clientEnd := net.Pipe()
	t.Cleanup(func() { clientEnd.Close() })

	go NewMux(conn.Wrap(serverEnd, "tun"), &msg.RegMux{ClientId: "nobody"})

	clientEnd.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := clientEnd.Read(make([]byte, 1)); err == nil {
		t.Fatal("the mux conn was not closed for a client id the server does not know")
	}
}

// TestMuxSessionReplacedAndDropped covers the session's lifecycle on the
// control: one session at a time, a client that re-dials replaces the old one
// (which is closed, and with it every stream it carried), and a session that
// dies on its own is dropped from the control rather than reported as live.
func TestMuxSessionReplacedAndDropped(t *testing.T) {
	reg := setupTestControlRegistry(t)
	ctl := muxTestControl(t, reg, "client-1")

	muxTestPair(t, "client-1")
	firstMux := waitForMuxSession(t, ctl, anySession)

	// a second mux conn for the same client -- what a client whose session died
	// looks like when its watchdog reconnects
	second := muxTestPair(t, "client-1")
	secondMux := waitForMuxSession(t, ctl, func(m *MuxSession) bool { return m != nil && m != firstMux })
	if secondMux == nil {
		t.Fatal("the second mux session did not replace the first")
	}

	waitForSessionClosed(t, firstMux)

	// and when the client drops the session it is holding, the control stops
	// reporting it: the accept loop notices and clears the slot
	second.Close()
	waitForMuxSession(t, ctl, noSession)
}

// TestProxyPoolServesDialedAndStreamConns covers the compatibility half of SPEC
// 3.1: the streams of a mux session and the conns of a client that still dials
// are the same kind of thing to the server -- both register through the same
// entry points into the same pool, and a public connection can be served from
// whichever the pool hands out. The mux transport replaces the dialed one; it
// does not get a private path.
func TestProxyPoolServesDialedAndStreamConns(t *testing.T) {
	reg := setupTestControlRegistry(t)
	ctl := muxTestControl(t, reg, "client-both")

	// the pre-mux path: a dialed conn registering over the real entry point
	dialedClient, dialedServer := tcpPair(t)
	go NewProxy(conn.Wrap(dialedServer, "pxy"), &msg.RegProxy{ClientId: ctl.id, Secret: testSessionSecret(ctl.id)})
	dialedConn := waitForProxy(t, ctl)

	// the mux path: a stream on a session the same control owns
	sess := muxTestPair(t, ctl.id)
	stream, err := sess.OpenStream()
	if err != nil {
		t.Fatalf("failed to open a proxy stream: %v", err)
	}

	streamConn := conn.Wrap(stream, "pxy")
	t.Cleanup(func() { streamConn.Close() })

	if err := msg.WriteMsg(streamConn, &msg.RegProxy{ClientId: ctl.id, Secret: testSessionSecret(ctl.id)}); err != nil {
		t.Fatalf("failed to register the proxy stream: %v", err)
	}
	muxConn := waitForProxy(t, ctl)

	for _, tc := range []struct {
		name      string
		proxyConn conn.Conn
		clientEnd conn.Conn
	}{
		{name: "dialed", proxyConn: dialedConn, clientEnd: conn.Wrap(dialedClient, "pxy")},
		{name: "mux stream", proxyConn: muxConn, clientEnd: streamConn},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want := msg.StartProxy{Url: "http://pool.ngrok.test", ClientAddr: "203.0.113.7:5000"}
			if err := msg.WriteMsg(tc.proxyConn, &want); err != nil {
				t.Fatalf("failed to write StartProxy: %v", err)
			}

			tc.clientEnd.SetReadDeadline(time.Now().Add(5 * time.Second))
			var got msg.StartProxy
			if err := msg.ReadMsgInto(tc.clientEnd, &got); err != nil {
				t.Fatalf("StartProxy did not arrive on the %s proxy conn: %v", tc.name, err)
			}
			if got != want {
				t.Fatalf("StartProxy = %+v, want %+v", got, want)
			}
		})
	}
}
