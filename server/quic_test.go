package server

// Tests for the QUIC carrier of the multiplexed proxy transport (SPEC cluster
// 7, section 8-A).
//
// The layout mirrors mux_test.go, and where a claim is the same claim the smux
// tests already make -- per-stream RegProxy re-verification, replace-and-close
// session lifecycle, StartProxy reaching the client stream -- these tests make
// it over the QUIC path with the real listener and the real dial (loopback
// UDP, snakeoil certs), because the interesting parts of the QUIC path are
// exactly the parts a net.Pipe cannot stand in for: the ALPN handshake, the
// stream-to-net.Conn adaptation, deadlines on streams.
//
// What is deliberately NOT retested here: the pool end of the handoff
// (registry_v2_test.go), the join unwinding when a session dies (mux_test.go,
// identical through the shared registerProxyStream), and the smux path itself,
// which this cluster's refactor must not have changed (its own suite,
// untouched, is the regression test for that).

import (
	"context"
	"crypto/tls"
	"io"
	"reflect"
	"testing"
	"time"

	"ngrok/conn"
	"ngrok/msg"
	"ngrok/version"

	"github.com/quic-go/quic-go"
)

// ---------------------------------------------------------------------------
// fixtures

// quicTestListener starts the real QUIC listener the way Main() does, on a
// loopback port, with the embedded development certificate.
func quicTestListener(t *testing.T) *quic.Listener {
	t.Helper()

	tlsConfig, err := LoadTLSConfig("", "")
	if err != nil {
		t.Fatalf("failed to load the test TLS config: %v", err)
	}

	ql, err := startQuicListener("127.0.0.1:0", tlsConfig)
	if err != nil {
		t.Fatalf("failed to start the QUIC listener: %v", err)
	}
	t.Cleanup(func() { ql.Close() })

	return ql
}

// quicTestPair brings up one QUIC session end to end: a listener (every call
// starts its own -- tests that want several sessions just call this again),
// a client dialed the way the client's dialQuicSession will dial (ALPN set,
// snakeoil cert accepted), and the accept loop running on the goroutine
// startQuicListener spawned. What the client does from here -- first stream
// carries RegMux -- is quicTestBind's business.
func quicTestPair(t *testing.T) quic.Connection {
	t.Helper()

	ql := quicTestListener(t)
	return quicTestDial(t, ql.Addr().String())
}

// quicTestDial dials a QUIC listener the way a client would: the ALPN
// protocol in NextProtos (its absence or mismatch is a refused handshake, not
// a fallback -- that refusal is itself asserted in
// TestQuicDialWithoutALPNFails), certificates accepted as tests accept
// snakeoil.
func quicTestDial(t *testing.T, addr string) quic.Connection {
	t.Helper()

	tlsCfg := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{quicALPN}}
	qconn, err := quic.DialAddr(context.Background(), addr, tlsCfg, quicConfig())
	if err != nil {
		t.Fatalf("failed to dial the QUIC listener at %s: %v", addr, err)
	}
	t.Cleanup(func() { qconn.CloseWithError(quicSessionError, "test over") })

	return qconn
}

// quicTestBind runs the bind handshake from the client side: open the first
// stream, send RegMux. That is the whole of what the client's dialQuicSession
// does after the dial; the server's half runs on the accept-loop goroutine.
//
// A nil ctl (the unknown-client test has no control to wait for) skips the
// detach wait on cleanup.
func quicTestBind(t *testing.T, qconn quic.Connection, ctl *Control, clientId, secret string) {
	t.Helper()

	bindConn := conn.Wrap(quicTestOpenStream(t, qconn), "quic")
	if err := msg.WriteMsg(bindConn, &msg.RegMux{ClientId: clientId, Secret: secret}); err != nil {
		t.Fatalf("failed to send RegMux: %v", err)
	}

	t.Cleanup(func() {
		qconn.CloseWithError(quicSessionError, "test over")
		waitForBoundSessionDetach(t, ctl)
	})
}

// quicTestOpenStream opens one stream and hands it through the same
// net.Conn adaptation the server applies, wrapped the way the client wraps a
// stream: open, adapt, conn.Wrap.
func quicTestOpenStream(t *testing.T, qconn quic.Connection) conn.Conn {
	t.Helper()

	stream, err := qconn.OpenStream()
	if err != nil {
		t.Fatalf("failed to open a stream: %v", err)
	}

	streamConn := conn.Wrap(newQuicStreamConn(qconn, stream), "pxy")
	t.Cleanup(func() { streamConn.Close() })

	return streamConn
}

// quicTestProxyStream opens one proxy stream on a bound session the way the
// client's proxyStream does -- open, wrap, RegProxy -- and returns the client
// end. The pooled half is the test's to take from the control.
func quicTestProxyStream(t *testing.T, qconn quic.Connection, clientId, secret string) conn.Conn {
	t.Helper()

	streamConn := quicTestOpenStream(t, qconn)
	if err := msg.WriteMsg(streamConn, &msg.RegProxy{ClientId: clientId, Secret: secret}); err != nil {
		t.Fatalf("failed to register the proxy stream: %v", err)
	}

	return streamConn
}

// waitForBoundSession polls the control's session slot until want accepts what
// is in it. The QUIC session is attached by the listener's accept-loop
// goroutine, so no test can assume the slot is already in the state it is
// waiting for.
func waitForBoundSession(t *testing.T, ctl *Control, want func(streamSession) bool) streamSession {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for {
		s := ctl.boundSession()
		if want(s) {
			return s
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for the bound session (present: %t)", s != nil)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// anyBound is the "a session appeared" state the tests wait for.
func anyBound(s streamSession) bool { return s != nil }

// waitForBoundSessionDetach waits until the control no longer holds a session,
// mirroring waitForMuxDetach (mux_test.go) for the transport-blind slot: the
// session clears the slot as its last act, so waiting for it is waiting for
// the accept loop to be done with the control, the registry and the logger.
func waitForBoundSessionDetach(t *testing.T, ctl *Control) {
	t.Helper()

	if ctl == nil {
		return
	}

	const grace = 5 * time.Second
	deadline := time.Now().Add(grace)
	for {
		if ctl.boundSession() == nil {
			// The session is attached by the accept-loop goroutine, so it may
			// not have appeared yet: give the handshake a moment before
			// believing the slot is empty because nothing was ever put in it.
			time.Sleep(20 * time.Millisecond)
			if ctl.boundSession() == nil {
				return
			}
			continue
		}

		if time.Now().After(deadline) {
			t.Errorf("the session did not detach from the control within %s", grace)
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// waitForQuicClosed waits until the server has closed the QUIC session. A
// Connection's Context is canceled when the connection is closed, from either
// side -- the one wait that covers both the explicit CloseWithError paths and
// the replacement close.
func waitForQuicClosed(t *testing.T, qconn quic.Connection) {
	t.Helper()

	select {
	case <-qconn.Context().Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the server did not close the QUIC session")
	}
}

// assertServedProxyConn is the assertion both carriers must pass on what their
// session handed to the pool: StartProxy written to the pooled conn arrives on
// the client's stream, and bytes written into the pooled conn reach the client
// stream -- the handshake and the server-to-agent direction of the data path,
// over the conn.Conn the RegisterProxy call received.
func assertServedProxyConn(t *testing.T, proxyConn, clientEnd conn.Conn) {
	t.Helper()

	startPxy := msg.StartProxy{Url: "http://equiv.ngrok.test", ClientAddr: "203.0.113.7:6000"}
	if err := msg.WriteMsg(proxyConn, &startPxy); err != nil {
		t.Fatalf("failed to write StartProxy to the pooled conn: %v", err)
	}

	clientEnd.SetReadDeadline(time.Now().Add(5 * time.Second))
	var got msg.StartProxy
	if err := msg.ReadMsgInto(clientEnd, &got); err != nil {
		t.Fatalf("StartProxy did not arrive on the client stream: %v", err)
	}
	if got != startPxy {
		t.Fatalf("StartProxy on the stream = %+v, want %+v", got, startPxy)
	}

	payload := "GET / HTTP/1.1\r\nHost: equiv.ngrok.test\r\n\r\n"
	if _, err := io.WriteString(proxyConn, payload); err != nil {
		t.Fatalf("failed to write the payload into the pooled conn: %v", err)
	}

	gotPayload := make([]byte, len(payload))
	if _, err := io.ReadFull(clientEnd, gotPayload); err != nil {
		t.Fatalf("the payload never reached the client stream: %v", err)
	}
	if string(gotPayload) != payload {
		t.Fatalf("the client stream received %q, want %q", gotPayload, payload)
	}
	clientEnd.SetReadDeadline(time.Time{})
}

// ---------------------------------------------------------------------------
// the bind handshake

// TestQuicSessionBindsAndServesProxyStreams is the happy path, end to end:
// RegMux on the first stream binds the session to its control, a later stream
// carrying RegProxy lands in that control's pool, and the pooled conn serves
// StartProxy and payload -- the QUIC session behaving, stream for stream, like
// the smux conn mux_test.go covers.
func TestQuicSessionBindsAndServesProxyStreams(t *testing.T) {
	reg := setupTestControlRegistry(t)
	ctl := muxTestControl(t, reg, "client-quic")

	qconn := quicTestPair(t)
	quicTestBind(t, qconn, ctl, "client-quic", testSessionSecret("client-quic"))

	s := waitForBoundSession(t, ctl, anyBound)
	q, ok := s.(*QuicSession)
	if !ok {
		t.Fatalf("the bound session is a %T, want *QuicSession", s)
	}
	if q.Id() != "client-quic" {
		t.Fatalf("session Id() = %q, want the client id it registered as", q.Id())
	}

	streamConn := quicTestProxyStream(t, qconn, "client-quic", testSessionSecret("client-quic"))
	proxyConn := waitForProxy(t, ctl)

	assertServedProxyConn(t, proxyConn, streamConn)
}

// TestQuicSessionForUnknownClientIsClosed covers the bind's first refusal: a
// session naming a client the server does not know is closed -- there is
// nothing to attach it to, and the client's watchdog will try again.
func TestQuicSessionForUnknownClientIsClosed(t *testing.T) {
	setupTestControlRegistry(t) // empty: no client is registered

	qconn := quicTestPair(t)
	quicTestBind(t, qconn, nil, "nobody", "whatever")

	waitForQuicClosed(t, qconn)
}

// TestQuicSessionRejectsWrongSecret covers the bind's second refusal: naming a
// live client id is not enough, the session secret is what makes the bind
// authentication rather than naming. A rejected session is closed and nothing
// is bound to the control.
func TestQuicSessionRejectsWrongSecret(t *testing.T) {
	reg := setupTestControlRegistry(t)
	ctl := muxTestControl(t, reg, "client-secret")

	qconn := quicTestPair(t)
	quicTestBind(t, qconn, ctl, "client-secret", "not the session secret")

	waitForQuicClosed(t, qconn)

	if s := ctl.boundSession(); s != nil {
		t.Fatalf("a session with a wrong secret was bound: %T", s)
	}
}

// TestQuicDialWithoutALPNFails pins the cross-protocol refusal where it
// belongs: in the handshake. A client that dials the QUIC listener without
// offering the ngrok ALPN protocol -- some other QUIC service's client, or a
// plain TLS probe -- fails the handshake instead of ever reaching the mux
// protocol, which is the whole reason the ALPN is REQUIRED both directions.
func TestQuicDialWithoutALPNFails(t *testing.T) {
	ql := quicTestListener(t)

	tlsCfg := &tls.Config{InsecureSkipVerify: true} // no NextProtos
	if _, err := quic.DialAddr(context.Background(), ql.Addr().String(), tlsCfg, quicConfig()); err == nil {
		t.Fatal("a dial without the ngrok ALPN protocol was not refused by the handshake")
	}
}

// ---------------------------------------------------------------------------
// per-stream re-verification

// TestQuicStreamReVerification covers the checks only a stream can make, the
// same ones mux_test.go covers for smux: the transport authenticates the
// session, not its streams, so each stream re-states the session's
// credentials, and anything that does not line up is closed and never pooled.
func TestQuicStreamReVerification(t *testing.T) {
	cases := []struct {
		name          string
		regProxy      func(secret string) *msg.RegProxy
		whyRejectedIs string
	}{
		{
			name: "another client id",
			// the other id's own valid secret: the id is what rejects it,
			// so the (correct) verdict on the secret never comes up
			regProxy: func(secret string) *msg.RegProxy {
				return &msg.RegProxy{ClientId: "client-other", Secret: secret}
			},
			whyRejectedIs: "a stream for another client id",
		},
		{
			name: "wrong session secret",
			regProxy: func(secret string) *msg.RegProxy {
				return &msg.RegProxy{ClientId: "client-quic", Secret: "not the session secret"}
			},
			whyRejectedIs: "a stream with a wrong secret",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reg := setupTestControlRegistry(t)
			ctl := muxTestControl(t, reg, "client-quic")

			qconn := quicTestPair(t)
			quicTestBind(t, qconn, ctl, "client-quic", testSessionSecret("client-quic"))
			waitForBoundSession(t, ctl, anyBound)

			streamConn := quicTestOpenStream(t, qconn)
			if err := msg.WriteMsg(streamConn, tc.regProxy(testSessionSecret("client-other"))); err != nil {
				t.Fatalf("failed to write RegProxy: %v", err)
			}

			// the server closes the stream instead of registering it
			streamConn.SetReadDeadline(time.Now().Add(5 * time.Second))
			if _, err := streamConn.Read(make([]byte, 1)); err == nil {
				t.Fatalf("%s was not closed", tc.whyRejectedIs)
			}

			// and the rejection happens before the pool: nothing was
			// registered. The check is deterministic here because the close
			// the client just observed is the last thing the stream's handler
			// does.
			select {
			case c := <-ctl.proxies:
				c.Close()
				t.Fatalf("%s was registered in the proxy pool", tc.whyRejectedIs)
			default:
			}
		})
	}
}

// ---------------------------------------------------------------------------
// session lifecycle on the control

// TestQuicSessionReplacedAndClosed covers the replace-and-close-prior
// semantics on the QUIC path: one session at a time, a re-dial replaces the
// old one (which is closed), and the slot reports the replacement.
func TestQuicSessionReplacedAndClosed(t *testing.T) {
	reg := setupTestControlRegistry(t)
	ctl := muxTestControl(t, reg, "client-q2")

	qconn := quicTestPair(t)
	quicTestBind(t, qconn, ctl, "client-q2", testSessionSecret("client-q2"))
	first := waitForBoundSession(t, ctl, anyBound)

	// a second QUIC session for the same client -- what a client whose session
	// died looks like when its watchdog reconnects
	qconn2 := quicTestPair(t)
	quicTestBind(t, qconn2, ctl, "client-q2", testSessionSecret("client-q2"))
	second := waitForBoundSession(t, ctl, func(s streamSession) bool { return s != nil && s != first })

	if second.(*QuicSession).Id() != "client-q2" {
		t.Fatalf("the replacement session registered as %q", second.(*QuicSession).Id())
	}

	// the loser of the replacement is closed, not left to be discovered stale
	select {
	case <-first.(*QuicSession).conn.Context().Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the replaced QUIC session was not closed")
	}
}

// TestQuicSessionReplacedAcrossTransports pins the transport-blindness of the
// slot: the replace-and-close-prior semantics do not care which carrier each
// session rides, so a client may move between QUIC and smux -- which is what
// its fallback does when a QUIC session goes wrong mid-session.
func TestQuicSessionReplacedAcrossTransports(t *testing.T) {
	reg := setupTestControlRegistry(t)
	ctl := muxTestControl(t, reg, "client-xport")

	qconn := quicTestPair(t)
	quicTestBind(t, qconn, ctl, "client-xport", testSessionSecret("client-xport"))
	quicSess := waitForBoundSession(t, ctl, anyBound)

	// the same client registers an smux session: the QUIC session must lose
	muxTestPair(t, "client-xport")
	s := waitForBoundSession(t, ctl, func(cur streamSession) bool { return cur != nil && cur != quicSess })

	if _, ok := s.(*MuxSession); !ok {
		t.Fatalf("the replacement session is a %T, want *MuxSession", s)
	}

	select {
	case <-quicSess.(*QuicSession).conn.Context().Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the QUIC session was not closed when the smux session replaced it")
	}
}

// ---------------------------------------------------------------------------
// streamSession equivalence

// TestStreamSessionCarriersHandIdenticalProxyConns is the equivalence claim of
// the streamSession extraction: the smux and QUIC paths are the same code from
// AcceptStream onward -- one registerProxyStream, one RegisterProxy -- and
// what that code hands the pool is not just behaviorally similar but the same
// kind of thing: the same dynamic type, serving the same handshake, in both
// directions.
func TestStreamSessionCarriersHandIdenticalProxyConns(t *testing.T) {
	reg := setupTestControlRegistry(t)

	// smux leg: the fixture mux_test.go uses, driving the real NewMux path
	ctlS := muxTestControl(t, reg, "client-equiv")
	smuxSess := muxTestPair(t, "client-equiv")
	smuxStream, err := smuxSess.OpenStream()
	if err != nil {
		t.Fatalf("failed to open a smux proxy stream: %v", err)
	}
	smuxEnd := conn.Wrap(smuxStream, "pxy")
	t.Cleanup(func() { smuxEnd.Close() })
	if err := msg.WriteMsg(smuxEnd, &msg.RegProxy{ClientId: "client-equiv", Secret: testSessionSecret("client-equiv")}); err != nil {
		t.Fatalf("failed to register the smux proxy stream: %v", err)
	}
	smuxProxy := waitForProxy(t, ctlS)

	// quic leg: the real listener, dial, bind and stream path
	ctlQ := muxTestControl(t, reg, "client-quiv")
	quicConn := quicTestPair(t)
	quicTestBind(t, quicConn, ctlQ, "client-quiv", testSessionSecret("client-quiv"))
	waitForBoundSession(t, ctlQ, anyBound)
	quicEnd := quicTestProxyStream(t, quicConn, "client-quiv", testSessionSecret("client-quiv"))
	quicProxy := waitForProxy(t, ctlQ)

	// the same kind of conn in the pool: both legs wrap their stream in the
	// same conn.Conn stack, so a consumer -- StartProxy, Join, the rewriter --
	// cannot tell which carrier a proxy conn came from, which is the point.
	if reflect.TypeOf(smuxProxy) != reflect.TypeOf(quicProxy) {
		t.Fatalf("the pool received different conn types: smux %T vs quic %T", smuxProxy, quicProxy)
	}

	t.Run("smux", func(t *testing.T) { assertServedProxyConn(t, smuxProxy, smuxEnd) })
	t.Run("quic", func(t *testing.T) { assertServedProxyConn(t, quicProxy, quicEnd) })
}

// ---------------------------------------------------------------------------
// capability advertisement and configuration

// TestQuicCapabilityAdvertisedOnlyWhenListenerUp covers the gate on
// AuthResp.Caps: proxy-quic is advertised only while the QUIC listener is up,
// and the capabilities a server without one advertises are exactly what it
// always advertised (review gate 2: the default behavior is byte-identical).
func TestQuicCapabilityAdvertisedOnlyWhenListenerUp(t *testing.T) {
	setupTestRegistry(t)
	setupTestControlRegistry(t)

	prev := quicServing.Load()
	t.Cleanup(func() { quicServing.Store(prev) })

	quicServing.Store(false)
	_, _, off := startTestControl(t, &msg.Auth{Version: version.Proto})
	if off.Error != "" {
		t.Fatalf("the session was refused: %s", off.Error)
	}
	assertCaps(t, off.Caps, msg.MuxCapability, true)
	assertCaps(t, off.Caps, msg.QuicCapability, false)

	quicServing.Store(true)
	_, _, on := startTestControl(t, &msg.Auth{Version: version.Proto})
	if on.Error != "" {
		t.Fatalf("the session was refused: %s", on.Error)
	}
	assertCaps(t, on.Caps, msg.MuxCapability, true)
	assertCaps(t, on.Caps, msg.QuicCapability, true)
}

// assertCaps asserts whether want is present in caps.
func assertCaps(t *testing.T, caps []string, want string, present bool) {
	t.Helper()

	found := false
	for _, c := range caps {
		if c == want {
			found = true
			break
		}
	}
	if found != present {
		t.Fatalf("AuthResp.Caps %v: %q present = %t, want %t", caps, want, found, present)
	}
}

// TestQuicAddrConfigAndFlag covers the configuration surface: quic_addr
// survives the strict YAML decode (the struct field landed with the key), the
// flag beats the file, the default is disabled, and a typo'd key is still a
// failed load -- adding a field must not have loosened the strictness that
// protects every other key.
func TestQuicAddrConfigAndFlag(t *testing.T) {
	t.Run("config key accepted", func(t *testing.T) {
		configPath := writeServerConfig(t, `
tunnel_addr: localhost:4443
quic_addr: localhost:4443
`)
		opts := parseServerArgs(t, []string{"ngrokd", "-config", configPath})
		if opts.quicAddr != "localhost:4443" {
			t.Errorf("quicAddr: config file value ignored, got %q", opts.quicAddr)
		}
		if opts.tunnelAddr != "localhost:4443" {
			t.Errorf("tunnelAddr: config file value ignored, got %q", opts.tunnelAddr)
		}
	})

	t.Run("flag beats config", func(t *testing.T) {
		configPath := writeServerConfig(t, `
quic_addr: localhost:4443
`)
		opts := parseServerArgs(t, []string{"ngrokd", "-config", configPath, "-quicAddr", "localhost:5555"})
		if opts.quicAddr != "localhost:5555" {
			t.Errorf("quicAddr: the explicit flag should beat the config file, got %q", opts.quicAddr)
		}
	})

	t.Run("default disabled", func(t *testing.T) {
		opts := parseServerArgs(t, []string{"ngrokd"})
		if opts.quicAddr != "" {
			t.Errorf("quicAddr: default should be empty (disabled), got %q", opts.quicAddr)
		}
	})

	t.Run("typo still rejected", func(t *testing.T) {
		configPath := writeServerConfig(t, `
quic_add: localhost:4443
`)
		if _, err := loadServerConfig(configPath); err == nil {
			t.Error("a typo'd key (quic_add) was silently accepted by the strict decode")
		}
	})
}
