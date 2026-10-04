package client

// Tests for the client's QUIC carrier (SPEC-CLUSTER7 5).
//
// The shape follows mux_test.go's: a fake server stands in for the real
// listener, dispatches by what arrives (RegMux on the first stream, RegProxy on
// every later one), and hands the test the public end of whatever proxy conn it
// served. Here the transport underneath is a real quic-go listener on UDP
// loopback, because the thing under test is precisely the adapter between the
// client's carrier machinery and quic-go's shapes (Connection, Stream, the
// missing LocalAddr/RemoteAddr, the half-close semantics of Stream.Close).
//
// The QUIC and TCP listeners in these tests share one port number on purpose:
// UDP and TCP port spaces are independent, and "the QUIC listener on the same
// host:port as the TCP server" is the deployment contract dialQuicSession dials
// against. Composing both fakes on one address is how the fallback tests get a
// real handoff -- QUIC refuses at the handshake, smux answers on the same port
// -- instead of a handwave.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"github.com/quic-go/quic-go"
	"math/big"
	"net"
	"ngrok/conn"
	"ngrok/msg"
	"testing"
	"time"
)

// quicTestHost is the TLS name the client presents (SNI) and the certificate
// the fake server answers with. The tests run with InsecureSkipVerify (the
// NGROK_INSECURE_SKIP_VERIFY=1 path of the real config), so the name only has
// to be consistent, not trustworthy.
const quicTestHost = "ngrokd.quic.test"

// quicTestTimeout is how long the fake server waits for a message before
// giving up on a conn, and how long the tests wait on the client: long enough
// that a slow CI box passes, short enough that a wiring bug fails instead of
// hanging.
const quicTestTimeout = 10 * time.Second

// ---------------------------------------------------------------------------
// the fixture

// quicTestServerCert mints the self-signed certificate the fake QUIC server
// terminates TLS with. Nothing validates it (the client runs with
// InsecureSkipVerify), but it must parse and be a valid server cert. The ALPN
// the listener answers with is configured separately, because one test leans
// on it NOT matching.
func quicTestServerCert(t *testing.T) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate the test server key: %v", err)
	}

	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: quicTestHost},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{quicTestHost},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create the test server certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed to parse the test server certificate: %v", err)
	}

	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// quicTestClientTLS is the model's TLS configuration for these tests: the
// skip-verify road of the real client (newClientModel with
// NGROK_INSECURE_SKIP_VERIFY=1), pointed at the fake server's name.
func quicTestClientTLS() *tls.Config {
	return &tls.Config{
		ServerName:         quicTestHost,
		InsecureSkipVerify: true,
	}
}

// quicTestServer is the QUIC stand-in for the server's tunnel listener: one
// UDP listener whose connections speak the mux protocol -- RegMux on the first
// stream, RegProxy/StartProxy on every later one.
type quicTestServer struct {
	listener *quic.Listener
	addr     string

	// regMux carries every RegMux the first stream of a session carried, in
	// arrival order.
	regMux chan msg.RegMux

	// proxies carries every proxy stream whose handshake was answered, in
	// order, as the public conn the test speaks requests on.
	proxies chan *fakeProxy

	publicUrl string
}

// startFakeQuicServerAt starts the fake QUIC listener on addr (host:port),
// speaking ALPN alpn -- deliberately wrong in the ALPN-mismatch test.
func startFakeQuicServerAt(t *testing.T, publicUrl, addr, alpn string) *quicTestServer {
	t.Helper()

	listener, err := quic.ListenAddr(addr, &tls.Config{
		Certificates: []tls.Certificate{quicTestServerCert(t)},
		NextProtos:   []string{alpn},
	}, quicConfig())
	if err != nil {
		t.Fatalf("failed to listen QUIC on %s: %v", addr, err)
	}
	t.Cleanup(func() { listener.Close() })

	s := &quicTestServer{
		listener:  listener,
		addr:      listener.Addr().String(),
		regMux:    make(chan msg.RegMux, 8),
		proxies:   make(chan *fakeProxy, 8),
		publicUrl: publicUrl,
	}
	go s.serve()

	return s
}

// startFakeQuicServer starts the fake QUIC listener on an ephemeral UDP port.
func startFakeQuicServer(t *testing.T, publicUrl string) *quicTestServer {
	t.Helper()
	return startFakeQuicServerAt(t, publicUrl, "127.0.0.1:0", quicALPN)
}

// serve accepts QUIC connections until the listener is closed.
func (s *quicTestServer) serve() {
	for {
		qconn, err := s.listener.Accept(context.Background())
		if err != nil {
			// the test closed the listener
			return
		}
		go s.serveConn(qconn)
	}
}

// serveConn serves one QUIC session exactly like server/quic.go is specified
// to: the first stream carries RegMux and binds the session; every stream
// after it carries RegProxy and is answered with StartProxy.
func (s *quicTestServer) serveConn(qconn *quic.Conn) {
	ctx := qconn.Context()

	stream, err := qconn.AcceptStream(ctx)
	if err != nil {
		qconn.CloseWithError(quicSessionCloseCode, "no registration stream")
		return
	}

	regConn := conn.Wrap(newQuicStreamConn(stream, qconn), "mux")
	regConn.SetReadDeadline(time.Now().Add(quicTestTimeout))
	var reg msg.RegMux
	if err := msg.ReadMsgInto(regConn, &reg); err != nil {
		regConn.Close()
		return
	}
	regConn.SetReadDeadline(time.Time{})
	s.regMux <- reg

	for {
		stream, err := qconn.AcceptStream(ctx)
		if err != nil {
			// the session died
			return
		}
		go s.serveStream(stream, qconn)
	}
}

// serveStream runs the server half of the proxy handshake on one stream and
// hands the public conn to the test.
func (s *quicTestServer) serveStream(stream *quic.Stream, qconn *quic.Conn) {
	pxyConn := conn.Wrap(newQuicStreamConn(stream, qconn), "pxy")

	pxyConn.SetReadDeadline(time.Now().Add(quicTestTimeout))
	var regProxy msg.RegProxy
	if err := msg.ReadMsgInto(pxyConn, &regProxy); err != nil {
		pxyConn.Close()
		return
	}
	pxyConn.SetReadDeadline(time.Time{})

	startPxy := &msg.StartProxy{Url: s.publicUrl, ClientAddr: testClientAddr}
	if err := msg.WriteMsg(pxyConn, startPxy); err != nil {
		pxyConn.Close()
		return
	}

	s.proxies <- &fakeProxy{transport: carrierQuic, regProxy: regProxy, public: pxyConn}
}

// acceptRegMux returns the next RegMux the fake server saw.
func (s *quicTestServer) acceptRegMux(t *testing.T) msg.RegMux {
	t.Helper()

	select {
	case reg := <-s.regMux:
		return reg
	case <-time.After(quicTestTimeout):
		t.Fatal("the fake QUIC server never saw a RegMux")
		return msg.RegMux{}
	}
}

// acceptProxy returns the next proxy conn the fake server served.
func (s *quicTestServer) acceptProxy(t *testing.T) *fakeProxy {
	t.Helper()

	select {
	case p := <-s.proxies:
		return p
	case <-time.After(quicTestTimeout):
		t.Fatal("the fake QUIC server was never asked to serve a proxy stream")
		return nil
	}
}

// shrinkQuicHandshakeTimeout replaces the QUIC handshake timeout for the
// duration of the test: the fallback tests need a dead UDP path to fail in
// milliseconds, not in the five seconds a real black hole is worth.
func shrinkQuicHandshakeTimeout(t *testing.T) {
	t.Helper()

	original := quicHandshakeTimeout
	quicHandshakeTimeout = 250 * time.Millisecond
	t.Cleanup(func() { quicHandshakeTimeout = original })
}

// quicTestModel is a model wired for the QUIC carrier: the proxy transport
// resolved to auto, the peer capability recorded as advertised (what
// control() snapshots when AuthResp names msg.QuicCapability), and the
// skip-verify TLS config the QUIC dial clones.
func quicTestModel(t *testing.T, publicUrl, upstreamAddr, serverAddr string) *ClientModel {
	t.Helper()

	model := muxTestModel(t, publicUrl, upstreamAddr)
	model.serverAddr = serverAddr
	model.id = "client-quic"
	model.setSessionSecret("quic-session-secret")
	model.tlsConfig = quicTestClientTLS()
	model.proxyTransport = proxyTransportAuto
	model.quicPeerCap.Store(true)
	return model
}

// ---------------------------------------------------------------------------
// tests

// TestQuicCarrierCarriesRegMuxOnFirstStream is the session bind (SPEC-CLUSTER7
// 3) reached the way the watchdog reaches it: through dialSession, with the
// model resolved to auto and the capability recorded -- the
// "auto + capability -> quic" row of the selection matrix, proven by which
// carrier comes back. The first stream of that session carries RegMux with the
// client id AND the session secret -- the same authentication the smux path
// makes on its raw conn. The secret is asserted here, not just the id: a QUIC
// carrier that bound sessions by name alone would be a hole the server could
// never see past.
func TestQuicCarrierCarriesRegMuxOnFirstStream(t *testing.T) {
	publicUrl := "http://" + muxTestPublicHost

	upstream, _ := upstreamServer(t)
	srv := startFakeQuicServer(t, publicUrl)

	model := quicTestModel(t, publicUrl, upstream.Listener.Addr().String(), srv.addr)

	sess, err := model.dialSession()
	if err != nil {
		t.Fatalf("dialQuicSession failed: %v", err)
	}
	t.Cleanup(sess.Close)

	if sess.transport != carrierQuic {
		t.Fatalf("dialQuicSession produced a %q session, want %q", sess.transport, carrierQuic)
	}

	reg := srv.acceptRegMux(t)
	if reg.ClientId != model.id {
		t.Fatalf("RegMux named %q, want %q", reg.ClientId, model.id)
	}
	if reg.Secret != "quic-session-secret" {
		t.Fatalf("RegMux carried secret %q, want the session secret", reg.Secret)
	}
}

// TestQuicCarrierServesProxyStreams is the whole QUIC path in one test: the
// published carrier answers a ReqProxy with a stream (not a dial), the
// RegProxy/StartProxy handshake runs on that stream, and the bytes that follow
// are relayed to the upstream by the same code every other transport uses.
// Hanging up on the public side ends the proxied connection -- over QUIC that
// means the stream's both directions die, which is exactly the quicStreamConn
// Close behavior the relay's unwind leans on.
func TestQuicCarrierServesProxyStreams(t *testing.T) {
	publicUrl := "http://" + muxTestPublicHost

	upstream, seen := upstreamServer(t)
	srv := startFakeQuicServer(t, publicUrl)

	model := quicTestModel(t, publicUrl, upstream.Listener.Addr().String(), srv.addr)

	sess, err := model.dialQuicSession()
	if err != nil {
		t.Fatalf("dialQuicSession failed: %v", err)
	}
	t.Cleanup(sess.Close)
	srv.acceptRegMux(t)
	model.setMuxSession(sess)

	done := make(chan struct{})
	go func() {
		defer close(done)
		model.proxy()
	}()

	proxy := srv.acceptProxy(t)
	if proxy.transport != carrierQuic {
		t.Fatalf("the ReqProxy was answered by a %q conn; with a QUIC session published it must be a QUIC stream", proxy.transport)
	}
	if proxy.regProxy.ClientId != model.id {
		t.Fatalf("RegProxy named %q, want %q", proxy.regProxy.ClientId, model.id)
	}

	publicRoundTrip(t, proxy.public, seen)

	proxy.public.Close()
	select {
	case <-done:
	case <-time.After(quicTestTimeout):
		t.Fatal("proxy() did not return after the public connection was closed")
	}

	// and the carrier is still alive for the next ReqProxy: closing one
	// stream must not have torn down the session the way it tears down a
	// dialed conn
	if sess.sess.IsClosed() {
		t.Fatal("closing one proxy stream killed the QUIC session")
	}
}

// TestQuicDialFallsThroughToSmuxOnALPNMismatch is the old-server pairing
// (SPEC-CLUSTER7 5): something QUIC-shaped is listening but refuses the
// handshake at ALPN -- what a TCP-only port answers when a QUIC client knocks.
// dialSession must surface the smux session, not the QUIC error: the mismatch
// is a fallback signal, and burning a watchdog attempt on it would make an
// upgrade-path coincidence look like a transport failure.
func TestQuicDialFallsThroughToSmuxOnALPNMismatch(t *testing.T) {
	publicUrl := "http://" + muxTestPublicHost
	shrinkQuicHandshakeTimeout(t)

	upstream, _ := upstreamServer(t)
	// the TCP fake first: its address is the one both dials aim at, UDP and
	// TCP side. The QUIC listener on the same port answers with an ALPN no
	// client of ours asks for.
	srv := startFakeTunnelServer(t, publicUrl)
	startFakeQuicServerAt(t, publicUrl, srv.addr, "wrong-alpn")

	model := quicTestModel(t, publicUrl, upstream.Listener.Addr().String(), srv.addr)
	// the TCP fake speaks plaintext (mux_test.go's fixture has no TLS), so
	// this model carries no TLS config: conn.Dial reads nil as "no TLS" on the
	// smux leg, and the QUIC leg -- where TLS is mandatory -- dials on library
	// defaults. Against the fixture's self-signed listener that dial dies at
	// the ALPN mismatch, which is the signal under test: the server refuses
	// the protocol before it ever sends a certificate.
	model.tlsConfig = nil

	sess, err := model.dialSession()
	if err != nil {
		t.Fatalf("dialSession failed: %v", err)
	}
	t.Cleanup(sess.Close)

	if sess.transport != carrierSmux {
		t.Fatalf("dialSession produced a %q session after the QUIC handshake refused; want the smux fallback", sess.transport)
	}
	// the session is a working one: the TCP side of the shared port answered
	// RegMux and built an smux session
	if got := srv.acceptRegMux(t); got != model.id {
		t.Fatalf("the fallback RegMux named %q, want %q", got, model.id)
	}
	srv.acceptSession(t)
}

// TestWatchdogTreatsYoungQuicSessionAsFailedAttempt covers the watchdog's
// arithmetic across carriers (SPEC-CLUSTER7 8-B): a QUIC session that
// established and died young is a failed attempt (the backoff and the give-up
// counter move), and the next dial -- QUIC now refusing, the smux path
// answering on the same port -- recovers the transport instead of giving up.
// The counting code is carrier-blind, so this test does not need eight dead
// QUIC sessions to prove the bound; it needs one, plus a live fallback.
func TestWatchdogTreatsYoungQuicSessionAsFailedAttempt(t *testing.T) {
	publicUrl := "http://" + muxTestPublicHost
	shrinkQuicHandshakeTimeout(t)

	upstream, _ := upstreamServer(t)
	srv := startFakeTunnelServer(t, publicUrl)
	// a QUIC listener on the shared port that is torn down before the
	// watchdog dials: the QUIC leg of every later attempt fails, and the
	// fallback is the only thing left to succeed
	dead := startFakeQuicServer(t, publicUrl)
	dead.listener.Close()

	model := quicTestModel(t, publicUrl, upstream.Listener.Addr().String(), srv.addr)
	// no TLS config, for the same reason the ALPN-mismatch test runs without
	// one: the smux fallback answers on the plain-TCP fake, and the QUIC leg
	// only has to fail (it does, at the closed UDP listener, inside the
	// shrunk handshake timeout).
	model.tlsConfig = nil

	// the dead-young session: a QUIC carrier that established a second ago
	// and is already gone (its AcceptStream fails at once, which is what
	// watch() turns into a closed done channel)
	young := newMuxSession(&deadCarrier{err: errors.New("carrier died")}, carrierQuic)
	t.Cleanup(young.Close)

	stop := make(chan struct{})
	watchdogDone := make(chan struct{})
	go func() {
		defer close(watchdogDone)
		model.muxWatchdog(stop, young)
	}()

	sess := waitForSession(t, model, nil)
	if sess.transport != carrierSmux {
		t.Fatalf("the watchdog recovered with a %q session; want the smux fallback after the young QUIC session", sess.transport)
	}
	if got := srv.acceptRegMux(t); got != model.id {
		t.Fatalf("the fallback RegMux named %q, want %q", got, model.id)
	}

	close(stop)
	select {
	case <-watchdogDone:
	case <-time.After(quicTestTimeout):
		t.Fatal("the watchdog did not return after the control session ended")
	}
}

// TestQuicTransportAllowedMatrix pins the per-attempt decision (SPEC-CLUSTER7
// 5) at unit level: the configuration's resolved transport and the control
// session's capability snapshot are the only two inputs, and the matrix is
// exactly their intersection. The http_proxy cases are not rows here on
// purpose: the proxy override is applied at construction (see
// TestNewClientModelResolvesProxyTransport), so by the time this decision
// runs, "http_proxy set" has already become proxyTransportTCP.
func TestQuicTransportAllowedMatrix(t *testing.T) {
	tests := []struct {
		name            string
		transport       proxyTransport
		peerCap         bool
		wantQuicAllowed bool
	}{
		{"auto with capability", proxyTransportAuto, true, true},
		{"auto without capability", proxyTransportAuto, false, false},
		{"quic pinned without capability", proxyTransportQuic, false, false},
		{"quic pinned with capability", proxyTransportQuic, true, true},
		{"tcp pinned ignores capability", proxyTransportTCP, true, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			model := &ClientModel{
				proxyTransport: tc.transport,
				tlsConfig:      quicTestClientTLS(),
			}
			model.quicPeerCap.Store(tc.peerCap)

			if got := model.quicTransportAllowed(); got != tc.wantQuicAllowed {
				t.Fatalf("quicTransportAllowed() = %v, want %v", got, tc.wantQuicAllowed)
			}
		})
	}
}

// TestQuicCarrierWatchReportsDeath exercises the death watch on the QUIC
// carrier: the watch goroutine surfaces a session's death by closing done --
// the watchdog's wake-up. A carrier whose AcceptStream never returned on
// death would leave the watchdog parked on a dead session, and every later
// ReqProxy with it.
func TestQuicCarrierWatchReportsDeath(t *testing.T) {
	publicUrl := "http://" + muxTestPublicHost

	upstream, _ := upstreamServer(t)
	srv := startFakeQuicServer(t, publicUrl)

	model := quicTestModel(t, publicUrl, upstream.Listener.Addr().String(), srv.addr)

	sess, err := model.dialQuicSession()
	if err != nil {
		t.Fatalf("dialQuicSession failed: %v", err)
	}
	t.Cleanup(sess.Close)
	srv.acceptRegMux(t)

	if sess.sess.IsClosed() {
		t.Fatal("a freshly dialed QUIC session reports itself closed")
	}

	// the server half dying is what a dropped carrier looks like from the
	// client; done must close without any stream being attempted
	sess.Close()
	select {
	case <-sess.done:
	case <-time.After(quicTestTimeout):
		t.Fatal("closing the QUIC session did not close the watchdog's done channel")
	}
	if !sess.sess.IsClosed() {
		t.Fatal("a closed QUIC session does not report itself closed")
	}
}

// ---------------------------------------------------------------------------
// a carrier that is already dead

// deadCarrier is a streamCarrier that died before the test started: every
// half returns the error, and IsClosed agrees. It is what the watchdog test
// feeds in to stand for "the QUIC session established and then died young"
// without needing a real handshake to have happened.
type deadCarrier struct {
	err error
}

func (c *deadCarrier) OpenStream() (net.Conn, error)   { return nil, c.err }
func (c *deadCarrier) AcceptStream() (net.Conn, error) { return nil, c.err }
func (c *deadCarrier) Close() error                    { return nil }
func (c *deadCarrier) IsClosed() bool                  { return true }
