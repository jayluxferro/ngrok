package client

// Tests for the client's half of carrier_dedup (SPEC-CLUSTER21): the proposal
// on RegProxy, the install-then-engage order at the wrap site, the one Info per
// tunnel when the server does not ack, and the close line's counters when it
// does.
//
// The fixtures are mux_test.go's -- fakeTunnelServer, publicRoundTrip,
// upstreamServer, proxyTestConn -- plus the acking twin of the fake server
// defined below, because the real fake never sets msg.StartProxy.DedupAck (it
// stands in for today's server). The acking twin answers the way a
// dedup-aware server/tunnel.go must: the ack goes out plain, the codec engages
// AFTER writing it, and every byte from then on is framed.
//
// What is *not* covered here: wire byte-exactness of the codec itself (dedup/'s
// own tests) and the full two-binary story incl. the kill switch (lane D's
// e2e). These tests pin the client's ordering and its log contract.

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xtaci/smux/v2"
	"ngrok/client/mvc"
	"ngrok/conn"
	"ngrok/dedup"
	"ngrok/log"
	"ngrok/msg"
)

// ---------------------------------------------------------------------------
// the recording logger

// recordingLogger keeps every formatted line, so the tests count log lines
// instead of trusting that they were emitted -- the "exactly one Info per
// tunnel" contract is a count, and a count needs a counter.
type recordingLogger struct {
	mu    sync.Mutex
	lines []string
}

func (l *recordingLogger) AddLogPrefix(string)          {}
func (l *recordingLogger) SetLogPrefixes(...string)     {}
func (l *recordingLogger) Debug(string, ...interface{}) {}
func (l *recordingLogger) Info(f string, args ...interface{}) {
	l.record(f, args...)
}
func (l *recordingLogger) Warn(f string, args ...interface{}) error {
	l.record(f, args...)
	return nil
}
func (l *recordingLogger) Error(f string, args ...interface{}) error {
	l.record(f, args...)
	return nil
}

func (l *recordingLogger) record(f string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(f, args...))
}

// snapshot returns the lines so far.
func (l *recordingLogger) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.lines...)
}

// countContaining counts the lines with sub in them.
func (l *recordingLogger) countContaining(sub string) int {
	n := 0
	for _, line := range l.snapshot() {
		if strings.Contains(line, sub) {
			n++
		}
	}
	return n
}

// ---------------------------------------------------------------------------
// the client under test

// dedupTestModel is muxTestModel with a recording logger and the tunnel's
// carrier_dedup resolution recorded the way the control loop would have, for
// wantDedup true and false alike -- the false case is the control that keeps
// the proposal honest (no configured tunnel, no proposal).
func dedupTestModel(t *testing.T, publicUrl, upstreamAddr string, wantDedup bool) (*ClientModel, *recordingLogger) {
	t.Helper()

	logger := &recordingLogger{}
	model := &ClientModel{
		Logger:       logger,
		metrics:      NewClientMetrics(),
		ctl:          &stubController{},
		tunnels:      map[string]mvc.Tunnel{publicUrl: httpTunnel(publicUrl, upstreamAddr)},
		carrierDedup: map[string]bool{publicUrl: wantDedup},
	}
	return model, logger
}

// publishMuxSession brings up the model's mux transport, so a test can choose
// which transport proxy() answers ReqProxy with. The fake servers dispatch by
// first message, so the same listener serves both transports.
func publishMuxSession(t *testing.T, model *ClientModel, acceptMux func(*testing.T) (string, *smux.Session)) {
	t.Helper()

	sess, err := model.dialMuxSession()
	if err != nil {
		t.Fatalf("dialMuxSession failed: %v", err)
	}
	t.Cleanup(sess.Close)
	model.setMuxSession(sess)

	clientId, session := acceptMux(t)
	if clientId != model.id {
		t.Fatalf("RegMux named %q, want %q", clientId, model.id)
	}
	t.Cleanup(func() { session.Close() })
}

// runOneStream answers one ReqProxy the way the control handler does and waits
// for the proxy conn to end, so a test can serve several streams in sequence
// and count what they logged between them. The serve closure returns the
// public end and the RegProxy the fake saw, for the tests that assert on the
// proposal.
func runOneStream(t *testing.T, model *ClientModel, serve func(*testing.T) (conn.Conn, msg.RegProxy), roundTrip func(*testing.T, conn.Conn)) msg.RegProxy {
	t.Helper()

	done := make(chan struct{})
	go func() {
		defer close(done)
		model.proxy()
	}()

	public, regProxy := serve(t)
	roundTrip(t, public)

	public.Close()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("proxy() did not return after the public connection was closed")
	}
	return regProxy
}

// ---------------------------------------------------------------------------
// the acking fake server

// dedupAckServer is fakeTunnelServer's twin with the one behavior today's fake
// cannot have: it acks. The dispatch is the same by first message (RegMux opens
// a session, RegProxy is a dialed conn), and every served proxy conn answers
// StartProxy.DedupAck: true, then speaks framed bytes through an ENGAGED codec
// -- the flip order server/tunnel.go owes the protocol.
type dedupAckServer struct {
	addr string

	regMux   chan string
	sessions chan *smux.Session
	proxies  chan *fakeAckProxy
}

// fakeAckProxy is one served proxy conn: how it arrived, what it proposed, and
// the public end -- already engaged -- the test speaks framed bytes on. The
// codec is kept alongside so a test can read the counters of the direction it
// writes itself.
type fakeAckProxy struct {
	transport string // "stream" or "dialed"
	regProxy  msg.RegProxy
	public    conn.Conn
	codec     *dedup.Conn
}

func startDedupAckServer(t *testing.T, publicUrl string) *dedupAckServer {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen for the acking fake server: %v", err)
	}
	t.Cleanup(func() { listener.Close() })

	s := &dedupAckServer{
		addr:     listener.Addr().String(),
		regMux:   make(chan string, 8),
		sessions: make(chan *smux.Session, 8),
		proxies:  make(chan *fakeAckProxy, 8),
	}

	go func() {
		for {
			rawConn, err := listener.Accept()
			if err != nil {
				return
			}
			go s.serveConn(conn.Wrap(rawConn, "tun"), publicUrl)
		}
	}()

	return s
}

func (s *dedupAckServer) serveConn(rawConn conn.Conn, publicUrl string) {
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
		go s.acceptStreams(sess, publicUrl)

	case *msg.RegProxy:
		rawConn.SetType("pxy")
		s.serveProxy(rawConn, *m, "dialed", publicUrl)

	default:
		rawConn.Close()
	}
}

func (s *dedupAckServer) acceptStreams(sess *smux.Session, publicUrl string) {
	for {
		stream, err := sess.AcceptStream()
		if err != nil {
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

			s.serveProxy(pxyConn, regProxy, "stream", publicUrl)
		}()
	}
}

// serveProxy acks, engages, and hands the test the engaged end. The write of
// the ack and the engage are two steps ON PURPOSE, in this order: the ack is
// the last plain byte of the stream, and a client that is still pass-through
// when the first framed byte arrives has its own flip to blame.
func (s *dedupAckServer) serveProxy(pxyConn conn.Conn, regProxy msg.RegProxy, transport, publicUrl string) {
	startPxy := &msg.StartProxy{Url: publicUrl, ClientAddr: testClientAddr, DedupAck: true}
	if err := msg.WriteMsg(pxyConn, startPxy); err != nil {
		pxyConn.Close()
		return
	}

	codec := dedup.NewEngaged(pxyConn)
	public := &proxyTestConn{Conn: codec, Logger: log.NewPrefixLogger("pxy"), id: "pxy"}
	s.proxies <- &fakeAckProxy{transport: transport, regProxy: regProxy, public: public, codec: codec}
}

func (s *dedupAckServer) acceptAckProxy(t *testing.T) *fakeAckProxy {
	t.Helper()

	select {
	case p := <-s.proxies:
		return p
	case <-time.After(10 * time.Second):
		t.Fatal("the acking fake server was never asked to serve a proxy conn")
		return nil
	}
}

// ---------------------------------------------------------------------------
// payload helpers

// dedupPostBodyLen is the request body the engaged cases POST: large enough to
// span many average chunks (4 KiB), repeated so the second POST's chunks are
// all table hits -- the spec's shape of the win, in miniature.
const dedupPostBodyLen = 64 * 1024

func dedupPostBody() []byte {
	pattern := []byte("carrier_dedup round-trip payload; the second identical POST must cross as references. ")
	body := make([]byte, 0, dedupPostBodyLen)
	for len(body) < dedupPostBodyLen {
		body = append(body, pattern...)
	}
	return body[:dedupPostBodyLen]
}

// drainingUpstream is upstreamServer with the two differences the engaged
// tests need. It drains the request body before answering: a Go server handed
// back an unconsumed body closes the local leg, and the request-direction copy
// dies with the body half-relayed. And it answers with the repeated payload
// rather than the small fixture body, because on the carrier the AGENT's write
// direction carries the responses -- requests arrive server-side and are only
// ever read -- so the client's offered/framed/refs counters count response
// bytes, and a 14-byte response can never produce a reference.
func drainingUpstream(t *testing.T) (*httptest.Server, <-chan upstreamRequest) {
	t.Helper()

	seen := make(chan upstreamRequest, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		r.Body.Close()

		seen <- upstreamRequest{method: r.Method, host: r.Host, header: r.Header.Clone()}

		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write(dedupPostBody())
	}))
	t.Cleanup(srv.Close)

	return srv, seen
}

// postRoundTrip plays one POST with the repeated body and reads the response,
// the way a public client would over one keep-alive connection. Requests ride
// the rewriter stack, so the upstream really parses what arrives.
func postRoundTrip(t *testing.T, public net.Conn, seen <-chan upstreamRequest) {
	t.Helper()

	public.SetDeadline(time.Now().Add(30 * time.Second))

	body := dedupPostBody()
	head := "POST /submit HTTP/1.1\r\n" +
		"Host: " + muxTestPublicHost + "\r\n" +
		"Content-Length: " + strconv.Itoa(len(body)) + "\r\n" +
		"\r\n"
	if _, err := io.WriteString(public, head); err != nil {
		t.Fatalf("failed to send the request head over the proxy conn: %v", err)
	}
	if _, err := public.Write(body); err != nil {
		t.Fatalf("failed to send the request body over the proxy conn: %v", err)
	}

	resp, got := readResponse(t, bufio.NewReader(public))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the public client got status %d, want 200", resp.StatusCode)
	}
	if string(got) != string(dedupPostBody()) {
		t.Fatalf("the public client got a %d-byte body, want the repeated payload intact (%d bytes)", len(got), dedupPostBodyLen)
	}

	req := upstreamObserved(t, seen)
	if req.method != http.MethodPost {
		t.Fatalf("the upstream saw method %q, want POST", req.method)
	}
}

// ---------------------------------------------------------------------------
// tests

// TestCarrierDedupProposalFollowsTheConfig pins the proposal half of the
// negotiation: RegProxy.Dedup is true exactly when a configured tunnel asked
// for the feature, on both transports. The client cannot know at RegProxy time
// which tunnel a proxy conn will serve -- StartProxy names it -- so the
// per-client proposal is as fine as the handshake can express, but never
// proposing without the key is what keeps the message shaped like today's for
// every client that did not opt in.
func TestCarrierDedupProposalFollowsTheConfig(t *testing.T) {
	publicUrl := "http://" + muxTestPublicHost

	cases := []struct {
		name      string
		wantDedup bool
		withMux   bool
	}{
		{name: "configured tunnel, mux stream", wantDedup: true, withMux: true},
		{name: "configured tunnel, dialed conn", wantDedup: true, withMux: false},
		{name: "no configured tunnel, dialed conn", wantDedup: false, withMux: false},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			upstream, seen := upstreamServer(t)
			srv := startFakeTunnelServer(t, publicUrl)

			model, _ := dedupTestModel(t, publicUrl, upstream.Listener.Addr().String(), tt.wantDedup)
			model.serverAddr = srv.addr
			model.id = "client-dedup-proposal"

			if tt.withMux {
				publishMuxSession(t, model, func(t *testing.T) (string, *smux.Session) {
					return srv.acceptRegMux(t), srv.acceptSession(t)
				})
			}

			regProxy := runOneStream(t, model, func(t *testing.T) (conn.Conn, msg.RegProxy) {
				proxy := srv.acceptProxy(t)
				return proxy.public, proxy.regProxy
			}, func(t *testing.T, public conn.Conn) {
				publicRoundTrip(t, public, seen)
			})

			if regProxy.Dedup != tt.wantDedup {
				t.Fatalf("RegProxy proposed Dedup=%v, want %v", regProxy.Dedup, tt.wantDedup)
			}
		})
	}
}

// TestCarrierDedupUnackedStaysPassThroughAndNoticesOncePerTunnel is the
// ordering pin's negative half: a tunnel with the key whose server never acks
// (an old binary, or the kill switch) relays plain bytes transparently -- had
// the client engaged on its own proposal, the codec would read this test's raw
// HTTP as frames and die loudly -- and the one notice per tunnel is a COUNT:
// three streams later there is still exactly one, and no close line.
func TestCarrierDedupUnackedStaysPassThroughAndNoticesOncePerTunnel(t *testing.T) {
	publicUrl := "http://" + muxTestPublicHost

	for _, withMux := range []bool{true, false} {
		name := "dialed"
		if withMux {
			name = "mux stream"
		}
		t.Run(name, func(t *testing.T) {
			upstream, seen := upstreamServer(t)
			srv := startFakeTunnelServer(t, publicUrl)

			model, logger := dedupTestModel(t, publicUrl, upstream.Listener.Addr().String(), true)
			model.serverAddr = srv.addr
			model.id = "client-dedup-noack"

			if withMux {
				publishMuxSession(t, model, func(t *testing.T) (string, *smux.Session) {
					return srv.acceptRegMux(t), srv.acceptSession(t)
				})
			}

			for i := 0; i < 3; i++ {
				runOneStream(t, model, func(t *testing.T) (conn.Conn, msg.RegProxy) {
					proxy := srv.acceptProxy(t)
					return proxy.public, proxy.regProxy
				}, func(t *testing.T, public conn.Conn) {
					publicRoundTrip(t, public, seen)
				})
			}

			if got := logger.countContaining("carrier_dedup"); got != 1 {
				t.Fatalf("three unacked streams logged %d carrier_dedup lines, want exactly 1:\n%v",
					got, strings.Join(logger.snapshot(), "\n"))
			}
			if got := logger.countContaining("offered="); got != 0 {
				t.Fatalf("an unacked proposal logged a close line %d times, want none", got)
			}
		})
	}
}

// TestCarrierDedupAckEngagesAndLogsTheCloseLine is the positive half: the
// server acks and frames from the byte after the ack; the client engages after
// READING it, and identical repeated POSTs cross the carrier as references on
// their second pass. The close line is the contract's honest-win number:
// exactly one per connection, with refs on the wire and fewer framed bytes
// than offered ones.
func TestCarrierDedupAckEngagesAndLogsTheCloseLine(t *testing.T) {
	publicUrl := "http://" + muxTestPublicHost

	for _, withMux := range []bool{true, false} {
		name := "dialed"
		if withMux {
			name = "mux stream"
		}
		t.Run(name, func(t *testing.T) {
			upstream, seen := drainingUpstream(t)
			srv := startDedupAckServer(t, publicUrl)

			model, logger := dedupTestModel(t, publicUrl, upstream.Listener.Addr().String(), true)
			model.serverAddr = srv.addr
			model.id = "client-dedup-ack"

			if withMux {
				publishMuxSession(t, model, func(t *testing.T) (string, *smux.Session) {
					return <-srv.regMux, <-srv.sessions
				})
			}

			done := make(chan struct{})
			go func() {
				defer close(done)
				model.proxy()
			}()

			proxy := srv.acceptAckProxy(t)
			wantTransport := "dialed"
			if withMux {
				wantTransport = "stream"
			}
			if proxy.transport != wantTransport {
				t.Fatalf("the ReqProxy was answered by a %s proxy conn, want %s", proxy.transport, wantTransport)
			}
			if !proxy.regProxy.Dedup {
				t.Fatal("the engaged case must start from a proposed RegProxy")
			}

			// Two identical POSTs on one keep-alive connection: the first
			// stores the chunks, the second references them.
			postRoundTrip(t, proxy.public, seen)
			postRoundTrip(t, proxy.public, seen)

			// The dedup effect, asserted on the codec the test writes itself:
			// the test's two POST bodies are byte-identical and cross the
			// carrier in writes of the test's own fixed grouping, so the
			// second POST's chunks are all table hits and the references are
			// deterministic. (The client's own close-line counters count the
			// RESPONSE direction, whose write grouping is conn.Join's and the
			// tee's to choose -- right for a log line, wrong for an exact
			// assertion.)
			offered, framed, refs := proxy.codec.Offered(), proxy.codec.Framed(), proxy.codec.Refs()
			if refs == 0 {
				t.Fatalf("the repeated POST produced no REF frames (offered=%d framed=%d refs=%d); the second pass was not deduplicated", offered, framed, refs)
			}
			if framed >= offered {
				t.Fatalf("the carrier framed %d bytes for %d offered; the repeated body did not shrink (offered=%d framed=%d refs=%d)",
					framed, offered, offered, framed, refs)
			}

			proxy.public.Close()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("proxy() did not return after the public connection was closed")
			}

			closes := logger.countContaining("offered=")
			notices := logger.countContaining("stays pass-through")
			if closes != 1 {
				t.Fatalf("one engaged connection logged %d close lines, want exactly 1:\n%v",
					closes, strings.Join(logger.snapshot(), "\n"))
			}
			if notices != 0 {
				t.Fatalf("an acked connection logged the no-ack notice %d times, want none", notices)
			}

			cOffered, cFramed, cRefs := parseCloseLine(t, logger)
			if cOffered == 0 {
				t.Fatalf("the close line reported no offered bytes (offered=%d framed=%d refs=%d); the engaged direction carried nothing", cOffered, cFramed, cRefs)
			}
		})
	}
}

// parseCloseLine digs the counters out of the one close line, so the assertion
// reads in the spec's own vocabulary.
func parseCloseLine(t *testing.T, logger *recordingLogger) (offered, framed, refs uint64) {
	t.Helper()

	for _, line := range logger.snapshot() {
		if !strings.Contains(line, "offered=") {
			continue
		}
		if _, err := fmt.Sscanf(line, "carrier_dedup: offered=%d framed=%d refs=%d", &offered, &framed, &refs); err != nil {
			t.Fatalf("close line %q does not match the contract shape: %v", line, err)
		}
		return offered, framed, refs
	}
	t.Fatal("no close line was logged")
	return 0, 0, 0
}

// TestCarrierDedupCloseLineAndNoticeAreGated is the unit-level half of the log
// contract, for the shapes the integration tests cannot reach: a nil codec (no
// proposal) logs nothing, an unknown tunnel earns no notice, and the notice is
// deduplicated in the model, not in the log sink.
func TestCarrierDedupCloseLineAndNoticeAreGated(t *testing.T) {
	const url = "http://" + muxTestPublicHost

	newCarrier := func() *dedup.Conn {
		inner, _ := net.Pipe()
		return dedup.NewPassThrough(&proxyTestConn{Conn: inner, Logger: log.NewPrefixLogger("pxy"), id: "pxy"})
	}

	t.Run("nil codec logs nothing", func(t *testing.T) {
		model, logger := dedupTestModel(t, url, "127.0.0.1:1", true)

		model.closeCarrierDedup(nil, &msg.StartProxy{Url: url, DedupAck: true})
		model.closeCarrierDedup(nil, &msg.StartProxy{Url: url})

		if got := logger.countContaining("carrier_dedup"); got != 0 {
			t.Fatalf("a nil codec logged %d lines, want none", got)
		}
	})

	t.Run("the notice is deduplicated per tunnel", func(t *testing.T) {
		model, logger := dedupTestModel(t, url, "127.0.0.1:1", true)
		carrier := newCarrier()

		for i := 0; i < 5; i++ {
			model.closeCarrierDedup(carrier, &msg.StartProxy{Url: url})
		}

		if got := logger.countContaining("carrier_dedup"); got != 1 {
			t.Fatalf("five unacked streams logged %d notices, want exactly 1", got)
		}
	})

	t.Run("an unknown tunnel earns no notice", func(t *testing.T) {
		model, logger := dedupTestModel(t, url, "127.0.0.1:1", true)
		carrier := newCarrier()

		model.closeCarrierDedup(carrier, &msg.StartProxy{Url: "http://someone-else.ngrok.test"})

		if got := logger.countContaining("carrier_dedup"); got != 0 {
			t.Fatalf("an unknown tunnel logged %d lines, want none", got)
		}
	})
}
