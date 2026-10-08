package client

// Integration tests for the agent-side h1<->h2c transcoder (SPEC-CLUSTER17):
//
//	raw visitor bytes <-> net.Pipe <-> relay()/serveProxyConnection() <->
//	upstreamH2Conn (the pipe end) <-> one-conn http.Server <-> http2.Transport
//	<-> local h2c server
//
// The local service of every test here is a real plaintext-HTTP/2 server (h2c,
// prior knowledge) built from the same x/net pieces the e2e harness runs as
// scripts/h2c_upstream.go -- "the upstream received real h2" only means
// something if something actually parses h2. The public side is one end of a
// net.Pipe, exactly as in model_proxy_test.go, whose helpers
// (relayUnderTest, proxyTestConn, getRequest) these tests reuse.
//
// What is *not* covered here: the config surface and its validation matrix
// (config_test.go, TestLoadConfigurationUpstreamProtocolValidation and
// friends) and the e2e group (h1 curl in, proto=HTTP/2.0 xff=present out).

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"ngrok/client/mvc"
	"ngrok/log"
	"ngrok/proto"
)

// h2Tunnel is the http tunnel every transcode test proxies through: the local
// leg is localAddr, the upstream protocol is http2 (the thing under test), and
// compression is off because mvc.Tunnel.Compress carries the RESOLVED value
// and these tests want the pure transcode path -- the config-level fact that
// compression composes with upstream_protocol is pinned in config_test.go.
func h2Tunnel(publicUrl, localAddr string) mvc.Tunnel {
	tunnel := httpTunnel(publicUrl, localAddr)
	tunnel.UpstreamProtocol = UpstreamProtocolHTTP2
	return tunnel
}

// countingListener counts accepted connections: the pooling assertion ("the
// h2c server saw ONE TCP connection") is made against this count, not against
// anything the server handler can see, because the whole point is what happens
// BELOW the handler.
type countingListener struct {
	net.Listener
	accepted int32

	// conns are the accepted connections, so kill() can close them on the
	// wire -- which is what makes it a death rather than a shutdown.
	mu    sync.Mutex
	conns []net.Conn
}

func (l *countingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		atomic.AddInt32(&l.accepted, 1)
		l.mu.Lock()
		l.conns = append(l.conns, c)
		l.mu.Unlock()
	}
	return c, err
}

func (l *countingListener) count() int {
	return int(atomic.LoadInt32(&l.accepted))
}

func (l *countingListener) killConns() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, c := range l.conns {
		c.Close()
	}
	l.conns = nil
}

// h2cUpstream is one in-test local service: an h2c (prior-knowledge) server on
// a real loopback port.
type h2cUpstream struct {
	addr string
	ln   *countingListener
	srv  *http.Server
}

func startH2cUpstream(t *testing.T, handler http.Handler) *h2cUpstream {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen for the h2c upstream: %v", err)
	}
	counting := &countingListener{Listener: ln}

	// MaxConcurrentStreams must be explicit: x/net's standalone http2.Server
	// passes the zero value through to the wire, advertising
	// SETTINGS_MAX_CONCURRENT_STREAMS=0 -- which per RFC 7540 §6.5.2 tells
	// the client this server accepts NO new streams, so a correct client
	// (ours, and any x/net one) refuses to pool and dials per request. Real
	// h2c services advertise real values; 250 is the spec's recommendation.
	// The pooling test below lives on this line: with 0 advertised it fails
	// with "saw 2 TCP connections" for reasons the code under test cannot
	// help.
	srv := &http.Server{Handler: h2c.NewHandler(handler, &http2.Server{MaxConcurrentStreams: 250})}
	go srv.Serve(counting)
	t.Cleanup(func() { srv.Close() })

	return &h2cUpstream{addr: ln.Addr().String(), ln: counting, srv: srv}
}

// kill simulates the service dying: the listener stops accepting (new dials
// are refused) and every accepted connection is closed on the wire -- which is
// what a process death looks like from the pool's side: FINs arrive, the
// pooled connections' read loops see them, the pool evicts. srv.Close() alone
// does NOT do the second half here: the h2 session runs inside the outer
// http.Server's handler, and under Close() the observed behavior is a
// connection that keeps reading frames but never dispatches them -- a request
// sent onto it waits forever, a state no real death produces.
func (u *h2cUpstream) kill() {
	u.ln.Close()
	u.ln.killConns()
	u.srv.Close()
}

// recordedRequest is what the h2c upstream saw on one request. Header is a
// clone taken inside the handler so the test goroutine can read it after the
// request is done (the same discipline model_proxy_test uses).
type recordedRequest struct {
	method string
	path   string
	host   string
	proto  string
	header http.Header
	body   []byte
}

// recordInto returns a handler that records each request it serves onto the
// given channel and answers it with status, headers and body.
func recordInto(seen chan recordedRequest, status int, headers map[string]string, body string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		seen <- recordedRequest{
			method: r.Method,
			path:   r.URL.Path,
			host:   r.Host,
			proto:  r.Proto,
			header: r.Header.Clone(),
			body:   bodyBytes,
		}

		for k, v := range headers {
			w.Header().Set(k, v)
		}
		w.WriteHeader(status)
		io.WriteString(w, body)
	})
}

// startH2Relay is startRelay with the h2 dial in the local leg's place: the
// same relay() call the proxy path makes, the same pipe standing in for the
// server, but the local conn comes from dialUpstreamH2 -- the transcoder --
// instead of conn.Dial. Returns the same relayUnderTest handle the
// model_proxy_test helpers drive (send/finish).
func startH2Relay(t *testing.T, tunnel mvc.Tunnel) *relayUnderTest {
	t.Helper()

	localConn, err := dialUpstreamH2(tunnel)
	if err != nil {
		t.Fatalf("failed to build the h2 transcoder for %s: %v", tunnel.LocalAddr, err)
	}

	publicEnd, serverEnd := net.Pipe()
	remoteConn := &proxyTestConn{Conn: serverEnd, Logger: log.NewPrefixLogger("pxy"), id: "pxy"}
	// A deadline on the test's end means a wiring bug fails the test instead of
	// hanging it: every read the test does is bounded.
	publicEnd.SetDeadline(time.Now().Add(30 * time.Second))

	h := &relayUnderTest{
		public:   publicEnd,
		result:   make(chan relayResult, 1),
		finished: make(chan struct{}),
	}

	model := &ClientModel{Logger: log.NewPrefixLogger("test")}
	go func() {
		defer close(h.finished)
		bytesIn, bytesOut := model.relay(localConn, remoteConn, tunnel, testClientAddr)
		h.result <- relayResult{bytesIn: bytesIn, bytesOut: bytesOut}
	}()

	t.Cleanup(func() {
		publicEnd.Close()
		select {
		case <-h.finished:
		case <-time.After(10 * time.Second):
			t.Errorf("relay did not return after the public connection was closed")
		}
	})

	return h
}

// readResponseHead parses one response head off a connection's bufio reader,
// leaving the body unread. One reader per connection, one head per test
// connection: read-ahead beyond the head would steal bytes from the body reads.
// Parsing the head (rather than reading raw bytes) is also what makes the
// dead-upstream cases work without an EOF on the pipe -- a Content-Length'd 502
// reads to exactly its declared length.
//
// The head-only form exists because model_proxy_test.go's readResponse reads
// the body to its framing end, which is exactly what the streaming tests must
// NOT do: their bodies have not ended while the test is proving streaming.
func readResponseHead(t *testing.T, br *bufio.Reader) *http.Response {
	t.Helper()

	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("failed to read the response a visitor would see: %v", err)
	}
	return resp
}

// readBodyBounded reads the response body with a deadline, because "the body
// never arrived" must fail the test, not hang it.
func readBodyBounded(t *testing.T, resp *http.Response) string {
	t.Helper()

	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(resp.Body)
		done <- string(b)
	}()
	select {
	case b := <-done:
		return b
	case <-time.After(10 * time.Second):
		t.Fatal("response body never completed")
		return ""
	}
}

// TestUpstreamH2TranscodeRoundTrip is the core assertion: an h1 request goes
// in, a real h2 request comes out the other side -- method, path, Host (as
// :authority), custom headers and body all intact -- and the h2 response comes
// back as h1. X-Forwarded-For arriving at the h2 upstream is the mirror image
// of SPEC-CLUSTER16's xff=absent: there the h2 visitor bypasses the rewriter,
// here the rewriter runs and its injection rides the transcode.
func TestUpstreamH2TranscodeRoundTrip(t *testing.T) {
	seen := make(chan recordedRequest, 4)
	up := startH2cUpstream(t, recordInto(seen, http.StatusTeapot, map[string]string{
		"Content-Type": "text/plain",
		"X-Upstream":   "yes",
	}, "h2-response-body"))

	h := startH2Relay(t, h2Tunnel("https://grpc.ngrok.dev", up.addr))

	h.send(t, "POST /rpc/Check HTTP/1.1\r\n"+
		"Host: grpc.ngrok.dev\r\n"+
		"X-Custom: transcode-me\r\n"+
		"Content-Length: 5\r\n"+
		"\r\n"+
		"hello")

	br := bufio.NewReader(h.public)
	resp := readResponseHead(t, br)
	if resp.StatusCode != http.StatusTeapot {
		t.Fatalf("expected the upstream's 418 to come back as 418, got %d", resp.StatusCode)
	}
	if body := readBodyBounded(t, resp); body != "h2-response-body" {
		t.Fatalf("response body did not survive the trip back: %q", body)
	}

	select {
	case req := <-seen:
		if req.proto != "HTTP/2.0" {
			t.Fatalf("the local service saw %q; the transcoder's contract is real h2", req.proto)
		}
		if req.method != "POST" || req.path != "/rpc/Check" {
			t.Fatalf("request line did not survive: %s %s", req.method, req.path)
		}
		if req.host != "grpc.ngrok.dev" {
			t.Fatalf(":authority: expected the request's Host %q, got %q", "grpc.ngrok.dev", req.host)
		}
		if got := req.header.Get("X-Custom"); got != "transcode-me" {
			t.Fatalf("custom header did not survive: %q", got)
		}
		if got := req.header.Get("X-Forwarded-For"); got != testClientIP {
			t.Fatalf("X-Forwarded-For: expected %q (rewriter injection rides the transcode), got %q", testClientIP, got)
		}
		if string(req.body) != "hello" {
			t.Fatalf("request body did not survive: %q", string(req.body))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the h2c upstream never saw the request")
	}

	h.finish(t)
}

// TestUpstreamH2RequestBodyStreams proves the request body is not buffered: the
// upstream receives the first chunk and acts on it BEFORE the test writes the
// second. The upstream handler blocks between the two reads, so if any stage
// (h1 server, transport, pipe) held the body back, both sides would deadlock
// and the test would time out with the fault squarely on the buffering.
func TestUpstreamH2RequestBodyStreams(t *testing.T) {
	firstChunkRead := make(chan struct{})

	up := startH2cUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		chunk := make([]byte, 5)
		if _, err := io.ReadFull(r.Body, chunk); err != nil {
			t.Errorf("upstream: first body chunk never arrived: %v", err)
			return
		}
		if string(chunk) != "aaaaa" {
			t.Errorf("upstream: first chunk was %q, want %q", chunk, "aaaaa")
		}
		close(firstChunkRead)

		if _, err := io.ReadFull(r.Body, chunk); err != nil {
			t.Errorf("upstream: second body chunk never arrived: %v", err)
			return
		}
		if string(chunk) != "bbbbb" {
			t.Errorf("upstream: second chunk was %q, want %q", chunk, "bbbbb")
		}

		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "done")
	}))

	h := startH2Relay(t, h2Tunnel("https://stream.ngrok.dev", up.addr))

	h.send(t, "POST /upload HTTP/1.1\r\n"+
		"Host: stream.ngrok.dev\r\n"+
		"Content-Length: 10\r\n"+
		"\r\n"+
		"aaaaa")

	select {
	case <-firstChunkRead:
	case <-time.After(10 * time.Second):
		t.Fatal("the upstream never acted on the first body chunk before the second was sent: the body is being buffered somewhere")
	}

	if _, err := io.WriteString(h.public, "bbbbb"); err != nil {
		t.Fatalf("failed to write the second body chunk: %v", err)
	}

	br := bufio.NewReader(h.public)
	resp := readResponseHead(t, br)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 after both chunks, got %d", resp.StatusCode)
	}
	if body := readBodyBounded(t, resp); body != "done" {
		t.Fatalf("unexpected body after streaming upload: %q", body)
	}

	h.finish(t)
}

// TestUpstreamH2ResponseBodyStreams is the response-direction twin: the
// upstream writes the first part and flushes, then BLOCKS until the test has
// observed those bytes on the public end. Only then does it write the rest, so
// "part1 arrived before part2 was even written" is deterministic -- no timing,
// no sleeps -- and a transcoder that buffered the response body would deadlock
// the test instead of failing it quietly.
func TestUpstreamH2ResponseBodyStreams(t *testing.T) {
	release := make(chan struct{})
	wroteFirst := make(chan struct{})

	up := startH2cUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "part1")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		close(wroteFirst)
		<-release
		io.WriteString(w, "part2")
	}))

	h := startH2Relay(t, h2Tunnel("https://stream.ngrok.dev", up.addr))

	h.send(t, getRequest("stream.ngrok.dev"))

	br := bufio.NewReader(h.public)
	resp := readResponseHead(t, br)
	buf := make([]byte, 5)
	if _, err := io.ReadFull(resp.Body, buf); err != nil {
		t.Fatalf("first response part never arrived: %v", err)
	}
	if string(buf) != "part1" {
		t.Fatalf("first response part was %q, want %q", buf, "part1")
	}

	close(release)

	rest, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("rest of the streamed response failed: %v", err)
	}
	if string(rest) != "part2" {
		t.Fatalf("second response part was %q, want %q", rest, "part2")
	}

	<-wroteFirst
	h.finish(t)
}

// TestUpstreamH2TrailerPassthrough: trailers the h2 service announces ride the
// transcode and come out as h1 chunk trailers. The upstream declares the
// trailer the net/http way (Trailer header before the body, value set after),
// which is exactly what makes it visible to the transport BEFORE the body is
// read -- the only moment the h1 side can declare it.
func TestUpstreamH2TrailerPassthrough(t *testing.T) {
	up := startH2cUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Trailer", "X-Checksum")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "trailed")
		w.Header().Set("X-Checksum", "abc123")
	}))

	h := startH2Relay(t, h2Tunnel("https://trailers.ngrok.dev", up.addr))

	h.send(t, getRequest("trailers.ngrok.dev"))

	br := bufio.NewReader(h.public)
	resp := readResponseHead(t, br)
	if body := readBodyBounded(t, resp); body != "trailed" {
		t.Fatalf("body did not survive: %q", body)
	}
	if got := resp.Trailer.Get("X-Checksum"); got != "abc123" {
		t.Fatalf("trailer did not survive the transcode: X-Checksum=%q (declared trailers arrive in resp.Trailer after the body)", got)
	}

	h.finish(t)
}

// TestUpstreamH2UpgradeRefused pins the Upgrade refusal (SPEC-CLUSTER17
// non-goals): fixed 502, body naming the rule -- h2 has no Upgrade without
// extended CONNECT, and this release does not implement extended CONNECT. The
// upstream FAILS the test if it is reached at all: the refusal happens on the
// h1 side, before anything is dialed. (The rewriter passes the Upgrade and
// Connection heads through verbatim -- only policy add/remove edits a head --
// so the h1 half sees the upgrade exactly the visitor sent it.)
func TestUpstreamH2UpgradeRefused(t *testing.T) {
	up := startH2cUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("the upgrade request reached the local service; it must be refused on the h1 side")
		w.WriteHeader(http.StatusOK)
	}))

	h := startH2Relay(t, h2Tunnel("https://chat.ngrok.dev", up.addr))

	h.send(t, "GET /chat HTTP/1.1\r\n"+
		"Host: chat.ngrok.dev\r\n"+
		"Connection: Upgrade\r\n"+
		"Upgrade: websocket\r\n"+
		"\r\n")

	br := bufio.NewReader(h.public)
	resp := readResponseHead(t, br)
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("upgrade must be answered with the fixed 502, got %d", resp.StatusCode)
	}
	body := readBodyBounded(t, resp)
	if !strings.Contains(body, "extended CONNECT") || !strings.Contains(body, "upstream_protocol") {
		t.Fatalf("the 502 body must name the rule (no upgrade without extended CONNECT; the key that owns the road), got:\n%s", body)
	}

	h.finish(t)
}

// TestUpstreamH2DeadLocalUsesExisting502 pins the dead-local-service story at
// the serveProxyConnection level: with the pool cold, the dial fails, and the
// failure is answered by the SAME code path a failed plain dial takes -- the
// HTTP/1.0 BadGateway page, written by writeBadGateway. The response line's
// version is the fingerprint: the transcoder's own mid-request 502 is an
// HTTP/1.1 from net/http; THIS one must be the existing HTTP/1.0.
func TestUpstreamH2DeadLocalUsesExisting502(t *testing.T) {
	// A port with nothing listening: bind one, note the address, close it.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find a free port: %v", err)
	}
	deadAddr := probe.Addr().String()
	probe.Close()

	tunnel := h2Tunnel("https://dead.ngrok.dev", deadAddr)
	h := startAgentTLSProxy(t, tunnel, nil, nil)

	br := bufio.NewReader(h.public)
	resp := readResponseHead(t, br)
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected the existing 502 path, got %d", resp.StatusCode)
	}
	// writeBadGateway's page is HTTP/1.0; the transcoder's own mid-request 502
	// would be an HTTP/1.1 from net/http. The version pins WHICH path answered.
	if resp.Proto != "HTTP/1.0" {
		t.Fatalf("the dead-local answer must be writeBadGateway's HTTP/1.0 page (the existing path), got %s", resp.Proto)
	}
	if body := readBodyBounded(t, resp); !strings.Contains(body, "Tunnel https://dead.ngrok.dev unavailable") {
		t.Fatalf("expected the BadGateway page body naming the tunnel, got:\n%s", body)
	}
}

// TestUpstreamH2DeadLocalAfterPoolWasWarm covers the other dead-service shape:
// the pool was warm, the service died, and the next connection's request finds
// out. The death is waited out (the transport's MarkDead eviction is
// asynchronous), so the next connection dials a cold pool against a closed
// listener and fails exactly where a failed plain dial fails -- the existing
// dead-upstream branch, fingerprint and all. The death-WHILE-in-flight shape
// (the bridge's own RoundTrip-error 502) is the test after this one.
func TestUpstreamH2DeadLocalAfterPoolWasWarm(t *testing.T) {
	seen := make(chan recordedRequest, 1)
	up := startH2cUpstream(t, recordInto(seen, http.StatusOK, nil, "first"))
	addr := up.addr

	first := startH2Relay(t, h2Tunnel("https://dying.ngrok.dev", addr))
	first.send(t, getRequest("dying.ngrok.dev"))
	firstBr := bufio.NewReader(first.public)
	resp := readResponseHead(t, firstBr)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the first request through a live service must succeed, got %d", resp.StatusCode)
	}
	readBodyBounded(t, resp)
	first.finish(t)

	// Kill the local service the way a process death kills one (see kill):
	// refused dials plus FINs on the wire. The pooled connection's read loop
	// sees its FIN, reports the connection dead, and the pool evicts it --
	// asynchronously, so wait the eviction out rather than race it.
	up.kill()
	waitPoolEmpty(t, addr)

	tunnel := h2Tunnel("https://dying.ngrok.dev", addr)
	h := startAgentTLSProxy(t, tunnel, nil, nil)

	// No request is written -- none is needed, and on a net.Pipe one would
	// deadlock: the dial-time 502 is answered before any request is read (the
	// cold-pool test above proves that ordering), so the visitor here only
	// reads.
	resp = readResponseHead(t, bufio.NewReader(h.public))
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("a dead local service must answer 502, got %d", resp.StatusCode)
	}
	// With the eviction waited out the road is deterministic: a cold pool's
	// eager dial against a closed listener, answered by the existing branch.
	// The same fingerprint the cold-pool test uses pins WHICH path answered.
	if resp.Proto != "HTTP/1.0" {
		t.Fatalf("the warm-pool dead-local answer must be writeBadGateway's HTTP/1.0 page (the existing path), got %s", resp.Proto)
	}
	if body := readBodyBounded(t, resp); !strings.Contains(body, "unavailable") {
		t.Fatalf("expected the BadGateway page body, got:\n%s", body)
	}
}

// waitPoolEmpty waits until the per-address pool holds no live connection, so
// a test never races the transport's asynchronous MarkDead eviction after
// killing the upstream.
func waitPoolEmpty(t *testing.T, addr string) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for {
		upstreamH2Mu.Lock()
		pool := upstreamH2Pools[addr]
		n := -1
		if pool != nil {
			pool.mu.Lock()
			n = len(pool.conns)
			pool.mu.Unlock()
		}
		upstreamH2Mu.Unlock()
		if n == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the pooled connection to %s was never evicted after the service died (pool holds %d)", addr, n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestUpstreamH2DeadMidRequestBridges502 pins the bridge's own 502 road: the
// service dies WHILE a request is in flight on a pooled connection. The h2
// stream dies with the connection, RoundTrip returns the connection error, and
// the bridge answers with the same BadGateway page the plain dial's failure
// produces -- this one written by net/http, so its response line is HTTP/1.1,
// the fingerprint that distinguishes it from writeBadGateway's HTTP/1.0.
func TestUpstreamH2DeadMidRequestBridges502(t *testing.T) {
	entered := make(chan struct{}, 1)
	up := startH2cUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		// Hold the request in flight until the dying connection cancels it.
		<-r.Context().Done()
	}))
	addr := up.addr

	h := startH2Relay(t, h2Tunnel("https://dying.ngrok.internal", addr))
	h.send(t, getRequest("dying.ngrok.internal"))

	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the request never reached the upstream")
	}

	up.kill()

	resp := readResponseHead(t, bufio.NewReader(h.public))
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("a service dying mid-request must answer the bridge's 502, got %d", resp.StatusCode)
	}
	if resp.Proto != "HTTP/1.1" {
		t.Fatalf("the mid-request 502 is net/http's own (the bridge's road), got %s", resp.Proto)
	}
	if body := readBodyBounded(t, resp); !strings.Contains(body, "unavailable") {
		t.Fatalf("expected the BadGateway page body naming the local service, got:\n%s", body)
	}

	h.finish(t)
}

// TestUpstreamH2ConcurrentConnectionsSharePool is the pooling assertion: two
// proxy connections, the first one's request still in flight (the upstream
// holds it), and the second one's request must ride the SAME local TCP
// connection -- what an h2 local service wants, and the reason the transport
// is per-address rather than per-connection.
func TestUpstreamH2ConcurrentConnectionsSharePool(t *testing.T) {
	// Every entry signals (buffered: two requests live at once); each one
	// then holds until release, so a request "reaching the upstream" is
	// observable while it is still in flight.
	entered := make(chan struct{}, 2)
	release := make(chan struct{})

	up := startH2cUpstream(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		<-release
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "held")
	}))

	tunnel := h2Tunnel("https://pooled.ngrok.dev", up.addr)

	first := startH2Relay(t, tunnel)
	first.send(t, getRequest("pooled.ngrok.dev"))
	firstBr := bufio.NewReader(first.public)
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the first request never reached the upstream")
	}

	// The second proxy connection starts while the first request is held.
	// Pooling means it rides the SAME local TCP connection as a second h2
	// stream, so this wait succeeds while stream one is still open. A
	// transport that serialized requests (or dialed a fresh connection per
	// proxy connection) would stall here -- and the listener count at the
	// end would catch the second road.
	second := startH2Relay(t, tunnel)
	second.send(t, getRequest("pooled.ngrok.dev"))
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the second request never reached the upstream while the first was still held -- no concurrent streams on one local connection")
	}

	close(release)

	for _, leg := range []struct {
		name string
		br   *bufio.Reader
	}{{"second", bufio.NewReader(second.public)}, {"first", firstBr}} {
		resp := readResponseHead(t, leg.br)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("the %s connection's request failed: %d", leg.name, resp.StatusCode)
		}
		if body := readBodyBounded(t, resp); body != "held" {
			t.Fatalf("unexpected body on the %s connection: %q", leg.name, body)
		}
	}

	if got := up.ln.count(); got != 1 {
		t.Fatalf("the h2c server saw %d TCP connections; concurrent proxy connections must pool onto one local h2c connection", got)
	}

	first.finish(t)
	second.finish(t)
}

// TestUpstreamHTTP1ExplicitKeepsPlainDial is review gate 1: upstream_protocol:
// http1 (spelled out) is today's path -- a plain TCP dial, an h1 upstream, no
// transcoder. Two observations pin it: the upstream receives HTTP/1.1 (not a
// transcoded h2 request), and no per-address pool exists for the address
// (constructing the transcoder is the only thing that creates one).
func TestUpstreamHTTP1ExplicitKeepsPlainDial(t *testing.T) {
	seen := make(chan recordedRequest, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seen <- recordedRequest{method: r.Method, proto: r.Proto, host: r.Host, header: r.Header.Clone(), body: body}
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "plain-h1")
	}))
	t.Cleanup(upstream.Close)

	upstreamAddr := upstream.Listener.Addr().String()
	tunnel := h2Tunnel("https://plain.ngrok.dev", upstreamAddr)
	tunnel.UpstreamProtocol = UpstreamProtocolHTTP1

	h := startAgentTLSProxy(t, tunnel, nil, nil)

	if _, err := io.WriteString(h.public, getRequest("plain.ngrok.dev")); err != nil {
		t.Fatalf("failed to write the request: %v", err)
	}
	resp := readResponseHead(t, bufio.NewReader(h.public))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected the plain h1 path to serve the request, got %d", resp.StatusCode)
	}
	if body := readBodyBounded(t, resp); body != "plain-h1" {
		t.Fatalf("unexpected body: %q", body)
	}

	select {
	case req := <-seen:
		if req.proto != "HTTP/1.1" {
			t.Fatalf("explicit http1 must dial h1: the upstream saw %q", req.proto)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the plain upstream never saw the request")
	}

	upstreamH2Mu.Lock()
	_, transcoderBuilt := upstreamH2Pools[upstreamAddr]
	upstreamH2Mu.Unlock()
	if transcoderBuilt {
		t.Fatalf("explicit upstream_protocol: http1 constructed a transcoder pool for %s; the dial must be today's plain dial", upstreamAddr)
	}
}

// TestUpstreamProtocolResolvesAtTunnelBoundary pins the config->mvc mapping:
// the config field keeps the key's absence as empty (so a config round-trip
// stays honest), and the tunnel the proxy path works with carries the resolved
// default.
func TestUpstreamProtocolResolvesAtTunnelBoundary(t *testing.T) {
	cases := []struct {
		configured string
		want       string
	}{
		{"", UpstreamProtocolHTTP1},
		{UpstreamProtocolHTTP1, UpstreamProtocolHTTP1},
		{UpstreamProtocolHTTP2, UpstreamProtocolHTTP2},
	}
	for _, tt := range cases {
		tunnel := tunnelFromConfig("https://x.ngrok.dev", "http", proto.NewHttp(), &TunnelConfiguration{
			Protocols:        map[string]string{"http": "127.0.0.1:8080"},
			UpstreamProtocol: tt.configured,
		})
		if tunnel.UpstreamProtocol != tt.want {
			t.Fatalf("upstream_protocol %q resolved to %q, want %q", tt.configured, tunnel.UpstreamProtocol, tt.want)
		}
	}
}
