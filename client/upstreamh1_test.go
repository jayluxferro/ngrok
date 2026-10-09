package client

// Unit tests for the h1 pool bridge (SPEC-CLUSTER25):
//
//	raw visitor bytes <-> net.Pipe <-> relay()/serveProxyConnection() <->
//	pipeBridgeConn (the pipe end) <-> one-conn http.Server <->
//	httputil.ReverseProxy <-> shared *http.Transport <-> local h1 server
//
// The local service of every test here is a real plaintext-HTTP/1.1 server on
// a real loopback port, with a countingListener in front of it (the
// SPEC-CLUSTER17 tests' fixture, reused) -- "the upstream saw one connection"
// only means something if the count is taken below the handler. The public
// side is one end of a net.Pipe, exactly as in model_proxy_test.go and
// upstreamh2_test.go, whose helpers these tests reuse.
//
// What is *not* covered here: the config surface and its refusal matrix
// (config_test.go, TestLoadConfigurationUpstreamPoolValidation) and the e2e
// group (scripts/e2e.sh, the pool group).

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"ngrok/client/mvc"
	"ngrok/log"
	"ngrok/proto"
)

// h1PoolTunnel is the pooled tunnel every bridge test proxies through: the
// local leg is localAddr and upstream_pool is the thing under test.
func h1PoolTunnel(publicUrl, localAddr string) mvc.Tunnel {
	tunnel := httpTunnel(publicUrl, localAddr)
	tunnel.UpstreamPool = true
	return tunnel
}

// h1Upstream is one in-test local h1 service on a real loopback port, with the
// accept count taken below the handler.
type h1Upstream struct {
	addr string
	ln   *countingListener
}

// startH1Upstream starts the service on addr -- "127.0.0.1:0" for a fresh
// port, a previously-returned addr to rebind the same port (the self-heal
// test, which is a service RESTART on the address the tunnel points at). kill
// stops the listener and closes every accepted connection -- a process death,
// not a graceful shutdown, exactly the h2 fixture's kill semantics.
func startH1Upstream(t *testing.T, addr string, handler http.Handler) *h1Upstream {
	t.Helper()

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("failed to listen for the h1 upstream on %s: %v", addr, err)
	}
	counting := &countingListener{Listener: ln}

	srv := &http.Server{Handler: handler}
	go srv.Serve(counting)
	t.Cleanup(func() { srv.Close() })

	return &h1Upstream{addr: ln.Addr().String(), ln: counting}
}

// kill makes the service look dead to new dials (listener closed) and to every
// accepted connection (closed on the wire).
func (u *h1Upstream) kill(t *testing.T) {
	t.Helper()
	if err := u.ln.Close(); err != nil {
		t.Fatalf("failed to close the upstream listener: %v", err)
	}
	u.ln.killConns()
}

// startH1PoolRelay is startH2Relay with the pooled dial in the local leg's
// place: the same relay() call the proxy path makes, the same pipe standing in
// for the server.
func startH1PoolRelay(t *testing.T, tunnel mvc.Tunnel) *relayUnderTest {
	t.Helper()

	localConn, err := dialUpstreamH1Pooled(tunnel)
	if err != nil {
		t.Fatalf("failed to build the h1 pool bridge for %s: %v", tunnel.LocalAddr, err)
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

// waitH1PoolWarm waits until a RoundTrip has succeeded through the address's
// pool, so a test never races markWarm.
func waitH1PoolWarm(t *testing.T, addr string) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for {
		upstreamH1Mu.Lock()
		pool := upstreamH1Pools[addr]
		warm := false
		if pool != nil {
			pool.mu.Lock()
			warm = pool.warm
			pool.mu.Unlock()
		}
		upstreamH1Mu.Unlock()
		if warm {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the pool for %s never marked warm", addr)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// h1PoolFor is the test-facing accessor: the pool for an address, failing the
// test when none exists.
func h1PoolFor(t *testing.T, addr string) *upstreamH1Pool {
	t.Helper()

	upstreamH1Mu.Lock()
	defer upstreamH1Mu.Unlock()
	pool := upstreamH1Pools[addr]
	if pool == nil {
		t.Fatalf("no h1 pool exists for %s; the bridge was not wired", addr)
	}
	return pool
}

// TestUpstreamH1PoolRoundTrip is the core assertion: an h1 request goes in,
// the upstream sees it as h1 -- method, path, Host (preserved, the fork's
// default), custom headers and body intact -- with exactly ONE
// X-Forwarded-For (the rewriter's injected value, carried through the bridge
// verbatim: gate 3's silent-trap pin, ReverseProxy's Rewrite mode is what
// keeps a second value from being appended) and exactly ONE
// X-Forwarded-Proto. The response comes back with its status, headers, body
// and declared Content-Length intact.
func TestUpstreamH1PoolRoundTrip(t *testing.T) {
	seen := make(chan recordedRequest, 4)
	up := startH1Upstream(t, "127.0.0.1:0", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		seen <- recordedRequest{method: r.Method, path: r.URL.Path, host: r.Host, proto: r.Proto, header: r.Header.Clone(), body: bodyBytes}
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-Upstream", "yes")
		w.WriteHeader(http.StatusTeapot)
		io.WriteString(w, "h1-pooled-body")
	}))

	h := startH1PoolRelay(t, h1PoolTunnel("https://pool.ngrok.dev", up.addr))

	h.send(t, "POST /rpc/Check HTTP/1.1\r\n"+
		"Host: pool.ngrok.dev\r\n"+
		"X-Custom: pool-me\r\n"+
		"Content-Length: 5\r\n"+
		"\r\n"+
		"hello")

	br := bufio.NewReader(h.public)
	resp := readResponseHead(t, br)
	if resp.StatusCode != http.StatusTeapot {
		t.Fatalf("expected the upstream's 418 to come back as 418, got %d", resp.StatusCode)
	}
	if resp.ContentLength != int64(len("h1-pooled-body")) {
		t.Fatalf("Content-Length did not survive the bridge: got %d, want %d", resp.ContentLength, len("h1-pooled-body"))
	}
	if body := readBodyBounded(t, resp); body != "h1-pooled-body" {
		t.Fatalf("response body did not survive the trip back: %q", body)
	}

	select {
	case req := <-seen:
		if req.proto != "HTTP/1.1" {
			t.Fatalf("the local service saw %q; the pooled bridge's contract is h1 end to end", req.proto)
		}
		if req.method != "POST" || req.path != "/rpc/Check" {
			t.Fatalf("request line did not survive: %s %s", req.method, req.path)
		}
		if req.host != "pool.ngrok.dev" {
			t.Fatalf("Host: expected the request's Host %q preserved (the fork's default), got %q", "pool.ngrok.dev", req.host)
		}
		if got := req.header.Get("X-Custom"); got != "pool-me" {
			t.Fatalf("custom header did not survive: %q", got)
		}
		if xff := req.header["X-Forwarded-For"]; len(xff) != 1 || xff[0] != testClientIP {
			t.Fatalf("X-Forwarded-For: expected exactly one value %q (rewriter injection carried verbatim), got %#v", testClientIP, xff)
		}
		if xfp := req.header["X-Forwarded-Proto"]; len(xfp) != 1 || xfp[0] != "https" {
			t.Fatalf("X-Forwarded-Proto: expected exactly one value \"https\", got %#v", xfp)
		}
		if string(req.body) != "hello" {
			t.Fatalf("request body did not survive: %q", string(req.body))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the h1 upstream never saw the request")
	}

	waitH1PoolWarm(t, up.addr)
	h.finish(t)
}

// TestUpstreamH1PoolByteExactBinaryBody pins the byte-exactness half of the
// e2e's scenario 1 at unit level: 64 KiB of random bytes, declared with an
// explicit Content-Length, must arrive with the same declared length and the
// same bytes -- random because a repeating pattern would pass through a
// framing bug that dropped or duplicated whole periods.
func TestUpstreamH1PoolByteExactBinaryBody(t *testing.T) {
	payload := make([]byte, 64*1024)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("failed to build the random payload: %v", err)
	}

	up := startH1Upstream(t, "127.0.0.1:0", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(payload)))
		w.WriteHeader(http.StatusOK)
		w.Write(payload)
	}))

	h := startH1PoolRelay(t, h1PoolTunnel("https://bytes.ngrok.dev", up.addr))
	h.send(t, getRequest("bytes.ngrok.dev"))

	br := bufio.NewReader(h.public)
	resp := readResponseHead(t, br)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	if resp.ContentLength != int64(len(payload)) {
		t.Fatalf("declared Content-Length changed across the bridge: got %d, want %d", resp.ContentLength, len(payload))
	}
	got := readBodyBounded(t, resp)
	if len(got) != len(payload) || !bytes.Equal([]byte(got), payload) {
		t.Fatalf("body changed across the bridge: got %d bytes, want %d (equal=%v)", len(got), len(payload), bytes.Equal([]byte(got), payload))
	}

	h.finish(t)
}

// TestUpstreamH1PoolReusesConnection is the accept collapse at unit level
// (spec objective 1): five requests over five proxy connections, served by
// keep-alive reuses of ONE upstream connection. The count is taken below the
// handler (countingListener), which is the only place the claim means
// anything.
func TestUpstreamH1PoolReusesConnection(t *testing.T) {
	var mu sync.Mutex
	served := 0
	up := startH1Upstream(t, "127.0.0.1:0", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		served++
		mu.Unlock()
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, "ok")
	}))

	tunnel := h1PoolTunnel("https://reuse.ngrok.dev", up.addr)
	for i := 0; i < 5; i++ {
		h := startH1PoolRelay(t, tunnel)
		h.send(t, getRequest("reuse.ngrok.dev"))

		br := bufio.NewReader(h.public)
		resp := readResponseHead(t, br)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("request %d answered %d", i+1, resp.StatusCode)
		}
		readBodyBounded(t, resp)
		waitH1PoolWarm(t, up.addr)
		h.finish(t)
	}

	// Exactly 2, not 1: the FIRST accept is the eager liveness probe -- a
	// dial-and-close, because http.Transport cannot pre-seed its idle pool --
	// and the second is the one keep-alive connection that then serves all
	// five requests. A plain dial for the same traffic would have accepted 5.
	if got := up.ln.count(); got != 2 {
		t.Fatalf("the upstream saw %d TCP connections for 5 requests; want exactly 2 (the one-time liveness probe + the one pooled connection serving all 5; a plain dial would be 5)", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if served != 5 {
		t.Fatalf("the upstream served %d of 5 requests", served)
	}
}

// TestUpstreamH1PoolTransportSettingsPinned pins the two silent-default traps
// and the streaming switch on the object itself, because none of them is fully
// observable on the wire (gate 3: "MaxIdleConnsPerHost set explicitly (grep +
// test)"):
//
//   - MaxIdleConnsPerHost 100 explicit: the net/http default of 2 would
//     quietly cap the pool at two connections per burst.
//   - IdleConnTimeout 90s: the shared upstreamH1IdleTimeout, mirroring the h2
//     pool's hygiene.
//   - FlushInterval -1: streaming parity on every response shape, not just
//     the text/event-stream one ReverseProxy sniffs.
//   - Transport: the SHARED per-address transport, not DefaultTransport --
//     the missing-ConnPool bug class from cluster 17, h1 edition.
func TestUpstreamH1PoolTransportSettingsPinned(t *testing.T) {
	up := startH1Upstream(t, "127.0.0.1:0", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "settings")
	}))

	tunnel := h1PoolTunnel("https://settings.ngrok.dev", up.addr)
	h := startH1PoolRelay(t, tunnel)
	h.send(t, getRequest("settings.ngrok.dev"))
	br := bufio.NewReader(h.public)
	resp := readResponseHead(t, br)
	readBodyBounded(t, resp)
	waitH1PoolWarm(t, up.addr)
	h.finish(t)

	pool := h1PoolFor(t, up.addr)
	if got := pool.transport.MaxIdleConnsPerHost; got != upstreamH1MaxIdleConnsPerHost {
		t.Fatalf("MaxIdleConnsPerHost = %d, want the explicit %d (the net/http default of 2 silently defeats pooling)", got, upstreamH1MaxIdleConnsPerHost)
	}
	if got := pool.transport.IdleConnTimeout; got != upstreamH1IdleTimeout {
		t.Fatalf("IdleConnTimeout = %v, want the shared %v", got, upstreamH1IdleTimeout)
	}
	if got := pool.transport.ResponseHeaderTimeout; got != 0 {
		t.Fatalf("ResponseHeaderTimeout = %v, want none (slow local services keep plain-dial parity)", got)
	}

	rp := (&upstreamH1Bridge{pool: pool, publicUrl: tunnel.PublicUrl, localAddr: tunnel.LocalAddr}).reverseProxy()
	if rp.Transport != http.RoundTripper(pool.transport) {
		t.Fatal("the ReverseProxy does not point at the shared per-address transport; it would pool under the wrong settings")
	}
	if rp.FlushInterval != -1 {
		t.Fatalf("FlushInterval = %v, want -1 (streaming parity)", rp.FlushInterval)
	}
	if rp.Rewrite == nil {
		t.Fatal("the ReverseProxy must use Rewrite (not Director): Director mode appends a second X-Forwarded-For")
	}
	if rp.ModifyResponse == nil {
		t.Fatal("the ReverseProxy must carry the warm marker (ModifyResponse retires the liveness probe)")
	}
}

// TestUpstreamH1DeadColdUsesExisting502 pins cold-failure parity at the byte
// level (spec objective 3, e2e scenario 3): with the local service dead, the
// pooled dial fails at the eager probe, and the visitor gets the SAME
// writeBadGateway page a failed plain dial produces -- compared here against
// the plain tunnel's bytes over the same wire, not merely asserted similar.
// The HTTP/1.0 response line is the fingerprint of the existing path.
func TestUpstreamH1DeadColdUsesExisting502(t *testing.T) {
	// A port with nothing listening: bind one, note the address, close it.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find a free port: %v", err)
	}
	deadAddr := probe.Addr().String()
	probe.Close()

	fetchRaw := func(t *testing.T, tunnel mvc.Tunnel) string {
		t.Helper()
		public := startAgentTLSProxy(t, tunnel, nil, nil).public
		// The visitor's request rides a goroutine on purpose: on this path
		// nobody ever reads it (the 502 is written before any relay starts),
		// and a synchronous net.Pipe write would block forever -- a real
		// socket would buffer the request and take the answer.
		go public.Write([]byte(getRequest(tunnel.PublicUrl[8:])))
		buf := make([]byte, 4096)
		n, err := io.ReadAtLeast(public, buf, 32)
		if err != nil {
			t.Fatalf("failed to read the 502 response: %v", err)
		}
		return string(buf[:n])
	}

	plain := fetchRaw(t, httpTunnel("https://dead.ngrok.dev", deadAddr))
	pooled := fetchRaw(t, h1PoolTunnel("https://dead.ngrok.dev", deadAddr))

	if plain != pooled {
		t.Fatalf("the pooled cold 502 is not byte-identical to the plain dial's:\nplain:  %q\npooled: %q", plain, pooled)
	}
	if !strings.HasPrefix(plain, "HTTP/1.0 502 Bad Gateway") {
		t.Fatalf("the dead-local answer must be writeBadGateway's HTTP/1.0 page, got:\n%s", plain)
	}
	if !strings.Contains(plain, "Tunnel https://dead.ngrok.dev unavailable") {
		t.Fatalf("expected the BadGateway page body naming the tunnel, got:\n%s", plain)
	}

	// The pool exists despite the failure: the probe ran, failed, and the
	// answer came from the caller's existing dead-upstream branch -- which is
	// the whole point of the eager probe.
	h1PoolFor(t, deadAddr)
}

// TestUpstreamH1WarmDeathAnswers502AndSelfHeals covers the other dead-service
// shape end to end (e2e scenario 4's unit twin): the pool was warm, the
// service died, the next request is answered by the bridge's own 502 (net/http
// writes it, so the response line is HTTP/1.1 -- the documented fingerprint
// that distinguishes the warm road from writeBadGateway's HTTP/1.0), and when
// the service comes back on the same address the tunnel heals with no operator
// action -- no poisoned pool.
func TestUpstreamH1WarmDeathAnswers502AndSelfHeals(t *testing.T) {
	seen := make(chan recordedRequest, 4)
	up := startH1Upstream(t, "127.0.0.1:0", recordInto(seen, http.StatusOK, nil, "alive"))
	addr := up.addr

	tunnel := h1PoolTunnel("https://heal.ngrok.dev", addr)

	first := startH1PoolRelay(t, tunnel)
	first.send(t, getRequest("heal.ngrok.dev"))
	firstBr := bufio.NewReader(first.public)
	resp := readResponseHead(t, firstBr)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the first request through a live service must succeed, got %d", resp.StatusCode)
	}
	readBodyBounded(t, resp)
	waitH1PoolWarm(t, addr)
	first.finish(t)

	// Kill: refused dials plus FINs on the wire, the way a process death kills
	// a service.
	up.kill(t)

	second := startH1PoolRelay(t, tunnel)
	second.send(t, getRequest("heal.ngrok.dev"))
	secondBr := bufio.NewReader(second.public)
	resp = readResponseHead(t, secondBr)
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("a warm pool whose service died must answer 502, got %d", resp.StatusCode)
	}
	if resp.Proto != "HTTP/1.1" {
		t.Fatalf("the warm-death 502 is the bridge's own (net/http writes HTTP/1.1), got %s", resp.Proto)
	}
	if body := readBodyBounded(t, resp); !strings.Contains(body, "unavailable") {
		t.Fatalf("expected the BadGateway page body, got:\n%s", body)
	}
	second.finish(t)

	// Restart on the SAME address -- the self-heal case, and the reason the
	// pool must not be poisoned by the death: the next request dials again and
	// succeeds. The rebind works because Go's net.Listen sets SO_REUSEADDR:
	// the dead connections' TIME_WAIT sockets do not hold the port against a
	// listener.
	startH1Upstream(t, addr, recordInto(seen, http.StatusOK, nil, "healed"))

	third := startH1PoolRelay(t, tunnel)
	third.send(t, getRequest("heal.ngrok.dev"))
	thirdBr := bufio.NewReader(third.public)
	resp = readResponseHead(t, thirdBr)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the tunnel must self-heal once the service returns, got %d", resp.StatusCode)
	}
	if body := readBodyBounded(t, resp); body != "healed" {
		t.Fatalf("unexpected body after the heal: %q", body)
	}
	third.finish(t)
}

// TestUpstreamH1SSEFirstByteBeforeEnd is the flush-parity pin (e2e scenario
// 6's unit twin, the SPEC-CLUSTER17 streaming tests' design): the upstream
// writes the first SSE event and FLUSHES, then blocks until the test releases
// it. The test proves those bytes are observable BEFORE releasing -- so "part1
// arrived before part2 was even written" is deterministic, no timing, no
// sleeps -- and a bridge that buffered the body would deadlock the test
// instead of failing it quietly.
func TestUpstreamH1SSEFirstByteBeforeEnd(t *testing.T) {
	release := make(chan struct{})

	up := startH1Upstream(t, "127.0.0.1:0", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "data: first\n\n")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		<-release
		io.WriteString(w, "data: second\n\n")
	}))

	h := startH1PoolRelay(t, h1PoolTunnel("https://sse.ngrok.dev", up.addr))
	h.send(t, getRequest("sse.ngrok.dev"))

	br := bufio.NewReader(h.public)
	resp := readResponseHead(t, br)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	buf := make([]byte, len("data: first\n\n"))
	if _, err := io.ReadFull(resp.Body, buf); err != nil {
		t.Fatalf("first SSE event never arrived: %v", err)
	}
	if string(buf) != "data: first\n\n" {
		t.Fatalf("first SSE event was %q, want %q", buf, "data: first\n\n")
	}

	// The first event is on the visitor's side; only now may the upstream
	// write the second.
	close(release)

	rest := readBodyBounded(t, resp)
	if rest != "data: second\n\n" {
		t.Fatalf("second SSE event was %q, want %q", rest, "data: second\n\n")
	}

	h.finish(t)
}

// TestUpstreamH1UpgradePassthroughPinned pins the shipped upgrade ruling
// (SPEC-CLUSTER25: "whichever ships is e2e-pinned and stated in the key's
// config comment. No silent choice"): WebSocket upgrades PASS THROUGH.
// ReverseProxy's 101 handling hijacks the bridge's pipe conn after writing the
// 101 head and splices raw bytes both ways -- the same thing the default raw
// pipe does for the same traffic, which is why refusing was never an option.
// The upstream here speaks just enough websocket to prove the mechanism: it
// requires the Upgrade handshake, answers 101, and echoes one frame's payload.
func TestUpstreamH1UpgradePassthroughPinned(t *testing.T) {
	framePayload := "ws-echo-me"

	up := startH1Upstream(t, "127.0.0.1:0", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "websocket" {
			http.Error(w, "not an upgrade", http.StatusBadRequest)
			return
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "no hijack", http.StatusInternalServerError)
			return
		}
		conn, brw, err := hj.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		fmt.Fprintf(brw, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
		brw.Flush()

		// One raw frame in, one raw frame out: a 0x81 text frame with the
		// payload echoed verbatim (no masking -- this fixture only proves the
		// tunnel carries post-upgrade bytes both ways).
		header := make([]byte, 2)
		if _, err := io.ReadFull(brw, header); err != nil {
			return
		}
		n := int(header[1] & 0x7f)
		payload := make([]byte, n)
		if _, err := io.ReadFull(brw, payload); err != nil {
			return
		}
		conn.Write([]byte{0x81, byte(n)})
		conn.Write(payload)
	}))

	h := startH1PoolRelay(t, h1PoolTunnel("https://ws.ngrok.dev", up.addr))
	h.send(t, "GET /ws HTTP/1.1\r\n"+
		"Host: ws.ngrok.dev\r\n"+
		"Connection: Upgrade\r\n"+
		"Upgrade: websocket\r\n"+
		"\r\n")

	br := bufio.NewReader(h.public)
	resp := readResponseHead(t, br)
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("the upgrade must pass through as 101, got %d", resp.StatusCode)
	}
	if !strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") {
		t.Fatalf("the 101 must carry the Upgrade: websocket header, got %q", resp.Header.Get("Upgrade"))
	}

	// Post-upgrade bytes must flow BOTH ways through the hijacked bridge.
	// The request frame is written into the public end, which the relay's
	// copier is already reading -- and the ECHO must be read back through the
	// bufio reader, not the raw conn: http.ReadResponse may have buffered
	// bytes beyond the 101 head, and reading the raw conn would miss them.
	frame := []byte{0x81, byte(len(framePayload))}
	frame = append(frame, framePayload...)
	if _, err := h.public.Write(frame); err != nil {
		t.Fatalf("failed to write the post-upgrade frame: %v", err)
	}

	echo := make([]byte, 2+len(framePayload))
	if _, err := io.ReadFull(br, echo); err != nil {
		t.Fatalf("no post-upgrade bytes came back through the bridge: %v", err)
	}
	if echo[0] != 0x81 || string(echo[2:]) != framePayload {
		t.Fatalf("the echoed frame was damaged: %#v", echo)
	}

	h.finish(t)
}

// TestUpstreamPoolResolvesAtTunnelBoundary pins the config->mvc mapping (the
// twin of TestUpstreamProtocolResolvesAtTunnelBoundary): a bool needs no
// resolving, so the tunnel carries the config value as written -- but the
// boundary is still where it crosses, and this is the test that catches a
// field that is parsed but never forwarded.
func TestUpstreamPoolResolvesAtTunnelBoundary(t *testing.T) {
	tunnel := tunnelFromConfig("https://x.ngrok.dev", "http", proto.NewHttp(), &TunnelConfiguration{
		Protocols:        map[string]string{"http": "127.0.0.1:8080"},
		UpstreamPool:     true,
		UpstreamProtocol: UpstreamProtocolHTTP1,
	})
	if !tunnel.UpstreamPool {
		t.Fatal("upstream_pool: true did not reach the tunnel the proxy path works with")
	}
	if tunnel.UpstreamProtocol != UpstreamProtocolHTTP1 {
		t.Fatalf("a pooled tunnel's upstream protocol resolved to %q, want %q", tunnel.UpstreamProtocol, UpstreamProtocolHTTP1)
	}

	plain := tunnelFromConfig("https://y.ngrok.dev", "http", proto.NewHttp(), &TunnelConfiguration{
		Protocols: map[string]string{"http": "127.0.0.1:8080"},
	})
	if plain.UpstreamPool {
		t.Fatal("no upstream_pool key must leave the field false (the zero value IS the default)")
	}
}
