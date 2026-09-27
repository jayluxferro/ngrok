package client

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"ngrok/client/mvc"
	"ngrok/conn"
	"ngrok/log"
	"ngrok/proto"
	"ngrok/rewriter"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Integration tests for the header-rewriting data path (SPEC 8-C):
//
//	public client <-> net.Pipe <-> relay() <-> localConn <-> httptest upstream
//
// relay() is the part of proxy() that runs once both legs of a proxied
// connection are up, so these tests need neither an ngrokd to register with nor
// a control channel to speak over. The public side of the connection is one end
// of a net.Pipe, where a test writes raw request bytes and reads back the bytes
// a client would see; the local side is a real server, because "the rewritten
// head arrived" only means something if something actually parses it.
//
// What is *not* covered here: the tunnel-population code in model.go (it needs
// a control connection to reach) and the inspector tee that proxy() wraps
// localConn in (it lives outside relay, and scripts/e2e.sh exercises it).

const (
	// testClientAddr is what the server puts in StartProxy.ClientAddr: an
	// "ip:port" string, because that is what server/tunnel.go sends
	// (RemoteAddr().String()).
	testClientAddr = "203.0.113.7:45678"

	// testClientIP is the X-Forwarded-For value policyFromTunnel derives from
	// it: the bare IP, port stripped (ngrok parity, SPEC 4.3).
	testClientIP = "203.0.113.7"

	// testUpstreamBody is the body the httptest upstream answers with; the
	// response tests check that it survives rewriting byte for byte.
	testUpstreamBody = "upstream-body"
)

// proxyTestConn adapts one end of a net.Pipe to conn.Conn. conn.Wrap only knows
// how to wrap *net.TCPConn and vhost connections (conn/conn.go:40-54), and the
// public side of these tests deliberately stays off the network.
type proxyTestConn struct {
	net.Conn
	log.Logger
	id string
}

func (c *proxyTestConn) Id() string       { return c.id }
func (c *proxyTestConn) SetType(string)   {}
func (c *proxyTestConn) CloseRead() error { return nil }

// upstreamRequest is what the httptest upstream saw on one request. Header is a
// clone taken inside the handler, so the test goroutine can read it afterwards
// without racing the server over the live request.
type upstreamRequest struct {
	method string
	host   string
	header http.Header
}

// upstreamServer starts a local upstream that reports every request it handles
// on the returned channel, and answers with a body and headers the response
// tests look for.
func upstreamServer(t *testing.T) (*httptest.Server, <-chan upstreamRequest) {
	t.Helper()

	seen := make(chan upstreamRequest, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- upstreamRequest{method: r.Method, host: r.Host, header: r.Header.Clone()}

		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-Upstream", "yes")
		w.Header().Set("X-Secret", "shh")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, testUpstreamBody)
	}))
	t.Cleanup(srv.Close)

	return srv, seen
}

// httpTunnel is the tunnel the http cases proxy through: its local leg is
// localAddr, its public URL is whatever the case wants X-Forwarded-Proto to be
// derived from, and its Protocol is set because relay asks the protocol whether
// this tunnel has headers at all.
func httpTunnel(publicUrl, localAddr string) mvc.Tunnel {
	return mvc.Tunnel{
		PublicUrl: publicUrl,
		LocalAddr: localAddr,
		Protocol:  proto.NewHttp(),
	}
}

// relayResult is what relay() reported once the connection was done.
type relayResult struct {
	bytesIn, bytesOut int64
}

// relayUnderTest is one in-flight proxied connection.
type relayUnderTest struct {
	// public is the server-side end of the tunnel as the test sees it: a
	// request written here is what the public client sent, and what is read
	// here is what the public client received.
	public net.Conn

	result   chan relayResult
	finished chan struct{}
}

// startRelay dials the local leg and starts the same call proxy() makes, with a
// pipe standing in for the server-side connection.
func startRelay(t *testing.T, upstreamAddr string, tunnel mvc.Tunnel) *relayUnderTest {
	t.Helper()

	localConn, err := conn.Dial(upstreamAddr, "prv", nil)
	if err != nil {
		t.Fatalf("failed to dial the upstream at %s: %v", upstreamAddr, err)
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

	// relay() returns only once both directions have stopped, and the test owns
	// one of them: close this end so the join winds down before the upstream
	// (and the rest of the test's fixtures) go away. Cleanups run
	// last-registered-first, so this happens before the httptest server closes.
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

// send writes raw bytes (a request head, usually) into the public end.
func (h *relayUnderTest) send(t *testing.T, raw string) {
	t.Helper()

	if _, err := io.WriteString(h.public, raw); err != nil {
		t.Fatalf("failed to write request to the public connection: %v", err)
	}
}

// finish closes the public end and returns relay's byte counts. It must be
// called at most once per test.
func (h *relayUnderTest) finish(t *testing.T) (bytesIn, bytesOut int64) {
	t.Helper()

	h.public.Close()
	select {
	case r := <-h.result:
		return r.bytesIn, r.bytesOut
	case <-time.After(10 * time.Second):
		t.Fatal("relay did not return after both legs were closed")
		return 0, 0
	}
}

// getRequest builds a raw HTTP/1.1 request head with no body, the way a client
// would put it on the wire.
func getRequest(host string, extra ...string) string {
	var b strings.Builder
	b.WriteString("GET / HTTP/1.1\r\n")
	b.WriteString("Host: " + host + "\r\n")
	for _, line := range extra {
		b.WriteString(line + "\r\n")
	}
	b.WriteString("\r\n")
	return b.String()
}

// forwardedHostValues is the X-Forwarded-Host list a case expects: nothing at
// all when the Host was left alone, exactly one value when it was rewritten.
func forwardedHostValues(want string) []string {
	if want == "" {
		return nil
	}
	return []string{want}
}

// upstreamObserved reads the next request the upstream reported.
func upstreamObserved(t *testing.T, seen <-chan upstreamRequest) upstreamRequest {
	t.Helper()

	select {
	case req := <-seen:
		return req
	case <-time.After(10 * time.Second):
		t.Fatal("the upstream never saw a request")
		return upstreamRequest{}
	}
}

// readResponse reads one response the way a client would: head first, then
// exactly the body its framing promises, so a pipelined response behind it
// stays parseable.
func readResponse(t *testing.T, br *bufio.Reader) (*http.Response, []byte) {
	t.Helper()

	// A nil request means "no expected method", which net/http treats as GET
	// (net/http/response.go: it only consults the request for HEAD).
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("failed to read response from the public connection: %v", err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}
	resp.Body.Close()

	return resp, body
}

// recordingReader remembers the raw bytes a test read off the public end, so a
// test can assert on what a client would literally see and not only on what
// net/http made of it.
type recordingReader struct {
	r io.Reader
	// raw holds everything read so far; the read-ahead bufio.Reader in front of
	// it may pull more than one response, which does not matter to the "these
	// bytes are (not) present" assertions made against it.
	raw bytes.Buffer
}

func (r *recordingReader) Read(p []byte) (n int, err error) {
	n, err = r.r.Read(p)
	r.raw.Write(p[:n])
	return n, err
}

// hostOf is the "rewrite" target for an address: what policyFromTunnel derives
// from tunnel.LocalAddr.
func hostOf(t *testing.T, addr string) string {
	t.Helper()

	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("failed to split host and port of %q: %v", addr, err)
	}
	return host
}

// requestWant is what a request-side case expects the upstream to have
// received. An empty forwardedHost means X-Forwarded-Host must be absent
// altogether, which is not the same as being present and empty.
type requestWant struct {
	host              string
	hostFromLocalAddr bool // host is the host part of the local address being dialed
	forwardedHost     string
	headers           map[string]string // Header.Get must return exactly these
	allValues         map[string][]string
	absent            []string
}

// TestRelayRewritesRequestHeads covers the request half of SPEC 8-C-1: a raw
// request written by the public client arrives at the local upstream with the
// Host, X-Forwarded-* and configured header changes the tunnel asks for.
func TestRelayRewritesRequestHeads(t *testing.T) {
	cases := []struct {
		name      string
		configure func(*mvc.Tunnel)
		request   string
		want      requestWant
	}{
		{
			// SPEC 4.1 + 4.3: no host_header means "preserve", and the
			// X-Forwarded injection is on for every http tunnel.
			name:    "unset host_header preserves the Host and adds the X-Forwarded pair",
			request: getRequest("localhost:18080", "User-Agent: curl/8.5.0"),
			want: requestWant{
				host:      "localhost:18080",
				allValues: map[string][]string{"X-Forwarded-For": {testClientIP}},
				headers:   map[string]string{"X-Forwarded-Proto": "http"},
				absent:    []string{"X-Forwarded-Host"},
			},
		},
		{
			// The Ollama case (SPEC 4.1): the local leg is 127.0.0.1:<port>,
			// and the upstream must see a bare 127.0.0.1 as the Host.
			name:      "host_header rewrite sends the local host and keeps the original",
			configure: func(tunnel *mvc.Tunnel) { tunnel.HostHeader = "rewrite" },
			request:   getRequest("localhost:18080", "User-Agent: curl/8.5.0"),
			want: requestWant{
				hostFromLocalAddr: true,
				forwardedHost:     "localhost:18080",
				headers:           map[string]string{"X-Forwarded-Proto": "http"},
				allValues:         map[string][]string{"X-Forwarded-For": {testClientIP}},
			},
		},
		{
			// The explicit form from Ollama's FAQ: the value is sent verbatim
			// and, like "rewrite", the original Host is preserved.
			name:      "host_header explicit value is sent verbatim",
			configure: func(tunnel *mvc.Tunnel) { tunnel.HostHeader = "localhost:11434" },
			request:   getRequest("tunnel.example.com", "User-Agent: curl/8.5.0"),
			want: requestWant{
				host:          "localhost:11434",
				forwardedHost: "tunnel.example.com",
				headers:       map[string]string{"X-Forwarded-Proto": "http"},
				allValues:     map[string][]string{"X-Forwarded-For": {testClientIP}},
			},
		},
		{
			// A spoofed X-Forwarded-For must be replaced, not joined (4.3):
			// exactly one value, and it is the one the server reported.
			name:    "X-Forwarded-For replaces what the client sent",
			request: getRequest("localhost:18080", "X-Forwarded-For: 10.0.0.1", "X-Forwarded-Proto: ftp"),
			want: requestWant{
				host:      "localhost:18080",
				headers:   map[string]string{"X-Forwarded-Proto": "http"},
				allValues: map[string][]string{"X-Forwarded-For": {testClientIP}},
			},
		},
		{
			// 4.2: additions are deserialized from the config's "Key: value"
			// form and appended, so a colon in the value survives.
			name: "request_header add sends the configured headers",
			configure: func(tunnel *mvc.Tunnel) {
				tunnel.RequestHeaderAdd = []string{"X-Custom: value", "X-Url: http://example.com/a:b"}
			},
			request: getRequest("localhost:18080"),
			want: requestWant{
				host:    "localhost:18080",
				headers: map[string]string{"X-Custom": "value", "X-Url": "http://example.com/a:b"},
			},
		},
		{
			// 4.2 again: add appends rather than replacing.
			name: "request_header add appends to a header the client already sent",
			configure: func(tunnel *mvc.Tunnel) {
				tunnel.RequestHeaderAdd = []string{"X-Custom: added"}
			},
			request: getRequest("localhost:18080", "X-Custom: original"),
			want: requestWant{
				host:      "localhost:18080",
				allValues: map[string][]string{"X-Custom": {"original", "added"}},
			},
		},
		{
			// 4.2: removals match case-insensitively.
			name: "request_header remove drops the client's header",
			configure: func(tunnel *mvc.Tunnel) {
				tunnel.RequestHeaderRemove = []string{"x-secret"}
			},
			request: getRequest("localhost:18080", "X-Secret: drop-me", "X-Keep: keep-me"),
			want: requestWant{
				host:    "localhost:18080",
				headers: map[string]string{"X-Keep": "keep-me"},
				absent:  []string{"X-Secret"},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, seen := upstreamServer(t)
			upstreamAddr := srv.Listener.Addr().String()

			tunnel := httpTunnel("http://localhost:18080", upstreamAddr)
			if tc.configure != nil {
				tc.configure(&tunnel)
			}

			h := startRelay(t, upstreamAddr, tunnel)
			h.send(t, tc.request)

			// Drain the response: it is how this direction is known to have
			// completed, and a case that fails here failed for a reason worth
			// seeing on its own.
			if _, body := readResponse(t, bufio.NewReader(h.public)); string(body) != testUpstreamBody {
				t.Fatalf("response body = %q, want %q", body, testUpstreamBody)
			}

			wantHost := tc.want.host
			if tc.want.hostFromLocalAddr {
				// The "rewrite" case: what the Host is rewritten to depends on
				// the address the test dialed.
				wantHost = hostOf(t, upstreamAddr)
			}

			got := upstreamObserved(t, seen)
			if got.method != "GET" {
				t.Fatalf("upstream saw method %q, want GET", got.method)
			}
			if got.host != wantHost {
				t.Fatalf("upstream saw Host %q, want %q", got.host, wantHost)
			}
			if has := got.header.Values("X-Forwarded-Host"); !reflect.DeepEqual(has, forwardedHostValues(tc.want.forwardedHost)) {
				t.Fatalf("upstream saw X-Forwarded-Host %v, want %v", has, forwardedHostValues(tc.want.forwardedHost))
			}
			for name, value := range tc.want.headers {
				if has := got.header.Get(name); has != value {
					t.Fatalf("upstream saw %s %q, want %q", name, has, value)
				}
			}
			for name, values := range tc.want.allValues {
				if has := got.header.Values(name); !reflect.DeepEqual(has, values) {
					t.Fatalf("upstream saw %s %v, want %v", name, has, values)
				}
			}
			for _, name := range tc.want.absent {
				if has := got.header.Values(name); len(has) > 0 {
					t.Fatalf("upstream saw %s %v, want the header absent", name, has)
				}
			}

			// 4.3 asks for the X-Forwarded pair on every rewritten http head;
			// every case above goes through the rewriter, so every case can
			// assert it. (The "no rewriting at all" direction is the tcp test.)
			if xff := got.header.Get("X-Forwarded-For"); xff != testClientIP {
				t.Fatalf("upstream saw X-Forwarded-For %q, want %q", xff, testClientIP)
			}
			if xfp := got.header.Get("X-Forwarded-Proto"); xfp != "http" {
				t.Fatalf("upstream saw X-Forwarded-Proto %q, want %q", xfp, "http")
			}
		})
	}
}

// TestRelayRewritesResponseHeads covers SPEC 8-C-1's response half: the bytes
// the upstream sent come back to the public client with the response policy
// applied and everything else untouched, body included.
func TestRelayRewritesResponseHeads(t *testing.T) {
	srv, seen := upstreamServer(t)
	tunnel := httpTunnel("http://localhost:18080", srv.Listener.Addr().String())
	tunnel.ResponseHeaderAdd = []string{"X-Served-By: ngrok"}
	tunnel.ResponseHeaderRemove = []string{"X-Secret"}

	h := startRelay(t, srv.Listener.Addr().String(), tunnel)
	h.send(t, getRequest("localhost:18080"))

	rec := &recordingReader{r: h.public}
	resp, body := readResponse(t, bufio.NewReader(rec))

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("response status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("X-Served-By"); got != "ngrok" {
		t.Fatalf("response X-Served-By = %q, want %q", got, "ngrok")
	}
	if has := resp.Header.Values("X-Secret"); len(has) > 0 {
		t.Fatalf("response still carries X-Secret %v, want it removed", has)
	}
	if got := resp.Header.Get("X-Upstream"); got != "yes" {
		t.Fatalf("untouched response header changed: X-Upstream = %q", got)
	}
	if got := resp.Header.Get("Content-Type"); got != "text/plain" {
		t.Fatalf("untouched response header changed: Content-Type = %q", got)
	}
	if string(body) != testUpstreamBody {
		t.Fatalf("response body = %q, want %q (bodies must pass through byte for byte)", body, testUpstreamBody)
	}

	// The parsed view above cannot tell a rewritten head from a re-encoded one,
	// so check the raw bytes too: the added header is canonicalized, the
	// removed one is gone, and the head ends where it should.
	raw := rec.raw.String()
	if !strings.Contains(raw, "HTTP/1.1 200 OK\r\n") {
		t.Fatalf("raw response does not start with the upstream's status line:\n%q", raw)
	}
	if !strings.Contains(raw, "X-Served-By: ngrok\r\n") {
		t.Fatalf("raw response is missing the added header:\n%q", raw)
	}
	if strings.Contains(raw, "X-Secret") {
		t.Fatalf("raw response still contains the removed header:\n%q", raw)
	}

	// The request that produced it had no request-side policy, so it went out
	// with only the automatic X-Forwarded pair.
	if got := upstreamObserved(t, seen); got.host != "localhost:18080" {
		t.Fatalf("upstream saw Host %q, want it preserved as %q", got.host, "localhost:18080")
	}
}

// TestRelayKeepsRewritingPipelinedRequests is SPEC 8-C-1's keep-alive case: two
// requests on one connection, both rewritten. This is the test that catches a
// rewriter which handles only the first head on a connection -- pipelining is
// what makes the second head, and the body framing of the first response,
// matter.
func TestRelayKeepsRewritingPipelinedRequests(t *testing.T) {
	srv, seen := upstreamServer(t)
	tunnel := httpTunnel("http://localhost:18080", srv.Listener.Addr().String())
	tunnel.HostHeader = "rewrite"

	h := startRelay(t, srv.Listener.Addr().String(), tunnel)

	br := bufio.NewReader(h.public)

	// Both requests go out before either response is read: the client is not
	// waiting for a reply to send the next one.
	h.send(t, getRequest("localhost:18080", "X-Connection: first"))
	h.send(t, getRequest("localhost:18080", "X-Connection: second"))

	for i, want := range []string{"first", "second"} {
		resp, body := readResponse(t, br)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("response %d status = %d, want 200", i+1, resp.StatusCode)
		}
		if string(body) != testUpstreamBody {
			t.Fatalf("response %d body = %q, want %q", i+1, body, testUpstreamBody)
		}

		req := upstreamObserved(t, seen)
		if req.host != hostOf(t, srv.Listener.Addr().String()) {
			t.Fatalf("request %d: upstream saw Host %q, want it rewritten to %q", i+1, req.host, hostOf(t, srv.Listener.Addr().String()))
		}
		if got := req.header.Get("X-Connection"); got != want {
			t.Fatalf("request %d: upstream saw X-Connection %q, want %q", i+1, got, want)
		}
		if xff := req.header.Get("X-Forwarded-For"); xff != testClientIP {
			t.Fatalf("request %d: upstream saw X-Forwarded-For %q, want %q", i+1, xff, testClientIP)
		}
	}

	// Both directions moved bytes, and the counts are reported in the same
	// order the raw join reported them (in: public -> local).
	bytesIn, bytesOut := h.finish(t)
	if bytesIn <= 0 {
		t.Fatalf("bytesIn = %d, want the two requests' worth of bytes", bytesIn)
	}
	if bytesOut <= 0 {
		t.Fatalf("bytesOut = %d, want the two responses' worth of bytes", bytesOut)
	}
}

// TestRelayTCPPassthrough is the "zero behavior change for TCP tunnels" half of
// the spec: even with a header policy configured on the tunnel, a tcp tunnel
// gets the raw byte pipe, so the request head arrives exactly as the client sent
// it and the response head comes back unreformatted. The upstream is a bare
// listener here on purpose -- there is no HTTP parser on either side of a tcp
// tunnel.
func TestRelayTCPPassthrough(t *testing.T) {
	rawResponse := "HTTP/1.0 200 OK\r\nX-Secret: keep-me\r\nContent-Length: 2\r\n\r\nhi"

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	seen := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()

		head, err := readHead(bufio.NewReader(c))
		if err != nil {
			return
		}
		seen <- head

		c.Write([]byte(rawResponse))
	}()

	request := getRequest("localhost:19001", "X-Secret: drop-me", "X-Forwarded-For: 10.0.0.1")

	// A policy that would visibly rewrite both directions if it were applied.
	tunnel := mvc.Tunnel{
		PublicUrl:            "tcp://0.tcp.ngrok.io:12345",
		LocalAddr:            ln.Addr().String(),
		Protocol:             proto.NewTcp(),
		HostHeader:           "rewrite",
		RequestHeaderRemove:  []string{"X-Secret"},
		ResponseHeaderAdd:    []string{"X-Served-By: ngrok"},
		ResponseHeaderRemove: []string{"X-Secret"},
	}

	h := startRelay(t, ln.Addr().String(), tunnel)
	h.send(t, request)

	got := make([]byte, len(rawResponse))
	if _, err := io.ReadFull(h.public, got); err != nil {
		t.Fatalf("failed to read the upstream's response: %v", err)
	}
	if string(got) != rawResponse {
		t.Fatalf("response = %q, want the upstream's bytes untouched %q", got, rawResponse)
	}

	select {
	case upstreamHead := <-seen:
		if upstreamHead != request {
			t.Fatalf("upstream saw\n%q\nwant the client's bytes untouched\n%q", upstreamHead, request)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the upstream never saw the request")
	}

	// With no rewriter in the path the counts are exact: everything the client
	// wrote went up, everything the upstream wrote came back.
	bytesIn, bytesOut := h.finish(t)
	if bytesIn != int64(len(request)) {
		t.Fatalf("bytesIn = %d, want %d (the raw request)", bytesIn, len(request))
	}
	if bytesOut != int64(len(rawResponse)) {
		t.Fatalf("bytesOut = %d, want %d (the raw response)", bytesOut, len(rawResponse))
	}
}

// TestRelayByteCountsFollowTheDirection pins the direction mapping SPEC 5.3
// flags as the easy thing to get wrong. The two counts have to keep the meaning
// the raw join gave them -- in: public -> local, out: local -> public -- even
// though the join's arguments are now rewriter-wrapped connections, because
// each count ends up in a different metric and a swap is invisible in the data
// itself. The upstream here is deliberately a bare listener, so the test can
// count exactly what arrived on each leg: the request head it read, and the
// response bytes the client read off the pipe.
func TestRelayByteCountsFollowTheDirection(t *testing.T) {
	rawResponse := "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	received := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()

		head, err := readHead(bufio.NewReader(c))
		if err != nil {
			return
		}
		received <- head

		c.Write([]byte(rawResponse))
		// Stay up until the relay closes this connection: the response
		// direction only ends when a leg does.
		io.Copy(io.Discard, c)
	}()

	tunnel := httpTunnel("http://localhost:18080", ln.Addr().String())
	tunnel.HostHeader = "rewrite"

	h := startRelay(t, ln.Addr().String(), tunnel)
	h.send(t, getRequest("localhost:18080"))

	rec := &recordingReader{r: h.public}
	if _, body := readResponse(t, bufio.NewReader(rec)); string(body) != "hello" {
		t.Fatalf("response body = %q, want %q", body, "hello")
	}

	var upstreamHead string
	select {
	case upstreamHead = <-received:
	case <-time.After(10 * time.Second):
		t.Fatal("the upstream never saw the request")
	}

	bytesIn, bytesOut := h.finish(t)
	clientBytes := int64(rec.raw.Len())

	// Keep the assertions above from passing by coincidence: the two legs must
	// have moved visibly different numbers of bytes, or a swapped pair would
	// look healthy.
	if int64(len(upstreamHead)) == clientBytes {
		t.Fatalf("test is not discriminating: both legs moved %d bytes", clientBytes)
	}

	if bytesIn != int64(len(upstreamHead)) {
		t.Fatalf("bytesIn = %d, want %d (the bytes written towards the upstream)", bytesIn, len(upstreamHead))
	}
	if bytesOut != clientBytes {
		t.Fatalf("bytesOut = %d, want %d (the bytes read by the public client)", bytesOut, clientBytes)
	}
}

// readHead reads one message head (through its blank line) off a raw upstream
// connection.
func readHead(br *bufio.Reader) (string, error) {
	var b strings.Builder
	for {
		line, err := br.ReadString('\n')
		b.WriteString(line)
		if err != nil {
			return b.String(), err
		}
		if line == "\r\n" || line == "\n" {
			return b.String(), nil
		}
	}
}

// TestPolicyFromTunnel covers the SPEC 5.3 field mapping this package owns: the
// "rewrite" target loses its port, the public URL picks the
// X-Forwarded-Proto value, and the tunnel's header policy is carried across
// untouched.
func TestPolicyFromTunnel(t *testing.T) {
	headerPolicy := mvc.Tunnel{
		PublicUrl: "http://localhost:18080",
		LocalAddr: "127.0.0.1:11434",

		HostHeader:           "rewrite",
		RequestHeaderAdd:     []string{"X-Custom: value"},
		RequestHeaderRemove:  []string{"X-Secret"},
		ResponseHeaderAdd:    []string{"X-Served-By: ngrok"},
		ResponseHeaderRemove: []string{"Server"},
	}

	cases := []struct {
		name       string
		tunnel     mvc.Tunnel
		clientAddr string
		want       rewriter.Policy
	}{
		{
			name:       "http tunnel with a rewrite policy",
			tunnel:     headerPolicy,
			clientAddr: testClientAddr,
			want: rewriter.Policy{
				HostHeader:           "rewrite",
				RequestHeaderAdd:     []string{"X-Custom: value"},
				RequestHeaderRemove:  []string{"X-Secret"},
				ResponseHeaderAdd:    []string{"X-Served-By: ngrok"},
				ResponseHeaderRemove: []string{"Server"},
				UpstreamHost:         "127.0.0.1",
				ClientAddr:           testClientIP,
				XForwardedProto:      "http",
			},
		},
		{
			// An https tunnel's local leg is still plain HTTP, so the value
			// comes from the public URL, not from LocalAddr.
			name: "https public url sets X-Forwarded-Proto",
			tunnel: mvc.Tunnel{
				PublicUrl: "https://ollama.ngrok.io",
				LocalAddr: "localhost:11434",
			},
			clientAddr: testClientAddr,
			want: rewriter.Policy{
				UpstreamHost:    "localhost",
				ClientAddr:      testClientIP,
				XForwardedProto: "https",
			},
		},
		{
			// An IPv6 local leg: SplitHostPort returns the address bare, and
			// policyFromTunnel re-brackets it -- RFC 7230 requires brackets
			// around an IPv6 literal in a Host value.
			name: "ipv6 local address keeps its brackets",
			tunnel: mvc.Tunnel{
				PublicUrl: "http://localhost:18080",
				LocalAddr: "[::1]:11434",
			},
			clientAddr: testClientAddr,
			want: rewriter.Policy{
				UpstreamHost:    "[::1]",
				ClientAddr:      testClientIP,
				XForwardedProto: "http",
			},
		},
		{
			// LocalAddr without a port: the whole value is the host. Nothing
			// normalizes it away, and guessing (appending a default port) would
			// be worse than sending what the config said.
			name: "local address without a port is used as the host",
			tunnel: mvc.Tunnel{
				PublicUrl: "http://localhost:18080",
				LocalAddr: "localhost",
			},
			clientAddr: testClientAddr,
			want: rewriter.Policy{
				UpstreamHost:    "localhost",
				ClientAddr:      testClientIP,
				XForwardedProto: "http",
			},
		},
		{
			// SPEC 3.4: the compression setting rides in the policy, and a
			// policy that asks for it is never skippable -- the rewriter
			// decides per response whether there is anything to compress, but
			// it cannot make that decision for a tunnel whose flag it never
			// saw. The cases above pin the other direction: a tunnel without
			// Compress produces a policy with Compress false.
			name: "compression is carried into the policy",
			tunnel: mvc.Tunnel{
				PublicUrl: "http://localhost:18080",
				LocalAddr: "127.0.0.1:11434",
				Compress:  true,
			},
			clientAddr: testClientAddr,
			want: rewriter.Policy{
				Compress:        true,
				UpstreamHost:    "127.0.0.1",
				ClientAddr:      testClientIP,
				XForwardedProto: "http",
			},
		},
		{
			// No flags: still not a no-op, because 4.3's X-Forwarded injection
			// is unconditional on http tunnels. relay() depends on this.
			name: "no flags is still a working policy",
			tunnel: mvc.Tunnel{
				PublicUrl: "http://localhost:18080",
				LocalAddr: "localhost:11434",
			},
			clientAddr: testClientAddr,
			want: rewriter.Policy{
				UpstreamHost:    "localhost",
				ClientAddr:      testClientIP,
				XForwardedProto: "http",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := policyFromTunnel(tc.tunnel, tc.clientAddr)
			if got == nil {
				t.Fatal("policyFromTunnel returned nil")
			}
			if !reflect.DeepEqual(*got, tc.want) {
				t.Fatalf("policyFromTunnel = %+v, want %+v", *got, tc.want)
			}
			if err := got.Validate(); err != nil {
				t.Fatalf("the policy the client builds is not valid: %v", err)
			}
			if got.IsNoop() {
				t.Fatal("policy is a no-op; relay would skip the rewriter for a live http tunnel")
			}
		})
	}
}

// TestFlattenHeaderConfig covers the nil-config case: a tunnel with no
// request_header/response_header block must flatten to empty lists, not to a
// nil dereference in the middle of the proxy path.
func TestFlattenHeaderConfig(t *testing.T) {
	add, remove := flattenHeaderConfig(nil)
	if len(add) != 0 || len(remove) != 0 {
		t.Fatalf("flattenHeaderConfig(nil) = %v, %v; want empty lists", add, remove)
	}

	hc := &HeaderConfig{Add: []string{"X-Custom: value"}, Remove: []string{"X-Secret"}}
	add, remove = flattenHeaderConfig(hc)
	if !reflect.DeepEqual(add, hc.Add) || !reflect.DeepEqual(remove, hc.Remove) {
		t.Fatalf("flattenHeaderConfig = %v, %v; want %v, %v", add, remove, hc.Add, hc.Remove)
	}
}
