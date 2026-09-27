package rewriter

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"ngrok/conn"
)

// check compares byte-exactly -- which is the whole point of most of these tests
// -- and reports the first offset that differs, so a failure can be read at a
// glance instead of by squinting at two 4 KiB strings.
func check(t *testing.T, what, got, want string) {
	t.Helper()
	if got == want {
		return
	}
	t.Fatalf("%s mismatch at byte %d\n got: %q\nwant: %q", what, firstDiff(got, want), got, want)
}

func firstDiff(a, b string) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return i
		}
	}
	return n
}

// pair drives both directions of one connection over in-memory sources. The
// request side is drained first, which is the order a live connection sees: a
// response can only be framed once the request that asked for it was parsed.
func pair(t *testing.T, p *Policy, reqIn, respIn string) (reqOut, respOut string) {
	t.Helper()
	req, resp := NewPair(strings.NewReader(reqIn), strings.NewReader(respIn), p)
	return drain(t, req), drain(t, resp)
}

// drain reads a rewriter to EOF through io.Copy, i.e. with 32 KiB caller buffers
// and no cooperation from the rewriter about message boundaries.
func drain(t *testing.T, r io.Reader) string {
	t.Helper()
	var b strings.Builder
	if _, err := io.Copy(&b, r); err != nil {
		t.Fatalf("reading the rewriter failed: %v", err)
	}
	return b.String()
}

// readOnce performs exactly one Read. A step of the state machine produces one
// head or one buffer, so this is how the tests interleave the two directions the
// way a live connection does.
func readOnce(t *testing.T, r io.Reader) string {
	t.Helper()
	buf := make([]byte, 4096)
	n, err := r.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("read failed: %v", err)
	}
	return string(buf[:n])
}

// tunnelPolicy is what a live http tunnel builds: X-Forwarded injection is
// always on (4.3), so this policy is never a no-op.
func tunnelPolicy() *Policy {
	return &Policy{ClientAddr: "203.0.113.7", XForwardedProto: "http"}
}

// compressPolicy is a live tunnel policy with the gzip transform on.
func compressPolicy() *Policy {
	return &Policy{ClientAddr: "203.0.113.7", XForwardedProto: "http", Compress: true}
}

// gzipRequest is what a browser or "curl --compressed" sends: the gzip token
// among others, which is the case the token match has to pick out of the list.
func gzipRequest(target string) string {
	return "GET " + target + " HTTP/1.1\r\nHost: a.example\r\nAccept-Encoding: gzip, deflate, br\r\n\r\n"
}

// gunzipBody decompresses a body the rewriter produced. The transform's whole
// contract is that this reproduces the upstream body byte for byte.
func gunzipBody(t *testing.T, b []byte) []byte {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("the transformed body is not a gzip stream: %v", err)
	}
	defer zr.Close()
	out, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("decompressing the transformed body failed: %v", err)
	}
	return out
}

// chunkBody frames b as chunks the way an upstream would, ending with the
// terminal chunk's size line so that a caller can add a trailer section.
func chunkBody(b string) string {
	return chunkBodyN(b, 200)
}

// chunkBodyN is chunkBody with an explicit chunk size, because the size decides
// how much the transform can compress per flush (see feedGzip): the cases that
// care about the ratio use a realistic one.
func chunkBodyN(b string, chunk int) string {
	var out strings.Builder
	for len(b) > 0 {
		n := chunk
		if n > len(b) {
			n = len(b)
		}
		fmt.Fprintf(&out, "%x\r\n%s\r\n", n, b[:n])
		b = b[n:]
	}
	out.WriteString("0\r\n")
	return out.String()
}

// httpStream reads the rewriter's output the way a real HTTP client does.
// net/http is the arbiter of "well-formed": if it cannot read a message we
// produced, the framing is wrong however the bytes look to a test.
type httpStream struct {
	t  *testing.T
	br *bufio.Reader
}

func newHTTPStream(t *testing.T, r io.Reader) *httpStream {
	t.Helper()
	return &httpStream{t: t, br: bufio.NewReader(r)}
}

// next reads one response and its decoded body. Fully reading the body is what
// advances the stream to the end of the message, so two next() calls on one
// stream prove the messages are framed one after the other.
func (s *httpStream) next() (*http.Response, []byte) {
	s.t.Helper()
	// The request is only there for ReadResponse's framing rules (a HEAD request
	// would mean "no body"); every response in these tests is an answer to a GET.
	req, err := http.NewRequest("GET", "http://a.example/", nil)
	if err != nil {
		s.t.Fatalf("building the request for ReadResponse failed: %v", err)
	}
	resp, err := http.ReadResponse(s.br, req)
	if err != nil {
		s.t.Fatalf("http.ReadResponse rejected the rewritten response: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		s.t.Fatalf("reading the rewritten response body failed: %v", err)
	}
	resp.Body.Close()
	return resp, body
}

// done asserts the stream ended where the last message ended: a byte left over
// here is a message that ran past its own framing.
func (s *httpStream) done() {
	s.t.Helper()
	if b, err := s.br.ReadByte(); err != io.EOF {
		s.t.Fatalf("expected the response stream to end after the last message, got byte %q (err %v)", b, err)
	}
}

// Case 1: GET with the default host policy. Everything the client sent must
// survive byte for byte -- field order, casing, spacing -- and only the
// X-Forwarded pair is appended.
func TestCase1HostPreserve(t *testing.T) {
	p := tunnelPolicy()

	reqIn := "GET /path?q=1 HTTP/1.1\r\n" +
		"Host: myapp.ngrok.io\r\n" +
		"user-agent: curl/8.5.0\r\n" +
		"X-Custom: keep-me\r\n" +
		"\r\n"
	wantReq := "GET /path?q=1 HTTP/1.1\r\n" +
		"Host: myapp.ngrok.io\r\n" +
		"user-agent: curl/8.5.0\r\n" +
		"X-Custom: keep-me\r\n" +
		"X-Forwarded-For: 203.0.113.7\r\n" +
		"X-Forwarded-Proto: http\r\n" +
		"\r\n"

	// The policy says nothing about responses, so the response is byte-identical.
	respIn := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"

	gotReq, gotResp := pair(t, p, reqIn, respIn)
	check(t, "request", gotReq, wantReq)
	check(t, "response", gotResp, respIn)
}

// Case 2: host_header=rewrite. Host becomes the upstream host in place, and the
// original is preserved for the upstream in X-Forwarded-Host (4.1).
func TestCase2HostRewrite(t *testing.T) {
	p := &Policy{
		HostHeader:      "rewrite",
		UpstreamHost:    "127.0.0.1",
		ClientAddr:      "198.51.100.4",
		XForwardedProto: "http",
	}

	reqIn := "GET / HTTP/1.1\r\nHost: myapp.ngrok.io\r\nAccept: */*\r\n\r\n"
	wantReq := "GET / HTTP/1.1\r\n" +
		"Host: 127.0.0.1\r\n" +
		"Accept: */*\r\n" +
		"X-Forwarded-Host: myapp.ngrok.io\r\n" +
		"X-Forwarded-For: 198.51.100.4\r\n" +
		"X-Forwarded-Proto: http\r\n" +
		"\r\n"

	gotReq, _ := pair(t, p, reqIn, "")
	check(t, "request", gotReq, wantReq)
}

// Case 3: an explicit host_header value wins, and the field keeps the casing it
// arrived with -- only the value changes.
func TestCase3HostExplicit(t *testing.T) {
	p := &Policy{
		HostHeader:      "internal.local:8080",
		ClientAddr:      "198.51.100.4",
		XForwardedProto: "http",
	}

	reqIn := "POST /v1/chat HTTP/1.1\r\nHOST: ollama.local\r\nContent-Length: 2\r\n\r\nhi"
	wantReq := "POST /v1/chat HTTP/1.1\r\n" +
		"HOST: internal.local:8080\r\n" +
		"Content-Length: 2\r\n" +
		"X-Forwarded-Host: ollama.local\r\n" +
		"X-Forwarded-For: 198.51.100.4\r\n" +
		"X-Forwarded-Proto: http\r\n" +
		"\r\n" +
		"hi"

	gotReq, _ := pair(t, p, reqIn, "")
	check(t, "request", gotReq, wantReq)
}

// Case 4: adds append (a duplicate key gets a second header), a host add
// overrides instead of appending, removes drop every match case-insensitively,
// and added names are canonicalized. No X-Forwarded values here, so the only
// additions are the policy's own.
func TestCase4HeaderAddAndRemove(t *testing.T) {
	p := &Policy{
		RequestHeaderAdd:    []string{"X-Dup: one", "Host: forced.local", "x-lower: canon"},
		RequestHeaderRemove: []string{"X-Secret", "x-gone"},
	}

	reqIn := "GET / HTTP/1.1\r\n" +
		"Host: orig.local\r\n" +
		"X-Secret: s1\r\n" +
		"x-secret: s2\r\n" +
		"X-Gone: g1\r\n" +
		"X-Dup: existing\r\n" +
		"\r\n"
	wantReq := "GET / HTTP/1.1\r\n" +
		"Host: forced.local\r\n" + // overridden in place: exactly one Host field
		"X-Dup: existing\r\n" + // untouched field, original bytes
		"X-Forwarded-Host: orig.local\r\n" +
		"X-Dup: one\r\n" + // appended next to the existing one
		"X-Lower: canon\r\n" +
		"\r\n"

	gotReq, _ := pair(t, p, reqIn, "")
	check(t, "request", gotReq, wantReq)

	// \r\nHost:, not Host:, so the X-Forwarded-Host field does not count.
	if n := strings.Count(gotReq, "\r\nHost:"); n != 1 {
		t.Fatalf("a host add entry must override, not append: %d Host fields", n)
	}
	if strings.Contains(gotReq, "X-Secret") || strings.Contains(gotReq, "X-Gone") {
		t.Fatalf("a removed header survived: %q", gotReq)
	}
}

// Case 5: the client's own X-Forwarded-For must not survive -- a spoofed value
// next to the real one is worse than no value -- and X-Forwarded-Proto is set
// from the tunnel. Note the space in the incoming values: they are replaced, not
// merged.
func TestCase5XForwardedReplaced(t *testing.T) {
	p := &Policy{
		HostHeader:      "rewrite",
		UpstreamHost:    "127.0.0.1",
		ClientAddr:      "203.0.113.7",
		XForwardedProto: "http",
	}

	reqIn := "GET / HTTP/1.1\r\n" +
		"Host: a.example\r\n" +
		"X-Forwarded-For: 6.6.6.6\r\n" +
		"X-Forwarded-Proto: https\r\n" +
		"X-Forwarded-Host: spoofed.example\r\n" +
		"\r\n"
	wantReq := "GET / HTTP/1.1\r\n" +
		"Host: 127.0.0.1\r\n" +
		"X-Forwarded-Host: a.example\r\n" +
		"X-Forwarded-For: 203.0.113.7\r\n" +
		"X-Forwarded-Proto: http\r\n" +
		"\r\n"

	gotReq, _ := pair(t, p, reqIn, "")
	check(t, "request", gotReq, wantReq)

	for _, spoof := range []string{"6.6.6.6", "spoofed.example", "https"} {
		if strings.Contains(gotReq, spoof) {
			t.Fatalf("client-supplied %q survived the rewrite: %q", spoof, gotReq)
		}
	}
	if n := strings.Count(gotReq, "X-Forwarded-For:"); n != 1 {
		t.Fatalf("expected exactly one X-Forwarded-For, got %d", n)
	}
}

// Case 6: content-length bodies are copied, not parsed. The bodies here contain
// the head terminator, and they arrive in the same read as the head, so this is
// the head/body boundary -- the bytes the bufio.Reader over-read past the head
// must be spliced in, not dropped or reordered.
func TestCase6ContentLengthBodiesAreByteExact(t *testing.T) {
	p := &Policy{
		ClientAddr:        "203.0.113.7",
		XForwardedProto:   "http",
		ResponseHeaderAdd: []string{"X-Served-By: ngrok"},
	}

	body := "\x00\x01\x02\r\n\r\n\xff\xfe binary \r\n\r\n tail"
	reqIn := fmt.Sprintf("POST /upload HTTP/1.1\r\nHost: a.example\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
	wantReq := fmt.Sprintf("POST /upload HTTP/1.1\r\nHost: a.example\r\nContent-Length: %d\r\n"+
		"X-Forwarded-For: 203.0.113.7\r\nX-Forwarded-Proto: http\r\n\r\n%s", len(body), body)

	rbody := "\x89PNG\r\n\x1a\n\r\n\r\nmore"
	respIn := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(rbody), rbody)
	wantResp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\nX-Served-By: ngrok\r\n\r\n%s", len(rbody), rbody)

	gotReq, gotResp := pair(t, p, reqIn, respIn)
	check(t, "request", gotReq, wantReq)
	check(t, "response", gotResp, wantResp)
}

// Case 7: chunked framing is copied, never re-encoded. Sizes, the chunk
// extension, the CRLF after each chunk and the trailer section must come out
// byte-identical, and the message after the trailers must be parsed as a head
// again.
func TestCase7ChunkedFramingIsByteExact(t *testing.T) {
	p := &Policy{
		ClientAddr:        "203.0.113.7",
		XForwardedProto:   "http",
		ResponseHeaderAdd: []string{"X-Served-By: ngrok"},
	}

	chunks := "5;name=value\r\nhello\r\n" + // chunk extension must survive verbatim
		"6\r\n world\r\n" +
		"0\r\n" +
		"Trailer-One: t1\r\n" +
		"trailer-two: t2\r\n" +
		"\r\n"

	reqIn := "POST /chunked HTTP/1.1\r\nHost: a.example\r\nTransfer-Encoding: chunked\r\n\r\n" + chunks +
		"GET /next HTTP/1.1\r\nHost: a.example\r\n\r\n"
	wantReq := "POST /chunked HTTP/1.1\r\nHost: a.example\r\nTransfer-Encoding: chunked\r\n" +
		"X-Forwarded-For: 203.0.113.7\r\nX-Forwarded-Proto: http\r\n\r\n" + chunks +
		"GET /next HTTP/1.1\r\nHost: a.example\r\nX-Forwarded-For: 203.0.113.7\r\nX-Forwarded-Proto: http\r\n\r\n"

	respChunks := "4\r\nwiki\r\n5\r\npedia\r\n0\r\n\r\n"
	respIn := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + respChunks +
		"HTTP/1.1 204 No Content\r\n\r\n"
	wantResp := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nX-Served-By: ngrok\r\n\r\n" + respChunks +
		"HTTP/1.1 204 No Content\r\nX-Served-By: ngrok\r\n\r\n"

	gotReq, gotResp := pair(t, p, reqIn, respIn)
	check(t, "request", gotReq, wantReq)
	check(t, "response", gotResp, wantResp)

	if !strings.Contains(gotReq, "5;name=value\r\nhello\r\n") {
		t.Fatalf("chunk framing was re-encoded: %q", gotReq)
	}
}

// Case 8: two pipelined requests on one connection. Both heads are rewritten,
// and the second one is actually parsed -- the first request's head must not
// swallow it.
func TestCase8PipelinedRequests(t *testing.T) {
	p := &Policy{HostHeader: "rewrite", UpstreamHost: "127.0.0.1"}

	reqIn := "GET /one HTTP/1.1\r\nHost: a.example\r\n\r\n" +
		"GET /two HTTP/1.1\r\nHost: b.example\r\n\r\n"
	wantReq := "GET /one HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Forwarded-Host: a.example\r\n\r\n" +
		"GET /two HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Forwarded-Host: b.example\r\n\r\n"

	gotReq, _ := pair(t, p, reqIn, "")
	check(t, "request", gotReq, wantReq)

	if n := strings.Count(gotReq, "Host: 127.0.0.1\r\n"); n != 2 {
		t.Fatalf("expected both pipelined requests to be rewritten, got %d", n)
	}
}

// Case 9: Expect: 100-continue. The interim 1xx head is emitted verbatim (no
// response policy on interim heads), the parser stays in the head phase for the
// final response, which does get the policy, and the request body after the
// interim exchange is untouched.
func TestCase9ExpectContinueInterimResponse(t *testing.T) {
	p := &Policy{
		ClientAddr:        "203.0.113.7",
		XForwardedProto:   "http",
		ResponseHeaderAdd: []string{"X-Served-By: ngrok"},
	}

	reqIn := "POST /e HTTP/1.1\r\nHost: a.example\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\nhello"
	wantReq := "POST /e HTTP/1.1\r\nHost: a.example\r\nExpect: 100-continue\r\nContent-Length: 5\r\n" +
		"X-Forwarded-For: 203.0.113.7\r\nX-Forwarded-Proto: http\r\n\r\nhello"

	respIn := "HTTP/1.1 100 Continue\r\n\r\n" +
		"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
	wantResp := "HTTP/1.1 100 Continue\r\n\r\n" +
		"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Served-By: ngrok\r\n\r\nok"

	gotReq, gotResp := pair(t, p, reqIn, respIn)
	check(t, "request", gotReq, wantReq)
	check(t, "response", gotResp, wantResp)
}

// Case 10: a HEAD response has headers only, whatever Content-Length it
// promises. The two directions are driven one read at a time, in the order a
// live connection sees them, so the response side really does have to learn the
// method from the request side -- and a mis-framed HEAD response would swallow
// the next response's head as its body.
func TestCase10HeadResponseHasNoBody(t *testing.T) {
	p := &Policy{
		ClientAddr:        "203.0.113.7",
		XForwardedProto:   "http",
		ResponseHeaderAdd: []string{"X-Served-By: ngrok"},
	}

	reqIn := "HEAD /one HTTP/1.1\r\nHost: a.example\r\n\r\n" +
		"GET /two HTTP/1.1\r\nHost: a.example\r\n\r\n"
	respIn := "HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\n" + // promises 1234 bytes, sends none
		"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"

	req, resp := NewPair(strings.NewReader(reqIn), strings.NewReader(respIn), p)

	check(t, "HEAD request", readOnce(t, req),
		"HEAD /one HTTP/1.1\r\nHost: a.example\r\nX-Forwarded-For: 203.0.113.7\r\nX-Forwarded-Proto: http\r\n\r\n")
	check(t, "HEAD response", readOnce(t, resp),
		"HTTP/1.1 200 OK\r\nContent-Length: 1234\r\nX-Served-By: ngrok\r\n\r\n")
	check(t, "second request", readOnce(t, req),
		"GET /two HTTP/1.1\r\nHost: a.example\r\nX-Forwarded-For: 203.0.113.7\r\nX-Forwarded-Proto: http\r\n\r\n")
	check(t, "second response", drain(t, resp),
		"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Served-By: ngrok\r\n\r\nok")
}

// Case 11: bodyless statuses. The 304 here carries a Content-Length that it must
// not honour -- a bodyless response that reads its Content-Length as a body
// would eat the whole next response.
func TestCase11NoBodyStatuses(t *testing.T) {
	p := &Policy{ResponseHeaderAdd: []string{"X-Served-By: ngrok"}}

	respIn := "HTTP/1.1 204 No Content\r\n\r\n" +
		"HTTP/1.1 304 Not Modified\r\nCache-Control: no-store\r\nContent-Length: 99\r\n\r\n" +
		"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"
	wantResp := "HTTP/1.1 204 No Content\r\nX-Served-By: ngrok\r\n\r\n" +
		"HTTP/1.1 304 Not Modified\r\nCache-Control: no-store\r\nContent-Length: 99\r\nX-Served-By: ngrok\r\n\r\n" +
		"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX-Served-By: ngrok\r\n\r\nhi"

	_, gotResp := pair(t, p, "", respIn)
	check(t, "response", gotResp, wantResp)
}

// Case 12: 101 Switching Protocols. Both directions go raw right after their
// heads, so the frames that follow survive byte for byte even though they
// contain CRLFCRLF.
func TestCase12Upgrade101BothDirectionsRaw(t *testing.T) {
	p := &Policy{
		ClientAddr:        "203.0.113.7",
		XForwardedProto:   "http",
		ResponseHeaderAdd: []string{"X-Served-By: ngrok"},
	}

	// Websocket-shaped frames: unmasked/masked payloads and a control frame whose
	// payload is itself a CRLFCRLF.
	frames := "\x81\x85\x00\x00\x00\x00hello" +
		"\x88\x82\x00\x00\x00\x00\r\n\r\n" +
		"raw\r\n\r\nbytes"

	reqIn := "GET /ws HTTP/1.1\r\nHost: a.example\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n" + frames
	wantReq := "GET /ws HTTP/1.1\r\nHost: a.example\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n" +
		"X-Forwarded-For: 203.0.113.7\r\nX-Forwarded-Proto: http\r\n\r\n" + frames

	respIn := "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n" + frames
	// The 101 head is interim: no response policy, verbatim bytes.
	wantResp := "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n" + frames

	gotReq, gotResp := pair(t, p, reqIn, respIn)
	check(t, "request", gotReq, wantReq)
	check(t, "response", gotResp, wantResp)

	// The other half of the upgrade path: the request side checks the shared flag
	// before parsing its next head, so a 101 seen by the response side stops the
	// request side from ever looking at the bytes again.
	t.Run("request side observes a 101 it did not ask for", func(t *testing.T) {
		nextReq := "GET /second HTTP/1.1\r\nHost: a.example\r\n\r\nbinary\r\n\r\nafter"
		req, resp := NewPair(strings.NewReader(nextReq),
			strings.NewReader("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n"), p)
		if got := readOnce(t, resp); !strings.HasPrefix(got, "HTTP/1.1 101") {
			t.Fatalf("expected the 101 head, got %q", got)
		}
		got := drain(t, req)
		check(t, "request", got, nextReq)
		if strings.Contains(got, "X-Forwarded-For") {
			t.Fatalf("a head was rewritten after the connection was upgraded: %q", got)
		}
	})
}

// Case 13: a request that asks for an upgrade goes raw as soon as its head is
// out, even before any 101 arrives. The frames here spell out an HTTP head, so a
// rewriter that kept parsing would rewrite it.
func TestCase13UpgradeRequestGoesRawAfterHead(t *testing.T) {
	p := tunnelPolicy()

	frames := "\x81\x2a" + "GET /fake HTTP/1.1\r\nHost: evil.example\r\n\r\n" + "\xff\xfe"
	reqIn := "GET /ws HTTP/1.1\r\nHost: a.example\r\nConnection: upgrade\r\nUpgrade: websocket\r\n\r\n" + frames
	wantReq := "GET /ws HTTP/1.1\r\nHost: a.example\r\nConnection: upgrade\r\nUpgrade: websocket\r\n" +
		"X-Forwarded-For: 203.0.113.7\r\nX-Forwarded-Proto: http\r\n\r\n" + frames

	gotReq, _ := pair(t, p, reqIn, "")
	check(t, "request", gotReq, wantReq)

	if n := strings.Count(gotReq, "X-Forwarded-For"); n != 1 {
		t.Fatalf("the frames were parsed as a second head: %d X-Forwarded-For fields", n)
	}
	if !strings.Contains(gotReq, "Host: evil.example") {
		t.Fatalf("the frames were rewritten: %q", gotReq)
	}
}

// Case 14: a head past the 64 KiB cap stops the parsing. Fail-open has to emit
// every byte that was already read -- including the over-read prefix and
// whatever followed it -- so the output is the input, byte for byte, and the rest
// of the connection stays raw.
func TestCase14OversizedHeadFailsOpen(t *testing.T) {
	p := tunnelPolicy()

	t.Run("one line over 64 KiB", func(t *testing.T) {
		in := "GET / HTTP/1.1\r\nX-Big: " + strings.Repeat("a", 70*1024) + "\r\n\r\n" + "tail bytes"
		gotReq, _ := pair(t, p, in, "")
		check(t, "request", gotReq, in)
		if strings.Contains(gotReq, "X-Forwarded-For") {
			t.Fatalf("an oversized head was rewritten instead of passed through")
		}
	})

	t.Run("many lines over 64 KiB", func(t *testing.T) {
		var b strings.Builder
		b.WriteString("GET / HTTP/1.1\r\n")
		for i := 0; i < 300; i++ {
			fmt.Fprintf(&b, "X-Filler-%d: %s\r\n", i, strings.Repeat("b", 400))
		}
		b.WriteString("\r\n")
		// A perfectly good request after the oversized one proves fail-open is
		// sticky: nothing later on the connection is parsed either.
		b.WriteString("GET /after HTTP/1.1\r\nHost: a.example\r\n\r\n")
		in := b.String()

		gotReq, _ := pair(t, p, in, "")
		check(t, "request", gotReq, in)
		if strings.Contains(gotReq, "X-Forwarded-For") {
			t.Fatalf("the connection was rewritten after failing open")
		}
	})
}

// Case 15: streams that are not HTTP at all. Each one must come out exactly as
// it went in -- the old code carried these connections, and this package must
// not be the reason a tunnel stops working.
func TestCase15NonHTTPStreamsPassThrough(t *testing.T) {
	p := tunnelPolicy()

	cases := []struct {
		name string
		in   string
	}{
		{"prose", "this is not http at all\r\n\r\nand here is more"},
		{"ssh banner", "SSH-2.0-OpenSSH_9.4\r\n\r\n"},
		{"binary with no terminator", "\x00\x01\x02\xffno terminator in here"},
		{"two-token request line", "GET /only-two-parts\r\nHost: a.example\r\n\r\n"},
		{"header line without a colon", "GET / HTTP/1.1\r\nnot a header line\r\n\r\n"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotReq, _ := pair(t, p, tc.in, "")
			check(t, "request", gotReq, tc.in)
		})
	}
}

// Case 16: IsNoop. It is what the client uses to skip wrapping the connection
// entirely, so it has to be exactly as narrow as the rewriter's effect: the
// automatic X-Forwarded injection (4.3) means a tunnel policy is never a no-op,
// even with no flags set.
func TestCase16IsNoop(t *testing.T) {
	cases := []struct {
		name string
		p    *Policy
		noop bool
	}{
		{"empty policy", &Policy{}, true},
		{"preserve", &Policy{HostHeader: "preserve"}, true},
		{"preserve in any case", &Policy{HostHeader: "PREserve"}, true},
		{"host rewrite", &Policy{HostHeader: "rewrite", UpstreamHost: "127.0.0.1"}, false},
		{"explicit host", &Policy{HostHeader: "internal.local"}, false},
		{"request add", &Policy{RequestHeaderAdd: []string{"X-A: b"}}, false},
		{"request remove", &Policy{RequestHeaderRemove: []string{"X-Secret"}}, false},
		{"response add", &Policy{ResponseHeaderAdd: []string{"X-A: b"}}, false},
		{"response remove", &Policy{ResponseHeaderRemove: []string{"Server"}}, false},
		{"forwarded for only", &Policy{ClientAddr: "203.0.113.7"}, false},
		{"forwarded proto only", &Policy{XForwardedProto: "http"}, false},
		{"tunnel policy", tunnelPolicy(), false},
		// The gzip transform fires per response, but a policy that asks for it can
		// never be skipped outright.
		{"compress", &Policy{Compress: true}, false},
		{"compress with preserve", &Policy{HostHeader: "preserve", Compress: true}, false},
	}

	for _, tc := range cases {
		if got := tc.p.IsNoop(); got != tc.noop {
			t.Fatalf("%s: IsNoop() = %v, want %v", tc.name, got, tc.noop)
		}
	}

	// Unit level, a no-op policy still runs both state machines, so it has to be
	// transparent: same bytes, body and all.
	in := "GET / HTTP/1.1\r\nHost: a.example\r\nContent-Length: 4\r\n\r\nbody"
	gotReq, _ := pair(t, &Policy{}, in, "")
	check(t, "no-op passthrough", gotReq, in)

	// And the path case 16 says has to keep working: a policy with nothing but
	// the X-Forwarded pair still passes the head through untouched otherwise.
	gotReq, _ = pair(t, tunnelPolicy(), in, "")
	check(t, "forwarded passthrough", gotReq,
		"GET / HTTP/1.1\r\nHost: a.example\r\nContent-Length: 4\r\n"+
			"X-Forwarded-For: 203.0.113.7\r\nX-Forwarded-Proto: http\r\n\r\nbody")
}

// TestValidate: every rejection has to name the offending entry, because the
// config layer reports these to a human at load time.
func TestValidate(t *testing.T) {
	valid := []*Policy{
		{},
		{HostHeader: "preserve"},
		{HostHeader: "rewrite", UpstreamHost: "127.0.0.1", ClientAddr: "203.0.113.7:51234", XForwardedProto: "https"},
		{HostHeader: "internal.local:8080"},
		{RequestHeaderAdd: []string{"X-A: b", "X-Url: http://localhost:8080/x"}, RequestHeaderRemove: []string{"X-Secret"}},
		{ResponseHeaderAdd: []string{"X-Served-By: ngrok"}, ResponseHeaderRemove: []string{"Server"}},
		// Compress adds no rule: it is a bool, and the fields the transform writes
		// are constants this package builds, not caller input.
		{Compress: true},
	}
	for _, p := range valid {
		if err := p.Validate(); err != nil {
			t.Fatalf("policy %+v should validate, got %v", p, err)
		}
	}

	invalid := []struct {
		name string
		p    *Policy
		want string
	}{
		{"crlf in add value", &Policy{RequestHeaderAdd: []string{"X-A: b\r\nX-Injected: 1"}}, "X-A: b"},
		{"add without a colon", &Policy{RequestHeaderAdd: []string{"X-NoColon"}}, "X-NoColon"},
		{"empty add name", &Policy{RequestHeaderAdd: []string{": value"}}, ": value"},
		{"non-token add name", &Policy{ResponseHeaderAdd: []string{"X Bad: v"}}, "X Bad"},
		{"user-agent add", &Policy{RequestHeaderAdd: []string{"user-agent: evil"}}, "user-agent"},
		{"user-agent remove", &Policy{ResponseHeaderRemove: []string{"User-Agent"}}, "User-Agent"},
		{"bad host_header", &Policy{HostHeader: "bad host/name"}, "host_header"},
		{"crlf in client addr", &Policy{ClientAddr: "1.2.3.4\r\nX-Injected: 1"}, "client_addr"},
		{"crlf in proto", &Policy{XForwardedProto: "http\nX-Injected: 1"}, "x_forwarded_proto"},
	}
	for _, tc := range invalid {
		err := tc.p.Validate()
		if err == nil {
			t.Fatalf("%s: expected an error", tc.name)
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: error %q does not name %q", tc.name, err, tc.want)
		}
	}
}

// fakeConn is the minimum conn.Conn the adapter needs. The embedded interface is
// deliberately nil: any delegation the rewriter is not supposed to do panics
// here instead of passing silently.
type fakeConn struct {
	conn.Conn
	src    *strings.Reader
	dst    bytes.Buffer
	id     string
	warned []string
}

func (c *fakeConn) Read(p []byte) (int, error)  { return c.src.Read(p) }
func (c *fakeConn) Write(p []byte) (int, error) { return c.dst.Write(p) }
func (c *fakeConn) Close() error                { return nil }
func (c *fakeConn) Id() string                  { return c.id }
func (c *fakeConn) Warn(format string, args ...interface{}) error {
	c.warned = append(c.warned, fmt.Sprintf(format, args...))
	return nil
}

// TestNewConnPairDelegates: the adapter rewrites Reads and leaves every other
// method to the connection it wraps, which is what lets conn.Join keep using it
// as a socket.
func TestNewConnPairDelegates(t *testing.T) {
	p := tunnelPolicy()

	public := &fakeConn{src: strings.NewReader("GET / HTTP/1.1\r\nHost: a.example\r\n\r\n"), id: "http:public"}
	upstream := &fakeConn{src: strings.NewReader("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"), id: "http:upstream"}

	toUpstream, fromUpstream := NewConnPair(public, upstream, p)

	check(t, "request", drain(t, toUpstream),
		"GET / HTTP/1.1\r\nHost: a.example\r\nX-Forwarded-For: 203.0.113.7\r\nX-Forwarded-Proto: http\r\n\r\n")
	check(t, "response", drain(t, fromUpstream), "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")

	if _, err := toUpstream.Write([]byte("resp")); err != nil {
		t.Fatalf("write through toUpstream failed: %v", err)
	}
	if _, err := fromUpstream.Write([]byte("req")); err != nil {
		t.Fatalf("write through fromUpstream failed: %v", err)
	}
	if got := public.dst.String(); got != "resp" {
		t.Fatalf("toUpstream wrote %q to its own connection, want %q", got, "resp")
	}
	if got := upstream.dst.String(); got != "req" {
		t.Fatalf("fromUpstream wrote %q to its own connection, want %q", got, "req")
	}
	if toUpstream.Id() != "http:public" || fromUpstream.Id() != "http:upstream" {
		t.Fatalf("ids did not delegate: %q, %q", toUpstream.Id(), fromUpstream.Id())
	}
	if err := toUpstream.Close(); err != nil {
		t.Fatalf("close did not delegate: %v", err)
	}
}

// TestFailOpenLogsOneWarning: review gate 4 wants fail-open to be visible, and
// exactly once -- a head that overflows is one event, not one per Read call.
func TestFailOpenLogsOneWarning(t *testing.T) {
	public := &fakeConn{
		src: strings.NewReader("GET / HTTP/1.1\r\nX-Big: " + strings.Repeat("a", 70*1024) + "\r\n\r\n"),
		id:  "http:gg",
	}
	upstream := &fakeConn{src: strings.NewReader(""), id: "http:up"}

	toUpstream, _ := NewConnPair(public, upstream, tunnelPolicy())
	drain(t, toUpstream)

	if len(public.warned) != 1 {
		t.Fatalf("expected exactly one fail-open warning, got %d: %v", len(public.warned), public.warned)
	}
	if !strings.Contains(public.warned[0], "64 KiB") {
		t.Fatalf("the warning does not say what happened: %q", public.warned[0])
	}
}

// TestResponseCloseDelimitedGoesRaw: a response with neither Content-Length nor
// chunked framing ends at EOF, so the bytes after its head are body -- even when
// they look exactly like another response.
func TestResponseCloseDelimitedGoesRaw(t *testing.T) {
	p := &Policy{ResponseHeaderAdd: []string{"X-Served-By: ngrok"}}

	respIn := "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n" +
		"HTTP/1.1 200 OK\r\n\r\nnot a second response"
	wantResp := "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-Served-By: ngrok\r\n\r\n" +
		"HTTP/1.1 200 OK\r\n\r\nnot a second response"

	_, gotResp := pair(t, p, "", respIn)
	check(t, "response", gotResp, wantResp)
	if n := strings.Count(gotResp, "X-Served-By"); n != 1 {
		t.Fatalf("a close-delimited body was parsed for heads: %d additions", n)
	}
}

// TestMalformedChunkSizeFailsOpen: the head is rewritten before the body proves
// itself, and then the rest of the message is copied verbatim.
func TestMalformedChunkSizeFailsOpen(t *testing.T) {
	in := "POST / HTTP/1.1\r\nHost: a.example\r\nTransfer-Encoding: chunked\r\n\r\n" +
		"zz\r\nnot hex\r\n0\r\n\r\n"
	want := "POST / HTTP/1.1\r\nHost: a.example\r\nTransfer-Encoding: chunked\r\n" +
		"X-Forwarded-For: 203.0.113.7\r\nX-Forwarded-Proto: http\r\n\r\n" +
		"zz\r\nnot hex\r\n0\r\n\r\n"

	gotReq, _ := pair(t, tunnelPolicy(), in, "")
	check(t, "request", gotReq, want)
}

// TestLeadingBlankLineIsTolerated: RFC 7230 3.5 wants at least one empty line
// before a request line to be ignored. Copying it through costs nothing and
// keeps the connection rewritten instead of dropping it into fail-open.
func TestLeadingBlankLineIsTolerated(t *testing.T) {
	in := "\r\nGET / HTTP/1.1\r\nHost: a.example\r\n\r\n"
	want := "\r\nGET / HTTP/1.1\r\nHost: a.example\r\n" +
		"X-Forwarded-For: 203.0.113.7\r\nX-Forwarded-Proto: http\r\n\r\n"

	gotReq, _ := pair(t, tunnelPolicy(), in, "")
	check(t, "request", gotReq, want)
}

// TestChunkedWinsOverContentLength: when both framings are present the chunked
// one is authoritative (RFC 7230 3.3.3). Reading the Content-Length instead
// would desync the connection, so it is worth pinning down.
func TestChunkedWinsOverContentLength(t *testing.T) {
	in := "POST / HTTP/1.1\r\nHost: a.example\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n" +
		"5\r\nhello\r\n0\r\n\r\n" +
		"GET /after HTTP/1.1\r\nHost: a.example\r\n\r\n"
	want := "POST / HTTP/1.1\r\nHost: a.example\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n" +
		"X-Forwarded-For: 203.0.113.7\r\nX-Forwarded-Proto: http\r\n\r\n" +
		"5\r\nhello\r\n0\r\n\r\n" +
		"GET /after HTTP/1.1\r\nHost: a.example\r\nX-Forwarded-For: 203.0.113.7\r\nX-Forwarded-Proto: http\r\n\r\n"

	gotReq, _ := pair(t, tunnelPolicy(), in, "")
	check(t, "request", gotReq, want)
}

// TestHostRewriteAddsMissingHost: an HTTP/1.0 request may carry no Host at all,
// and "Host := the value" is the whole point of the setting, so one is added --
// once, since there is no existing field to write it into.
func TestHostRewriteAddsMissingHost(t *testing.T) {
	p := &Policy{HostHeader: "rewrite", UpstreamHost: "127.0.0.1", ClientAddr: "203.0.113.7", XForwardedProto: "http"}

	in := "GET / HTTP/1.0\r\n\r\n"
	want := "GET / HTTP/1.0\r\nHost: 127.0.0.1\r\nX-Forwarded-For: 203.0.113.7\r\nX-Forwarded-Proto: http\r\n\r\n"

	gotReq, _ := pair(t, p, in, "")
	check(t, "request", gotReq, want)
}

// Case 17: the gzip transform's core promise. Whatever framed the upstream body
// -- a Content-Length, chunks, chunks with a trailer section, or nothing but the
// connection close -- the client gets one chunk-framed gzip message, and
// decompressing it reproduces the upstream body byte for byte. net/http does the
// parsing, so "the output is well-formed" means here exactly what it means to a
// real client.
func TestCase17GzipRoundTrip(t *testing.T) {
	body := strings.Repeat("{\"token\":\"hello gzip world\"}\n", 64)
	if len(body) < 1024 {
		t.Fatalf("the test body is too small to be interesting: %d bytes", len(body))
	}

	cases := []struct {
		name   string
		respIn string
		// keep are the head fragments that must survive byte for byte: only the
		// fields the transform has to change may move.
		keep []string
	}{
		{
			name: "content-length framed",
			respIn: fmt.Sprintf("HTTP/1.1 200 OK\r\nServer: ollama\r\nContent-Type: application/json\r\n"+
				"ETag: \"v1\"\r\nContent-Length: %d\r\n\r\n%s", len(body), body),
			keep: []string{"Server: ollama", "Content-Type: application/json"},
		},
		{
			name: "chunked framed",
			respIn: "HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\n" +
				"Transfer-Encoding: chunked\r\n\r\n" + chunkBody(body) + "\r\n",
			keep: []string{"Transfer-Encoding: chunked", "Content-Type: application/json; charset=utf-8"},
		},
		{
			name: "chunked framed with a trailer section",
			respIn: "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n" +
				chunkBody(body) + "Content-MD5: 6f5902ac237024bdd0c176cb93063dc4\r\n\r\n",
			keep: []string{"Transfer-Encoding: chunked"},
		},
		{
			name:   "close delimited",
			respIn: "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n" + body,
			keep:   []string{"Connection: close"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotReq, gotResp := pair(t, compressPolicy(), gzipRequest("/v1/chat"), tc.respIn)
			if !strings.Contains(gotReq, "Accept-Encoding: gzip, deflate, br") {
				t.Fatalf("the request side changed Accept-Encoding: %q", gotReq)
			}

			in := newHTTPStream(t, strings.NewReader(gotResp))
			resp, encoded := in.next()
			in.done()

			check(t, "Content-Encoding", resp.Header.Get("Content-Encoding"), "gzip")
			check(t, "Vary", resp.Header.Get("Vary"), "Accept-Encoding")
			if got := resp.Header.Get("Content-Length"); got != "" {
				t.Fatalf("Content-Length survived into a compressed response: %q", got)
			}
			if got := resp.Header.Get("ETag"); got != "" {
				t.Fatalf("an ETag for the identity body survived into a compressed response: %q", got)
			}
			if got := strings.Join(resp.TransferEncoding, ","); got != "chunked" {
				t.Fatalf("the compressed response does not declare chunked framing: %q", got)
			}
			check(t, "decompressed body", string(gunzipBody(t, encoded)), body)

			for _, fragment := range tc.keep {
				if !strings.Contains(gotResp, fragment) {
					t.Fatalf("a field the transform should not touch was rewritten: %q is missing from %q", fragment, gotResp)
				}
			}
			if strings.Contains(gotResp, "Content-MD5") {
				t.Fatalf("a trailer describing the identity body was forwarded: %q", gotResp)
			}
			if len(encoded) >= len(body) {
				t.Fatalf("the compressed body did not get smaller: %d >= %d bytes", len(encoded), len(body))
			}
		})
	}

	// Correctness does not depend on the chunk size, only the ratio does: a stream
	// of very small chunks pays a sync flush each (see feedGzip), so this case
	// asserts the round trip and nothing about size. An upstream that frames its
	// body in 7-byte chunks gets a valid gzip stream that happens not to be
	// smaller -- not a broken one.
	t.Run("tiny chunks still round-trip", func(t *testing.T) {
		respIn := "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n" +
			chunkBodyN(body, 7) + "\r\n"
		_, gotResp := pair(t, compressPolicy(), gzipRequest("/x"), respIn)
		in := newHTTPStream(t, strings.NewReader(gotResp))
		resp, encoded := in.next()
		in.done()
		check(t, "Content-Encoding", resp.Header.Get("Content-Encoding"), "gzip")
		check(t, "decompressed body", string(gunzipBody(t, encoded)), body)
	})
}

// Case 18: the skip matrix. Each row is one reason not to compress, and the
// response has to come out byte for byte as the upstream sent it: a compression
// feature that perturbs a response it decided not to touch is worse than no
// feature at all.
func TestCase18GzipSkipMatrix(t *testing.T) {
	big := strings.Repeat("compressible text, ", 64) // well over the 128-byte floor

	jsonResp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", len(big), big)

	cases := []struct {
		name string
		p    *Policy
		req  string
		resp string
	}{
		{
			name: "compress off in the policy",
			p:    tunnelPolicy(),
			req:  gzipRequest("/x"),
			resp: jsonResp,
		},
		{
			name: "client sent no Accept-Encoding",
			p:    compressPolicy(),
			req:  "GET /x HTTP/1.1\r\nHost: a.example\r\n\r\n",
			resp: jsonResp,
		},
		{
			name: "Accept-Encoding without gzip",
			p:    compressPolicy(),
			req:  "GET /x HTTP/1.1\r\nHost: a.example\r\nAccept-Encoding: identity\r\n\r\n",
			resp: jsonResp,
		},
		{
			name: "Accept-Encoding refuses gzip with q=0",
			p:    compressPolicy(),
			req:  "GET /x HTTP/1.1\r\nHost: a.example\r\nAccept-Encoding: gzip;q=0\r\n\r\n",
			resp: jsonResp,
		},
		{
			name: "Accept-Encoding wildcard",
			p:    compressPolicy(),
			req:  "GET /x HTTP/1.1\r\nHost: a.example\r\nAccept-Encoding: *\r\n\r\n",
			resp: jsonResp,
		},
		{
			name: "Range request",
			p:    compressPolicy(),
			req:  "GET /x HTTP/1.1\r\nHost: a.example\r\nAccept-Encoding: gzip\r\nRange: bytes=0-99\r\n\r\n",
			resp: jsonResp,
		},
		{
			name: "HEAD request",
			p:    compressPolicy(),
			req:  "HEAD /x HTTP/1.1\r\nHost: a.example\r\nAccept-Encoding: gzip\r\n\r\n",
			resp: "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 4096\r\n\r\n",
		},
		{
			name: "204",
			p:    compressPolicy(),
			req:  gzipRequest("/x"),
			resp: "HTTP/1.1 204 No Content\r\n\r\n",
		},
		{
			name: "304",
			p:    compressPolicy(),
			req:  gzipRequest("/x"),
			resp: "HTTP/1.1 304 Not Modified\r\nETag: \"v1\"\r\nContent-Type: text/html\r\n\r\n",
		},
		{
			name: "101",
			p:    compressPolicy(),
			req:  gzipRequest("/x"),
			resp: "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n",
		},
		{
			name: "already encoded",
			p:    compressPolicy(),
			req:  gzipRequest("/x"),
			resp: "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Encoding: br\r\nContent-Length: 12\r\n\r\nbr-encoded!!",
		},
		{
			name: "type that does not compress",
			p:    compressPolicy(),
			req:  gzipRequest("/x"),
			resp: fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: %d\r\n\r\n%s", len(big), big),
		},
		{
			name: "no type at all",
			p:    compressPolicy(),
			req:  gzipRequest("/x"),
			resp: fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(big), big),
		},
		{
			name: "declared body under the floor",
			p:    compressPolicy(),
			req:  gzipRequest("/x"),
			resp: "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 12\r\n\r\n{\"a\": \"tiny\"}",
		},
		{
			name: "HTTP/1.0 client",
			p:    compressPolicy(),
			req:  "GET /x HTTP/1.0\r\nHost: a.example\r\nAccept-Encoding: gzip\r\n\r\n",
			resp: jsonResp,
		},
		{
			// A 1.0 head is read as close-delimited whatever its framing fields say
			// (net/http ignores a transfer coding on a 1.0 response), so chunked
			// output under it would be read as body bytes.
			name: "upstream answered in HTTP/1.0",
			p:    compressPolicy(),
			req:  gzipRequest("/x"),
			resp: "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nContent-Length: " + strconv.Itoa(len(big)) + "\r\n\r\n" + big,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, gotResp := pair(t, tc.p, tc.req, tc.resp)
			check(t, "response", gotResp, tc.resp)
			if strings.Contains(strings.ToLower(gotResp), "content-encoding: gzip") {
				t.Fatalf("a skipped response was gzip-encoded: %q", gotResp)
			}
		})
	}

	// The matrix is a skip list, not a blanket refusal: a 404 with a compressible
	// body is a perfectly good thing to compress.
	for _, tc := range []struct{ name, resp string }{
		{"404 text/html", fmt.Sprintf("HTTP/1.1 404 Not Found\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: %d\r\n\r\n%s", len(big), big)},
		{"200 TEXT/PLAIN", fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: TEXT/PLAIN\r\nContent-Length: %d\r\n\r\n%s", len(big), big)},
	} {
		t.Run("positive control: "+tc.name, func(t *testing.T) {
			_, gotResp := pair(t, compressPolicy(), gzipRequest("/x"), tc.resp)
			in := newHTTPStream(t, strings.NewReader(gotResp))
			resp, encoded := in.next()
			in.done()
			check(t, "Content-Encoding", resp.Header.Get("Content-Encoding"), "gzip")
			check(t, "body", string(gunzipBody(t, encoded)), big)
		})
	}

	// The safety invariant, stated the way a regression would look: for a client
	// that never asked for gzip, every response shape comes out byte-identical --
	// including the ones that would otherwise be compressed.
	t.Run("safety invariant: no Accept-Encoding, no gzip", func(t *testing.T) {
		shapes := []struct{ name, resp string }{
			{"content-length json", jsonResp},
			{"chunked text", "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n" + chunkBody(big) + "\r\n"},
			{"close-delimited html", "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n" + big},
			{"svg", fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: image/svg+xml\r\nContent-Length: %d\r\n\r\n%s", len(big), big)},
		}
		for _, shape := range shapes {
			_, gotResp := pair(t, compressPolicy(), "GET /x HTTP/1.1\r\nHost: a.example\r\n\r\n", shape.resp)
			check(t, shape.name, gotResp, shape.resp)
			if strings.Contains(strings.ToLower(gotResp), "content-encoding: gzip") {
				t.Fatalf("%s: a client that never asked for gzip was sent a gzip body: %q", shape.name, gotResp)
			}
		}
	})
}

// Case 19: keep-alive. The second request on the connection says nothing about
// gzip, so its response must be identity: Content-Length intact, no chunk framing
// invented for it. The reads interleave in the order a live connection sees them
// -- request 1, response 1, request 2, response 2 -- because the response side can
// only know what request 2 asked for once request 2's head has gone through the
// request side. Draining both requests first is the pipelined case: Case 21.
func TestCase19GzipKeepAliveSecondRequestIsIdentity(t *testing.T) {
	big := strings.Repeat("compress me please. ", 64)
	small := "identity body, no gzip"
	second := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n%s", len(small), small)

	// The first response is framed both ways: with a Content-Length the transform
	// consumes a body it can count, and with chunks it has to find the end of the
	// input message and put a terminal chunk of its own before returning to heads.
	cases := []struct{ name, respIn string }{
		{
			name:   "content-length framed first response",
			respIn: fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n%s", len(big), big) + second,
		},
		{
			name:   "chunk framed first response",
			respIn: "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\n\r\n" + chunkBody(big) + "\r\n" + second,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reqIn := gzipRequest("/one") + "GET /two HTTP/1.1\r\nHost: a.example\r\n\r\n"
			req, resp := NewPair(strings.NewReader(reqIn), strings.NewReader(tc.respIn), compressPolicy())

			if got := readOnce(t, req); !strings.HasPrefix(got, "GET /one ") {
				t.Fatalf("expected request 1's head first, got %q", got)
			}

			in := newHTTPStream(t, resp)
			first, firstBody := in.next()
			check(t, "first response encoding", first.Header.Get("Content-Encoding"), "gzip")
			check(t, "first response body", string(gunzipBody(t, firstBody)), big)

			if got := readOnce(t, req); !strings.HasPrefix(got, "GET /two ") {
				t.Fatalf("expected request 2's head, got %q", got)
			}

			secondResp, secondBody := in.next()
			in.done()
			if got := secondResp.Header.Get("Content-Encoding"); got != "" {
				t.Fatalf("the second response was compressed for a request that did not ask: Content-Encoding %q", got)
			}
			check(t, "second response Content-Length", secondResp.Header.Get("Content-Length"), strconv.Itoa(len(small)))
			if got := strings.Join(secondResp.TransferEncoding, ","); got != "" {
				t.Fatalf("the identity response was re-framed: %q", got)
			}
			check(t, "second response body", string(secondBody), small)
			if len(secondResp.Header.Get("Vary")) != 0 {
				t.Fatalf("an identity response was given a Vary it never had: %q", secondResp.Header.Get("Vary"))
			}
		})
	}
}

// Case 20: the gzip failure path. A compressor writing into an in-memory buffer
// has no writer to fail, so nothing in the public path can reach this code; the
// test drives the handler directly to pin what it promises. The bytes already
// produced still have to reach the client, the reason is logged once, and the rest
// of the connection is copied raw rather than parsed into garbage.
func TestCase20GzipFailureEmitsThenGoesRaw(t *testing.T) {
	body := strings.Repeat("x", 300)
	respIn := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n%s", len(body), body)

	upstream := &fakeConn{id: "http:upstream"}
	reqReader, respReader := newPair(strings.NewReader(gzipRequest("/x")), strings.NewReader(respIn),
		compressPolicy(), upstream, upstream)
	resp := respReader.(*streamRewriter)

	// The request head goes first, exactly as it would on a live connection: the
	// response side only knows the client accepts gzip once that head is parsed.
	readOnce(t, reqReader.(*streamRewriter))

	head := readOnce(t, resp)
	if !strings.Contains(head, "Content-Encoding: gzip") {
		t.Fatalf("expected a compressed head, got %q", head)
	}
	if resp.gz == nil {
		t.Fatalf("the transform should be live after the head")
	}

	// Bytes the compressor already produced, then a failure it cannot have.
	partial := "partial output"
	if _, err := resp.gz.buf.WriteString(partial); err != nil {
		t.Fatalf("filling the compressor's output buffer failed: %v", err)
	}
	resp.gzipFail(errors.New("compressor exploded"))

	if resp.gz != nil || resp.phase != stRaw {
		t.Fatalf("a failed transform must hand the connection to the raw copy (gz=%v, phase=%v)", resp.gz, resp.phase)
	}
	if len(upstream.warned) != 1 {
		t.Fatalf("expected exactly one warning, got %v", upstream.warned)
	}
	if !strings.Contains(upstream.warned[0], "compressor exploded") {
		t.Fatalf("the warning does not name the reason: %q", upstream.warned[0])
	}

	// What was produced goes out as a chunk, then the source is copied verbatim.
	check(t, "produced bytes", readOnce(t, resp), fmt.Sprintf("%x\r\n%s\r\n", len(partial), partial))
	check(t, "passthrough", drain(t, resp), body)
	if len(upstream.warned) != 1 {
		t.Fatalf("the failure was logged more than once: %v", upstream.warned)
	}
}

// Case 21: pipelined requests. One connState slot describes both requests, so the
// response side uses the newer one's preferences -- the documented limitation.
// What matters is which way it fails: a client whose latest request did not ask
// for gzip gets identity responses, never a compressed one, and the connection
// stays well-formed either way.
func TestCase21GzipPipelinedRequestsStayWellFormed(t *testing.T) {
	big := strings.Repeat("compress me please. ", 64)

	reqIn := gzipRequest("/one") + "GET /two HTTP/1.1\r\nHost: a.example\r\n\r\n"
	respIn := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n%s", len(big), big) +
		fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n%s", len(big), big)

	// pair drains both requests before either response, which is exactly the shape
	// the single slot cannot describe.
	gotReq, gotResp := pair(t, compressPolicy(), reqIn, respIn)

	if n := strings.Count(gotReq, "X-Forwarded-For"); n != 2 {
		t.Fatalf("both pipelined requests should still be rewritten: %d", n)
	}
	if strings.Contains(strings.ToLower(gotResp), "content-encoding") {
		t.Fatalf("a pipelined request that did not ask for gzip was answered compressed: %q", gotResp)
	}
	check(t, "pipelined responses", gotResp, respIn)

	// And they are still two well-formed messages on one connection.
	in := newHTTPStream(t, strings.NewReader(gotResp))
	for i := 1; i <= 2; i++ {
		_, body := in.next()
		check(t, fmt.Sprintf("response %d body", i), string(body), big)
	}
	in.done()
}

// TestCompressibleTypes pins the declared set. It is a table rather than a chain
// of conditions, so these cases are the table's contract: a type in the set is
// compressed, parameters do not change the type, and everything else is left
// alone.
func TestCompressibleTypes(t *testing.T) {
	cases := []struct {
		contentType string
		want        bool
	}{
		{"text/html", true},
		{"text/plain; charset=utf-8", true},
		{"TEXT/CSS", true},
		{"text/event-stream", true},
		{"application/json", true},
		{"Application/JSON", true},
		{"application/javascript", true},
		{"application/xml", true},
		{"application/xhtml+xml", true},
		{"application/graphql", true},
		{"application/wasm", true},
		{"image/svg+xml", true},
		{"", false},
		{"text", false},
		{"application/json-seq", false},
		{"image/png", false},
		{"application/octet-stream", false},
		{"video/mp4", false},
	}

	for _, tc := range cases {
		if got := compressibleType(tc.contentType); got != tc.want {
			t.Fatalf("compressibleType(%q) = %v, want %v", tc.contentType, got, tc.want)
		}
	}
}
