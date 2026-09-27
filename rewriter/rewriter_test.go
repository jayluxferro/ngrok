package rewriter

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xtaci/smux/v2"

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
//
// The Content-Length is dropped on the way out as well as ignored on the way
// in. Forwarding it would hand the upstream a head that says two things at
// once, and which of the two it believes is a property of the upstream's
// implementation rather than of this message: that disagreement -- the reader
// this end, the writer that end -- is the CL.TE half of request smuggling. So
// what leaves here says exactly one thing about the body.
func TestChunkedWinsOverContentLength(t *testing.T) {
	in := "POST / HTTP/1.1\r\nHost: a.example\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n" +
		"5\r\nhello\r\n0\r\n\r\n" +
		"GET /after HTTP/1.1\r\nHost: a.example\r\n\r\n"
	want := "POST / HTTP/1.1\r\nHost: a.example\r\nTransfer-Encoding: chunked\r\n" +
		"X-Forwarded-For: 203.0.113.7\r\nX-Forwarded-Proto: http\r\n\r\n" +
		"5\r\nhello\r\n0\r\n\r\n" +
		"GET /after HTTP/1.1\r\nHost: a.example\r\nX-Forwarded-For: 203.0.113.7\r\nX-Forwarded-Proto: http\r\n\r\n"

	gotReq, _ := pair(t, tunnelPolicy(), in, "")
	check(t, "request", gotReq, want)

	// The output has to stay a message net/http is willing to read, and a
	// reader has to see the chunked body: dropping the field is a framing
	// change, so it is checked with the arbiter rather than by eye.
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(gotReq)))
	if err != nil {
		t.Fatalf("the normalized request is not readable by net/http: %v\n%s", err, gotReq)
	}
	defer req.Body.Close()
	if req.ContentLength != -1 {
		t.Fatalf("net/http read a Content-Length off the normalized head: %d\n%s", req.ContentLength, gotReq)
	}
	if body, err := io.ReadAll(req.Body); err != nil || string(body) != "hello" {
		t.Fatalf("the chunked body did not survive the normalization: %q (err %v)\n%s", body, err, gotReq)
	}
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

// --- policy hooks (SPEC 3.1) ------------------------------------------------
//
// The hook extension is the seam the traffic policy engine plugs into, and the
// tests below are its contract: a hook changes the head it is asked about,
// terminating from a hook ends the connection with a fabricated response, and a
// hook that fails -- panics, panics every time, or hands back a verdict nobody
// can read -- never costs a connection a byte it would otherwise have carried.
//
// They drive NewPair/NewConnPair rather than the state machine's internals,
// because "what the client reads" is the only thing a hook is allowed to change.

// syntheticTermination is one fabricated response used across the terminate
// tests: a status, a caller header, an inferred content-type and a body.
func syntheticTermination() *SyntheticResponse {
	return &SyntheticResponse{
		StatusCode: 503,
		Headers:    []string{"Retry-After: 60"},
		Body:       "maintenance\n",
	}
}

// TestHookNilSafety: a policy without hooks and a policy whose hooks decline
// every message must produce identical bytes. This is what makes the no-policy
// path the same path -- a hook that returns nil is a hook that cost one call.
func TestHookNilSafety(t *testing.T) {
	reqIn := "GET /a HTTP/1.1\r\nHost: a.example\r\n\r\n"
	respIn := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"

	declining := &Policy{
		ClientAddr:      "203.0.113.7",
		XForwardedProto: "http",
		RequestHook:     func(*http.Request) *RequestVerdict { return nil },
		ResponseHook:    func(*http.Response) *ResponseVerdict { return nil },
	}
	plain := tunnelPolicy()

	gotReq, gotResp := pair(t, declining, reqIn, respIn)
	wantReq, wantResp := pair(t, plain, reqIn, respIn)
	check(t, "request", gotReq, wantReq)
	check(t, "response", gotResp, wantResp)

	// A hook is a transformation even when it declines: IsNoop must not let a
	// caller skip the wrapping the hook path needs.
	if declining.IsNoop() {
		t.Fatalf("a policy with hooks reports itself a no-op")
	}
}

// TestHookRewritesMergeWithTheStaticPolicy: the hook's adds and removes are
// merged into the same head rewrite as the static ones, removes first, and the
// host entry of a request add overrides the host rather than adding a second
// one.
func TestHookRewritesMergeWithTheStaticPolicy(t *testing.T) {
	p := &Policy{
		HostHeader:           "rewrite",
		UpstreamHost:         "upstream.example",
		XForwardedProto:      "http",
		ClientAddr:           "203.0.113.7",
		RequestHeaderAdd:     []string{"X-Static: 1"},
		RequestHeaderRemove:  []string{"X-Drop-Me"},
		ResponseHeaderAdd:    []string{"X-Static: resp"},
		ResponseHeaderRemove: []string{"X-Res-Drop"},
		RequestHook: func(req *http.Request) *RequestVerdict {
			return &RequestVerdict{
				Add:    []string{"X-Hook: 2", "Host: hook.example"},
				Remove: []string{"X-Hook-Drop"},
			}
		},
		ResponseHook: func(resp *http.Response) *ResponseVerdict {
			return &ResponseVerdict{
				Add:    []string{"X-Hook: resp"},
				Remove: []string{"X-Res-Hook-Drop"},
			}
		},
	}

	reqIn := "GET /a HTTP/1.1\r\nHost: a.example\r\nX-Drop-Me: yes\r\nX-Hook-Drop: yes\r\n\r\n"
	respIn := "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX-Res-Drop: yes\r\nX-Res-Hook-Drop: yes\r\n\r\n"

	gotReq, gotResp := pair(t, p, reqIn, respIn)

	// Both sources of change are present in the same head: the static rewrite
	// (the X-Forwarded pair, the static add, the upstream host) and the hook's
	// (its add, its override of the host). The exact field order among them is
	// the static rewrite's business and is pinned by cases 1-5; what is
	// asserted here is that neither source swallowed the other.
	for _, want := range []string{
		"Host: hook.example", "X-Forwarded-Host: a.example", "X-Forwarded-For: 203.0.113.7",
		"X-Forwarded-Proto: http", "X-Static: 1", "X-Hook: 2",
	} {
		if !strings.Contains(gotReq, want) {
			t.Fatalf("request rewrite dropped %q:\n%q", want, gotReq)
		}
	}
	for _, gone := range []string{"X-Drop-Me", "X-Hook-Drop"} {
		if strings.Contains(gotReq, gone) {
			t.Fatalf("request rewrite kept %q, which was removed:\n%q", gone, gotReq)
		}
	}
	// The hook's "Host: hook.example" replaced the host rather than adding a
	// second Host field: the merge has to be by name, not by append.
	if strings.Count(gotReq, "\r\nHost:") != 1 {
		t.Fatalf("the hook's host add did not override the existing Host field: %q", gotReq)
	}

	for _, want := range []string{"X-Static: resp", "X-Hook: resp"} {
		if !strings.Contains(gotResp, want) {
			t.Fatalf("response rewrite dropped %q:\n%q", want, gotResp)
		}
	}
	for _, gone := range []string{"X-Res-Drop", "X-Res-Hook-Drop"} {
		if strings.Contains(gotResp, gone) {
			t.Fatalf("response rewrite kept %q, which was removed:\n%q", gone, gotResp)
		}
	}
}

// TestHookSeesHeadOnlyObjects: the hook is handed what the head bytes can
// describe, and nothing is invented for the fields they cannot.
func TestHookSeesHeadOnlyObjects(t *testing.T) {
	var gotMethod, gotPath, gotHost, gotProto, gotURI, gotHeader string
	var gotTLS *tls.ConnectionState
	var gotBody io.ReadCloser
	p := &Policy{
		RequestHook: func(req *http.Request) *RequestVerdict {
			gotMethod = req.Method
			gotPath = req.URL.Path
			gotHost = req.Host
			gotProto = req.Proto
			gotURI = req.RequestURI
			gotHeader = req.Header.Get("X-Probe")
			gotTLS = req.TLS
			gotBody = req.Body
			return nil
		},
	}
	respIn := "HTTP/1.1 204 No Content\r\n\r\n"
	gotReq, _ := pair(t, p, "POST /deep/path?q=1 HTTP/1.1\r\nHost: a.example\r\nX-Probe: yes\r\nContent-Length: 4\r\n\r\nbody", respIn)

	if gotMethod != "POST" || gotPath != "/deep/path" || gotHost != "a.example" ||
		gotProto != "HTTP/1.1" || gotURI != "/deep/path?q=1" || gotHeader != "yes" {
		t.Fatalf("the hook did not see the request it describes: %q %q %q %q %q %q",
			gotMethod, gotPath, gotHost, gotProto, gotURI, gotHeader)
	}
	if gotTLS != nil {
		t.Fatalf("TLS was populated from a plaintext head: %v", gotTLS)
	}
	// "Body fields are not meaningful" has a precise meaning: the object is
	// built from the head bytes, so a body reader on it reads the head buffer,
	// not the live stream. Reading it yields nothing, and -- the invariant that
	// matters -- the rewriter still copies the body it never gave the hook.
	if gotBody != nil && gotBody != http.NoBody {
		if n, err := io.ReadAll(gotBody); err == nil && len(n) > 0 {
			t.Fatalf("the hook's body reader handed over live stream bytes: %q", n)
		}
	}
	if !strings.HasSuffix(gotReq, "\r\n\r\nbody") {
		t.Fatalf("the body did not reach the upstream: %q", gotReq)
	}
}

// TestHookTerminateEmitsSyntheticResponse: a terminating verdict drops the
// request -- the upstream is never handed it, and never asked anything -- and
// answers the client with a response net/http can read, after which the
// connection ends.
func TestHookTerminateEmitsSyntheticResponse(t *testing.T) {
	term := syntheticTermination()
	p := &Policy{
		RequestHook: func(req *http.Request) *RequestVerdict {
			if req.URL.Path == "/maintenance" {
				return &RequestVerdict{Terminate: term}
			}
			return nil
		},
	}

	reqIn := "POST /maintenance HTTP/1.1\r\nHost: a.example\r\nContent-Length: 4\r\n\r\nbody"
	// The upstream says nothing, because it is never spoken to.
	req, resp := NewPair(strings.NewReader(reqIn), strings.NewReader(""), p)

	// The request side forwards nothing: the head is dropped, and the body the
	// client keeps sending is drained rather than passed on.
	if got := drain(t, req); got != "" {
		t.Fatalf("a terminated request reached the upstream: %q", got)
	}

	s := newHTTPStream(t, resp)
	got, body := s.next()
	if got.StatusCode != 503 {
		t.Fatalf("status = %d, want 503", got.StatusCode)
	}
	if got.Header.Get("Retry-After") != "60" {
		t.Fatalf("the verdict's header was not emitted: %v", got.Header)
	}
	if string(body) != "maintenance\n" {
		t.Fatalf("body = %q, want %q", body, "maintenance\n")
	}
	// net/http reads Connection: close as "this message ends the connection",
	// which is the framing the renderer promised (and which
	// TestSyntheticResponseRender pins byte for byte).
	if !got.Close {
		t.Fatalf("a synthetic response must be the last message on the connection")
	}
	s.done()
}

// TestHookTerminateBeatsAnAvailableResponse: the pending termination is emitted
// before the source is read, so a response that is already sitting in the
// upstream's buffer is not delivered to a client whose request was refused.
func TestHookTerminateBeatsAnAvailableResponse(t *testing.T) {
	p := &Policy{
		RequestHook: func(req *http.Request) *RequestVerdict {
			if req.URL.Path == "/admin" {
				return &RequestVerdict{Terminate: &SyntheticResponse{StatusCode: 403}}
			}
			return nil
		},
	}

	reqIn := "GET /ok HTTP/1.1\r\nHost: a.example\r\n\r\n" +
		"GET /admin HTTP/1.1\r\nHost: a.example\r\n\r\n"
	respIn := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok" +
		"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nleaked!"

	req, resp := NewPair(strings.NewReader(reqIn), strings.NewReader(respIn), p)

	// First message: an ordinary request, and the response it asked for. One
	// read per step, in the order a live connection produces them.
	check(t, "request 1", readOnce(t, req), "GET /ok HTTP/1.1\r\nHost: a.example\r\n\r\n")
	check(t, "response 1 head", readOnce(t, resp), "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n")
	check(t, "response 1 body", readOnce(t, resp), "ok")

	// Second message: refused. The request is dropped and the answer is the
	// 403, not the "leaked!" response the upstream had already sent.
	if got := drain(t, req); got != "" {
		t.Fatalf("the refused request was forwarded: %q", got)
	}
	got := drain(t, resp)
	if !strings.Contains(got, "403") {
		t.Fatalf("the synthetic response was not emitted: %q", got)
	}
	if strings.Contains(got, "leaked!") {
		t.Fatalf("an upstream response was delivered for a refused request: %q", got)
	}
}

// TestSyntheticResponseGoesThroughTheResponseHook: an answer the edge fabricated
// is still a response, so the response-phase policy gets to change it -- that is
// how a remove-headers or add-headers action reaches a deny or a custom-response.
// ngrok documents this for a request-phase custom-response ("actions defined in
// the on_http_response phase will still be executed"), and it is what workstream
// B's e2e expected of the mux path.
func TestSyntheticResponseGoesThroughTheResponseHook(t *testing.T) {
	var saw *http.Response
	p := &Policy{
		RequestHook: func(req *http.Request) *RequestVerdict {
			if req.URL.Path != "/admin" {
				return nil
			}
			// No StatusCode: the documented default 403. The hook must be told
			// the status the client is going to get, not the zero it was built
			// with, or a rule written against res.status_code would miss it.
			return &RequestVerdict{Terminate: &SyntheticResponse{
				Headers: []string{"Server: ngrok/edge", "Content-Type: text/plain"},
				Body:    "no",
			}}
		},
		ResponseHook: func(resp *http.Response) *ResponseVerdict {
			saw = resp
			return &ResponseVerdict{
				// "server" is not the casing the response carries, and "x-absent"
				// is not on the response at all: both are how a policy names a
				// header, and neither may go wrong.
				Remove: []string{"server", "x-absent"},
				Add:    []string{"X-Policy: applied"},
			}
		},
	}

	public := &fakeConn{src: strings.NewReader("GET /admin HTTP/1.1\r\nHost: a.example\r\n\r\n"), id: "http:public"}
	upstream := &fakeConn{src: strings.NewReader(""), id: "http:upstream"}
	toUpstream, fromUpstream := NewConnPair(public, upstream, p)

	if got := drain(t, toUpstream); got != "" {
		t.Fatalf("a terminated request reached the upstream: %q", got)
	}
	check(t, "response", drain(t, fromUpstream),
		"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nX-Policy: applied\r\n"+
			"Content-Length: 2\r\nConnection: close\r\n\r\nno")

	if saw == nil {
		t.Fatal("the response hook was never asked about the synthetic response")
	}
	if saw.StatusCode != 403 {
		t.Fatalf("the hook saw status %d, want the 403 the client is sent", saw.StatusCode)
	}
	if got := saw.Header.Get("Content-Type"); got != "text/plain" {
		t.Fatalf("the hook saw Content-Type %q, want the response's own header", got)
	}
	if got := saw.Header.Get("Server"); got != "ngrok/edge" {
		t.Fatalf("the hook saw Server %q, want the response's own header", got)
	}
	if len(upstream.warned) != 0 {
		t.Fatalf("a hook that worked must not warn: %v", upstream.warned)
	}
}

// TestSyntheticResponseHookPanicIsFailOpen: the fail-open rule reaches the
// synthetic path too. A response hook that panics on a fabricated response
// cannot cost the client the answer it was refused with -- the terminate goes out
// unmodified, and the failure is logged on the connection's response side.
func TestSyntheticResponseHookPanicIsFailOpen(t *testing.T) {
	term := syntheticTermination()
	p := &Policy{
		RequestHook: func(*http.Request) *RequestVerdict {
			return &RequestVerdict{Terminate: term}
		},
		ResponseHook: func(*http.Response) *ResponseVerdict { panic("response hook boom") },
	}

	public := &fakeConn{src: strings.NewReader("GET /a HTTP/1.1\r\nHost: a.example\r\n\r\n"), id: "http:public"}
	upstream := &fakeConn{src: strings.NewReader(""), id: "http:upstream"}
	toUpstream, fromUpstream := NewConnPair(public, upstream, p)

	if got := drain(t, toUpstream); got != "" {
		t.Fatalf("a terminated request reached the upstream: %q", got)
	}
	check(t, "response", drain(t, fromUpstream), string(term.Render()))

	if len(upstream.warned) != 1 || !strings.Contains(upstream.warned[0], "response hook panicked") {
		t.Fatalf("want one warning about the panicking response hook, got %v", upstream.warned)
	}
}

// TestHookPanicFailsOpen: a hook that panics is a hook that does not apply. The
// connection keeps going with the static rewrite, and the failure is logged
// once per direction on the connection it happened on.
func TestHookPanicFailsOpen(t *testing.T) {
	p := &Policy{
		ClientAddr:      "203.0.113.7",
		XForwardedProto: "http",
		RequestHook:     func(*http.Request) *RequestVerdict { panic("request hook boom") },
		ResponseHook:    func(*http.Response) *ResponseVerdict { panic("response hook boom") },
	}

	public := &fakeConn{src: strings.NewReader("GET /a HTTP/1.1\r\nHost: a.example\r\n\r\n"), id: "http:public"}
	upstream := &fakeConn{src: strings.NewReader("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"), id: "http:upstream"}

	toUpstream, fromUpstream := NewConnPair(public, upstream, p)

	check(t, "request", drain(t, toUpstream),
		"GET /a HTTP/1.1\r\nHost: a.example\r\nX-Forwarded-For: 203.0.113.7\r\nX-Forwarded-Proto: http\r\n\r\n")
	check(t, "response", drain(t, fromUpstream), "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")

	if len(public.warned) != 1 || !strings.Contains(public.warned[0], "request hook panicked") {
		t.Fatalf("want one warning about the request hook, got %v", public.warned)
	}
	if len(upstream.warned) != 1 || !strings.Contains(upstream.warned[0], "response hook panicked") {
		t.Fatalf("want one warning about the response hook, got %v", upstream.warned)
	}
}

// TestHookNotCalledOn1xx: interim responses are not responses any action
// describes, and the 1xx rule has to survive the hook path.
func TestHookNotCalledOn1xx(t *testing.T) {
	calls := 0
	var statuses []int
	p := &Policy{
		RequestHook: func(*http.Request) *RequestVerdict { return nil },
		ResponseHook: func(resp *http.Response) *ResponseVerdict {
			calls++
			statuses = append(statuses, resp.StatusCode)
			return nil
		},
	}

	respIn := "HTTP/1.1 100 Continue\r\n\r\n" +
		"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok" +
		"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n" +
		"HTTP/1.1 204 No Content\r\n\r\n"

	req, resp := NewPair(strings.NewReader("GET /a HTTP/1.1\r\nHost: a.example\r\n\r\n"), strings.NewReader(respIn), p)

	check(t, "request", readOnce(t, req), "GET /a HTTP/1.1\r\nHost: a.example\r\n\r\n")
	check(t, "100", readOnce(t, resp), "HTTP/1.1 100 Continue\r\n\r\n")
	check(t, "200 head", readOnce(t, resp), "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n")
	check(t, "200 body", readOnce(t, resp), "ok")
	check(t, "101", readOnce(t, resp),
		"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")

	if calls != 1 || len(statuses) != 1 || statuses[0] != 200 {
		t.Fatalf("the response hook ran %d time(s) on %v; only the 200 is a response", calls, statuses)
	}
}

// TestHookHostAddNeedsNoHostOverrideOnResponses: a "Host" add is a host override
// on the request side and an ordinary header on the response side, which is
// what the two directions' rewrites do with it.
func TestHookHostAddOnResponseIsJustAHeader(t *testing.T) {
	p := &Policy{
		ResponseHook: func(*http.Response) *ResponseVerdict {
			return &ResponseVerdict{Add: []string{"X-Served: yes"}}
		},
	}
	gotReq, gotResp := pair(t, p, "GET / HTTP/1.1\r\nHost: a.example\r\n\r\n",
		"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
	check(t, "request", gotReq, "GET / HTTP/1.1\r\nHost: a.example\r\n\r\n")
	check(t, "response", gotResp, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX-Served: yes\r\n\r\n")
}

// TestSyntheticResponseRender pins the fabricated message itself: framing the
// caller cannot break, a status the caller cannot omit, and CR/LF in a header
// value dropped rather than smuggled.
func TestSyntheticResponseRender(t *testing.T) {
	tests := []struct {
		name string
		resp *SyntheticResponse
		want string
	}{
		{
			"deny",
			&SyntheticResponse{StatusCode: 403},
			"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
		},
		{
			"zero status is a 403",
			&SyntheticResponse{},
			"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
		},
		{
			"headers and body",
			&SyntheticResponse{
				StatusCode: 503,
				Headers:    []string{"Retry-After: 60", "Content-Type: text/plain"},
				Body:       "down",
			},
			"HTTP/1.1 503 Service Unavailable\r\nRetry-After: 60\r\nContent-Type: text/plain\r\n" +
				"Content-Length: 4\r\nConnection: close\r\n\r\ndown",
		},
		{
			"framing is the renderer's to write",
			&SyntheticResponse{
				StatusCode: 200,
				Headers:    []string{"Content-Length: 999", "Connection: keep-alive", "X-Ok: 1"},
				Body:       "hi",
			},
			"HTTP/1.1 200 OK\r\nX-Ok: 1\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi",
		},
		{
			"unusable entries are dropped",
			&SyntheticResponse{
				StatusCode: 200,
				Headers:    []string{"no colon", "Bad Name: x", "X-CRLF: a\r\nX-Injected: b", "X-Good: 1"},
			},
			"HTTP/1.1 200 OK\r\nX-Good: 1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			check(t, "rendered", string(tt.resp.Render()), tt.want)
		})
	}
}

// blockingConn is a conn.Conn whose Read parks until it is closed: the upstream
// that will never answer, in the shape the wake exists for. It is also the guard
// against a test that hangs instead of failing: the timeout read returns an error
// saying so.
//
// SetReadDeadline stores the deadline and deliberately does NOT wake the parked
// read. That is not a shortcut, it is a model of the transport the terminate hang
// was found on: smux's Stream.SetReadDeadline only stores the value and
// Stream.Read samples it once, on entry (smux/v2 stream.go, waitRead), so a read
// already parked never learns that one was set. A TCP socket would wake -- the
// kernel does that -- and an earlier version of this fake woke too, which is
// exactly why the deadline-based wake passed here while the mux path hung. The
// wake closes the source now (NewConnPair), so closing must wake this read.
type blockingConn struct {
	conn.Conn
	entered  chan struct{}
	closed   chan struct{}
	enterOne sync.Once
	closeOne sync.Once
	dst      bytes.Buffer

	// deadline is written and never read: the point of the fake is what the
	// connection does with one, which is nothing.
	deadline time.Time
}

func newBlockingConn() *blockingConn {
	return &blockingConn{entered: make(chan struct{}), closed: make(chan struct{})}
}

func (c *blockingConn) Read(p []byte) (int, error) {
	c.enterOne.Do(func() { close(c.entered) })
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	case <-time.After(5 * time.Second):
		return 0, errors.New("the parked read was never woken")
	}
}

func (c *blockingConn) Write(p []byte) (int, error) { return c.dst.Write(p) }

func (c *blockingConn) Close() error {
	c.closeOne.Do(func() { close(c.closed) })
	return nil
}

func (c *blockingConn) SetReadDeadline(d time.Time) error {
	c.deadline = d
	return nil
}

// TestHookWakeUnblocksParkedResponseSide is the race the spec's terminate model
// has to solve: conn.Join drives both directions at once, so the response side
// is usually already parked in a read of its upstream when the request side
// decides to terminate -- and in the terminated case the upstream is never
// asked anything, so that read would never return. The wake (closing the
// response side's source, see NewConnPair) is what turns "wait forever" into
// "emit the synthetic response now".
//
// The connection this parks in is the fake above, which wakes on Close only, and
// the response is waited for with a bound rather than until it arrives. That
// bound is not decoration: a deadline-based wake leaves the read parked until the
// fake's own five-second give-up (it has to return something), so the response
// still lands, five seconds late, and a test that only waits for the bytes passes
// on the bug. The wake has to work, not merely not-forever.
// TestHookTerminateOverMuxStream is the same case on a real smux stream, where
// nothing gives up and the read never ends at all.
func TestHookWakeUnblocksParkedResponseSide(t *testing.T) {
	term := syntheticTermination()
	p := &Policy{
		RequestHook: func(*http.Request) *RequestVerdict {
			return &RequestVerdict{Terminate: term}
		},
	}

	public := &fakeConn{src: strings.NewReader("GET /a HTTP/1.1\r\nHost: a.example\r\n\r\n"), id: "http:public"}
	upstream := newBlockingConn()

	toUpstream, fromUpstream := NewConnPair(public, upstream, p)

	respOut := make(chan copyResult, 1)
	go func() {
		var b strings.Builder
		_, err := io.Copy(&b, fromUpstream)
		respOut <- copyResult{b.String(), err}
	}()

	// Wait until the response side really is parked in the blocking read, so
	// that the wake is exercised rather than the check-before-read path.
	<-upstream.entered

	// The request side terminates the connection.
	if got := drain(t, toUpstream); got != "" {
		t.Fatalf("the terminated request was forwarded: %q", got)
	}

	select {
	case got := <-respOut:
		if got.err != nil {
			t.Fatalf("the response side did not end cleanly: %v", got.err)
		}
		check(t, "response", got.out, string(term.Render()))
	case <-time.After(2 * time.Second):
		t.Fatal("the parked response side was not woken promptly: a deadline set on " +
			"a connection whose read is already waiting is stored and never seen")
	}
}

// observedStream reports the first read the rewriter makes of it, then delegates.
// It is how the mux test below knows the response side reached its parked read:
// nothing in smux reports that, and the read has to be parked before the wake is
// what ends it -- otherwise the terminate is taken on the way in (stepHead's
// entry check) and the case the test exists for is not exercised.
type observedStream struct {
	conn.Conn
	entered chan struct{}
	once    sync.Once
}

func (s *observedStream) Read(p []byte) (int, error) {
	s.once.Do(func() { close(s.entered) })
	return s.Conn.Read(p)
}

// TestHookTerminateOverMuxStream: the terminate case above, on the transport the
// hang was actually reported on.
//
// The response source is a real smux stream over an in-memory pipe, wrapped with
// conn.Wrap exactly as the server wraps one (server/mux.go, handleStream), and the
// response side is parked in a read of it when the request side terminates. With
// a deadline-based wake it stays parked there -- smux's Stream.SetReadDeadline
// cannot end a read that is already waiting, which the fake above cannot show
// but this does -- so this is the test that fails ("the synthetic response was
// never delivered") on the bug workstream B hit in its e2e, and the reason the
// wake closes the source instead.
func TestHookTerminateOverMuxStream(t *testing.T) {
	term := syntheticTermination()
	p := &Policy{
		RequestHook: func(*http.Request) *RequestVerdict {
			return &RequestVerdict{Terminate: term}
		},
	}

	// The smux session: the client end of the pipe is the upstream that says
	// nothing, the server end is what the tunnel reads responses from.
	clientPipe, serverPipe := net.Pipe()
	sess, err := smux.Server(serverPipe, smux.DefaultConfig())
	if err != nil {
		t.Fatalf("smux.Server: %v", err)
	}
	defer sess.Close()
	clientSess, err := smux.Client(clientPipe, smux.DefaultConfig())
	if err != nil {
		t.Fatalf("smux.Client: %v", err)
	}
	defer clientSess.Close()

	upstreamStream, err := clientSess.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	defer upstreamStream.Close()

	// AcceptStream has no deadline of its own, so bound it here rather than
	// letting a session that never comes up hang the suite.
	accepted := make(chan *smux.Stream, 1)
	acceptErr := make(chan error, 1)
	go func() {
		stream, err := sess.AcceptStream()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- stream
	}()
	var stream *smux.Stream
	select {
	case stream = <-accepted:
	case err := <-acceptErr:
		t.Fatalf("AcceptStream: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("the mux session never accepted the stream")
	}
	defer stream.Close()

	respSrc := &observedStream{Conn: conn.Wrap(stream, "pxy"), entered: make(chan struct{})}
	public := &fakeConn{src: strings.NewReader("GET /a HTTP/1.1\r\nHost: a.example\r\n\r\n"), id: "http:public"}

	toUpstream, fromUpstream := NewConnPair(public, respSrc, p)

	respOut := make(chan copyResult, 1)
	go func() {
		var b strings.Builder
		_, err := io.Copy(&b, fromUpstream)
		respOut <- copyResult{b.String(), err}
	}()

	// Wait for the response side to reach the stream, then let that read settle
	// into the wait smux parks it in. The sleep is a settle, not a
	// synchronization: no API reports "this stream read is now parked". It only
	// has to be long enough for the reported case to be the likely one -- the
	// fake above is where the same path is exact.
	select {
	case <-respSrc.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the response side never read the stream")
	}
	time.Sleep(50 * time.Millisecond)

	// The request side terminates: the request is dropped, and the read parked on
	// the smux stream is ended by closing that stream rather than by a deadline
	// smux would never notice.
	if got := drain(t, toUpstream); got != "" {
		t.Fatalf("the terminated request was forwarded: %q", got)
	}

	select {
	case got := <-respOut:
		if got.err != nil {
			t.Fatalf("the response side did not end cleanly: %v", got.err)
		}
		check(t, "response", got.out, string(term.Render()))
	case <-time.After(5 * time.Second):
		t.Fatal("the synthetic response was never delivered: the response side is still parked in the stream read")
	}

	// And nothing was ever written to the upstream's end of the stream. The read
	// below reports EOF (the tunnel end closed it) or its deadline, never a byte;
	// which of the two depends on how the close and the read interleave.
	if err := upstreamStream.SetReadDeadline(time.Now().Add(250 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline on the upstream end: %v", err)
	}
	switch n, err := upstreamStream.Read(make([]byte, 64)); {
	case n != 0:
		t.Fatalf("the terminated request reached the upstream: %d bytes", n)
	case err == nil:
		t.Fatalf("the upstream read returned (0, nil), which is not an ending")
	}
}

// --- the audit's findings, one test each ------------------------------------

// copyResult is one direction's drained output, or why it stopped. The tests
// below drive a direction on a goroutine and need the error to travel with the
// bytes: an io.Copy that ends in an error is a different finding from one that
// ends at EOF with the wrong bytes, and a bare channel of strings cannot say
// which happened.
type copyResult struct {
	out string
	err error
}

// TestOversizedHeadWithARequestHookIsRefused (PT-C1).
//
// A head this proxy cannot parse is a head it cannot ask the request hook
// about: the hook is handed a *http.Request built from the parsed head, and
// there is no parsed head. Fail-open was the old answer -- pass the bytes
// through unread -- and it is right for a policy of static rewrites, whose
// worst case is a rewrite that did not happen. It is not right for a hook: a
// hook is a question with a yes/no answer, and forwarding the request anyway
// answers it yes. Anyone who can pad a head past the parser's 64 KiB limit
// could then walk past every hook rule, which is a bypass of exactly the thing
// the hook exists for, and the padding is under the attacker's control.
//
// So: with a request hook armed, an oversized head is refused on the
// synthetic-response path with 431, the origin never sees a byte of it, and the
// refusal is sticky -- the request side stops parsing, so a well-formed request
// behind the oversized one is not forwarded either. Without a hook the old
// contract stands, byte for byte, and the other direction is untouched: a
// response hook has no verdict that says "do not forward this" (see
// ResponseVerdict), so refusing an oversized response head would only mean
// dropping an answer.
func TestOversizedHeadWithARequestHookIsRefused(t *testing.T) {
	bigLine := "GET / HTTP/1.1\r\nX-Big: " + strings.Repeat("a", 70*1024) + "\r\n\r\n" + "tail bytes"

	var manyLines strings.Builder
	manyLines.WriteString("GET / HTTP/1.1\r\n")
	for i := 0; i < 300; i++ {
		fmt.Fprintf(&manyLines, "X-Filler-%d: %s\r\n", i, strings.Repeat("b", 400))
	}
	manyLines.WriteString("\r\n")
	// A perfectly good request behind the oversized head: nothing later on the
	// connection is parsed after a refusal, so the origin must not see this one
	// either.
	manyLines.WriteString("GET /after HTTP/1.1\r\nHost: a.example\r\n\r\n")

	cases := []struct {
		name string
		in   string
	}{
		// readLine's errLineTooLong: one line that does not fit the read buffer.
		{"line over the read buffer", bigLine},
		// The head-size cap: many lines that do fit, but not together.
		{"head over the cap", manyLines.String()},
	}

	for _, tc := range cases {
		t.Run(tc.name+": no hook, fail-open", func(t *testing.T) {
			gotReq, gotResp := pair(t, tunnelPolicy(), tc.in, "")
			check(t, "request", gotReq, tc.in)
			if gotResp != "" {
				t.Fatalf("the response side answered a request that was only passed through: %q", gotResp)
			}
		})

		t.Run(tc.name+": request hook armed, refused", func(t *testing.T) {
			calls := 0
			p := &Policy{RequestHook: func(*http.Request) *RequestVerdict {
				calls++
				return &RequestVerdict{Terminate: syntheticTermination()}
			}}

			gotReq, gotResp := pair(t, p, tc.in, "")

			if gotReq != "" {
				t.Fatalf("the origin saw %d byte(s) of a head that could not be parsed: %q", len(gotReq), gotReq)
			}
			if calls != 0 {
				t.Fatalf("the hook was called %d time(s) on a request with no parsed head", calls)
			}

			// The client gets the refusal, as one complete message that
			// net/http can read -- 431 is what a client (and net/http's own
			// MaxHeaderBytes path) understands as "the head was too big".
			stream := newHTTPStream(t, strings.NewReader(gotResp))
			resp, body := stream.next()
			if resp.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
				t.Fatalf("the refusal was answered with %d, want %d:\n%q", resp.StatusCode, http.StatusRequestHeaderFieldsTooLarge, gotResp)
			}
			if !strings.Contains(strings.ToLower(string(body)), "too large") {
				t.Fatalf("the refusal body does not say what happened: %q", body)
			}
			stream.done()
		})
	}

	t.Run("response side: oversized head still fails open", func(t *testing.T) {
		// The scope of the refusal, pinned: it is a request-side decision about
		// a request-side hook. The response hook has no terminate, so there is
		// no verdict to carry out here and fail-open is what is left.
		in := "HTTP/1.1 200 OK\r\nX-Big: " + strings.Repeat("c", 70*1024) + "\r\n\r\n"
		p := &Policy{
			RequestHook:  func(*http.Request) *RequestVerdict { return nil },
			ResponseHook: func(*http.Response) *ResponseVerdict { return nil },
		}
		gotReq, gotResp := pair(t, p, "GET / HTTP/1.1\r\nHost: a.example\r\n\r\n", in)
		if gotReq == "" {
			t.Fatal("the request was not forwarded")
		}
		check(t, "response", gotResp, in)
	})
}

// TestMalformedHeadWithARequestHookIsRefused (PT-C1, the cheap route).
//
// The test above refuses a head past 64 KiB. That is the expensive version of
// the same bypass: a head this package cannot parse is a head no request-phase
// action runs on, so failing open forwards a request the policy would have
// refused. A head that fails to *parse* costs the attacker one malformed line --
// an obs-fold continuation, a header line with no colon, a space in a field name
// -- and it is stickier than the oversized one, because failOpen leaves the whole
// connection in stRaw: every later request on it, well-formed or not, is
// forwarded unpoliced until the connection ends.
//
// The three cases below are the reviewer's, one per shape. Each is run twice:
// with a static-only policy (tunnelPolicy, no hooks) the old fail-open contract
// stands byte for byte, and with a request hook armed the connection is refused
// with 431 before any of it reaches the origin. A well-formed request is
// pipelined behind the malformed one in every case, which is what makes the
// stickiness assertion: after the refusal the origin must see none of it either,
// and the hook must never have run.
//
// The response side is pinned at the end for the reason the oversized test gives:
// the refusal is a request-side decision about a request-side hook.
func TestMalformedHeadWithARequestHookIsRefused(t *testing.T) {
	cases := []struct {
		name string
		head string
	}{
		// RFC 7230 3.2.4: obs-fold is deprecated and this parser refuses it, so a
		// continuation line is enough to skip every rule on the connection.
		{"obs-fold continuation line", "GET /admin HTTP/1.1\r\nHost: a.example\r\nX-Folded: one\r\n two\r\n\r\n"},
		// parseHeaderField's colon check.
		{"header line without a colon", "GET /admin HTTP/1.1\r\nHost: a.example\r\nnot a header line\r\n\r\n"},
		// parseHeaderField's token check on the name.
		{"space in the field name", "GET /admin HTTP/1.1\r\nHost: a.example\r\nX Bad: v\r\n\r\n"},
	}
	// A well-formed request behind the malformed one. Nothing later on the
	// connection is parsed after a refusal, so with a hook armed the origin must
	// not see this one either -- that is the difference between refusing the
	// request and refusing the whole connection, and it is the behavior the
	// change is for.
	const after = "GET /after HTTP/1.1\r\nHost: a.example\r\n\r\n"

	for _, tc := range cases {
		in := tc.head + after

		t.Run(tc.name+": no hook, fail-open", func(t *testing.T) {
			gotReq, gotResp := pair(t, tunnelPolicy(), in, "")
			check(t, "request", gotReq, in)
			if gotResp != "" {
				t.Fatalf("the response side answered a request that was only passed through: %q", gotResp)
			}
		})

		t.Run(tc.name+": request hook armed, refused", func(t *testing.T) {
			calls := 0
			p := &Policy{RequestHook: func(*http.Request) *RequestVerdict {
				calls++
				return &RequestVerdict{Terminate: syntheticTermination()}
			}}

			gotReq, gotResp := pair(t, p, in, "")

			if gotReq != "" {
				t.Fatalf("the origin saw %d byte(s) of a connection whose first head was malformed: %q", len(gotReq), gotReq)
			}
			if calls != 0 {
				t.Fatalf("the hook was called %d time(s) on a connection whose first head was malformed", calls)
			}

			// The client gets the refusal, as one complete message that net/http
			// can read. 431 rather than 400: it is the status this proxy already
			// answers the unprocessable-head class with (see refuseHead), and a
			// client that pads its headers and a client that folds them should
			// not have to tell two statuses apart to know the policy engine
			// refused to look at the request.
			stream := newHTTPStream(t, strings.NewReader(gotResp))
			resp, body := stream.next()
			if resp.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
				t.Fatalf("the refusal was answered with %d, want %d:\n%q", resp.StatusCode, http.StatusRequestHeaderFieldsTooLarge, gotResp)
			}
			if !strings.Contains(strings.ToLower(string(body)), "malformed") {
				t.Fatalf("the refusal body does not say what happened: %q", body)
			}
			stream.done()
		})
	}

	t.Run("response side: malformed head still fails open", func(t *testing.T) {
		// The response hook has no terminate verdict, so there is nothing to
		// carry out; dropping an answer would be the only other option, and the
		// edge has already forwarded the request.
		in := "HTTP/1.1 200 OK\r\nnot a header line\r\n\r\n"
		p := &Policy{
			RequestHook:  func(*http.Request) *RequestVerdict { return nil },
			ResponseHook: func(*http.Response) *ResponseVerdict { return nil },
		}
		gotReq, gotResp := pair(t, p, "GET / HTTP/1.1\r\nHost: a.example\r\n\r\n", in)
		if gotReq == "" {
			t.Fatal("the request was not forwarded")
		}
		check(t, "response", gotResp, in)
	})
}

// TestContentLengthIsDroppedWhenTheBodyIsChunkFramed (M2, RFC 7230 3.3.3).
//
// A message that carries both framings is the CL.TE request-smuggling shape,
// and this package is an intermediary on it: the reader (this side) framed the
// body by Transfer-Encoding, so a Content-Length in the same head is a second,
// disagreeing statement of where the body ends. Sending both leaves the choice
// to the next hop, and the whole point of smuggling is that two hops can choose
// differently. The field is dropped on the way out in both directions, and the
// output has to stay a message net/http reads the same way -- this side's reader
// and a client are the two hops whose disagreement is the attack.
func TestContentLengthIsDroppedWhenTheBodyIsChunkFramed(t *testing.T) {
	body := "5\r\nhello\r\n0\r\n\r\n"

	t.Run("request", func(t *testing.T) {
		in := "POST / HTTP/1.1\r\nHost: a.example\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n" + body
		gotReq, _ := pair(t, tunnelPolicy(), in, "")

		if strings.Contains(gotReq, "Content-Length") {
			t.Fatalf("a chunk-framed request went out with a Content-Length too:\n%q", gotReq)
		}
		if !strings.Contains(gotReq, "Transfer-Encoding: chunked") {
			t.Fatalf("the framing header was lost as well:\n%q", gotReq)
		}
		req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(gotReq)))
		if err != nil {
			t.Fatalf("net/http cannot read the normalized request: %v\n%q", err, gotReq)
		}
		defer req.Body.Close()
		if req.ContentLength != -1 {
			t.Fatalf("net/http read a Content-Length off the normalized head: %d\n%q", req.ContentLength, gotReq)
		}
		if got, err := io.ReadAll(req.Body); err != nil || string(got) != "hello" {
			t.Fatalf("the chunked body did not survive: %q (err %v)\n%q", got, err, gotReq)
		}
	})

	t.Run("response", func(t *testing.T) {
		in := "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n" + body
		_, gotResp := pair(t, tunnelPolicy(), "GET / HTTP/1.1\r\nHost: a.example\r\n\r\n", in)

		if strings.Contains(gotResp, "Content-Length") {
			t.Fatalf("a chunk-framed response went out with a Content-Length too:\n%q", gotResp)
		}
		stream := newHTTPStream(t, strings.NewReader(gotResp))
		resp, got := stream.next()
		if string(got) != "hello" {
			t.Fatalf("the chunked body did not survive: %q\n%q", got, gotResp)
		}
		if resp.ContentLength != -1 {
			t.Fatalf("net/http read a Content-Length off the normalized head: %d\n%q", resp.ContentLength, gotResp)
		}
		stream.done()
	})

	t.Run("a policy that removes Transfer-Encoding does not resurrect the length", func(t *testing.T) {
		// The removes shape the head; the framing was already decided by the
		// input. A policy that strips the field still gets a chunk-framed body,
		// so a Content-Length kept here would be a length the bytes behind the
		// head do not have -- the removal is the author's footgun to fire, and
		// this package does not fire a second one for them.
		p := &Policy{RequestHeaderRemove: []string{"transfer-encoding"}}
		in := "POST / HTTP/1.1\r\nHost: a.example\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n" + body
		gotReq, _ := pair(t, p, in, "")

		if strings.Contains(gotReq, "Content-Length") {
			t.Fatalf("the Content-Length survived a chunk-framed body:\n%q", gotReq)
		}
		if strings.Contains(gotReq, "Transfer-Encoding") {
			t.Fatalf("the policy's removal did not happen:\n%q", gotReq)
		}
	})

	t.Run("a Content-Length message is untouched", func(t *testing.T) {
		in := "POST / HTTP/1.1\r\nHost: a.example\r\nContent-Length: 5\r\n\r\nhello"
		gotReq, _ := pair(t, tunnelPolicy(), in, "")
		want := "POST / HTTP/1.1\r\nHost: a.example\r\nContent-Length: 5\r\n" +
			"X-Forwarded-For: 203.0.113.7\r\nX-Forwarded-Proto: http\r\n\r\nhello"
		check(t, "request", gotReq, want)
	})
}

// TestTerminateInTheParkWindowIsNotLost (M3).
//
// The response side's park is a check followed by a wait: "is a terminate
// already published?" and, if not, "wake me when one is". The wait has to be
// registered before the answer is looked for, or a terminate published between
// the two is a terminate whose wake nobody sends -- the request side sees a
// response side that is not parked yet and stays quiet, the response side
// registers as parked and hears nothing, and the connection is stuck until
// something else ends it. That was the R1-R3 report. The fix is one atomic
// check-and-park (connState.parkResponse) rather than a tighter pair of locks:
// the window has to stop existing, not get smaller.
//
// The window is opened here on purpose, through the package's test-only gap
// hook, so the interleaving is the reported one rather than one the scheduler
// may or may not produce. The request side publishes its terminate while the
// response side is held in the gap. With the old check-then-park this test does
// not fail, it stalls: the 2s bound below is what turns the stall into a
// failure, and the response source is the fake whose read parks until it is
// closed (blockingConn), so "nothing woke it" is a five-second read error
// rather than a hang that takes the suite with it.
func TestTerminateInTheParkWindowIsNotLost(t *testing.T) {
	term := syntheticTermination()

	reached := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once

	oldHook := testParkGapHook
	testParkGapHook = func(*connState) {
		once.Do(func() { close(reached) })
		<-release
	}
	defer func() { testParkGapHook = oldHook }()

	p := &Policy{RequestHook: func(*http.Request) *RequestVerdict {
		return &RequestVerdict{Terminate: term}
	}}

	public := &fakeConn{src: strings.NewReader("GET /a HTTP/1.1\r\nHost: a.example\r\n\r\n"), id: "http:public"}
	upstream := newBlockingConn()
	toUpstream, fromUpstream := NewConnPair(public, upstream, p)

	respOut := make(chan copyResult, 1)
	go func() {
		var b strings.Builder
		_, err := io.Copy(&b, fromUpstream)
		respOut <- copyResult{b.String(), err}
	}()

	// The response side is now in the gap: the generation is claimed and
	// nothing is parked yet.
	select {
	case <-reached:
	case <-time.After(5 * time.Second):
		t.Fatal("the response side never reached the park window")
	}

	// The request side decides to terminate, right here, in the window.
	if got := drain(t, toUpstream); got != "" {
		t.Fatalf("the terminated request was forwarded: %q", got)
	}
	close(release)

	select {
	case got := <-respOut:
		if got.err != nil {
			t.Fatalf("the response side did not end cleanly: %v", got.err)
		}
		check(t, "response", got.out, string(term.Render()))
	case <-time.After(2 * time.Second):
		t.Fatal("a terminate published between the response side's check and its park was lost: " +
			"the response side is parked waiting for a wake that was already sent")
	}
}

// stagedRespConn is the upstream for the pipelining test below: it hands over
// the one response it has, but only once the test says so, and it reports its
// own close. Close is what the wake does to this connection, and a close while
// the response is in flight is exactly how a wake aimed at the wrong request
// truncates the answer that is on the wire -- so "the wake did not fire" is
// observable here rather than asserted: a closed connection never hands the
// response over at all.
type stagedRespConn struct {
	conn.Conn
	entered chan struct{}
	release chan struct{}
	closed  chan struct{}
	payload string

	enterOne sync.Once
	closeOne sync.Once
	sent     bool
}

func newStagedRespConn(payload string) *stagedRespConn {
	return &stagedRespConn{
		entered: make(chan struct{}),
		release: make(chan struct{}),
		closed:  make(chan struct{}),
		payload: payload,
	}
}

func (c *stagedRespConn) Read(p []byte) (int, error) {
	c.enterOne.Do(func() { close(c.entered) })
	select {
	case <-c.release:
	case <-c.closed:
		return 0, net.ErrClosed
	}
	if c.sent {
		return 0, io.EOF
	}
	c.sent = true
	return copy(p, c.payload), nil
}

func (c *stagedRespConn) Close() error {
	c.closeOne.Do(func() { close(c.closed) })
	return nil
}

// TestPipelinedTerminateAnswersItsOwnRequest (M4).
//
// Two requests on one connection, the second terminated by the hook. The
// terminate has to reach the response side as the answer to the second request:
// R1's answer is the origin's and is in flight, and R2's is the edge's and
// belongs after it. The old shape -- one terminate slot and a "the response
// side is parked" bit -- could not tell the two requests apart, so it delivered
// the synthetic answer in R1's slot and, worse, woke the response side by
// closing its source while R1's answer was still being read: the client got a
// refusal for a request that was allowed, and lost the body of a response that
// had already started.
//
// The generation keying is what makes this test possible: the response side
// parks for generation 1, the terminate carries generation 2, so the wake is
// not sent (the source is not closed, nothing in flight is truncated) and the
// terminate waits in the slot until the response side's turn 2 arrives. Both
// halves are asserted below -- the close that must not have happened while R1's
// answer is in flight, and the order of the two messages at the end.
func TestPipelinedTerminateAnswersItsOwnRequest(t *testing.T) {
	term := syntheticTermination()
	p := &Policy{RequestHook: func(r *http.Request) *RequestVerdict {
		if r.URL.Path == "/two" {
			return &RequestVerdict{Terminate: term}
		}
		return nil
	}}

	// R1's answer, chunk-framed so that there are body bytes after the head for
	// a truncating wake to cut off.
	r1 := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" +
		"7\r\nfirst: \r\n7\r\nsecond:\r\n5\r\nhello\r\n0\r\n\r\n"
	upstream := newStagedRespConn(r1)

	public := &fakeConn{
		src: strings.NewReader("GET /one HTTP/1.1\r\nHost: a.example\r\n\r\n" +
			"GET /two HTTP/1.1\r\nHost: a.example\r\n\r\n"),
		id: "http:public",
	}
	toUpstream, fromUpstream := NewConnPair(public, upstream, p)

	respOut := make(chan copyResult, 1)
	go func() {
		var b strings.Builder
		_, err := io.Copy(&b, fromUpstream)
		respOut <- copyResult{b.String(), err}
	}()

	// The response side parks in the read of R1's answer: the generation it is
	// parked on is 1.
	select {
	case <-upstream.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the response side never read its upstream")
	}

	// R1 goes to the origin, R2 is terminated. The terminate is published while
	// the response side is parked on R1.
	reqOut := drain(t, toUpstream)
	if reqOut != "GET /one HTTP/1.1\r\nHost: a.example\r\n\r\n" {
		t.Fatalf("R1 was not forwarded untouched: %q", reqOut)
	}

	// The wake must not have fired: a terminate for a later request is not this
	// request's answer, and closing this source would truncate R1's answer.
	select {
	case <-upstream.closed:
		t.Fatal("the wake closed the upstream for a terminate that answers a later request:" +
			" R1's response was in flight and its body is now truncated")
	default:
	}

	// Let R1's answer through. It has to come out first and whole, followed by
	// R2's synthetic.
	close(upstream.release)

	select {
	case got := <-respOut:
		if got.err != nil {
			t.Fatalf("the response side did not end cleanly: %v", got.err)
		}
		check(t, "response", got.out, r1+string(term.Render()))

		stream := newHTTPStream(t, strings.NewReader(got.out))
		first, firstBody := stream.next()
		if first.StatusCode != http.StatusOK || string(firstBody) != "first: second:hello" {
			t.Fatalf("R1's own response was not delivered for R1: %d %q", first.StatusCode, firstBody)
		}
		second, secondBody := stream.next()
		if second.StatusCode != term.StatusCode || string(secondBody) != term.Body {
			t.Fatalf("R2's synthetic response was not delivered for R2: %d %q", second.StatusCode, secondBody)
		}
		stream.done()
	case <-time.After(5 * time.Second):
		t.Fatal("the response side never produced R1's response and R2's synthetic response")
	}
}
