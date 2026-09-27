package rewriter

import (
	"bytes"
	"fmt"
	"io"
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
