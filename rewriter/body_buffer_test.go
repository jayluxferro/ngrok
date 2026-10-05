package rewriter

import (
	"bufio"
	"bytes"
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

	"ngrok/conn"
)

// Tests for the deferred verdict (Policy.BodyBufferCap): the request head is
// held, the declared body is captured into pooled slabs, and the hook is asked
// once with the body in hand -- or with Body nil, the pinned "could not
// capture" signal (policy/webhook.go's bufferedBody is the production
// consumer). The byte-exactness bar is the package's own: what the upstream
// finally receives is what the client sent, head and body, whatever the
// capture did in between, and a policy without a cap never leaves the
// head-only path at all (the untouched existing suite is that proof; the last
// test here re-states it for the cap explicitly).

// patternBody is n bytes of deterministic, non-repeating-furthest content: a
// reordering, a lost slab or a duplicated slab shows up as a mismatch at the
// first wrong byte, not as an equal-length blur.
func patternBody(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte('a' + i%26)
	}
	return b
}

// captureRequest is a POST whose body the buffering path would capture.
func captureRequest(target string, body []byte) string {
	var b strings.Builder
	b.WriteString("POST " + target + " HTTP/1.1\r\n")
	b.WriteString("Host: a.example\r\n")
	b.WriteString("Content-Type: application/json\r\n")
	b.WriteString("Content-Length: " + strconv.Itoa(len(body)) + "\r\n")
	b.WriteString("\r\n")
	b.Write(body)
	return b.String()
}

// requestStream reads the request side's output the way the upstream would:
// net/http is the arbiter of "well-formed" here exactly as it is for the
// responses httpStream reads.
type requestStream struct {
	t  *testing.T
	br *bufio.Reader
}

func newRequestStream(t *testing.T, r io.Reader) *requestStream {
	t.Helper()
	return &requestStream{t: t, br: bufio.NewReader(r)}
}

// next reads one request and its body. Fully reading the body is what advances
// past the message, so two next() calls on one stream prove two whole requests
// arrived framed one after the other.
func (s *requestStream) next() (*http.Request, []byte) {
	s.t.Helper()
	req, err := http.ReadRequest(s.br)
	if err != nil {
		s.t.Fatalf("http.ReadRequest rejected the forwarded request: %v", err)
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		s.t.Fatalf("reading the forwarded body failed: %v", err)
	}
	req.Body.Close()
	return req, body
}

// drainByByte reads a rewriter to EOF one byte per Read -- the slowest reader
// there is, and the one that turns any boundary mistake (a duplicated byte, a
// lost one, a body byte emitted before its head was finished) into a visible
// mismatch at a specific offset.
func drainByByte(t *testing.T, r io.Reader) string {
	t.Helper()
	var b strings.Builder
	buf := make([]byte, 1)
	for i := 0; ; i++ {
		if i > 1<<24 {
			t.Fatal("drainByByte: runaway read loop")
		}
		n, err := r.Read(buf)
		b.Write(buf[:n])
		if err == io.EOF {
			return b.String()
		}
		if err != nil {
			t.Fatalf("reading the rewriter failed: %v", err)
		}
	}
}

// bufferingPolicy is a live-shaped policy with the deferred verdict armed: the
// X-Forwarded pair a real tunnel always carries, plus the cap and the hook.
func bufferingPolicy(cap int, hook func(*http.Request) *RequestVerdict) *Policy {
	return &Policy{
		ClientAddr:      "203.0.113.7",
		XForwardedProto: "http",
		BodyBufferCap:   cap,
		RequestHook:     hook,
	}
}

// rawBufferPolicy arms the deferred verdict with no static policy at all, so a
// forwarded head is re-emitted verbatim and a test's expected bytes are the
// input itself. The one capture test that asserts a rewritten head uses
// bufferingPolicy and spells the X-Forwarded lines out.
func rawBufferPolicy(cap int, hook func(*http.Request) *RequestVerdict) *Policy {
	return &Policy{
		BodyBufferCap: cap,
		RequestHook:   hook,
	}
}

// TestBodyBufferCapturesThenEmitsByteExact is the round trip the feature
// exists for: a body that spans slab boundaries (65 KiB plus an odd tail) is
// captured, the hook sees exactly the sent bytes, and the upstream receives
// the rewritten head followed by the body byte for byte -- read back one byte
// per Read, so the boundaries the capture crossed cannot hide. The head must
// come out with the policy applied (the X-Forwarded pair, in the position the
// static rewrite always puts it), not parroted from the held bytes.
func TestBodyBufferCapturesThenEmitsByteExact(t *testing.T) {
	body := patternBody(65536 + 4321)
	reqIn := captureRequest("/hook", body)

	var (
		calls     int
		hookBody  []byte
		hadReader bool
	)
	p := bufferingPolicy(1<<20, func(req *http.Request) *RequestVerdict {
		calls++
		hadReader = req.Body != nil
		if req.Body != nil {
			hookBody, _ = io.ReadAll(req.Body)
		}
		return nil
	})

	req, _ := NewPair(strings.NewReader(reqIn), strings.NewReader(""), p)
	got := drainByByte(t, req)

	if calls != 1 {
		t.Fatalf("the hook ran %d times for one request (want exactly 1)", calls)
	}
	if !hadReader {
		t.Fatal("the hook's request had a nil Body on the captured path")
	}
	if !bytes.Equal(hookBody, body) {
		t.Fatalf("the hook saw %d bytes, want the %d sent (first diff at %d)",
			len(hookBody), len(body), firstDiff(string(hookBody), string(body)))
	}
	want := "POST /hook HTTP/1.1\r\nHost: a.example\r\nContent-Type: application/json\r\n" +
		"Content-Length: " + strconv.Itoa(len(body)) + "\r\n" +
		"X-Forwarded-For: 203.0.113.7\r\nX-Forwarded-Proto: http\r\n\r\n" +
		string(body)
	check(t, "forwarded request", got, want)

	// net/http must accept the message the capture produced: the framing the
	// upstream parses is the one that matters.
	s := newRequestStream(t, strings.NewReader(got))
	gotReq, gotBody := s.next()
	if gotReq.Method != "POST" || gotReq.URL.Path != "/hook" {
		t.Fatalf("the forwarded request is not the one sent: %s %s", gotReq.Method, gotReq.URL.Path)
	}
	if !bytes.Equal(gotBody, body) {
		t.Fatalf("the forwarded body differs at byte %d", firstDiff(string(gotBody), string(body)))
	}
	if _, err := s.br.ReadByte(); err != io.EOF {
		t.Fatalf("bytes left over after the forwarded body: %v", err)
	}
}

// TestBodyBufferOverCapAsksWithNilBodyAndTerminates: a declared length over
// the cap is not captured, the hook is told so with a nil Body, and the
// verdict it returns -- the action's fixed 403, here as anywhere -- is
// carried out by the ordinary terminate plumbing. The upstream is never
// spoken to.
func TestBodyBufferOverCapAsksWithNilBodyAndTerminates(t *testing.T) {
	body := patternBody(100)
	reqIn := captureRequest("/hook", body)

	var gotNil bool
	term := &SyntheticResponse{
		StatusCode: http.StatusForbidden,
		Body:       "webhook-verification: the request failed stripe signature verification\n",
	}
	p := bufferingPolicy(16, func(req *http.Request) *RequestVerdict {
		gotNil = req.Body == nil
		return &RequestVerdict{Terminate: term}
	})

	req, resp := NewPair(strings.NewReader(reqIn), strings.NewReader(""), p)
	if out := drainByByte(t, req); out != "" {
		t.Fatalf("an over-cap request reached the upstream: %q", out)
	}
	if !gotNil {
		t.Fatal("the hook was not told the body could not be captured (Body was not nil)")
	}

	s := newHTTPStream(t, resp)
	got, respBody := s.next()
	if got.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", got.StatusCode)
	}
	if string(respBody) != term.Body {
		t.Fatalf("the fixed body was not emitted: %q", respBody)
	}
	s.done()
}

// TestBodyBufferOverCapAllowForwardsUnbuffered: the rewriter provides the
// body-or-nil and the action decides. A nil verdict on an uncapturable body
// forwards the request through the ordinary path -- copied by Content-Length,
// byte for byte -- which is what keeps the rewriter policy-agnostic.
func TestBodyBufferOverCapAllowForwardsUnbuffered(t *testing.T) {
	body := patternBody(100)
	reqIn := captureRequest("/hook", body)

	var gotNil bool
	p := rawBufferPolicy(16, func(req *http.Request) *RequestVerdict {
		gotNil = req.Body == nil
		return nil
	})

	req, _ := NewPair(strings.NewReader(reqIn), strings.NewReader(""), p)
	check(t, "allowed over-cap request", drainByByte(t, req), reqIn)
	if !gotNil {
		t.Fatal("the hook was not told the body could not be captured")
	}
}

// TestBodyBufferChunkedAsksWithNilBodyAndTerminates: v1 does not de-chunk, so
// a Transfer-Encoding body cannot be captured and the hook decides with a nil
// Body. (The bytes after the head are never looked at: the verdict is due
// before any chunk is parsed.)
func TestBodyBufferChunkedAsksWithNilBodyAndTerminates(t *testing.T) {
	reqIn := "POST /hook HTTP/1.1\r\nHost: a.example\r\n" +
		"Transfer-Encoding: chunked\r\n\r\n" + chunkBody("hello")

	var gotNil bool
	term := syntheticTermination()
	p := bufferingPolicy(1<<20, func(req *http.Request) *RequestVerdict {
		gotNil = req.Body == nil
		return &RequestVerdict{Terminate: term}
	})

	req, resp := NewPair(strings.NewReader(reqIn), strings.NewReader(""), p)
	if out := drainByByte(t, req); out != "" {
		t.Fatalf("a chunked request reached the upstream: %q", out)
	}
	if !gotNil {
		t.Fatal("the hook was not told the chunked body could not be captured")
	}

	s := newHTTPStream(t, resp)
	got, _ := s.next()
	if got.StatusCode != term.StatusCode {
		t.Fatalf("status = %d, want %d", got.StatusCode, term.StatusCode)
	}
	s.done()
}

// TestBodyBufferUpgradeAsksWithNilBodyAndTerminates: an upgrade request's
// "body" is the upgraded protocol itself, which no cap can frame; the hook is
// asked with a nil Body and its verdict rules. (Webhook traffic is plain
// POSTs; this is the fail-closed answer to the shape that is not one.)
func TestBodyBufferUpgradeAsksWithNilBodyAndTerminates(t *testing.T) {
	reqIn := "GET /ws HTTP/1.1\r\nHost: a.example\r\n" +
		"Connection: Upgrade\r\nUpgrade: websocket\r\n\r\n"

	var gotNil bool
	term := syntheticTermination()
	p := bufferingPolicy(1<<20, func(req *http.Request) *RequestVerdict {
		gotNil = req.Body == nil
		return &RequestVerdict{Terminate: term}
	})

	req, resp := NewPair(strings.NewReader(reqIn), strings.NewReader(""), p)
	if out := drainByByte(t, req); out != "" {
		t.Fatalf("an upgrade request reached the upstream under a buffering policy: %q", out)
	}
	if !gotNil {
		t.Fatal("the hook was not told the upgrade could not be captured")
	}

	s := newHTTPStream(t, resp)
	got, _ := s.next()
	if got.StatusCode != term.StatusCode {
		t.Fatalf("status = %d, want %d", got.StatusCode, term.StatusCode)
	}
	s.done()
}

// TestBodyBufferTerminateAfterCaptureWakesParkedResponseSide is the deferred
// verdict's version of the park race the terminate model was built for: the
// response side is already parked in a read of its upstream when the capture
// completes and the hook refuses. The terminate must still reach it through
// the wake, tagged with this request's generation -- buffering the body must
// not have disturbed either.
func TestBodyBufferTerminateAfterCaptureWakesParkedResponseSide(t *testing.T) {
	body := []byte("0123456789")
	reqIn := captureRequest("/maintenance", body)

	var sawBody string
	term := syntheticTermination()
	p := bufferingPolicy(1<<20, func(req *http.Request) *RequestVerdict {
		b, _ := io.ReadAll(req.Body)
		sawBody = string(b)
		return &RequestVerdict{Terminate: term}
	})

	public := &fakeConn{src: strings.NewReader(reqIn), id: "bufferwake:public"}
	upstream := newBlockingConn()
	toUpstream, fromUpstream := NewConnPair(public, upstream, p)

	// The response side reads only when its reader does, so the drain runs
	// first and the entered signal is what proves the read is parked -- the
	// same order the existing wake test uses.
	var b strings.Builder
	errc := make(chan error, 1)
	go func() {
		_, err := io.Copy(&b, fromUpstream)
		errc <- err
	}()
	<-upstream.entered

	if out := drainByByte(t, toUpstream); out != "" {
		t.Fatalf("the terminated request was forwarded: %q", out)
	}
	if sawBody != string(body) {
		t.Fatalf("the hook judged %q, want the captured %q", sawBody, body)
	}

	// The wake closes the response side's source; the copy ends with the
	// synthetic. The bound below is what makes a lost wake a failure rather
	// than a hang: a deadline-based fake would leave the read parked until
	// the blocking conn's own five-second give-up, and a test that only
	// waits for the bytes would pass on the bug (see the existing wake test
	// for the full argument).
	if err := waitCopy(t, &b, errc, string(term.Render())); err != nil {
		t.Fatalf("the parked response side did not get the terminate: %v", err)
	}
}

// waitCopy waits (bounded) for a copy to end and its output to be exactly
// what was expected.
func waitCopy(t *testing.T, b *strings.Builder, errc <-chan error, want string) error {
	t.Helper()
	select {
	case err := <-errc:
		if err != nil {
			return err
		}
		if b.String() != want {
			t.Fatalf("response mismatch:\n got %q\nwant %q", b.String(), want)
		}
		return nil
	case <-time.After(2 * time.Second):
		return errors.New("timed out waiting for the woken response side")
	}
}

// captureConn delivers one staged prefix and then parks every read until
// Close -- the shape of a live socket mid-body: bytes in flight, more
// promised by the Content-Length, sender still going. Close is what ends a
// parked read on the live path (conn.go's Close comment), so it is what ends
// one here.
type captureConn struct {
	conn.Conn
	prefix    []byte
	exhausted chan struct{}
	once      sync.Once
	closed    chan struct{}
	closeOnce sync.Once
	warned    []string
}

// Warn is the one log.Logger method the rewriter calls on a request-side
// source (the abandonment warning); like fakeConn's it records rather than
// panics into a nil embedded interface.
func (c *captureConn) Warn(format string, args ...interface{}) error {
	c.warned = append(c.warned, fmt.Sprintf(format, args...))
	return nil
}

func newCaptureConn(prefix string) *captureConn {
	return &captureConn{
		prefix:    []byte(prefix),
		exhausted: make(chan struct{}),
		closed:    make(chan struct{}),
	}
}

func (c *captureConn) Read(p []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		if len(c.prefix) == 0 {
			c.once.Do(func() { close(c.exhausted) })
		}
		return n, nil
	}
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	case <-time.After(5 * time.Second):
		return 0, errors.New("the mid-capture read was never woken")
	}
}

func (c *captureConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

// TestBodyBufferMidCaptureCloseReleasesSlabsExactlyOnce is the ownership
// proof for the capture: a connection closed mid-body abandons the capture,
// asks the hook without a body, and -- the point -- returns every slab it
// took (the capture's and the direction's own reader) to the pool exactly
// once, with no array ever in two owners' hands. 70000 captured bytes span
// two 64 KiB slabs, so the count is three: two capture slabs plus the
// request side's read buffer. (The response side never reads, so it never
// acquires one.)
func TestBodyBufferMidCaptureCloseReleasesSlabsExactlyOnce(t *testing.T) {
	const captured = 70000 // > 64 KiB: two slabs
	body := patternBody(200000)
	head := "POST /hook HTTP/1.1\r\nHost: a.example\r\nContent-Length: " +
		strconv.Itoa(len(body)) + "\r\n\r\n"
	prefix := head + string(body[:captured])

	pool := testPool()
	gets, puts := map[*byte]int{}, map[*byte]int{}

	var gotNil bool
	term := &SyntheticResponse{StatusCode: http.StatusForbidden, Body: "no body, no verdict\n"}
	p := bufferingPolicy(1<<20, func(req *http.Request) *RequestVerdict {
		gotNil = req.Body == nil
		return &RequestVerdict{Terminate: term}
	})

	withPool(t, pool, func() {
		testGetHook = func(b []byte) { gets[&b[0]]++ }
		testPutHook = func(b []byte) { puts[&b[0]]++ }
		defer func() { testGetHook, testPutHook = nil, nil }()

		public := newCaptureConn(prefix)
		upstream := &fakeConn{src: strings.NewReader(""), id: "midcapture:upstream"}
		toUpstream, fromUpstream := NewConnPair(public, upstream, p)

		reqOut := make(chan copyResult, 1)
		go func() {
			var b strings.Builder
			_, err := io.Copy(&b, toUpstream)
			reqOut <- copyResult{b.String(), err}
		}()

		// The prefix is consumed, the capture holds 70000 bytes, and the next
		// read is parked: this is mid-capture in the strongest sense.
		<-public.exhausted

		// The join's other goroutine closes the leg. Closing the request
		// side's source is what ends a parked read on the live path, so the
		// abandonment runs on the reading goroutine: slabs back, hook asked
		// with a nil Body, terminate published.
		toUpstream.Close()

		got := <-reqOut
		if got.out != "" {
			t.Fatalf("the abandoned request was forwarded: %q", got.out)
		}
		if !gotNil {
			t.Fatal("the hook was not told the capture was abandoned (Body was not nil)")
		}

		// The response side now takes the published terminate the ordinary
		// way and answers with it.
		respOut := make(chan copyResult, 1)
		go func() {
			var b strings.Builder
			_, err := io.Copy(&b, fromUpstream)
			respOut <- copyResult{b.String(), err}
		}()
		resp := <-respOut
		if resp.err != nil {
			t.Fatalf("the response side did not end cleanly: %v", resp.err)
		}
		check(t, "terminate after abandoned capture", resp.out, string(term.Render()))

		fromUpstream.Close()
	})

	// Three leases ended: the two capture slabs and the request side's reader
	// (its copy ended on the Close-induced error). The response side acquired
	// nothing: its terminate was already published when it entered the message,
	// so parkResponse handed it over before the first read and its read buffer
	// was never taken.
	checkSlabs(t, gets, puts, 3)
}

// TestBodyBufferCompleteCaptureReleasesSlabsExactlyOnce: the success path's
// release. A captured-and-forwarded request puts its slabs back when the
// verdict emits, and the directions' own readers go back at their Close, four
// leases in all -- the same exactly-once discipline, on the happy path.
func TestBodyBufferCompleteCaptureReleasesSlabsExactlyOnce(t *testing.T) {
	body := patternBody(70000)
	reqIn := captureRequest("/hook", body)
	respIn := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"

	pool := testPool()
	gets, puts := map[*byte]int{}, map[*byte]int{}

	withPool(t, pool, func() {
		testGetHook = func(b []byte) { gets[&b[0]]++ }
		testPutHook = func(b []byte) { puts[&b[0]]++ }
		defer func() { testGetHook, testPutHook = nil, nil }()

		public := &fakeConn{src: strings.NewReader(reqIn), id: "caprelease:public"}
		upstream := &fakeConn{src: strings.NewReader(respIn), id: "caprelease:upstream"}
		toUpstream, fromUpstream := NewConnPair(public, upstream, bufferingPolicy(1<<20,
			func(*http.Request) *RequestVerdict { return nil }))
		drain(t, toUpstream)
		drain(t, fromUpstream)
		for i := 0; i < 3; i++ {
			toUpstream.Close()
			fromUpstream.Close()
		}
	})

	// Four leases ended -- two capture slabs, one read buffer per direction --
	// so four Gets and four Puts, and every array back to zero: no double Put
	// from the three repeated Closes, no array still held. (One observer, not
	// putRecorder stacked on ownershipTracker: both install testPutHook, and
	// the second start would silence the first's decrements.)
	checkSlabs(t, gets, puts, 4)
}

// checkSlabs asserts the pool accounting a slab test is about: exactly n
// leases (Gets) and n releases (Puts), and every array that ever circulated
// ending at zero -- neither shared while live nor lost on exit.
func checkSlabs(t *testing.T, gets, puts map[*byte]int, n int) {
	t.Helper()
	getTotal, putTotal := 0, 0
	for _, v := range gets {
		getTotal += v
	}
	for _, v := range puts {
		putTotal += v
	}
	if getTotal != n || putTotal != n {
		t.Fatalf("%d buffer leases ended with %d releases (want %d of each)", getTotal, putTotal, n)
	}
	for slab, got := range gets {
		if put := puts[slab]; got != put {
			t.Fatalf("slab %p was acquired %d times but released %d", slab, got, put)
		}
	}
}

// TestBodyBufferPipelinedSecondRequest: the state machine must come all the
// way back. Request 2's head re-enters the same deferred logic after request
// 1's verdict emitted, and its body is captured as its own -- two requests,
// two verdicts, one stream, no byte crossed between them.
func TestBodyBufferPipelinedSecondRequest(t *testing.T) {
	body1 := []byte("0123456789")
	body2 := []byte("abcde")
	reqIn := captureRequest("/first", body1) + captureRequest("/second", body2)

	var (
		calls  int
		paths  []string
		bodies []string
	)
	p := rawBufferPolicy(1<<20, func(req *http.Request) *RequestVerdict {
		calls++
		paths = append(paths, req.URL.Path)
		b, _ := io.ReadAll(req.Body)
		bodies = append(bodies, string(b))
		return nil
	})

	req, _ := NewPair(strings.NewReader(reqIn), strings.NewReader(""), p)
	check(t, "pipelined requests", drainByByte(t, req), reqIn)

	if calls != 2 {
		t.Fatalf("the hook ran %d times for two requests", calls)
	}
	if paths[0] != "/first" || paths[1] != "/second" {
		t.Fatalf("the hook saw the requests out of order: %v", paths)
	}
	if string(bodies[0]) != string(body1) || string(bodies[1]) != string(body2) {
		t.Fatalf("the hook saw bodies %q and %q, want %q and %q",
			bodies[0], bodies[1], body1, body2)
	}

	// Both messages must frame cleanly for the upstream, one after the other.
	s := newRequestStream(t, strings.NewReader(reqIn))
	if _, b := s.next(); string(b) != string(body1) {
		t.Fatalf("first body forwarded as %q", b)
	}
	if _, b := s.next(); string(b) != string(body2) {
		t.Fatalf("second body forwarded as %q", b)
	}
}

// TestBodyBufferEmptyContentLengthIsCapturedNotNil: a declared Content-Length
// of zero is fully captured -- there is nothing to wait for -- so the hook's
// Body is non-nil and empty. nil is reserved for "could not capture"; an
// action must be able to tell an empty body it judged from one it never saw.
func TestBodyBufferEmptyContentLengthIsCapturedNotNil(t *testing.T) {
	reqIn := "POST /ping HTTP/1.1\r\nHost: a.example\r\nContent-Length: 0\r\n\r\n"

	var (
		hadBody   bool
		readEmpty bool
	)
	p := rawBufferPolicy(1<<20, func(req *http.Request) *RequestVerdict {
		hadBody = req.Body != nil
		if req.Body != nil {
			b, _ := io.ReadAll(req.Body)
			readEmpty = len(b) == 0
		}
		return nil
	})

	req, _ := NewPair(strings.NewReader(reqIn), strings.NewReader(""), p)
	check(t, "empty-body request", drainByByte(t, req), reqIn)
	if !hadBody || !readEmpty {
		t.Fatalf("a Content-Length: 0 body looked uncaptured (body present: %v, empty: %v)", hadBody, readEmpty)
	}
}

// TestBodyBufferTruncatedSourceAsksWithNilBodyAndTerminates: a stream that
// ends before its declared length cannot deliver the body the verdict is
// about. The capture is abandoned, the hook is asked with a nil Body -- the
// same finding as every other uncapturable shape -- and a refusing verdict is
// carried out normally. The upstream sees nothing.
func TestBodyBufferTruncatedSourceAsksWithNilBodyAndTerminates(t *testing.T) {
	reqIn := "POST /hook HTTP/1.1\r\nHost: a.example\r\nContent-Length: 100\r\n\r\n" +
		string(patternBody(10))

	var gotNil bool
	term := syntheticTermination()
	p := bufferingPolicy(1<<20, func(req *http.Request) *RequestVerdict {
		gotNil = req.Body == nil
		return &RequestVerdict{Terminate: term}
	})

	req, resp := NewPair(strings.NewReader(reqIn), strings.NewReader(""), p)
	if out := drainByByte(t, req); out != "" {
		t.Fatalf("a truncated request was forwarded: %q", out)
	}
	if !gotNil {
		t.Fatal("the hook was not told the capture was abandoned")
	}

	s := newHTTPStream(t, resp)
	got, _ := s.next()
	if got.StatusCode != term.StatusCode {
		t.Fatalf("status = %d, want %d", got.StatusCode, term.StatusCode)
	}
	s.done()
}

// TestBodyBufferTruncatedAllowForwardsWhatArrived: the other half of the
// abandonment. A hook that declines to refuse a truncated body gets the
// request forwarded with whatever arrived -- head first, then the partial
// body -- and the rest truncates exactly as the ordinary Content-Length path
// would have truncated it. No byte of what was captured may be lost: those
// bytes left the reader's buffer the moment they were banked.
func TestBodyBufferTruncatedAllowForwardsWhatArrived(t *testing.T) {
	partial := patternBody(10)
	reqIn := "POST /hook HTTP/1.1\r\nHost: a.example\r\nContent-Length: 100\r\n\r\n" +
		string(partial)

	var gotNil bool
	p := rawBufferPolicy(1<<20, func(req *http.Request) *RequestVerdict {
		gotNil = req.Body == nil
		return nil
	})

	req, _ := NewPair(strings.NewReader(reqIn), strings.NewReader(""), p)
	check(t, "truncated request, allowed", drainByByte(t, req), reqIn)
	if !gotNil {
		t.Fatal("the hook was not told the capture was abandoned")
	}
}

// TestBodyBufferZeroCapIsHeadOnly is the zero-cost proof restated: a policy
// that carries the default cap (zero) with a hook produces byte-identical
// output to the same policy without the field at all. Every existing hook
// test is this claim exercised one shape at a time; this is the A/B.
func TestBodyBufferZeroCapIsHeadOnly(t *testing.T) {
	reqIn := captureRequest("/hook", patternBody(64))
	respIn := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"

	hook := func(*http.Request) *RequestVerdict { return nil }
	base := tunnelPolicy()

	withCap := *base
	withCap.RequestHook = hook

	gotReqA, gotRespA := pair(t, &withCap, reqIn, respIn)
	gotReqB, gotRespB := pair(t, base, reqIn, respIn)
	check(t, "request with cap 0", gotReqA, gotReqB)
	check(t, "response with cap 0", gotRespA, gotRespB)
}

// TestBodyBufferValidateRefusesNegativeCap: a cap a caller cannot mean is a
// load-time error, not a silent compile-down to "no buffering" that would
// 403 every webhook later. Zero stays legal -- it is the default.
func TestBodyBufferValidateRefusesNegativeCap(t *testing.T) {
	p := tunnelPolicy()
	if err := p.Validate(); err != nil {
		t.Fatalf("the default policy does not validate: %v", err)
	}
	p.BodyBufferCap = -1
	if err := p.Validate(); err == nil {
		t.Fatal("a negative BodyBufferCap validated")
	}
}
