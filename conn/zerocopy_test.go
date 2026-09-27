package conn

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

// The two methods zerocopy.go adds are what io.Copy looks for before it stages
// anything, so a change that quietly lost one of them would leave every test in
// this file passing while the data path silently went back to a userspace loop.
// Assert the interfaces at compile time: this file does not build without them.
var (
	_ io.ReaderFrom = (*loggedConn)(nil)
	_ io.WriterTo   = (*loggedConn)(nil)
)

// testTimeout bounds every blocking step in this file. The payloads are a few
// hundred KiB over loopback and the copies take milliseconds, so a step that
// reaches this bound is a hang -- the failure mode the writeOnly/readOnly
// wrappers in zerocopy.go exist to prevent is a copy that re-enters itself --
// and it should fail the test instead of wedging the suite.
const testTimeout = 5 * time.Second

// pattern returns n deterministic, non-repeating bytes. Non-repeating matters:
// uniform filler would hide a copy that dropped, duplicated or reordered a
// chunk, which is exactly what these tests are looking for.
func pattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*31 + i/251)
	}
	return b
}

// ioResult is one end's half of a copy: the bytes a read produced, or the
// outcome of a write. Both directions of a join run at once and net.Pipe writes
// block until read, so every pump below runs in its own goroutine and reports
// back here rather than calling t.Fatalf from a goroutine that is not the
// test's.
type ioResult struct {
	buf []byte
	n   int
	err error
}

// pumpWrite writes payload from its own goroutine, and closes w afterwards when
// closeAfter is set -- that close is how the copy under test learns the peer is
// done and its read side should see EOF.
func pumpWrite(w io.Writer, payload []byte, closeAfter bool) <-chan ioResult {
	done := make(chan ioResult, 1)
	go func() {
		n, err := w.Write(payload)
		if closeAfter {
			if c, ok := w.(io.Closer); ok {
				c.Close()
			}
		}
		done <- ioResult{n: n, err: err}
	}()
	return done
}

// pumpRead reads exactly n bytes from r, which is the only way to notice a copy
// that stalls partway through.
func pumpRead(r io.Reader, n int) <-chan ioResult {
	done := make(chan ioResult, 1)
	go func() {
		buf := make([]byte, n)
		got, err := io.ReadFull(r, buf)
		done <- ioResult{buf: buf[:got], n: got, err: err}
	}()
	return done
}

// waitFor blocks until ch delivers, and fails the test if that takes longer
// than testTimeout.
func waitFor[T any](t *testing.T, what string, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(testTimeout):
		var zero T
		t.Fatalf("%s did not finish within %s; a copy re-entering itself hangs exactly like this", what, testTimeout)
		return zero
	}
}

// newLeg returns the two ends of one proxied leg: near, which the code under
// test gets, and far, which the test writes to and reads from.
//
// kind picks the transport, and with it the branch under test. "pipe" is a
// net.Pipe pair: it is not a *net.TCPConn, so the generic fallbacks in
// zerocopy.go run. "tcp" is a real loopback socket: the net package's own
// ReadFrom/WriteTo run, which is the Linux splice path.
func newLeg(t *testing.T, kind string) (near *loggedConn, far net.Conn) {
	t.Helper()

	switch kind {
	case "pipe":
		nearRaw, farRaw := net.Pipe()
		near, far = Wrap(nearRaw, "test"), farRaw
	case "tcp":
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen on loopback: %v", err)
		}
		defer ln.Close()

		type accepted struct {
			conn net.Conn
			err  error
		}
		acceptedCh := make(chan accepted, 1)
		go func() {
			c, err := ln.Accept()
			acceptedCh <- accepted{c, err}
		}()

		dialed, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("dial %s: %v", ln.Addr(), err)
		}
		res := waitFor(t, "loopback accept", acceptedCh)
		if res.err != nil {
			t.Fatalf("accept on %s: %v", ln.Addr(), res.err)
		}
		near, far = Wrap(dialed, "test"), res.conn
	default:
		t.Fatalf("unknown leg kind %q", kind)
	}

	// Deadlines on every end: without them a copy that never returns leaves the
	// far end blocked forever and the suite hangs instead of failing.
	deadline := time.Now().Add(testTimeout)
	for _, c := range []net.Conn{near, far} {
		if err := c.SetDeadline(deadline); err != nil {
			t.Fatalf("set deadline on %s leg: %v", kind, err)
		}
	}

	t.Cleanup(func() {
		near.Close()
		far.Close()
	})
	return near, far
}

// tcpPair is one loopback connection with BOTH of its ends wrapped, for the
// tests that hand a wrapper to ReadFrom or WriteTo directly rather than through
// a join.
func tcpPair(t *testing.T) (near, far *loggedConn) {
	t.Helper()

	nearEnd, farRaw := newLeg(t, "tcp")
	return nearEnd, Wrap(farRaw, "far")
}

// plainConn presents a conn.Conn through a type that exposes only what the
// conn.Conn interface declares, hiding ReadFrom and WriterTo with it. That is
// not an artificial shape: rewriter's filteredConn embeds the interface the
// same way, and so does this repo's own proxyTestConn, so this is what Join is
// handed for every HTTP tunnel that has header rewriting turned on. It is also
// the only shape that makes io.Copy fall past WriterTo/ReaderFrom and stage
// through the buffer Join hands it.
type plainConn struct {
	Conn
}

// TestReadFromDelegatesToTCPConn pins the branch that matters: a wrapper around
// a plain socket hands the copy to (*net.TCPConn).ReadFrom, which on Linux is
// where splice(2) lives. Whether this particular test splices is not asserted --
// that depends on the source also being a socket and cannot be observed
// portably -- but the branch, the count and the bytes are.
func TestReadFromDelegatesToTCPConn(t *testing.T) {
	dst, dstFar := tcpPair(t) // bytes are copied INTO dst
	src, srcFar := tcpPair(t) // and read OUT OF src

	for name, c := range map[string]*loggedConn{"dst": dst, "src": src} {
		if _, ok := c.Conn.(*net.TCPConn); !ok {
			t.Fatalf("%s wraps %T, want *net.TCPConn -- the delegation is the point of this test", name, c.Conn)
		}
	}

	// 300 KiB crosses the 256 KiB staging size, so the copy has to handle more
	// than one fill of its buffer rather than getting the whole payload in one
	// Read.
	payload := pattern(300*1024 + 7)

	sent := pumpWrite(srcFar, payload, true) // then EOF
	got := pumpRead(dstFar, len(payload))

	n, err := dst.ReadFrom(src)
	if err != nil {
		t.Fatalf("ReadFrom: %v after %d bytes", err, n)
	}
	if n != int64(len(payload)) {
		t.Fatalf("ReadFrom copied %d bytes, want %d", n, len(payload))
	}

	if res := waitFor(t, "write into srcFar", sent); res.err != nil || res.n != len(payload) {
		t.Fatalf("writing into the source: n=%d err=%v", res.n, res.err)
	}
	if res := waitFor(t, "read from dstFar", got); res.err != nil || !bytes.Equal(res.buf, payload) {
		t.Fatalf("bytes did not survive the copy: n=%d err=%v", res.n, res.err)
	}
}

// TestWriteToDelegatesToTCPConn is the mirror image: the wrapper is the source
// and the net package is asked to write it out.
func TestWriteToDelegatesToTCPConn(t *testing.T) {
	src, srcFar := tcpPair(t) // bytes are read OUT OF src
	dst, dstFar := tcpPair(t) // and written INTO dst

	for name, c := range map[string]*loggedConn{"src": src, "dst": dst} {
		if _, ok := c.Conn.(*net.TCPConn); !ok {
			t.Fatalf("%s wraps %T, want *net.TCPConn -- the delegation is the point of this test", name, c.Conn)
		}
	}

	payload := pattern(300*1024 + 7)

	sent := pumpWrite(srcFar, payload, true) // then EOF
	got := pumpRead(dstFar, len(payload))

	n, err := src.WriteTo(dst)
	if err != nil {
		t.Fatalf("WriteTo: %v after %d bytes", err, n)
	}
	if n != int64(len(payload)) {
		t.Fatalf("WriteTo copied %d bytes, want %d", n, len(payload))
	}

	if res := waitFor(t, "write into srcFar", sent); res.err != nil || res.n != len(payload) {
		t.Fatalf("writing into the source: n=%d err=%v", res.n, res.err)
	}
	if res := waitFor(t, "read from dstFar", got); res.err != nil || !bytes.Equal(res.buf, payload) {
		t.Fatalf("bytes did not survive the copy: n=%d err=%v", res.n, res.err)
	}
}

// TestGenericFallbackDoesNotRecurse covers the other branch of both methods: an
// underlying conn that is not a *net.TCPConn. net.Pipe stands in for the real
// cases -- TLS legs and smux streams -- which cannot be built without their own
// machinery.
//
// The sources are deliberately readers with no WriteTo of their own. io.Copy
// checks its destination for io.ReaderFrom before it does anything else, so a
// fallback written as a bare io.Copy(c, r) would call straight back into
// ReadFrom and spin until the stack ran out; the writeOnly/readOnly wrappers
// are what stop that, and a regression shows up here as a stack overflow or a
// hang rather than as a wrong answer.
func TestGenericFallbackDoesNotRecurse(t *testing.T) {
	t.Run("ReadFrom", func(t *testing.T) {
		wrapped, farRaw := newLeg(t, "pipe")
		if _, ok := wrapped.Conn.(*net.TCPConn); ok {
			t.Fatal("net.Pipe is a *net.TCPConn; this test would not cover the fallback")
		}

		payload := pattern(64*1024 + 3)
		source := io.LimitReader(bytes.NewReader(payload), int64(len(payload)))

		got := pumpRead(farRaw, len(payload))
		n, err := wrapped.ReadFrom(source)
		if err != nil {
			t.Fatalf("ReadFrom: %v after %d bytes", err, n)
		}
		if n != int64(len(payload)) {
			t.Fatalf("ReadFrom copied %d bytes, want %d", n, len(payload))
		}
		if res := waitFor(t, "read from the pipe", got); res.err != nil || !bytes.Equal(res.buf, payload) {
			t.Fatalf("bytes did not survive the copy: n=%d err=%v", res.n, res.err)
		}
	})

	t.Run("WriteTo", func(t *testing.T) {
		wrapped, farRaw := newLeg(t, "pipe")
		if _, ok := wrapped.Conn.(*net.TCPConn); ok {
			t.Fatal("net.Pipe is a *net.TCPConn; this test would not cover the fallback")
		}

		payload := pattern(64*1024 + 3)
		sent := pumpWrite(farRaw, payload, true) // then EOF

		var sink bytes.Buffer
		n, err := wrapped.WriteTo(&sink)
		if err != nil {
			t.Fatalf("WriteTo: %v after %d bytes", err, n)
		}
		if n != int64(len(payload)) {
			t.Fatalf("WriteTo copied %d bytes, want %d", n, len(payload))
		}
		if res := waitFor(t, "write into the pipe", sent); res.err != nil || res.n != len(payload) {
			t.Fatalf("writing into the pipe: n=%d err=%v", res.n, res.err)
		}
		if !bytes.Equal(sink.Bytes(), payload) {
			t.Fatalf("bytes did not survive the copy: got %d bytes", sink.Len())
		}
	})
}

// joinResult is what Join reported once both directions had stopped. Join's
// first return value is the bytes it copied into its first argument from its
// second (client/model.go counts on that order), so the fields are named for
// position and checked against the direction the test drove.
type joinResult struct {
	firstBytes, secondBytes int64
}

// TestJoinCopiesBothWaysAndCountsBytes keeps Join's contract -- bytes in both
// directions, counts reported per direction, both ends closed -- honest on the
// two leg shapes that reach it without header rewriting: net.Pipe-backed
// wrappers (the generic fallbacks) and loopback sockets (the delegation, which
// on Linux is the splice path).
func TestJoinCopiesBothWaysAndCountsBytes(t *testing.T) {
	t.Run("pipe", func(t *testing.T) { runJoinCase(t, "pipe", false) })
	t.Run("tcp", func(t *testing.T) { runJoinCase(t, "tcp", false) })
}

// TestJoinStagingBufferIsNotShared is the same join as the "pipe" case above
// with the property spelled out, because this is the shape that breaks if
// Join's staging buffer is one process-wide slice: rewriter.filteredConn hides
// ReadFrom/WriterTo exactly like plainConn does, so io.CopyBuffer stages every
// read through the buffer it is given, in BOTH directions at once, and two
// copies sharing one slice overwrite each other's in-flight bytes. Under -race
// that is a data race here; without it, corrupted payloads.
//
// This test is what caught the first version of that buffer, which was one
// package-level slice: -race reported both join goroutines reading into it at
// once. It stays as the guard on the pool that replaced it.
func TestJoinStagingBufferIsNotShared(t *testing.T) {
	runJoinCase(t, "pipe", true)
}

// runJoinCase joins two legs and drives all four of their ends at once: bytes
// into a's far end, out of b's far end, and the same the other way. Concurrent
// rather than alternating, because that is what a real connection does and what
// makes both directions run through the copy path simultaneously.
func runJoinCase(t *testing.T, kind string, hideInterfaces bool) {
	t.Helper()

	nearA, aFar := newLeg(t, kind)
	nearB, bFar := newLeg(t, kind)

	var a, b Conn = nearA, nearB
	if hideInterfaces {
		a, b = plainConn{nearA}, plainConn{nearB}
	}

	// Two payloads of different lengths and different contents: the counts Join
	// reports are checked against them, so a direction reported backwards, or a
	// copy that moved the wrong bytes, cannot pass.
	first := pattern(200*1024 + 13) // a -> b
	second := pattern(100*1024 + 5) // b -> a

	joined := make(chan joinResult, 1)
	go func() {
		firstBytes, secondBytes := Join(a, b)
		joined <- joinResult{firstBytes: firstBytes, secondBytes: secondBytes}
	}()

	sentFirst := pumpWrite(aFar, first, false)
	gotFirst := pumpRead(bFar, len(first))
	sentSecond := pumpWrite(bFar, second, false)
	gotSecond := pumpRead(aFar, len(second))

	if res := waitFor(t, "write into a's far end", sentFirst); res.err != nil || res.n != len(first) {
		t.Fatalf("writing the first payload: n=%d err=%v", res.n, res.err)
	}
	if res := waitFor(t, "read from b's far end", gotFirst); res.err != nil || !bytes.Equal(res.buf, first) {
		t.Fatalf("first payload did not survive the join: n=%d err=%v", res.n, res.err)
	}
	if res := waitFor(t, "write into b's far end", sentSecond); res.err != nil || res.n != len(second) {
		t.Fatalf("writing the second payload: n=%d err=%v", res.n, res.err)
	}
	if res := waitFor(t, "read from a's far end", gotSecond); res.err != nil || !bytes.Equal(res.buf, second) {
		t.Fatalf("second payload did not survive the join: n=%d err=%v", res.n, res.err)
	}

	// Closing the far ends is what ends the copies: Join closes the ends it was
	// given, and the test closes the ones it still owns.
	aFar.Close()
	bFar.Close()

	res := waitFor(t, "Join returning", joined)
	if res.secondBytes != int64(len(first)) {
		t.Errorf("Join reported %d bytes a->b, want %d", res.secondBytes, len(first))
	}
	if res.firstBytes != int64(len(second)) {
		t.Errorf("Join reported %d bytes b->a, want %d", res.firstBytes, len(second))
	}
}
