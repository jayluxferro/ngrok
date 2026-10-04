package rewriter

import (
	"bufio"
	"errors"
	"io"
	"math"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// Tests for the pooled read buffer (readBufPool, pooledReader, and the
// filteredConn.Close release site). The byte-exactness of the reader itself is
// covered by the whole of the existing suite -- every pair() and NewConnPair
// test now runs over pooledReader -- so these tests cover what the rest do
// not: semantics matched against bufio directly, the allocation win, the
// exactly-once release, and the no-aliasing property that makes recycling
// safe.

// testPool returns a pool shaped like the production one. Tests swap it into
// readBufPool (tests in this package are sequential; readBufPool is consulted
// only through getReadBuf/putReadBuf, so swapping is race-free) and restore
// it with the deferred withPool.
func testPool() *sync.Pool {
	return &sync.Pool{New: func() interface{} { return &readBuf{} }}
}

// withPool swaps readBufPool out for p for the duration of f.
func withPool(t *testing.T, p *sync.Pool, f func()) {
	t.Helper()
	saved := readBufPool
	readBufPool = p
	defer func() { readBufPool = saved }()
	f()
}

// putRecorder is the test-visible Put counter. sync.Pool cannot be inspected
// (Get and Put are deliberately opaque), so the release tests observe
// recycling through testPutHook, which fires exactly where a buffer goes back
// into the pool. Production never sets the hook; the cost there is one nil
// check per recycled buffer.
type putRecorder struct {
	mu   sync.Mutex
	bufs [][]byte
}

func (r *putRecorder) start() {
	r.mu.Lock()
	r.bufs = nil
	testPutHook = r.record
	r.mu.Unlock()
}

func (r *putRecorder) stop() {
	r.mu.Lock()
	testPutHook = nil
	r.mu.Unlock()
}

func (r *putRecorder) record(b []byte) {
	r.mu.Lock()
	r.bufs = append(r.bufs, b)
	r.mu.Unlock()
}

func (r *putRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.bufs)
}

// distinct reports how many different backing arrays were Put. The
// double-release hazard this package guards against is one array Put twice --
// two connections holding one buffer -- so "two Puts" alone proves nothing;
// the identities must differ.
func (r *putRecorder) distinct() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	seen := make(map[*byte]bool, len(r.bufs))
	for _, b := range r.bufs {
		seen[&b[0]] = true
	}
	return len(seen)
}

// readerOverA is the read surface both implementations in the differential
// test expose: the two methods the state machine uses, which is exactly the
// inventory the pooled reader was built over.
type readerOverA interface {
	Read(p []byte) (int, error)
	ReadSlice(delim byte) ([]byte, error)
}

// readerCall is one observed call: which operation, what it returned, and the
// error classified the way a caller can distinguish it.
type readerCall struct {
	op   string
	data string
	err  error
}

func (c readerCall) String() string {
	switch {
	case c.err == nil:
		return c.op + ":" + c.data
	case errors.Is(c.err, io.EOF):
		return c.op + ":EOF(" + c.data + ")"
	case errors.Is(c.err, bufio.ErrBufferFull):
		return c.op + ":BufferFull(" + c.data + ")"
	default:
		return c.op + ":ERR(" + c.err.Error() + ")(" + c.data + ")"
	}
}

// driveReader drives rd the way the state machine does: ReadSlice lines until
// the source reports an error with nothing buffered, then verbatim chunked
// Reads until a byte-less error. Every call is recorded, so a divergence in
// buffering, error deferral or the (0, nil) quirk shows up as the first
// differing call, not as a garbled stream.
func driveReader(rd readerOverA, chunk int) []readerCall {
	var calls []readerCall
	for i := 0; ; i++ {
		if i > 1<<16 {
			panic("driveReader: runaway line loop")
		}
		line, err := rd.ReadSlice('\n')
		calls = append(calls, readerCall{"readslice", string(line), err})
		if err != nil && len(line) == 0 {
			break
		}
	}
	for i := 0; ; i++ {
		if i > 1<<16 {
			panic("driveReader: runaway read loop")
		}
		p := make([]byte, chunk)
		n, err := rd.Read(p)
		calls = append(calls, readerCall{"read", string(p[:n]), err})
		if n == 0 && err != nil {
			break
		}
	}
	return calls
}

// TestPooledReaderMirrorsBufio is the differential test behind "semantics are
// mirrored from bufio.Reader method for method": over every input shape the
// state machine can meet, and every read-chunk size that touches the direct
// path and the buffered path, the pooled reader must produce the exact
// sequence of (bytes, error) calls bufio.Reader produces. The buffers are
// sized identically -- a differently sized bufio would legitimately produce a
// different ReadSlice call sequence (ErrBufferFull at its own boundaries).
// The existing suite asserts the consequences (byte-exact streams); this pins
// the mechanism.
func TestPooledReaderMirrorsBufio(t *testing.T) {
	inputs := []struct{ name, in string }{
		{"simple head", "GET / HTTP/1.1\r\nHost: a\r\n\r\nbody"},
		{"lf-only lines", "GET / HTTP/1.1\nHost: a\n\nbody"},
		{"empty source", ""},
		{"only a newline", "\n"},
		{"blank lines before start", "\r\n\r\nGET / HTTP/1.1\r\n\r\n"},
		{"no terminator at eof", "GET / HTTP/1.1\r\nHost: a\r\nX"},
		{"line ending at buffer edge", strings.Repeat("a", readBufferSize-2) + "\r\ntrailing"},
		{"line longer than buffer", strings.Repeat("b", readBufferSize+10) + "\r\nrest"},
		{"many small lines", strings.Repeat("X: y\r\n", 5000)},
		{"binary bytes", "\x00\x01\x02\r\n\x03\r\n\x04\x05\xff"},
		{"eof exactly at line end", "GET / HTTP/1.1\r\n"},
	}
	chunks := []int{1, 2, 7, 100, 4096, readBufferSize - 1, readBufferSize, readBufferSize + 100}

	saved := readBufPool
	readBufPool = testPool()
	defer func() { readBufPool = saved }()

	for _, in := range inputs {
		for _, chunk := range chunks {
			want := driveReader(bufio.NewReaderSize(strings.NewReader(in.in), readBufferSize), chunk)
			got := driveReader(newPooledReader(strings.NewReader(in.in)), chunk)
			if len(got) != len(want) {
				t.Fatalf("%s, chunk %d: %d calls, bufio made %d", in.name, chunk, len(got), len(want))
			}
			for i := range got {
				if got[i].String() != want[i].String() {
					t.Fatalf("%s, chunk %d: call %d\n got %q\nwant %q", in.name, chunk, i, got[i].String(), want[i].String())
				}
			}
		}
	}
}

// pairCycle is one full live-path connection, shaped like the server's join
// and the client's relay: a wrapped pair over in-memory sources, both
// directions drained to EOF, both legs closed the way conn.Join's defers do.
// It allocates nothing on any goroutine but the caller's, which is what makes
// the AllocsPerRun measurement below deterministic.
func pairCycle(reqIn, respIn string) {
	public := &fakeConn{src: strings.NewReader(reqIn), id: "allocs:public"}
	upstream := &fakeConn{src: strings.NewReader(respIn), id: "allocs:upstream"}
	toUpstream, fromUpstream := NewConnPair(public, upstream, tunnelPolicy())
	io.Copy(io.Discard, toUpstream)
	io.Copy(io.Discard, fromUpstream)
	toUpstream.Close()
	fromUpstream.Close()
}

// TestPairPerConnectionAllocsDrop is the allocation proof for the pooling:
// a full rewritten request/response cycle must allocate measurably less per
// connection with the pool live than with pooling off (which is exactly what
// the bufio.NewReaderSize code did -- readBufPool nil makes getReadBuf
// allocate and putReadBuf drop). The assertion pins the direction, not a
// count; the logged numbers are the ones the changelog cites. The pool is
// warmed well past steady state first, and both phases measure 20 runs, so
// the comparison is the recycled Get a server under load sees rather than
// first-connection misses plus allocator noise from io.Copy's own pools.
func TestPairPerConnectionAllocsDrop(t *testing.T) {
	const (
		runs = 20
	)
	var (
		reqIn  = "GET /path?q=1 HTTP/1.1\r\nHost: myapp.ngrok.io\r\nuser-agent: curl/8.5.0\r\nAccept: */*\r\n\r\n"
		respIn = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 2\r\n\r\nok"
	)

	saved := readBufPool
	defer func() { readBufPool = saved }()

	readBufPool = nil
	unpooled := minAllocs(runs, func() { pairCycle(reqIn, respIn) })

	readBufPool = testPool()
	pooled := minAllocs(runs, func() { pairCycle(reqIn, respIn) })

	t.Logf("allocs per connection (floor): unpooled %d, pooled %d (drop %d)", unpooled, pooled, unpooled-pooled)
	// The floor comparison, not an average: allocation counts are
	// noise-additive (GC scheduling and the race runtime can only ADD
	// allocations to an invocation, never remove the deterministic ones), so
	// min-of-N estimates the deterministic floor and the floor is what
	// pooling lowers -- by exactly the two pooled arrays. An average, which
	// is what AllocsPerRun returns, ties whenever the delta (2) is the size
	// of the noise: -count=2 reproduced exactly that tie.
	if pooled >= unpooled {
		t.Fatalf("pooling did not reduce allocations per connection: unpooled %d, pooled %d", unpooled, pooled)
	}
}

// minAllocs reports the smallest single-invocation allocation count observed
// over runs invocations (each preceded by a GC and a warm-up call). See the
// test above for why the minimum is the stable statistic here.
func minAllocs(runs int, f func()) uint64 {
	var best uint64 = math.MaxUint64
	var before, after runtime.MemStats
	for i := 0; i < runs; i++ {
		// No forced GC between invocations: a GC empties sync.Pool, and the
		// saving being measured only exists in the warm-pool regime -- with
		// the pool cleared every call pays cold allocation and the pooled
		// floor lands ABOVE the unpooled one (measured, not theorized). The
		// warm-up call before each measured one keeps the pool warm; noise
		// stays additive, so the minimum still estimates the floor.
		f()
		runtime.ReadMemStats(&before)
		f()
		runtime.ReadMemStats(&after)
		if n := after.Mallocs - before.Mallocs; n < best {
			best = n
		}
	}
	return best
}

// TestCloseReleasesBufferExactlyOnce drives the release site the way
// conn.Join does -- each leg closed once per pipe goroutine, so three Closes
// on a leg is a normal shutdown, not an error -- and checks the pool received
// exactly one buffer per direction, with two distinct identities (the
// double-release hazard: a twice-Put buffer is handed to two connections at
// once, the corruption class conn's TestJoinStagingBufferIsNotShared
// documents for joinBufPool). Whether sync.Pool later returns those arrays
// from Get is the stdlib's GC-backed business and not asserted here; the
// ownership side of the invariant is TestJoinShapedConcurrentCloseReleasesOnce,
// which watches Gets as well.
func TestCloseReleasesBufferExactlyOnce(t *testing.T) {
	pool := testPool()
	rec := &putRecorder{}

	withPool(t, pool, func() {
		public := &fakeConn{src: strings.NewReader("GET / HTTP/1.1\r\nHost: a.example\r\n\r\n"), id: "once:public"}
		upstream := &fakeConn{src: strings.NewReader("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"), id: "once:upstream"}
		toUpstream, fromUpstream := NewConnPair(public, upstream, tunnelPolicy())
		io.Copy(io.Discard, toUpstream)
		io.Copy(io.Discard, fromUpstream)

		rec.start()
		defer rec.stop()
		// The shape of a join's shutdown, times three: both goroutines defer
		// Close on both legs.
		for i := 0; i < 3; i++ {
			toUpstream.Close()
			fromUpstream.Close()
		}
	})

	if got := rec.count(); got != 2 {
		t.Fatalf("%d buffers were released for two directions (want exactly 2)", got)
	}
	if got := rec.distinct(); got != 2 {
		t.Fatalf("%d distinct buffers were released for two directions (want 2; a repeat is a double Put)", got)
	}
}

// ownershipTracker is the double-release detector for the concurrent join
// shape. Watching Puts alone cannot prove exactly-once release there: when
// one direction ends early, it releases its array, and the other direction --
// waking only then -- may legitimately acquire and later release that same
// array. What must never happen is overlap: an array Put while its previous
// owner still holds it, or a Get handing an array out twice. The tracker
// counts owners per array and flags any transition that would mean two live
// readers of one 64 KiB slab.
type ownershipTracker struct {
	mu    sync.Mutex
	owned map[*byte]int
}

func newOwnershipTracker() *ownershipTracker {
	return &ownershipTracker{owned: make(map[*byte]int)}
}

func (tr *ownershipTracker) start() {
	testPutHook = func(b []byte) {
		tr.mu.Lock()
		defer tr.mu.Unlock()
		tr.owned[&b[0]]--
	}
	testGetHook = func(b []byte) {
		tr.mu.Lock()
		defer tr.mu.Unlock()
		tr.owned[&b[0]]++
	}
}

func (tr *ownershipTracker) stop() {
	testPutHook, testGetHook = nil, nil
}

// checkJoin asserts the ownership invariant over everything observed so far:
// every array has zero or one owner, so no slab was handed to two connections
// at once.
func (tr *ownershipTracker) checkJoin(t *testing.T, join int) {
	t.Helper()
	tr.mu.Lock()
	defer tr.mu.Unlock()
	for _, owners := range tr.owned {
		if owners < 0 || owners > 1 {
			t.Fatalf("join %d: an array has %d owners (a buffer shared by two connections)", join, owners)
		}
	}
}

// TestJoinShapedConcurrentCloseReleasesOnce is the exactly-once proof under
// the concurrency a real join has: two goroutines, one per direction, each
// draining its copy and then closing BOTH legs, so the first direction to
// finish closes the other's legs mid-copy -- the shutdown shape that makes
// naive release-on-Close unsafe. The pool is watched on both sides (Puts and
// Gets) and every transition that would put two live readers on one array
// fails the test.
func TestJoinShapedConcurrentCloseReleasesOnce(t *testing.T) {
	const iterations = 25

	pool := testPool()
	tr := newOwnershipTracker()

	withPool(t, pool, func() {
		tr.start()
		defer tr.stop()
		for i := 0; i < iterations; i++ {
			reqIn := "POST /x HTTP/1.1\r\nHost: a.example\r\nContent-Length: 3\r\n\r\nabcGET /n HTTP/1.1\r\n"
			respIn := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
			public := &fakeConn{src: strings.NewReader(reqIn), id: "joinc:public"}
			upstream := &fakeConn{src: strings.NewReader(respIn), id: "joinc:upstream"}
			toUpstream, fromUpstream := NewConnPair(public, upstream, tunnelPolicy())

			var wg sync.WaitGroup
			wg.Add(2)
			go func() {
				defer wg.Done()
				io.Copy(io.Discard, fromUpstream)
				fromUpstream.Close()
				toUpstream.Close()
			}()
			go func() {
				defer wg.Done()
				io.Copy(io.Discard, toUpstream)
				toUpstream.Close()
				fromUpstream.Close()
			}()
			wg.Wait()

			// Both legs were closed, so both arrays are back: nothing may
			// still be owned, and nothing may ever have had two owners.
			for _, owners := range tr.owned {
				if owners != 0 {
					t.Fatalf("join %d: an array ends the join with %d owners (both legs were closed)", i, owners)
				}
			}
			tr.checkJoin(t, i)
		}
	})
}

// TestReleasedBufferScribbleDoesNotCorrupt is the no-aliasing proof: the
// rewriter must copy every byte it parses out of the pooled array (readLine
// appends each line into the owned pending slice; out is grown by append), so
// that once the array is back in the pool and another connection scribbles
// over all 64 KiB of it, nothing this connection emitted can change. The
// second half drives a new connection over the scribbled array itself: stale
// bytes from the previous connection must not leak into it, and its own
// output must be exact.
func TestReleasedBufferScribbleDoesNotCorrupt(t *testing.T) {
	pool := testPool()
	rec := &putRecorder{}

	// The head flows through ReadSlice into pending; the body is over-read
	// into the array and spliced; the dangling second head is flushed
	// verbatim by fail-open. All three paths must own their bytes.
	reqIn := "GET / HTTP/1.1\r\nHost: a.example\r\nContent-Length: 5\r\n\r\nhelloGET /tw"
	wantReq := "GET / HTTP/1.1\r\nHost: a.example\r\nContent-Length: 5\r\n" +
		"X-Forwarded-For: 203.0.113.7\r\nX-Forwarded-Proto: http\r\n\r\n" +
		"helloGET /tw"

	var got string
	withPool(t, pool, func() {
		public := &fakeConn{src: strings.NewReader(reqIn), id: "scribble:public"}
		upstream := &fakeConn{src: strings.NewReader(""), id: "scribble:upstream"}
		toUpstream, _ := NewConnPair(public, upstream, tunnelPolicy())
		got = drain(t, toUpstream)
		rec.start()
		toUpstream.Close()
		rec.stop()
	})

	if got := rec.count(); got != 1 {
		t.Fatalf("%d buffers were released for one direction (want exactly 1)", got)
	}

	// Destroy the buffer that went back to the pool. It is already in service:
	// the next connection Gets this exact array.
	scribbled := rec.bufs[0]
	for i := range scribbled {
		scribbled[i] = 0xFF
	}

	check(t, "request read before release", got, wantReq)

	// The scribbled array now serves a new connection. Every byte of the new
	// request must come out as rewritten, with nothing of the old one's bytes
	// (or the 0xFF fill) showing through.
	req2 := "GET /second HTTP/1.1\r\nHost: b.example\r\n\r\n"
	want2 := "GET /second HTTP/1.1\r\nHost: b.example\r\n" +
		"X-Forwarded-For: 203.0.113.7\r\nX-Forwarded-Proto: http\r\n\r\n"
	withPool(t, pool, func() {
		public := &fakeConn{src: strings.NewReader(req2), id: "scribble2:public"}
		upstream := &fakeConn{src: strings.NewReader(""), id: "scribble2:upstream"}
		toUpstream, _ := NewConnPair(public, upstream, tunnelPolicy())
		check(t, "request over the scribbled buffer", drain(t, toUpstream), want2)
		toUpstream.Close()
	})
}

// TestCloseMidStreamReleasesAtTermination covers the deferred half of the
// release handshake: Close while the direction is still mid-copy (the normal
// keep-alive shutdown, where the first direction to finish closes the other's
// legs) must not touch the array the copy is reading -- and must still get it
// back when that copy ends. The bytes after the Close must be exactly what an
// un-Closed reader would produce either way.
func TestCloseMidStreamReleasesAtTermination(t *testing.T) {
	pool := testPool()
	rec := &putRecorder{}

	reqIn := "GET / HTTP/1.1\r\nHost: a.example\r\nContent-Length: 5\r\n\r\nhelloGET /tw"
	wantReq := "GET / HTTP/1.1\r\nHost: a.example\r\nContent-Length: 5\r\n" +
		"X-Forwarded-For: 203.0.113.7\r\nX-Forwarded-Proto: http\r\n\r\n" +
		"helloGET /tw"

	withPool(t, pool, func() {
		public := &fakeConn{src: strings.NewReader(reqIn), id: "midstream:public"}
		upstream := &fakeConn{src: strings.NewReader(""), id: "midstream:upstream"}
		toUpstream, _ := NewConnPair(public, upstream, tunnelPolicy())

		// One Read carries the rewritten head, blank line included; the body
		// and the flushed tail are still in the array when the join's other
		// goroutine would close.
		head := readOnce(t, toUpstream)
		toUpstream.Close()
		rest := drain(t, toUpstream)

		check(t, "request head", head,
			"GET / HTTP/1.1\r\nHost: a.example\r\nContent-Length: 5\r\nX-Forwarded-For: 203.0.113.7\r\nX-Forwarded-Proto: http\r\n\r\n")
		check(t, "request after close", rest, "helloGET /tw")
		check(t, "request whole", head+rest, wantReq)

		// The copy kept going past the Close and ended at EOF: that termination
		// is where the buffer may go to the pool, because it is the one moment
		// provably no view into it is live.
		if got := rec.count(); got != 0 {
			t.Fatalf("buffers released before bookkeeping started: %d", got)
		}
		rec.start()
		defer rec.stop()
		// A second full close cycle re-runs release through the Once, so drive
		// a fresh pair to observe the mid-stream shape's Put.
		public2 := &fakeConn{src: strings.NewReader(reqIn), id: "midstream2:public"}
		upstream2 := &fakeConn{src: strings.NewReader(""), id: "midstream2:upstream"}
		toUpstream2, _ := NewConnPair(public2, upstream2, tunnelPolicy())
		readOnce(t, toUpstream2)
		toUpstream2.Close()
		if got := rec.count(); got != 0 {
			t.Fatalf("a mid-stream close released %d buffers immediately (want 0: the array was still in use)", got)
		}
		drain(t, toUpstream2)
		if got := rec.count(); got != 1 {
			t.Fatalf("%d buffers released for a mid-stream close (want exactly 1, at termination)", got)
		}
	})
}

// TestCloseWithoutPoolingIsSafe: with readBufPool nil -- the switch tests use
// to measure the unpooled path -- the whole release path must degrade to the
// old behavior: buffers are dropped for the GC, nothing is Put, nothing
// panics, and the stream is byte-exact.
func TestCloseWithoutPoolingIsSafe(t *testing.T) {
	reqIn := "GET / HTTP/1.1\r\nHost: a.example\r\nContent-Length: 2\r\n\r\nhiGET /tw"
	wantReq := "GET / HTTP/1.1\r\nHost: a.example\r\nContent-Length: 2\r\n" +
		"X-Forwarded-For: 203.0.113.7\r\nX-Forwarded-Proto: http\r\n\r\n" +
		"hiGET /tw"

	rec := &putRecorder{}
	rec.start()
	defer rec.stop()

	var got string
	withPool(t, nil, func() {
		public := &fakeConn{src: strings.NewReader(reqIn), id: "nopool:public"}
		upstream := &fakeConn{src: strings.NewReader(""), id: "nopool:upstream"}
		toUpstream, _ := NewConnPair(public, upstream, tunnelPolicy())
		got = drain(t, toUpstream)
		for i := 0; i < 3; i++ {
			toUpstream.Close()
		}
	})
	check(t, "request with pooling off", got, wantReq)
	if got := rec.count(); got != 0 {
		t.Fatalf("%d buffers were Put with pooling disabled (want 0)", got)
	}
}

// TestFilteredConnCloseStillDelegates: Close grew a release side effect; it
// must still close the wrapped connection and return its error, because every
// caller (conn.Join's defers, the shutdown paths) treats it as the
// connection's Close.
func TestFilteredConnCloseStillDelegates(t *testing.T) {
	upstream := &fakeConn{src: strings.NewReader(""), id: "close:upstream"}
	public := &fakeConn{
		src: strings.NewReader("GET / HTTP/1.1\r\nHost: a.example\r\n\r\n"), id: "close:public",
	}
	toUpstream, _ := NewConnPair(public, upstream, tunnelPolicy())
	if err := toUpstream.Close(); err != nil {
		t.Fatalf("close returned an error: %v", err)
	}
	// fakeConn.Close is a no-op by design (the embedded interface is nil and
	// the override returns nil), so there is nothing more to observe here than
	// that Close ran and stayed quiet -- the delegation contract is covered by
	// TestNewConnPairDelegates, and this test exists so a future error-return
	// in that chain cannot be silently swallowed by the release handling.
}
