package dedup

import (
	"bytes"
	"errors"
	"io"
	"math/rand"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---- in-memory net.Conn scaffolding ----

// memConn is a net.Conn over a byte reader plus a recording writer. It is
// single-goroutine (the tests below are sequential by design -- determinism
// -- and the one concurrency test uses net.Pipe), so there is no locking.
type memConn struct {
	r io.Reader
	w *bytes.Buffer
}

func (c *memConn) Read(p []byte) (int, error)        { return c.r.Read(p) }
func (c *memConn) Write(p []byte) (int, error)       { return c.w.Write(p) }
func (c *memConn) Close() error                      { return nil }
func (c *memConn) LocalAddr() net.Addr               { return nil }
func (c *memConn) RemoteAddr() net.Addr              { return nil }
func (c *memConn) SetDeadline(t time.Time) error     { return nil }
func (c *memConn) SetReadDeadline(t time.Time) error { return nil }

func (c *memConn) SetWriteDeadline(t time.Time) error { return nil }

// newMemConnWriter returns an engaged codec over a recorder; the frames of
// every Write land in w.wbuf (the batch buffer survives the Write).
func newMemConnWriter() (*Conn, *bytes.Buffer) {
	var wire bytes.Buffer
	return NewEngaged(&memConn{r: strings.NewReader(""), w: &wire}), &wire
}

func newMemConnReader(wire []byte) *Conn {
	return NewEngaged(&memConn{r: bytes.NewReader(wire)})
}

// frame is one parsed wire frame, for the tests' own inspection of the wire.
type frame struct {
	typ     uint8
	payload []byte
}

// walkFrames parses a wire buffer into frames and asserts the format
// invariants on the way. The codec must never produce a frame the receiver
// would reject, so the walker doubles as an encoder-side well-formedness
// gate on every wire buffer a test produces.
func walkFrames(t *testing.T, wire []byte) []frame {
	t.Helper()
	var fs []frame
	for len(wire) > 0 {
		if len(wire) < frameHeaderLen {
			t.Fatalf("truncated frame header: %d bytes left", len(wire))
		}
		typ := wire[0]
		l := int(be16(wire[1:frameHeaderLen]))
		wire = wire[frameHeaderLen:]
		switch typ {
		case frameLiteral:
			if l < minChunk || l > maxChunk {
				t.Fatalf("LITERAL of %d bytes outside [%d,%d]", l, minChunk, maxChunk)
			}
		case frameTail:
			if l < 1 || l >= maxChunk {
				t.Fatalf("TAIL of %d bytes outside [1,%d]", l, maxChunk-1)
			}
		case frameRef:
			if l != refPayloadLen {
				t.Fatalf("REF of %d bytes, want %d", l, refPayloadLen)
			}
		default:
			t.Fatalf("unknown frame type %d on the wire", typ)
		}
		if len(wire) < l {
			t.Fatalf("frame type %d declares %d bytes, %d left", typ, l, len(wire))
		}
		fs = append(fs, frame{typ, wire[:l]})
		wire = wire[l:]
	}
	return fs
}

func countType(fs []frame, typ uint8) int {
	n := 0
	for _, f := range fs {
		if f.typ == typ {
			n++
		}
	}
	return n
}

func readAll(t *testing.T, c *Conn, hint int) []byte {
	t.Helper()
	var got bytes.Buffer
	buf := make([]byte, 64*1024)
	for got.Len() < hint {
		n, err := c.Read(buf)
		got.Write(buf[:n])
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read: %v", err)
		}
	}
	return got.Bytes()
}

// TestTransparencyFuzz is the review-gate-1 test: whatever the codec does to
// the stream must be invisible above it. Seeded math/rand, so it is
// deterministic and rerunnable (and -count=2 exercises it twice, which is
// the point of the quality gate). Each iteration varies the payload class,
// the write split, and the read sizes; the assertions are byte equality,
// the table-mirror invariant (both ends' tables must remain identical, since
// that is what REF resolution silently trusts), and the 4 MiB per-direction
// bound under unbounded input.
func TestTransparencyFuzz(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for iter := 0; iter < 200; iter++ {
		payload := mixedCorpus(rng, rng.Intn(256*1024))

		var wire bytes.Buffer
		w := NewEngaged(&memConn{r: strings.NewReader(""), w: &wire})
		off := 0
		for off < len(payload) {
			n := 1 + rng.Intn(48*1024)
			if off+n > len(payload) {
				n = len(payload) - off
			}
			if _, err := w.Write(payload[off : off+n]); err != nil {
				t.Fatalf("iter %d: write: %v", iter, err)
			}
			off += n
		}

		r := newMemConnReader(wire.Bytes())
		got := readAll(t, r, len(payload))
		if !bytes.Equal(got, payload) {
			t.Fatalf("iter %d: decoded stream diverged (%d decoded, %d offered)", iter, len(got), len(payload))
		}

		if w.enc.count != r.dec.count || w.enc.memBytes() != r.dec.memBytes() {
			t.Fatalf("iter %d: tables diverged: enc count=%d bytes=%d, dec count=%d bytes=%d",
				iter, w.enc.count, w.enc.memBytes(), r.dec.count, r.dec.memBytes())
		}
		for _, tb := range []*table{&w.enc, &r.dec} {
			if tb.memBytes() > uint64(ringSlots)*maxChunk {
				t.Fatalf("iter %d: table holds %d bytes, bound is %d", iter, tb.memBytes(), uint64(ringSlots)*maxChunk)
			}
		}
	}
}

// TestTwoDirectionalPipe runs the real shape -- one full-duplex stream, both
// directions pumping concurrently through the SAME wrapper instance
// (conn.Join's two pipes), -race watching for the shared state. net.Pipe is
// unbuffered and synchronous, so every frame written is backpressure into
// the peer's Read; deadlines turn any framing deadlock into a failure
// instead of a hang.
func TestTwoDirectionalPipe(t *testing.T) {
	innerA, innerB := net.Pipe()
	a := NewEngaged(innerA)
	b := NewEngaged(innerB)
	deadline := time.Now().Add(10 * time.Second)
	innerA.SetDeadline(deadline)
	innerB.SetDeadline(deadline)

	rng := rand.New(rand.NewSource(5))
	ab := mixedCorpus(rng, 1024*1024)
	ba := mixedCorpus(rng, 1024*1024)

	// One rand source per pump: math/rand is not goroutine-safe, and the
	// four pumps run concurrently. Seeding each direction separately keeps
	// the run deterministic.
	writeSizes := func(seed int64) func() int {
		r := rand.New(rand.NewSource(seed))
		return func() int { return 1 + r.Intn(32*1024) }
	}
	sizeAB, sizeBA := writeSizes(51), writeSizes(52)

	var wg sync.WaitGroup
	pumpWrite := func(c *Conn, p []byte, nextSize func() int) {
		defer wg.Done()
		off := 0
		for off < len(p) {
			n := nextSize()
			if off+n > len(p) {
				n = len(p) - off
			}
			if _, err := c.Write(p[off : off+n]); err != nil {
				t.Errorf("write: %v", err)
				return
			}
			off += n
		}
	}
	pumpRead := func(c *Conn, want []byte) {
		defer wg.Done()
		got := make([]byte, 0, len(want))
		buf := make([]byte, 32*1024)
		for len(got) < len(want) {
			n, err := c.Read(buf)
			got = append(got, buf[:n]...)
			if err != nil {
				t.Errorf("read after %d/%d bytes: %v", len(got), len(want), err)
				return
			}
		}
		if !bytes.Equal(got, want) {
			t.Error("decoded stream diverged over the pipe")
		}
	}
	wg.Add(4)
	go pumpWrite(a, ab, sizeAB)
	go pumpRead(b, ab)
	go pumpWrite(b, ba, sizeBA)
	go pumpRead(a, ba)
	wg.Wait()

	if a.enc.count != b.dec.count || b.enc.count != a.dec.count {
		t.Fatalf("cross-direction tables diverged: a.enc=%d b.dec=%d b.enc=%d a.dec=%d",
			a.enc.count, b.dec.count, b.enc.count, a.dec.count)
	}
}

// TestTailCausality is the latency guard: a Write returns only after its
// bytes are framed. Write less than a chunk and inspect the wire the moment
// Write returns -- everything must already be there, as a single TAIL, with
// nothing buffered awaiting a boundary (a second identical write must
// produce a second independent TAIL, proving no state carried and no chunk
// formed across the write seam).
func TestTailCausality(t *testing.T) {
	w, wire := newMemConnWriter()

	one := bytes.Repeat([]byte{0x42}, 100)
	if n, err := w.Write(one); err != nil || n != len(one) {
		t.Fatalf("write: n=%d err=%v", n, err)
	}
	fs := walkFrames(t, append([]byte(nil), wire.Bytes()...))
	if len(fs) != 1 || fs[0].typ != frameTail || !bytes.Equal(fs[0].payload, one) {
		t.Fatalf("first write framed as %d frames (want exactly one TAIL carrying all 100 bytes)", len(fs))
	}
	if got, want := wire.Len(), frameHeaderLen+len(one); got != want {
		t.Fatalf("%d bytes framed after Write returned, want %d", got, want)
	}

	two := bytes.Repeat([]byte{0x43}, 100)
	if _, err := w.Write(two); err != nil {
		t.Fatal(err)
	}
	fs = walkFrames(t, append([]byte(nil), wire.Bytes()...))
	if len(fs) != 2 || fs[1].typ != frameTail || !bytes.Equal(fs[1].payload, two) {
		t.Fatalf("second write framed as %d frames (want a second independent TAIL)", len(fs))
	}

	// A large write ends in a TAIL too: chunks first, remainder flushed.
	rng := rand.New(rand.NewSource(11))
	big := make([]byte, 48*1024)
	rng.Read(big)
	before := wire.Len()
	if _, err := w.Write(big); err != nil {
		t.Fatal(err)
	}
	fs = walkFrames(t, wire.Bytes()[before:])
	payload := 0
	for _, f := range fs {
		payload += len(f.payload)
	}
	if payload != len(big) {
		t.Fatalf("framed %d payload bytes for a %d-byte write", payload, len(big))
	}
	if last := fs[len(fs)-1]; last.typ != frameTail {
		t.Fatalf("write ended with frame type %d, want the TAIL flush", last.typ)
	}

	// And a zero-byte write is nothing at all -- no empty frames.
	before = wire.Len()
	if n, err := w.Write(nil); err != nil || n != 0 {
		t.Fatalf("zero write: n=%d err=%v", n, err)
	}
	if walkFrames(t, wire.Bytes()[before:]) != nil {
		t.Fatal("zero-byte write produced frames")
	}
}

// TestPassThroughByteIdentical: a disengaged wrapper must be
// indistinguishable from no wrapper -- bytes through Read and Write 1:1,
// counters untouched. This is the state every tunnel sits in when the peer
// never acked (or the kill switch is on), so it is the state whose
// transparency is contractual.
func TestPassThroughByteIdentical(t *testing.T) {
	payload := mixedCorpus(rand.New(rand.NewSource(3)), 64*1024)

	var wire bytes.Buffer
	w := NewPassThrough(&memConn{r: strings.NewReader(""), w: &wire})
	if n, err := w.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("write: n=%d err=%v", n, err)
	}
	if !bytes.Equal(wire.Bytes(), payload) {
		t.Fatal("pass-through Write altered the byte stream")
	}
	r := NewPassThrough(&memConn{r: bytes.NewReader(payload)})
	got := readAll(t, r, len(payload))
	if !bytes.Equal(got, payload) {
		t.Fatal("pass-through Read altered the byte stream")
	}
	if w.Offered() != 0 || w.Framed() != 0 || w.Refs() != 0 {
		t.Fatal("pass-through traffic moved the dedup counters")
	}
}

// TestEngageFlip drives the install-then-engage sequence lanes B/C will
// build: install pass-through, send the handshake plaintext, flip on the
// ack, then frame everything after. The reader mirrors the same sequence,
// which is exactly the negotiation's ordering guarantee expressed as a test:
// plaintext before the flip on one end is read as plaintext before the flip
// on the other. Engage is a one-way latch; the redundant call below must be
// a harmless no-op.
func TestEngageFlip(t *testing.T) {
	hello := []byte("POST /msg HTTP/1.1\r\nRegProxy: plaintext handshake bytes\r\n\r\n")
	body := mixedCorpus(rand.New(rand.NewSource(4)), 48*1024)

	var wire bytes.Buffer
	w := NewPassThrough(&memConn{r: strings.NewReader(""), w: &wire})
	if _, err := w.Write(hello); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire.Bytes(), hello) {
		t.Fatal("pre-engage write was framed")
	}
	w.Engage()
	w.Engage() // redundant: no-op, not a toggle
	if _, err := w.Write(body); err != nil {
		t.Fatal(err)
	}

	r := NewPassThrough(&memConn{r: bytes.NewReader(wire.Bytes())})
	got := make([]byte, len(hello))
	if _, err := io.ReadFull(r, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, hello) {
		t.Fatal("pre-engage bytes did not pass through on the reader")
	}
	r.Engage()
	r.Engage()
	rest := readAll(t, r, len(body))
	if !bytes.Equal(rest, body) {
		t.Fatal("post-engage bytes decoded wrong")
	}
}

// TestFailLoudCorruptRefDigest corrupts the 8-byte digest prefix inside a
// REF and demands the hard error: Read fails, the error is sticky, and --
// the "never wrong bytes" half -- every byte emitted BEFORE the error is
// still exactly right. The corrupted chunk's bytes must never appear.
func TestFailLoudCorruptRefDigest(t *testing.T) {
	body := llmPromptBody(rand.New(rand.NewSource(21)), 64*1024)
	w, wire := newMemConnWriter()
	w.Write(body) // stores the chunks
	wireAt := wire.Len()
	w.Write(body) // pure refs
	full := append([]byte(nil), wire.Bytes()...)

	// Locate the digest byte of the first REF at or after the second write.
	off := 0
	refOff := -1
	for _, f := range walkFrames(t, full) {
		if f.typ == frameRef && off >= wireAt {
			refOff = off + frameHeaderLen + 2 // [slot u16][digest 8B]
			break
		}
		off += frameHeaderLen + len(f.payload)
	}
	if refOff < 0 {
		t.Fatal("no REF frame found after the stored copy")
	}
	corrupt := append([]byte(nil), full...)
	corrupt[refOff] ^= 0xFF

	r := newMemConnReader(corrupt)
	got := readAll(t, r, len(body)) // the stored copy decodes cleanly
	if !bytes.Equal(got, body) {
		t.Fatal("bytes before the corruption were already wrong")
	}
	buf := make([]byte, 64*1024)
	n, err := r.Read(buf)
	if err == nil {
		t.Fatalf("corrupted REF decoded as %d clean bytes instead of erroring", n)
	}
	if n != 0 {
		t.Fatalf("corrupted REF emitted %d bytes alongside the error", n)
	}
	if _, err := r.Read(buf); err == nil {
		t.Fatal("error is not sticky")
	}
}

// TestFailLoudWrongSlot covers the deterministic half of REF verification at
// the wrapper level: a REF naming a slot that was never stored, and one
// naming a slot the ring has already evicted. Both must die at Read, never
// fabricate bytes. The evicted case deliberately carries the slot's
// ORIGINAL, correct digest: the window check must reject it on position
// alone -- "a REF to an evicted slot is a desync error" must not depend on
// the 2^-64 digest lottery.
func TestFailLoudWrongSlot(t *testing.T) {
	rng := rand.New(rand.NewSource(31))

	// Never-stored: one forced literal (a maxChunk write always cuts), then
	// a well-formed REF to a slot id far outside anything the table inserted.
	w1, wire1 := newMemConnWriter()
	big := make([]byte, maxChunk)
	rng.Read(big)
	w1.Write(big)
	fs := walkFrames(t, append([]byte(nil), wire1.Bytes()...))
	if len(fs) == 0 || fs[0].typ != frameLiteral {
		t.Fatalf("setup: expected the first frame to be a literal, got %v", fs)
	}
	ref := appendFrameHeader(make([]byte, 0, frameHeaderLen+refPayloadLen), frameRef, refPayloadLen)
	ref = appendBE16(ref, 999) // never stored
	ref = append(ref, fs[0].payload[:refDigestLen]...)
	// Drain: clean literals precede the crafted REF, so the error is
	// expected exactly when the REF is reached.
	r := newMemConnReader(append(wire1.Bytes(), ref...))
	buf := make([]byte, 32*1024)
	total := 0
	for {
		n, err := r.Read(buf)
		total += n
		if err != nil {
			break
		}
	}
	expected := 0
	for _, f := range fs {
		expected += len(f.payload)
	}
	if total != expected {
		t.Fatalf("never-stored slot: emitted %d clean bytes before erroring, want %d", total, expected)
	}

	// Evicted: stream distinct maxChunk writes until slot 0 is out of the
	// window, then present the crafted REF on a fresh reader whose table
	// holds the same history.
	w2, wire2 := newMemConnWriter()
	for int(w2.enc.count) <= ringSlots {
		c := make([]byte, maxChunk)
		rng.Read(c)
		w2.Write(c)
	}
	history := append([]byte(nil), wire2.Bytes()...)
	fs2 := walkFrames(t, history)
	expected = 0
	for _, f := range fs2 {
		expected += len(f.payload)
	}
	chunk0 := fs2[0].payload
	ref = appendFrameHeader(ref[:0], frameRef, refPayloadLen)
	ref = appendBE16(ref, 0)
	key0 := digestOf(chunk0)
	ref = append(ref, key0[:refDigestLen]...)

	r = newMemConnReader(append(history, ref...))
	total = 0
	for {
		n, err := r.Read(buf)
		total += n
		if err != nil {
			break
		}
	}
	if total != expected {
		t.Fatalf("emitted %d clean bytes, want exactly the %d payload bytes before the evicted REF", total, expected)
	}
}

// TestMalformedFrames feeds each wire invariant violation and demands the
// hard error. These frames cannot be produced by any encoder in this fork,
// so on the wire they mean desync or attack -- either way, not data.
func TestMalformedFrames(t *testing.T) {
	cases := []struct {
		name string
		wire []byte
	}{
		{"unknown frame type", []byte{7, 0, 4, 1, 2, 3, 4}},
		{"undersized literal", []byte{byte(frameLiteral), 0, 4, 1, 2, 3, 4}},
		// 0x4101 = 16641 > maxChunk: must be rejected at the header, before
		// any payload byte exists to fill.
		{"oversized literal", []byte{byte(frameLiteral), 0x41, 0x01}},
		{"empty tail", []byte{byte(frameTail), 0, 0}},
		{"ref with short payload", []byte{byte(frameRef), 0, 4, 1, 2, 3, 4}},
		{"truncated mid-frame", []byte{byte(frameTail), 0, 100, 1, 2, 3}},
	}
	for _, tc := range cases {
		r := newMemConnReader(tc.wire)
		if _, err := r.Read(make([]byte, 64)); err == nil {
			t.Fatalf("%s: accepted", tc.name)
		}
	}
}

// TestEOFTransparency: EOF on a frame boundary is a clean close passed
// straight through; EOF mid-frame is not a close, it is a truncated stream,
// and must be an error -- reporting EOF there would silently drop the tail
// of the byte stream.
func TestEOFTransparency(t *testing.T) {
	body := mixedCorpus(rand.New(rand.NewSource(17)), 4096)
	w, _ := newMemConnWriter()
	w.Write(body)

	r := newMemConnReader(append([]byte(nil), w.wbuf...))
	got := readAll(t, r, len(body))
	if !bytes.Equal(got, body) {
		t.Fatal("body decoded wrong before EOF")
	}
	if _, err := r.Read(make([]byte, 16)); err != io.EOF {
		t.Fatalf("clean close surfaced as %v", err)
	}

	wire := append([]byte(nil), w.wbuf...)
	r = newMemConnReader(wire[:len(wire)-2]) // bite the tail frame's payload
	buf := make([]byte, 64*1024)
	var total int
	var lastErr error
	for lastErr == nil {
		n, err := r.Read(buf)
		total += n
		lastErr = err
	}
	if !errors.Is(lastErr, io.ErrUnexpectedEOF) {
		t.Fatalf("truncated stream surfaced as %v, want unexpected-EOF", lastErr)
	}
	if total >= len(body) {
		t.Fatalf("emitted %d bytes from a %d-byte body cut short", total, len(body))
	}
}

// TestCounters pins the close-line numbers on a stream with a known shape:
// offered is input bytes, framed is wire bytes (headers included), refs is
// the REF count -- and a second identical copy over the same wrapper is
// where the refs show up. offered/framed is the honest win number of spec §5.
func TestCounters(t *testing.T) {
	body := llmPromptBody(rand.New(rand.NewSource(23)), 64*1024)
	w, wire := newMemConnWriter()

	w.Write(body)
	firstRefs := w.Refs()
	if w.Offered() != uint64(len(body)) {
		t.Fatalf("offered=%d want %d", w.Offered(), len(body))
	}
	if w.Framed() != uint64(wire.Len()) {
		t.Fatalf("framed=%d want %d", w.Framed(), wire.Len())
	}
	if firstRefs != 0 {
		t.Fatalf("first copy emitted %d refs", firstRefs)
	}

	wireAt := wire.Len()
	w.Write(body)
	fs := walkFrames(t, wire.Bytes()[wireAt:])
	if uint64(countType(fs, frameRef)) != w.Refs()-firstRefs {
		t.Fatalf("second copy: walker counted %d refs, counter says %d",
			countType(fs, frameRef), w.Refs()-firstRefs)
	}
	if w.Offered() != 2*uint64(len(body)) || w.Framed() != uint64(wire.Len()) {
		t.Fatal("counters drifted from the wire")
	}
	if w.Refs() == 0 {
		t.Fatal("identical second copy emitted no refs")
	}
}
