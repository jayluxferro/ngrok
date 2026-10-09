// Package dedup implements the carrier_dedup codec (SPEC-CLUSTER21,
// docs/specs/17-carrier-dedup.md §2): a net.Conn decorator that sits on an
// agent↔server carrier stream and re-encodes the byte stream through
// content-defined chunking so repeated chunks -- a re-sent 32 KiB LLM system
// prompt is the shape of the win -- cross the wire as 10-byte references.
//
// The organizing rule is FAIL-LOUD TRANSPARENCY. Transparency: the wrapper
// is a protocol-agnostic byte filter; the rewriter's connpair, the h2c
// transcoder and plain http/tcp tunnels all ride unchanged above it, and a
// reader above the wrapper sees the exact byte stream that was written
// (fuzz-pinned). Fail-loud: reassembly is verified (every REF is re-hashed
// against its 8-byte digest prefix), and any desync is a hard error that
// kills the connection -- never zero-fill, never skip, never fall through.
// A desync can only be a bug (both endpoints ship together in this fork),
// and a bug's honest expression is a dead connection the visitor retries,
// not silently corrupted bytes.
//
// # Shape
//
// One Conn decorates one full-duplex stream and holds TWO tables -- one per
// direction, matching the spec's "per-stream, per-direction" bound of
// ringSlots × maxChunk = 4 MiB each. The write direction chunks outgoing
// bytes (LITERAL/TAIL/REF frames); the read direction parses them and
// mirrors the far end's inserts. conn.Join runs the two directions on
// separate goroutines, so the tables are each single-goroutine and only the
// engage flag and the counters are atomic. The wrapper deliberately exposes
// no ReadFrom/WriterTo: embedding the net.Conn *interface* promotes only
// net.Conn's method set (conn/zerocopy.go's own caveat), so io.CopyBuffer
// between two wrapped streams cannot route around the codec.
//
// # Engagement
//
// Negotiation lives in the RegProxy/StartProxy handshake (spec §1, lanes
// B/C); this package only provides the two states both ends need:
//
//   - NewPassThrough installs the wrapper engaged=no: Read and Write
//     delegate 1:1 and the wire is byte-identical to no wrapper at all.
//     This is the install-then-engage shape the client wants (install at
//     the conn.Wrap site, flip on the StartProxy ack).
//   - NewEngaged installs it encoding immediately, for the server side
//     post-ack and for tests.
//   - Engage flips pass-through → encoding, both directions, and stays
//     flipped.
//
// The flip is only coherent at the handshake boundary, and the reason is
// worth stating where the flip lives: the client engages after reading the
// ack, the server after writing it, and every pre-engage byte on the wire
// is the msg exchange itself, consumed before either side's payload pump
// starts. Because the stream is ordered, each end decodes nothing but
// post-ack frames -- no window exists in which one side encodes and the
// other does not. Engaging at any other point is a protocol bug this
// package cannot detect; it will surface as the fail-loud desync error.
package dedup

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
)

// Compile-time proof the wrapper is a plain net.Conn: lanes B and C install
// it as the inner conn of conn.Wrap's stream (client/model.go, server/mux.go)
// and nothing about it may be special.
var _ net.Conn = (*Conn)(nil)

// maxBatch bounds one framing batch: the largest slice of p encoded into a
// single inner Write. It keeps the batch buffer's steady-state footprint
// bounded (conn.Join hands Write up to joinBufSize = 256 KiB at a time)
// without meaningfully costing large writes: four batches cover the join
// buffer, and each batch is one inner Write either way.
const maxBatch = 64 * 1024

// errStreamDesync marks every error this codec MANUFACTURES from its own
// framing analysis: a rejected header, a REF that fails verification, an
// unknown frame type. It is how fail() tells "the codec determined this
// stream is unframable" -- a desync, the fail-loud event the telemetry
// counts -- apart from "the transport died under a blocked read". The
// distinction is not pedantry: conn.Join tears both legs down on any error,
// and the LOCAL close of a perfectly healthy stream surfaces to the codec's
// blocked read as the inner conn's own error (a closed-pipe/reset, never a
// boundary EOF -- the far end's close is what arrives as EOF). The first
// draft of the desync counter counted every sticky error but a bare io.EOF,
// and the e2e dedup group caught it within one run: a healthy scenario
// logged desyncs=1 per stream on the server -- one per visitor disconnect,
// the join's own teardown -- while the far end, seeing the remote close as
// a clean boundary EOF, logged zero. A counter that reads one on every
// closed connection is noise, not the v2 gate's signal.
//
// The mid-frame truncation (io.EOF after a partial frame) is counted too,
// via errors.Is(io.ErrUnexpectedEOF) rather than this sentinel: readErr
// already re-classifies exactly that case, and a stream that ends mid-frame
// is a framing lie whoever caused it.
var errStreamDesync = errors.New("carrier_dedup: stream desync")

// Conn is the carrier_dedup wrapper. Construct with NewPassThrough (for
// install-then-engage) or NewEngaged; both take the inner conn and delegate
// everything they do not own -- deadlines, addresses, Close -- to it.
type Conn struct {
	net.Conn

	engaged atomic.Bool

	// Write direction: table + batch buffer. Owned by the join's writer
	// goroutine; only the counters below are read cross-goroutine.
	enc  table
	wbuf []byte

	// Read direction: table + frame parser state. Owned by the join's
	// reader goroutine. pay is the frame payload buffer (a frame payload
	// never exceeds maxChunk -- larger lengths are rejected as protocol
	// violations before allocation matters); out is decoded surplus from a
	// frame larger than the caller's Read buffer.
	dec     table
	hdr     [frameHeaderLen]byte
	hdrN    int
	need    int
	pay     []byte
	payN    int
	out     []byte
	readErr error

	// The per-stream close line (spec §5): offered=X framed=Y refs=Z -- the
	// honest win number, logged by lanes B/C/D at join teardown. Atomic
	// because the accessor can race the (single) writer goroutine; the
	// counters themselves are only advanced on the write path.
	offered atomic.Uint64
	framed  atomic.Uint64
	refs    atomic.Uint64

	// The telemetry half of the close line (SPEC-CLUSTER23):
	// desyncs=N readWire=W readPayload=P. The asymmetry with the three
	// above is the point of the cluster: offered/framed/refs only ever
	// advance on the WRITE path, and the win the feature exists for --
	// agent->server requests -- crosses the server on its READ path, so a
	// server aggregating only its own write counters would aggregate the
	// ~0 direction and miss the payload entirely. wireIn/decodedOut are
	// the read direction's framed/offered pair; desyncs is the fail-loud
	// event made queryable. Same atomicity rule: advanced only by the
	// join's reader goroutine, read cross-goroutine at teardown.
	desyncs    atomic.Uint64
	wireIn     atomic.Uint64
	decodedOut atomic.Uint64
}

// NewPassThrough wraps inner with the codec disengaged: every byte passes
// through 1:1 and the wire is byte-identical to no wrapper. This is the
// constructor for install-then-engage -- wrap at the conn.Wrap site, flip
// with Engage when the handshake acks.
func NewPassThrough(inner net.Conn) *Conn {
	c := &Conn{Conn: inner}
	c.init()
	return c
}

// NewEngaged wraps inner with the codec encoding from the first byte. Use it
// where engagement is already established (the server side after writing the
// StartProxy ack) and in tests.
func NewEngaged(inner net.Conn) *Conn {
	c := NewPassThrough(inner)
	c.engaged.Store(true)
	return c
}

// Engage turns the pass-through wrapper into an encoding wrapper, both
// directions. Only meaningful on a NewPassThrough wrapper and only at the
// handshake boundary (see the package comment for why the ordering makes the
// flip safe); later calls are no-ops.
func (c *Conn) Engage() {
	c.engaged.Store(true)
}

func (c *Conn) init() {
	c.enc = newTable()
	c.dec = newTable()
	c.pay = make([]byte, maxChunk)
}

// Offered returns the count of payload bytes accepted by engaged Writes --
// the "offered" figure of the close line.
func (c *Conn) Offered() uint64 { return c.offered.Load() }

// Framed returns the count of wire bytes the engaged Writes produced,
// headers included -- the "framed" figure. offered/framed is the honest win
// number; on random data expect ~1.002 (three header bytes per minChunk plus
// tails), on the repeated-prompt case well under 1.
func (c *Conn) Framed() uint64 { return c.framed.Load() }

// Refs returns the number of REF frames emitted -- the "refs" figure.
func (c *Conn) Refs() uint64 { return c.refs.Load() }

// Desyncs returns the number of desyncs this codec observed: framing
// violations it rejected (bad header, failed REF verification, unknown type)
// and streams that ended mid-frame. Transport deaths -- a join tearing down
// a blocked read because the visitor disconnected, a reset, a deadline --
// are NOT desyncs and do not count, whatever error they hand the codec; see
// errStreamDesync for the full story. Zero is the honest steady state of a
// healthy stream on BOTH ends; a non-zero figure is the v2 gate's queryable
// version of the once-per-direction Warn log.
func (c *Conn) Desyncs() uint64 { return c.desyncs.Load() }

// WireIn returns the count of inner bytes the engaged Reads consumed,
// headers included -- the "readWire" figure. It is the read direction's
// Framed(): what the far end actually put on the wire for this side.
func (c *Conn) WireIn() uint64 { return c.wireIn.Load() }

// DecodedOut returns the count of payload bytes the engaged Reads emitted --
// the "readPayload" figure. WireIn/DecodedOut is the read direction's win
// number, the same shape as Framed()/Offered(); bytes held in the surplus
// buffer (a frame larger than the caller's Read) are counted once, when
// their frame is decoded, not again per partial handout.
func (c *Conn) DecodedOut() uint64 { return c.decodedOut.Load() }

// Write encodes p and writes it to the inner conn. On success it returns
// len(p): every byte of p is framed before Write returns -- complete chunks
// as LITERAL/REF, the remainder as a TAIL (frame.go explains why the
// remainder may not be buffered). Nothing is ever held back, so there is
// nothing to flush at Close.
func (c *Conn) Write(p []byte) (int, error) {
	if !c.engaged.Load() {
		return c.Conn.Write(p)
	}
	c.offered.Add(uint64(len(p)))
	total := 0
	for len(p) > 0 {
		batch := p
		if len(batch) > maxBatch {
			batch = batch[:maxBatch]
		}
		c.wbuf = appendFrames(c.wbuf[:0], &c.enc, &c.refs, batch)
		n, err := c.Conn.Write(c.wbuf)
		if err == nil && n < len(c.wbuf) {
			// io.Writer's contract says this cannot happen; honoring it here
			// is the difference between a torn frame being reported and the
			// peer decoding silence as data.
			err = io.ErrShortWrite
		}
		if err != nil {
			// A short or failed inner write leaves the stream framing
			// integrity broken as far as the peer is concerned; the caller
			// (conn.Join's pipe) tears the leg down on any error, so
			// reporting only the fully-flushed prefix is honest and safe.
			return total, err
		}
		c.framed.Add(uint64(len(c.wbuf)))
		total += len(batch)
		p = p[len(batch):]
	}
	return total, nil
}

// Read reassembles the byte stream from frames, one frame per call (frames
// are ≤ maxChunk = 16 KiB, well under conn.Join's staging buffer, so the
// granularity costs nothing). Errors are sticky: a desync kills the
// connection, and a second Read on a dead stream returns the same error
// rather than inventing progress.
func (c *Conn) Read(p []byte) (int, error) {
	if !c.engaged.Load() {
		return c.Conn.Read(p)
	}
	if len(p) == 0 {
		return 0, nil
	}
	if c.readErr != nil {
		return 0, c.readErr
	}
	if len(c.out) > 0 {
		n := copy(p, c.out)
		c.out = c.out[n:]
		return n, nil
	}
	if c.hdrN < frameHeaderLen {
		err := c.fill(c.hdr[c.hdrN:frameHeaderLen])
		if err != nil {
			return c.fail(readErr(err, c.hdrN == 0))
		}
		c.hdrN = frameHeaderLen
		if err := c.validateHeader(); err != nil {
			return c.fail(err)
		}
		c.payN = 0
	}
	if c.payN < c.need {
		err := c.fill(c.pay[c.payN:c.need])
		if err != nil {
			return c.fail(readErr(err, false))
		}
		c.payN = c.need
	}
	payload, err := c.decodeFrame()
	if err != nil {
		return c.fail(err)
	}
	// One add per frame decoded (SPEC-CLUSTER23): the wire bytes it cost
	// were counted in fill, the payload it produced here. The surplus
	// branch below re-emits from c.out without re-counting -- those bytes
	// were this frame's payload the moment decodeFrame returned them.
	c.decodedOut.Add(uint64(len(payload)))
	n := copy(p, payload)
	if n < len(payload) {
		c.out = append(c.out[:0], payload[n:]...)
	}
	c.hdrN = 0
	return n, nil
}

// validateHeader enforces the wire invariant at the only place a frame's
// size is learnable, and it enforces it TIGHTLY -- not just "fits in the
// buffer" but "a length this encoder can produce". A LITERAL is always a
// complete chunk (min..max); a TAIL is the post-chunk remainder (1..max-1;
// it cannot be zero because the encoder emits no empty frames, and cannot
// reach max because that scan always cuts). Any other length is a desync,
// not data: refuse it before touching the payload buffer. The tightness is
// what lets Read return exactly one frame's bytes without a re-check loop --
// a valid frame always yields at least one byte, so Read can never report a
// byteless success and spin io.Copy.
func (c *Conn) validateHeader() error {
	typ := c.hdr[0]
	need := int(be16(c.hdr[1:frameHeaderLen]))
	switch typ {
	case frameLiteral:
		if need < minChunk || need > maxChunk {
			return fmt.Errorf("%w: LITERAL frame of %d bytes outside [%d,%d]", errStreamDesync, need, minChunk, maxChunk)
		}
	case frameTail:
		if need < 1 || need >= maxChunk {
			return fmt.Errorf("%w: TAIL frame of %d bytes outside [1,%d]", errStreamDesync, need, maxChunk-1)
		}
	case frameRef:
		if need != refPayloadLen {
			return fmt.Errorf("%w: REF frame with payload length %d, want %d", errStreamDesync, need, refPayloadLen)
		}
	default:
		return fmt.Errorf("%w: unknown frame type %d", errStreamDesync, typ)
	}
	c.need = need
	return nil
}

// decodeFrame turns a fully-received frame into the payload bytes to emit.
// LITERAL inserts into the mirror table (both ends insert the same literal
// sequence, in order -- that is the whole determinism argument);
// TAIL does not (the receiver mirrors the sender, which stored nothing);
// REF is resolved through the table with re-hash verification, and any
// miss is the fail-loud hard error.
func (c *Conn) decodeFrame() ([]byte, error) {
	switch c.hdr[0] {
	case frameLiteral:
		payload := c.pay[:c.need]
		c.dec.insert(digestOf(payload), payload)
		return payload, nil
	case frameTail:
		return c.pay[:c.need], nil
	case frameRef:
		return c.dec.fetch(be16(c.pay[:2]), c.pay[2:refPayloadLen])
	default:
		// validateHeader already rejected this; unreachable, but the
		// fall-through answer to an unknown type is an error, not silence.
		return nil, fmt.Errorf("%w: unknown frame type %d", errStreamDesync, c.hdr[0])
	}
}

// fill reads from the inner conn until dst is full. It never discards bytes:
// a Read that returns both data and EOF consumes the data first and lets the
// EOF surface on the next fill, at the frame boundary where it means a clean
// close.
//
// The single exit is load-bearing for the telemetry (SPEC-CLUSTER23): one
// wireIn add per fill, on every path, so a fill that consumed bytes before
// hitting a failing edge still books them -- a truncated stream's readWire
// must reflect the bytes that really crossed before it died, or the win
// number quietly undercounts exactly the streams an operator is debugging.
func (c *Conn) fill(dst []byte) error {
	consumed := 0
	var err error
	for len(dst) > 0 && err == nil {
		var n int
		n, err = c.Conn.Read(dst)
		consumed += n
		if n > 0 {
			dst = dst[n:]
		} else if err == nil {
			// io.Reader contract violation; the net.Conn and smux
			// implementations this wraps never do it. Fail rather than spin.
			err = io.ErrNoProgress
		}
	}
	c.wireIn.Add(uint64(consumed))
	if len(dst) == 0 {
		// dst filled: whatever the last Read also returned is dropped, as it
		// always was -- the data was consumed first and the stream is at a
		// frame boundary, where a trailing error would mean nothing.
		return nil
	}
	return err
}

// readErr classifies an inner-read failure. EOF exactly at a frame boundary
// (before any header byte) is the peer's clean close and passes through as
// io.EOF -- the stream above the wrapper closes transparently. EOF mid-frame
// is a truncated stream: the encoder always emits whole frames, so a partial
// one cannot be a well-behaved close, and reporting it as EOF would silently
// drop the tail of the byte stream.
func readErr(err error, atBoundary bool) error {
	if err == io.EOF && !atBoundary {
		return fmt.Errorf("carrier_dedup: stream ended mid-frame: %w", io.ErrUnexpectedEOF)
	}
	return err
}

// fail records the sticky error. The stream is dead the moment a desync is
// seen -- conn.Join closes both legs on any Read error -- so every later
// Read returns the same hard error and can never manufacture bytes.
//
// The desync counter (SPEC-CLUSTER23) counts only the deaths the CODEC
// determined -- the errStreamDesync-marked framing violations and the
// mid-frame truncation readErr classifies -- never the raw error an inner
// conn hands back when the join closes a healthy stream underneath a
// blocked read. fail() is unreachable twice for one error (the sticky check
// in Read precedes every fail site), so the add is once-per-death, not
// once-per-Read.
func (c *Conn) fail(err error) (int, error) {
	if errors.Is(err, errStreamDesync) || errors.Is(err, io.ErrUnexpectedEOF) {
		c.desyncs.Add(1)
	}
	c.readErr = err
	return 0, err
}
