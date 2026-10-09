package dedup

import "sync/atomic"

// The frame format is internal to this package -- nothing above the wrapper
// ever sees a frame, and no frame type leaks into msg/ or conn/ (review gate
// 1). It exists only so the receiver can reassemble the exact byte stream;
// it is not a message boundary and conveys no semantics beyond "these bytes
// are stored / not stored".
//
//	[type u8][len u16 big-endian][payload]
//
// There are no escape sequences. Escape-stuffing is where transparent-filter
// bugs live (a stuffed byte that the sender forgets to unstuff on a
// non-payload path), and it costs 2x on pathological data; a counted length
// needs neither.
const (
	frameHeaderLen = 3

	frameLiteral uint8 = 1 // payload stored AND ring-inserted on both ends
	frameTail    uint8 = 2 // partial-chunk flush; NOT stored, receiver mirrors
	frameRef     uint8 = 3 // payload is [slot u16][digest prefix 8B] = 10 bytes
)

// refPayloadLen is the fixed REF payload size: slot id plus truncated digest.
const refPayloadLen = 2 + refDigestLen

// appendBE16 / be16: frame lengths and slot ids are big-endian, matching the
// "network byte order" default a reader of this fork will assume elsewhere.
func appendBE16(dst []byte, v uint16) []byte {
	return append(dst, byte(v>>8), byte(v))
}

func be16(b []byte) uint16 {
	return uint16(b[0])<<8 | uint16(b[1])
}

func appendFrameHeader(dst []byte, typ uint8, length int) []byte {
	return append(dst, typ, byte(length>>8), byte(length))
}

// appendChunk emits one chunk as a REF when its digest is already in the
// table, else as a LITERAL followed by the insert. This is the entire dedup
// decision; note what it does NOT do -- it never compresses a LITERAL (gzip
// owns compression; one mechanism per job), and a REF does not refresh the
// table (see table.insert).
func (t *table) appendChunk(dst []byte, chunk []byte, refs *atomic.Uint64) []byte {
	key := digestOf(chunk)
	if s, ok := t.index[key]; ok {
		dst = appendFrameHeader(dst, frameRef, refPayloadLen)
		dst = appendBE16(dst, s)
		dst = append(dst, key[:refDigestLen]...)
		refs.Add(1)
		return dst
	}
	dst = appendFrameHeader(dst, frameLiteral, len(chunk))
	dst = append(dst, chunk...)
	t.insert(key, chunk)
	return dst
}

// appendFrames frames one write batch: every complete chunk the chunker
// finds, then the remainder as a TAIL. The TAIL is the latency guard
// (SPEC-CLUSTER21 §2): without it a small interactive write would sit in the
// codec until enough further bytes arrived to reach a boundary -- and since
// the far end cannot reply until the bytes arrive, that is a stall, not a
// delay. A Write returns only after all of its bytes are on the wire; there
// is no such thing as bytes buffered awaiting a boundary, and consequently
// no flush-at-close either (Close has nothing to flush, ever).
//
// The honest cost of the guard, recorded here because the bench will show
// it: a payload delivered in writes smaller than minChunk never forms chunks
// at all -- every write is a TAIL and dedups to nothing. The carrier reads
// through conn.Join's 256 KiB staging buffer, so request bodies arrive in
// large batches in practice and the repeated-prompt case chunks fine; an
// MSS-trickling sender would simply see pass-through economics. TAILs are
// also where the varying parts of real payloads land anyway (the shared
// prefix ends at a boundary; the mutation rides the tail), so not storing
// them loses nothing measurable.
func appendFrames(dst []byte, t *table, refs *atomic.Uint64, p []byte) []byte {
	for {
		n := nextChunk(p)
		if n == 0 {
			break
		}
		dst = t.appendChunk(dst, p[:n], refs)
		p = p[n:]
	}
	if len(p) > 0 {
		dst = appendFrameHeader(dst, frameTail, len(p))
		dst = append(dst, p...)
	}
	return dst
}
