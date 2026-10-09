package dedup

import (
	"bytes"
	"fmt"

	"golang.org/x/crypto/blake2b"
)

// ringSlots is the table capacity: 256 chunks x maxChunk 16 KiB = 4 MiB live
// bytes per direction, the spec's hard bound (table.memBytes below is its
// runtime witness). 256 is also why a u16 fits the wire slot id with room for
// the liveness window arithmetic in fetch.
const ringSlots = 256
const ringMask = ringSlots - 1

// slot is one ring entry. The buffer is allocated on first use and reused
// across evictions (grown only if a bigger chunk arrives), so an idle or
// lightly-deduped stream never pays the full 4 MiB -- the bound is on LIVE
// bytes, which is what memBytes accounts, not on the array's footprint.
type slot struct {
	key digest
	buf []byte
}

// table is the per-stream, per-direction chunk table: a bare-array FIFO ring
// plus a digest index.
//
// Deliberately NOT util/ring.go, which is a different shape twice over: it is
// a mutex-guarded container/list of interface{} values built for concurrent
// borrow-and-return, while this table is fixed-capacity, single-goroutine
// (one join pipe per direction -- dedup.Conn's Read and Write each own
// exactly one table), and addressed by wire-visible slot ids that must be
// arithmetically meaningful on the far end. The determinism the wire protocol
// needs -- identical insert order on both ends, therefore identical eviction
// -- holds because each direction's literal sequence is ordered, and
// per-stream ordering is the only ordering the design relies on
// (SPEC-CLUSTER21 §2; TestRingEvictionDeterminism pins state equality).
type table struct {
	slots [ringSlots]slot

	// index maps digest -> insert sequence number, the encoding side's
	// lookup. The decoding side never queries it: a REF names its slot
	// directly, and the mirror insert keeps the map only so that both ends'
	// tables are structurally identical (and so the determinism test can
	// deep-compare them).
	index map[digest]uint16

	// count is the number of inserts ever performed. Insert k lives at ring
	// index k&ringMask and carries wire slot id k&0xFFFF; the lowest
	// ringSlots entries of the sequence are live and everything older has
	// been evicted.
	count uint64

	// bytes is the live payload total across slots: inserted on insert,
	// subtracted on evict. memBytes reports it; the 4 MiB bound test reads
	// exactly this rather than guessing from runtime.MemStats.
	bytes uint64
}

func newTable() table {
	return table{index: make(map[digest]uint16)}
}

// insert stores a chunk at the next ring position, evicting the position's
// previous occupant FIFO. Only LITERALs insert -- a REF is a repeat, and
// refreshing on repeat would turn the FIFO into LRU, which the far end
// cannot mirror (it never learns about a REF-hit's "refresh" without another
// frame type). Purity of insert-on-store is what makes both ends' eviction
// sequences identical by construction.
func (t *table) insert(key digest, chunk []byte) {
	k := t.count
	old := &t.slots[int(k)&ringMask]
	if len(old.buf) > 0 {
		// The occupant cannot be in the index under a different insert
		// number: a repeated digest is answered by REF and never re-inserted,
		// so key -> k is injective and this delete is exactly the evicted
		// entry's.
		delete(t.index, old.key)
		t.bytes -= uint64(len(old.buf))
	}
	if cap(old.buf) < len(chunk) {
		old.buf = make([]byte, len(chunk))
	}
	old.buf = old.buf[:len(chunk)]
	copy(old.buf, chunk)
	old.key = key
	t.index[key] = uint16(k)
	t.bytes += uint64(len(chunk))
	t.count = k + 1
}

// fetch resolves a REF on the decoding side and returns the chunk bytes
// (aliased into the ring -- callers copy out before the next insert can
// overwrite the slot).
//
// Both failure modes are protocol violations and hard errors, per the
// fail-loud contract: never zero-fill, never skip, never fall through.
//
//   - Liveness: d = (count-1-s) mod 65536 must satisfy d < ringSlots (inside
//     the window) and d < count (the slot was actually inserted -- this is
//     what rejects a reference into the never-populated part of the ring
//     before warmup, and an evicted slot after it). The mod-65536 arithmetic
//     is exact because the window (256) is far below half the modulus: the
//     u16 slot id identifies at most one insert of the live window.
//   - Content: the chunk is re-hashed and compared against the REF's 8-byte
//     prefix. This is the check that converts a wrong-slot bug (or a
//     corrupted frame) into an error instead of silently emitting the wrong
//     bytes: the slot choice itself is never trusted, only re-verified.
func (t *table) fetch(s uint16, prefix []byte) ([]byte, error) {
	d := (uint16(t.count-1) - s) & 0xFFFF
	if !(d < ringSlots && uint64(d) < t.count) {
		return nil, fmt.Errorf("%w: REF to slot %d outside the live window (count=%d)", errStreamDesync, s, t.count)
	}
	sl := &t.slots[int(s)&ringMask]
	sum := blake2b.Sum256(sl.buf)
	if !bytes.Equal(sum[:refDigestLen], prefix) {
		return nil, fmt.Errorf("%w: REF to slot %d failed digest verification", errStreamDesync, s)
	}
	return sl.buf, nil
}

// memBytes is the table's live payload total. Per direction the bound is
// ringSlots x maxChunk = 4 MiB; TestMemoryBound holds it under unbounded
// input.
func (t *table) memBytes() uint64 {
	return t.bytes
}
