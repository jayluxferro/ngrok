package dedup

import (
	"bytes"
	"math/rand"
	"testing"
)

// applyEncoder mirrors the encoder's insert decision (appendChunk without the
// framing): a digest already present is answered by REF and must NOT be
// re-inserted, so a determinism comparison that bypasses this would be
// comparing tables no real stream could produce.
func applyEncoder(t *table, key digest, chunk []byte) {
	if _, ok := t.index[key]; !ok {
		t.insert(key, chunk)
	}
}

func assertTablesEqual(t *testing.T, label string, a, b *table) {
	t.Helper()
	if a.count != b.count {
		t.Fatalf("%s: insert counts diverged: %d vs %d", label, a.count, b.count)
	}
	if a.bytes != b.bytes {
		t.Fatalf("%s: live byte counts diverged: %d vs %d", label, a.bytes, b.bytes)
	}
	if len(a.index) != len(b.index) {
		t.Fatalf("%s: index sizes diverged: %d vs %d", label, len(a.index), len(b.index))
	}
	for k, sa := range a.index {
		sb, ok := b.index[k]
		if !ok {
			t.Fatalf("%s: digest %v present on one end only", label, k)
		}
		if sa != sb {
			t.Fatalf("%s: digest %v maps to slot %d on one end, %d on the other", label, k, sa, sb)
		}
	}
	for i := range a.slots {
		if len(a.slots[i].buf) != len(b.slots[i].buf) {
			t.Fatalf("%s: slot %d lengths diverged: %d vs %d", label, i, len(a.slots[i].buf), len(b.slots[i].buf))
		}
		if a.slots[i].key != b.slots[i].key {
			t.Fatalf("%s: slot %d keys diverged", label, i)
		}
		if !bytes.Equal(a.slots[i].buf, b.slots[i].buf) {
			t.Fatalf("%s: slot %d contents diverged", label, i)
		}
	}
}

// TestRingEvictionDeterminism is the spec's "both ends evict identically over
// adversarial insert orders". The encoder and the decoder build independent
// tables from the same literal sequence; if eviction ever diverged -- an
// off-by-one in the ring, a refresh hiding in the REF path -- the decoder
// would resolve REFs against different chunks and the re-hash in fetch would
// be the only thing between us and silent corruption. State is therefore
// compared in full after EVERY insert, not just at the end: divergence is a
// desync, and a desync should be caught at the step that caused it.
func TestRingEvictionDeterminism(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	enc, dec := newTable(), newTable()

	// Adversarial shape: sizes sweeping the whole legal range, digests
	// sometimes repeating (the encoder path for a repeat is REF -- no
	// insert -- and the repeat exercises exactly the "REF must not refresh
	// the ring" rule that keeps the two sequences identical), with lookups
	// interleaved to prove they mutate nothing.
	for i := 0; i < 1000; i++ {
		size := minChunk + rng.Intn(maxChunk-minChunk)
		chunk := make([]byte, size)
		rng.Read(chunk)
		key := digestOf(chunk)
		if i%7 == 0 && enc.count > 0 {
			// Re-offer the newest chunk: identical content, so a correct
			// encoder REFs instead of inserting and both tables must not
			// move. (The newest slot is always occupied, which an indexed
			// probe would not be early in the warmup.)
			old := &enc.slots[int(enc.count-1)&ringMask]
			key = old.key
			chunk = old.buf
		}
		applyEncoder(&enc, key, chunk)
		applyEncoder(&dec, key, chunk)
		if i%11 == 0 {
			// Lookups are pure: fetch a live slot (and the digest index on
			// the encoder side) and confirm the state did not change.
			if enc.count > 0 {
				s := uint16(enc.count-1) & 0xFFFF
				if _, err := dec.fetch(s, nil); err == nil {
					// prefix nil cannot verify, and must error; the state
					// check below is the real assertion.
					t.Fatalf("fetch accepted a nil digest prefix")
				}
			}
		}
		assertTablesEqual(t, "after insert", &enc, &dec)
	}
}

// TestFetchFailLoud walks the failure table of fetch directly: a slot never
// stored, a slot evicted, and a live slot whose digest prefix does not match
// all hard-error; only an in-window slot with a matching prefix yields bytes.
// These are the two halves of the fail-safe contract -- the deterministic
// window check and the 2^-64 content check -- exercised separately, because
// a bug in either must surface here rather than as a wrong byte emitted
// above the wrapper.
func TestFetchFailLoud(t *testing.T) {
	tb := newTable()
	chunk := bytes.Repeat([]byte{0xAB}, 600)
	key := digestOf(chunk)
	tb.insert(key, chunk)

	// Live slot, correct prefix: the only path that returns bytes.
	got, err := tb.fetch(0, key[:refDigestLen])
	if err != nil || !bytes.Equal(got, chunk) {
		t.Fatalf("fetch of live slot: err=%v len=%d", err, len(got))
	}

	// Live slot, corrupted prefix: the re-hash must catch it.
	bad := append([]byte(nil), key[:refDigestLen]...)
	bad[0] ^= 0xFF
	if _, err := tb.fetch(0, bad); err == nil {
		t.Fatal("fetch accepted a corrupted digest prefix")
	}

	// Never-stored slot: outside the populated prefix of the ring. d < count
	// is what rejects this before warmup.
	if _, err := tb.fetch(100, key[:refDigestLen]); err == nil {
		t.Fatal("fetch accepted a slot that was never stored")
	}

	// Evicted slot: fill the ring past capacity and confirm slot 0 is
	// rejected even with its original, correct digest -- window position,
	// not content, is what retires it. Content is tagged with both bytes of
	// the index: 256 distinct chunks need the high byte, byte(256) being
	// indistinguishable from byte(0).
	newest := bytes.Repeat([]byte{byte(ringSlots % 256), byte(ringSlots >> 8)}, 300)
	for i := 1; i <= ringSlots; i++ {
		c := bytes.Repeat([]byte{byte(i % 256), byte(i >> 8)}, 300)
		tb.insert(digestOf(c), c)
	}
	if _, err := tb.fetch(0, key[:refDigestLen]); err == nil {
		t.Fatal("fetch accepted an evicted slot")
	}
	newestKey := digestOf(newest)
	if _, err := tb.fetch(uint16(ringSlots), newestKey[:refDigestLen]); err != nil {
		t.Fatalf("fetch of the newest slot failed: %v", err)
	}
}

// TestWindowWraparound pins the slot-id arithmetic at the u16 seam: slot ids
// wrap mod 65536 while liveness is a 256-wide window behind the insert
// count. A window check done in the wrong arithmetic would accept a stale id
// after wraparound (or reject live ones); with the modulus 256x the window,
// in-window ids are unique mod 65536 and the check is exact. Drive count
// across 65536 and past it, fetching everything live.
func TestWindowWraparound(t *testing.T) {
	tb := newTable()
	chunk := bytes.Repeat([]byte{0x5A}, 600)
	key := digestOf(chunk)
	tb.insert(key, chunk) // slot id 0, ring index 0

	// Push the count around the u16. Every insert must carry content unique
	// across the whole test -- the encoder path never re-inserts a live
	// digest, and a duplicate insert would desync the index from the ring in
	// a way no real stream can produce (the evict-delete would drop the
	// newer mapping). The (i+1, cycle) pair tags each chunk uniquely.
	tag := func(i, cycle int) []byte {
		return bytes.Repeat([]byte{byte(i + 1), byte(cycle)}, 300)
	}
	lastCycle := 256
	for cycle := 0; cycle <= lastCycle; cycle++ {
		for i := 0; i < ringSlots; i++ {
			c := tag(i, cycle)
			tb.insert(digestOf(c), c)
		}
	}
	// count is now 1+257*256; the original slot id 0 is long dead.
	if _, err := tb.fetch(0, key[:refDigestLen]); err == nil {
		t.Fatal("slot id 0 accepted after wraparound despite eviction")
	}

	// A live id near the wrap seam: the newest insert is count-1; its u16 id
	// is (count-1) & 0xFFFF. Fetch it by computing the id the encoder would
	// emit, which exercises the subtraction across the seam.
	newest := uint16(tb.count-1) & 0xFFFF
	last := tag(ringSlots-1, lastCycle)
	lastKey := digestOf(last)
	got, err := tb.fetch(newest, lastKey[:refDigestLen])
	if err != nil || !bytes.Equal(got, last) {
		t.Fatalf("fetch across the u16 seam failed: err=%v match=%v", err, bytes.Equal(got, last))
	}
}

// TestMemoryBound is the 4 MiB hard bound held under unbounded input: after
// 1000 max-size inserts (16 MB offered), the table still holds exactly
// ringSlots x maxChunk live bytes -- not a byte more, and not the 16 MB a
// leak would accumulate. The number comes from the table's own accounting
// (memBytes), which is maintained on insert and evict; the wrapper-level
// bound under a real stream is asserted in TestTransparencyFuzz.
func TestMemoryBound(t *testing.T) {
	tb := newTable()
	big := make([]byte, maxChunk)
	for i := 0; i < 1000; i++ {
		big[0] = byte(i)
		big[1] = byte(i >> 8)
		tb.insert(digestOf(big), big)
	}
	if got, want := tb.memBytes(), uint64(ringSlots)*maxChunk; got != want {
		t.Fatalf("live bytes after 1000 max-chunk inserts: got %d, want %d", got, want)
	}
	if len(tb.index) != ringSlots {
		t.Fatalf("index size after unbounded inserts: got %d, want %d", len(tb.index), ringSlots)
	}
}
