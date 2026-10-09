package dedup

import (
	"bytes"
	"fmt"
	"math/rand"
	"testing"
)

// mixedCorpus builds n bytes that alternate between the payload classes the
// bench cares about: uniform random (the control case -- should still chunk
// within bounds), repeated blocks (the dedup case), and JSON-ish text (the
// llm-json case). Deterministic for a given seed: every test in this file
// must rerun byte-identically.
func mixedCorpus(rng *rand.Rand, n int) []byte {
	out := make([]byte, 0, n)
	block := make([]byte, 3*1024)
	for len(out) < n {
		switch rng.Intn(3) {
		case 0: // random
			seg := make([]byte, 1+rng.Intn(16*1024))
			rng.Read(seg)
			out = append(out, seg...)
		case 1: // repeated block: high dedup, uniform content
			rng.Read(block)
			for len(out) < n && rng.Intn(4) > 0 {
				out = append(out, block...)
			}
		default: // json-ish text
			for len(out) < n && rng.Intn(8) > 0 {
				out = append(out, []byte(fmt.Sprintf(`{"role":"system","content":"rule %d: answer tersely","ts":"2025-01-01T00:00:%02dZ"},`, rng.Intn(9999), rng.Intn(60)))...)
			}
		}
	}
	return out[:n]
}

// TestBoundaryDiscipline is the min/avg/max gate over a large corpus: no
// chunk below minChunk, none above maxChunk, average within tolerance of the
// theoretical mean. The mean is 4608, not 4096: the 12-bit trigger mask sets
// a 1/4096 hazard per candidate byte, but candidates only start at
// minChunk=512, so chunk lengths are 512 + Geom(1/4096). chunker.go records
// why v1 keeps the single-mask shape (and what FastCDC's normalized variant
// would buy); this test asserts the stated expectation so a parameter change
// cannot quietly move the dedup granularity.
func TestBoundaryDiscipline(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	data := mixedCorpus(rng, 4*1024*1024)

	var lens []int
	rest := data
	for {
		n := nextChunk(rest)
		if n == 0 {
			break
		}
		lens = append(lens, n)
		rest = rest[n:]
	}
	tail := len(rest)

	if len(lens) < 500 {
		t.Fatalf("corpus yielded only %d chunks; boundary logic may not be exercising", len(lens))
	}
	sum := 0
	for _, n := range lens {
		if n < minChunk {
			t.Fatalf("chunk of %d bytes below minChunk %d", n, minChunk)
		}
		if n > maxChunk {
			t.Fatalf("chunk of %d bytes above maxChunk %d", n, maxChunk)
		}
		sum += n
	}
	avg := float64(sum) / float64(len(lens))
	const want = minChunk + (1 << avgBits) // 512 + 4096 = 4608
	lo, hi := want*88/100, want*112/100
	if avg < float64(lo) || avg > float64(hi) {
		t.Fatalf("average chunk %.0f outside [%d,%d] (nominal 4 KiB mask, mean %d)", avg, lo, hi, want)
	}
	if tail >= maxChunk {
		t.Fatalf("corpus tail of %d bytes should have been a chunk", tail)
	}
	t.Logf("%d chunks over 4 MiB, avg %.0f B, tail %d B", len(lens), avg, tail)
}

// TestForcedMaxCut pins the maxChunk force: a byte value whose Gear hash
// never lands on the trigger across a whole window must still be cut at
// maxChunk. The value is searched rather than named because whether a
// constant run triggers depends on gear[b]; 256 candidates make finding one
// that does not trigger a certainty in practice, and the search is
// deterministic.
func TestForcedMaxCut(t *testing.T) {
	found := -1
	for b := 0; b < 256; b++ {
		run := bytes.Repeat([]byte{byte(b)}, 3*maxChunk)
		if nextChunk(run) == maxChunk {
			found = b
			break
		}
	}
	if found < 0 {
		t.Fatal("no constant run avoids the Gear trigger; the forced-max branch is unreachable for constants -- verify the mask math")
	}
	if n := nextChunk(bytes.Repeat([]byte{byte(found)}, 100*1024)); n != maxChunk {
		t.Fatalf("constant run cut at %d, want the maxChunk force %d", n, maxChunk)
	}
}

// llmPromptBody is the resync corpus: a 32 KiB body shaped like the bench's
// llm-json payload (structured text, timestamp near the head), plus the
// spec's mutation -- byte 10 flipped. The assertion strategy is the spec's:
// the COUNT is asserted, not eyeballed.
//
// Why the expected count is exact rather than "a few": the Gear trigger reads
// only the ~avgBits bytes before a candidate, and every candidate below
// minChunk=512 is suppressed. A mutation at byte 10 can therefore influence
// no boundary at all (the first candidate sits at 512), so body2's chunk
// boundaries are byte-identical to body1's, exactly one chunk (the one
// containing the mutation) misses, and every chunk after it re-hits. That is
// the CDC resync property in its strongest form, and it is what makes the
// llm-json bench case work on real mutated payloads.
func TestResyncCorpus(t *testing.T) {
	rng := rand.New(rand.NewSource(99))
	body := llmPromptBody(rng, 32*1024)
	mutated := append([]byte(nil), body...)
	mutated[10] ^= 0xFF

	w, _ := newMemConnWriter()
	if _, err := w.Write(body); err != nil {
		t.Fatal(err)
	}
	// w.wbuf is the codec's reused batch buffer, so each write's frames must
	// be copied out before the next write overwrites them.
	wire1 := append([]byte(nil), w.wbuf...)
	if _, err := w.Write(mutated); err != nil {
		t.Fatal(err)
	}
	wire2 := append([]byte(nil), w.wbuf...)

	frames1 := walkFrames(t, wire1)
	frames2 := walkFrames(t, wire2)

	chunks1 := countType(frames1, frameLiteral)
	refs1 := countType(frames1, frameRef)
	if refs1 != 0 {
		t.Fatalf("first copy of the body emitted %d refs; nothing was stored yet", refs1)
	}

	// The resync assertions, by count:
	lit2 := countType(frames2, frameLiteral)
	refs2 := countType(frames2, frameRef)
	if lit2 != 1 {
		t.Fatalf("mutated body re-stored %d chunks, want exactly 1 (the chunk holding byte 10)", lit2)
	}
	if refs2 != chunks1-1 {
		t.Fatalf("mutated body emitted %d refs, want chunks1-1 = %d: boundaries did not resync", refs2, chunks1-1)
	}

	// And the resynced stream must still reassemble byte-exactly.
	r := newMemConnReader(append(append([]byte(nil), wire1...), wire2...))
	got := readAll(t, r, len(body)+len(mutated))
	if !bytes.Equal(got, append(append([]byte(nil), body...), mutated...)) {
		t.Fatal("decoded resync corpus diverged from the input")
	}
}

func llmPromptBody(rng *rand.Rand, n int) []byte {
	var b bytes.Buffer
	b.WriteString(`{"model":"carrier-test","created":1735689600,"messages":[{"role":"system","content":"`)
	for b.Len() < n {
		fmt.Fprintf(&b, "Rule %d: the quick brown fox jumps over the lazy dog; answer tersely and cite the rule number. ", rng.Intn(10000))
	}
	out := b.Bytes()[:n]
	// Keep the mutation site well inside the JSON preamble (a truncation
	// would put byte 10 in a region no copy shares).
	return append([]byte(nil), out...)
}
