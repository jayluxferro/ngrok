package dedup

import "golang.org/x/crypto/blake2b"

// Chunking parameters (SPEC-CLUSTER21 §2, docs/specs/17-carrier-dedup.md).
//
// The chunker is content-defined (CDC), not fixed-size, because the payloads
// this feature targets mutate near their head: a timestamp, a nonce, the
// X-Forwarded-For the server injects. A fixed boundary after the mutation
// shifts by the mutation's length, so every subsequent chunk digest changes
// and a second copy of the payload dedups to nothing. A content-defined
// boundary is a function of local content only, so the stream resynchronizes
// within a few dozen bytes of the mutation -- on the Gear hash specifically,
// within the hash's effective window, which is shorter than the mandatory
// minimum below and therefore never shifts a real boundary at all
// (TestResyncCorpus pins this).
const (
	// minChunk is the shortest chunk the hash is allowed to cut. Boundaries
	// below this are suppressed regardless of the hash, which bounds the
	// framing overhead a pathological payload can force: at worst one frame
	// header per minChunk bytes.
	minChunk = 512

	// maxChunk is the forced cut. Without it a payload whose Gear hash never
	// hits the trigger would grow the pending chunk without bound, and the
	// frame header's u16 length with it.
	maxChunk = 16 * 1024

	// avgBits is the trigger mask width: a boundary fires when the rolling
	// hash's low avgBits bits are all zero, i.e. with probability 2^-avgBits
	// per candidate byte. 12 bits is the "average 4 KiB" of the spec.
	avgBits = 12
	avgMask = (1 << avgBits) - 1
)

// The expectation stated honestly, because the boundary test asserts against
// it: with the trigger suppressed until minChunk, the chunk length is
// minChunk + Geom(1/4096), so the expected chunk over random data is
// 512 + 4096 = 4608 bytes, not 4096. The "4 KiB average" names the mask (the
// CDC hazard rate), and the mandatory minimum shifts the mean up by half a
// kilobyte. FastCDC's normalized two-mask scheme can pull the mean onto the
// nominal target, at the price of a second mask and a normalization point;
// v1 keeps the single mask the spec names and the test asserts the 4608
// expectation (chunker_test.go, TestBoundaryDiscipline).

// gear is the Gear hash's per-byte table. Gear is the FastCDC family's
// cheapest rolling hash -- one shift and one add per byte, no division, no
// window buffer: h = (h<<1) + gear[b]. The trigger only reads the low
// avgBits bits, which the shift retires after ~avgBits bytes, so the hash's
// effective window is ~12 bytes. That short window is what makes resync
// immediate: a mutated byte can only influence boundary candidates within a
// dozen bytes of itself, and every candidate below minChunk is suppressed
// anyway.
//
// The values only need to look uniform; they must be IDENTICAL on both ends,
// which is trivially true here (both binaries embed the same table) but is
// still generated from a fixed seed rather than written as literals so the
// generation is checkable at a glance and the table stays 6 lines instead of
// 32. xorshift64*, seeded from the golden-ratio constant, zero mapped away (a
// zero entry would make a repeated NUL byte... still fine, but there is no
// reason to allow it).
var gear = func() [256]uint64 {
	var g [256]uint64
	x := uint64(0x9E3779B97F4A7C15)
	for i := range g {
		x ^= x >> 12
		x ^= x << 25
		x ^= x >> 27
		v := x * 0x2545F4914F6CDD1D
		if v == 0 {
			v = 1
		}
		g[i] = v
	}
	return g
}()

// nextChunk returns the length of the first complete chunk in p: the offset
// of the first content-defined boundary at or after minChunk, or maxChunk if
// the boundary is forced, or 0 if p holds no complete chunk (the caller then
// owes the remainder a TAIL). The hash starts fresh at each call, which is
// correct because the caller resets it at every boundary and at every Write:
// the boundary decision reads only the ~avgBits bytes before the candidate,
// so nothing before the last boundary can leak into the next decision.
func nextChunk(p []byte) int {
	n := len(p)
	if n > maxChunk {
		n = maxChunk
	}
	h := uint64(0)
	for i := 0; i < n; i++ {
		h = (h << 1) + gear[p[i]]
		if i+1 >= minChunk && h&avgMask == 0 {
			return i + 1
		}
	}
	if len(p) >= maxChunk {
		return maxChunk
	}
	return 0
}

// digestLen is the full table-key width: blake2b.Sum256 truncated to 16
// bytes. Blake2b is already in the module graph (quic-go pulls it), has
// AVX2 assembly in-tree, and at ~1 ns/B amortized it is far under any home
// uplink's need; the truncation halves the map key at no measurable
// collision risk (2^-128).
const digestLen = 16

// refDigestLen is how much of the digest rides a REF frame. The receiver
// re-hashes the fetched chunk and compares these 8 bytes, which turns even a
// wrong-slot bug from silent corruption into a detected abort -- undetected
// probability 2^-64 per ref. The window/liveness check (table.fetch) is the
// deterministic half of the detection; this prefix is the content half.
const refDigestLen = 8

// digest is a truncated Blake2b-256, the table key on the encoding side.
type digest [digestLen]byte

// digestOf keys a chunk. Keyed mode (key derived from the session secret) is
// noted in the spec as free defense-in-depth for a shared carrier; optional,
// not v1.
func digestOf(chunk []byte) digest {
	sum := blake2b.Sum256(chunk)
	var d digest
	copy(d[:], sum[:digestLen])
	return d
}
