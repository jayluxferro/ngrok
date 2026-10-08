# SPEC-CLUSTER21 — carrier_dedup: per-stream content-defined chunk dedup on the agent↔server carrier

Status: draft (target v1.0.21)

Every proxied connection crosses three legs: visitor↔ngrokd, ngrokd↔agent
(the carrier), agent↔local service. Only the carrier has our binary on both
ends — and the carrier is where nothing else looks: gzip owns compressible
*responses* (agent-side, visitor-negotiated), requests are compressed by
nothing, and the carrier never had zero-copy to lose (splice fires only on
plain-socket legs; carrier streams are smux/QUIC streams that already pay a
userspace staging copy — conn/zerocopy.go:33-38).

This cluster adds an experimental, per-tunnel opt-in byte filter on the
carrier: content-defined chunking (Gear/FastCDC), Blake2b-128 chunk digests,
per-stream per-direction FIFO tables, in-band framing negotiated on the
existing RegProxy/StartProxy handshake. A repeated 32 KiB LLM system prompt
over one keep-alive connection is the shape of the win: the prefix chunks
become 10-byte references.

The organizing rule is **fail-loud transparency**: the codec reassembles the
exact byte stream or the connection dies with an error — never zero-fill,
never skip, never fall through. A desync can only be a bug (both endpoints
ship together in this fork), and a bug's honest expression is a dead
connection the visitor retries, not silently corrupted bytes.

## Objectives

1. `carrier_dedup: true` — a per-tunnel client config key, default off.
   Engages on every proxy stream the tunnel opens, both directions,
   independently.
2. Negotiation on the existing handshake, version-safe with old peers:
   RegProxy carries an additive proposal, StartProxy an additive ack; an
   unacked proposal stays pass-through (one Info log per tunnel, not per
   stream). No caps-machinery change.
3. The codec (new `dedup/` package): Gear-hash content-defined chunking
   (avg 4 KiB, min 512 B, max 16 KiB), Blake2b truncated to 16 bytes as
   the table key, 256-slot FIFO ring per direction (4 MiB hard bound),
   [type u8][len u16] framing with LITERAL / TAIL / REF frame types.
4. A per-stream close line logging offered vs framed bytes — the honest
   win number (loopback cannot show bandwidth as wall-clock; the counters
   can show it as bytes).
5. Bench payloads in scripts/bench.sh: llm-json (repeated system prompt
   with a head mutation — the CDC resync case), sse (static boilerplate),
   and the random-bulk control (expected ~0.1% overhead, no surprise
   slowdown), each on/off × both carriers, plus a netem-constrained
   carrier variant for the daedalus Linux VM where saved bytes convert
   to transfer time.

## Non-goals (binding)

- **Cross-stream or cross-session tables.** smux/QUIC streams are
  independently ordered; a REF on stream B cannot be guaranteed to follow
  the STORE on stream A at the receiver without a store/ack protocol
  riding reverse-direction control frames. That is real machinery — a v2
  that v1's counters must justify (cross-stream demand visible in the
  logs before it is built).
- **Persistence** of any table across connections or processes. Never.
- **Response-direction ambition.** Both directions are framed (the codec
  is symmetric), but when the visitor accepts gzip the response direction
  carries gzip output and hits ~0 — documented, accepted; requests are
  the win. Dedup is not a gzip replacement; the two are orthogonal
  (gzip: response bodies, visitor-negotiated; dedup: carrier bytes,
  operator-configured).
- **UDP tunnels, agent-terminated tunnels.** UDP proxy streams carry
  length-framed datagrams a byte-stream codec would corrupt;
  agent-terminated tunnels carry TLS ciphertext (fresh AEAD nonces — zero
  repeats, pure overhead). Both combinations are refused at config load,
  loudly, naming the tunnel.
- **Visitor-leg or local-leg dedup.** A filter there has a non-ours
  endpoint and kills splice on raw tcp tunnels. Disqualified by
  construction, not by effort.
- **Literal compression inside the codec.** The codec never compresses a
  LITERAL; gzip owns compression. One mechanism per job.

## Design

### 1. Negotiation — `msg/` (additive fields, old peers safe)

Both wire messages are `encoding/json` with default unmarshaling: unknown
fields are ignored by old binaries, so additive booleans are version-safe
without touching the capability exchange.

- `RegProxy` gains `Dedup bool` — the client proposes, setting it only
  for streams of tunnels with `carrier_dedup: true`.
- `StartProxy` gains `DedupAck bool` — the server confirms.

Flip points, ordered: the client engages after reading StartProxy (an ack
means the server wrapped its side; no ack means pass-through); the server
engages after *writing* the ack. RegProxy/StartProxy are the only msg
frames on a proxy stream, so nothing later in the stream's life is
mode-ambiguous. The server's kill switch (`-disableCarrierDedup`, below)
answers without the ack; the client logs one Info per tunnel
(internally deduplicated), never per stream.

### 2. The codec — `dedup/` (new package)

**Chunking.** Gear rolling hash (one multiply+mask per byte,
FastCDC-family), average 4 KiB via a 12-bit mask, min 512 B, max 16 KiB.
Content-defined, not fixed-size, because a length-changing field (a
timestamp, a nonce, the X-Forwarded-For the server injects) shifts every
fixed boundary after it — CDC resynchronizes within ~an average chunk
spacing of the mutation. That resync is the entire difference between
"works on identical payloads" and "works on real LLM JSON".

**Digests.** `blake2b.Sum256` truncated to 16 bytes as the table key —
x/crypto/blake2b is already an indirect dependency (quic-go pulls it;
promote indirect→direct, no new module), it has AVX2 assembly in-tree,
and ~1 ns/B amortized at boundaries is far under any home uplink's
need. Keyed mode (key derived from the session secret) is noted as free
defense-in-depth for a shared carrier; optional, not v1.

**Table.** Per stream, per direction: a 256-slot FIFO ring (bare array,
single-goroutine — deliberately NOT util/ring.go, which is a different
shape) plus `map[digest]slot`. Eviction is deterministic FIFO — identical
insert order on both ends because each direction's literal sequence is
ordered, and per-stream ordering is the only ordering the design relies
on. Hard bound: 256 × 16 KiB = 4 MiB per direction.

**Framing.** In-band, internal to the wrapper — `[type u8][len u16]
[payload]`; types LITERAL (stored, inserted into the ring on both ends),
TAIL (a partial chunk flushed to keep latency causal — NOT stored,
receiver mirrors), REF (`[slot u16][digest 8B truncated]`, 10 bytes).
Nothing above the wrapper ever sees a frame; Read reassembles the exact
byte stream. No escape sequences — escape-stuffing is where
transparent-filter bugs live, and it costs 2× on pathological data.

**The latency guard.** Every Write emits frames for complete chunks,
then flushes the remainder as a TAIL. Without this, a small interactive
write sits in the codec until the next write — and since the far end
cannot reply until the bytes arrive, that is a stall, not a delay.
Boundary detection is causal; the TAIL keeps it that way for shell-ish
and SSE-sized writes. TAILs are the varying parts of payloads in
practice (the shared prefix ends at a boundary; the mutation rides the
tail), so not storing them loses nothing measurable.

**Failure semantics — the fail-safe contract.** On REF: fetch the slot,
re-hash, compare to the REF's 8-byte digest prefix. Miss or mismatch is
a protocol violation: Read returns a hard error, the join's staged copy
errors, both legs close — the visitor connection dies loudly. Never
zero-fill, never skip, never fall through. The 8-byte verification turns
even a wrong-slot bug from silent corruption into a detected abort
(undetected probability 2⁻⁶⁴ per ref).

### 3. Integration points

- Client wrap site: `client/model.go` (the `conn.Wrap(stream, "pxy")` in
  the proxy-dial path) — wrapper installed pass-through, engaged on the
  StartProxy ack.
- Server wrap site: `server/mux.go` (the accepted-stream wrap in
  `registerProxyStream`; QUIC streams arrive through the same seam).
- Server ack site: `server/tunnel.go` (where StartProxy is written from
  the pool).
- Both wrappers are `net.Conn` decorators: protocol-agnostic opaque
  bytes, so http/tcp tunnel mixtures, the rewriter's connpair, and the
  h2c transcoder all ride unchanged above them.

### 4. Configuration

```yaml
tunnels:
  ollama:
    proto:
      http: 11434
    carrier_dedup: true
```

- Validation (client, at load, tunnel named): a tunnel with
  `carrier_dedup: true` may not declare a udp protocol or
  `agent_tls_termination`. The udp refusal covers mixed tunnels too —
  udp flows ride the same proxy-stream machinery with length-framed
  datagrams inside, so "the http legs dedup, the udp legs don't" is not
  a per-stream distinction the negotiation can express (the proposal is
  per stream, but the config key is the tunnel's, and an operator
  reading `carrier_dedup: true` on a mixed tunnel would be right to
  expect it means the tunnel); refusing the combination is the honest
  spelling. The agent-TLS refusal is the zero-value case: the carrier
  holds TLS ciphertext, fresh AEAD nonces mean zero repeats, and the
  codec would be pure overhead plus a second framing layer over
  encrypted bytes.
- The default is never written back into the field (the
  `upstream_protocol` round-trip rule).
- Server: `-disableCarrierDedup` (default false) — an ops kill switch
  that stops confirming proposals; existing tunnels fall back to
  pass-through without client changes. Both binaries ship together, but
  an experimental feature owes its operators a big red lever.

### 5. Observability

- Per stream, at close, one Info line both processes can log:
  `carrier_dedup: offered=X framed=Y refs=Z` — the honest win number.
  (The join already logs "Copied %d bytes"; this rides the same hook.)
- The v1.0.20 bot's `/status` and the admin `/metrics` grow nothing in
  v1 — per-stream logs are the v1 surface; aggregated counters are a
  follow-up if the feature survives its bench.

### 6. Bench — scripts/bench.sh

Payloads (each run on/off × smux/QUIC):
1. **llm-json** — ~100 POSTs over one keep-alive connection: shared
   32 KiB system prompt, ~200-byte varying suffix, timestamp/nonce near
   the head (forces the CDC resync; this payload IS the kill criterion).
2. **sse** — text/event-stream with static per-event boilerplate; run
   with and without `Accept-Encoding: gzip` (the dedup-under-gzip case).
3. **control** — the existing 64 MiB random bulk, dedup ON: expected
   ~0.1% wire overhead, no surprise slowdown, CPU bounded.
4. **netem variant** (daedalus Linux VM): `tc qdisc` the carrier to
   ~10 Mbit so saved bytes become transfer time — the one variant that
   shows a user-visible win honestly. Loopback cannot (no bandwidth
   constraint); the loopback runs establish the ratio, the cost, and the
   control-case overhead.

**Pre-registered expectations** (stated before the runs, so the bench can
fail them): llm-json ≥ ~50% offered-bytes reduction (below that, the
feature is not earning its complexity — kill criterion); control ≤ ~1%
overhead; CPU delta small and reported; p95 neutral-to-slightly-worse on
loopback and admitted as such. QUIC and smux columns both present (the
harness already fails a run whose QUIC carrier did not establish).

## File ownership (workstreams)

| Lane | Owns |
|---|---|
| **A — codec** | `dedup/*.go` (codec: CDC, ring, framing, wrapper; tests: transparency fuzz, resync corpus, fail-loud desync, boundary min/avg/max, ring eviction determinism) |
| **B — client** | `client/model.go` (wrap site + negotiation + Info-dedup), `client/config.go` (key + refusals), `client/config_test.go` |
| **C — server + msg** | `msg/` (RegProxy/StartProxy additive fields — the one shared file, owned here; B codes against the names in §1), `server/mux.go` (wrap site), `server/tunnel.go` (ack), `server/cli.go`+`server/config.go` (kill switch) |
| **D — bench & docs** (after A/B/C) | `scripts/bench.sh` payloads, `README.md`, `docs/CHANGELOG.md`, `version/version.go` |

A first (pure new package, no dependencies on B/C); B and C in parallel
against A's landed API + §1's field names; D last. No lane touches
`rewriter/`, `conn/` beyond reading, or `policy/`.

## Testing strategy

- **dedup/**: byte-exact transparency (io.Reader/Writer random fuzz —
  anything the codec does to the stream must be invisible above it);
  the resync corpus (mutate byte 10 of a 32 KiB body, expect prefix-miss
  then post-resync hits — the count is asserted, not eyeballed);
  fail-loud (corrupt a REF's digest → Read errors, never wrong bytes;
  wrong-slot → detected by re-hash); boundary discipline (min/avg/max
  over a large corpus); TAIL causality (a Write returns only after its
  bytes are framed — no such thing as bytes buffered awaiting a
  boundary); ring eviction determinism (both ends evict identically over
  adversarial insert orders); 4 MiB bound held under unbounded input.
- **client**: the three refusals (udp proto, agent_tls_termination,
  mixed-udp) naming the tunnel; the round-trip rule; negotiation states
  (ack → engaged; no ack → pass-through + exactly one Info per tunnel
  across many streams — asserted with a test logger).
- **server**: the kill switch (proposal unacked when set; no per-stream
  log spam); the ack written before the server-side wrapper engages
  (ordering pinned by a test that feeds frames immediately).
- **e2e**: a `dedup` group — dedup tunnel serving real HTTP (curl
  correctness through the codec, both carriers); an old-binary
  interop case (client with dedup against a server binary lacking the
  ack → pass-through, traffic correct, one Info); the llm-json payload
  end-to-end with the offered/framed ratio asserted ≥ the kill line;
  kill switch on → traffic still correct.
- **bench**: the §6 matrix, results recorded in the changelog with the
  pre-registered expectations checked off, on the daedalus VM for netem.

## Review gates

1. **Transparency**: the fuzz test green; no path above the wrapper can
   observe framing (grep: the wrapper's Read/Write are the only frame
   producers/consumers; no frame type leaks into msg/ or conn/).
2. **Fail-loud**: the desync tests green; grep the codec for any
   zero-fill/skip/fall-through on error — none exists.
3. **Negotiation ordering**: ack-then-engage pinned both sides;
   old-peer fallback pinned; kill switch pinned.
4. **Refusals**: the config refusals green, tunnel named, both
   spellings (udp any, agent_tls_termination).
5. **Additivity outside the design**: `git diff --stat v1.0.20..` touches
   no Go file outside `dedup/`, `client/model.go`, `client/config*.go`,
   `server/mux.go`, `server/tunnel.go`, `server/cli.go`,
   `server/config.go`, `msg/` (the two additive fields only),
   `version/version.go`.
6. **Full gates**: vet/test/-race on dedup, client, server; full e2e
   green incl. the new group; bench matrix run with expectations
   checked; `msg/` diff is exactly the two fields.
7. Docs: README (the key, the honest win/cost framing, the refusals),
   CHANGELOG 1.0.21 (bench numbers with the loopback caveat stated the
   way the QUIC bench states its own), spec index + status flip.

## Release

v1.0.21.
