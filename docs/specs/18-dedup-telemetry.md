# SPEC-CLUSTER23 — carrier_dedup telemetry: per-tunnel and global counters for the v2 gate

Cluster 21 (spec 17) shipped `carrier_dedup` with log lines as its entire
observability surface: a per-stream close line on each end, regex-parsed by the
bench and asserted by six e2e scenarios, and nothing aggregated anywhere — no
counters in `/metrics`, nothing in prometheus, nothing in `tunnelSnapshot`, no
desync count. Spec 17 §53-55 gates dedup v2 on "cross-stream demand visible in
the logs before it is built": greppable logs technically carry that signal, but
as an operational matter the gate cannot be evaluated without hand-grepping.
This cluster makes the feature visible the way every other server quantity is
visible — `/metrics` JSON, prometheus, and the workbench's `/tunnels` snapshots
— without touching the wire, the codec's framing, or the hot path's lock
discipline.

The load-bearing subtlety the design must survive: **the win direction is
invisible in the existing counters.** `offered/framed/refs` advance only on the
write path (dedup/dedup.go:105-107), and the win is agent→server *requests* —
which the server receives on its *read* path. A server that aggregated only its
own write counters would aggregate the ~0 direction (the server's responses,
near-zero under gzip by design, spec 17 §Non-goals) and miss the payload
entirely. Read-direction counters are therefore not an add-on; they are the
difference between telemetry and decoration.

## Objectives

1. Per-tunnel and global carrier_dedup counters on the admin surface:
   `/metrics` JSON, `/metrics/prometheus`, and `tunnelSnapshot` (which flows to
   `/tunnels` and the workbench UI verbatim).
2. The fail-loud event counted, not just logged: desyncs increment a counter
   and still log once, exactly as today.
3. Read-direction counters (`read_wire`, `read_payload`) so the win direction
   is aggregated where the win lands — the server.
4. Spec 17's v2 gate becomes evaluable from the admin surface.
5. Zero hot-path cost beyond atomic adds: no new locks, no new allocations, no
   wire bytes.

## Non-goals (binding)

- No wire changes — `msg/` handshake keys untouched.
- No client admin surface — the client has none (client/metrics.go is internal
  go-metrics, never exposed); the client stays log-only, its close line growing
  the same appended fields.
- No v2 features: no cross-stream tables, no bigger rings, no adaptive
  parameters. This cluster measures; it does not evolve the codec.
- The close-line format is APPEND-ONLY. scripts/bench.sh (:785 regex) and six
  e2e scenarios parse it positionally; appending fields after `refs=Z` is
  backward-compatible, anything else breaks bench and e2e in the same commit
  and is refused at review gate 3.
- No per-stream time series, no per-flow breakdown beyond the tunnel.

## Design

### 1. Counters — `dedup/`

The codec (`dedup/dedup.go`) gains, beside the existing write-path
`offered/framed/refs`:

- `desyncs atomic.Uint64` — incremented in `fail()`, **only when the sticky
  error is not io.EOF**: a boundary EOF passes through `readErr` unchanged as a
  clean close (dedup.go:325-336) and still flows through `fail()`
  (dedup.go:215-218), and a clean close is not a desync. This counter is the
  fail-loud event made queryable; the once-per-direction Warn log is unchanged.
- `wireIn atomic.Uint64` — inner bytes consumed, one add per `fill()` call
  (dedup.go:304-323).
- `decodedOut atomic.Uint64` — payload bytes emitted, one add per
  `decodeFrame()` (dedup.go:283-298).

Two atomic adds per ≤16 KiB frame on the read path, the same order as the
existing per-batch write adds. Accessors mirror `Offered()/Framed()/Refs()`.
Counters advance only while engaged; a pass-through stream leaves every counter
at zero (pinned by the existing pass-through test, dedup_test.go:297-317).

### 2. Close line — both ends, appended fields only

`carrier_dedup: offered=X framed=Y refs=Z desyncs=N readWire=W readPayload=P`

Server at join teardown (server/tunnel.go:1040-1042), client in
`closeCarrierDedup` (client/model.go:923). Appending after `refs=` keeps every
positional consumer alive untouched — which is itself the review proof that the
change was append-only (gate 3).

### 3. Server aggregation — once per stream, at the existing site

At the close site where both `t` and `codec` are in scope
(server/tunnel.go:1036-1045, beside the existing `observe.onConnClose` call), a
new `observabilityStore` method — mirroring `onConnClose`'s locking
(observability.go:372-383) — folds the codec's final counters into the tunnel's
snapshot and the globals. Codec counters are atomics during the stream's life;
the store lock is touched once per stream at teardown, never on the frame path.

### 4. Surfaces — `server/observability.go`, `server/admin.go`

- `tunnelSnapshot` gains (registration-facts style, observability.go:10-33,
  but mutated at stream close like the connection counters):
  `dedup_offered`, `dedup_framed`, `dedup_refs`, `dedup_desyncs`,
  `dedup_read_wire`, `dedup_read_payload`, `dedup_streams` (engaged-stream
  count). JSON snake_case, matching `bytes_in`. They appear in `/tunnels`
  (admin.go:320-323 encodes snapshots verbatim) and therefore in the workbench
  UI with zero SPA changes.
- Globals join the counter block (admin.go:19-26 style):
  `dedup_offered_total`, `dedup_framed_total`, `dedup_refs_total`,
  `dedup_desyncs_total`, `dedup_read_wire_total`, `dedup_read_payload_total`,
  `dedup_streams_total` — surfaced in `/metrics` JSON (admin.go:236-241 style)
  and prometheus (admin.go:298-311 counter style); per-tunnel
  `ngrokd_tunnel_dedup_*{url,protocol}` lines in the existing per-tunnel loop
  (admin.go:306-317).

### 5. e2e — one admin-enabled stack in the dedup group

The dedup group's ngrokds deliberately run without `-adminAddr`
(scripts/e2e.sh:5440-5455). One stack gains `-adminAddr=127.0.0.1:19104` (free:
the group's banner inventory holds `:19090-:19103` taken elsewhere), then:

- After dedup 1's traffic: `/tunnels` shows the tunnel with non-zero
  `dedup_offered`, `dedup_streams >= 1`, and `dedup_read_wire` > 0 — the
  win-direction assertion, server-side.
- `/metrics` JSON carries the globals; `/metrics/prometheus` carries both the
  `ngrokd_dedup_*_total` lines and the per-tunnel `ngrokd_tunnel_dedup_*` line
  for the dedup tunnel.
- The kill-switch stack (dedup 3) asserts a zero delta: no dedup fields move.
- The six existing close-line scenarios run UNCHANGED — the append-only proof.

## File ownership (workstreams)

Small enough for two lanes:

- **A** — `dedup/dedup.go` (counters + accessors + close-line fields),
  `server/tunnel.go` (aggregation call), `server/observability.go` (snapshot
  fields + method), `server/admin.go` (globals + surfaces), unit tests
  (extend `TestCounters`; desync-not-on-clean-close; aggregation method;
  admin surface shape).
- **B** (after A) — `scripts/e2e.sh` dedup group: admin-enabled stack + the
  four assertions above. Optionally `scripts/bench.sh` `dedup_scrape` gains
  the new keys as result columns.

## Testing strategy

- Unit: counters advance exactly (offered/framed/refs pinned already at
  dedup_test.go:547-576); clean boundary close leaves `desyncs` at 0 while a
  genuine mid-frame desync increments it; pass-through leaves all at zero;
  the aggregation method folds correctly under `-race` with concurrent
  closes; admin JSON/prometheus shape tests follow the existing admin_test
  idioms.
- e2e: the four new assertions plus the six unchanged close-line scenarios.
- Bench: the dedup legs re-run before/after — bulk especially (the codec
  halved smux bulk once; two more atomic adds per frame must not move it
  beyond noise). This is gate 4, not optional.

## Review gates

1. gofmt -l clean; go vet; full `-race -tags debug` sweep green.
2. Desync counter excludes clean closes — verified by a test that closes at a
   frame boundary and asserts zero.
3. Append-only proof: bench.sh's :785 regex and all six e2e close-line
   scenarios pass WITHOUT modification. Any consumer edit = the change was
   not append-only = refuse.
4. Bench dedup legs within noise of the pre-change numbers (same tree, same
   machine, both orderings).
5. Kill-switch and pass-through paths show zero deltas everywhere.
6. Full e2e suite green; CI green before tag.

## Release

v1.0.22. CHANGELOG states the win-direction rationale in one sentence (why
read counters are the point, not a nicety) and the honest scope: this measures
the feature; it does not change it. v2 remains gated — now on counters an
operator can actually read.
