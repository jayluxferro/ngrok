# SPEC-CLUSTER25 — opt-in `upstream_pool` for HTTP/HTTPS tunnels: the h1 twin of the transcoder

Cluster 17 gave `upstream_protocol: http2` tunnels a parsed local leg and, with
it, connection pooling for free. The default h1 local leg has none: every proxy
conn dials the upstream fresh (`client/model.go` ~1101), because the client
pipes bytes and pooling a raw socket is unsound — the client cannot know
whether a finished proxy conn ended on an h1 message boundary, so handing a
still-open socket to the next proxy conn can splice half a request onto a new
one. This cluster gives h1 upstreams the same escape hatch cluster 17 built
for h2: an opt-in parsed local leg, owned by net/http on both crossings,
behind a per-address shared pool. The default path is untouched — byte
identical — and the proxy leg keeps every property this fork exists for
(rewriter pair, traffic-policy hooks, inspector tee, XFF injection,
compression): only the local leg is parsed, the exact line cluster 17
already crossed.

Paid ngrok's prior art, honestly stated: its agent terminates HTTP by
architecture, so its upstream leg rides net/http pooling with no user-visible
flag. The fork's default leg is raw, so the parsed leg must be opt-in —
that is the whole design.

## Objectives

1. `upstream_pool: true` on http/https tunnels: N requests over k pooled
   local conns instead of N fresh dials — the accept collapse, made visible
   and pinned.
2. Default path byte-identical; the new branch lives beside the existing
   dial, which does not move (review gate 2).
3. Failure vocabulary parity with the plain dial: dead upstream answers the
   same `BadGateway` page cold (first use) and warm (dies mid-run), then
   self-heals — no poisoned pool.
4. Websockets (101 Upgrade) keep working on opt-in tunnels.
5. No new user knobs: fixed constants, the cluster-17 discipline.

## Non-goals (binding)

- NO raw-socket idle pool. Cross-proxy-conn socket reuse without parsing is
  unsound on a byte pipe (no boundary knowledge); this is a design refusal,
  not a deferred item.
- No UDP (the connected-socket anti-reflector design stands, `client/model.go`
  ~1174-1180), no tcp legs, no `forward_to` (no local dial happens) — all
  refused at validation, never at runtime.
- No `upstream_protocol: http2` combination (that leg already pools; both
  cannot own the local dial) and no `alpn` containing "h2" (alpn-h2 visitors
  are relayed raw to the local leg; the client never branches on
  NegotiatedProtocol, so the bridge would parse h2 bytes as h1 — verified
  absence in client/). `alpn: ["http/1.1"]` composes.
- No visitor-leg, wire-protocol, or server changes.
- No real-RTT local-leg netem scenario: `scripts/bench-netem` shapes the
  visitor→edge leg only. Flagged as future bench work; not faked here.
- No per-request streaming-behavior regressions: SSE/flush parity is pinned
   (spec 17's fixtures are the crib).

## Design

### 1. Config surface

`upstream_pool: true` — bool on TunnelConfiguration, yaml omitempty, default
OFF, never written back on SaveAuthToken (the carrier_dedup discipline,
`client/config.go` ~133-142: zero value IS the default). Mirrored on
`mvc.Tunnel` (`client/mvc/state.go` ~55 precedent), resolved at the
config→tunnel boundary like UpstreamProtocol (`client/model.go` ~819).

`validateUpstreamPool` (modeled on validateUpstreamProtocol ~1386 and
validateCarrierDedup) refuses, in the family's established voice:
- any non-HTTP proto leg, tcp/udp including "+"-mixed;
- `forward_to` (the local dial doesn't happen);
- `upstream_protocol: http2`;
- `alpn` containing "h2".
Composes with: `upstream_protocol: http1` (the feature's exact shape),
agent_tls_termination (it transforms the remote leg; the local dial precedes
it), carrier_dedup (carrier leg), compression and the header keys (proxy leg).

### 2. The bridge — `client/upstreamh1.go`

The h1 twin of cluster 17's transcoder: `net.Pipe` + the one-conn-listener
`http.Server` + a shared per-address `*http.Transport` serving an
`httputil.ReverseProxy` handler. Shared scaffolding (oneConnListener, pipe
bridge helpers) is EXTRACTED from `client/upstreamh2.go` into
`client/upstream_shared.go` — mechanical move only; cluster-17's tests
staying green is the safety proof. This codebase does not hand-roll framing
on data paths: net/http owns both crossings.

- `FlushInterval: -1` — streaming/SSE parity.
- `Rewrite` (not Director): suppress ReverseProxy's XFF append. The fork's
  rewriter already injects X-Forwarded-For unconditionally on the proxy leg
  (~1656-1658); the bridge must carry that value through VERBATIM, never
  append a second. The missing-ConnPool bug class from cluster 17, h1
  edition — e2e-pinned (gate 3).
- `MaxIdleConnsPerHost: 100` explicit — the default of 2 silently defeats
  pooling under concurrency.
- `IdleConnTimeout: 90s` mirroring `upstreamH2IdleTimeout` (same comment
  style); deliberately NO ResponseHeaderTimeout (slow local services keep
  plain-dial parity; visitor patience is the bound — the cluster-17 ruling).
- Upgrades: ReverseProxy's 101 passthrough is the TARGET (h1 can upgrade;
  refusing would regress websockets that work through today's raw pipe). If
  passthrough proves unsound on net.Pipe at implementation, the documented
  REFUSAL ships instead — whichever ships is e2e-pinned and stated in the
  key's config comment. No silent choice.
- Failure semantics: `http.Transport` cannot pre-seed its pool, so "eager
  dial" becomes a synchronous liveness dial on the first bridge per address
  until the first successful RoundTrip marks it warm. Cold dead-service
  fails at the existing 502 path; warm death answers per-request with the
  SAME `BadGateway` constant (~106) and the transport retires the conn —
  same wire vocabulary as cluster 17, detection point documented. No h1 PING
  exists: a silently-dead pooled conn is noticed by the next request failing.
  Weaker hygiene than h2; documented, accepted.
- Content-Length-across-crossing bugs (the cluster-17 class) do not exist
  here: ReverseProxy passes response framing through as received; h1→h1 has
  no protocol crossing.

### 3. Dial-site wiring

`client/model.go` ~1096-1102 gains one branch
(`tunnel.UpstreamPool → dialUpstreamH1Pooled(tunnel)`); the existing else
branch stays byte-identical. Known behavior on opt-in tunnels: the local-leg
inspector tee sees Go-serialized h1 (header case/order may differ from the
visitor's bytes) — dev-inspection only, documented.

## Bench

The proof is fixture-side, in `scripts/bench_carrier.rb`: extend the shared
upstream fixture (write_fixtures ~372-419) to count accepted connections and
report `upstream_accepts` beside the existing keys (log-offset before/after
pattern ~759-770). Reuse scenario_conn_rate (~897, `Connection: close`) and
keep-alive (~961) unchanged; run the harness's OFF-vs-ON compare (two agent
configs differing in exactly this yaml key).

- Expected: OFF → accepts ≈ N requests; ON → accepts collapse to k << N
  (bounded by concurrency + MaxIdleConnsPerHost). upstream_accepts is the
  headline metric; visitor-side keepalive_conns is expected ~unchanged and
  labeled honestly.
- Loopback honesty: dial+accept+teardown ≈ 0.1-0.3 ms, so conn-rate p50/p95
  moves single-digit-to-tens of percent at localhost; the real win case is a
  real-RTT local leg (container/VM hop, accept queueing, per-conn-state
  upstreams) — stated in the CHANGELOG, not measured here (non-goal above).
- `proxySetupTimer` (client/metrics.go ~17) already spans dial+setup and
  shows the delta directly; byte metrics keep their meaning (bytes still
  count pipe crossings, framing included).

## e2e (scripts/e2e_run.sh)

1. Byte-exact body + Content-Length preserved through the bridge.
2. Reuse proof: N requests, upstream accepts ≤ k, all 200.
3. Dead upstream cold → 502 page byte-identical to plain-dial BadGateway.
4. Upstream restart mid-run → 502 then self-heal, no poisoned pool.
5. Websocket/101 — pins whichever upgrade behavior shipped.
6. SSE first-byte-before-end (flush parity; dedup fixtures' SSE upstream is
   the crib).
7. No double XFF: exactly one X-Forwarded-For, the visitor IP.
8. Load-time refusal matrix: tcp / udp / http2-combo / alpn-h2-combo /
   forward_to.
9. agent_tls_termination + upstream_pool composes.
10. SaveAuthToken round-trip: tunnels lacking the key don't grow it.

## File ownership (workstreams)

- **A** — `client/upstream_shared.go` (new, extracted), `client/upstreamh1.go`
  (new), `client/upstreamh2.go` (extraction only), `client/config.go` +
  `client/config_test.go` (field + validator), `client/mvc/state.go`,
  `client/model.go` (resolution ~819 + dial branch ~1096-1102),
  `client/model_proxy_test.go` (wiring), bridge unit tests.
- **B** (after A) — `scripts/bench_carrier.rb` (fixture + columns),
  `scripts/e2e_run.sh` (the 10 scenarios above).

## Review gates

1. gofmt -l clean; go vet; full `-race -tags debug` sweep green.
2. Default-path byte-identity: the else branch and the raw-pipe relay are
   diff-identical to pre-cluster master.
3. XFF: exactly one header, e2e-pinned; MaxIdleConnsPerHost set explicitly
   (grep + test) — the two silent-default traps.
4. Bench OFF-vs-ON: accept collapse N→k demonstrated; conn-rate deltas
   reported as measured, not oversold; keepalive legs within noise.
5. Upgrade behavior pinned (passthrough or documented refusal) — no silent
   fallback.
6. Full e2e suite green; CI green before tag.

## Release

Next release in landing order after the telemetry + toolchain trains
(expected v1.0.24). CHANGELOG states the honest shape: the structural change
is the accept collapse; loopback rps movement is small and the real-RTT case
is the use case; the key is opt-in because the default leg is deliberately
raw.

## Amendment 2026-10-09 (post-implementation): as built

Spec bodies are immutable; this section records what shipped against the
design, including the two places reality corrected a guess.

Shipped exactly the opt-in shape: `upstream_pool: true` on
`TunnelConfiguration` (`client/config.go`, `validateUpstreamPool` with the
four refusals verbatim, tcp/udp/forward_to/http2/alpn-h2, "+"-mixed pinned),
the `mvc.Tunnel` mirror, and the one dial-site branch in `client/model.go`.
The extraction is real: `client/upstream_shared.go` (out of
`client/upstreamh2.go`, mechanical — cluster 17's tests green unchanged),
and the bridge in `client/upstreamh1.go`: `upstreamH1PoolFor` per local
address, `upstreamH1IdleTimeout` 90s, `upstreamH1MaxIdleConnsPerHost` 100
explicit, no `ResponseHeaderTimeout` (the cluster-17 ruling carried),
`FlushInterval: -1`, `Rewrite` mode carrying the rewriter's XFF verbatim.

The upgrade ruling resolved to PASSTHROUGH: ReverseProxy's 101 handling
(hijack + splice) works over the net.Pipe one-conn-listener bridge, e2e
scenario 5 pins a genuine upgrade with a post-upgrade frame round-trip, and
the key's config comment states it. No refusal was needed.

Warm/cold detection points as built: cold is the first-use synchronous
liveness dial (`ensureWarm`, per address, until the first successful
RoundTrip) — a cold dead service fails into the existing `writeBadGateway`
HTTP/1.0 path byte-identically, e2e-pinned as "same page modulo the
hostname", whose substitution moves only the Content-Length digit
writeBadGateway itself computes. Warm is `ModifyResponse` (the only moment
the name is honest — it runs on success including 101, never on RoundTrip
error); a warm death answers the bridge's HTTP/1.1 502, a fingerprint
deliberately distinct from the cold page, and the next request re-dials —
self-heal pinned on a same-port restart with no operator action.

Harness names as built: `scripts/e2e.sh` (the spec's `e2e_run.sh`) and
`scripts/bench.sh` (the spec's `bench_carrier.rb`) — the same renames the
two preceding clusters' amendments recorded.

Bench as built: the shared upstream fixture counts accepts to a per-accept
log; the OFF leg's count is VALIDATED equal to the request count (200 fresh
visitor connections = 200 plain dials) before the ON number may be read;
the ON leg measured 0 new accepts on its first live run — the warmup's
pooled conn, inside its 90s idle window, served all 200 — recorded because
the honest expectation includes zero, not because a "~1" guess failed.
One fixture lesson worth keeping: a pooled client holds idle keep-alive
connections open BY DESIGN, and the bench's single-threaded python fixture
froze exactly the way a single-threaded upstream behind `upstream_pool`
would in production (it served the pooled tunnel's first response and then
blocked forever reading the next request off the held conn). The pool leg's
fixture is threaded; accept counts stay exact — they are taken on the
accept-loop thread — and the other legs keep the historical shape.

e2e as built: the ten scenarios shipped as the pool group of
`scripts/e2e.sh`. The SSE probe initially asserted the visitor's stream
"ends with the last event's bytes" — unreachable through
`httputil.ReverseProxy`, which strips the upstream's hop-by-hop
`Connection: close` and re-serializes the unknown-length body as chunked;
two early "passes" had been truncation accidents (a reset that chopped the
chunked terminator satisfied the success condition). The shipped probe
asserts content membership plus a completed chunked stream. The
SaveAuthToken scenario pins the rewrite's actual marshaled form (`auth_token:`),
both directions: a pooled tunnel's key survives it, a key-less config grows
nothing.
