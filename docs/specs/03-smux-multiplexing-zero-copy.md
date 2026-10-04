# Spec 03 — smux multiplexing and zero-copy throughput

Status: shipped (see the changelog entry for its release; this document is the design record)


## 1. Objectives (the throughput cluster)

1. **Stream multiplexing** — public connections become streams on ONE long-lived mux connection per client↔server session (smux), eliminating per-connection TCP+TLS handshakes and setup round-trips. This mirrors ngrok v3's muxado architecture and is the dominant win for connection-heavy workloads.
2. **Zero-copy legs** — `ReadFrom`/`WriterTo` on the connection wrapper so `io.Copy` uses `splice(2)` on Linux; larger copy buffers everywhere (macOS has no splice).
3. **Bench harness** — deterministic end-to-end benchmarks (bulk MiB/s, connection rate, keep-alive req/s) with before/after comparison. Baseline binaries are already captured at commit a4f6ecb in /tmp/bench-baseline/.
4. Non-goals this cluster: upstream connection reuse (phase 2), public HTTP/2, QUIC, kTLS.

## 2. Background facts (verified)

- Proxy connections today: per public connection, the client dials `serverAddr` fresh (`client/model.go:376-392`), sends `RegProxy{ClientId}`, waits for `StartProxy` (`:400-405`), then dials local and `conn.Join`s. Server side (`server/control.go`, `server/tunnel.go`): `Control.proxies` is a channel of idle pre-dialed proxy conns (max 10, `proxyMaxPoolSize`); `ReqProxy` pings the client over control when the pool is low.
- The server has ONE listener (`tunnelAddr`); control vs proxy conns are distinguished by their first message (Auth vs RegProxy).
- `msg` wire format: JSON `Envelope{Type, Payload}` with `TypeMap` registry (`msg/msg.go:10-23`). Additive message types are backward compatible.
- Capability negotiation already exists: `Auth.Caps []string` / `AuthResp.Caps []string`.
- `conn.Wrap` (`conn/conn.go:40-54`) currently returns nil for generic `net.Conn` (only vhost/`*net.TCPConn`/loggedConn handled) — smux streams need a new default case.
- `conn.Join` (`conn/conn.go:202-226`) uses plain `io.Copy` (32 KiB buffers) and never reaches splice because `loggedConn` has no `ReadFrom`/`WriterTo`.
- The rewriter/tee/gzip stack operates on `conn.Conn` — if streams are wrapped into `conn.Conn`, the ENTIRE downstream stack is untouched.

## 3. Design

### 3.1 Mux transport (workstream A)

Dependency: `github.com/xtaci/smux/v2` (MIT, maintained; the KCP author). `smux.Stream` implements `net.Conn`.

**Protocol additions (msg):** new `RegMux{ClientId string}` + `TypeMap` entry. No version bump.

**Server:**
- `AuthResp.Caps` advertises `"proxy-mux"` when enabled (always on in this fork; the cap exists so mixed-version deployments degrade gracefully).
- When the listener reads `RegMux{ClientId}`: look up `ControlRegistry`, validate the client id, wrap the conn in `smux.Server`, store the session on the Control, and start an accept loop. Failed lookup/validation → log + close.
- Accept loop: each `smux.Stream` gets wrapped via `conn.Wrap` (needs the generic-`net.Conn` default case) as `"pxy"`, its first message must be `RegProxy{ClientId}` (validated against the Control's id), then it is registered into the proxy pool exactly like today's TCP proxy conns — `StartProxy` + join semantics unchanged. Streams replace pooled TCP conns as the proxy-conn source: `RegisterProxy`/`GetProxy` now pull from streams; when stream inventory is low, send `ReqProxy` over control as today (the client opens new streams instead of dialing).
- Legacy path retained: if a client does not open a mux conn (pre-1.0.4 agent), the existing TCP proxy-conn pool keeps working. Both paths can serve simultaneously.
- Session teardown: mux conn close → smux session close → all streams error out; joins unwind as today (Join closes both ends).

**Client:**
- After `AuthResp` with cap `"proxy-mux"`: dial one mux conn to `serverAddr`, send `RegMux{ClientId}`, wrap in `smux.Client` (keepalive on).
- `ReqProxy` handler: open a stream on the session, write `RegProxy{ClientId}` on the stream, read `StartProxy`, then the EXISTING relay path verbatim (dial local leg, tee, rewriter/gzip, `conn.Join`). No new copy logic.
- Fallback: no cap → today's per-connection dial path.
- The mux conn needs its own watchdog: if the session dies, reconnect the mux conn (bounded retry) and log; in-flight streams fail closed (their joins unwind).

**conn/conn.go (A's only edit there):** add a default case to `wrapConn` that wraps any `net.Conn` into a `loggedConn` (needed for `smux.Stream`). Nothing else in conn/.

**Rationale for keeping RegProxy/StartProxy on streams:** it preserves auth-per-stream, the pooled-conn economics, and every downstream component (Join/tee/rewriter/gzip) byte-for-byte. The win comes from killing handshakes, not from changing the data path.

**Honest tradeoffs to document:** the mux conn is a shared failure domain (its death kills all streams — mitigated by the reconnect watchdog); smux adds per-stream buffering (window memory); stream setup is one frame RTT but stream count is bounded by smux defaults (tune if bench shows contention).

### 3.2 Zero-copy legs (workstream B, after A)

New file `conn/zerocopy.go` (methods on `loggedConn`, so no changes to A's region):
- `ReadFrom(r io.Reader)` — if underlying conn is `*net.TCPConn`, delegate to its `ReadFrom` (splice on Linux, generic fallback elsewhere); otherwise `io.Copy(writeOnly{c}, r)` where `writeOnly` exposes only `Write` (avoids `io.Copy` re-entering `ReadFrom`).
- `WriteTo(w io.Writer)` — if underlying is `*net.TCPConn`, delegate to its `WriteTo`; else generic copy loop.
- `conn/conn.go`: change `Join`'s `io.Copy` calls to `io.CopyBuffer` with a package-level 256 KiB buffer (macOS win; harmless on Linux).
- The tee (conn/tee.go) is left as-is: its pipe fan-out cannot splice; the gzip/rewriter stack still runs on top.

### 3.3 Bench harness (workstream C)

New `scripts/bench.sh` (style of scripts/e2e.sh; same port conventions; uses existing helpers if extractable). Scenarios, all end-to-end through a live ngrokd+ngrok:
1. **bulk**: upstream serves 64 MiB of random bytes; download via curl through the tunnel; report MiB/s (3 runs, median).
2. **conn-rate**: 200 sequential requests with `Connection: close`; report req/s and p50/p95 wall time.
3. **keep-alive**: 1000 requests on one connection; report req/s.
Output a compact table with BASELINE vs CURRENT columns if given two binary dirs (`bench.sh /path/baseline /path/current`).

**Changelog (C):** new Unreleased section: smux multiplexing (cap-gated, legacy fallback, shared-failure-domain note), zero-copy legs, bench harness; honest notes about what improved and where the old path remains.

## 4. Workstreams (file ownership exclusive)

### A — smux multiplexing (parallel with C)
Files: `go.mod`, `go.sum`, `msg/msg.go` (RegMux + TypeMap), `conn/conn.go` (wrapConn default case ONLY), `server/control.go`, new `server/mux.go`, `server/tunnel.go` (proxy-conn acquisition via streams), `server/main.go` if the listener dispatch needs a new branch (check), `client/model.go` (mux conn setup + ReqProxy stream path), new tests (`server/mux_test.go`, client mux tests using in-process smux session over net.Pipe). Do NOT touch client/config.go, cli.go, mvc/, headers.go, conn/zerocopy.go (doesn't exist yet), scripts/, docs/.

Verification: gofmt clean on touched files; `go build -tags debug <explicit packages>`; `go vet`; `go test -tags debug -race -count=1 ./server/ ./msg/ ./client/ ./conn/`; plus a manual smoke (or extend an e2e-style check if trivial — do NOT edit scripts/e2e.sh; C owns scripts).

### B — zero-copy (AFTER A lands)
Files: new `conn/zerocopy.go`, `conn/conn.go` (Join buffer only), new `conn/zerocopy_test.go`. Verify with `go test -race ./conn/` + full gate suite.

### C — bench harness + changelog (parallel with A)
Files: new `scripts/bench.sh`, `docs/CHANGELOG.md` (Unreleased section). Do NOT touch go.mod/go.sum, server/, client/, conn/, msg/.

## 5. Review gates (architect)

1. Full gates green; e2e unchanged-pass (mux must not regress any existing scenario).
2. Bench: run the harness against /tmp/bench-baseline (a4f6ecb) and the new tree. Success: **conn-rate ≥ 4x** on the mux path; **bulk ≥ 1.2x**; keep-alive no worse than baseline. Numbers reported honestly, including any misses.
3. Legacy fallback verified: a client built without the cap (simulate by disabling) still works against the new server.
4. Fail-closed behavior: killing the mux conn unwinds streams without goroutine leaks (`-race`, plus a targeted test).
5. No regressions in pooling/internal/forward_to/compression (their tests + e2e stay green).

## 6. Success metrics

- req/s on short-lived connections up ≥4x; bulk MiB/s up ≥1.2x; keep-alive latency neutral.
- All cluster-1/2 tests and e2e scenarios green.
- Release note explains the new transport with the honest shared-failure-domain caveat.
