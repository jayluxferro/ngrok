# SPEC-CLUSTER7: QUIC agent transport + rewriter buffer pooling

Status: approved (user: "work autonomously till everything is done"; cluster 7 = the
AI-workload throughput push). Goal: kill TCP head-of-line blocking across multiplexed
proxy streams (one lost packet on the smux carrier stalls EVERY stream today), and cut
the per-connection allocation tax on the HTTP data path.

## 1. Objectives

1. **QUIC as an alternative agent↔server proxy transport**, negotiated by capability,
   defaulting on when both sides support it, falling back to today's TCP+smux → per-conn
   dial chain without operator intervention.
2. **Pool the rewriter's per-connection bufio** (2×64 KiB on every client HTTP connection
   and every policy-hooked server connection) — the deferred 1.0.4 follow-up.
3. Measured, honestly-reported benchmarks: QUIC vs smux columns for conn-rate, keep-alive,
   bulk; allocs-per-connection before/after pooling. Loopback hides the HOL win (no loss
   there) — the changelog says so plainly rather than claiming a loopback number as the win.

## 2. Non-goals

- Public-edge HTTP/3 (QUIC for visitors) — later; this is the agent leg only.
- The control channel stays on TCP+TLS. It is low-volume, latency-tolerant, and keeping
  it independent of the experimental transport is the resilience story when QUIC breaks.
- No Blake2b chunk dedup (Levis-inspired) — deferred until QUIC lands and is measured;
  speculative dedup on top of an unmeasured transport stacks guesses.
- No http_proxy support for QUIC: `http_proxy` set → force the TCP path (CONNECT cannot
  carry UDP); logged at INFO when overridden.

## 3. Wire + negotiation (single source of truth in msg/)

- `msg.QuicCapability = "proxy-quic"` beside `MuxCapability` (msg/msg.go:247 pattern).
- RegMux/RegProxy are REUSED verbatim over QUIC streams — no new message types: the first
  stream of a QUIC session carries RegMux (session bind), every subsequent stream carries
  RegProxy (per-stream re-verification), exactly mirroring server/mux.go's smux flow.
- Server advertises `proxy-quic` in AuthResp.Caps ONLY when the QUIC listener is up
  (server/control.go:250-256 site). Absent capability → client never tries QUIC.
- QUIC TLS: the server's existing cert pair; ALPN `ngrok` REQUIRED both directions
  (NextProtos ["ngrok"]; Dial fails on mismatch — cross-protocol misdirection is refused
  by the handshake, not by hope).

## 4. Server (agent A)

- Flag `-quicAddr` (server/cli.go), YAML `quic_addr` (server/config.go — strict decode
  means the struct field MUST land with it). Default **empty = disabled**: opt-in, the
  default footprint (one TCP port) is unchanged.
- `server/quic.go` (+ quic_test.go): `Listen QUIC` on the UDP addr with quic-go pinned at
  **v0.45.0** (newest release declaring go 1.21 — our pin; v0.46+ needs go 1.22, upgrade
  rides the eventual deliberate toolchain bump). Transport config: KeepAlivePeriod 10s,
  MaxIdleTimeout 30s (match smux's load-bearing settings, client/model.go:1183-1192),
  MaxIncomingStreams 512, MaxIncomingUniStreams 0 (we never use uni streams).
- Extract the smux-specific session shape into a small interface BOTH transports
  implement (server/mux.go refactored, behavior byte-identical):
  ```go
  type streamSession interface {
      AcceptStream() (net.Conn, error) // death watch + per-stream accept
      Close() error
  }
  ```
  Control holds a streamSession (SetMuxSession signature narrows to it); accept loop,
  per-stream RegProxy re-verification (`regPxy.ClientId == m.ctl && secretMatches`),
  RegisterProxy handoff — all identical to mux.go today, shared or duplicated cleanly
  (implementer's judgment; shared wins if it doesn't contort mux.go).
- QUIC session auth: first stream = RegMux{ClientId, Secret}; validate exactly like
  NewMux (unknown client closes; constant-time secretMatches; server/mux.go:65-103).
  Bind to the control's session slot with the same replace-and-close-prior semantics.

## 5. Client (agent B)

- Config key `proxy_transport: auto|quic|tcp` (default auto) + flag `-proxy-transport`
  (client/config.go non-strict decode is fine; validate the enum, fail loudly on typos).
  `http_proxy` set → forced tcp (INFO log naming the override).
- Generalize the carrier (client/model.go): muxSession's `*smux.Session` field becomes a
  `streamCarrier` (OpenStream/AcceptStream/Close/IsClosed over net.Conn) with two
  adapters (smux, quic). Watchdog, backoff, muxMinSessionLifetime, setMuxSession/
  clearMuxSession, proxyStream's RegProxy→StartProxy handshake: UNCHANGED logic, now
  carrier-blind. Auto preference per attempt: quic (if capability + config allow) →
  on dial error fall through to the smux path inside the SAME watchdog attempt cycle;
  give-up constants unchanged (8 attempts).
- dialQuicSession: quic.DialAddr with the model's existing tlsCfg + NextProtos ["ngrok"]
  (honor TrustHostRootCerts / embedded CAs / NGROK_INSECURE_SKIP_VERIFY identically);
  first stream carries RegMux; carrier = the QUIC conn. ALPN mismatch error = clean
  fallback (old server on that port), not a retry loop.
- No flag/config for keepalives — fixed values shared with smux (one source: consts in
  msg/ or client/model.go reused by both adapters — implementer picks, document).

## 6. Pooling (agent P — owns rewriter/ ONLY; zero call-site changes)

- The pair's two 64 KiB bufio backing arrays (rewriter/rewriter.go:951-960) come from a
  package-private sync.Pool of []byte (match joinBufPool's conventions: pool beside the
  user, size const above, comment stating the concurrency rationale).
- Release site: **filteredConn.Close** (rewriter/conn.go) via sync.Once — the ONE site
  (double-release hands one buffer to two connections; TestJoinStagingBufferIsNotShared
  is the precedent for the corruption class). Join already defers Close on both conns
  (conn/conn.go:247-248), so client relay and server join need NO changes.
- bufio.Reader has no Reset: implement a minimal pooled reader (Read + the bufio methods
  the rewriter actually calls — inventory them first) over the pooled slice, or wrap
  bufio.NewReader over a pooled-backing bytes.Reader — whichever keeps rewriter.go's
  call sites unchanged. Idempotent, nil-safe Release semantics documented on the pair.
- Do NOT pool: readRequestHead's replay bufio (escapes into replayConn for the conn's
  life), tee readers (analyzer goroutines can outlive Join), joinBufPool (already
  correct).
- Proof: a test asserting allocs-per-connection drop (testing.AllocsPerRun over a
  rewritten request/response cycle) + existing rewriter suite green under -race.

## 7. File ownership (exclusive)

- **A (server)**: msg/msg.go, server/quic.go+, server/main.go, server/cli.go,
  server/config.go, server/control.go, server/mux.go, server tests. go.mod/go.sum for
  quic-go v0.45.0 (A runs `go get github.com/quic-go/quic-go@v0.45.0` FIRST and reports
  immediately if it fights the go 1.21 directive).
- **B (client)**: client/model.go, client/config.go, client/cli.go, client tests.
- **P (pooling)**: rewriter/* only.
- **C (after A+B+P)**: scripts/e2e.sh (quic group + fallback scenario), scripts/bench.sh
  (quic_ columns via the labeled two-dir compare mode; document loopback-hides-HOL),
  docs/CHANGELOG.md 1.0.9, README, version/version.go Patch "9".

## 8. Testing strategy

- A: quic_test.go — session bind (valid RegMux), unknown client / wrong secret closed;
  per-stream RegProxy re-verification; capability advertised only with listener up;
  strict-decode accepts quic_addr; streamSession equivalence (smux and quic paths hand
  identical conns to RegisterProxy).
- B: carrier adapter tests (dial a local quic-go listener; RegMux on first stream;
  stream open → RegProxy → StartProxy flows); proxy_transport validation table;
  auto→quic / capability-absent→smux / http_proxy→tcp selection matrix (unit-level);
  watchdog counts a dead-young QUIC session as an attempt and falls through to TCP.
- P: AllocsPerRun drop asserted; double-Close releases once; -race suite green.
- C e2e: server with -quicAddr → client log shows the quic carrier + 200s through it;
  same server, `-proxy-transport=tcp` → smux path green (fallback proof);
  quic+agent-terminated-tunnel composition (orthogonal legs, one scenario proves it).

## 9. Review gates

1. Full build/vet/test -tags debug -race green; e2e green including all prior groups.
2. Default behavior byte-identical when quic_addr unset / capability absent / config tcp.
3. smux path refactor (streamSession extraction) is behavior-preserving — existing mux
   tests untouched and green.
4. One release site for pooled buffers; no call-site changes outside rewriter/.
5. quic-go pinned v0.45.0 with the go-1.21 constraint documented in go.mod vicinity or
   CHANGELOG (upgrade rides the toolchain bump).
6. Bench numbers reported with the loopback caveat stated in the same table, not the prose.
