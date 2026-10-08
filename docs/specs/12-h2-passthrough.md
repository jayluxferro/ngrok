# SPEC-CLUSTER16 — HTTP/2 passthrough on agent-terminated tunnels

Status: shipped (v1.0.16)

Amendment (post-review, pre-ship): the response side of a passthrough pair
needed one mechanism the spec did not name. It parks between messages in a
line wait for its next status line; an h2 upstream's first answer is a
SETTINGS frame — binary, no line break — so the parked wait held the frames
and the connection deadlocked with both sides sleeping (found in the first
live e2e run, not in unit tests: staged in-memory sources end in EOF and
exit through fail-open, which a healthy held-open upstream never offers).
The fix is a one-shot passthrough wake flag on the connection state: the
request side arms it in `setPassthrough`, the response reader's `ReadSlice`
consumes it between its delimiter scan and its next fill and returns what it
consumed with `errPassthroughWake`, and `stepHead` answers that with the
same flush-and-go-raw the line-boundary check takes. Pinned by
`TestHTTP2PrefaceWakeReleasesAResponseSideHeldOnBinary`, which fails in 5 s
without the wake and passes with it.

## Objectives

1. An agent-terminated (`agent_tls_termination: true`) tunnel can offer `h2`
   in its public ALPN, so h2-mandatory visitors — grpc-go clients above all —
   work end-to-end through the existing raw-passthrough architecture.
2. Fix the latent preface-corruption bug this cluster's recon found: the
   rewriter's `parseRequestLine` (rewriter/rewriter.go:2954-2963) accepts the
   h2 prior-knowledge preface line `PRI * HTTP/2.0` (`PRI` is a valid token,
   `*` a non-empty target, `isHTTPVersion` takes any `digit.digit`), the head
   "parses" with zero fields, and the always-on `X-Forwarded-For` injection
   (client/model.go:1477-1484 — the comment there states XFF is always on for
   live HTTP tunnels) splices a header line into the 24-byte fixed preface,
   shifting `SM\r\n\r\n` out of position. Any conforming h2 server then
   rejects the connection as a framing error.
3. Zero server changes. The server relays agent-terminated TLS unread
   (server/http.go `serveAgentTLS`, `passthroughConn`); ALPN on these tunnels
   is negotiated end-to-end between visitor and agent. `on_tcp_connect`
   still runs server-side on the raw accept (http.go:336-339), unchanged.

## Non-goals (binding)

- **No HTTP/2 on the public edge listener.** The whole edge path is
  HTTP/1-text-shaped (bounded head parse → Host routing → byte pipe), and h2
  routing means HPACK-frame transcoding with a standing request-smuggling
  review burden — the bounded-parser philosophy this codebase is built on
  exists to avoid hand-rolled framing on the public path. Also refused as
  protocol-illegal: advertising `h2` in ALPN and then serving h1 text (RFC
  7540 §3.3 makes the negotiated protocol binding; there is no
  post-negotiation fallback). Edge h2 remains deferred with a written case
  for revival.
- **No h2c public listener** (same cost, near-zero visitor value).
- **No extended CONNECT / websocket-over-h2.**
- **No X-Forwarded-For on h2 connections.** XFF injection is rewriter-driven
  and h2 passthrough is raw by definition; an h2 visitor's local service sees
  no client IP. This is a documented loss, not an oversight — the alternative
  is parsing h2 frames, which is the edge-h2 cost this cluster refuses.
- **No agent-side h1→h2 local-leg transcoding** — that is SPEC-CLUSTER17
  (`upstream_protocol: http2`), which builds on this spec's guard but owns
  client/model.go and must land after this cluster.

## Design

### 1. The `alpn` tunnel key (opt-in, per tunnel)

```yaml
tunnels:
  grpc:
    proto:
      https: 7000
    hostname: grpc
    agent_tls_termination: true
    tls:
      crt: /etc/certs/grpc.crt
      key: /etc/certs/grpc.key
    alpn: ["h2", "http/1.1"]   # NEW. Unset (default) = no ALPN offered, today's behavior
    compression: false          # REQUIRED when "h2" is offered — see matrix
```

- New field `TunnelConfiguration.Alpn []string` (`alpn` in YAML), CLI
  `-alpn h2,http/1.1` (comma-separated) for the default tunnel.
- **Default unset offers no ALPN at all** — byte-identical visitor handshakes
  to today. This is deliberate: advertising `h2` unconditionally would flip
  every h2-capable visitor (browsers included) onto h2 toward local services
  that only speak HTTP/1.1. Opt-in is the only safe default.
- Validation matrix, all at config load, all naming the tunnel and the rule:
  1. `alpn` requires `agent_tls_termination: true` on an https leg (the
     terminator whose ALPN this is). Refused otherwise.
  2. Values ⊆ {"h2", "http/1.1"}, list non-empty, no duplicates. Refused
     otherwise, spelling out the accepted set.
  3. When `"h2"` ∈ alpn — and only then; `["http/1.1"]` alone pins h1 and
     changes nothing servicewise — the tunnel must be servable for h2
     visitors, which by the passthrough semantics means nothing
     rewriter-driven may be configured:
     - the traffic policy has NO `on_http_request`/`on_http_response` rules
       (`on_tcp_connect` is fine — it runs server-side on the raw accept);
     - `host_header` is unset or `preserve`, and `request_header` /
       `response_header` add/remove are all empty;
     - `compression: false` is set explicitly (compression defaults ON, and
       the rewriter cannot frame h2 bodies — an operator must state the
       off).
     The refusal for each names the conflicting key and why: a visitor must
     never be able to dodge a configured control by choosing the h2 ALPN.
- No wire change: `alpn` is agent-local (the terminator is agent-local), so
  old servers pair fine and `msg/` is untouched.

### 2. The terminator (workstream B, client/tlsagent.go)

`finishAgentTLSConfig` (client/tlsagent.go:161) gains the tunnel's alpn list
and sets `cfg.NextProtos` when non-empty. Each cert model already builds a
fresh `*tls.Config` (no shared pointer — the clone-then-set hazard the
server-side QUIC path guards against, server/quic.go:136-139, does not exist
here), so the assignment is plain. Order the list as written: `h2` first
means h2-capable visitors get h2; that is the operator's stated intent. The
negotiated protocol needs no branch after termination — plaintext flows into
`relay` whatever was negotiated, and the rewriter guard (below) handles h2.

### 3. The rewriter preface guard (workstream A, rewriter/)

At request-head parse, when the request line's method is `PRI` or its version
is `HTTP/2.0`, the connection is an h2 prior-knowledge stream:

- **No policy hooks armed on the connection** → fail open for the whole
  connection: replay every consumed byte verbatim (preface + `SM\r\n\r\n` +
  any SETTINGS frames already read — the existing replay machinery that the
  unparseable-head fail-open path uses), then raw-copy both directions for
  the life of the connection. No injection, no rewriting, no compression.
- **Hooks armed** → this cannot happen through config (the load-time matrix
  above refuses it), and the guard still must not passthrough — a hook
  armed is a control armed, and passthrough would bypass it. Close the
  connection and log at WARN naming the tunnel. Never a 431: an h2 visitor
  cannot read an HTTP/1-text error, and garbage framing is a worse answer
  than a closed connection.
- The guard lives in the shared state machine, so the server side is covered
  by construction (edge tunnels cannot negotiate h2 today — the server
  advertises no ALPN — and a prior-knowledge h2c visitor on the plain http
  listener is turned away at routing with the no-Host 404 before any
  rewriter exists; defense in depth is free here, not extra work).

### 4. What h2 visitors get (and do not get)

| | h1 visitor (same tunnel) | h2 visitor |
|---|---|---|
| Rewriting / XFF / compression | as configured (XFF always) | none — raw passthrough |
| `on_tcp_connect` | server-side, raw accept | same |
| `on_http_*` policy | hook, per connection | refused at load (matrix 3) |
| Local service speaks | HTTP/1.1 | h2c prior-knowledge (plaintext h2 frames) |

The tunnel is dual-protocol by construction when both values are offered;
the matrix guarantees the two columns cannot disagree about enforcement.

## File ownership (exclusive)

- **Workstream A**: `rewriter/rewriter.go`, `rewriter/rewriter_test.go`
  (or the package's existing test files). Nothing else.
- **Workstream B**: `client/tlsagent.go`, `client/tlsagent_test.go`.
- **Workstream C**: `client/config.go`, `client/config_test.go`,
  `client/cli.go`, `client/mvc/state.go` (only if the flag plumbing needs
  it), `client/model.go` (only the line that passes `Alpn` into the
  terminator call site, if any — B's function reads it from the
  `TunnelConfiguration` it already receives, so the expected change is none).
- **Architect (after review)**: e2e scenarios in `scripts/e2e.sh`,
  `docs/CHANGELOG.md`, `version/version.go`, README feature rows,
  spec status flip, index row, commit/tag/push/CI watch.

## Testing strategy

- **A (unit)**: preface + `SM` + SETTINGS + DATA round-trips byte-exact with
  no injection; guard fires with hooks armed → close not 431; h2 detection on
  `PRI` alone and on `HTTP/2.0` alone; no cross-talk to adjacent pure-h1
  connections through the same pair machinery.
- **B (unit)**: NextProtos set only when configured; empty/unset → nil
  (handshake bytes unchanged); a real self-test h2 handshake against the
  finished config; all three cert models.
- **C (unit)**: the full validation matrix — each refusal message asserted
  verbatim (house style), plus `-alpn` flag parse (comma list, spaces
  tolerated, bad value refused).
- **E2E (architect)**: agent-terminated tunnel with `alpn: [h2, http/1.1]` +
  `compression: false` against a local h2c upstream (small Go helper the
  harness runs); `curl --http2-prior-knowledge` (preface without ALPN —
  exercises the guard directly) and ALPN-negotiated h2; h1 curl on the SAME
  tunnel still gets XFF (dual-protocol columns); every load-refusal scenario
  fails startup with the named message.

## Review gates

1. A default-config (no `alpn` anywhere) build produces byte-identical
   visitor handshakes and rewriter behavior — grep that NextProtos is nil
   unless configured.
2. The hooks-armed + preface path closes, never passes through, never 43x.
3. Every matrix-3 refusal names the conflicting key and the reason.
4. `go test -tags debug -race ./...` green; e2e group green; no new module
   requirements (x/net promotion is CLUSTER17's concern, not this one).
5. Changelog states the XFF loss for h2 visitors and the dual-protocol
   behavior plainly.
