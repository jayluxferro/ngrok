# Spec 02 — Internal endpoints, forward-to, pooling, compression

Status: shipped (see the changelog entry for its release; this document is the design record)


## 1. Objectives

1. **`.internal` endpoints** — private, per-account-namespaced tunnels not reachable from public Host routing (ngrok parity for the `internal` binding).
2. **`forward_to`** — a public endpoint may route its traffic to an internal endpoint owned by the same account (static, config-driven approximation of ngrok's `forward-internal` action; the policy engine comes later).
3. **Endpoint pooling** — multiple agents may register the same URL (round-robin connection distribution). ngrok runs L7 per-request for HTTP; we do L4 per-connection in this cluster (honest simplification; keep-alive stays end-to-end).
4. **Response compression (gzip)** — client-side streaming gzip of compressible upstream responses, mirroring ngrok's legacy `compression: true` agent feature. This is the throughput feature: Ollama NDJSON streams compress ~5–10x.

## 2. Background facts (verified against the code)

- `TunnelRegistry` (`server/registry.go`): `map[string]*Tunnel`, `Register` fails on duplicate URL, affinity LRU cache for random-URL re-assignment, `Del`, `Get`.
- `Tunnel` (`server/tunnel.go:28-49`): `req *msg.ReqTunnel`, `url`, `listener` (TCP only), `ctl *Control`. `registerVhost` (`:52-92`) registers by Hostname, Subdomain, or random URL.
- TCP tunnels bind a real `net.TCPListener` per tunnel (`NewTunnel` `case "tcp"`, `:106-158`). Pooling must share the first listener.
- `Control` (`server/control.go:24-62`): `auth *msg.Auth` (the `User` field IS the auth token when `opts.authTokens` is set — the account identity for namespacing), `proxies chan conn.Conn` (proxy-connection pool, max 10), `tunnels []*Tunnel`.
- Public HTTP routing: `server/http.go:94-113` — vhost Host lookup → `registry.Get(url)` → tunnel's connection handler (the `StartProxy` + `conn.Join` flow in `server/tunnel.go:~300-328`).
- Wire protocol (`msg/msg.go`): JSON envelope, `ReqTunnel`/`NewTunnel` correlated by `ReqId`; unknown JSON fields are ignored by old code — additive `ReqTunnel` fields are backward compatible.
- Rewriter (`rewriter/rewriter.go`): read-driven per-direction state machines; `Policy` + `compiledPolicy` + shared `connState` (mutex-guarded `lastMethod`, `upgraded`). Response direction phases: stHead / stBodyCL / stChunkSize / stChunkData / stChunkDataEnd / stChunkTrailer / stRaw. Head rewrite at `stepHead`; fail-open everywhere.
- Client config: `client/config.go` (`TunnelConfiguration`, `LoadConfiguration` validation), `client/cli.go` (`Options`, `stringList` repeatable flag type from cluster 1), `client/mvc/state.go` (`Tunnel` struct), `client/model.go` (ReqTunnel construction + `relay()`/`policyFromTunnel`).

## 3. Design decisions

### 3.1 Accounts = auth tokens

The fork has no account concept; identity is the `Auth.User` token. Namespacing rule: when `opts.authTokens` is set, the owner of a connection is `Auth.User`; otherwise all clients share one namespace named `"default"` (documented limitation). Internal endpoints registered by U are reachable only via `forward_to` from endpoints owned by U (same-account forwarding only; ngrok's cross-account variant is a paid feature — skip).

### 3.2 Registry v2

`TunnelRegistry.tunnels` becomes `map[string]*bucket` where `bucket{tunnels []*Tunnel; next uint32; owner string}`.

- Public keys: the URL exactly as today ("http://hostname", "tcp://host:port").
- Internal keys: `url + "\x00" + owner` — invisible to public vhost lookup (which uses the bare URL), so `.internal` hosts are never reachable from the public listener. 404 as today.
- `Register(url, owner, t, pooling)`: conflict unless the existing bucket is pooling AND the new tunnel is pooling.
- `Get(url, owner)` (owner used only for internal keys; public keys ignore it): round-robin (`atomic.AddUint32`) across the bucket — this alone implements pooling.
- TCP pooling: the first tunnel binds the listener; subsequent pooling tunnels append to the same bucket without binding; `Shutdown` closes the listener only for the tunnel that created it and removes only that tunnel from the bucket; empty bucket → `Del`.
- Internal endpoint rules: `Hostname` required, lowercase, must end in `.internal`, no subdomain/random assignment, no public listener involvement, no TCP internal endpoints in this cluster (HTTP/HTTPS only; ngrok supports tcp://x.internal:port — note as future).

### 3.3 forward_to (static routing chain)

`ReqTunnel.ForwardTo` (string, optional) = internal URL ("https://svc.internal") owned by the same account. When a public connection resolves to tunnel P and P.ForwardTo != "":

1. Resolve F with P's owner: `registry.Get(F, owner)`. Missing → 502 ("forward target offline").
2. Depth limit 8 + cycle detection (visited-URL set along the chain) → 502 on violation.
3. Dispatch the public connection through the target tunnel I's existing proxy flow (StartProxy carries the public client's real address, so X-Forwarded-For stays truthful). P's agent never sees the connection.
4. The public client sees I's upstream response verbatim.

### 3.4 Compression (client-side gzip)

Config: `-compression` bool flag (default **true**, ngrok v2 parity — flagged behavior change) + per-tunnel YAML `compression: true|false`.

**Mechanics** (all in `rewriter/`, no server changes):
- `Policy` gains `Compress bool`.
- Request side records per-request into `connState` (single-slot, same documented pattern as `lastMethod`): `reqAcceptsGzip` (Accept-Encoding contains `gzip`), `reqHasRange` (Range header present).
- Response side, after head parse, enters a **gzip transform phase** iff ALL of: `policy.Compress` && `reqAcceptsGzip` && !`reqHasRange` && request version is HTTP/1.1+ && response start line is HTTP/1.1+ (HTTP/1.0 clients/responses skip — chunked re-framing is not safe there; verified experimentally) && status >= 200 && status != 204/304 && not 101 && `lastMethod != "HEAD"` && no existing `Content-Encoding` && Content-Type in the compressible set (text/*, application/json, application/javascript, application/xml, application/xhtml+xml, application/graphql, image/svg+xml, application/wasm) && (no Content-Length or Content-Length >= 128).
- Head rewrite in gzip mode: drop `Content-Length`, drop `ETag`, append `Content-Encoding: gzip`, append `Vary: Accept-Encoding`, append `Transfer-Encoding: chunked` (required — the compressed output is re-framed as chunked; a close-delimited compressed body would be mis-read), keep everything else byte-identical. Upstream trailers and non-chunked `Transfer-Encoding` fields are dropped in gzip mode: they describe the body being replaced.
- Body: stream source bytes (any framing: CL, chunked, close-delimited) through a `gzip.Writer` into **chunked** output frames (the one place the rewriter is allowed to re-frame; framing of the *input* is still never modified). After the message body ends (CL satisfied / terminal chunk / EOF), close the gzip writer, emit the terminal `0\r\n\r\n`, return to stHead.
- Errors mid-gzip are effectively impossible (writer target is an in-memory buffer); on any unexpected error: log WARN once and fail open to stRaw for the rest of the connection, emitting what was already produced.
- Non-gzip responses keep today's byte-identical path.

**Safety invariants (golden-test):** a client that never sent `Accept-Encoding: gzip` NEVER receives `Content-Encoding: gzip`; decompressing the emitted body reproduces the upstream body byte-for-byte; chunk framing of the gzip output is well-formed (parse with `http.ReadResponse`); second request on a keep-alive connection without gzip gets an identity response.

### 3.5 Wire protocol

`msg.ReqTunnel` gains: `Binding string` (`""` public | `"internal"`), `Pooling bool`, `ForwardTo string`. No version bump, no Caps change (client+server ship together in the fork).

## 4. Workstreams (file ownership is exclusive; no shared files)

### A — server core (parallel)
Files: `server/registry.go`, `server/tunnel.go`, `server/control.go`, `server/http.go` (only the routing lookup if needed), `msg/msg.go`, new `server/registry_v2_test.go` + additions to existing server tests if any. Do NOT touch client/, rewriter/, docs/, e2e.

Deliverables:
1. Registry v2 per 3.2 with round-robin `Get`; keep the affinity cache behavior for random-URL assignment intact; keep existing method signatures where callers don't need the new behavior, add new ones (`RegisterWithPooling` or equivalent — your call, document it).
2. `ReqTunnel` fields per 3.5; `NewTunnel` handles Binding/Pooling (including TCP listener sharing per 3.2).
3. `forward_to` resolution chain per 3.3 wired into the public HTTP connection path (and TCP if trivially shared — otherwise HTTP-only, document it).
4. Owner derivation: `t.ctl.auth.User` when `opts.authTokens` non-empty else `"default"` — add a small helper (e.g. `ownerOf(ctl) string`) used everywhere namespacing applies.
5. Unit tests: pooling conflict matrix (pool×pool ok, pool×non-pool conflict both directions, duplicate non-pool), round-robin distribution across 3 tunnels, TCP listener sharing + shutdown of one member, internal keys invisible to public lookup, same-account forward resolution, cross-account forward rejection, cycle → 502, depth limit → 502, missing target → 502, owner fallback when auth disabled.

Verification: `go build -tags debug <packages>`, `go vet -tags debug ./server/... ./msg/...`, `go test -tags debug -race ./server/ ./msg/`.

### B — rewriter gzip core (parallel)
Files: `rewriter/rewriter.go`, `rewriter/rewriter_test.go` ONLY. Do NOT touch client/, server/, msg/, docs/, e2e.

Deliverables: `Policy.Compress`, the connState per-request gzip/range slots, the gzip transform phase, head rewrite rules, and the 3.4 skip matrix — exactly as specified in 3.4. Extend `Validate`/`IsNoop` sensibly (`Compress` is a transformation; document). Tests: golden matrix — gzip round-trip (decompress output == upstream body) for CL-framed, chunked-framed, and close-delimited bodies; chunked output parses via `http.ReadResponse`; skip matrix (no Accept-Encoding, Range, HEAD, 204, 304, 101, Content-Encoding present, image/png, Content-Length < 128, non-compressible Content-Type); keep-alive second request identity; pipelined conservative behavior; `IsNoop`/`Validate` updates.

Verification: `go build ./rewriter/`, `go vet ./rewriter/`, `go test -race -count=1 ./rewriter/`.

### C — client wiring (AFTER A and B)
Files: `client/cli.go`, `client/config.go`, `client/mvc/state.go`, `client/model.go`, `client/headers.go`, `client/config_test.go`, `client/model_proxy_test.go` (extensions), `scripts/e2e.sh`, `docs/CHANGELOG.md`, and new tests. Do NOT touch server/, msg/, rewriter/.

Deliverables:
1. Flags: `-binding` ("public"|"internal"), `-pooling` (bool), `-forward-to <url>`, `-compression` (bool, default true). YAML keys: `binding`, `pooling`, `forward_to`, `compression` on `TunnelConfiguration`. Validation (fail loudly): binding enum; internal ⇒ hostname required and ends `.internal`; forward_to ⇒ parses as URL with host ending `.internal`.
2. `mvc.Tunnel` fields: `Binding string`, `Pooling bool`, `ForwardTo string`, `Compress bool`; population in `client/model.go` from `reqIdToTunnelConfig` (same pattern as cluster 1); `ReqTunnel` construction sends the new fields.
3. `policyFromTunnel` carries `Compress` into the policy.
4. e2e: extend `scripts/e2e.sh` — (a) compression: `curl --compressed` through the tunnel returns `Content-Encoding: gzip` and the decompressed body matches upstream; plain curl returns identity; (b) pooling: two clients register the same subdomain with `-pooling`, requests distribute (count hits on two upstreams); (c) internal+forward-to: internal endpoint + a public endpoint with `-forward-to`, curl the public one → upstream receives it, and the `.internal` host 404s when curled directly.
5. Changelog entry: new flags, pooling, internal endpoints, forward_to, compression default-on (explicitly called out as a behavior change with the `-compression=false` opt-out).

Verification: `go build -tags debug <packages>`, `go vet -tags debug ./client/...`, `go test -tags debug -race ./client/ ./rewriter/ ./server/ ./msg/`, `bash scripts/e2e.sh` (needs free ports; see script's conventions).

## 5. Review gates (architect, after C)

1. Full gate suite green (`-tags debug`; `./...` is broken by a stray pkg/mod — use the explicit package lists).
2. Existing behavior unchanged for: public tunnels without new flags; non-pooling registration; public vhost lookup; TCP tunnels without pooling; identity (uncompressed) responses when the client doesn't accept gzip.
3. Compression default-on is explicitly confirmed with the user at review (behavior change).
4. Fail-open preserved: gzip/forward-chain failures never drop bytes or hang connections; 502s are explicit, logged, and connection-safe.
5. Data-driven: owner/namespace helpers, bucket logic, and the compressible-type set are declarative (no scattered ad-hoc checks).
6. No goroutine leaks (`-race`).

## 6. Success metrics

- `go test -tags debug -race` green across client/rewriter/server/msg/proto/util.
- e2e: pooling distributes across two upstreams; `curl --compressed` round-trips; public curl of a `.internal` host 404s; `forward_to` chain reaches the internal upstream.
- Real-world: two `ngrok` clients on one machine pool a subdomain; Ollama traffic through a tunnel with compression on shows ~5–10x smaller responses.
