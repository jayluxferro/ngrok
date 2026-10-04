# Spec 04 — Server-side traffic policy engine

Status: shipped (see the changelog entry for its release; this document is the design record)


## 1. Objectives

Bring ngrok's defining feature to the fork: **Traffic Policy enforced at the edge** — which for self-hosting means ngrokd. This cluster implements the cheap action subset with CEL conditions, mirroring ngrok's exact config shapes:

- `on_tcp_connect`: `restrict-ips`, `deny`, `log`
- `on_http_request`: `add-headers`, `remove-headers`, `deny`, `custom-response`, `log`, `set-vars`
- `on_http_response`: `add-headers`, `remove-headers`, `log`

Non-goals this cluster (later): oauth/oidc/saml/jwt-validation, forward-internal as an action, rate-limit, circuit-breaker, url-rewrite, compress-response, request body access in CEL, CEL macro set beyond the documented subset.

## 2. Background facts (verified)

- Enforcement points: `server/http.go:85-169` httpHandler (rate limits → vhost Host parse → registry lookup → basic-auth → ResolveForward → `target.HandlePublicConnection(c)`); `server/tunnel.go:344+` listenTcp (accept → `conn.Wrap` → HandlePublicConnection). `HandlePublicConnection` writes `StartProxy` on a pooled proxy conn then `conn.Join`s (the rewriter-aware `relay` equivalent lives client-side; the server joins raw today).
- The rewriter package (`rewriter/rewriter.go`) is direction-agnostic: it parses every request/response head per keep-alive message, with shared `connState` (lastMethod/upgraded, single-slot pattern) and fail-open. `Policy` has HostHeader/add/remove/Compress; `NewConnPair(reqSrc, respSrc, p)` wraps the source side of each direction. It does NOT yet have extension hooks.
- `msg.ReqTunnel` (msg/msg.go) is JSON-envelope serialized; additive fields are backward compatible. Client validates config fail-loudly at load (`client/config.go` validateEndpointPolicy/validateHeaderPolicy pattern).
- Go module constraint: `go 1.21` directive AND CI builds with go1.21 (release.yml). cel-go must be pinned to a release compatible with go 1.21 (v0.20.x is the last known-good line for 1.20/1.21; verify at `go get` time — do NOT bump the go directive).
- ngrok's exact action config schemas live in the docs clone at /tmp/ngrok-docs (gateway/traffic-policy/actions/*.mdx) — mirror them precisely; that is the parity requirement.

## 3. Design

### 3.1 Rewriter hook extension (minimal, nil-safe)

`rewriter.Policy` gains two optional hooks (exported types in rewriter, so policy/ can implement them without a cycle):

```go
// SyntheticResponse is a response the edge fabricates without consulting the upstream.
type SyntheticResponse struct { StatusCode int; Headers []string /* "Key: value" */; Body string }

// RequestVerdict transforms or terminates the request being forwarded.
type RequestVerdict struct {
    Terminate *SyntheticResponse // non-nil: do not forward; respond synthetically and close
    Add       []string           // "Key: value", appended after static policy adds
    Remove    []string           // header names, case-insensitive
}

type ResponseVerdict struct { Add []string; Remove []string }

Policy.RequestHook  func(req *http.Request) *RequestVerdict   // nil-safe
Policy.ResponseHook func(resp *http.Response) *ResponseVerdict // nil-safe
```

- Hooks receive head-only objects: the rewriter builds `http.Request`/`http.Response` from the parsed head bytes (http.ReadRequest/ReadResponse on a bytes.Reader); the doc comment must state that body fields are not meaningful and only Method/URL/Host/Header/StatusCode/Proto are populated.
- Request side `stepHead`: after static rewrite, if RequestHook != nil → call it. `Terminate != nil` → set `connState.terminate <- resp` (buffered 1), DO NOT emit the request head, switch the request side to a drain phase (keep reading from source into a discard so the public client's writes do not block) until the connection closes. `Add/Remove` merge into the head rewrite (removes first, then adds).
- Response side: before reading the source on each new message, drain any pending terminate: emit the synthetic response (status line from StatusCode, headers, `Content-Length`, body, keep-alive: close), then return io.EOF so Join unwinds and both conns close. A terminate mid-body (response side already streaming the previous response) is handled by the buffered channel: the synthetic response is emitted only between messages; documented limitation.
- ResponseHook: called in response `stepHead` after static rewrite; Add/Remove merge (removes first). 1xx heads: hook NOT called (parity with cluster 1's 1xx rule).
- Fail-open unchanged: any hook panic or rewriter-level error keeps the connection on the raw path; hook panics are recovered and logged once (WARN).

### 3.2 policy package (new, top-level `policy/`)

Imports: rewriter (hook types), cel-go, ngrok/log. Exported types with BOTH yaml and json tags (msg envelopes use encoding/json):

```go
type TrafficPolicy struct { OnTCPConnect []*Action `yaml:"on_tcp_connect" json:"on_tcp_connect"`; OnHTTPRequest []*Action `yaml:"on_http_request" json:"on_http_request"`; OnHTTPResponse []*Action `yaml:"on_http_response" json:"on_http_response"` }
type Action struct { Name string `yaml:"name" json:"name"`; Expressions []string `yaml:"expressions" json:"expressions"`; Config map[string]interface{} `yaml:"config" json:"config"` }
```

- `Validate() error` — unknown action name, unknown phase, bad CEL (compile at validate time!), bad config (per-action shape per ngrok docs) → error naming the action (fail loudly).
- `Compile() (*Compiled, error)` — cel-go env with the documented variable subset: `conn.client_ip` (string), `conn.remote_addr` (string), `req.method`, `req.url.path`, `req.url.query`, `req.url.raw`, `req.headers` (map[string]string), `req.cookies` (map[string]string), `res.status_code` (int, response phase only). Per-action compiled CEL programs.
- `NewRequestHook(compiled, logger) rewriter.RequestHookFunc`-style constructors (naming is yours) and a `NewResponseHook`; the hooks evaluate actions in phase order, honor per-action `expressions` (all expressions ANDed per action), implement: restrict-ips (CIDR allow/deny lists incl. IPv6; deny wins), deny (default 403, empty body), custom-response (status_code/headers/body from config, defaults: 200/empty), add/remove-headers, log (structured WARN/INFO entry with evaluated fields), set-vars (store strings, `${vars.name}` substitution in later actions' header values and custom-response body/headers, in phase order).
- `EvaluateConnect(connAddr string) ConnectVerdict` for on_tcp_connect (restrict-ips/deny/log), used by the server at accept time.
- cel-go version: pin a go-1.21-compatible release (v0.20.x). Document the CEL variable subset in the package doc.

### 3.3 Server wiring

- `msg.ReqTunnel` gains `TrafficPolicy *policy.TrafficPolicy` (json tag; nil = no policy; backward compatible).
- `server/tunnel.go` NewTunnel/register: store the policy on the Tunnel (nil-safe); nothing else changes.
- `server/http.go` httpHandler: after `ResolveForward` (and basic-auth), before `HandlePublicConnection`: if target has a policy → `EvaluateConnect` against `remoteIP(c.RemoteAddr())`; verdict deny → write the synthetic response (or 403 default), close, return. Then `HandlePublicConnection(c, policy)` — signature change (or a variant); inside, wrap the join with `rewriter.NewConnPair(publicConn, proxyConn, serverPolicy)` where serverPolicy = rewriter.Policy{HostHeader: preserve-defaults, RequestHook: policy hooks, ResponseHook: policy hooks, ClientAddr: <the public addr — do NOT set: client injects XFF; keep server policy limited to hooks and NO X-Forwarded/Compress/Host logic>}. Join direction mirrors the client (requests: publicConn source; responses: proxyConn source).
- `server/tunnel.go` listenTcp: after accept, `EvaluateConnect`; deny → close (optionally write nothing — TCP has no response; log).
- Per-connection compiled policy caching: compile once per tunnel at registration (store *policy.Compiled on Tunnel), not per connection; hook state (vars) is per connection.

### 3.4 Client plumbing (workstream B)

- `TunnelConfiguration.TrafficPolicy *policy.TrafficPolicy` yaml `traffic_policy`; CLI `-traffic-policy-file <path>` (reads YAML/JSON file into the policy, for the default tunnel). Validation: `policy.Validate()` at config load, naming the tunnel.
- `ReqTunnel` construction carries the policy.
- Known parity gap to document: keep-alive through terminated connections (we close after a synthetic response; ngrok can keep the connection).

## 4. Workstreams (file ownership exclusive; SEQUENTIAL: A then B)

### A — engine (rewriter hooks + policy package + server wiring)
Files: rewriter/rewriter.go + rewriter_test.go (hook extension + tests), new policy/ package (policy.go, validate.go, cel.go + tests), msg/msg.go, server/http.go, server/tunnel.go, new server tests, go.mod/go.sum (cel-go, pinned ≤ v0.20.x for go 1.21). Do NOT touch client/, scripts/, docs/.

Tests: rewriter — hook nil-safety, terminate emits synthetic response + closes (net/http ReadResponse-parseable), hook add/remove merge with static policy, hook not called on 1xx, panic recovery → fail-open; policy — validation table (every error names the action), CEL table (path/method/headers/client_ip/res.status_code, expressions ANDing, bad CEL rejected at Validate), restrict-ips CIDR matrix incl. IPv6 + deny-wins, deny default 403, custom-response config, set-vars + ${vars} substitution ordering, log action produces a structured log line; server — on_tcp_connect restrict-ips on http and tcp paths, terminate flow end-to-end over net.Pipe (public client reads the synthetic response, upstream never dialed), response-phase remove-headers visible to the public client, no-policy path byte-identical.

Verification: gofmt clean; `go build -tags debug ./...` (works since v1.0.4); `go vet -tags debug ./...`; `go test -tags debug -race -count=1 ./...`; e2e NOT yours (B owns it — but note if e2e would break).

### B — client plumbing + e2e + changelog (after A)
Files: client/config.go, client/cli.go, client/model.go (ReqTunnel policy attachment), client/config_test.go, scripts/e2e.sh (policy scenarios: deny on req.url.path via CEL → 403, custom-response with body/header, restrict-ips allow/deny from 127.0.0.1, add-headers on request visible upstream + remove-headers on response visible to curl, log action line in the server log, -traffic-policy-file end-to-end), docs/CHANGELOG.md (new Unreleased section: the engine, the action set, the CEL variable subset, parity gaps: keep-alive-close after terminate, no macro set beyond the subset, no body access).

Verification: full gates + `bash scripts/e2e.sh`.

## 5. Review gates (architect)

1. Full gates green (`go build/vet/test -race ./...`); e2e PASS with all prior scenarios + new policy scenarios.
2. No-policy path byte-identical (all cluster-1/2/3 tests untouched and green).
3. Fail-open: hook panic, CEL runtime error (should be impossible post-compile, but recover), or malformed stream never breaks a connection the old code would have carried.
4. Parity spot-check vs ngrok action schemas (docs clone) for the implemented actions; deviations listed in the changelog.
5. cel-go pinned go-1.21-compatible; no go directive bump.

## 6. Success metrics

- Policy attached to a tunnel enforces deny/custom-response/restrict-ips/add-remove-headers/log/set-vars with CEL conditions, config shapes matching ngrok's docs.
- `curl` a blocked path → synthetic response; allowed path → upstream; restricted IP → 403; headers transformed both directions.
- Changelog documents the action set, the CEL variable subset, and the parity gaps honestly.
