# SPEC: HTTP Header Manipulation for the ngrok fork

Status: approved for implementation (user selected "Header cluster now", Sept 2026).
Scope: client-side only. Server untouched.

## 1. Objectives

1. Fix the Ollama-over-tunnel 403 by adding Host-header control (ngrok `--host-header` parity).
2. Add the five ngrok header flags and their config-file keys.
3. Auto-inject `X-Forwarded-For`, `X-Forwarded-Proto` (always) and `X-Forwarded-Host` (when Host is rewritten), matching ngrok behavior.
4. Byte-exact passthrough of request/response bodies and framing; zero behavior change for TCP tunnels; no change to the server.

## 2. Non-goals (explicit)

- **No hop-by-hop header stripping.** The fork currently forwards everything raw; ngrok strips hop-by-hop headers, but changing that now would alter behavior for existing users. Roadmap item, not this release.
- **No `Location` header rewriting in responses** (ngrok's documented side effect of host rewriting). Deferred follow-up; note it in the changelog.
- No gzip, no response buffering, no HTTP/2, no TLS changes, no server-side policy.
- No changes to the inspector/analyzer tee (it stays as-is and must keep working).

## 3. Background facts (verified against the code)

- Data path is raw byte pipes. Server parses the request head only for vhost lookup (`server/http.go`), then streams the original bytes; `StartProxy` carries only `Url` + `ClientAddr` (`msg/msg.go:108-111`).
- Client proxy loop: `client/model.go:401-440` reads `StartProxy`, dials the local upstream, wraps it in the inspector tee (`proto/http.go:85-91`), then `conn.Join(localConn, remoteConn)` (`conn/conn.go:202-226`) copies both directions with `io.Copy`.
- `mvc.Tunnel` (`client/mvc/state.go:25-29`) is `{PublicUrl, Protocol, LocalAddr}` — the natural carrier for per-tunnel header policy.
- Config plumbing: CLI flags in `client/cli.go` (`Options` struct, Go `flag` pkg — no repeatable flag support, needs a custom `flag.Value`); config file in `client/config.go` (`Configuration` / `TunnelConfiguration`, `gopkg.in/yaml.v1`); the `default` CLI tunnel is synthesized in `LoadConfiguration` (`client/config.go:175-190`).
- Go 1.21, module path `ngrok`. Tests use plain stdlib `testing` with `t.Fatalf` (see `server/ratelimit_test.go`).

## 4. Semantics to implement (ngrok parity)

### 4.1 `host_header`

Values: `rewrite` | `preserve` | explicit hostname. Default (unset) = `preserve` = current behavior.

| Setting | Behavior on the request sent to the local upstream |
|---|---|
| unset / `preserve` | Host unchanged |
| `rewrite` | Host := hostname portion of `tunnel.LocalAddr` (e.g. `127.0.0.1:11434` → `127.0.0.1`; `localhost:11434` → `localhost`). Original Host saved to `X-Forwarded-Host`. |
| explicit value | Host := the value; original Host saved to `X-Forwarded-Host`. |

Validation: must be `rewrite`, `preserve`, or a non-empty hostname (no spaces, no `/`, no CR/LF). Reject at config load with a clear error (fail loudly, no silent default).

### 4.2 Request/response header add/remove

CLI flags (repeatable, mirroring ngrok):
- `-host-header <value>`
- `-request-header-add <key:value>` (repeatable)
- `-request-header-remove <key>` (repeatable)
- `-response-header-add <key:value>` (repeatable)
- `-response-header-remove <key>` (repeatable)

Config-file keys (this fork's v1-style YAML: the local address lives INSIDE the `proto:` map — there is no `addr:` key; `proto` is the PUBLIC protocol(s), the local leg is always plain HTTP/TCP):
```yaml
tunnels:
  ollama:
    proto:
      http: 127.0.0.1:11434      # public http -> local 127.0.0.1:11434 (plain HTTP, never TLS)
      # https: 127.0.0.1:11434   # optionally also serve public https, same local leg
    host_header: rewrite          # Host becomes 127.0.0.1 (loopback -> Ollama accepts)
    request_header:
      add: ["X-Custom: value"]
      remove: ["X-Secret"]
    response_header:
      add: ["X-Served-By: ngrok"]
      remove: ["Server"]
```

Explicit-value alternative for Ollama (the exact form from Ollama's FAQ): `host_header: "localhost:11434"`. Both `rewrite` (resolving to `127.0.0.1` or `localhost` depending on the configured local addr) and the explicit form pass Ollama's loopback Host check.

Semantics:
- **Add is append**, not replace: if the key already exists, a second header with the same key is appended — EXCEPT `host`, which overrides (never appends).
- **Remove** drops all headers matching the key case-insensitively.
- Header-name matching is case-insensitive everywhere.
- Added header names are serialized in canonical form (Go's `textproto.CanonicalMIMEHeaderKey`). Untouched headers keep their original bytes/order/casing.
- `user-agent` may not be added or removed → reject at config load (ngrok parity).
- Values containing CR/LF are rejected at config load (header-injection guard).

### 4.3 Automatic X-Forwarded injection (always on for http/https tunnels)

- `X-Forwarded-For` := `startPxy.ClientAddr`, **replacing** any value the public client sent (prevents spoofing; ngrok parity).
- `X-Forwarded-Proto` := `http` or `https` derived from the tunnel's public URL.
- `X-Forwarded-Host` := original Host, only when the Host is rewritten (4.1).

> Decision point flagged for the user at review: this is the ONE default behavior change for tunnels that set no flags. It is standard reverse-proxy behavior and the only way upstreams can see real client IPs; keep unless the user vetoes.

### 4.4 Ordering within a rewritten head

1. Remove configured removals (case-insensitive), including any existing `X-Forwarded-For`/`X-Forwarded-Proto` (we replace them).
2. Host rewrite / override (per 4.1) + `X-Forwarded-Host` if rewritten.
3. Append configured additions in declaration order.
4. Append `X-Forwarded-For` and `X-Forwarded-Proto` last.

## 5. Architecture

### 5.1 New package: `rewriter/` (import `ngrok/rewriter`)

Works on `io.Reader` primitives (testable with buffers/pipes), with a `conn.Conn` adapter for the live path. No imports of `client`, `server`, `mvc` (imports `ngrok/conn` and `ngrok/log` allowed).

```go
package rewriter

// Policy is the per-tunnel header policy, built from config + StartProxy metadata.
// Add/Remove entries are ordered slices; add entries are "Key: value" strings.
type Policy struct {
	HostHeader          string   // "", "rewrite", "preserve", or explicit host
	RequestHeaderAdd    []string // "Key: value" pairs, append semantics
	RequestHeaderRemove []string // header names
	ResponseHeaderAdd   []string
	ResponseHeaderRemove []string
	UpstreamHost        string // hostname of tunnel.LocalAddr, for "rewrite"
	ClientAddr          string // from StartProxy.ClientAddr
	XForwardedProto     string // "http" | "https"
}

// Validate checks the policy for CR/LF injection, user-agent targets, malformed
// add entries; returns an error naming the offending entry.
func (p *Policy) Validate() error

// IsNoop reports whether the policy performs no transformation at all
// (used by the client to skip wrapping when possible).
func (p *Policy) IsNoop() bool

// NewPair returns request- and response-direction readers sharing connection
// state (upgrade + last request method). reqSrc is the public->local stream
// (reads: requests), respSrc is local->public (reads: responses).
func NewPair(reqSrc, respSrc io.Reader, p *Policy) (req, resp io.Reader)

// NewConnPair wraps the two readers in conn.Conn adapters (Write/Close/deadlines
// delegate to the embedded conn; Read returns transformed bytes).
func NewConnPair(reqSrc, respSrc conn.Conn, p *Policy) (toUpstream, fromUpstream conn.Conn)
```

### 5.2 The streaming head-rewriter (core difficulty — read carefully)

Each direction is a read-driven state machine over a connection-lifetime `bufio.Reader` (64 KiB). Transformed bytes are emitted from an internal buffer before more source reads happen. No extra goroutines.

**Shared connection state** (`connState`, mutex-guarded):
- `lastMethod string` — request method, needed by the response side for HEAD (no body).
- `upgraded bool` — set when a request carries `Connection: upgrade` + `Upgrade:` (request side self-switches to raw after emitting its head), or when a `101 Switching Protocols` response is seen (response side switches raw; request side checks this flag between heads).

**Request direction phases:**
1. `head`: read until `\r\n\r\n`, 64 KiB cap. Parse request line + MIME headers from the buffered head bytes. Apply 4.1–4.4. Emit rewritten head. If the request is an upgrade → set `upgraded`, then phase `raw`. Else derive body framing:
   - `Content-Length: N` → phase `bodyCL(N)` (copy exactly N bytes raw, then back to `head`)
   - `Transfer-Encoding: chunked` → phase `bodyChunked` (track chunk-size lines, copy chunks + trailers raw, back to `head`)
   - neither → phase `head` (no body)
2. `raw`: passthrough until EOF.
3. **Fail-open**: head parse error, malformed framing, or 64 KiB overflow → emit all already-buffered bytes, log at WARN with the connection id, switch to `raw`. Never tear down a connection the old code would have carried.
4. EOF mid-head → emit buffered bytes, then EOF.

**Response direction phases:** same shape, with response framing rules:
- 1xx interim responses (e.g. `100 Continue`): emit head, stay in `head` for the next head (1xx may precede the final response; loop).
- `101` → set `upgraded`, emit head, phase `raw`.
- no body: status `204`/`304`, any 1xx, or `lastMethod == "HEAD"` → straight back to `head`.
- `Content-Length: N` → `bodyCL(N)`; `Transfer-Encoding: chunked` → `bodyChunked`; else close-delimited → `raw` (no next head).
- Response policy = only add/remove (no Host/X-Forwarded logic on responses).

**Preservation guarantees (golden-test invariants):** body bytes and chunk framing are byte-identical; header order/casing of untouched headers is identical; `Connection: upgrade` requests still work (websockets regression test).

### 5.3 Integration point

`client/model.go:439-440`. Current:
```go
localConn := tunnel.Protocol.WrapConn(localConn, mvc.ConnectionContext{...}) // tee
bytesIn, bytesOut := conn.Join(localConn, remoteConn)
```
New:
```go
localConn := tunnel.Protocol.WrapConn(localConn, mvc.ConnectionContext{...}) // tee, unchanged
if tunnel.Protocol.GetName() == "http" {
	policy := policyFromTunnel(tunnel, startPxy.ClientAddr) // helper, workstream C
	if policy != nil && !policy.IsNoop() {
		toUpstream, fromUpstream := rewriter.NewConnPair(remoteConn, localConn, policy)
		bytesIn, bytesOut = conn.Join(fromUpstream, toUpstream)
	} else { ... existing Join ... }
} else { ... existing Join ... }
```

Direction check: `Join(c, c2)` copies `c2→c` and `c→c2` (`conn/conn.go:202-226`). Requests flow `remoteConn→localConn` and must pass the request rewriter; responses flow `localConn→remoteConn` through the response rewriter. Each rewriter wraps the **source** side of its direction.

The 502 Bad-Gateway path (`client/model.go:421-429`) is untouched.

## 6. Config plumbing

### 6.1 `client/cli.go`

- Add to `Options`: `hostHeader string`, `requestHeaderAdd, requestHeaderRemove, responseHeaderAdd, responseHeaderRemove stringList`.
- New `type stringList []string` implementing `flag.Value` (String() joins; Set() appends, splits add-entries on first `:` at validation time, not here).
- Register five repeatable flags with ngrok-style help text (e.g. `"header key:value to add to request"`).
- Wire into the `default`-tunnel synthesis in `config.go`.

### 6.2 `client/config.go`

- `TunnelConfiguration` gains:
```go
HostHeader     string        `yaml:"host_header,omitempty"`
RequestHeader  *HeaderConfig `yaml:"request_header,omitempty"`
ResponseHeader *HeaderConfig `yaml:"response_header,omitempty"`
```
with `type HeaderConfig struct { Add []string `yaml:"add,omitempty"`; Remove []string `yaml:"remove,omitempty"` }`.
- Validation in `LoadConfiguration` (fail loudly): `host_header` in {unset, rewrite, preserve, valid hostname}; add entries contain exactly one first-colon split with non-empty key; keys are RFC 7230 tokens (regex, no CR/LF); `user-agent` rejected for add/remove.
- `default`-tunnel synthesis (`config.go:175-190`) copies the new fields from `opts`.

### 6.3 `client/mvc/state.go`

- `Tunnel` gains `HostHeader string`, `RequestHeaderAdd, RequestHeaderRemove, ResponseHeaderAdd, ResponseHeaderRemove []string`.
- Populated where `mvc.Tunnel` is constructed in the tunnel-established handler (`client/model.go:~350`), from `reqIdToTunnelConfig[m.ReqId]`.

## 7. File structure (deliverables)

```
rewriter/
  rewriter.go          # Policy, Validate, IsNoop, NewPair, state machines
  conn.go              # NewConnPair + filtered conn.Conn adapter
  rewriter_test.go     # golden + matrix tests (see 8)
client/
  cli.go               # flags (modified)
  config.go            # config structs + validation (modified)
  model.go             # integration (modified, workstream C only)
  mvc/state.go         # Tunnel fields (modified)
docs/
  CHANGELOG.md         # entry (modified)
scripts/
  e2e.sh               # extended with an Ollama-style scenario (workstream C)
```

## 8. Testing strategy

**A — rewriter unit tests (workstream A, must all pass with `-race`):**
1. GET, Host preserve (default) — output byte-identical except X-Forwarded additions.
2. `rewrite` → Host = UpstreamHost; `X-Forwarded-Host` = original.
3. Explicit host value.
4. Add appends duplicate key; host add overrides; remove drops all matches case-insensitively.
5. `X-Forwarded-For` replaced (client sent a spoofed one), `X-Forwarded-Proto` set.
6. Content-Length request body + response body byte-exact (binary body with `\r\n\r\n` inside).
7. Chunked request + chunked response: framing sizes byte-identical.
8. Pipelined two GETs on one connection; second Host also rewritten.
9. `Expect: 100-continue` → 100 interim → 200 final, both heads rewritten.
10. HEAD request → response without body → next response parses correctly.
11. 204 / 304 no-body responses.
12. 101 upgrade → both directions raw passthrough (websocket-shaped bytes after 101 survive untouched, including binary frames containing `\r\n\r\n`).
13. Upgrade request (no 101 yet) → request side raw after head.
14. Oversized head (>64 KiB) → fail-open raw, all bytes preserved.
15. Garbage/non-HTTP stream → raw passthrough.
16. `IsNoop` policy → (skipped at integration level; unit-level still exercises the passthrough-with-X-Forwarded path).

**B — config tests (workstream B):** YAML unmarshal round-trip (nested request_header/response_header); invalid host_header rejected; add without `:` rejected; CR/LF in value rejected; user-agent rejected; repeatable flag parsing (including multiple `-request-header-add`).

**C — integration (workstream C):**
1. Table-driven test driving `model.go`'s proxy path with a `net.Pipe` fake remote conn and a real `httptest` upstream: assert rewritten Host arrives, response headers pass through, keep-alive works across two requests.
2. Extend `scripts/e2e.sh`: upstream that 403s when Host != localhost (exactly Ollama's behavior); `curl` through the tunnel → 403 without flags, 200 with `-host-header=rewrite`; plus a `-response-header-add` assertion.
3. Manual check documented in the PR/release notes: real Ollama + `-host-header=rewrite`.

## 9. Workstreams

- **A (parallel):** `rewriter/` package — Policy, Validate, IsNoop, NewPair, NewConnPair, both state machines, all 16 unit-test cases. Deliverable: `rewriter/*.go`. Must not import client/server/mvc. `go test ./rewriter/ -race` green.
- **B (parallel):** config plumbing — cli.go flags + stringList, config.go structs + validation, mvc.Tunnel fields (+ population code stubs? NO — model.go population is C's job; B only adds the fields and leaves a compile-safe TODO-free placeholder: B sets the fields in the constructor with zero values only if it compiles — otherwise C does the population). Deliverable: modified `client/cli.go`, `client/config.go`, `client/mvc/state.go`, config tests. `go build ./...` must stay green (B runs before C lands).
- **C (after A and B):** integration — model.go wiring + `policyFromTunnel` helper, population of mvc.Tunnel fields, e2e script, integration tests. Deliverable: modified `client/model.go`, `scripts/e2e.sh`, integration tests.

Agents must not touch files outside their workstream. No commits; leave the tree dirty for review.

## 10. Review gates (the architect checks after C)

1. `go build ./...`, `go vet ./...`, `go test ./...` green; rewriter tests with `-race`.
2. Existing behavior unchanged when no flags set — except the X-Forwarded decision (4.3), which the user reviews explicitly.
3. Data-driven code: policy construction is declarative field copies, no if/elif chains beyond the two state machines' phase switches; validation errors name the offending entry.
4. Fail-open verified: garbage streams never break connections the old code carried (test 14/15).
5. Semantics parity spot-check vs section 4 table.
6. No goroutine leaks (`-race` + `goleak`-style check if quick, else manual).

## 11. Success metrics

- `go test ./...` green before AND after (no regressions in server tests).
- Golden tests prove byte-exact body/framing preservation.
- e2e: Ollama-shaped 403 turns into 200 with `-host-header=rewrite`.
- Release note lists the five flags with examples (documented in CHANGELOG.md).
