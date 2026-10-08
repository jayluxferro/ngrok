# SPEC-CLUSTER19 — ngrokd admin web UI: the config workbench + observability SPA

Status: shipped (v1.0.19)

The admin listener is 70% of a control plane already: three-mode auth with
browser sessions, a CSP, a per-IP rate limiter, `/metrics` with a 1s sampler,
`/tunnels` snapshots, `/events` SSE, `/recommendations`. What is missing is
everything *write-shaped* — and the one screen it serves is an inline HTML
const. This cluster turns it into a real UI: a static SPA served from embedded
assets, and a small JSON API that lets an operator validate and render the
exact documents the agent and the policy engine consume, against the exact
code that consumes them.

The organizing rule is **single source of truth**: config validation is the
same traversal `LoadConfiguration` runs (extracted, not duplicated), the
policy action matrix is the same `actionPhases` map the engine enforces
(newly exported), and the schema table the UI renders is pinned to the
config structs by a reflection test that fails when either side drifts.

## Objectives

1. `/` serves a workbench + observability SPA from `server/assets` (the
   `server-assets` make target already packages `assets/server/...`; this is
   ngrokd's first *import* of that package). Tabs: Overview, Tunnels, Events
   (the current inline dashboard's content, relocated), and Workbench.
2. A JSON API under `/api/`, every route behind the existing admin auth,
   method-pinned, `no-store`, bodies capped at 1 MiB:
   - `GET /api/schema` — the config key table (hand-tabled, reflection-pinned)
     plus the policy action matrix (derived from `actionPhases`).
   - `POST /api/validate/config` — validates a client config document with
     the agent's own validators.
   - `POST /api/validate/policy` — validates one traffic-policy document
     (`on_tcp_connect` / `on_http_request` / `on_http_response` root) with
     `TrafficPolicy.Validate()`.
   - `POST /api/render` — parse + canonical re-marshal (YAML, 2-space) of
     either document kind; download-only (the client turns the response into
     a Blob; the server never writes files).
3. `/tunnels` snapshots gain the registration facts an operator debugging a
   live endpoint wants: owner, internal, agent-TLS, forward_to, claimed
   port, pooling, policy-attached. Additive JSON; existing consumers
   unaffected.
4. Vanilla JS/CSS only. No `package.json`, no build step, no framework: the
   repo has none, the existing dashboard is already vanilla, and an admin
   surface is the last place to grow a node toolchain. `fetch()` + JSON;
   DOM built with `createElement`/`textContent` — **never** server data
   interpolated into HTML, client-side or server-side.

## Non-goals (binding)

- **Remote agent control.** No server→agent wire message exists by design,
  and an authenticated endpoint that starts or stops processes on user
  machines is an RCE surface deserving its own threat model. If ever built,
  it is its own cluster.
- **Server-side per-request traffic inspector.** The inspector tee is
  agent-local by architecture (the server relays bytes it mostly cannot
  parse); the SSE event stream is the whole server-side story. Paid ngrok's
  inspector equivalently lives in the agent.
- **Multi-user admin / RBAC.** One admin principal, as today.
- **Editing live-tunnel policies.** Policies are registration-scoped; the
  workbench edits *documents*, not running endpoints.
- **Server-side file writes.** Render is a download, not a saved file. The
  workbench also never *reads* operator-named files (see the
  `traffic_policy_file` refusal below).
- **Vault-aware validation.** Refused, loudly (see Design §3) — not a
  limitation to engineer around later, the honest answer.

## Design

### 1. API surface — `server/admin_api.go` (new), wired in `admin.go`

All four routes register through a sibling of the existing `secure()`
wrapper (same security headers, method check, auth check) that consults its
own rate limiter (§2). Request/response shapes:

- **Envelope.** The three POST endpoints take
  `{"content": "<raw document text>"}` (render adds `"kind":
  "config" | "policy"`). JSON only — one shape everywhere, and JSON parsing
  keeps YAML quirk-handling out of the transport layer.
- **Validation verdicts are 200s.** `{"valid": true}` or
  `{"valid": false, "error": "<the validator's message, verbatim>"}`. The
  endpoint succeeded; the document is bad. 4xx stays for transport faults:
  malformed envelope 400, oversize 413, vault refusal 422 (§3), wrong
  method / no auth as the wrapper already answers.
- **Caps.** `http.MaxBytesReader(w, r.Body, 1<<20)` on every POST; the
  wrapper family makes this uniform. A 413 body names the cap.
- **Schema payload.**
  `{"config": {"top_level": [...], "tunnel": [...]}, "policy":
  {"phases": {"on_tcp_connect": ["deny", ...], ...}, "actions":
  [{"name": "deny", "phases": [...], "summary": "..."}]}}`. Config rows:
  `{key, type, default, summary}`; `key` is the YAML spelling (e.g.
  `tunnels.<name>.subdomain`, `auth_token`). Policy phases and names come
  from the exported matrix (§4); summaries are hand-tabled beside it with a
  both-directions pin (§4).

### 2. Rate budget — the keystroke question, resolved

`-adminRate` (default 120/min per IP) governs pages, metrics, tunnels,
events. The workbench validates on keystroke-idle (500 ms debounce) plus
explicit button; a fast editor pasting sections can beat 120/min and would
lock themselves out of their own dashboard mid-edit.

`/api/*` gets its **own** limiter: `apiRate = 5 × adminRate` when
`adminRate > 0` (default: 600/min = 10 validations/s sustained — past any
typist, still a real cap), and 0 — off — exactly when `-adminRate 0` says
the whole admin surface is unthrottled. An operator who deliberately sets a
tight `-adminRate` gets a proportionally tight API budget, never a surprise
floor. Implementation: a second `newIPRateLimiter` beside the first in
`adminHandler`; unit test pins the 5× arithmetic and the 0-propagation.

### 3. Vault safety — refuse, never resolve

`policy.SetVaults` is **process-global** (`server/vaults_config.go:34`,
`client/config.go:1544`). ngrokd installs its own set at startup; the
client loader installs the agent's. A workbench validation call must touch
neither: mutating the server's live set to answer a UI question would feed
garbage to real tunnel registrations, and validating against it would
answer a question about the *agent's* vaults with the *server's* set.

Therefore:

- `client.ValidateConfigurationDoc` (§5) refuses, with sentinel error
  `ErrVaultRefused`, any document containing a top-level `vaults:` block or
  any `secret(` reference — the raw text is scanned before parsing, so the
  refusal cannot be outrun by placement or nesting. The sentinel lives in
  the function, not the HTTP layer, so *any* caller inherits the safety.
- The policy handler applies the same raw scan (`secret(`) before parsing;
  a hit is the 422 with the same explanation. `policy.TrafficPolicy`
  stays workbench-agnostic — the refusal is a caller concern.
- Both 422 bodies say the same thing: vaults resolve against each process's
  own configured set; the workbench has none and will not guess; remove the
  block/references to validate the rest.

Deliberately crude: a header value that merely *contains* `secret(` is
refused too. Fail-closed with an explanation beats a clever parse that
might miss a spelling.

### 4. Policy matrix, exported — `policy/validate.go`

```go
// PhaseActionMatrix returns, keyed by phase name ("on_tcp_connect", ...),
// the sorted action names that phase implements, derived from actionPhases
// — the same map the engine enforces — so a UI cannot disagree with the
// build about what is legal where.
func PhaseActionMatrix() map[string][]string
```

Phase names come from `phase.String()` (already the YAML spellings). The
oidc row appears automatically; the next action lands here without a UI
change. Summaries: a hand-tabled `map[string]string` in `admin_api.go`
(one line per action, prose only — config *shapes* are the changelog's
job). Pin, both directions, in tests: every matrix action has a summary;
every summary names a matrix action.

### 5. `ValidateConfigurationDoc` — extraction, not duplication

`LoadConfiguration`'s post-parse body splits into
`(*Configuration).applyDefaultsAndValidate(loadVaults, loadFileRefs bool) error`:

- **Moves in** (verbatim, same order, same error strings): defaults
  (`server_addr`, `inspect_addr`), the loud negative-value refusals and
  zero-defaults (`inspect_max_body_bytes`, `proxy_max_concurrency`),
  `loadVaults()` (gated on `loadVaults`, in its exact current position
  between the defaults block and address normalization), address
  normalization, the `http_proxy` URL-shape check, `inspect_auth` form,
  the size ceiling, and the whole per-tunnel loop —
  `validateEndpointPolicy`, protocol normalization/validation,
  `validateRemotePort`, `validateAgentTLS`, `validateHeaderPolicy`,
  `traffic_policy_file` resolution (gated on `loadFileRefs`; when false, a
  doc naming the key is refused with "inline the policy (or resolve the
  file) to validate it here" — the workbench never reads operator-named
  paths; cert *paths* under `tls:` are shape-checked only, as today),
  `validateTrafficPolicy`, the `alpn` rules, and cluster 17's
  `upstream_protocol` validation.
- **Stays in `LoadConfiguration`**: file reading, the old single-token
  format check (the workbench runs it too — a token-only doc is valid),
  and the `http_proxy` *environment* fallback, which moves *before* the
  call — order-invisible, since no default touches `HttpProxy` and the
  fallback only fills it when empty.
- `LoadConfiguration` calls `applyDefaultsAndValidate(true, true)`;
  `ValidateConfigurationDoc` calls `applyDefaultsAndValidate(false, false)`.

Then:

```go
// ValidateConfigurationDoc parses and validates a client configuration
// document exactly as LoadConfiguration would, without reading files,
// consulting the environment, or touching process-global vault state.
func ValidateConfigurationDoc(buf []byte) error
```

**The parity proof is a test, not a claim**: a corpus of bad documents goes
through both `LoadConfiguration` (temp file) and `ValidateConfigurationDoc`,
and the error strings must match byte-for-byte — the extraction cannot
drift because drift fails the build.

**Cost, stated honestly**: ngrokd grows an import of `ngrok/client`, whose
dependency closure (QUIC, mvc/views) lands in the server binary. Single
module, legal import; the size delta gets measured and named in the
changelog. The alternative — relocating the validators to a shared package
— is a refactor with no behavior change, rejected here.

### 6. Static assets — `assets/server/dashboard/` (new subtree)

Files: `index.html`, `style.css`, `app.js`. The `server-assets` make target
already packages `assets/server/...`; **zero Makefile change**.

- `/` serves `dashboard/index.html` from the assets package
  (`text/html; charset=utf-8`, `no-store`). The big inline
  `adminDashboardHTML` const is **removed** — its Overview/Tunnels/Events
  content relocates into the SPA. `loginHTML` stays inline (tiny, no
  script).
- `/static/<name>` serves exactly `{index.html, style.css, app.js}` — a
  fixed switch, not a path join; anything else 404s. MIME by extension
  (`text/html`, `text/css`, `text/javascript`).
- **CSP tightens**: `script-src` drops `'unsafe-inline'` — every script is
  now an external file; the inline dashboard was the only reason the
  allowance existed. `style-src 'self' 'unsafe-inline'` stays (the SPA
  uses a few inline style attributes; a future cluster can tighten).
- Debug builds: go-bindata `-debug` bakes absolute paths into the source
  tree (dev-machine-only); release builds embed. Same standing caveat as
  client assets, same documentation.

### 7. Snapshot enrichment — `server/observability.go`

`tunnelSnapshot` gains, filled once at `onTunnelOpen` (registration facts
are immutable; the counters keep their existing lifecycle):

| field | json | source |
|---|---|---|
| owner | `owner` | `t.owner` |
| internal | `internal` | `t.internal()` |
| agent TLS | `agent_tls` | `t.agentTLS()` |
| forward_to | `forward_to` | `t.forwardTo()` |
| claimed port | `claimed_port` | `t.claimedPort` |
| pooling | `pooling` | `t.req.Pooling` |
| policy attached | `policy_attached` | `t.policy != nil` |

### 8. The SPA — `assets/server/dashboard/`

One page, four tabs, ~600 lines total of hand-written ES2020 + CSS in the
existing dashboard's visual language (dark, monospace, cards):

- **Overview** — the metric cards + rate rows the inline page showed, from
  `/metrics`.
- **Tunnels** — the snapshot table with the new columns.
- **Events** — the SSE reader (unchanged semantics, relocated).
- **Workbench** — two editors (config, policy): `<textarea>` with
  Validate (500 ms debounce + button), the verdict line rendered via
  `textContent` (never `innerHTML` — errors are operator-controlled text
  and are still never parsed as HTML), a collapsible schema sidebar fed by
  `/api/schema`, and Render → download (`Blob` + `URL.createObjectURL`,
  filename `ngrok-config.yaml` / `traffic-policy.yaml`).

No state leaves the browser; no localStorage of documents (a config in
localStorage is a credential sitting in a less-audited store — the editor
is deliberately ephemeral and says so in a footer line).

## File ownership (workstreams)

| Workstream | Owns |
|---|---|
| **A — server API** | `server/admin.go` (routes, CSP, `/` + `/static/`, const removal), `server/admin_api.go` (new), `server/admin_api_test.go` (new), `server/observability.go`, `policy/validate.go` (+ tests) |
| **B — client extraction** | `client/config.go`, `client/config_test.go` |
| **C — dashboard** | `assets/server/dashboard/*` only |
| **D — e2e** | `scripts/e2e.sh` (new `admin2` group), its helper files |

A and B are independent. C codes against §1's JSON contract in parallel
(the contract is fixed by this spec; if A must deviate, A updates the spec
first). D lands last. No workstream touches `msg/`.

## Testing strategy

- **client**: the parity corpus (§5); each refusal class (vaults block,
  `secret(` in a policy, `traffic_policy_file`, negative ints, bad
  protocol, bad `alpn` combo); the legacy token-only doc; a minimal valid
  doc; defaults still applied (empty `server_addr` normalized in the copy,
  not an error).
- **policy**: matrix covers every `actionPhases` row; phase names are the
  YAML spellings; sorted output.
- **server**: per-endpoint handler tests (200 valid / 200 invalid-with-
  message / 400 envelope / 413 oversize / 422 vault / 405 / 401), schema
  shape, summaries both-directions pin, reflection pin (§4, schema table ↔
  struct tags), static MIME + 404 + `no-store`, CSP without
  `unsafe-inline` in `script-src`, enriched snapshot fields, the 5× rate
  arithmetic.
- **e2e (`admin2` group, ports grepped for collisions first — the standing
  rule)**: ngrokd with `-adminAddr` + auth; `/api/schema` returns parseable
  JSON; validate-config good/bad; validate-policy good/bad/`secret(`→422;
  render round trip re-validates as the same document; `/static/app.js`
  MIME; `/` served with the tightened CSP; `/tunnels` shows `owner` on a
  registered tunnel.

## Review gates

1. **Vault safety**: no `/api` code path reaches `policy.SetVaults` or
   `os.ReadFile` of an operator-named path (grep + the refusal tests pin
   it).
2. **Parity**: the corpus test green; error strings identical.
3. **Pins**: reflection pin + summaries pin green — the UI's schema cannot
   disagree with the structs or the engine.
4. **CSP + caps**: served headers verified (no `unsafe-inline` scripts;
   `no-store` on API; 413 on the 1 MiB+1 body).
5. **Full gates**: `-tags debug` build/vet/test for touched packages, race,
   full e2e green, `make release-server` binary boots and serves `/static/`
   from embedded assets (embedded-path smoke, not just the debug build).
6. **`msg/` untouched** — no wire change anywhere in the cluster.
7. Docs: README (admin endpoints table grows the API + workbench blurb),
   CHANGELOG 1.0.19 (including the binary-size delta from the client
   import), spec status flip.

## Release

v1.0.19.

## Amendments (post-ship findings)

1. **§5's "a token-only doc is valid" was wrong about the code it
   described.** The legacy single-token branch sits behind the YAML parse
   in `LoadConfiguration`, and `yaml.v3` refuses a scalar into the
   `Configuration` struct — so a bare token has been a parse error on the
   loader road since the parser swap; the legacy branch is unreachable.
   `ValidateConfigurationDoc` mirrors the loader (same refusal, same
   message) rather than becoming the one road that accepts a document the
   agent rejects. Pinned client-side (`TestValidateConfigurationDocLegacyToken`)
   and server-side (validate/config on a token-only body answers
   `{"valid": false}` with the yaml complaint). Found by workstream B at
   implementation; recorded here because the spec text, not the code, was
   the error.
2. **`proxy_transport` joined the extraction in v1.0.20.** At ship time
   the enum check was opts-entangled in `LoadConfiguration`'s flag merge
   and therefore absent from `ValidateConfigurationDoc` — a workbench
   document with `proxy_transport: grpc` validated as good, the one
   divergence-from-the-loader the workbench could produce. v1.0.20 moves
   the flag override before the extracted call (the `http_proxy` env
   pattern) and the switch to the end of `applyDefaultsAndValidate` —
   last, preserving the loader's error precedence (a bad tunnel has
   always outranked a bad carrier word) — with two corpus additions
   pinning both the refusal and the ordering.
3. **`/static/*` rides the API budget, not the pages budget** (§1's
   "behind the existing admin auth" resolves to `secureAPI`): the SPA's
   three files require credentials and spend the 5× `/api/*` limiter,
   three requests per page load. Coherent — the browser replays
   credentials — but worth stating, since a bare `curl /static/app.js`
   answering 401 is by design.
