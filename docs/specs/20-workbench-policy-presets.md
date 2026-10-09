# SPEC-CLUSTER26 — workbench policy presets: curated fragments the engine can never rot under

The workbench's editor starts from a blank page. `/api/schema` tells the
operator what EXISTS — every field, every action, every phase — but not what
GOOD looks like. Presets are curated policy fragments the workbench offers
as starting points, each one guaranteed valid against the REAL validator at
insert time and kept honest by a pin test that fails the BUILD when the
engine moves underneath. The rot class this kills is real and was found in
this tree: the README's own `restrict-ips` example carried a `cidrs:` key the
validator has always refused — documentation drift the engine could not
catch. A preset cannot drift that way: the pin test compiles every preset
through the same handler stack the operator's keystrokes hit.

The shape is the `/api/schema` pattern's third artifact: hand-tabled
embedded Go data, a GET endpoint behind `secureAPI`, pinned by unit tests in
both directions. No static file, no auth surface change, no budget change.

## Objectives

1. `GET /api/presets` — byte-stable, sorted, curated fragment list.
2. Every preset is a valid policy document per the real validator, PINNED:
   engine drift breaks the build, not the operator's insert.
3. SPA: a presets panel that inserts a fragment into the ephemeral editor
   (textContent-only DOM, no localStorage, no new static files).
4. e2e: endpoint contract + live per-preset validation + a schema cross-join.

## Non-goals (binding)

- NO new file under `/static/` — the exactly-three-files rule defended at
  `server/admin.go` ~418-431 and pinned by e2e admin2-10 stands. Presets are
  data the app fetches; that is what `/api/*` is for. Baking them into
  app.js is refused for the same reason the schema wasn't: the pin story
  lives in the server package the tests import.
- NO preset contains `secret(` — the raw scan 422s it at insert
  (`server/admin_api.go` ~300-303); vault refs land red. Placeholders only
  (`REPLACE_ME`).
- No server-side file writes, no runtime file reads (the `traffic_policy_file`
  refusal precedent: the admin surface never touches operator-named paths).
- No config-generation magic: inserting a fragment is a text insert; the
  workbench's validate button remains the only oracle.
- `kind: "policy"` v1 — the field exists for forward-compat (config presets
  someday); nothing branches on it yet.
- No auth/budget/CSP changes: the route inherits `secureAPI`'s 401/405,
  the 5× api limiter, `no-store`, and the CSP — fetched once per visit and
  cached in memory exactly like `schemaCache` (app.js ~593-618).

## Design

### 1. Payload — `server/admin_api.go`

`[]apiPreset` hand-tabled beside `configTopLevelSchema` /
`configTunnelSchema` / `policyActionSummaries` (~143-202 pattern):

```go
type apiPreset struct {
    Name        string   `json:"name"`        // sort key, unique
    Title       string   `json:"title"`
    Phase       string   `json:"phase"`       // on_http_request | on_http_response | on_tcp_connect
    Description string   `json:"description"`
    YAML        string   `json:"yaml"`        // the fragment, insertable as-is
    Notes       []string `json:"notes"`       // hint lines shown after insert
    Kind        string   `json:"kind"`        // "policy" (v1)
}
```

Sorted by name at table order; JSON encodes in slice order (byte-stable —
no map iteration anywhere in the payload).

### 2. Route — `server/admin.go`

`mux.HandleFunc("/api/presets", secureAPI(http.MethodGet, handleAPIPresets))`
in the ~358-361 block beside the other api routes. The handler is a
`json.Encode` of the table — the `/api/schema` handler's shape.

### 3. The nine (shapes verified against `policy/validate.go`, NOT the README)

1. `request-logging` — on_http_request `log` + `metadata`: the smallest
   valid document; teaches the phase/rule/config shape.
2. `ip-allowlist` — on_tcp_connect `restrict-ips`: `allow:
   ["10.0.0.0/24"]` + `enforce: true` (explicit for teaching; the accepted
   keys are exactly `enforce|allow|deny` — `ip_policies` is refused with
   "use allow/deny CIDRs", validate.go ~366-372).
3. `admin-path-deny` — on_http_request `deny`, `expressions:
   ['req.url.path.startsWith("/admin")']`, `status_code: 403`: CEL by
   example.
4. `basic-auth-gate` — `basic-auth` with `realm` + `credentials:
   ["alice:REPLACE_ME"]`.
5. `bearer-token-gate` — `bearer-auth` with `tokens: ["REPLACE_ME"]`.
6. `jwt-gate` — `jwt-validation`: `jwks_uri`/`issuer`/`audience`/
   `algorithms: [RS256]`/`leeway` (the README's jwt section carries the
   real shape; the validator is still the authority).
7. `oidc-protect` — `oidc`: `issuer`/`client_id`/
   `client_secret: REPLACE_ME` (notes must state it is refused on
   agent-TLS-terminated endpoints — registration refuses what it cannot
   enforce).
8. `webhook-verify` — `webhook-verification`: `provider: stripe`, secret
   `REPLACE_ME`.
9. `security-headers` — on_http_response `add-headers` (HSTS,
   X-Content-Type-Options): the only preset teaching that the response
   phase exists.

### 4. Pin test — `server/admin_api_test.go`

`TestPresetsAreValidPolicyDocuments`, per preset:
- (a) POST the preset's yaml through the REAL handler stack (the file's
  httptest helper idiom) to `/api/validate/policy` → 200 `valid: true`.
  This is the war-path pin — the same code the operator's insert hits.
- (b) The whole marshaled payload greps clean of `secret(` — the raw-scan
  422 trap, guarded at the source.
- (c) Parse the fragment: every phase key must be a key of the action
  matrix (the `PhaseActionMatrix`/summaries accessor) and every rule name
  must sit in that phase's action list — the analogue of the
  action-summaries pin (~583-613). An engine phase-move or rename fails
  the build here.
- (d) The fragment round-trips `/api/render` (kind=policy) → `valid: true`,
  non-empty output.

### 5. SPA — `assets/server/dashboard/app.js` (+ `style.css` classes)

A presets panel listing title + description; selecting one writes its yaml
into the ephemeral editor and renders its notes as hint lines. Every
dynamic node via textContent. Cached per visit like `schemaCache`. The
three-file static set is untouched (contents only).

### 6. e2e — `scripts/e2e_run.sh` (admin2 group, ~4259+ idioms)

- `GET /api/presets` → 200; array non-empty; names unique + sorted;
  `name`/`title`/`phase`/`yaml` non-empty; `kind == "policy"`.
- Per-preset live `POST /api/validate/policy` → 200 `valid: true` (the
  war-path pin, run live).
- Payload greps clean of `secret(`.
- `POST /api/presets` → 405; no-creds GET → 401 (mirrors the existing
  auth assertions).
- Cross-join: every preset `phase` is a `/api/schema` phases key and each
  fragment action name appears in that phase's action list — catches
  preset/schema divergence on the war path too.

## File ownership (workstreams)

- **A** — `server/admin_api.go` + `server/admin_api_test.go` (table,
  handler, pin test), `server/admin.go` (one route line),
  `assets/server/dashboard/app.js` + `style.css` (panel).
- **B** (after A) — `scripts/e2e_run.sh` (the scenarios above).

## Review gates

1. gofmt -l clean; go vet; `-race -tags debug` green; full e2e green.
2. The pin bites: mutate one preset's yaml to an invalid shape in a scratch
   copy, watch `TestPresetsAreValidPolicyDocuments` fail, revert. A pin
   that cannot fail is decoration.
3. No new `/static/` file; `innerHTML`/`localStorage` greps clean on the
   app.js diff; static set still exactly three.
4. `secureAPI` inheritance verified (405 on POST, 401 without creds,
   limiter + no-store + CSP ride).
5. CI green before tag.

## Release

Wave 2, second train (expected v1.0.25, after upstream_pool). CHANGELOG
names the payload surface and the pin — and states the principle this
cluster operationalizes: presets copy the validator, never the README.
