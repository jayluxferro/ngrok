# SPEC-CLUSTER6: Traffic-policy authentication actions

Status: approved (user: "add different header authentication supports etc, apikey, bearer etc all").
Scope: the server-side policy engine (policy/ package) — four new on_http_request
actions. Because the engine evaluates on both sides (server for edge tunnels, agent
for agent-terminated tunnels, per SPEC-CLUSTER5), all four work everywhere automatically.

## 1. Objectives

Stateless request authentication as traffic-policy actions, evaluated per request head,
terminating unauthenticated requests with a proper 401 challenge:

1. `basic-auth` — HTTP Basic (ngrok parity: their `basic-auth` action).
2. `bearer-auth` — static bearer tokens in `Authorization: Bearer <token>`.
3. `apikey-auth` — static API keys in a configurable header.
4. `jwt-validation` — JWT signature/claims validation against a JWKS (ngrok parity).

Commercial ngrok has basic-auth and jwt-validation; apikey/bearer are the fork's
additions the user asked for by name.

## 2. Non-goals

- No oauth/oidc/saml (they need session stores and provider round-trips — a later cluster).
- No vault `secret()` references in policy YAML (cluster 9); credentials are inline
  config values for now, and the changelog says so plainly.
- No OR-composition of auth actions: actions run in declared order and the first
  failure terminates (existing engine semantics, documented).
- No response-phase or tcp-phase variants: request-phase only (an authenticated TCP
  stream has no headers to read).

## 3. Config shapes (all flat, engine conventions: name + expressions + config)

```yaml
on_http_request:
  - name: basic-auth
    config:
      realm: restricted          # default "ngrok"
      credentials:               # "user:password" entries; several allowed
        - alice:secret
  - name: apikey-auth
    config:
      header: X-Api-Key          # default; case-insensitive lookup
      keys:
        - "ak-live-0001"
  - name: bearer-auth
    config:
      tokens:
        - "tok_abcdef"
  - name: jwt-validation
    config:
      jwks_uri: https://idp.example/.well-known/jwks.json
      issuer: https://idp.example
      audience: my-endpoint
      algorithms: [RS256]        # default RS256; allowlist enforced
      leeway_seconds: 30         # exp/nbf clock skew, default 0
      claims:                    # optional exact-match required claims
        scope: tunnels:read
```

## 4. Semantics

- **Execution point**: the existing request-hook verdict machinery (the same path
  `deny` and `custom-response` take). On failure the action terminates the request
  with a synthetic 401; on success it is a no-op and later actions/run rules proceed.
- **401 shape** (fail-loud, standards-correct):
  - basic-auth: `401` + `WWW-Authenticate: Basic realm="<realm>"`.
  - bearer-auth: `401` + `WWW-Authenticate: Bearer`.
  - jwt-validation: `401` + `WWW-Authenticate: Bearer error="invalid_token"`.
  - apikey-auth: `401` (no challenge header — there is no standard challenge for
    custom API-key headers; body names the missing header).
  - Body text names what failed without echoing any credential material.
- **Basic parsing**: accept RFC 7617 only; base64 decode failures and missing colon
  are plain failures (401), never 400 — the challenge is the answer.
- **Bearer parsing**: exactly `Bearer <token>` (case-insensitive scheme), one space,
  non-empty token; anything else 401s.
- **Constant-time**: every credential comparison uses crypto/subtle (ConstantTimeCompare
  over digests, or the fixed-length pattern the codebase already uses for session
  secrets — read server/auth.go and mirror it). Iterate ALL credentials, short-circuit
  nothing.
- **JWKS**:
  - Fetch with a bounded client (10s timeout), cache keys by kid in memory; refetch
    once on an unknown kid (key rotation), then fail. Bound the cache (e.g. 32 keys)
    and the JWKS body (1 MiB).
  - Signature: github.com/golang-jwt/jwt/v5 (new dependency; `go get` it, pin in
    go.mod like cel-go was). Enforce the algorithm allowlist against BOTH the policy
    config AND the JWT header alg — "none" is refused outright, and alg/key-type
    confusion (e.g. an HS alg when the JWKS key is RSA) is refused by construction
    (validate via the parsed JWK's key type).
  - Registered claims: exp/nbf honored with leeway; iss/aud required to match when
    configured (audience via jwt's audience validation); `claims` entries are
    exact string equality on public claims.
- **Validation (config load, fail loudly)**: empty credentials/keys/tokens lists
  refused; basic entries must contain a colon (empty user or password allowed);
  CR/LF in any credential or realm refused (header injection); apikey header must be
  a valid header name; jwt requires jwks_uri (http/https URL) and a non-empty
  algorithm allowlist drawn from {RS256,RS384,RS512,ES256,ES384,ES512,EdDSA};
  unknown keys in any config refused (existing strict-decode house rule).
- **Logging**: action log lines name the action and the outcome (401 issued), never
  a credential, token, key, or JWT. The wire/debug logger already redacts; keep
  credentials out of the verdict objects' string forms too.

## 5. File ownership

- **Agent A (single agent)**: policy/auth_actions.go (basic/bearer/apikey),
  policy/jwt.go + policy/jwks.go, the action-registry/validator extensions
  (policy/validate.go, policy/policy.go wherever the existing actions register),
  go.mod/go.sum, and tests: policy/auth_actions_test.go, policy/jwt_test.go,
  policy/jwks_test.go. Read policy/policy.go + policy/validate.go FIRST and extend
  the existing data-driven action table — no new dispatch mechanisms.
- **Agent C (after A)**: scripts/e2e.sh (new auth scenario group), docs/CHANGELOG.md
  (1.0.8), README docs section, version/version.go Patch "8".

## 6. Testing strategy

- Action validators: table tests per §4 validation rules, errors naming the field.
- Executor tests through the existing request-hook harness (the pattern in
  server/policy_test.go): missing Authorization → 401 + exact WWW-Authenticate;
  wrong credential → 401; correct credential → request passes to upstream.
  Multiple credentials; apikey custom header case-insensitivity.
- JWT: httptest JWKS server + locally generated RSA/ECDSA keys (generate in-test):
  valid token passes; expired (with/without leeway); wrong issuer/audience; alg
  "none"; RS-key token signed HS (confusion); unknown kid triggers refetch then
  succeeds (rotation); JWKS server down → 401 (fail closed, not open) with the
  fetch failure logged once.
- Both-side check: one test running an auth action through the agent-side hook path
  (cluster 5's client-side evaluation) proves the actions travel with the policy.
- e2e (C): basic-auth with curl -u (401 then 200), bearer + apikey round-trips, jwt
  against a local JWKS python server, and one combined policy (auth + deny rule).

## 7. Review gates

1. `go build/vet/test -tags debug ./... -race` green.
2. All four actions in the existing action table — data-driven, no if-chains.
3. Constant-time comparisons verified by reading, not by timing tests.
4. JWKS failure modes fail CLOSED.
5. No credential material in any log line or error string.
6. Existing actions' behavior byte-identical (existing policy tests untouched).
