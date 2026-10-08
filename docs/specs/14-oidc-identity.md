# SPEC-CLUSTER18 — OIDC authentication action (`oidc`)

Status: approved (handed to workstreams P/S)

The first policy action whose verdict must survive three connections and two
external round trips. That is why it lives at the routing layer beside the
other pre-dispatch refusals (legacy HttpAuth, connectVerdict), not in the
per-request hook machinery the stateless actions share.

## Objectives

1. `on_http_request` gains an `oidc` action: visitors of an edge-terminated
   tunnel are redirected through an OIDC provider's authorization-code +
   PKCE flow and admitted only with a valid session cookie, with identity
   claims forwarded to the local service as headers.
2. Reuse, not re-solve: ID-token validation reuses the `jwt-validation`
   machinery (`policy/jwt.go` parser, `policy/jwks.go` cache with the whole
   v1.0.12 audited discipline — bounded bodies, no redirects, singleflight,
   refetch throttle, kty/alg cross-check); the token/discovery HTTP clients
   copy `jwks.go`'s bounds verbatim; constant-time compares reuse the
   credential-list discipline (`policy/auth_actions.go:99-106`).
3. No new module dependencies: `golang-jwt/v5` is already a direct require;
   PKCE (S256) and HMAC cookie signing are stdlib crypto. `coreos/go-oidc`
   is REJECTED — it would drag transitive dependencies to replace ~90%
   reusable local code whose fail-closed behavior this fork has already
   audited and pinned with tests.

## Non-goals (binding)

- **SAML: deferred, effectively dropped.** XML-DSig (exclusive
  canonicalization, signature-wrapping variants) with zero stdlib support;
  the credible libraries (`crewjam/saml`, `russellhaering/goxmldsig`) are
  new heavy dependencies with CVE history in exactly this parsing. This
  fork's security identity is the opposite trade. Revival bar: a written
  request from a deployment whose IdP cannot front OIDC, plus a library
  choice with its own audit — its own spec cluster, never bundled here.
- **No generic OAuth2** (GitHub is not OIDC — it needs nonstandard
  `/user/emails`; that is the 67-provider long tail, a future preset
  cluster if ever).
- **No preset aliases in v1** (google/entra/okta/auth0 issuer templates —
  Entra's `{tenant-id}` templating is real surface; pasting an issuer URL
  is one line an operator does once).
- **No logout endpoint, no server-side revocation.** Logout is cookie
  expiry; a server that needs to kill all sessions restarts with a random
  key (or rotates the configured one). Stated, not apologized for.
- **No agent-side OIDC.** The edge cannot run the flow on zero-knowledge
  tunnels (no plaintext means no Host, no cookie, nothing to 302 from) —
  refused at registration, below. Agent-side OIDC (the agent compiles and
  runs the identical policy package) is a feasible future fork-unique
  cluster with its own spec for agent-held secrets and per-agent sessions.
- **No per-request re-check after dispatch.** The first request on each
  connection decides (the same granularity Host routing and legacy HttpAuth
  have); keep-alive requests on a dispatched connection ride the session
  established at its head.

## Design

### 1. Enforcement point: pre-dispatch in `routeHTTP`

After `Match(proto, host)` succeeds and before `HandlePublicConnection`
pulls a proxy stream (server/http.go:644, the seam where HttpAuth and
connectVerdict already intercept — server/http.go:675-679, :709-713). The
hook layer is wrong for this action on three counts the recon verified: a
proxy stream would be burned per unauthenticated visit and per callback
(server/tunnel.go:924, join at :977); `emitSynthetic` ends the connection
after its response (rewriter/rewriter.go:2283) so hook enforcement buys
nothing for a redirect; and the callback needs routing-layer interception,
which the rewriter cannot do.

In the rewriter hook the `oidc` action is skipped — consumed pre-dispatch.
Other request-phase actions in the same policy evaluate in the hook as
always, on the authenticated connection, in document order.

**The callback path is reserved**: requests whose path equals
`callback_path` (default `/oauth2/callback`) never reach the local service.
Stated in the config error when a policy both carries `oidc` and the
operator's traffic obviously lives on that path — no, v1 simply reserves it
and documents it.

### 2. The flow

**First request, no/invalid session cookie** → synthetic `302` to the
discovered authorization endpoint with `client_id`,
`redirect_uri = scheme://<request-host><callback_path>`, `scope`, `state`,
`nonce`, `code_challenge` (S256) + `method`; plus ONE signed flow cookie
(10-minute TTL, `Path=callback_path`, HttpOnly, SameSite=Lax) binding
`{state, nonce, original URL, request host}` under the session key.

**Callback** (`path == callback_path`) → verify flow-cookie signature, compare
`state` constant-time, verify the cookie's bound host equals the request
host (a code obtained for one host must not be redeemable on another);
exchange `code` + verifier at the token endpoint (bounded client, one POST,
non-200 refused); validate the ID token through the `jwt.go` parser
(asymmetric-only allowlist, `exp` required, `iss` = configured issuer,
`aud` = client_id, kid via the JWKS cache) plus a `nonce` exact-match
post-signature; check `allowed_domains` (email domain / `hd` claim) and
`claims` (exact-match map, the jwt-validation loop); mint the session
cookie; `302` to the bound original URL.

**Valid session** → inject identity headers into the replayed head —
`X-Forwarded-User` (`sub`), `X-Forwarded-Email`, and
`X-Forwarded-Preferred-Username`, each present only when the token carries
the claim — and dispatch.

**Failure is fail-closed and fixed-shaped.** Discovery unreachable or
refused, token exchange failed, signature/state/nonce wrong,
`allowed_domains` miss: a fixed synthetic response per class (503 for IdP
unreachability, 403 for verification failures), built at compile where
possible, never echoing anything request- or token-derived. IdP
unreachability is logged once per connection (the JWKS failure-logging
discipline).

### 3. Config surface

```yaml
traffic_policy:
  on_http_request:
    - name: oidc
      config:
        issuer: https://accounts.google.com   # https, loopback-exempt for tests
        client_id: "....apps.googleusercontent.com"
        client_secret: secret("main/google")  # vault-composable; inline allowed
        scopes: [openid, email]               # default shown; profile optional
        callback_path: /oauth2/callback       # default shown
        session_duration_seconds: 3600        # default shown; hard ceiling 86400
        allowed_domains: [example.com]        # optional post-verification check
        claims: { hd: example.com }           # optional exact-match, jwt-validation shape
```

Validation at load (both sides, the standard path): issuer is a URL
(https, loopback-exempt — `checkJWKSURI`'s exact rule, policy/jwt.go:351-366);
`client_id` non-empty; `client_secret` non-empty and CR/LF-free; scopes ⊆
non-empty tokens with `openid` forced first if absent (an operator may drop
`email`/`profile`, never `openid`); `callback_path` starts with `/`, carries
no `?`/`#`, no CR/LF; duration in (0, 86400].

**The plaintext-secret divergence, stated plainly.** The static actions
reduce credentials to digests at load so compiled policies hold no
plaintext; the OIDC token exchange needs the secret at runtime, so it
cannot. It resolves through the existing `resolveCredential` seam
(policy/vault.go:311-327) — the *reference* travels the registration wire,
never the plaintext (`TestVaultBothSidesResolveIdentically` pins the
property), and the server re-resolves against its own vaults at
registration (server/tunnel.go:296-303). It never reaches a log line,
error string, or verdict — the `jwt.go` discipline (:30-34, :223-227).

**Wire redaction gap this cluster must close.** `client_secret` is a
*string* policy field, so it serializes into `ReqTunnel.TrafficPolicy`
outside the credential-*array* redaction (`msg/conn.go`
`policyCredentialFieldNames`). A `"client_secret"` entry joins the
string-field redaction (`redactStringField`, beside `"Secret"` and
`"HttpAuth"`) — or the DEBUG wire log becomes a credential store, the exact
class the webhook e2e sentinel caught in 1.0.15. A sentinel test asserts it.

### 4. Session store: signed cookies, no server state

The session cookie is HMAC-SHA256 over `{exp, sub, email,
preferred_username, mint-nonce}` under a server-side key — not encrypted:
the identity claims are the visitor's own and visible to them; the ID token
itself is never in the cookie. TTL = `session_duration_seconds` (claim
inside the blob). No in-memory session map: it would break silently on
restart and under any load balancer, and needs eviction policy this
codebase has no precedent for.

**The key.** New optional server config `oidc_session_key`. Unset (default):
a random key generated at startup — zero config, sessions invalidate on
restart (visitors re-authenticate; logged once at INFO). Set: sessions
survive restarts, and operators fronting multiple ngrokds with one hostname
share the key to keep sessions valid across nodes.

### 5. Registration refusal for zero-knowledge tunnels

`oidc` in the compiled policy plus `TLSTermination: agent` fails `NewTunnel`
before the URL is claimed, on the precedent of
`TestNewTunnelRefusesAPolicyItCannotEnforce` (server/policy_test.go:728) —
an endpoint that looks protected and cannot be is not a state this fork
ships. The refusal names both facts.

## File ownership (exclusive)

- **Workstream P (policy)**: `policy/oidc.go` (new — action compile,
  discovery/token clients, PKCE, cookie mint/verify, the Decide/Callback
  API), `policy/oidc_test.go` (httptest fake IdP: discovery + JWKS +
  authorization + token endpoints; the whole flow, every failure class),
  `policy/validate.go` (registry row: `oidc`, request phase only),
  `policy/policy.go` (only if `Compiled` needs the accessor S consumes),
  `msg/conn.go` + `msg/conn_test.go` (client_secret string-field redaction).
- **Workstream S (server)**: `server/http.go` (pre-dispatch branch; renders
  verdicts via the existing synthetic-response path), `server/tunnel.go`
  (registration refusal), `server/main.go` (read + install
  `oidc_session_key` via a `SetOIDCSessionKey` once-at-startup setter, the
  `SetVaults` precedent), plus the server-side tests for each.
- **Architect (after review)**: e2e fake-IdP scenario group, CHANGELOG,
  version bump, README, spec/index updates, commit/tag/push/CI watch.

**The seam (contract both sides build against):** S hands P the parsed
first-request fields (method, path, query, Cookie header) plus scheme and
request host; P returns exactly one verdict — dispatch-with-injected-headers
/ synthetic-302-with-cookies / synthetic-403 / synthetic-503 / close — and
owns all crypto and all HTTP toward the IdP. S owns rendering and dispatch
and never touches the IdP.

## Testing strategy

- **P**: full happy path against the httptest IdP (302 → callback → mint →
  replay with cookie → inject); state tamper/replay (constant-time path
  exercised); nonce mismatch; cross-host callback refused; PKCE verifier
  uniquely bound per flow; expired flow cookie; discovery poison (wrong
  issuer in doc → refuse); token endpoint non-200; `allowed_domains` and
  `claims` misses; session cookie forgery (wrong key), expiry, ceiling
  clamp at 86400; redaction sentinel (client_secret `<redacted>` in the
  serialized policy).
- **S**: pre-dispatch ordering (no proxy stream spent on a 302 — assert via
  the connection counters); registration refusal message; `oidc_session_key`
  unset → random key INFO log; hook skips the consumed action.
- **E2E (architect)**: a Go fake-IdP helper the harness starts (discovery,
  JWKS, authorize → 302 back with a code, token → signed ID token), driven
  by `curl` with a cookie jar through a live tunnel: the complete
  three-connection loop in bash. Fallback if too brittle: keep the loop at
  P's httptest level and e2e only the redirect-no-cookie and
  registration-refusal shapes.

## Review gates

1. Fail-closed everywhere: every IdP failure class answers a fixed
   synthetic and never passes; nothing request- or token-derived reaches a
   response body or log line.
2. `client_secret` redaction proven by sentinel test; plaintext in no
   compiled-policy debug dump.
3. Zero-knowledge refusal message names both the action and the termination
   mode.
4. Session cookie is HMAC-verified on every first-request, TTL-bounded,
   ≤ 24 h; the ID token never crosses into a cookie or header.
5. No new module requirements; `go.mod`/`go.sum` unchanged.
6. Full gates (`-tags debug -race ./...`), e2e group green, spec status
   flip, index row, changelog entry stating the no-revocation and
   restart-invalidates-sessions behaviors.
