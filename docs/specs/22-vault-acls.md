# SPEC-CLUSTER28 — per-tenant vault ACLs: who may resolve whose secrets

The security audit's vault-scoping finding (docs/⟨URL_39·e7ec6314⟩, vault
section): vault scoping is server-wide — any authenticated token may
reference any vault entry, and an operator who binds a vault secret into an
endpoint they control can probe it at that endpoint's request rate. The
oracle is two-step: resolve-anyone (the reference) plus a digest-compare
endpoint (the probe). This cluster closes step 1: each vault may declare
which tenants — which authenticated tokens — may resolve into it. Step 2
survives for entries a tenant IS allowed to reference; that residual is
inherent to digest-compare endpoints and is documented, not hidden.

The design invents nothing: the identity already exists (the validated
auth-token string, via `ownerOf`), the enforcement point already exists
(the server compiles an agent document in exactly one place, and the
owner is in hand there), and the refusal vocabulary already exists (the
de-enumerated unknown-vault error). Per-key ACLs are refused as a design
matter: a vault is already the trust unit the operator names, and per-key
lists multiply config surface while adding an inventory side-channel for
zero additional honesty.

## Objectives

1. `acl:` on a vault source: the list of owners (auth tokens, plaintext or
   `sha256:` digest form — the same two spellings tokenMatches accepts)
   that may resolve that vault's entries from an AGENT-SUBMITTED document.
2. Enforcement at the single server-side Compile, threaded down the
   existing build traversal — compiler-enforced at every resolution seam,
   so a future agent-facing compile cannot forget the owner silently.
3. Denial is byte-identical to the unknown-vault error: ACL membership is
   not guessable.
4. Unset `acl:` is exactly today's behavior — no forced migration.
5. Loud operator-side startup checks; the client refuses `acl:` loudly
   (it is a server-side concept).

## Non-goals (binding)

- NO per-key ACLs (rationale above).
- NO per-resolution audit log of which owner resolved what — provenance is
  deliberately dropped after digesting (vault/key names exist only for
  load-error text); an access log of secret references is itself a
  disclosure surface.
- NO vault rotation or reload: no config-reload path exists anywhere in
  server/ or client/ (verified); vaults and ACLs are set once at startup,
  restart to change. Rotation is out of scope by reality, not by deferral.
- NO account objects beyond the token-string identity; NO per-tenant
  encryption at rest.
- Admin API unchanged and fail-closed: `/api/validate/policy` and
  `/api/render` keep 422-refusing any document containing `secret(` — no
  vault resolution happens there today, none will.
- Client-side vaults stay out: the agent's vaults are the local user's
  own process-global set; the same document already resolves against
  different sets on each side BY DESIGN. The client's only change is the
  loud refusal of `acl:` in its own config.
- NOT closing the allowed-tenant endpoint-rate oracle (the audit's step
  2) — that boundary is per-entry policy, a different mechanism; recorded
  as residual.
- NOT the adjacent pre-existing finding that `server/metrics.go` ships
  the raw auth token as `User` to the metrics sink — parked as its own
  future unit; recorded here so it is not lost.

## Design

### 1. Identity — the auth token string, via ownerOf

The client sends its token as ⟨URL_40·e7ec6314⟩er (client/model.go ~554);
the server validates constant-time against authTokens (server/control.go
~148-163; dual sha256: form, server/auth.go ~17-25). `ownerOf`
(server/control.go ~103-117) returns the trimmed ⟨URL_40·e7ec6314⟩er when
tokens are configured, else "default" (server/registry.go ~25-27). Tunnel
captures it at construction: `owner: ownerOf(ctl)` (server/tunnel.go
~289). Cross-owner refusal precedent: the pooling bucket join
(server/registry.go ~251-253), wording reused for cross-owner wildcards.

Operational caveat, stated in the config comment and CHANGELOG: identity
is exactly as stable as the server's token config. Rotating a token
rotates the owner name; ACL entries naming the old token must change in
the same config edit or the next registration is refused (loudly, at the
ACL check — fail-loud at resolution is the design).

### 2. Data model — vault-level ACL on the shared decode type

```yaml
# server configuration only
vaults:
  main:
    file: /etc/ngrok/vault.yml
    acl:                    # owners that may resolve into this vault
      - tenant-a            # exact token as the client sends it
      - sha256:9f2c…        # or digest form, same spelling tokenMatches accepts
  shared:
    env_prefix: NGROK_VAULT_SHARED_
    # no acl: => any authenticated token (today's behavior, byte-for-byte)
```

`ACL []string \`yaml:"acl,omitempty"\`` on `VaultSource`
(policy/vault.go ~63-78 — the one type both sides decode; the server
decodes it under strict decode). VaultSource is shared, so `acl:`
becomes DECODABLE client-side — the client's vault loader refuses it
loudly ("acl is a server-side concept; client vaults are your own
configuration") rather than silently ignoring dead config
(client/config.go ~1725-1731 install site).

### 3. Enforcement — one choke point, threaded

The server compiles an agent document in exactly one place:
`NewTunnel` → `m.TrafficPolicy.Compile()` (server/tunnel.go ~302, wrapped
"invalid traffic policy:", refused before the url is claimed) — where
`t.owner` already exists (~289). That call passes the owner; every other
Compile caller passes nil.

The owner threads down the existing single traversal as a parameter
named `agentOwner` — build (policy/validate.go ~152) → buildPhase →
action dispatch (~437-446) → every resolution seam: `credentialList`
(policy/auth_actions.go ~354, its resolveCredential call ~376; used by
basic ~160, bearer ~215, apikey ~298), oidc client_secret
(policy/oidc.go ~533), webhook secrets (policy/webhook.go ~463 via
ResolveSecretRef), and ResolveSecretRef (policy/vault.go ~412).
`resolveCredential` (policy/vault.go ~327) is where the ACL is checked.

`agentOwner == nil` means process-own configuration, unrestricted: the
client's validate/compile (client/config.go ~1546, client/model.go
~1562), the server's own event-destination auth_header
(server/events_export.go ~245-259, resolved at construction), and tests.
The parameter is mandatory at the seam functions — an unscoped call site
cannot be written; the single production owner-passing call site is
e2e-pinned.

Why a parameter and not a process-global: the vault SET is load-once
global by design (policy/vault.go ~28-33 says why), but identity is
per-registration and registrations are concurrent — a global would race
two tenants mid-Compile. The load-once comment's own logic forces the
parameter.

### 4. Denial semantics and timing

An ACL-denied resolution returns the byte-identical unknown-vault error,
`no vault named %q is configured` (policy/vault.go ~343). This is
load-bearing: the de-enumeration discipline (~391-402 comment; the
audit's vault section) exists precisely because these errors travel back
to the submitting agent. Denied == nonexistent, always — ACL membership
must not be guessable from the refusal.

Timing: ACL comparison reuses `tokenMatches` (constant-time,
sha256:-aware) per entry and folds with OR across entries — no
early-exit, or entry position leaks through latency.

### 5. Startup loudness — operator-side, back-compat preserved

Unset `acl:` is exactly today's behavior; existing single-tenant configs
start unchanged. Loudness moves to load time (loadServerVaults,
server/vaults_config.go ~29-36 — the token list is already parsed by
then, cli.go ~177-184):

- A vault WITH `acl:` on a server with NO -authToken: refuse to start
  unless the acl is exactly `["default"]` (ownerOf maps everyone to
  "default"; anything else is dead config — loud in the operator's own
  file, zero wire leak).
- An acl entry that is a malformed `sha256:` form: refuse at load (reuse
  the existing digest check, policy/vault.go ~243).
- A multi-token server with an ACL-less vault: WARN at startup —
  "every authenticated token may resolve its entries." Visible, not
  fatal (back-compat).

### 6. Wire and log discipline (verified, not assumed)

DEBUG wire logs already redact by field name across both directions —
"Secret", "HttpAuth", oidc "client_secret" (msg/conn.go ~88-92) and the
policy credential lists "credentials"/"tokens"/"keys"/"secrets"
(msg/conn.go ~116-124), which is where vault reference text travels; only
the Ref crosses the wire, never the value. The ACL refusal is a
registration error on the existing channel, carrying the unknown-vault
wording only — no new wire surface.

### 7. e2e — `scripts/⟨URL_8·e7ec6314⟩` vault group (multi-token harness precedent ~:1126)

1. Two tenants, own-read works: `-authToken=tenant-a,tenant-b`; vault
   `main` acl `[tenant-a]`; tenant-a registers basic-auth with
   `secret("main/api")` → registers; endpoint 200 with right creds /
   401 without.
2. Cross-read refused: tenant-b submits the same doc → registration
   refused with the unknown-vault wording.
3. No-oracle pin: tenant-b's refusal for the acl'd "main" is
   byte-identical to the refusal for a misspelled vault — same document,
   one byte changed.
4. Back-compat: an ACL-less vault on the same multi-token server
   resolves for BOTH tenants (pins current behavior).
5. Digest deployment: -authToken stored `sha256:`; acl entry also
   `sha256:`; tenant resolves.
6. Server-own path ignores ACL: event destination auth_header
   `secret("main/api")` still resolves at construction (operator use,
   not agent).
7. Seam coverage: agent docs with webhook secrets / oidc client_secret
   against an acl-denied vault refused through those seams too; admin
   API still 422s secret( docs.
8. No-token server: acl `[default]` works; acl `[someone]` refuses
   server startup naming the vault.
9. Redaction sentinel: refused registrations still redact credential
   lists in both DEBUG wire logs (existing sentinel pattern).

## File ownership (workstreams)

- **A** — `policy/vault.go` (ACL field, resolveCredential check,
  constant-time fold), `policy/validate.go`, `policy/auth_actions.go`,
  `policy/oidc.go`, `policy/webhook.go` (agentOwner threading), per-seam
  tests in the matching _test files.
- **B** (after A; also after cluster 23 — both touch server/tunnel.go)
  — `server/tunnel.go` (the one call site: pass t.owner into Compile),
  `server/vaults_config.go` (startup loudness + tests),
  `client/config.go` (acl refusal + test), `docs/⟨URL_39·e7ec6314⟩` NOT
  edited (audits are point-in-time records; the changelog + a spec-09
  bottom amendment carry the closure).
- **C** (after B) — `scripts/⟨URL_8·e7ec6314⟩` (the nine scenarios),
  `docs/CHANGELOG.md`, spec-09 bottom amendment, `docs/specs/README.md`
  status flip.

## Testing strategy

Per-seam denial tests (one per builder: basic/bearer/apikey/oidc/webhook
+ generic ResolveSecretRef); the nil-scope paths pinned (client validate
resolves; event auth_header resolves — existing tests stay green
unchanged); startup-loudness unit tests (the three rules); the
byte-identical denial pinned in unit AND e2e; `-race` with concurrent
multi-tenant registrations (the reason threading exists).

## Review gates

1. gofmt -l clean; go vet; full `-race -tags debug` sweep green.
2. Threading completeness: `grep` shows every resolveCredential/
   ResolveSecretRef call path carries agentOwner (nil or owner) — the
   compiler proves the rest; zero unscoped agent-facing call sites.
3. No-oracle pin green (scenario 3) — byte-identical refusals.
4. Constant-time fold: no early-exit across entries (code review + a
   reorder-invariance test).
5. Back-compat pinned (scenario 4) and startup loudness pinned (unit).
6. Full e2e suite green; CI green before tag.

## Release

Wave 3, second train (expected v1.0.27). CHANGELOG states the operational
cost honestly: tokens-are-identity means rotating a token rotates the
owner name — ACL entries move in the same config edit; and names the
documented residual: an allowed tenant can still probe entries they are
allowed to reference at their own endpoint's rate.
