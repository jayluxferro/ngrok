# SPEC-CLUSTER9: Vaults/secrets + event export

Status: spec ready; implementation gated on cluster 8 (shared files: client/config.go,
policy/*, server/observability-adjacent). Standing directive covers it.
Pre-authorized by SPEC-CLUSTER6 §2 ("credentials are inline config values for now; vault
refs come cluster 9") and the eval doc's "fork can add file/env sources ngrok lacks".

## 1. Objectives

1. **Vaults**: policy credentials (basic-auth/bearer/apikey entries) resolvable from a
   file-backed vault instead of inline YAML — resolved ONCE at config build, transported
   as digests only, never in CEL, never per-request.
2. **Event export**: the server's existing event stream shipped to external destinations
   (http POST with batching, jsonl file append), with observable drop accounting.

## 2. Non-goals

- No server-side encryption-at-rest, KMS, or dynamic secrets (file/env sources are the
  self-hosting win; commercial parity does not require more).
- No `secret()` as a CEL function — recon confirms resolution belongs at build time
  (per-request CEL reads would put vaults on the data path and secrets in interpolation
  output). The `secret("...")` syntax appears ONLY in config value positions.
- No new client-side event bus (client events stay in the mvc views).
- No new event types beyond `connection_open` — the six existing + that one cover the
  lifecycle; more can follow without design change.

## 3. Vaults design (per recon anchors)

### 3.1 Syntax and resolution point

- Any string credential value in an auth action's config may be `secret("vault/key")`.
- Resolution happens between `credentialList` (policy/auth_actions.go:330) and `digestsOf`
  (:382), inside the build*Auth constructors — load-time, loud failure naming the vault
  and key ("vault \"main\" has no key \"prod-api\""), per the package's stated contract.
- The SAME resolution runs client-side (config load, where the doc is validated today at
  client/config.go:856-890) and server-side (Compile at server/tunnel.go:269-278) — both
  sides already validate; both must resolve identically.

### 3.2 Vault sources (the fork's differentiation)

- Client `vaults:` block on Configuration (non-strict YAML, client/config.go:23-34):
  ```yaml
  vaults:
    main:
      file: /etc/ngrok/vault.yml      # key: value pairs, values may be sha256:<hex>
      # or
      env_prefix: NGROK_VAULT_MAIN_   # NGROK_VAULT_MAIN_PROD_API=<value>
  ```
- Server `vaults:` on strict serverConfig (server/config.go:17-37) — same shapes, strict
  decode, for server-originating policies later; the key lands now so both sides speak it.
- Vault file entries may themselves be `sha256:<hex>` pre-digested values (mirrors
  auth_tokens storage, server/auth.go:12-25 dual form): a deployment can keep ONLY
  digests on disk and never hold plaintext at all.

### 3.3 Wire and heap hygiene

- After resolution, everything downstream is exactly today's pipeline: digestsOf →
  constant-time list compare → 401s from static strings. A vault-sourced credential is
  indistinguishable from an inline one post-build.
- Client→server ReqTunnel carries the policy; because inline plaintext credentials
  already cross inside TLS, v1 transports the document as-is BUT: vault `env:`-sourced
  entries are resolved client-side before send, and the redaction gap is closed —
  `redactSecrets` (msg/conn.go:122-187) additionally rewrites the credential-bearing
  fields (`credentials`, `tokens`, `keys`) of serialized policies, so wire DEBUG logs
  never show them regardless of source.

### 3.4 Tests

- Resolution table: file vault, env vault, missing vault, missing key (error names both),
  pre-digested entry round-trip, mixed inline+vault list, CR/LF refusal applies post-
  resolution, no double-resolution (`secret()` inside a resolved value = literal).
- Both-sides equivalence: same doc + same vault resolves identically client and server.
- Wire: debug-serialized ReqTunnel shows no credential values from any source.

## 4. Event export design

### 4.1 New event type + hub change

- `connection_open` (symmetric with onConnClose; observability.go:260-267 currently only
  bumps counters) — client addr, tunnel url, proto.
- `eventHub.publish` gains an atomic dropped-event counter per subscriber... per the
  recon: keep the drop-on-full select/default idiom, ADD `atomic.Uint64` drops surfaced
  in /metrics payload and the metricsPoint sampler (admin.go:155-166 style).

### 4.2 Destinations (config: strict server keys)

```yaml
event_destinations:
  - type: http
    url: https://collector.example/ngrok
    auth_header: "Authorization: Bearer <token>"   # literal or secret("vault/...") — vaults compose
    batch_size: 100
    flush_interval: 5s
  - type: jsonl
    path: /var/log/ngrok/events.jsonl
```
- Both destinations: one bounded queue (cap 1000, the KeenIoMetrics precedent,
  server/metrics.go:182) + one drain goroutine; http copies the Keen.io batch/ticker/
  AuthedRequest shape (metrics.go:177-257); jsonl appends one pre-marshaled line per
  event (payload comes from the same marshal publish already does).
- Backpressure: drop-on-full with the counter; a permanently failing destination backs
  off (existing retry conventions), logs one sampled line per state change, never blocks
  the hub (publish stays non-blocking).
- `auth_header` values support `secret("vault/...")` — resolved at load from the server's
  vaults, digested... NO: an auth header needs plaintext at flush time. Exception to the
  digest rule, documented: header values are resolved to plaintext at load, held in
  memory only, never logged (add to the redaction set by field name).

### 4.3 Tests

- Hub: connection_open emitted on open; drop counter increments when a subscriber stalls
  and stops when it drains.
- http destination: httptest server asserts batch shape, auth header, retry/backoff on
  500, drop accounting when the collector is slow.
- jsonl destination: append + reopen resilience (file recreated), line = valid JSON with
  the eventHeader shape.
- Config: strict decode accepts the destination list; unknown type refused loudly;
  secret() in auth_header resolves from the server vault.

## 5. File ownership

- **A (vaults)**: policy/auth_actions.go (resolution seam), policy/vault.go (new: source
  loading, file/env), policy tests; client/config.go (vaults block + client-side
  resolution wiring), msg/conn.go (redaction extension) + tests.
- **B (events)**: server/observability.go (connection_open + drop counters), server/
  events_export.go (new: destinations), server/config.go + cli.go (config keys),
  server/admin.go (counter surfacing), server tests.
- **C (after A+B)**: scripts/e2e.sh (vault scenario: env-source a basic-auth credential;
  jsonl destination scenario grepping events for tunnel_open), docs/CHANGELOG.md 1.0.11,
  README, version/version.go Patch "11".

## 6. Review gates

1. Full build/vet/test -race green; e2e green incl. all prior groups.
2. No plaintext credential in any serialized wire DEBUG output (test pins it).
3. Resolution failures are load-time and name vault+key; no silent fallback to inline.
4. Publish path stays non-blocking under a stalled destination (test with -race).
5. Drop counters observable in /metrics; destinations never block the hub.
6. Existing behavior byte-identical with no vaults/destinations configured.
