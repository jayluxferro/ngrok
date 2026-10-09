# Design specs

The binding contracts this fork's features were built against. Each spec is
written BEFORE implementation, reviewed, then handed to implementation
workstreams as the single source of truth for scope, semantics, file
ownership, and review gates. Once its release ships, a spec becomes a
historical record: the user-facing truth for what changed is the
[changelog](../CHANGELOG.md); the spec is the why-and-how for maintainers.

## How to read a spec

Every spec follows the same shape: objectives and non-goals first (what will
NOT be built is as binding as what will), then design, then **file
ownership** — exclusive sets per implementation workstream so parallel agents
cannot collide — then a testing strategy and numbered **review gates** the
architect checks before anything ships. Status lines at the top are the spec's
lifecycle: `draft` → `approved` → `shipped` (a shipped spec is not edited
retroactively; corrections ship as changelog entries and, where design-level,
as amendments at the bottom of the file).

## Index

Implementation clusters. Numbering is by spec file; releases land in
dependency order, which can differ from file order — spec 13 reuses the
client files spec 12 owns until v1.0.16 ships, so spec 14's oidc lands
between them. Releases
skipped below (1.0.6, 1.0.12, 1.0.13) were audit/hardening and toolchain
rounds with no feature spec — their record is the changelog.

| Spec | Feature | Release | Status |
|---|---|---|---|
| [01-header-control.md](01-header-control.md) | HTTP header manipulation (host rewrite, add/remove, X-Forwarded-*) — the Ollama 403 fix | v1.0.2 | shipped |
| [02-internal-endpoints-forward-compression.md](02-internal-endpoints-forward-compression.md) | `.internal` endpoints, `forward_to`, endpoint pooling, response compression | v1.0.3 | shipped |
| [03-smux-multiplexing-zero-copy.md](03-smux-multiplexing-zero-copy.md) | smux proxy multiplexing, zero-copy splicing, benchmark harness | v1.0.4 | shipped |
| [04-traffic-policy-engine.md](04-traffic-policy-engine.md) | Server-side traffic policy engine: CEL expressions, three phases, deny/custom-response/header/log actions, restrict-ips | v1.0.5 | shipped |
| [05-zero-knowledge-tls-fixed-ports.md](05-zero-knowledge-tls-fixed-ports.md) | Agent TLS termination (SNI-routed passthrough, three cert models), fixed remote TCP ports with ownership | v1.0.7 | shipped |
| [06-policy-auth-actions.md](06-policy-auth-actions.md) | basic-auth, bearer-auth, apikey-auth, jwt-validation (JWKS, fail-closed) | v1.0.8 | shipped |
| [07-quic-transport-buffer-pooling.md](07-quic-transport-buffer-pooling.md) | QUIC agent↔server carrier with smux fallback, rewriter buffer pooling, YAML parity (`traffic_policy_file`) | v1.0.9 | shipped |
| [08-udp-tunnels.md](08-udp-tunnels.md) | UDP tunnels: flow model, datagram framing, per-protocol port claims | v1.0.10 | shipped |
| [09-vaults-event-export.md](09-vaults-event-export.md) | Secret vaults (`secret()` at build time), event export destinations with drop accounting | v1.0.11 | shipped |
| [10-webhook-verification.md](10-webhook-verification.md) | webhook-verification policy action; the rewriter's bounded body buffering with deferred verdict | v1.0.15 | shipped |
| [11-wildcard-hostnames.md](11-wildcard-hostnames.md) | `*.<server-domain>` tunnels: one shared matcher, exact-wins routing | v1.0.14 | shipped |
| [12-h2-passthrough.md](12-h2-passthrough.md) | Opt-in `h2` ALPN on agent-terminated tunnels; the rewriter's HTTP/2 preface fail-open guard | v1.0.16 | shipped |
| [13-upstream-h2c.md](13-upstream-h2c.md) | Agent-side `upstream_protocol: http2` — h1↔h2c transcoder on the local leg | shipped | v1.0.18 |
| [14-oidc-identity.md](14-oidc-identity.md) | `oidc` policy action: PKCE authorization-code flow at the routing layer, signed-cookie sessions | v1.0.17 | shipped |
| [15-admin-web-ui.md](15-admin-web-ui.md) | ngrokd admin web UI: config workbench + observability SPA, `/api` validate/schema/render, snapshot enrichment | v1.0.19 | shipped |
| [16-telegram-ops-bot.md](16-telegram-ops-bot.md) | `ngrok-bot`: read-only Telegram commands + event alerts over the admin API | v1.0.20 | shipped |
| [17-carrier-dedup.md](17-carrier-dedup.md) | `carrier_dedup`: experimental per-stream CDC+Blake2b chunk dedup on the agent↔server carrier | v1.0.21 | shipped |
| [18-dedup-telemetry.md](18-dedup-telemetry.md) | carrier_dedup telemetry: per-tunnel + global counters, both wire directions, desyncs counted codec-honestly, v2 gate made evaluable | v1.0.23 | shipped |
| [19-upstream-connection-pooling.md](19-upstream-connection-pooling.md) | Opt-in `upstream_pool` for HTTP/HTTPS tunnels: parsed local leg over a shared per-address pool — the h1 twin of the cluster-17 transcoder; raw-socket reuse refused at the design level | draft | draft |
| [20-workbench-policy-presets.md](20-workbench-policy-presets.md) | Workbench policy presets: `GET /api/presets` + curated fragments pinned valid against the real validator — engine drift breaks the build, not the operator's insert | draft | draft |
| [21-workbench-snapshot-diffing.md](21-workbench-snapshot-diffing.md) | Workbench snapshot diffing: SPA-side added/removed/reconfigured/restarted classification of `/tunnels` polls, watched-field immutability pinned; zero Go changes | draft | draft |
| [22-vault-acls.md](22-vault-acls.md) | Per-tenant vault ACLs: `acl:` per vault, token-string principals via ownerOf, enforcement threaded through the single agent-document Compile, denial byte-identical to unknown-vault | draft | draft |

## Not specced here

- **v1.0.6 / v1.0.12** — the two adversarial audit rounds. Findings-to-fixes
  records live in the changelog entries; the audit method (fresh-eyes streams,
  severity-ranked findings, fix-down-to-minor) is described in each.
- **v1.0.13** — the toolchain bump and `cel.dev/cel-go` module migration; a
  dependency move with an explicit abort-condition brief, not a design surface.
- The upstream-parity evaluation that ordered all of this is
  [docs/NGROK_FEATURE_EVALUATION.md](../NGROK_FEATURE_EVALUATION.md).
