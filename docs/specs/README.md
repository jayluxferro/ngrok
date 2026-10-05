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

Implementation clusters, in build order. Numbering is by spec file; releases
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
| [10-webhook-verification.md](10-webhook-verification.md) | webhook-verification policy action; the rewriter's bounded body buffering with deferred verdict | — | approved, implementation next |
| [11-wildcard-hostnames.md](11-wildcard-hostnames.md) | `*.<server-domain>` tunnels: one shared matcher, exact-wins routing | v1.0.14 | shipped |

## Not specced here

- **v1.0.6 / v1.0.12** — the two adversarial audit rounds. Findings-to-fixes
  records live in the changelog entries; the audit method (fresh-eyes streams,
  severity-ranked findings, fix-down-to-minor) is described in each.
- **v1.0.13** — the toolchain bump and `cel.dev/cel-go` module migration; a
  dependency move with an explicit abort-condition brief, not a design surface.
- The upstream-parity evaluation that ordered all of this is
  [docs/NGROK_FEATURE_EVALUATION.md](../NGROK_FEATURE_EVALUATION.md).
