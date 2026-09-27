# ngrok Commercial Feature Evaluation (v3, September 2026)

This document is the consolidated evaluation of commercial ngrok's feature surface, produced to drive the self-hosted fork's roadmap. Sources: the official documentation repository (3,866 pages, July 2026 snapshot), live pricing/limits pages, the ngrok REST API contract, and static analysis (strings/symbols, command help output) of the official v3.39.11 agent binary.

## The one architectural fact

**Traffic Policy — and nearly everything interesting — is enforced in the ngrok cloud edge, not in the agent.** The agent is a deliberately dumb, outbound-only tunnel: it uploads endpoint declarations (including a traffic policy file) to the cloud, which parses requests, evaluates policy, and forwards what survives to the agent over a muxado-multiplexed TLS connection. The single documented agent-side exception is TLS termination (`agent_tls_termination`).

Consequence for the fork: every cloud feature maps to the fork's **server** (ngrokd), not the client. In a self-hosted deployment the server *is* the edge, so the mapping is natural — but the work is server-side.

## Tier model (current)

**Free / Hobbyist ($10/mo) / Pay-as-you-go ($20/mo + usage)**. There is no Enterprise tier; enterprise-shaped capability is sold as PAYG add-ons (SSO & RBAC $10/user/mo, governance suite $15/user/mo, custom TLS certs $0.27/active-hour, dedicated agent IPs $900/mo/region, custom connect URLs $250/mo, log exporting $0.25/2k events). Legacy Free/Personal/Pro/Business tier names appear only in vestigial error strings.

## Feature catalog

Effort ratings are for a self-hosted fork (v1.7-style Go codebase, raw-byte proxy path, no policy engine). `ngrokd` below means the fork's self-hosted server.

| Feature | Where ngrok runs it | Tier | Fork effort | Notes |
|---|---|---|---|---|
| http/tcp/tls tunnels + `--url`, `--name`, `--metadata`, `--description` | agent uploads declaration; cloud routes | Free+ | low | Fork has http/https/tcp + subdomain/hostname today |
| `file://` built-in file server | agent | Free+ | low | Static handler; path traversal care |
| Upstream TLS (`ngrok http https://…`, `--upstream-tls-verify[-cas]`) | agent | Free+ | low | Default is **no verification**; verify modes undocumented |
| `--upstream-proxy-protocol` (v1/v2) | agent | Free+ | low | Prepend PROXY header to upstream |
| Host/request/response header flags | agent | Free+ | **done (v1.0.2)** | Missing: automatic `Location` rewrite on host rewrite |
| Websockets | agent passthrough | Free+ | low | Zero-config upstream; already works |
| HTTP/2 to upstream (h2c prior knowledge) | agent | Free+ | medium | `upstream_protocol: http1\|http2`; real parity gap |
| Authtokens + `bind:` ACLs (hostname/hostport/label/wildcard) | cloud | PAYG | medium | Registry + creation-time binding check; small grammar |
| Custom connect URLs | cloud | PAYG | skip | Meaningless self-hosted; configurable server address instead |
| Endpoint resource model (agent/cloud/internal, bindings public/internal/kubernetes) | cloud | Free+/PAYG | medium | Field set fully documented |
| Endpoint pooling / load balancing (implicit pools, L4 TCP / L7 HTTP) | cloud edge | PAYG | medium | **Highest-leverage server feature** |
| Agent sessions: list / stop / restart / remote update | cloud + agent opt-in | Free+ (update PAYG) | medium | Session registry + control channel |
| Kubernetes Operator | separate OSS product | Free | reuse | **Open source — repoint, don't rebuild** |
| Agent SDKs (Go/Rust/Python/JS stable, Java alpha) | embedded agent | Free | high | Four+ bindings against a new server API |
| Local traffic inspector UI + `localhost:4040/api` (replay, no auth) | agent | Free | medium | Fork has a basic one; `/api/endpoints` + replay semantics documented |
| Cloud traffic inspector (retention tiers, full-capture opt-in) | cloud | Free 24h / PAYG 72h+ | high | Capture toggle + truncation rules + search UI |
| Traffic identities: oauth (8 providers), oidc, saml (Coming Soon), jwt-validation | cloud | Free 3 MAU / PAYG $1/MAU | high (jwt medium) | `jwt-validation` is stateless — a good early win |
| Log exporting: event destinations (firehose/kinesis/cloudwatch/datadog/azure), 55 event types, $0.25/2k events | cloud | PAYG | medium | 5 sinks, oneof target object, documented envelope |
| Custom/reserved/wildcard domains + ACME | cloud | Free 1 / PAYG | medium | Reservation exclusivity + DNS-01 for wildcards |
| Reserved TCP addresses | cloud | Free (card) / PAYG | low/medium | Port allocation table |
| Zero-knowledge TLS / `agent_tls_termination` | **agent** | PAYG | low | **Self-hosted server doesn't terminate at all — simpler than ngrok, high differentiation** |
| TLS tunnels with `terminate_at` (edge/agent/upstream) | agent+cloud | Hobbyist+ | medium | SNI demux + cert selection |
| Vaults and secrets (write-only values, CEL `secret()` refs) | cloud | Free 5 / PAYG | medium | Fork can add file/env sources ngrok lacks |
| IP policies (allow/deny CIDR rules) + `restrict-ips` + IP restrictions (account-wide, 4 types, warn mode) | cloud | PAYG | low/medium | CIDR match on L4 source IP |
| IP Intelligence feeds (client_ip.* enrichment) | cloud | add-on | high/OD | Data licensing problem, not code; BYO feeds |
| Certificate authorities + mTLS validation | cloud (+agent for TLS tunnels) | PAYG | low/medium | PEM store + verification hook |
| Traffic Policy engine: CEL + 105 macros + 26 actions across 4 phases | cloud | Free 5 rules / TPU-metered | **high** | Largest single surface; subset first (below) |
| REST API: 60 resource groups, Bearer + `Ngrok-Version: 2`, limit/before_id paging, CEL `filter`, `ERR_NGROK_*` errors, 120 req/min | cloud | Free+ | medium | Decide mirror-vs-own paths deliberately |
| verify-webhook: 67 live providers, 4 with challenge auto-handling | cloud | Free 500/mo | medium | Per-provider algorithms must come from vendors' docs |
| `.internal` endpoints + `forward-internal` action | cloud | PAYG | medium | **Load-bearing primitive for private/site-to-site; do early** |
| Outbound proxy support (`http_proxy` env, `proxy_url` config, SOCKS5) | agent | PAYG | low | Self-contained; high enterprise value |
| UDP / QUIC / HTTP-3 | — | — | skip | **Not supported upstream — not a parity gap** |
| Legacy edges/backends/labeled tunnels | cloud | sunset | skip | Deprecated 2023; superseded by pools + policy |
| AI Gateway (LLM routing, credits, 9 providers, 4 custom incl. Ollama) | separate cloud product | separate billing | high/new service | Only hook to self-host is `.internal` endpoints; use LiteLLM instead |
| `ngrokd`/`ngrokctl` private-connectivity daemon | separate product | — | high | Privileged networking; **and the name is taken (see below)** |
| Dashboard/account plane: SSO (SAML/OIDC), SCIM, RBAC, service users, API keys, MFA, usage/billing | cloud | PAYG add-ons | medium/high | Minimum viable: users, roles, API keys, authtokens, session list/kill |

## Suggested sequencing

1. **Header cluster** — done (v1.0.2).
2. **`.internal` endpoints + `forward-internal` + endpoint pooling** — the three features that make multi-agent self-hosted deployments actually useful; pooling is the highest-leverage single server feature.
3. **Cheap policy subset** — `add-headers`, `remove-headers`, `log`, `set-vars`, `deny`, `custom-response` (non-terminating + cheap terminators), plus `restrict-ips` with agent-side `--cidr-allow/--cidr-deny` parity. This retires the legacy flag surface and covers the header-manipulation use case natively.
4. **Zero-knowledge TLS** (`agent_tls_termination`) — easier for a self-hosted fork than for ngrok; high differentiation.
5. **`jwt-validation`** — stateless, no session store; the identity feature worth doing first.
6. **Vaults + secrets**, then **event export pipeline** (log exporting), then everything else; the Kubernetes Operator is repointed, not rebuilt.

## Escalations for a deliberate decision

1. **The name `ngrokd` is taken.** ngrok now ships a product literally called `ngrokd` — a local private-connectivity daemon (install script, Docker image `ngrok/ngrokd:latest`, companion CLI `ngrokctl`). The fork's server binary is named `ngrokd`. Shipping more code under that name collides in search, package registries, and user mental models. A naming decision should be made deliberately (see also the fork's positioning below).
2. **ngrok's positioning statement.** ngrok's FAQ asserts there are no open-source agent versions and that "source builds are most likely malicious", while acknowledging the original open-source 1.x codebase on GitHub. This fork is a continuation of that acknowledged 1.x codebase (modernized: Go modules, Go 1.21, protocol 2). The factual ground is solid, but the fork's naming, README wording, and legal posture are decisions to make now rather than after the feature set grows. Not legal advice — just a flag.

## Documentation inconsistencies worth knowing (so the fork does not inherit them)

- Log-export availability contradicts itself across pages (free+PAYG vs PAYG-only).
- Event destination `format` documented as `JSON`, returned as `json`; error body shape differs between pages.
- The API Reference nav group labeled "Traffic Policy" contains CAs/IP Policies/Applications, not policy resources.
- Three different region enums ship simultaneously; `eu-lon-1` is accepted by the agent but missing from the PoP table.
- `verify-webhook` marketing says "68 providers"; the table has 69 (67 live).
- OIDC page inherits OAuth's managed-provider table; OIDC omits `redirect_path`.
- Several flags marked deprecated in the CLI reference are still taught as live elsewhere (`--host-header`, `--upstream-protocol`, `--basic-auth`, `--websocket-tcp-converter` whose deprecation points at a nonexistent replacement).
- The secrets page claims values are "never persisted in logs" four lines above a warning that full-capture mode may record them in cleartext.

## Open uncertainties (docs silent)

Upstream-TLS verify mode semantics; whether `--upstream-proxy-protocol` applies to HTTP; local-inspector replay subpath existence; identity/session retention windows; whether an ngrok-signed identity JWT exists; OAuth/OIDC session-duration defaults; mTLS plan gates; API key expiry; account-level data-residency controls.
