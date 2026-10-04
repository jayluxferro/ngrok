# Spec 11 — Wildcard hostnames

Status: approved (user: parity items). Recon complete. v1 follows the recon's
smallest-safe shape exactly; the bigger ownership questions are non-goals.

## 1. Objectives

`hostname: *.domain.tld` tunnels where the domain is the SERVER'S OWN configured
domain: one wildcard bucket catches every otherwise-unregistered name beneath it.
Exact names still win (exact-first lookup); the wildcard only serves misses.

## 2. v1 scope (locked by recon)

- `*.<server domain>` ONLY (the -domain/$VHOST value, vhost derivation
  server/tunnel.go:160-174). Arbitrary-domain wildcards need the ownership model
  first — refused with an error naming the server's domain.
- One label deep: `*.example.com` matches `api.example.com`, NOT
  `a.b.example.com`, NOT `example.com`. Longest base wins if multiple wildcards
  could match (only possible via pooling joins today).
- Public binding, http/https only. Refused on `binding: internal` (the owner
  namespace must stay exact) and in `subdomain` (canonicalize: users write the
  wildcard in `hostname`).
- Registration grammar: exactly one leading `*.` label, nothing else wild, no `*`
  mid-name — validated BOTH sides (client validateEndpointPolicy, server
  validateRequest; the mirror discipline server/tunnel.go:223-230).
- Ownership: a wildcard bucket carries bucket.owner; a second wildcard over the
  same base from ANOTHER owner is refused (pooling refusal's wording,
  registry.go:192-197). Exact names under a live wildcard remain independently
  registerable, first-come — documented as a guarantee about ROUTING precedence,
  not about name reservation.
- TLS v1: agent-CA model works UNCHANGED (the agent mints a leaf per SNI name —
  recon 2.3: no change needed); edge-terminated wildcards keep the single server
  cert exactly like every hostname tunnel today (documented; per-SNI GetCertificate
  is the follow-up, not this cluster).

## 3. Implementation

- ONE matcher, adopted by both public sites: `Match(proto, host)` on the registry —
  exact map hit first (the hit path stays map-priced: NO wildcard scan on hits),
  then longest-one-label-suffix over a small wildcard list (a slice or map keyed by
  base domain, built at register/unregister), port stripped inside Match (strip only
  the proto's defaultPortMap port), `.internal` excluded before fallback. Sites:
  the SNI lookup (server/http.go:288) and the Host lookup (:633). GetInternal and
  the self-lookups stay exact.
- Registration: hostname branch accepts `*.<vhost>` (after validation); the bucket
  registers under the literal `*.example.com` key AND joins the wildcard index.
- The 404 negative-routing path (Host: no-such-name → 404) now must consider the
  wildcard: a name under a live wildcard routes to it; a name NOT under it still
  404s; the 421 path unchanged.
- Client: validateEndpointPolicy accepts `*.<domain>` grammar (and refuses
  everything else wild); the derived PublicUrl shows the wildcard literally.

## 4. File ownership

- **A (server)**: server/registry.go (Match + wildcard index + owner refusal),
  server/tunnel.go (validateRequest grammar + registration), server/http.go (both
  lookup sites + 404/421 interplay), server tests (registry_v2_test.go model:
  hit/miss/one-label/longest-base/owner-refusal/port-stripping/exact-wins;
  sni_test.go: wildcard SNI → passthrough + edge variants).
- **B (client)**: client/config.go (grammar validation, hostname canonicalization),
  client tests. Small enough to fold into A if A prefers — but keep client/config.go
  ownership explicit either way.
- **C (after)**: e2e (wildcard http: hit → 200, exact-wins, two-label miss → 404,
  other-owner wildcard refused; wildcard SNI agent-terminated with CA leaf minted
  for the visitor's exact name; bench note: conn-rate unchanged on exact hits),
  docs/CHANGELOG (fold into the 1.0.14 release if both clusters land together, else
  1.0.15), README, version.

## 5. Review gates

1. Full -race + e2e green.
2. Exact-hit path measurably unchanged (bench conn-rate within noise; the wildcard
   scan runs only on misses — assert via a counter or by construction review).
3. Both routing sites (SNI + Host) agree on every case — one shared matcher, no
   per-site logic.
4. `.internal` NEVER matches a wildcard (test pins it).
5. Fail-loudly: every refusal names the rule (server-domain-only, grammar,
   cross-owner) and the accepted shape.
