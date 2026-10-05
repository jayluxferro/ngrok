# Spec 10 — Webhook verification

Status: shipped (see the changelog entry for its release; this document is the design record) (user: parity items, work autonomously). Recon complete (see agent
report — anchors below). v1.0.14 material. The load-bearing change is in the REWRITER:
the first body buffering in the request path, with a deferred verdict.

## 1. Objectives

A request-phase action `webhook-verification` that checks provider signature schemes
(Stripe, GitHub, Svix) over the signed body before the request reaches the local
service. Failure answers 403 with a per-provider fixed body. Secrets compose with
vaults. Works on edge and agent-terminated tunnels (both enforcement points share the
rewriter).

## 2. Non-goals (v1)

- No Slack (url_verification challenge echo needs request-derived response bodies —
  deferred to v2 with a sanitization design).
- No header-only shortcuts that pretend to verify without the body — if the body
  cannot be buffered (chunked, close-delimited, over cap), the action FAILS CLOSED
  with 403, never open.
- No new CEL body variables (policy/policy.go:41-43 stays true).
- No async/replay verification, no per-provider retry semantics.

## 3. The rewriter change (agent R — the risky half)

Deferred verdict with bounded body buffering in rewriter/:
- Compiled policy gains `NeedsBody bool` (set at build when any request-phase action
  implements bodyConsumer). The rewriter checks it in stepHead (rewriter.go:1660
  region): when set, it does NOT emit the head; it transitions to a new body-buffer
  state that accumulates up to `webhookBodyCap` (1 MiB) of CL-framed body bytes
  (Content-Length known from the head; the cap is checked against CL up front — a CL
  over cap terminates immediately with the 403).
- When the body is fully buffered: run the deferred hook with a head object that
  carries the body (new field on the head struct, populated only on this path); the
  verdict either terminates (existing plumbing: generation tag, park/wake,
  setTerminate — rewriter.go:1522-1556) or emits head + buffered body and continues
  the stream normally.
- Chunked transfer-encoding or close-delimited bodies under a NeedsBody policy:
  terminate with the 403 immediately (do NOT de-chunk in v1; document loudly).
- Upgrade/websocket requests under NeedsBody: impossible in practice (webhooks are
  plain POSTs) — if it happens, terminate with 403 (fail closed).
- Version skew: an old enforcing rewriter cannot run a NeedsBody policy — the
  registration refuses loudly (TestNewTunnelRefusesAPolicyItCannotEnforce precedent,
  server/policy_test.go:732): the compiled policy carries a marker the server checks
  against its own rewriter capability; the AGENT-side path gets the same guard via
  the existing terminationEchoError-style version vocabulary (client refuses a
  NeedsBody policy it cannot buffer).
- Pooled buffers stay pooled: the body accumulator draws from the existing 64 KiB
  pooled read buffers (or a dedicated capped pool); no unbounded allocation; release
  on all exit paths (the pooled_test ownership patterns apply — exactly-once).
- Bench canary: bulk (64 MiB) MUST be unchanged without NeedsBody policies (the
  buffering path is opt-in per compiled policy — zero cost when no policy needs it;
  a bench row proves parity).

## 4. The policy action (agent P)

`webhook-verification`, request-phase only, config:
```yaml
- name: webhook-verification
  config:
    provider: stripe        # stripe | github | svix
    secrets:                # one or more (rotation); inline or secret("vault/key")
      - "whsec_..."
    tolerance_seconds: 300  # default 300, >= 0; negative refused with jwt's wording
```
- Schemes: stripe = HMAC-SHA256 over `{t}.{payload}` from `Stripe-Signature`
  `t=...,v1=...` (all v1 entries checked, constant-time; timestamp within tolerance);
  github = HMAC-SHA256 over body from `x-hub-signature-256: sha256=...`; svix =
  HMAC-SHA256 over `{svix-id}.{svix-timestamp}.{body}` from `svix-signature`
  (whsecs prefixed `whsec_`, multiple secrets = multiple schemes `v1,gcm` — v1 only).
- Secrets resolve through ResolveSecretRef at BUILD time (both sides); a
  digest-prefixed resolved value is REFUSED (HMAC needs plaintext; contrast the
  credential path where digests are the point); plaintext held in the compiled action
  for the tunnel's lifetime, never logged, never in a response (the
  no-credential-material rule holds by construction).
- Failure: 403, fixed per-provider body built at load time (deny shape,
  SyntheticResponse; nothing request-derived). Success: no-op.
- All comparisons constant-time over digests where lengths vary (HMAC output is fixed
  length; compare subtle.ConstantTimeCompare on the computed vs provided hex/base64).
- Header parsing strict: malformed signature headers = 403 (fail closed), never 400.

## 5. File ownership

- **R (rewriter)**: rewriter/rewriter.go, rewriter/conn.go (if the head struct gains a
  body field), rewriter tests + new deferred-verdict tests (buffer complete, over-cap,
  chunked refusal, terminate-after-buffer, emit-then-continue, pooled release).
- **P (policy)**: policy/policy.go (action const, phase matrix, NeedsBody flag,
  evalRequest case), policy/validate.go (config keys/builder), policy/webhook.go
  (new: the three schemes), policy tests (golden signatures generated in-test with
  real HMAC; tolerance boundaries; rotation secrets; vault composition; digest-prefixed
  refusal; malformed header table).
- **C (after R+P)**: e2e (python upstream echoing headers/body; signed POST via a
  small python signer → 200; tampered body → 403; wrong secret → 403; stale timestamp
  → 403; chunked refusal; agent-terminated-tunnel variant; vault-sourced secret),
  bench parity row (bulk unchanged), docs/CHANGELOG 1.0.14, README, version "14".
- Server/client capability markers: R owns rewriter/ side; the server-side
  registration guard lives with P's policy surface (server/tunnel.go one-line check +
  test) — coordinate via the marker const in policy/ (P defines, server consumes).

## 6. Review gates

1. Full -race + e2e green; bulk bench parity row within noise (no policy = no cost).
2. Fail-closed everywhere the body cannot be verified (chunked, close-delimited,
   over-cap, malformed header, old rewriter): 403, never open, never 400.
3. Buffer release exactly-once on every exit path; -race clean under concurrent
   buffered+terminated+upgraded mixes.
4. No plaintext secret in any log/error/response (grep-pinned).
5. Data-driven provider table (a fourth provider = one entry + one scheme func).
