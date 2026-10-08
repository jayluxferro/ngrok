# Changelog
## 1.0.18 - 2026-10-08 - Upstream HTTP/2: `upstream_protocol: http2`

The local leg's parity gap closed: an ordinary edge-terminated tunnel can
now serve a local service that only speaks h2c — a gRPC server, an h2 API
— by transcoding in the agent. `upstream_protocol: http2` on an http/
https tunnel keeps the proxy leg HTTP/1.1, where the rewriter,
traffic-policy phases, inspector tee, XFF injection and compression all
run unchanged, and speaks plaintext HTTP/2 (h2c, prior knowledge) to the
local address. It is the mirror image of v1.0.16's h2 passthrough: there
the VISITOR speaks h2 and everything is spliced raw; here the visitor
speaks h1 and the local service receives real h2 with every control's
output riding the crossing.

### The key

```yaml
tunnels:
  grpc-edge:
    proto:
      http: 9090
    hostname: grpc
    upstream_protocol: http2   # http1 (the default) | http2
```

CLI twin: `-upstream-protocol http2`. `http1` is the spelled-out default;
the key's absence changes nothing, and a config without it never grows
one. The matrix refuses what it cannot honor at load, naming the tunnel:
tcp/udp tunnels (no h1 proxy leg to transcode), `forward_to` endpoints
(the local port is never dialed, so there is nothing to transcode), and
`alpn` lists containing `h2` — the two h2 features own the local leg
incompatibly (`alpn` splices h2 visitors through raw to an h2c listener;
`upstream_protocol` parses h1 and transcodes), and the refusal says which
tool serves which need. Everything rewriter- or policy-driven composes —
those controls run on the visitor leg, which the transcoder keeps
unchanged: the deliberate contrast with `alpn` h2's strict company rules.

### The transcoder

The local dial site substitutes an in-process bridge: a one-connection
`http.Server` over a `net.Pipe` — net/http does every byte of h1 framing;
this codebase does not hand-roll framing on data paths — feeding a shared
per-address `http2.Transport` in the h2c prior-knowledge shape. Bodies
stream in both directions, announced trailers ride the crossing as h1
chunk trailers, and concurrent proxy connections pool their streams onto
shared local h2c connections, which is what an h2 service wants.

Two details the implementation earned the hard way:

- The transport's `ConnPool` must be the transcoder's own pool. Left
  unset, `RoundTrip` consults the transport's internal cache, which never
  learns of the eagerly-dialed connection — it silently dials its own,
  one per transport, and strands the dead-service contract (the eager
  dial is what makes a dead local service fail at the dial site, answered
  by the existing 502 path instead of inside the first request).
- The response's `Content-Length` is not copied across the crossing: over
  h2 it is a framing header, not a claim about the body. The h2 server
  includes it only when it buffered the whole response before the handler
  returned; copying it would pin the h1 side to identity framing and
  silently drop declared trailers whenever the h2 server lost that race.

### Death, silence, and upgrades

A dead local service surfaces exactly as today — the same WARN, the same
502 page — on all three roads: a cold pool (dial refused), a warm pool
(the connection's FIN evicts it and the next dial is refused), and death
mid-request (the stream dies with the connection and the bridge answers
the same 502). The pool also health-checks its idle connections — a PING
after 30 seconds of silence, eviction if it goes unanswered — because a
shared pool can hold a connection whose peer vanished without a FIN, a
problem a per-request dial doesn't have. Deliberately NOT set: a response
timeout. A slow local service gets exactly the deal the plain dial gives
it — the visitor's own patience is the bound, on both roads. Websockets
and other `Upgrade` requests are refused with a fixed 502 naming the
rule: h2 has no Upgrade without extended CONNECT, which this release does
not implement.

`golang.org/x/net` is promoted from indirect to direct (the
`x/net/http2` transport is the local leg). The server and the wire
protocol are untouched — an old server pairs fine.

## 1.0.17 - 2026-10-08 - Single sign-on: the oidc action

An `oidc` action in an `on_http_request` policy makes an endpoint a real
relying party: a visitor without a session is redirected to your identity
provider (authorization-code flow with PKCE S256, strict issuer and
discovery validation, single-use codes), the provider sends the code back
to a reserved callback path on the endpoint's own hostname, and the
verified identity arrives at the local service as `X-Forwarded-User`,
`X-Forwarded-Email` and `X-Forwarded-Preferred-Username` — spliced into the
dispatched request head, with any client-supplied copy of those fields
stripped first, so what reaches the upstream is exactly the identity the
token vouched for.

The action is the first whose verdict survives a connection boundary, and
it is enforced pre-dispatch at the routing layer rather than in the
per-request hook, for two reasons the hook layer cannot fix: an
unauthenticated visit would burn a proxy connection per redirect
(`HandlePublicConnection` pulls one before any hook runs), and the
callback needs routing-layer interception a rewriter cannot do. The
granularity is the first request on a connection — keep-alive and
pipelined requests ride its decision, the same granularity Host routing
and the legacy HttpAuth have always had. The policy's other request-phase
actions still run, in document order, on the authenticated connection.

### The action

```yaml
tunnels:
  app:
    hostname: app.example.com
    proto:
      http: 8080
    traffic_policy:
      on_http_request:
        - name: oidc
          config:
            issuer: https://accounts.google.com  # https; loopback for tests
            client_id: "....apps.googleusercontent.com"
            client_secret: secret("main/google") # vault-composable
            scopes: [openid, email]              # openid forced first
            callback_path: /oauth2/callback      # default; reserved endpoint-wide
            session_duration_seconds: 3600       # (0, 86400]
            allowed_domains: [example.com]       # optional post-verification gate
            claims: { hd: example.com }          # optional exact-match check
```

### The session

No server-side session store exists, by design: the session cookie is an
HMAC-SHA256 signature over the identity and expiry (signed, not encrypted
— the ID token never rides a cookie), so sessions survive a restart and
balance across servers by construction. The flow cookie that binds the
dance is short-lived and scoped to the callback path.

`oidc_session_key` in the server's config sets the signing key: unset, a
random key is generated per startup (a restart then invalidates every
session — logged, at INFO); set, it must be at least 32 bytes and sessions
survive restarts. It is config-file only, deliberately not a flag — a
signing key has no business in `ps` output or shell history, the same call
`event_destinations` made.

### The honest limits

- **No revocation.** A minted session lives until it expires; logout is the
  browser dropping the cookie. There is no server-side kill switch.
- **Failure taxonomy, fail-closed everywhere.** A token endpoint that
  *answers* with an error gets the fixed `403 oidc: authentication
  failed`; a token endpoint that cannot be *reached* gets a `503` — an
  identity provider outage is an outage of the protected endpoint, never
  an open door. Every unverified or malformed piece of the dance (state,
  nonce, signature, claims) gets the 403. A session cookie that fails its
  MAC is treated as *no session* — a fresh redirect to the provider, not a
  403 — because a stale cookie (say, every visitor's, after the operator
  rotates `oidc_session_key`) is indistinguishable from a forged one, and
  both are simply unauthenticated. The claimed identity is never believed
  either way.
- **`session_duration_seconds` above 86400 is a load refusal**, not a
  clamp — a policy asking for more than a day of session is a policy worth
  reading again.
- **Zero-knowledge endpoints cannot carry the action**: the server holds
  only ciphertext there — no Host, no Cookie, no plaintext to redirect —
  and the registration is refused naming both facts, before the url is
  claimed. A `forward_to` chain that lands an oidc policy on an
  agent-terminated endpoint fails closed agent-side (403), same rule as
  every other policy that cannot run where the traffic terminates.
- **First request decides.** The verdict's granularity is the connection,
  not the request: a request pipelined behind an authenticated one rides
  the authentication (pinned by test, byte for byte).

The fake IdP the e2e suite drives the whole loop against — discovery, JWKS,
authorize, token, single-use codes, `redirect_uri` binding — ships as
`scripts/oidc_fake_idp.go`, build-ignored like the h2c helper.

## 1.0.16 - 2026-10-08 - HTTP/2 passthrough on agent-terminated tunnels

An opt-in `alpn` key on zero-knowledge tunnels, so visitors that *must* speak
HTTP/2 -- grpc-go clients above all -- work end-to-end through the existing
raw-passthrough architecture: the agent's TLS terminator offers `h2` in its
ALPN, the visitor negotiates it, and from there the whole connection is
carried as opaque bytes in both directions.

Shipping this also fixed a latent bug the design work uncovered: the
rewriter's request-line parser accepted the h2 prior-knowledge preface
(`PRI * HTTP/2.0` -- `PRI` is a valid HTTP/1 token and `*` a non-empty
target), the "head" parsed with zero fields, and the always-on
`X-Forwarded-For` injection spliced a header line into the middle of the
24-byte fixed preface, shifting `SM\r\n\r\n` out of position. Any conforming
h2 server then rejected the connection as a framing error. A prior-knowledge
visitor to any rewritten tunnel was broken by the rewriter itself, before
this release.

### The tunnel key

```yaml
tunnels:
  grpc-edge:
    proto:
      https: 7000
    hostname: grpc
    agent_tls_termination: true
    alpn: ["h2", "http/1.1"]   # http/1.1 (default) | h2
    compression: false          # required to be explicitly false with h2
```

CLI twin: `-alpn h2,http/1.1` beside the agent-TLS flags. `alpn` is validated
at load, and `h2` in the list is refused unless the tunnel is one the h2
visitor cannot dodge controls on:

- **`agent_tls_termination` is required** -- ALPN is negotiated between
  visitor and agent, which only exists where the agent terminates TLS.
- **No `on_http_request` / `on_http_response` rules** -- an h2 connection
  never produces an HTTP/1 head for a policy phase to judge, so a rule there
  would be a control an h2 visitor simply sidesteps. The refusal names the
  conflicting phases.
- **No header settings, and `host_header` only unset or `preserve`** -- same
  reasoning: those rewrites splice text into heads this connection will never
  have.
- **`compression: false`, stated explicitly** -- the gzip transform re-frames
  HTTP/1 responses; there are none to re-frame here, and a default that
  silently promised one would be a lie the config refuses to tell.

An `alpn` list of `["http/1.1"]` alone triggers none of this: it is the
spelled-out default, and every visitor is HTTP/1, so every control applies.
The asymmetry is the point -- the refusals guard the combination where a
control would silently not run, not the key itself.

### The guard

The rewriter recognizes the preface at request-head parse (`PRI` as the
method, or `HTTP/2.0` as the version -- either signal alone is enough to say
the stream is not HTTP/1) and, with no policy hook armed on the connection,
hands the whole connection to the raw byte copy: every byte consumed so far
is replayed verbatim, nothing is injected, nothing rewritten, both directions
for the life of the connection. An h1 visitor on the same tunnel keeps the
fully rewritten path -- the guard is per connection, not per tunnel.

Releasing the response side took one more mechanism the first live run
caught: the response rewriter parks between messages waiting for a status
*line*, and an h2 upstream's first answer is a SETTINGS frame -- binary, with
no line break in it at all -- so a parked side would sit there holding the
frames while the visitor waited for a handshake answer that never left the
agent: both sides asleep, zero bytes, a clean deadlock. The request side now
arms a one-shot wake flag when it hands the connection over, and the parked
line wait exits on it at its first opportunity, replaying whatever it
consumed in order before joining the raw copy.

With a policy hook armed, the guard closes the connection instead of passing
it through and logs one WARN naming the tunnel: passthrough would deliver
every request to the local service without the hook ever seeing one. The
close is a close and not a 431 -- a visitor that assumed h2 cannot read an
HTTP/1-text error, and a closed connection says the same thing without
pretending to speak its protocol. This configuration is already refused at
load; the guard is the depth behind that refusal.

### What an h2 visitor does not get

`X-Forwarded-For` / `X-Forwarded-Proto` injection, header rewrites, host
rewrites, compression, the traffic policy's http phases, and the inspector's
HTTP parse: all of these live on the HTTP/1 side of the rewriter, and a
passthrough connection has no such side. The tunnel's own logs say so at the
moment it happens (one INFO line per connection, naming the tunnel), and the
load-time matrix above exists so no configuration can expect both at once.
`on_tcp_connect` still runs server-side on the raw accept, as it always has
for agent-terminated tunnels.

## 1.0.15 - 2026-10-05 - Webhook verification

A request-phase policy action that verifies the signatures webhook providers
put on their deliveries -- Stripe, GitHub and Svix -- over the request body,
before anything reaches the local service. It is the policy engine's first
body-consuming action, so this release is as much about the rewriter as
about the action: the request path's first body buffering, with the
verdict deferred until the body is in hand.

### The action

```yaml
traffic_policy:
  on_http_request:
    - name: webhook-verification
      config:
        provider: stripe            # stripe | github | svix
        secrets:                    # one or more -- several = rotation
          - "whsec_..."             # inline, or secret("vault/key")
        tolerance_seconds: 300      # send-time skew allowed; default 300
```

- **`provider: stripe`** reads `Stripe-Signature: t=<unix>,v1=<hex>` and
  checks HMAC-SHA256 over `{t}.{body}`. Every `v1` entry is checked (Stripe
  sends one per live endpoint key), an entry this engine cannot parse
  refuses the whole header rather than being skipped past, and a second
  `t=` is malformed -- the header would not say which time signed the
  payload. Version tags the scheme does not carry (Stripe has issued `v0`
  historically) are ignored: admission still requires a verified `v1`, so
  ignoring one cannot admit anything.
- **`provider: github`** reads `X-Hub-Signature-256: sha256=<hex>` and
  checks HMAC-SHA256 over the body alone. No timestamp participates -- the
  tolerance field is accepted and simply unused -- so a genuinely signed
  delivery replays for as long as its secret is configured. That is
  GitHub's scheme, not a choice of ours; rotation (removing a leaked key
  from the config) is the retirement story.
- **`provider: svix`** reads `svix-id`, `svix-timestamp` and
  `svix-signature: v1,<base64>` and checks HMAC-SHA256 over
  `{svix-id}.{svix-timestamp}.{body}` with the DECODED bytes of the
  `whsec_`-prefixed secret. A value without the prefix, or whose remainder
  does not base64-decode, is refused at load: Svix issues its secrets in
  exactly that spelling, and a wrong-credential paste is better named at
  load than discovered as a webhook that refuses every real delivery for a
  year.
- **Every comparison is constant-time, and no key short-circuits the
  list.** A refused request is answered only after every configured secret
  has been tried -- the same discipline the credential lists use -- so the
  time to a 403 says nothing about which entry was being tried, and
  rotation leaks no oracle. The cost is one extra HMAC per configured key.
- **The tolerance covers skew in both directions and its boundary is
  inclusive**: a timestamp exactly `tolerance_seconds` from now is admitted
  (the operator's own stated accept, not something to tighten by a
  nanosecond of wall clock); anything beyond is refused. The default 300
  seconds is what Stripe's and Svix's own SDKs use.
- **Failure is one fixed 403 per provider**, built once at load: a
  malformed signature header, a stale timestamp, a wrong secret, and a body
  that could not be buffered all answer the same bytes. None of them
  answers 400 -- a distinct code per malformation would teach a probing
  client which part of its forgery was wrong. The failure log names the
  method, target and a fixed label; no signature material and nothing
  request-derived reaches a log line or a response body.

### Fail-closed

The action's authority is the body, so every request whose body cannot be
verified refuses rather than passes: `Transfer-Encoding: chunked` (not
de-chunked in this release), no Content-Length (close-delimited), a declared
length over the cap, a body that ends short of its declaration, and a
request with no body field at all -- all answer the same fixed 403, never a
400, never an open door. The sharpest of these is deliberate: a request
that declares a body but presents none for verification is refused even
though an HMAC over the empty string is a perfectly legal computation,
because an empty verification body is the fail-open shape -- sign nothing
once, smuggle anything forever in front of a signature that never covered
it.

### Vaults

`secrets` entries compose with the vaults like every credential field:
`secret("vault/key")` as the whole value, resolved at load on whichever
side loads the policy -- the reference text is what crosses the wire, the
server re-resolves at registration, and a server without the vault refuses
the registration rather than expose an endpoint that only looks verified.
One rule is stricter than the credential path, on purpose: a resolved value
spelled `sha256:...` is refused. A pre-digested credential is the
credential path's whole point -- compare digests, hold no plaintext -- but
an HMAC is computed *with* the key, so a digest of the key verifies
nothing; the plaintext signing secret has to exist somewhere, and the
honest choice is to demand it rather than accept a form that can never
verify. Empty values and values carrying CR/LF are refused at load as well
(an empty secret verifies nothing; a CR or LF in a header-carried scheme is
injection). The svix provider additionally demands its `whsec_` spelling at
load, per the scheme note above.

### The rewriter: first request-body buffering

A body-consuming verdict cannot be made from the head, and the body is, by
the rewriter's own rules, never somewhere a hook could read it -- it is
still on the wire when the verdict is due. A policy whose request phase
declares a body cap (only `webhook-verification` today, 1 MiB) switches the
request rewriter to a deferred verdict: the head is withheld, the declared
body is banked as it arrives, and the hook runs once over head + body. The
framing is checked before anything is withheld -- Content-Length present
and within the cap, no `Transfer-Encoding`, not an upgrade -- and every
uncapturable shape goes to the hook with the body marked absent, where the
action's fail-closed rule answers it. Buffers come from the existing 64 KiB
pooled slabs, drawn only as the body needs them (a small webhook POST costs
one slab), and every exit path -- verdict terminate, verdict forward,
truncated body, connection close -- releases them exactly once, on the
reading goroutine.

The switch is opt-in per compiled policy and costs a policy that does not
ask for it one integer comparison per head: the bulk (64 MiB) bench parity
row measured -0.8%, inside noise. Both enforcement points carry the cap --
the server's tunnel join and the client's `attachPolicyHooks` -- so an
agent-terminated tunnel verifies deliveries exactly as an edge-terminated
one does.

### Known limitations

- **CL-framed bodies only.** A chunked or close-delimited delivery is
  refused with the fixed 403, not verified. Providers sign a payload they
  send with a length, so real deliveries carry Content-Length; a sender
  that does not cannot be verified by this release.
- **`Expect: 100-continue` stalls under a buffering policy.** The rewriter
  withholds the request head while the body is buffered, so nothing answers
  the interim `100` a client asked for until the verdict; the client waits
  out its own continue timeout and sends anyway. Real webhook senders do
  not send Expect, and the over-cap refusal (which answers the head
  immediately) is unaffected.
- **Slack's `url_verification` challenge echo is deferred**: answering it
  needs a response body derived from the request, and the engine's
  synthetic responses are built at load. A Slack endpoint behind this
  action must answer its own challenge.
- **The body is never exposed to CEL.** No `req.body.*` variable exists and
  expressions cannot read buffered bytes: what a policy can know about a
  body is that a webhook action verified it, nothing else.

## 1.0.14 - 2026-10-05 - Wildcard hostnames

A tunnel can now claim every name exactly one label under the server's own
domain: `hostname: "*.example.com"` serves `anything.example.com` -- every
otherwise-unregistered one-label name -- while exact registrations keep
winning. The shape is deliberately narrow, because the narrowness is what
makes it safe to hand out: the base must be the server's own domain, the
match is one label deep, and the wildcard only ever serves misses.

### Server

**One matcher, both routing sites.** The registry gained `Match(proto,
host)`: the exact map hit first -- a hit costs what a lookup always cost,
the wildcard index is never consulted on a hit -- then, on a miss, a single
lookup of the name's base in a wildcard index (`*.example.com` registers
under its literal `http://*.example.com` key *and* the index entry
`http://example.com`). The SNI handler and the Host handler both call it,
so an https visitor routing by ClientHello and an http visitor routing by
Host header cannot disagree about who serves a name. Only the protocol's
default port is stripped from a Host header (`name.example.com:80` routes;
a non-default port stays part of the name and misses, as it always has),
and the reserved `.internal` namespace is excluded before the fallback.

**Exact-first is a routing guarantee, not a reservation.** `api.example.com`
registered by any agent is served by its own tunnel even while
`*.example.com` is live; the wildcard serves the rest. Exact names under a
live wildcard remain independently registerable, first-come -- the wildcard
promise is about routing precedence, never about holding a name.

**Cross-owner wildcards are refused with pooling's wording.** A wildcard
bucket carries an owner like any bucket: a second wildcard over the same
base from another token is refused ("already registered by a different
account; pooling only joins a pool owned by the same account"). A wildcard
over the same base from the same owner joins as a pooling member and
round-robins like any pooled endpoint.

**Every refusal names the rule and the accepted shape.** Wildcards bind
publicly on http and https only; a wildcard whose base is not this server's
own domain (`-domain`/`$VHOST`) is refused with the wanted base spelled out.

**Agent-terminated wildcards work unchanged.** The agent mints a leaf per
visitor name: a ClientHello for `anything.example.com` routes by SNI and
passes through as raw TLS bytes, answered with a leaf naming exactly the
name the visitor asked for. Edge-terminated wildcards keep the single
server certificate, exactly like every hostname tunnel today.

**Behavior change: an explicit default port in Host now routes.** A request
with `Host: name.example.com:80` used to 404 -- the port stayed part of the
name, so it missed the exact key while the bare name routed. Match now
strips the protocol's default port before looking, so `name:80` serves the
tunnel `name` serves. Called out as the change it is: a client that relied
on the old 404 will now be served.

### Client

`hostname: "*.example.com"` is accepted wherever a hostname is -- config
file and CLI flags alike -- and the derived public url keeps the literal
star. The client refuses at load, naming the accepted shape: every
wildcard-bearing spelling that is not a wildcard (`a.*.b`, `*`, `*.`), a
`*` in `subdomain` (write the wildcard in `hostname`), and a wildcard on
`binding: internal` or on a tcp/udp tunnel (the port-routed rule fires
first, in its words). The grammar is the mirror of the server's; the one
check the client deliberately does not restate is the own-domain rule,
because it cannot know the server's domain -- that refusal is the server's,
with the base it wanted named.

### Known limitations

- The base must be the server's own domain. Wildcards over arbitrary
  domains need an ownership model this fork does not have yet.
- One label only: `*.example.com` matches `api.example.com`, never
  `a.b.example.com` and never `example.com` itself.
- A wildcard is not a reservation: only names nobody exactly registered are
  served, and any exact name under it stays registerable while it lives.
- The `subdomain` field cannot carry the star, and `GetInternal` and
  `.internal` lookups never match a wildcard.

## 1.0.13 - 2026-10-04 - Toolchain bump and cel-go module migration

The deliberate dependency migration the 1.21 pin was holding back. The go
directive moves to 1.23.0, cel-go moves from its dead module path
(github.com/google/cel-go, last release v0.31) to cel.dev/cel-go v0.32.0,
and quic-go rides the unlocked ceiling to v0.54.0.

The cel-go change is a module-path move, not an API migration: every
identifier policy/ uses survived intact, the pinned refusal substrings
("recursion limit", "code point size exceeds limit", the undeclared-
reference hint) all behave identically, and the full policy suite --
including its fuzz corpus -- passed with zero test edits. quic-go's
v0.45→v0.54 delta is interface-to-struct renames in this codebase's
terms; the e2e quic group (carrier round-trips, fallback, agent-TLS
over QUIC, UDP over the QUIC carrier) is the wire-behavior judge and is
green unchanged.

CI pins go 1.23 in all three workflows; the dependency updater's skip
class and toolchain guard now reason about the 1.23 floor (cel-go v0.32
requires it; holding there keeps quic-go at v0.54.0, the newest release
declaring 1.23 -- v0.55 needs 1.24). Transitive floors rode the two
bumps; the old cel-go-v0.20 dependency graph dropped away.

## 1.0.12 - 2026-10-04 - Adversarial audit round: hardening

A four-stream adversarial audit (code correctness, security, QA coverage,
wire/API consistency) over everything 1.0.7-1.0.11 shipped, run the way the
1.0.6 round was: fresh eyes, concrete failure scenarios, every finding fixed
down to MINOR. Zero criticals, ten majors, ~25 minors; this release is the
fixes.

### Server

- **UDP admission moved before allocation.** Rate limit, per-IP cap, a new
  per-tunnel flow cap (256) and a global flow cap (65536) now run before a
  flow, goroutine, or proxy connection exists; a refused datagram creates
  nothing. Idle refresh is inbound-and-accepted-only: only public-client
  datagrams that actually enter the (16-deep) queue sustain a flow, so a
  spoofed-source flow gets its one query and dies, and a client shouting
  into a stalled agent's full queue pins nothing. Flow-cap drops publish
  connection_cap_drop events and a counter.
- **The https listener gates before the SNI peek.** Over-budget IPs are
  turned away without the server reading one byte of ClientHello or logging
  an SNI line, and each connection passes each gate exactly once across the
  edge/passthrough routes.
- **A regression the audit's own e2e caught, fixed before release: the
  terminated-https path lost its TLS close_notify** when the gates/handler
  split moved connection ownership -- the raw socket closed under the TLS
  layer and careful clients (openssl among them) read an unexpected EOF
  after the last response. terminateWithServerCert now closes the TLS layer
  it owns; a test pins clean EOF.
- QUIC pre-auth sessions are capped (256) with a sampled refusal;
  event-export HTTP destinations refuse redirects (a credential must never
  leave for a second origin) and refuse CR/LF in vault-resolved header
  values; privileged-port claims warn by name; SNI bytes log as %q so a
  crafted ClientHello cannot forge log lines.

### Policy

- **JWKS fetches are throttled.** An unknown kid costs at most one fetch per
  30s window per cache, shared across concurrent requests (singleflight);
  spraying invented kids no longer turns the edge into a TLS-handshake
  client aimed at the IdP. jwks_uri must be https (loopback exempt); RSA
  moduli are capped at 8192 bits; tokens must carry exp.
- **Vault errors no longer enumerate inventory.** Registration failures say
  exactly `no vault named X is configured` / `vault X has no key Y` -- never
  the list of configured vaults or keys, which was a directory listing aimed
  at any authenticated agent. Pre-digested vault entries now work in
  basic-auth (the separator check cannot apply to a digest and no longer
  pretends to).

### Client

- `proto: {http+https: ...}` tunnels get their name-derived subdomain back
  (a 1.0.10 regression the wire audit caught: the guard exact-matched the
  combined key).
- `-proto=tcp/-proto=udp -hostname=.../-subdomain=...` is now refused at
  startup on the flags path exactly as the config path always did, instead
  of silently discarding the name.
- An unrecognized `-log-level` is a startup error naming the accepted set
  {DEBUG, INFO, WARNING, ERROR}; it used to fall back to DEBUG in silence.
  The previously-undocumented TRACE/FINEST/FINE/CRITICAL spellings now
  error too.

### Both / tests

- The QA stream's coverage gaps are closed with tests that pin mechanism:
  on_tcp_connect deny on the passthrough path never reaches the agent; the
  QUIC dial clones (never aliases) the model's TLS config and rejects
  untrusted certificates; a stalled UDP flow does not starve a healthy one;
  a vault-resolved auth_header reaches the collector and a dangling
  reference fails naming vault and key; SNI routing is case-insensitive;
  the ClientHello length parser's bit-2 precedence, digest storage in
  compiled actions, and the allocs-per-connection floor comparison (the
  flaky -count=2 measurement is now a min-of-N floor estimate -- the
  deterministic saving exists only in the warm-pool regime, which a forced
  GC between measurements destroys rather than controls).
- Docs: the 1.0.9 changelog header is restored; the stale vault-wiring
  comment is gone; README's -log default, -log-level spelling, framing
  description and -adminAddr default now match the code.

### Known limitations

- Vault scoping is server-wide: any authenticated token may reference any
  vault entry, and an operator who binds a vault secret into an endpoint
  they control can probe it at that endpoint's request rate. Multi-tenant
  deployments should treat vaults as single-trust. Per-tenant vault ACLs
  are future work.
- The UDP flow caps and JWKS refetch interval are constants, not
  configuration; if deployment reality needs them tunable, the changelog
  will say so when it happens.
- The reflector posture of a public UDP forwarder is unchanged and
  documented in 1.0.10; this release bounds the amplification economics
  (gates before allocation, accepted-only refresh) without changing what a
  cooperating backend can answer.

## 1.0.11 - 2026-10-04 - Secret vaults and event export

Two features for running this fork in production rather than in demos:
credentials can live in a named vault instead of inside the policy document,
and the server's event stream can be shipped to a collector or a file instead
of only being reachable through the admin `/events` endpoint.

### Server

**Event export (`event_destinations`).** The ngrokd config gains a list of
destinations the event hub ships to, each with its own bounded queue and its
own drain goroutine:

```yaml
# ngrokd config
event_destinations:
  - type: http
    url: https://collector.example/ngrok
    auth_header: "Authorization: Bearer <token>"   # literal or secret("vault/key")
    batch_size: 100          # default 100
    flush_interval: 5s       # default 5s
  - type: jsonl
    path: /var/log/ngrok/events.jsonl
```

The `http` destination POSTs batches as a JSON array of events: a batch is
flushed when it reaches `batch_size` or when `flush_interval` elapses,
whichever comes first. A POST that fails is retried with capped exponential
backoff **forever -- the batch is never abandoned**, because the alternative
(giving up after N attempts) silently loses events that the drop counters
exist to account for. The cost of a dead collector is therefore not lost
events but a filling queue: the destination's 1000-slot queue overflows, and
the overflow is what the counters below measure. The `jsonl` destination
appends one pre-marshaled JSON line per event (a `tail -f`-able image of the
`/events` stream), reopening the file on failure so rotation and a recreated
path heal themselves.

**Loss is visible, never silent -- and visible only there.** A destination
that cannot keep up never blocks the hub (publish stays non-blocking); the
events it cannot take are counted in `/metrics`:

- `event_drop_count` -- events the hub dropped on any full subscriber queue,
  also exported as the `ngrokd_event_drop_count` Prometheus counter on
  `/metrics/prometheus`;
- `event_destinations` -- one row per destination with `type`, `target`,
  `dropped` (queue overflow, plus jsonl lines a failing file could not take)
  and `queue_depth`, surfaced on the 1s sampler.

The design consequence is worth stating plainly: with a stalled destination
the event stream is *eventually consistent with reality only through these
counters*. If a dropped counter is greater than zero, those events are gone.

**`connection_open`.** A new event type carrying `client_addr`, `url` and
`protocol`, published when a public connection is accepted -- the opening
half of `connection_close` (which carries the byte totals), so the two
together bracket one served connection.

**Vaults on the server.** The strict server config speaks the same `vaults:`
block as the client (below), and resolves event-destination `auth_header`
values against it at construction. A tunnel registration whose policy
references a vault the server does not have is refused there (see Both).

### Client

**`vaults:` block.** Credential lists in traffic policies (`basic-auth`'s
`credentials`, `bearer-auth`'s `tokens`, `apikey-auth`'s `keys`) may carry
`secret("vault/key")` references instead of inline values, resolved against
vaults named in the config:

```yaml
# ngrok client config (same shapes in ngrokd's)
vaults:
  main:
    file: /etc/ngrok/vault.yml      # a flat YAML key: value map
  staging:
    env_prefix: NGROK_VAULT_STAGING_  # NGROK_VAULT_STAGING_PROD_API=... -> key "PROD_API"

tunnels:
  private:
    proto:
      http: 8080
    traffic_policy:
      on_http_request:
        - name: basic-auth
          config:
            credentials:
              - 'secret("main/api")'
```

A vault file entry may be written `sha256:<hex>` -- a pre-digested credential,
the same dual form auth tokens use -- so a deployment can keep only digests on
disk and never hold the plaintext at all. The env key is the variable name
minus the prefix, verbatim: the environment cannot carry a hyphen, so file key
`prod-api` and env key `PROD_API` are two different keys.

**Wire-log redaction closed the credential gap.** The DEBUG wire log has
always redacted session secrets; it now also redacts the `credentials`,
`tokens` and `keys` arrays of serialized policies, so a vault-sourced and an
inline credential are equally absent from logs -- regardless of which side
logged the message. Resolution failures name the vault and the key (and the
configured key names), and a malformed `secret(...)` is a load error, never a
literal credential that silently matches nothing.

### Both

- **Resolution is build-time only.** `secret("vault/key")` is resolved once,
  at configuration load (client) or registration (server), immediately before
  the credential digests are taken. It is not a CEL function and never appears
  mid-string: per-request resolution would put the vault on the data path and
  credential material into `${...}` interpolation output. After resolution a
  vault-sourced credential is indistinguishable from an inline one -- digests,
  constant-time compare, static 401s.
- **Both sides must have the vault.** The reference text, not the value,
  crosses the wire: the client resolves against its own vaults (agent-side
  phases need that), and the server re-resolves the same document against its
  own vaults at registration. A server without the vault refuses the
  registration -- an endpoint that looks protected and is not is not a state
  this fork ships. Consequence: rolling out a new vault means deploying the
  vault to the server *and* the agent's config together.
- CR/LF checks and the `user:password` shape check apply to the *resolved*
  value, so a vault entry obeys the same rules as the literal it stands for.

### Known limitations

- **Vault files hold plaintext (or digests) on disk** -- file permissions are
  the operator's control, not the feature's. There is no encryption at rest,
  no KMS integration, no dynamic secrets; `sha256:<hex>` entries are the one
  way to keep plaintext off disk entirely.
- **Env-sourced values are visible in the process environment** (`/proc`, ps
  egress, shell history of whatever exported them).
- **`auth_header` is a plaintext exception.** An event destination's header
  value must be present at flush time, so `secret(...)` there resolves to
  plaintext held in memory for the life of the process. It is never logged,
  but it is not digested either -- the digest rule stops where a header value
  begins.
- **Event export has no client-side counterpart and no sampling**: the client
  keeps its events in the local views; the server exports everything or
  nothing, per destination.

## 1.0.10 - 2026-10-04 - UDP tunnels

A new public protocol, `udp`, the first one this fork has added. It puts a
local UDP service on a public UDP port with the semantics UDP actually has:
datagram-preserving, lossy by design, ordering within one sender only.
`ngrok -proto=udp 53` exposes a local DNS resolver; `ngrok -proto=udp 5353`
exposes an mDNS-style responder; a game server or a QUIC upstream works the
same way. Nothing in the path adds reliability -- no retransmission, no
reordering, no reassembly -- because UDP must stay UDP: a tunnel that quietly
retransmits is a TCP tunnel wearing a UDP address, and the application above
it (which usually owns its own reliability, or owns its own silence) would
have its semantics bent without being told.

The harder design fact is that UDP has no connections, and everything this
tunnel type inherits from the TCP path is per-connection: admission, rate
limits, connection caps, the `on_tcp_connect` policy phase, one proxy conn
per unit of traffic. The server solves this by inventing the unit -- see the
flow model below -- rather than by per-packet decisions, which would re-run
admission on every datagram and rate-limit the second half of every burst.

### Server

**The flow model.** A **flow** is one public `(ip, port)` that has sent at
least one datagram to the tunnel. The first datagram from an unknown address
establishes a flow, and at that moment -- once, not per datagram -- the whole
TCP admission sequence runs: the per-IP rate limit, the per-IP connection
cap, the endpoint's `on_tcp_connect` phase, then a proxy conn from the
agent's pool, introduced by `StartProxy` with the flow's address as
`ClientAddr` so the agent knows which flow it is serving. Datagrams from a
known address extend that address's flow. The tunnel's public datagrams are
drained by a single reader that never blocks on a flow -- establishment and
framing happen off the read loop -- so one slow agent cannot stall the other
flows on the port; each flow holds a bounded queue and drops past it, exactly
as a congested UDP path would.

**A refusal is silence.** A flow denied by rate limit, connection cap or
`on_tcp_connect` is closed without a reply: UDP callers have no protocol to
be answered in, and there is no datagram-shaped 403. This is stated rather
than apologized for because it is the correct behavior and it is also the
confusing one -- a refused sender sees exactly what it would see from an
unreachable port. `on_tcp_connect` keeps its historical name and runs per
flow, with `conn.client_ip` / `conn.remote_addr` set to the flow's address;
the phase's `deny` is the tool for "this source may not open flows at all".
No other policy phase applies to udp (there are no request heads to act on).

**Datagram framing on the proxy leg.** The proxy conn is a byte stream
(TCP, smux, or a QUIC stream), so each datagram travels as a 4-byte
big-endian length prefix followed by exactly that many payload bytes, in
both directions. The frame boundary is the datagram boundary -- nothing is
coalesced and nothing is split, which is the one property a UDP relay must
not compromise. A length field above 65507 (the largest UDP/IPv4 payload
that can exist) cannot have come from a datagram anyone sent; it is a
protocol error and closes the flow, because a stream that lost its framing
cannot be resynchronized. A datagram larger than that arriving at the public
socket cannot be relayed whole either; it is dropped and logged rather than
delivered in pieces.

**Idle expiry, 30 seconds, both ends.** A flow with no datagram in either
direction for 30s is closed -- server and agent each run the same window on
the same constant. It is deliberately not configurable: with no wire message
to negotiate it, a server-side knob would let the two ends disagree, and the
failure mode would be replies silently dropped by whichever half expired
first. One constant, both binaries, is the design; if it ever needs to move,
it moves in the protocol. Every datagram in either direction refreshes the
deadline, so a chatty flow never expires.

**Pooling assigns per flow.** A pooled udp endpoint round-robins flows
across its members the way a pooled tcp endpoint round-robins connections --
the first datagram's flow is served by whichever member the rotation picks.
A single flow never spans two agents.

**Port claims grew a protocol dimension.** The ownership registry keys
claims on `(proto, port)`, because the kernel itself keeps the spaces apart:
a TCP listener on 5000 and a UDP socket on 5000 are different sockets with
no namespace in common, so `udp:5000` never fights `tcp:5000`. Within one
protocol space the old rules are unchanged: one owner, refcounted holds, and
a second token asking for the port is refused with the port and protocol
named ("remote udp port 5000 already claimed by another auth token"). The
registry also sees the server's own UDP listener -- the QUIC proxy listener
from 1.0.9 -- so a udp tunnel cannot claim the port ngrokd's QUIC endpoint
listens on; the refusal names it.

### Client

The agent side is one new branch in the proxy path and a small pump pair:

- **The local leg is a *connected* UDP socket** (`net.DialUDP` toward the
  configured local address). Connectedness is load-bearing in one direction:
  the kernel only ever delivers that socket datagrams from the configured
  local service, so a public client can never use the agent as a reflector
  toward a third host. The same trick runs on the server's public socket
  toward the public client. There is no `forward_to`/`.internal` for udp,
  and a dead local service surfaces as silence (an ICMP port-unreachable on
  a connected socket becomes a write error, which closes the flow quietly --
  udp is not an HTTP protocol and there is no 502 to write).
- **Replies go out through the tunnel's public socket, source port
  preserved.** The server answers each flow from the socket it bound, so the
  public client sees the reply come from the exact ip:port it sent to --
  which is what lets a stateless client (a DNS resolver, most of all) accept
  the answer. The obvious alternative -- the server dialing a fresh UDP
  socket per flow -- was rejected precisely because it breaks this: an
  ephemeral source port on a second socket makes the reply look like it came
  from a stranger, and resolvers drop it.
- **Idle is mirrored.** The agent expires its half of a silent flow at the
  same 30s, logging the close quietly; either side's expiry tears down the
  whole flow (the proxy conn close is the signal), so both ends agree a
  silent flow is over and neither waits on the other to notice.
- **`remote_port` accepts udp**, on the command line (`-proto=udp
  -remote-port=5353`) and in the config file (`remote_port:` on the tunnel),
  with the same rules as tcp: one protocol exactly, ports below 1024 need a
  privileged server, and the claim is owned by the auth token.
- `hostname`/`subdomain` are refused for udp, exactly as for tcp: the
  endpoint is its port.

### Operator exposure: this is a public reflector, state it like one

A udp tunnel forwards datagrams in both directions between a public port and
your local service, and your local service's replies go back to whoever
asked -- from your server's address. That is a reflector by construction,
and the amplification question deserves a straight answer: an attacker can
send small requests and make your local service send responses to
attacker-chosen source addresses. What bounds it:

- **Reply targets are pinned per flow.** Replies go only to the address that
  established the flow -- the server's public socket writes are
  `WriteToUDP(..., flow.client)` and the agent's local socket is connected to
  the configured service. Neither half will ever send to a third host because
  a datagram told it to; the worst a spoofed source address buys an attacker
  is a flow whose replies go into the void toward the spoofed address.
- **Admission runs per flow, at the first datagram**: the per-IP rate limit
  and connection cap you configure for the public listener (`-publicRate`,
  `-maxConnPerIP`) gate flow creation the same way they gate TCP
  connections, and `on_tcp_connect` can refuse flows by source before any
  proxy conn is spent.
- **The idle timeout bounds the window**: a flow lives 30s past its last
  datagram in either direction, so a flow opened for one amplified burst
  cannot be kept alive indefinitely without more datagrams from the claimed
  source.
- **One proxy conn per flow**, and the flow's queue to its agent is bounded
  (16 datagrams, drop past it): a flow cannot make the server buffer
  unboundedly on the agent's behalf.

Treat a udp tunnel's exposure the way you would treat the same UDP service
published on your own firewall: put source policy on it (`on_tcp_connect`
deny by CIDR) if the service amplifies, and prefer tcp tunnels for anything
that does not actually need UDP.

### Known limitations

- **Nameless port-routed tunnels no longer get their name auto-assigned as a
  subdomain.** A tunnel whose every protocol is port-routed (tcp, udp) keeps
  the name it was defined with and registers no subdomain: the server refuses
  names on port-routed endpoints because their url is their bound port, and a
  tunnel the loader had silently named could not register at all (the
  collision was found by the udp e2e group and fixed before release -- this
  entry records the behavior, not an open limitation). Name-routed tunnels
  (any http/https leg) keep the long-standing assignment; a tcp leg always
  ignored it, so nothing a tcp tunnel ever saw changes.
- **Local testing on macOS is capped by the loopback MTU, not by the
  protocol.** The tunnel carries datagrams up to 65507 bytes, but a datagram
  above the interface MTU fragments, and macOS loopback tops out well below
  the protocol maximum (~16 KiB in practice). Round-tripping a maximal
  datagram against a local ngrokd will fail with silence; that is the wire
  under test, not the tunnel. The e2e suite keeps its payloads small for
  exactly this reason; test large-datagram behavior against a real network.
- **Loss, reordering and ICMP errors are invisible by design.** A datagram
  dropped between any two legs is dropped; an unreachable local port is
  silence. Nothing logs "the datagram did not arrive" because nothing can
  know.
- **Flow establishment is one attempt.** If no proxy conn is available when
  the first datagram arrives (the agent is reconnecting, the pool is empty),
  the datagram is dropped and the flow closed; the sender's next datagram
  establishes a fresh flow. There is no queueing of flows behind a reconnect,
  because holding a flow's datagrams while waiting for an agent is exactly
  the buffering UDP promises not to do.
- **No inspector, no http policy phases, no health checks for udp.** There
  are no requests to display and no probes that speak the local protocol;
  the web interface shows nothing for a udp tunnel. A pooled udp endpoint
  has no health checks, like its tcp counterpart: a dead member keeps
  receiving its share of flows until its control connection drops.
- **`on_tcp_connect` is the only policy phase a udp tunnel can carry**, and
  a refusal is silence (see above) -- an operator debugging "why does no one
  hear me" should check the server log for "Traffic policy refused the flow"
  before checking anything else.

## 1.0.9 - 2026-10-04 - QUIC agent transport + pooled rewriter buffers

Two throughput changes with the same target: the cost of moving many streams
through one tunnel. QUIC becomes an alternative carrier for the multiplexed
agent→server proxy connection, so one lost packet no longer stalls every
stream behind it (that is what TCP head-of-line blocking does to a smux
carrier), and the rewriter stops allocating its two 64 KiB read buffers per
connection. Both are invisible when they work: with QUIC disabled -- the
default -- nothing changes for anyone.

### Server

QUIC is opt-in and off by default. `-quicAddr` (or `quic_addr` in the server
config) turns on a UDP listener beside the TCP tunnel listener -- a port
number is two independent bindings, one per protocol, so the QUIC endpoint
lives on the same port the clients already know:

```yaml
# ngrokd config
quic_addr: 0.0.0.0:4443    # empty (the default) = QUIC disabled
```

The default footprint is unchanged: one TCP port. With the listener up, the
server advertises a new `proxy-quic` capability in AuthResp, and only then --
the capability is what authorizes clients to dial UDP at all, so a server
that never opted in is never QUIC-dialed, and one that stops advertising it
stops receiving QUIC sessions without any operator action.

The QUIC handshake reuses the tunnel listener's certificate pair and requires
the ALPN protocol `ngrok` in both directions. A peer that answers with any
other protocol -- an old server on that port, or some other UDP service --
fails the handshake and nothing else happens; cross-protocol misdirection is
refused by TLS, not by hope.

Sessions mirror the smux flow exactly, with no new message types: the first
stream of a QUIC session carries `RegMux` (the session bind -- unknown
client closed, secret compared in constant time, replace-and-close-prior in
the control's session slot), and every later stream carries `RegProxy`, which
re-verifies the client id and secret per stream exactly as the smux path
does. The smux session shape was extracted into a `streamSession` interface
(`AcceptStream`/`Close`) that both carriers implement, and both hand
identical `net.Conn`s to `RegisterProxy` -- downstream of that handoff, the
transport a stream arrived on is unknowable, which is the point.

### Client

`proxy_transport` selects the carrier the multiplexed proxy connection rides
(`auto` by default), or `-proxy-transport` on the command line:

```yaml
# ngrok client config
server_addr: your-server.com:4443
proxy_transport: auto   # auto (default) | quic | tcp
```

- **`auto`** prefers QUIC whenever the server advertised `proxy-quic`, and on
  a failed QUIC dial falls through to the TCP+smux path *inside the same
  attempt* -- a fallback spends no extra attempt of the give-up arithmetic,
  which still counts 8. The preference is re-evaluated per attempt, so a
  server whose QUIC listener comes and goes sees clients follow it with no
  configuration change.
- **`quic`** pins the QUIC carrier, subject to the same capability gate: a
  server that does not advertise `proxy-quic` gets a smux session even from a
  client that asked for QUIC. The capability, not the config, decides what is
  possible; the config decides what is preferred.
- **`tcp`** pins today's behavior byte-for-byte.

Named tunnels also gain `traffic_policy_file`, the config-file twin of
`-traffic-policy-file`: the policy lives in the named file instead of inline
under `traffic_policy`, is resolved once at load with the same validation an
inline document gets, and naming both spellings on one tunnel is refused --
they are alternatives, like the two cert models in the `tls` block.

`http_proxy` forces `tcp` regardless of the setting, logged at INFO: an HTTP
CONNECT proxy carries TCP and cannot carry the UDP a QUIC session needs, and
a client that silently ignored the override would look healthy and never
move a stream.

The QUIC dial uses the same TLS trust decision as the control channel
(`trust_host_root_certs`, embedded CAs, `NGROK_INSECURE_SKIP_VERIFY`) with
only the ALPN added. Keepalive (10s) and idle timeout (30s) are the values
smux already ran, shared by both carriers, with no new knobs.

### Rewriter buffer pooling

Every connection the header rewriter serves paid for two 64 KiB `bufio`
backing arrays -- one per direction -- on the client's HTTP relay and on
every policy-hooked server connection. Both now come from a package-private
`sync.Pool`: **two allocations per connection saved**, with zero call-site
changes outside `rewriter/`. The buffers are read-only scratch, so recycling
is safe; what makes it *correct* is the release discipline:

- **One release site.** `filteredConn.Close` returns each direction's buffer
  to the pool through a `sync.Once`. Every path out of a joined pair already
  goes through that Close, so client relay and server join needed no changes
  -- and a double release, which would hand one buffer to two live
  connections, is structurally impossible rather than merely avoided.
- **Ownership is tested, not asserted.** The suite covers the corruption
  class head-on: exactly-once release under concurrent Close, a scribbled
  (poisoned) released buffer never reaching a live connection, release at
  mid-stream termination, and an `AllocsPerRun` test that pins the
  per-connection drop so a future change cannot quietly give it back.

Deliberately not pooled: the request-head replay buffer (it escapes into the
connection's replay path and lives as long as the connection does) and the
tee readers used by analyzer goroutines (they can outlive the join). Pooling
those would trade a real aliasing hazard for two allocations.

### Both

- **quic-go is pinned at v0.45.0** -- the newest release declaring `go 1.21`,
  this fork's toolchain pin (v0.46+ needs go 1.22). The upgrade rides the
  eventual deliberate toolchain bump; the pin and its reason live in go.mod.
- **Watchdog, backoff and session-lifetime logic are carrier-blind.** A dead
  QUIC session is handled like a dead smux session: an attempt, a backoff, a
  fallback. The e2e suite proves the flip side by restarting the server
  without `-quicAddr` under a live client: it reconnects, sees no capability,
  lands on smux, and keeps serving.
- The public edge does not speak HTTP/3; nothing about visitor connections
  changes. QUIC carries the agent leg only.

### Known limitations

- **Loopback benchmarks establish parity, not superiority -- and the table
  says so in the table.** `scripts/bench.sh` prints the QUIC rows with a NOTE
  row attached: loopback has no packet loss, and QUIC's win is per-stream
  independence *under loss*, so the head-of-line-blocking win cannot show on
  a lossless wire. Measured on the development box (macOS), the QUIC carrier
  matched smux on conn-rate (deltas inside the harness's own documented
  same-binaries noise band) and ran 11-16% behind on keep-alive, and was
  ~8x behind on bulk (≈58-60 vs ≈470-480 MiB/s): quic-go's batched UDP
  syscalls (`recvmmsg`) and GSO are Linux-only, so on darwin every datagram
  is a per-packet syscall at bulk rates. Linux numbers are unmeasured; treat
  the bulk gap as a property of this box until measured elsewhere.
- **The control channel stays on TCP+TLS, by design.** It is low-volume and
  latency-tolerant, and keeping it independent of the experimental transport
  is what makes a QUIC outage survivable: the control connection negotiates
  every capability, so a broken QUIC path is a fallback, not an outage.
- **First-QUIC-dial latency on lossy paths is unmeasured.** A QUIC handshake
  can need more round trips than TCP+TLS on a lossy path, which could make
  the first stream slower than smux for small transfers. What is known: the
  handshake is bounded (5s), a failed or timed-out dial falls through to smux
  in the same attempt, and the fallback is the reason the uncertainty above
  is a latency question, not an availability one.
- **A firewall that silently drops UDP** shows up as a QUIC dial failure and
  the client falls back to smux per attempt -- correct, but the QUIC dial is
  re-attempted on every reconnect. Open the tunnel port's UDP side
  end-to-end if you want the QUIC carrier, not just its TCP side.
- **No QUIC through `http_proxy`** -- not a missing feature but a protocol
  fact (CONNECT cannot carry UDP); the client forces tcp there and says so at
  INFO.

## 1.0.8 - 2026-10-04 - Traffic-policy authentication actions

Four request-phase actions that ask who is calling before a request goes any
further: `basic-auth`, `bearer-auth`, `apikey-auth` and `jwt-validation`.
They join the existing action set and reuse its discipline exactly: an action
runs in the order the policy declares it, admits a request by doing nothing,
and terminates one with a synthetic `401` when the answer is wrong -- the
same verdict path `deny` and `custom-response` take, so a terminated request
never reaches the upstream and carries no request there.

### Both

The actions run wherever the `on_http_request` phase runs, which since 1.0.7
means on the server for edge-terminated tunnels and in the agent for
agent-terminated ones. Nothing in the action decides the side: the policy
travels with the tunnel, and the phase evaluates where the plaintext is. As
with every action, the configs are validated when the policy is loaded and a
bad document stops the tunnel at startup with the rule named.

- **`basic-auth`** checks RFC 7617 credentials from `Authorization: Basic`
  against a list of `user:password` entries:

  ```yaml
  traffic_policy:
    on_http_request:
      - name: basic-auth
        config:
          realm: restricted          # default "ngrok"
          credentials:               # "user:password" entries; several allowed
            - alice:secret
  ```

  A request with no credentials, wrong ones, malformed base64, or a decoded
  value with no colon is answered `401` with
  `WWW-Authenticate: Basic realm="restricted"` -- the challenge is the answer
  to every credential shape the action cannot read, never a `400`.

- **`bearer-auth`** checks the token of `Authorization: Bearer <token>`
  (exactly one space, non-empty) against a static list:

  ```yaml
  - name: bearer-auth
    config:
      tokens:
        - "tok_abcdef"
  ```

  Failure answers `401` with `WWW-Authenticate: Bearer`, bare, no
  parameters.

- **`apikey-auth`** checks one request header against a static list:

  ```yaml
  - name: apikey-auth
    config:
      header: X-Api-Key          # this is the default; lookup is case-insensitive
      keys:
        - "ak-live-0001"
  ```

  Failure answers a plain `401` whose body names the configured header.
  There is deliberately no `WWW-Authenticate` for this action: no standard
  challenge exists for a custom API-key header, and inventing one would
  teach clients to send credentials to whatever header the error names.

- **`jwt-validation`** verifies a bearer JWT against a JWKS -- the
  signature, the registered claims (`exp`/`nbf` with leeway, `iss`/`aud`
  when configured), and any exact-match string claims the policy names:

  ```yaml
  - name: jwt-validation
    config:
      jwks_uri: https://idp.example/.well-known/jwks.json
      issuer: https://idp.example
      audience: my-endpoint
      algorithms: [RS256]        # default RS256
      leeway_seconds: 30         # exp/nbf clock skew, default 0
      claims:                    # optional exact-match required claims
        scope: tunnels:read
  ```

  Failure answers `401` with `WWW-Authenticate: Bearer error="invalid_token"`.

- **Credentials live as SHA-256 digests in the compiled policy.** Every
  comparison is `crypto/subtle` over two equal-length digests, the whole
  credential list is walked with no short-circuit, and the plaintext values
  are garbage-collectable after load: a heap dump of a running edge holds
  digests, not passwords. Nothing credential-shaped reaches a log line or a
  response body by construction -- the JWT library's own errors are mapped
  to fixed labels before logging, because their text can quote claim values,
  and a claim value is credential material.

- **The JWKS is fail-closed, and the cost is stated plainly.** Keys are
  fetched on first use and cached by `kid`, bounded, with one refetch on an
  unknown `kid` so an IdP key rotation does not need a restart. When the
  `jwks_uri` cannot be fetched, every request that needs a key is refused
  with the 401 -- an IdP outage is an outage of the protected endpoint, not
  an opportunity to pass unverified tokens -- and the fetch failure is
  logged once per connection to say so.

- **The JWT algorithm allowlist is all-asymmetric, on purpose.** A policy
  may allow only {RS256, RS384, RS512, ES256, ES384, ES512, EdDSA} -- no
  `none`, no HS*: an HMAC algorithm has no honest secret to verify with
  here, and the classic confusion attack that feeds the (public) RSA key to
  an HMAC as its secret is refused structurally, before any key is looked
  up. The token's own `alg` must be in the policy's list, and the key the
  JWKS names must be of the type the algorithm family implies (RSA for RS*,
  EC for ES*, OKP for EdDSA).

- **Credentials are inline config values for now.** The policy YAML carries
  the passwords, tokens and keys itself; references into a vault or secret
  store are planned but not built. Treat a policy file that carries auth
  config as a credential: same handling, same disk.

### Known limitations

- **Auth actions compose by order, not by OR.** Two auth actions in one
  phase mean "a request must pass both": the first failure terminates, and
  there is no syntax for "any one of these would do". Put multiple
  credentials inside one action instead of stacking actions.
- **The JWT algorithm allowlist is fixed to the asymmetric set** described
  above; a deployment whose IdP signs its tokens with an HS* algorithm
  cannot be expressed, by design.
- **`leeway_seconds` defaults to 0**, so a token whose `exp` is even one
  second behind the endpoint's clock is refused; set a leeway when the IdP
  and this endpoint do not share a clock source.
- **`apikey-auth` has no standard challenge.** The 401 body names the
  required header, but nothing in the response tells a generic HTTP client
  or a browser how to authenticate: callers must send the configured header
  themselves.

## 1.0.7 - 2026-10-04 - Zero-knowledge TLS + fixed remote TCP ports

Two features about who holds the credentials of a public endpoint, plus the
first end-to-end coverage the public https listener has ever had.

**Agent TLS termination** (zero-knowledge TLS) moves the public side of an
https endpoint from the server to the agent. The server routes an incoming TLS
connection by the name in its ClientHello (SNI) and relays the records
untouched: it never terminates the TLS, never holds the certificate or its
key, and never sees the plaintext -- there is no plaintext on the server side
of these tunnels at all. TLS terminates in the agent, which then speaks plain
HTTP to the local service through the ordinary path. This is the capability
commercial ngrok gates behind paid plans; here it removes the server
certificate from the trust story entirely, because for an agent-terminated
endpoint the server's certificate is simply not involved.

**Fixed remote TCP ports** make a tcp tunnel's public port deterministic and
owned: `-remote-port N` (or the existing `remote_port` config key) claims port
N for the claiming auth token and keeps it against other tokens -- including
across the window between one registration closing and the next opening, which
is exactly the window a bare kernel bind leaves open.

**Upgrade the client and the server together.** Be precise about what enforces
this, because it is looser than it looks: the authentication handshake only
compares the wire protocol version (`version.Proto`, "2"); the software
version is exchanged for display and metrics, and the exact-equality helper
`version.Compat` in `version/version.go` is not consulted by the handshake at
all. `TLSTermination` is an additive wire field, so an older server decoding a
1.0.7 registration drops it in silence: the registration *succeeds*, and the
endpoint would come up edge-terminated while the agent arms its own TLS
terminator. That pairing is refused rather than suffered: the server's success
acknowledgement now echoes the termination mode it actually registered, and a
client that asked for agent termination shuts the tunnel down at establishment
with an error naming the version gap, instead of failing one proxied
connection at a time. The safe order is still "server first, or both at once":
a 1.0.7 server with an older client is fine (the missing field decodes as edge
termination, today's behavior), and a 1.0.7 client against an older server
refuses any tunnel configured with `agent_tls_termination`.

### Server

- **The https listener routes by SNI.** `server/sni.go` reads exactly one
  ClientHello off each accepted connection -- bounded by the same 64 KiB
  budget as the request-head parser, reassembled across fragmented TLS
  records, every consumed byte returned for replay -- and the name it finds
  decides the connection's fate. An SNI that matches an agent-terminated
  endpoint passes the connection through as raw bytes; everything else (no
  SNI, unmatched SNI, SNI on an edge endpoint, a stream that is not TLS at
  all) is replayed into the server's TLS terminator and routed by Host exactly
  as before. Edge http, edge https and tcp tunnels behave identically to
  1.0.6 modulo the cost of one peeked read.
- **Zero-knowledge joins are raw bytes, and stay raw.** For an
  agent-terminated endpoint the server's join is `conn.Join` and nothing else:
  no request hooks, no response hooks, no head parse. The property travels
  with the connection through a `forward_to` chain -- if the entry endpoint is
  agent-terminated, the chain's terminus receives ciphertext regardless of
  what kind of endpoint it is, and its hooks are skipped for the same reason.
- **`on_tcp_connect` stays server-side** and now runs on the passthrough path
  too, before an agent is asked for anything, along with the per-IP rate
  limits and connection caps. A connection refused here is closed; note the
  synthetic refusal response is written onto the raw TLS stream, so a TLS
  visitor experiences the enforcement as a closed connection rather than a
  readable 403 (see Known limitations).
- **A Host that names an agent-terminated endpoint on a terminated connection
  answers `421 Misdirected Request`.** The server will never pipe plaintext
  into such a tunnel, and 421 is the one status that tells a client it used
  the right name over the wrong connection: reconnect naming the endpoint's
  hostname (SNI).
- **Fixed remote ports are owned by an auth token** (`server/portclaims.go`).
  The claim is consulted before the kernel sees the bind: a port another
  token holds is refused with "remote port %d already claimed by another auth
  token"; a port the server itself listens on is refused with the listener
  named; the same token re-claiming (a reconnect, another pooling member) is
  allowed and never opens a free window. The claim is released when the
  tunnel's teardown runs, and a bind that then fails (privileged port, foreign
  process) releases it again rather than locking the account out of its own
  request.

### Client

- **`agent_tls_termination: true`** on a tunnel (or `-agent-tls-termination`
  for the default tunnel) moves that tunnel's https leg to the agent. The
  certificate comes from a new `tls:` block with three models, in priority
  order: explicit `crt`/`key` (one fixed leaf); `ca_crt`/`ca_key` (the agent
  mints a short-lived leaf per SNI name on demand -- ECDSA P-256, 24h
  validity, cached per name so every handshake for a name presents the same
  certificate; the CA key never leaves the agent); or neither, which is a
  temporary self-signed certificate with a loud WARN carrying its sha256
  fingerprint. TLS 1.2 is the floor and no client certificates are requested,
  in every model.
- **Validation is at load and names the file.** A `tls:` block without the
  switch, a half-named pair, both pairs at once, or a file that is missing or
  unparseable is a startup error; a CA without `CA:TRUE` or without a
  self-signature is refused with the reason. The files are re-read per
  session, so a certificate rotated on disk is picked up at the next
  reconnect.
- **The agent-side policy split.** On an agent-terminated tunnel the
  `on_http_request` / `on_http_response` phases run in the agent, compiled
  with the same policy package the server uses, merged into the same rewriter
  that carries the header and compression semantics. `on_tcp_connect` stays
  server-side for every tunnel (it evaluates at accept time, before any proxy
  connection exists -- an agent could not enforce it at all). Plain
  edge-terminated tunnels are unchanged: their policy phases still run on the
  server.
- **Everything else survives the move, on the plaintext.** Header rewriting
  (`host_header`, add/remove), X-Forwarded-For injection, response
  compression, the inspector tee and the dead-upstream 502 -- which now goes
  out over a *completed* handshake, so a visitor sees a real 502 instead of a
  TLS decode error -- all act on the plaintext after the agent terminates.
  The e2e suite proves the header rewrite and the deny action over a live
  agent-terminated tunnel.
- **`-remote-port N`** claims a fixed public port for the default tcp tunnel,
  with the same rules the config key has (tcp only, exactly one protocol) and
  two new guardrails: a port below 1024 is refused at load with a note that
  the server process needs the privileges to bind it, and a flag value above
  65535 is refused instead of wrapping around the uint16 wire field.

### Known limitations

- **Agent-terminated endpoints need SNI-capable visitors.** The endpoint's
  name only exists in the ClientHello; a client that sends no SNI cannot be
  routed, terminates at the server, and gets the 421 described above. IP-literal
  access to an agent-terminated hostname is therefore impossible by design.
- **A forward chain carries the entry's passthrough with it.** An
  agent-terminated endpoint with a `forward_to` delivers ciphertext to the
  chain's terminus even when that terminus is a plain HTTP endpoint, so the
  terminus's own `on_http_*` phases and header rewrites do not run for those
  connections. Serve agent-terminated traffic from the endpoint that
  terminates it.
- **The ephemeral cert model shows browser warnings by design.** A
  self-signed certificate is exactly what the WARN says it is; the fingerprint
  in the log pins which certificate a visitor that skipped verification
  actually saw. Configure `tls.crt`/`tls.key` or `tls.ca_crt`/`tls.ca_key`
  to make it go away.
- **An `on_tcp_connect` denial on an agent-terminated endpoint is silent to a
  TLS visitor.** The refusal is written before any TLS termination exists on
  the path, so the bytes cannot be read by the visitor; enforcement is the
  closed connection. The same denial on an edge endpoint still answers with
  the readable 403.
- **Fixed ports below 1024 need a privileged server process**, and a claimed
  port the kernel cannot bind (foreign process, permissions) surfaces the
  underlying bind error -- the ownership registry refuses claims it knows
  about, it does not reserve the port against the rest of the machine.
- **CA-minted leaves live 24 hours** and the per-name cache is per tunnel
  session: a visitor pinning a leaf instead of trusting the CA will see the
  leaf change across agent restarts. Trust the CA, not the leaf.
- **A tight restart loop on a fixed port can lose the bind race.** Ownership
  is claimed and released cleanly across restarts, but the kernel can still
  hold the listening socket for a moment after the old process closes it, so
  a client restarted with no settle delay can see the explicit-port
  registration fail with a bind error (the claim is released again and the
  next registration can take the port). A restart with even a short pause
  between stop and start does not hit it.

## 1.0.6 - 2026-09-27 - Security hardening release

A hardening pass over ngrokd, the agent and the policy engine, from a fuzzing
and review report against the 1.0.5 tree. Nothing in the feature set changed:
this release is about what a hostile or merely malformed peer can make the
server do.

**Upgrade the client and the server together.** The proxy and mux paths now
require the session secret the server hands out at authentication, so a 1.0.6
server refuses an older client's proxy connections rather than serving them
unauthenticated. An old server ignores the new field, so a 1.0.6 client talking
to one is not refused -- it just does not get the protection. Mixed deployments
therefore either fail (old client, new server) or are silently unprotected (new
client, old server), and there is no version of this that is safe to run half
upgraded on those paths.

### Server

- **Session secret authentication on the proxy and mux paths.** The Auth
  response now carries a per-session secret, and `RegProxy` / `RegMux` have to
  present it; the comparison is constant time. A client id alone -- which is
  public, it is the tunnel's own id -- is no longer enough to register a proxy
  connection or a mux session. See the upgrade note above.
- **Pooled endpoints enforce ownership.** A client can only join the pooling
  bucket for its own endpoints; the bucket key is scoped to the owning
  registration, so a name collision cannot put a stranger's traffic on your
  agent.
- **The `.internal` namespace is enforced server-side.** A public request for an
  internal hostname is a miss by construction: internal endpoints resolve only
  through the `forward_to` chain, and the lookup is namespaced by owner.
- **Public request heads are bounded.** The head on a public HTTP connection is
  read by a bounded parser (64 KiB cap, per head and per line) that answers
  `431` past the cap instead of growing with the request, and it refuses while
  routing -- before an agent is asked for a proxy connection. The cap is the
  reader's buffer, so neither one enormous header line nor a great many ordinary
  ones can make the edge hold more than that.
- **A head goes out declaring one framing, not two.** A message carrying both
  `Transfer-Encoding: chunked` and a `Content-Length` is a request-smuggling
  shape -- two disagreeing statements of where the body ends, and the next hop
  is free to believe the other one -- so the Content-Length is dropped from the
  emitted head in both directions, per RFC 7230 §3.3.3 ("a sender MUST NOT send
  a Content-Length header field in any message that contains a
  Transfer-Encoding header field"). The test is the chunked *token*, not the
  presence of the field: a Transfer-Encoding this build cannot frame with keeps
  the Content-Length that describes the bytes actually copied.
- **Terminate and park are atomic and generation-keyed.** A connection that is
  terminated while it is parked can no longer be handed a response generated for
  a previous occupant of the same slot, and a park/terminate race can no longer
  lose a wake-up. The synthetic responses the edge writes itself (`404`, `431`,
  `502`, policy answers) carry the generation of the connection they were built
  for, so a pipelined or recycled connection cannot be served the wrong one.
- **The `404` for an unknown host escapes the Host value and sets a
  Content-Type.** The hostname is echoed back, so it is escaped now, and the
  response is served as text.
- **Token checks run before version negotiation**, so an unauthenticated peer
  cannot use the handshake as an oracle for which versions this build speaks.
- **Affinity cache files are written `0600`.** The cache holds the mapping from
  a client to its assigned server; it is now created with the permission a file
  that describes other people's sessions deserves, and an existing file is
  re-`chmod`ed on the next rewrite rather than left as it was found.
- **The server's config file is decoded strictly.** A key the server does not
  know -- `auth_toknes`, a rate limit nested one level too deep -- fails the
  load instead of being discarded, so a misspelling cannot silently leave the
  server unprotected.

### Policy

- **The CEL environment is strict.** A policy that references a variable this
  build does not declare is a load error instead of a rule that evaluates
  differently than it reads.
- **Header values with CR or LF are refused at load**, as are unknown
  `add-headers` config fields. A policy that cannot be enforced as written is a
  load error, not a rule that quietly skips.
- **A policy is capped at 1000 actions**, so a document cannot turn the request
  path into an unbounded compile.
- **An unparseable request head is refused, not forwarded, when a request hook
  is armed.** A request-phase action is handed a parsed request, so a head the
  rewriter cannot parse -- past the 64 KiB read limit, or malformed (a folded
  continuation line, a field line without a colon, a field name that is not a
  token) -- is a request whose rules cannot be evaluated at all; the old answer
  was fail-open (forward the bytes unrewritten), which let anyone who could pad
  a head past the limit, or add one folded header line, choose to be subject to
  no policy. With a request hook armed the connection now gets a `431`, the
  origin sees none of it, and the refusal is sticky for the connection, so a
  well-formed request pipelined behind the refused one is not forwarded either.
  Without a hook the old fail-open contract stands byte for byte; the response
  direction is untouched (see the known limitations).
- **Validation messages are deterministic.** The list of actions a phase
  implements is derived from the same table the engine enforces -- sorted, not
  hand-maintained -- so the message that tells an operator what they could have
  written cannot go stale or vary between runs.
- **One header-validation gate.** The rule for a legal header name, the
  `user-agent` prohibition and the CR/LF rule existed in three copies (the
  config loader, the rewriter and the policy validator). The loader now builds
  the same `rewriter.Policy` it would run and validates *that*, so a tunnel
  which loads is a tunnel the writer can write. This closes the fuzzing report's
  R1: a value refused by the writer used to be accepted by a loader that carried
  its own copy of the rules.

### Both

- **yaml.v3 instead of yaml.v1.** Flow-shaped documents now load
  (`proto: {http: 8080}` was a parse error), and a malformed file is an error
  message instead of a panic -- the v1 scanner read past the end of its buffer
  and had no recovery story. The policy rule shape is unchanged and still flat;
  see "The rule shape, and where it differs from ngrok" below for what nesting
  does.
- **Session secrets never appear in the log or the event stream.** Not at DEBUG,
  not in a refusal message, not in an event payload -- there is a test that runs
  every path that touches the secret and greps both.
- **A config file can no longer disable the rate limits by omission.** Loading
  any `-config` file used to reset `-authRate` and `-adminRate` to 0 (the
  "disabled" value) even when the file did not mention them, because the
  "unset" sentinel for an integer key was the same as the value that means
  "off"; the limits are now only changed by a key that is actually present.
- **The client's numeric limits reject a negative value.** A negative
  `inspect_max_body_bytes` or `proxy_max_concurrency` used to be clamped to the
  default in silence, so a file that asked for a limit it did not get loaded as
  if it had asked for the default; both are load errors now, and the message
  says to omit the key to keep the default.
- **CI runs every package.** The workflow listed package paths explicitly and
  had never been updated for `./rewriter` and `./policy` -- the two packages
  these fixes live in -- so neither had a test run in CI. The test, vet and
  `-race` steps now run `./...` with the same tags.

### Known limitations

- **Policy path matching is against the raw request target.** Dot-segments are
  not normalized before a `req.url.path` expression is evaluated, so a `deny` on
  an exact path can be stepped around by a backend (or an intermediary) that
  normalizes `/a/../b` itself. Match the shape you actually control -- prefix or
  parameter patterns rather than one exact path -- or normalize at the origin.
- **An oversized response head fails open.** The 64 KiB bound and the `431` are
  on the request head; a response head larger than the reader's cap is handed to
  the agent rather than rejected, because the response is already being proxied
  and there is no correct way to un-send it. A hostile upstream can therefore
  still make an agent deal with a large response head, but it cannot make the
  edge buffer it.
- **A forward chain uses the entry endpoint's policy when the entry has one.**
  An internal endpoint protected by its own policy is protected only when the
  public endpoint that forwards to it carries no policy at all; the entry's
  rules win rather than being merged. Keep the strict rules on the entry, or
  leave the entry policy-free so the target's policy applies.
- **A request target without a Host field answers 404.** The bounded head
  parser routes on the Host field alone, so a proxy-form target
  (`GET http://svc.test/ HTTP/1.1` with no Host) no longer routes by the
  target's authority the way the old parser did.
- **A 1.0.6 client against an older server loses session resume.** The old
  server does not return a session secret, so the client re-registers as a new
  session on every control reconnect and its tunnel URL changes each time.
  Mixed deployments are unsupported on the proxy paths either way -- upgrade
  together.
- **The public-leg head buffer is 64 KiB per connection, and the per-IP rate
  limits are off by default.** A hostile client can still hold 64 KiB per
  connection at the edge; `-publicRate` and `-maxConnPerIP` remain 0 (disabled)
  until an operator sets them. Public deployments should set both.

## 1.0.5 - 2026-09-27 - Traffic policy engine (server-side): restrict-ips, deny, custom-response, header and log actions

A tunnel can now carry a **traffic policy**: rules that ngrokd evaluates against
each connection, each request and each response, at the edge, before and after
the traffic reaches the agent. The policy is authored once -- as `traffic_policy`
on a tunnel in the config file, or in a file named by `-traffic-policy-file` --
and travels with the tunnel registration. The agent validates it, forwards it,
and never evaluates it: an agent that is stale, restarted or compromised cannot
change what the policy does, and a denied request never reaches your local
service at all.

A tunnel with no policy costs nothing and takes the path it always took: no hook
is built and `conn.Join` runs the raw join. That is not an optimization but the
review gate this work was held to, because the whole point of an edge control is
that adding it is not allowed to change the traffic of the endpoints that did
not ask for it.

Every action runs over both transports this server serves: the multiplexed path
every current client negotiates and the per-connection path older agents still
use. That includes the two actions that answer a request from the edge (`deny`
and `custom-response`), and the response phase runs on the answer they fabricate
as well as on one the upstream wrote -- both are exercised end to end by the
harness, over the mux path.

### Where a policy is written, and how it fails

Two spellings, one validation path:

```yaml
tunnels:
  guarded:
    hostname: guarded
    proto:
      http: 8080
    traffic_policy:      # one endpoint's policy
      on_http_request:
        - name: add-headers
          config:
            headers:
              X-From: policy
```

```bash
ngrok -traffic-policy-file=policy.yml -hostname=guarded 8080
```

The file given to the flag *is* the policy document -- its top level is the
`on_*` phases, not a `tunnels:` map -- and it applies to the endpoint the command
line describes. The path is the only thing the flag records: the file is read and
validated in `LoadConfiguration`, which is also where a config-file policy is
validated, so a policy is checked by exactly one code path no matter how it was
written. The flag is refused on a `tcp` tunnel (`-traffic-policy-file is only
supported for http and https, not tcp...`), because two of its three phases
cannot run there.

Validation is the loud kind, on purpose. A control the server cannot enforce must
not load, because the alternative -- an endpoint that looks protected and is not
-- is worse than a startup failure. At config load:

- the rule is checked against the actions this build implements, the phases each
  action may appear in, that action's own config fields, and its CEL
  expressions, and the message names all four:
  `Tunnel web: invalid traffic policy: on_http_request[0] (deny): unknown config field "body"`;
- a tunnel with no HTTP leg is refused a policy with request/response rules
  (`... traffic policy has on_http_request/on_http_response rules, which only run
  on http and https, and this tunnel has neither`);
- the same policy is compiled again by ngrokd when the tunnel registers, before
  the tunnel claims its URL, so a policy this build's server cannot compile fails
  the registration rather than leaving a half-protected endpoint up.

### The rule shape, and where it differs from ngrok

One action per rule, with the rule's name, its conditions and its config at the
same level:

```yaml
- name: add-headers        # the action's name, from the documented set
  expressions:             # optional CEL conditions, ANDed
    - 'req.url.path == "/api"'
  config:                  # the action's own fields
    headers:
      X-From: policy
```

ngrok nests instead -- a rule is a name plus an `actions:` list of
`{type, config}`. **This build cannot read that shape, and the way it fails
matters.** The document is decoded into a struct that has fields for `name`,
`expressions` and `config` and no field for a nested action list, and the
decoder is not in strict mode (`yaml.Unmarshal`, not a `Decoder` with
`KnownFields(true)`), so a key the struct does not have -- `actions:` included --
is dropped in silence. An unnamed nested rule therefore fails loudly
(`on_http_request[0]: action has no name`), but a nested rule that *is* named
after a real action -- `- name: deny` with an `actions:` list under it -- decodes
as that action with no conditions and no config, i.e. as a rule that applies to
everything. An ngrok policy pasted into this build can end up denying all
traffic. Keep the flat form; do not nest.

The yaml.v1-to-yaml.v3 parser swap changed one thing here, and only one: the
nested spelling is no longer a *parse* problem (it never was), so nothing about
it changed. What did change is flow syntax, which is now accepted where v1
rejected it -- `proto: {http: 8080}` used to fail to parse at all
(`found unexpected ':'`, a colon inside a plain scalar in a flow mapping) and
now decodes to the same map the block form does. The other two shapes in the
worked example this cluster was specified with are still refused, each for its
own reason. `headers: {"X-Policy: checked"}` is read by both parsers as a flow
mapping with one key and a null value, i.e. a set entry, and then rejected
(`"X-Policy: checked" is not a valid header name`); `vars: {who: policy}` is
rejected because `vars` must be a list of one-entry maps
(`config field "vars" must be a list of one-entry maps, got an object`). The
example above, and the one in the e2e script, is the shape that works.

Per-action config field names mirror ngrok (`headers` as a name-to-value object
for `add-headers`, as a list of names for `remove-headers`, `vars` as a list of
one-entry maps for `set-vars`, `metadata` as an object for `log`, `status_code`,
`body`, `allow`/`deny`/`enforce` for `restrict-ips`), so a policy migrated from
ngrok mostly needs its envelope rewritten.

### The actions, by phase

Rules run in the order they are written. Phases run in the order
`on_tcp_connect`, `on_http_request`, `on_http_response`; a rule with no
`expressions` always applies.

| action | `on_tcp_connect` | `on_http_request` | `on_http_response` | config |
| --- | --- | --- | --- | --- |
| `restrict-ips` | yes | -- | -- | `allow`/`deny` CIDR lists, `enforce` (default true; false logs without refusing) |
| `deny` | yes | yes | -- | `status_code` (request phase, default 403); no config at connect: there is no HTTP response to give a status to |
| `custom-response` | -- | yes | -- | `status_code` (default 200), `body`, `headers`; `content-type` is sniffed from the body when not given |
| `add-headers` | -- | yes | yes | `headers`: name -> value |
| `remove-headers` | -- | yes | yes | `headers`: list of names |
| `set-vars` | -- | yes | -- | `vars`: list of one-entry maps, referenced later as `${vars.name}` |
| `log` | yes | yes | yes | `metadata`: name -> value, interpolated, written to the server log |

`ip_policies` is recognized and refused at load (`... is not implemented in this
build (it needs the ngrok API); use allow/deny CIDRs`) rather than accepted and
ignored.

### The CEL variables

`conn.client_ip` and `conn.remote_addr` exist in every phase. `on_http_request`
adds `req.method`, `req.url.path`, `req.url.query`, `req.url.raw` (the request
target as it arrived), `req.headers`, `req.cookies` and `vars`.
`on_http_response` adds `res.status_code` and `vars` -- and deliberately not
`req.*`: the response hook is handed a head-only response and has no request to
read, so a policy that refers to the request there fails to compile at load time
instead of evaluating against a zero value that would quietly be wrong.

The subset is the whole environment. `conn.geo.*`, `endpoint.*`, `conn.tls.*` and
the rest of ngrok's surface are not declared, so a policy that names one fails to
load with a compile error naming the action. That is the same trade this package
makes everywhere: a rule that silently never matches is worse than a rule that
refuses to load.

### Parity notes worth knowing before you write a policy

- **A synthesized response ends the connection.** The edge frames it with
  `Content-Length` and `Connection: close`, so there is no keep-alive through a
  terminate and a pipelining client must reconnect. This is 1.0-compatible
  framing, and it is what the response rewriter can emit without a body-length
  guess.
- **A synthesized response runs the response phase too.** A `deny` or a
  `custom-response` is answered by the edge without an upstream ever being
  asked, and the response phase then runs on the answer it fabricated, exactly
  as it does on a real one -- ngrok's custom-response page says so outright. The
  hook is asked about a head-only response whose status is the one the client
  will see, so a rule written against `res.status_code` matches what it looks
  like it should. Headers are all it can change: the status and the body of an
  edge answer belong to the terminating action's config, and there is no
  upstream response to replace. A connection refused at `on_tcp_connect` is the
  exception -- it is answered before a request is parsed, so no request or
  response phase runs for it at all.
- **`${...}` interpolation renders strings only.** There is no typed
  substitution: a value set to a number is interpolated in its string form.
- **`req.headers` joins repeated fields with `", "`** and lower-cases the names.
  ngrok's is `map[string][]string`; this build's is `map[string]string`, so a
  header sent twice is one string with a comma in it -- which is also what makes
  `req.headers["x-forwarded-for"].contains(...)` work the way people expect.
- **`custom-response` is request-phase only in this release** (ngrok also allows
  it on the response phase).
- **`${vars.x}` is set by `set-vars` in the same phase**, in written order: a
  header value that uses a var must come after the `set-vars` rule that defines
  it. The e2e file is ordered that way deliberately, and it is the ordering that
  proves interpolation reads the current phase's vars rather than the previous
  request's.

### What the e2e covers

`scripts/e2e.sh` runs the whole set through a live tunnel: `restrict-ips`
two-sided (an allow-only test would pass with no policy at all, so the same
client address is also denied by a second tunnel's policy), a request-phase
`deny` terminating `/blocked` at the edge with an empty body, a
`custom-response` answering `/teapot` with its own status, header and body, the
response phase running on that fabricated answer (the `X-Edge` header it adds is
asserted on the 418 as well as on a real response), request-phase `set-vars` +
`add-headers` reaching the upstream, response-phase `remove-headers` +
`add-headers` reaching the public client, `log` writing interpolated metadata
into ngrokd's log, `-traffic-policy-file` feeding a policy to the default
tunnel, and a policy file the client cannot enforce stopping the client at
startup with a message naming the file and the rule.

Every policy request in the harness is bounded (15s), so a rule that never
answers fails an assertion with a status code and a message rather than hanging
the script. That bound is not padding: see the note on the wake below.

### The terminate wake, and why the harness is the only thing that caught it

The edge answers a terminated request through the *response* side of the
rewriter, which is usually already parked in a read of its upstream -- the
request that would have provoked a response was never forwarded. Waking that
read is the whole trick, and the first implementation got it wrong in a way no
unit test could see: it woke it with `SetReadDeadline(time.Now())`. That works on
a `net.TCPConn` and on `net.Pipe`, and does not work on a **smux stream**, which
is what the server hands the rewriter on the mux path every current client
negotiates. `smux.Stream.SetReadDeadline` only stores the value
(`stream.go:339`), and `waitRead` samples it **once, at entry**
(`stream.go:194`), so a read already parked never learns a deadline was set. The
response side stayed parked, the request side kept draining a public connection
that never EOFs, the client got zero bytes, and `conn.Join` waited on both legs
forever, leaking the handler goroutine.

The unit test passed because its test double implements `SetReadDeadline` by
closing a channel -- which is how a TCP conn behaves, and not how a mux stream
does. The e2e found it through a real tunnel, and a goroutine dump of the hung
ngrokd named both parked legs (`stepDrain` on the public conn,
`smux.Stream.waitRead` on the proxy stream).

The wake is now `Close()` on the source being abandoned: it needs no
per-implementation rule to get right, it is how every `conn.Conn` in this
program ends anyway, and a terminate makes that source disposable -- the
synthetic response is the last message of the connection and `conn.Join` would
close that leg moments later. (`CloseRead` would have been the tidier half-close
and is not available: `loggedConn.CloseRead` calls `tcp.CloseRead()` on a
`*net.TCPConn` that is nil for a mux-wrapped conn, and `smux.Stream` has no
`CloseRead` at all.) The lesson worth keeping: a test double that mocks a
transport's *timeout* semantics has to be as pessimistic as the oddest transport
in the system, or it will pass exactly the case the real one deadlocks on.

## 1.0.4 - 2026-09-27 - Throughput: stream multiplexing, zero-copy legs, bench harness

All three changes go after the same cost: the per-connection setup that every
short-lived public request pays today. No numbers are quoted in this entry -- the
harness described in the last section is how they are measured, against the
pre-change binaries, and the figures belong here once they are in.

### Stream multiplexing (smux)

Public connections are now carried as streams over **one** long-lived
multiplexed connection per client session, instead of dialing `tunnelAddr` again
for each one. The old path paid a TCP connection (and its TLS handshake), an
`Auth` build, and a `RegProxy` -> `StartProxy` round trip for every public
connection; a stream costs a frame on a session that is already up.

The handshake is negotiated, not assumed. ngrokd advertises a `proxy-mux`
capability in `AuthResp.Caps`; a client that sees it opens the mux connection
once after auth and registers it with `RegMux{ClientId}`. From then on its
`ReqProxy` handler opens a stream instead of dialing, and a stream's first
message is still `RegProxy{ClientId}`, validated against the session's id. Every
component downstream of the proxy connection -- the local dial, the tee, the
header rewriter, gzip, `conn.Join`, pooling -- is unchanged, because a stream is
wrapped into the same `conn.Conn` a TCP proxy connection was. Multiplexing
removes setup round trips; it does not touch the data path.

The wire addition is additive and the capability gates it, so there is no
version bump and no flag day:

- An agent that does not negotiate `proxy-mux` (any build before this one) keeps
  using the per-connection proxy pool, and ngrokd serves both kinds of client at
  the same time. A deployment upgrades and downgrades one agent at a time.
- Both paths can be live in one process, so a rolling restart cannot strand a
  client on a path the server no longer serves.

**The mux connection is a shared failure domain, and that is the real cost of
this change.** Every stream on it dies with it: a network blip, a stalled
connection, or a server restart takes down all of that agent's in-flight public
connections at once, where the old per-connection path lost at most the one
connection that was in flight. The agent watches the session and reconnects with
bounded retries, so new requests recover on their own, but requests that were in
flight are **dropped, not replayed** -- nothing above the transport knows whether
a half-written request is safe to send again. On a lossy network this trades
setup latency for a coarser blast radius; the per-connection path is the safer
choice if that trade is not acceptable yet.

Smaller costs worth knowing: smux buffers per stream (window memory that grows
with concurrent streams), and the number of streams a session will carry is
bounded by smux's defaults rather than by a setting of ours.

### Zero-copy copy legs

The wrapped connection now implements `ReadFrom` and `WriteTo`, delegating to the
underlying `*net.TCPConn` when there is one. That is enough for `io.Copy` to
reach `splice(2)` on Linux, so the tunnel legs move bytes between sockets in the
kernel instead of through a userspace buffer. `conn.Join` also stops copying
through 32 KiB buffers and uses a 256 KiB one.

Two honest qualifications:

- `splice` only happens when both legs are plain TCP and nothing sits between
  them. The tee, the header rewriter and gzip all run on `conn.Conn`, so a tunnel
  with compression on (the default) or a tee in the path cannot be splice-only --
  the copy falls back to userspace for those legs.
- macOS has no `splice(2)`, which is where this fork is developed and where the
  harness is run. There the visible change is the larger buffer, not zero-copy;
  a macOS benchmark cannot show the Linux win, so do not read a small macOS
  improvement as "the splice path does not work".

### Benchmark harness

New `scripts/bench.sh`, a deterministic end-to-end benchmark: a python upstream
on loopback, a real ngrokd, a real agent, and three scenarios measured through
the live tunnel.

| scenario | what it measures |
|---|---|
| bulk | 64 MiB of incompressible random bytes to `/dev/null`, MiB/s, median of 3 runs |
| conn-rate | 200 sequential requests with `Connection: close`, req/s plus p50/p95 per-request wall time |
| keep-alive | 1000 requests in one curl invocation, req/s, plus the number of TCP connections curl actually had to open |

```
bash scripts/bench.sh                        # build the working tree (-tags debug) and run once
bash scripts/bench.sh baseline_dir current_dir
```

The two-directory form (each directory holding an `ngrok` and an `ngrokd`) prints
`BASELINE | CURRENT | DELTA` and is the point of the thing: the pre-mux binaries
live in `/tmp/bench-baseline` and the comparison is what says whether the
multiplexing work paid off. Numbers also land in `/tmp/ngrok-bench-result.json`
for anything that wants to parse them, and per-variant logs in
`/tmp/ngrok-bench-*.log`.

Three details that make the table readable, because each one is a way a
benchmark lies:

- The bulk body is random and seeded, so it is reproducible but cannot be
  compressed into a flattering number; the request counts and body size are
  constants, not flags, so two runs are comparable.
- The keep-alive row reports connections opened next to req/s. `1000 requests
  over 1 connection` and `1000 requests over 1000 connections` both produce a
  large req/s, and only the second is a failure to reuse anything.
- Scenarios validate themselves (byte counts and HTTP status codes are checked
  before a number is reported) and the harness exits non-zero if one fails, so a
  broken run fails loudly instead of printing a fast number.

The harness owns ports 18180 / 15443 / 19101 / 19190, deliberately disjoint from
`scripts/e2e.sh`'s 18080 / 14443 / 19001+, so both can run at once. Its own
sanity check is to point it at the same binaries twice: on an idle machine the
deltas sit near zero, and on a busy one they can still reach 10-15%, which is the
noise floor a claimed win has to clear. The two directories are measured one
after the other rather than side by side (they need the same ports), so a machine
that changes speed mid-run shows up in the table as a delta -- worth knowing
before reading a small one as a regression.

### Measured (loopback, macOS)

The harness was run twice in opposite orders and the results averaged: the
measurement machine showed a sequential order effect of 20-40% between runs,
so a single ordering's deltas are not trustworthy on their own.

| scenario | pre-mux | mux | delta |
|---|---:|---:|---:|
| short-lived connections | 554 req/s | 641 req/s | **+15.7%** |
| short-lived p95 latency | 2.95 ms | 1.86 ms | **-37%** |
| keep-alive | ~3,500 req/s | ~3,450 req/s | neutral |
| bulk 64 MiB | ~590 MiB/s | ~618 MiB/s | within noise |

Interpretation: over loopback a TCP handshake already costs well under a
millisecond, which bounds the multiplexing win; the p95 improvement is the
part that survives. The win grows with network round-trip time: where a real
connection pays two RTTs of setup, a stream pays one frame on an established
session. The zero-copy `splice` leg cannot be measured on macOS at all -- it
only fires on Linux with plain-TCP legs, and the bulk scenario's incompressible
body is gzip-bound in both variants.

## 1.0.3 - 2026-09-27 - Internal endpoints, forward_to, endpoint pooling, response compression

### Added

Four new per-tunnel settings. Like the header flags in 1.0.2, the command-line
form feeds the tunnel synthesized for the simple `ngrok <port>` invocation; a
tunnel named in the config file uses the equivalent YAML key on that tunnel
instead.

| Flag | YAML key | Default | Effect |
|---|---|---|---|
| `-binding <public\|internal>` | `binding` | `public` | `internal` registers the endpoint in the `.internal` namespace instead of on the public listener. |
| `-pooling` | `pooling` | `false` | Lets several agents serve the same url; ngrokd round-robins connections across them. |
| `-forward-to <url>` | `forward_to` | none | Static route: connections are served by another, internal endpoint of the same account. |
| `-compression` | `compression` | `true` | Gzips eligible responses on their way back to the public client. |

Internal endpoint and forwarding tunnel in a config file:

```yaml
tunnels:
  svc:                      # reachable only from this account, through the
    proto:                  # endpoint below; the public listener 404s for it
      https: 127.0.0.1:8080
    hostname: svc.internal
    binding: internal
  public:
    proto:
      http: 127.0.0.1:8080
    hostname: public
    forward_to: https://svc.internal
    pooling: false
    compression: true
```

### Internal endpoints

`-binding=internal` (or `binding: internal`) requires `-hostname=<name>.internal`:
lowercase, ending in `.internal`, with no subdomain and no `-remote-port`, and
only over http or https (TCP internal endpoints are not in this release).
Internal endpoints are namespaced by account: two accounts may each own
`svc.internal`; with `-authtoken` unset every client is the `default` account.

An internal endpoint is invisible to the public listener. Asking for its hostname
there is answered with the usual 404 (logged distinctly, so an internal hostname
lookup is not mistaken for a typo), and the only way to reach it is a
`forward_to` from another endpoint of the same account.

The `binding: internal` half of that is not optional: a `.internal` hostname with
the default (`public`) binding is rejected at startup, because the public
listener treats every `.internal` hostname as a miss.

### forward_to

A public endpoint with `forward_to` hands its connections to an internal
endpoint: the forwarding endpoint's own local port is never dialed, and its agent
never sees the connection. The public client gets the internal endpoint's
upstream response verbatim, and `X-Forwarded-For` still carries the real public
client address. The chain is resolved at connection time, so an internal
endpoint that is offline, missing, or part of a cycle (or that exceeds the depth
limit of 8) answers **502** instead of hanging.

Limitations to know about:

- The chain does not rewrite the Host header. What the internal endpoint's
  upstream receives is what the public client sent, unless that endpoint sets
  `host_header` itself.
- Basic auth (`http_auth`) applies to the entry tunnel, the one the public client
  addressed. The internal endpoint's own auth is not consulted on a forwarded
  request.

### Endpoint pooling

`-pooling` lets several agents register the same url. ngrokd keeps them in one
bucket and round-robins each new public connection across them; every member
must opt in, so a registration without `-pooling` is still refused a url that is
already pooled, and vice versa. TCP members share a single listener, which the
member that bound it keeps until it disconnects.

Known limitations: there are no health checks, so a dead member keeps receiving
its share of connections until its control connection drops; and there is no
session affinity -- consecutive requests from one client land on different
members.

### Response compression

Eligible responses are gzipped on the way back to the public client. This is
**on by default**, matching ngrok v2, and it is a behavior change: your
upstream's bytes are no longer necessarily what the public client receives.
Pass `-compression=false` (or `compression: false` for one tunnel in a config
file) to send responses exactly as the local server wrote them.

A response is compressed only if **all** of these hold: compression is on for
the tunnel; the client sent `Accept-Encoding: gzip`; the request carried no
`Range`; both the request and the response are HTTP/1.1 or later; the status is
not 1xx, 204 or 304, and the method was not `HEAD`; the response has no
`Content-Encoding` yet; the `Content-Type` is compressible (`text/*`,
`application/json`, `application/javascript`, `application/xml`,
`application/xhtml+xml`, `application/graphql`, `image/svg+xml`,
`application/wasm`); and it has no `Content-Length` or one of at least 128 bytes.

When it applies, the head is rewritten to `Content-Encoding: gzip` plus
`Vary: Accept-Encoding`, and the body is re-framed as chunked
(`Transfer-Encoding: chunked` is added, `Content-Length` and `ETag` are dropped).
The re-framing is why HTTP/1.0 clients and responses, and `Range` requests, are
skipped: a compressed body cannot be close-delimited or byte-ranged. Trailers and
a non-chunked `Transfer-Encoding` from the upstream are dropped in gzip mode,
because they describe the body being replaced. Anything not covered above keeps
the previous byte-identical behavior.

### Fixed

- A data race in the shared random-number generator: connection ids and random
  tunnel URLs are now drawn under a lock, so concurrent connections no longer
  race (found by the cluster-2 server tests under `-race`).

### Configuration errors

Bad endpoint configuration fails at startup, naming the tunnel and the offending
value, rather than turning into a 502 (or silence) at request time:

- `binding` must be `public` or `internal` (`public` normalizes to unset).
- `binding: internal` requires a `.internal` hostname: `-binding=internal`
  without `-hostname` says so and points at `-hostname=<name>.internal`.
- `forward_to` must be an http or https URL whose host ends in `.internal`, with
  the same scheme as the internal endpoint is registered with (the internal
  registry key carries the scheme), no path, query, port or credentials.
- `forward_to` and `binding: internal` are only valid on http/https tunnels, not
  TCP ones.
- A hostname ending in `.internal` requires `binding: internal`; the combination
  is refused because the public listener never routes `.internal` hosts.

## 1.0.2 - 2026-09-27 - HTTP header control

### Added

Five new client flags for HTTP tunnels, mirroring ngrok's header options. Each one
also has a config-file equivalent, set per tunnel.

| Flag | Repeatable | Effect |
|---|---|---|
| `-host-header <value>` | no | `rewrite` sets the Host header of requests sent to your local server to the local address's hostname, `preserve` (the default) leaves it untouched, or pass an explicit hostname to force. The original Host is reported to your server as `X-Forwarded-Host`. |
| `-request-header-add <key:value>` | yes | Appends a header to the request sent to your local server. If the key is already present it is appended again, except `host`, which is overridden. |
| `-request-header-remove <key>` | yes | Removes every request header with that name (case-insensitive). |
| `-response-header-add <key:value>` | yes | Appends a header to the response sent back to the public client. |
| `-response-header-remove <key>` | yes | Removes every response header with that name (case-insensitive). |

Example: expose a local Ollama server that only answers requests whose Host is
`localhost`, and hide the identifying `Server` header:

    ngrok -host-header=rewrite -response-header-remove=Server 11434

The same tunnel in a config file:

```yaml
tunnels:
  ollama:
    proto:
      http: 127.0.0.1:11434
    host_header: rewrite
    request_header:
      add: ["X-Custom: value"]
      remove: ["X-Secret"]
    response_header:
      add: ["X-Served-By: ngrok"]
      remove: ["Server"]
```

### Configuration errors

Bad header configuration fails at startup rather than on the wire, naming the
tunnel and the offending entry:

- `host_header` must be `rewrite`, `preserve`, or a hostname with no spaces, no
  `/` and no CR/LF.
- Add entries must be `key:value` with a non-empty key; keys must be valid HTTP
  header names (RFC 7230 tokens).
- `user-agent` may not be added or removed.
- Any CR or LF in a value is rejected (header-injection guard).

### Behavior changes to be aware of

- `X-Forwarded-For` and `X-Forwarded-Proto` are now injected on every HTTP/HTTPS
  tunnel, even when no header flags are set. `X-Forwarded-For` replaces any value
  the public client sent, so upstreams can trust it for the real client IP.
- `Location` response headers are **not** rewritten when the Host is rewritten
  (ngrok does rewrite them). Deferred to a follow-up release.
- TCP tunnels are unaffected: header settings are validated but never applied.
- Response header actions apply to the final response only; interim 1xx
  responses (e.g. `100 Continue`, `101 Switching Protocols`) pass through
  unchanged.
- Known limitation: if a keep-alive connection pipelines a `HEAD` followed by
  a body-bearing request before the first response returns, the HEAD's
  response body may be mis-framed; the connection then fails open to raw
  passthrough (no data loss, rewriting stops).

## 1.0.0 - 2025-12-13
- Initial release of modernized ngrok fork
- Updated to work with Go 1.21+
- Migrated from GOPATH to Go modules
- Fixed deprecated API usage (rand.Seed, io/ioutil)
- Added optional server-side authentication via auth tokens
- Made TLS certificates optional (falls back to system root CAs)
- Added GitHub Actions workflow for automated releases
- Improved build system and documentation
