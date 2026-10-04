# Changelog
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
