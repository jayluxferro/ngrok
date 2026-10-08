# ngrok - Self-Hosted Secure Tunnels to Localhost

ngrok is a self-hosted tool that creates secure tunnels to localhost: you run both the server (ngrokd) and the client yourself, with complete control over your tunnels and your data. It is an independent, actively developed fork of the original ngrok v1 codebase (see [Acknowledgments](#acknowledgments)) — a decade of porting work plus traffic policies, zero-knowledge TLS, UDP tunnels, a QUIC transport, secret vaults and event export that the original never had.

## Features

- **HTTP/HTTPS tunneling** — expose local web servers, with header control (host rewrite, add/remove, X-Forwarded-*)
- **Wildcard hostnames** — `hostname: "*.example.com"` serves every otherwise-unregistered name one label under the server's own domain; exact registrations always win
- **TCP tunneling** — arbitrary TCP, with fixed, owned remote ports (`-remote-port`)
- **UDP tunneling** — datagram-preserving public UDP (DNS, game servers, IoT devices), per-flow admission, same owned ports
- **Zero-knowledge TLS** — terminate https in the agent; the server routes by SNI and never sees plaintext or your certificates
- **HTTP/2 visitors** — opt-in `alpn: ["h2", "http/1.1"]` on agent-terminated tunnels serves h2-mandatory clients (gRPC) by raw passthrough; HTTP/1 visitors on the same tunnel keep the fully rewritten path
- **Upstream HTTP/2** — `upstream_protocol: http2` speaks h2c to the local service (gRPC servers, h2 APIs) while the visitor leg stays HTTP/1.1 with rewriting, policies, compression and XFF intact — the mirror of `alpn` h2 passthrough
- **Traffic policy engine** — CEL-expressed rules per tunnel: deny, custom responses, header actions, IP restrictions, and request authentication (basic-auth, bearer, API key, JWT via JWKS)
- **Single sign-on (OIDC)** — an `oidc` policy action redirects unauthenticated visitors through your identity provider (authorization-code + PKCE, HMAC-signed sessions, no server-side state) and forwards the verified identity as `X-Forwarded-*` headers
- **Secret vaults** — credentials sourced from files or the environment via `secret("vault/key")`, digests-only-on-disk supported
- **Event export** — the server's event stream to HTTP collectors or JSONL files, with visible drop accounting
- **QUIC agent transport** — the agent↔server multiplexed connection rides QUIC when enabled (no TCP head-of-line blocking across streams), with automatic smux fallback
- **Endpoint pooling & compression** — share one public endpoint across agents; gzip response compression
- **Web inspector & terminal UI** — inspect HTTP traffic in real time

## Quick Start

### Building from Source

**Requirements:**
- Go 1.23 or later (the go.mod directive is the authority)
- Make (optional, for using the Makefile)

**Build the client and server:**
```bash
git clone <repository-url>
cd ngrok
make
```

This will create:
- `bin/ngrok` - The client binary
- `bin/ngrokd` - The server binary

**Build individual components:**
```bash
make client    # Build only the client
make server    # Build only the server
```

**Build release versions:**
```bash
make release-client  # Client with embedded assets
make release-server  # Server with embedded assets
make release-all     # Both release versions
```

### Running ngrok

**Basic setup:**
1. Start your ngrok server (see [Self-Hosting](#self-hosting))
2. Create a config file `~/.ngrok`:
   ```yaml
   server_addr: your-server.com:4443  # Tunnel control port (not HTTP/HTTPS ports)
   trust_host_root_certs: true
   ```
3. Run the client:
   ```bash
   ./bin/ngrok -config=~/.ngrok 8080
   ```

Or use command-line options:
```bash
./bin/ngrok -config=~/.ngrok -subdomain=myapp 8080
```

## Self-Hosting

You can run your own ngrok server for complete control over your tunnels. See [docs/SELFHOSTING.md](docs/SELFHOSTING.md) for detailed instructions.

**Quick setup:**
1. Get an SSL certificate for your domain (wildcard recommended: `*.example.com`)
2. Set up DNS: point `*.example.com` to your server's IP
3. Compile the server: `make release-server`
4. Run the server:
   ```bash
   # Without authentication (accepts all connections):
   ./bin/ngrokd -tlsKey="/path/to/tls.key" -tlsCrt="/path/to/tls.crt" -domain="example.com"
   
   # With authentication (requires valid tokens):
   ./bin/ngrokd -tlsKey="/path/to/tls.key" -tlsCrt="/path/to/tls.crt" -domain="example.com" -authToken="your-secret-token"
   ```

## Development

### Project Structure

```
ngrok/
├── client/          # Agent: model, config, CLI, agent-TLS termination
│   ├── mvc/         # MVC framework
│   └── views/       # UI views (terminal & web)
├── server/          # ngrokd: listeners, registry, policy enforcement,
│   │                #   UDP flows, event export, admin API
├── policy/          # Traffic-policy engine: CEL envs, actions, vaults, JWKS
├── rewriter/        # Streaming header rewriter (the data-path brain)
├── conn/            # Connection plumbing, zero-copy, pooling
├── msg/             # Wire messages + redaction
├── proto/           # Protocol identities (HTTP, TCP, UDP) + datagram framing
├── log/             # Logging
├── util/            # Utilities
├── main/            # Entry points (ngrok client, ngrokd server)
└── assets/          # Static assets (HTML, CSS, JS, TLS certs)
```

Design documents for every feature live in [docs/specs/](docs/specs/README.md).

### Development Workflow

**Debug builds** (read assets from filesystem):
```bash
make client    # Debug client
make server    # Debug server
```

**Release builds** (embed assets in binary):
```bash
make release-client
make release-server
```

**Local development setup:**

1. Add to `/etc/hosts`:
   ```
   127.0.0.1 ngrok.me
   127.0.0.1 test.ngrok.me
   ```

2. Run the server:
   ```bash
   ./bin/ngrokd -domain ngrok.me
   ```

3. Create `debug.yml`:
   ```yaml
   server_addr: ngrok.me:4443
   tunnels:
     test:
       proto:
         http: 8080
   ```

4. Run the client:
   ```bash
   ./bin/ngrok -config=debug.yml -log=ngrok.log start test
   ```

### Code Organization

- **Protocol**: Message definitions and wire format in `msg/`
- **Client**: Main logic in `client/`, MVC pattern for UI
- **Server**: Tunnel management in `server/`
- **Assets**: Static files in `assets/`, embedded via go-bindata

See [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) for more detailed development information.

## Configuration

ngrok reads configuration from `~/.ngrok` by default. You can specify a custom config file with `-config`.

**Example configuration:**
```yaml
server_addr: your-server.com:4443  # Tunnel control port (default: 4443, TLS-encrypted)
inspect_addr: 127.0.0.1:4040       # Local web interface for inspecting requests
inspect_auth: admin:secret         # Optional: basic auth for inspector UI
inspect_token: some-token          # Optional: header token for inspector (X-Ngrok-Inspect-Token)
inspect_max_body_bytes: 1048576    # Optional: max captured request/response body bytes
proxy_max_concurrency: 64          # Optional: max concurrent proxy setup workers on client
trust_host_root_certs: true        # Trust your server's TLS certificate
auth_token: your-auth-token        # Optional: Authentication token (if required by your server)

tunnels:
  web:
    subdomain: myapp
    proto:
      http: 8080
  api:
    hostname: api.example.com
    proto:
      https: 3000
  tcp:
    remote_port: 12345
    proto:
      tcp: 3306
```

**Wildcard hostnames.** A tunnel whose `hostname` is `*.<your server's
domain>` serves every otherwise-unregistered name exactly one label under
that domain, and coexists with exact tunnels — the exact registration
always wins, the wildcard serves the rest:

```yaml
tunnels:
  api:
    hostname: api.example.com   # exact: always wins over the wildcard
    proto:
      http: 3000
  catchall:
    hostname: "*.example.com"   # one label deep: anything.example.com,
    proto:                      # never a.b.example.com, never example.com
      http: 8080
```

The base must be the server's own domain (`-domain`/`$VHOST`), and the
binding is http/https only. An exact name under a live wildcard stays
independently registerable, and a second auth token's wildcard over the
same base is refused (pooling's same-owner rule).

**Zero-knowledge TLS (agent-side termination).** With `agent_tls_termination`
the server routes an https connection by the hostname in the visitor's TLS
ClientHello (SNI) and relays the bytes unread: it never terminates the TLS,
never holds your certificate or key, and never sees plaintext. TLS ends in the
agent, which then speaks plain HTTP to your local service:

```yaml
server_addr: your-server.com:4443
trust_host_root_certs: true

tunnels:
  api:
    hostname: api.example.com
    proto:
      https: 3000
    agent_tls_termination: true
    tls:
      ca_crt: /etc/ngrok/ca.crt   # the agent mints a leaf per requested hostname
      ca_key: /etc/ngrok/ca.key   # the CA key never leaves this machine

  fixed-cert:
    hostname: app.example.com
    proto:
      https: 3001
    agent_tls_termination: true
    tls:
      crt: /etc/ssl/app.crt       # or present one explicit certificate
      key: /etc/ssl/app.key
```

Visitors verify against *your* certificate chain (distribute `ca.crt` to the
clients that need it), not the server's. With neither pair configured the
agent presents a temporary self-signed certificate, logs a WARN with its
fingerprint, and browsers show a certificate error — by design. Both cert
files are read and validated at startup, so a bad path or PEM fails the client
before it registers. Two limits to know: visitors must send SNI (a request
with no hostname answers `421 Misdirected Request`), and `on_http_request` /
`on_http_response` traffic policies for such tunnels run in the agent rather
than on the server — the server has only ciphertext.

**Traffic policies.** Each tunnel can carry a policy — CEL-expressed rules
evaluated per request, response, and TCP connection. The server enforces them
for edge-terminated tunnels; agent-terminated ones enforce the HTTP phases in
the agent (the server holds only ciphertext). Request rules can deny, answer
with a custom response, rewrite headers, or restrict source IPs:

```yaml
tunnels:
  guarded:
    hostname: app.example.com
    proto:
      http: 8080
    traffic_policy:
      on_tcp_connect:
        - name: restrict-ips
          config:
            cidrs: ["203.0.113.0/24"]     # everyone else: connection refused
      on_http_request:
        - name: deny
          expressions: ['req.url.path.startsWith("/admin")']
          config:
            status_code: 403
```

The full action set (header actions, `custom-response`, `log`, `set-vars`, the
authentication actions below) with exact config shapes is in the
[changelog](docs/CHANGELOG.md); policies can also live in their own file via
`traffic_policy_file:`.

**Traffic-policy authentication.** An `on_http_request` policy can require a
credential before a request is forwarded at all — the edge answers `401`
itself and the upstream never sees the attempt. `basic-auth` checks RFC 7617
credentials and answers with a `WWW-Authenticate` challenge; `jwt-validation`
verifies a bearer JWT's signature and claims against your identity
provider's JWKS. Both run wherever the phase runs: on the server for
edge-terminated tunnels, in the agent for agent-terminated ones.

```yaml
tunnels:
  private:
    hostname: app.example.com
    proto:
      http: 8080
    traffic_policy:
      on_http_request:
        - name: basic-auth
          config:
            realm: restricted       # default "ngrok"
            credentials:
              - alice:secret
  api:
    hostname: api.example.com
    proto:
      https: 3000
    traffic_policy:
      on_http_request:
        - name: jwt-validation
          config:
            jwks_uri: https://idp.example/.well-known/jwks.json
            issuer: https://idp.example
            audience: api
            algorithms: [RS256]     # all-asymmetric allowlist; no HS*, no "none"
            leeway_seconds: 30      # exp/nbf clock skew, default 0
```

Missing or wrong credentials get a standards-shaped `401`
(`WWW-Authenticate: Basic realm="restricted"`, or
`WWW-Authenticate: Bearer error="invalid_token"` for rejected JWTs).
Credentials are held as SHA-256 digests in the compiled policy and compared
in constant time; a JWKS that cannot be fetched fails closed — an identity
provider outage is an outage of the protected endpoint, never an open door.
`bearer-auth` (static bearer tokens) and `apikey-auth` (API keys in a
configurable header, plain 401 — there is no standard challenge for a
custom header) round out the set; see [docs/CHANGELOG.md](docs/CHANGELOG.md)
for their exact config shapes and the current limitations.

**Webhook verification.** A webhook provider's deliveries can be verified
at the edge before they are forwarded: a `webhook-verification` rule checks
the provider's signature (Stripe, GitHub or Svix) over the request body and
forwards only what verifies — each provider's signing secret comes inline or
from a vault, and several secrets mean rotation:

```yaml
tunnels:
  hooks:
    hostname: hooks.example.com
    proto:
      http: 8080
    traffic_policy:
      on_http_request:
        - name: webhook-verification
          config:
            provider: stripe          # stripe | github | svix
            secrets:
              - 'secret("main/stripe")'
            tolerance_seconds: 300    # send-time skew allowed; default 300
```

Verification is fail-closed: a tampered body, wrong secret, stale timestamp,
malformed signature header — and every request whose body the engine cannot
buffer to verify (chunked, close-delimited, over the 1 MiB cap) — answers
one fixed 403, never a pass-through and never a 400.

**Single sign-on (OIDC).** Where the credentials actions ask the *visitor*
to present something, an `oidc` action outsources the question to your
identity provider: an unauthenticated visit is redirected there (authorization
code + PKCE S256), the provider's answer lands on a reserved callback path
on the endpoint's own hostname, and the local service receives the request
with the verified identity already in it — `X-Forwarded-User`,
`X-Forwarded-Email`, `X-Forwarded-Preferred-Username` — any client-supplied
copy of those fields stripped first. Sessions are HMAC-signed cookies with
no server-side state (restart- and load-balancer-safe by construction), and
`oidc_session_key` in the server config pins the signing key across
restarts. The action is enforced at the routing layer, before a proxy
connection is spent, so an unauthenticated visit costs the endpoint
nothing but the redirect:

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
            issuer: https://accounts.google.com
            client_id: "....apps.googleusercontent.com"
            client_secret: secret("main/google")
            scopes: [openid, email]
            session_duration_seconds: 3600   # ceiling 86400
```

The first request on a connection decides it (keep-alive and pipelined
requests ride the decision, like Host routing always has); the policy's
other request-phase actions still run, in order, on the authenticated
connection. Everything fails closed — a token endpoint that answers with
an error gets a fixed 403, one that cannot be reached gets a 503, and a
session cookie that fails verification simply starts a new login (a stale
cookie after a key rotation is indistinguishable from a forged one, and
neither is ever believed). Zero-knowledge (agent-terminated)
endpoints cannot carry the action and are refused at registration: the
server holds only ciphertext there, with no Host or Cookie to run the flow
on. The full decision surface — `callback_path`, `allowed_domains`,
`claims` — is documented in the [changelog](docs/CHANGELOG.md).

**Secret vaults.** Credential entries can be kept out of the policy document
and sourced from a named vault instead — `secret("vault/key")` as the whole
value, resolved once at configuration load, never per request and never
inside a policy expression:

```yaml
# ngrok client config — ngrokd speaks the same vaults: block
vaults:
  main:
    file: /etc/ngrok/vault.yml        # flat YAML map: api: "alice:s3cret"
  staging:
    env_prefix: NGROK_VAULT_STAGING_  # NGROK_VAULT_STAGING_API=... -> key "API"

tunnels:
  private:
    hostname: app.example.com
    proto:
      http: 8080
    traffic_policy:
      on_http_request:
        - name: basic-auth
          config:
            credentials:
              - 'secret("main/api")'
```

A vault file entry may be written `sha256:<hex>` — a pre-digested credential —
so the disk never holds the plaintext at all. The reference text, not the
value, is what crosses the wire to the server: each side resolves against its
own `vaults:` block, so **a vault must exist on both sides** — a server
without it refuses the registration rather than exposing an endpoint that
only looks protected. A missing vault or key fails the load loudly, naming
both; with pre-digested entries and the wire log's credential redaction, the
plaintext need never appear in a file, an env var you can avoid, or a log.

**Event export (server).** ngrokd's event stream (`tunnel_open`,
`connection_open`, `connection_close`, `auth_reject`, …) can ship to external
destinations instead of only the admin `/events` SSE endpoint:

```yaml
# ngrokd config
event_destinations:
  - type: http
    url: https://collector.example/ngrok
    auth_header: "Authorization: Bearer <token>"   # literal or secret("vault/key")
    batch_size: 100        # flush when full...
    flush_interval: 5s     # ...or when this elapses; failed POSTs retry with backoff
  - type: jsonl
    path: /var/log/ngrok/events.jsonl   # one JSON event per line, tail -f-able
```

A destination that cannot keep up never blocks the server: its queue
overflows and the loss is counted in `/metrics` — `event_drop_count` (hub
total, also `ngrokd_event_drop_count` on `/metrics/prometheus`) plus one
`event_destinations` row per destination with `type`, `target`, `dropped` and
`queue_depth`. The counters are the only record of what a stalled
destination lost — check them before trusting the stream.

**QUIC proxy transport (agent leg).** The multiplexed connection that carries
tunnel traffic between agent and server can ride QUIC instead of TCP+smux, so
a lost packet stalls only its own stream rather than every stream behind it
(TCP head-of-line blocking). It is negotiated by capability and off unless
the server opts in — the server gains a UDP listener beside its TCP tunnel
listener (a port number is two independent bindings, one per protocol):

```yaml
# ngrokd config
quic_addr: 0.0.0.0:4443   # empty (the default) = QUIC disabled
```

and the client picks a carrier — `auto` (the default) prefers QUIC whenever
the server advertised the `proxy-quic` capability and falls back to TCP+smux
on any failed QUIC dial within the same reconnect attempt; `quic` pins QUIC
(still only when the server offers it); `tcp` pins today's behavior:

```yaml
# ngrok client config
server_addr: your-server.com:4443
proxy_transport: auto     # auto (default) | quic | tcp
```

The QUIC handshake uses the tunnel listener's certificate and the same trust
decision as the control connection, and requires the ALPN protocol `ngrok` —
a peer answering with anything else fails the handshake and the client falls
back. `http_proxy` forces `tcp` regardless (an HTTP CONNECT proxy cannot
carry the UDP a QUIC session needs). **Firewall note:** the tunnel port's
*UDP* side must be open end-to-end; a path that silently drops UDP degrades
to smux on every attempt — never an outage, but never QUIC either.

**Tunnel an IoT/TCP device.** A plain tcp tunnel forwards raw bytes to a
local service port — e.g. a Levis IoT node listening on `127.0.0.1:5681`:

```yaml
  iot:
    proto:
      tcp: 127.0.0.1:5681
```

On the command line, claim a deterministic public port for it:
`ngrok -proto=tcp -remote-port=15781 127.0.0.1:5681`. A claimed port belongs
to your auth token until the tunnel closes: reconnects get the same port back,
and another token asking for it is refused at registration.

**Tunnel a UDP service.** A udp tunnel forwards datagrams, not a byte stream:
the public side is a UDP port, every datagram a public client sends arrives
whole at the local service, and replies go back out from the tunnel's public
port with that port as their source — so even a stateless client (a DNS
resolver above all) accepts the answer. Expose a local resolver:

```bash
ngrok -proto=udp 53
```

or a device that speaks UDP — the same Levis-style IoT node as above, over
its datagram protocol:

```bash
ngrok -proto=udp -remote-port=5681 127.0.0.1:5681
```

Port claims are per protocol — the kernel keeps the spaces apart, so
`udp:5353` and `tcp:5353` are different ports and can be held at once
(`remote_port` works for both).

The config-file shape works too — a tunnel whose every protocol is
port-routed simply keeps its name instead of having it silently turned into
a subdomain the endpoint cannot use:

```yaml
tunnels:
  dns:
    proto: {udp: "127.0.0.1:53"}
    remote_port: 5353
```

What UDP keeps, and what that costs: the tunnel is datagram-preserving and
adds no reliability — loss, reordering and unreachable ports behave exactly
as they would point-to-point, and a dead local service is silence, not an
error page. Admission is per **flow** (a flow is one public `ip:port` that
has sent a datagram): the first datagram runs the same gates a TCP
connection gets — rate limit, connection cap, `on_tcp_connect` — and a flow
with no traffic in either direction expires after 30 seconds on both ends. A
refused flow answers nothing at all: UDP has no protocol to deliver a 403
in, so a deny in `on_tcp_connect` (this is the one policy phase a udp tunnel
can carry) looks identical to an unreachable port. The server log says which
it was ("Traffic policy refused the flow from ...").

**Firewall note:** the tunnel's public *UDP* port must be open end-to-end.
TCP reachability proves nothing about UDP on the same number — a path that
silently drops UDP produces exactly the silence of a dead service, on every
datagram.

**Operator exposure:** a public UDP forwarder reflects what your local
service sends back to whoever established a flow — replies go only to the
flow's own source address (never a third host), admission is gated per flow
(`-publicRate`, `-maxConnPerIP`, `on_tcp_connect`), and the 30-second idle
window bounds a flow's life. If the local service amplifies (small query,
large answer), put source policy on the tunnel before exposing it.

## Command Line Options

**Client (`ngrok`):**
```bash
ngrok [OPTIONS] <local port or address>

Options:
  -config=path       Configuration file path (default: ~/.ngrok)
  -log=path          Log file path (default: none, logs to nowhere)
  -log-level=level   Log level: DEBUG, INFO, WARNING, ERROR
  -log-format=format Log format: text or json
  -subdomain=name    Request a specific subdomain
  -hostname=name     Request a specific hostname
  -authtoken=token   Authentication token (for self-hosted server)
  -proxy-transport=name
                     Carrier for the multiplexed proxy connection to the server:
                     auto (default: QUIC when the server offers it, falling back to
                     TCP), quic, or tcp. Setting http_proxy forces TCP regardless
  -remote-port=N     Claim this fixed public port for a tcp or udp tunnel (reconnects
                     keep it; another auth token is refused it; port spaces are
                     per-protocol, so tcp:N and udp:N are independent claims)
  -agent-tls-termination
                     Terminate public https TLS in this agent: the server routes by SNI
                     and relays TLS bytes unread (zero-knowledge TLS)
  -tls-crt=path      Certificate the agent presents (with -agent-tls-termination; needs -tls-key)
  -tls-key=path      Private key of -tls-crt
  -tls-ca-crt=path   CA the agent mints per-hostname certificates from
                     (with -agent-tls-termination; needs -tls-ca-key)
  -tls-ca-key=path   Private key of -tls-ca-crt; never leaves this machine
```

**Server (`ngrokd`):**
```bash
ngrokd [OPTIONS]

Options:
  -domain=name       Domain to serve tunnels on
  -httpAddr=:80      HTTP listening address (for public tunnel traffic)
  -httpsAddr=:443    HTTPS listening address (for public tunnel traffic)
  -tunnelAddr=:4443  Tunnel control connection address (for ngrok clients, TLS-encrypted)
  -quicAddr=addr     Public address listening for QUIC proxy sessions (UDP), empty
                     string to disable; the tunnel port's number works as the QUIC
                     port too (one TCP + one independent UDP binding)
  -adminAddr=addr    Admin address for /healthz and /metrics (empty by default: the admin endpoint is off unless an address is given)
  -config=path       YAML config file for ngrokd options
  -adminAuth=u:p     Basic auth for all admin endpoints
  -adminToken=token  Header token for admin endpoints (X-Ngrok-Admin-Token)
  -adminRate=n       Max admin requests per minute per IP (0 disables)
  -tlsKey=path       Path to TLS private key
  -tlsCrt=path       Path to TLS certificate
  -authToken=tokens  Comma-separated list of valid auth tokens
                     Supports plaintext tokens and sha256:<hex-digest> values
  -hashToken=token   Print sha256 token hash in format sha256:<hex> and exit
  -log=path          Log file path (default: none, logs to nowhere)
  -log-level=level   Log level: DEBUG, INFO, WARNING, ERROR
  -log-format=format Log format: text or json
  -maxMsgBytes=n     Max control/proxy message size in bytes
  -authRate=n        Max auth attempts per minute per IP (0 disables)
  -publicRate=n      Max new public conns per second per IP (0 disables)
  -maxConnPerIP=n    Max concurrent public conns per IP (0 disables)
  -pprof             Enable /debug/pprof on -adminAddr
  -statusURL=url     Query admin URL (or /metrics) and print JSON status, then exit
  -statusAuth=u:p    Basic auth for -statusURL
  -statusToken=tok   X-Ngrok-Admin-Token for -statusURL
```

**Authentication:**
- If `-authToken` is not specified, the server accepts all connections (no authentication required)
- If `-authToken` is specified, clients must provide a matching token in their config file
- Multiple tokens can be specified: `-authToken="token1,token2,token3"`

**Note:** The `server_addr` in the client config points to the `tunnelAddr` port (4443), which is separate from the HTTP (80) and HTTPS (443) ports. Port 4443 handles client control connections, while ports 80/443 handle the actual tunneled web traffic.

## Recommended Hardened Server Command

```bash
./bin/ngrokd \
  -domain=example.com \
  -tlsCrt=/etc/ngrok/tls.crt \
  -tlsKey=/etc/ngrok/tls.key \
  -authToken="sha256:<digest1>,sha256:<digest2>" \
  -adminAddr=127.0.0.1:9090 \
  -maxMsgBytes=4194304 \
  -authRate=120 \
  -publicRate=200 \
  -maxConnPerIP=100 \
  -log-format=json
```

Generate token digests with:
```bash
./bin/ngrokd -hashToken="my-secret-token"
```

Admin endpoints:
- `/` dashboard (live metrics/tunnels/events)
- `/healthz` health check
- `/metrics` JSON counters
- `/metrics/prometheus` Prometheus text format
- `/recommendations` observed-traffic-based flag tuning suggestions
- `/tunnels` per-tunnel stats
- `/events` SSE event stream
- `/debug/pprof/*` if `-pprof` is enabled

## Protocol

ngrok uses a custom protocol over TLS for secure tunneling:

1. **Control Connection**: Long-lived TCP connection for tunnel management
2. **Proxy Connections**: Separate connections for each public request
3. **Message Format**: 8-byte little-endian length-prefixed JSON messages

See [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) for detailed protocol documentation.
For production hardening guidance, see [docs/PRODUCTION_CHECKLIST.md](docs/PRODUCTION_CHECKLIST.md).

## Smoke Test

Run a lightweight local smoke check:
```bash
./scripts/smoke.sh
```

Run full local e2e tunnel validation:
```bash
./scripts/e2e.sh
```

Generate tuning suggestions from production observations:
```bash
./scripts/tune-defaults.sh http://127.0.0.1:9090
```
Optionally set `NGROK_ADMIN_TOKEN` for authenticated admin APIs.

## Benchmarks

`scripts/bench.sh` measures bulk throughput, connection rate, keep-alive rate
and TLS connection rate through a real tunnel stack, on both carrier legs
(smux and QUIC) — `BENCH_SCENARIOS="bulk conn-rate keep-alive"` runs a focused
subset. Two standing caveats the report carries in its own table: loopback has
no packet loss, so QUIC's head-of-line-blocking win cannot show there (the
numbers establish parity, not superiority), and on macOS the QUIC bulk rate
measures well behind smux because quic-go batches UDP syscalls
(`recvmmsg`/GSO) on Linux only. Run it on your target hardware before quoting
numbers.

## License

See [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.
For release notes/changelog entries, use [docs/CHANGELOG_TEMPLATE.md](docs/CHANGELOG_TEMPLATE.md).

## Related Projects

- [Original ngrok v1](https://github.com/inconshreveable/ngrok) - The original archived repository
- [ngrok cloud service](https://ngrok.com) - Commercial managed ngrok service (not related to this self-hosted project)

## Acknowledgments

This fork stands on the original ngrok v1 codebase by [inconshreveable](https://github.com/inconshreveable), actively developed 2013-2016. The port to modern Go and modules, and every feature above, is this project's own work; the design record for each is in [docs/specs/](docs/specs/README.md) and the release history in the [changelog](docs/CHANGELOG.md).
