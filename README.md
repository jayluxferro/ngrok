# ngrok - Self-Hosted Secure Tunnels to Localhost

ngrok is a self-hosted tool that creates secure tunnels to localhost, allowing you to expose local servers to the internet. This is a modernized fork of the original ngrok v1 codebase, updated to work with current Go versions (1.21+).

**This project is designed for self-hosting** - you run both the client and server yourself, giving you complete control over your tunnels and data.

## Features

- **HTTP/HTTPS Tunneling**: Expose local web servers to the internet
- **TCP Tunneling**: Tunnel arbitrary TCP traffic, with fixed, owned remote ports (`-remote-port`)
- **Zero-Knowledge TLS**: Terminate https TLS in the agent — the server routes by SNI and never sees plaintext or your certificates
- **Web Interface**: Inspect HTTP requests and responses in real-time
- **Terminal UI**: Beautiful terminal interface for monitoring tunnels
- **Self-Hosted**: Run your own ngrok server for complete control

## Quick Start

### Building from Source

**Requirements:**
- Go 1.21 or later
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
├── client/          # Client code
│   ├── assets/      # Generated asset files
│   ├── mvc/         # MVC framework
│   └── views/       # UI views (terminal & web)
├── server/          # Server code
│   └── assets/      # Generated asset files
├── conn/            # Connection handling
├── log/             # Logging utilities
├── msg/             # Protocol messages
├── proto/           # Protocol implementations (HTTP, TCP)
├── util/            # Utility functions
├── main/            # Entry points
│   ├── ngrok/       # Client main
│   └── ngrokd/      # Server main
└── assets/          # Static assets (HTML, CSS, JS, TLS certs)
```

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

## Command Line Options

**Client (`ngrok`):**
```bash
ngrok [OPTIONS] <local port or address>

Options:
  -config=path       Configuration file path (default: ~/.ngrok)
  -log=path          Log file path (default: stdout)
  -log-level=level   Log level: DEBUG, INFO, WARN, ERROR
  -log-format=format Log format: text or json
  -subdomain=name    Request a specific subdomain
  -hostname=name     Request a specific hostname
  -authtoken=token   Authentication token (for self-hosted server)
  -remote-port=N     Claim this fixed public port for a tcp tunnel (reconnects keep it;
                     another auth token is refused it)
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
  -adminAddr=:9090   Admin address for /healthz and /metrics (empty to disable)
  -config=path       YAML config file for ngrokd options
  -adminAuth=u:p     Basic auth for all admin endpoints
  -adminToken=token  Header token for admin endpoints (X-Ngrok-Admin-Token)
  -adminRate=n       Max admin requests per minute per IP (0 disables)
  -tlsKey=path       Path to TLS private key
  -tlsCrt=path       Path to TLS certificate
  -authToken=tokens  Comma-separated list of valid auth tokens
                     Supports plaintext tokens and sha256:<hex-digest> values
  -hashToken=token   Print sha256 token hash in format sha256:<hex> and exit
  -log=path          Log file path (default: stdout)
  -log-level=level   Log level: DEBUG, INFO, WARN, ERROR
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
3. **Message Format**: Netstring-encoded JSON messages

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

## Modernization

This fork has been updated to work with modern Go versions:

- ✅ Updated to Go 1.21+
- ✅ Migrated to Go modules
- ✅ Fixed deprecated APIs (`rand.Seed`, `ioutil` functions)
- ✅ Updated project structure for Go modules
- ✅ Modernized build system

## License

See [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.
For release notes/changelog entries, use [docs/CHANGELOG_TEMPLATE.md](docs/CHANGELOG_TEMPLATE.md).

## Related Projects

- [Original ngrok v1](https://github.com/inconshreveable/ngrok) - The original archived repository
- [ngrok cloud service](https://ngrok.com) - Commercial managed ngrok service (not related to this self-hosted project)

## Acknowledgments

This is a modernized fork of the original ngrok v1 codebase developed by [inconshreveable](https://github.com/inconshreveable). The original codebase was actively developed from 2013-2016.
