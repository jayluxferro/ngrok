# Changelog
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
