# Changelog
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
