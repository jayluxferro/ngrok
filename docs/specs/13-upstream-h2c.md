# SPEC-CLUSTER17 — Agent-side `upstream_protocol: http2` (h1↔h2c transcoding)

Status: draft (approved at workstream start; implementation begins after
CLUSTER16 lands — it owns client/config.go and client/model.go until then)

Builds on SPEC-CLUSTER16's preface guard but solves the opposite leg: there
the visitor speaks h2 and the local service must too (raw passthrough);
here the PROXY leg stays h1 — where the rewriter, policy hooks, tee and
XFF injection all live — and the LOCAL service speaks h2c. This is the
parity gap the fork's own evaluation ranked as the real one (ngrok cloud's
agent-side `upstream_protocol` opt-in), and the shape ngrok cloud itself
runs: edge speaks h1-class protocols to the agent, agent speaks h2
upstream.

## Objectives

1. `upstream_protocol: http2` on an http/https tunnel: the agent transcodes
   each h1 request from the proxy leg into an h2 stream toward the local
   service and the h2 response back into h1 — with the rewriter,
   traffic-policy phases, inspector tee, XFF injection and compression all
   running UNCHANGED on the h1 side, exactly as they do today.
2. Everything the local service receives is real h2: a gRPC server, an
   h2c API, anything that demands `PRI * HTTP/2.0` framing, is servable
   from an ordinary edge-terminated tunnel.
3. `golang.org/x/net` is promoted from indirect to direct dependency for
   `http2.Transport` — this cluster is the promotion the 16 spec deferred.
   No version bump rides it (v0.28.0 already in the graph via quic-go); the
   go.mod edit moves one require out of the indirect block, nothing else.

## Non-goals (binding)

- **No extended CONNECT, no websocket upgrade over the transcode path.** An
  Upgrade request is refused with a fixed 502 that names the
  incompatibility (below), not half-upgraded.
- **No h2 multiplexing exposed to the proxy leg.** The proxy leg is serial
  h1 per connection, as it has always been; the h2 side MAY pool multiple
  proxy connections' streams onto one local h2c connection (the transport's
  own pooling — a bonus, not a contract).
- **No visitor-leg change of any kind.** This cluster touches only the
  local dial in the agent. Edge h2 remains deferred (SPEC-CLUSTER16's
  non-goal reasoning stands).
- **No server or wire changes.** `upstream_protocol` is agent-local; the
  server never learns it and `msg/` is untouched. An old server pairs
  fine.

## Design

### 1. Config surface

```yaml
tunnels:
  grpc-edge:
    proto:
      http: 9090
    hostname: grpc
    upstream_protocol: http2   # http1 (default) | http2
```

CLI twin: `-upstream-protocol http2` feeding the synthesized default
tunnel. Validation at load, naming the tunnel and the accepted shape:

- values are exactly `http1` | `http2` (no case folding — the token is a
  config enum, not a wire advertisement, but a misspelling must fail
  loudly, and `http1` is the spelled-out default so the key reads honestly);
- http/https tunnels only: refused on tcp/udp with the `remote_port`
  family's wording (the two protocol families that have no h1 proxy leg);
- refused combined with `forward_to` — a forwarding endpoint's local port
  is never dialed, so there is nothing to transcode;
- refused combined with an `alpn` list containing `"h2"` — the two h2
  stories own the local leg incompatibly: `alpn` h2 visitors are raw
  passthrough (SPEC-CLUSTER16's guard splices visitor bytes straight
  through, so they must reach an h2c listener directly) while this cluster's
  local leg is the transcoder, which expects to parse h1. One tunnel, one
  local-leg shape; the refusal says which tool serves which need (h2
  visitors → `alpn` passthrough, h1 visitors → `upstream_protocol`). An
  `alpn` list of `["http/1.1"]` alone composes freely — every visitor is
  h1, the transcoder serves them all;
- `binding: internal` composes (an internal terminus is dialed like any
  local service), and so do policies, header settings and compression —
  the contrast with the alpn matrix is the point: those controls run on
  the h1 side, which is the side the transcoder keeps alive.

### 2. The transcoder

At the local dial in `serveProxyConnection` (client/model.go — today always
a plain TCP dial, nil TLS config), `upstream_protocol: http2` substitutes
an in-process h1↔h2 bridge:

- **The h1 half is a one-connection `http.Server`.** A `net.Pipe`; one end
  is handed to the server as its only connection (the classic one-conn
  listener adapter); the other end is the `conn.Conn` the rewriter pair
  receives as the local leg. The server does every byte of h1 parsing and
  framing in both directions — this codebase does not hand-roll framing on
  data paths, and the transcoder is a data path.
- **The h2 half is a shared `http2.Transport`.** One transport per local
  address (`AllowHTTP: true`, `DialTLSContext` returning a plain dial —
  the h2c prior-knowledge shape), so concurrent proxy connections pool
  their streams onto shared local h2c connections, which is what an h2
  local service wants. Its handler RoundTrips each parsed request and
  copies the response back; bodies STREAM in both directions (the handler
  writes while `resp.Body` reads — no buffering of either side).
- **Hop-by-hop headers** are stripped/added by net/http on both crossings
  (RoundTrip and the response write), stdlib behavior verbatim; trailers
  pass through.
- **Upgrade requests** (`Connection: Upgrade`): answered on the h1 side
  with a fixed 502 whose body names the rule — h2 has no Upgrade without
  extended CONNECT, and this release does not implement extended CONNECT.
  The refusal is built once, like every synthetic in this codebase.
- **A dead local service** surfaces exactly as the plain dial's dead
  upstream does today: the h2 dial error is answered by the agent's
  existing 502 path — no new failure vocabulary.
- The pipe end honors the conn.Conn contract (deadlines — net.Pipe has
  them; Close tears down both halves and cancels in-flight streams).

### 3. What each leg sees

| | proxy leg (unchanged) | local leg |
|---|---|---|
| Protocol | HTTP/1.1, as today | h2c prior-knowledge |
| Rewriter / XFF / compression | runs, unchanged | — (its output rides the transcode) |
| on_http_* policy phases | run where they run today | — |
| Inspector tee | h1 side, unchanged | — |
| Local service sees | — | real h2 requests, `X-Forwarded-For` among the headers, `:authority` from the rewritten Host |

## File ownership (exclusive)

- **Workstream T** (single, after 16 lands): `client/upstreamh2.go` (new —
  the transport pool, the one-conn server bridge, the Upgrade 502),
  `client/upstreamh2_test.go`, `client/config.go` + `client/config_test.go`
  (the key, the flag parse, the validation matrix),
  `client/cli.go` (the flag), `client/model.go` (the conditional dial),
  `go.mod`/`go.sum` (the x/net promotion — indirect block to direct, no
  version change).
- **Architect (after review)**: e2e group (`scripts/e2e.sh` — reuses the
  16 group's h2c helper verbatim: an edge-terminated
  `upstream_protocol: http2` tunnel, h1 curl in, asserts
  `proto=HTTP/2.0 xff=present` — the mirror image of the 16 group's
  xff=absent, and the pair of assertions is the whole two-cluster story),
  CHANGELOG, version, README, spec/index flip, commit/tag/push/CI watch.

## Testing strategy

- **Unit (T)**: transcode round-trip against an in-test h2c server
  (`x/net/http2/h2c`, the e2e helper's pattern): method/path/headers/body
  in and out; streaming (a large body through without buffering — assert
  memory or chunk timing, at minimum correctness); XFF header present on
  the h2 side; trailer passthrough; Upgrade request → the fixed 502 with
  its named body; dead local service → the existing 502 path; concurrent
  proxy connections share the pooled transport (assert the h2c server saw
  one TCP connection); validation refusals verbatim; `http1` explicitly =
  today's dial (no transcoder constructed).
- **E2E (architect)**: the group described above, plus the
  combined-with-alpn refusal and a policy (basic-auth) still enforced
  through the transcode path.

## Review gates

1. `upstream_protocol: http1` (explicit) constructs no transcoder — the
   dial is byte-for-byte today's path (grep + test).
2. The combined `alpn`-h2 + `upstream_protocol` refusal names both tools
   and which leg each owns.
3. Upgrade answers the fixed 502; dead upstream answers the existing 502;
   no new failure vocabulary exists.
4. go.mod diff is exactly the x/net move (no version bumps, no additions).
5. `msg/` untouched (client-side only, no wire change).
6. Full gates (`-tags debug -race ./...`), e2e green including the 16
   group (no regression), changelog + version + README + spec flip.
