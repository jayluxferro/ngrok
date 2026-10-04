# SPEC-CLUSTER5: Fixed TCP ports + zero-knowledge TLS (agent TLS termination)

Status: approved. Scope decided with the user: zero-knowledge TLS only (no jwt/vault bundling),
all three agent cert models (explicit cert/key, CA-minted, ephemeral fallback). TCP fixed port
rides along (user request: "specify a specific port so it doesn't keep changing").

## 1. Objectives

1. **Fixed TCP remote ports**: let a tcp tunnel claim a deterministic server-side port, with
   ownership enforcement so no other auth token can take it (incl. across reconnects).
2. **Zero-knowledge TLS**: public https traffic routed by SNI and passed through as TLS bytes;
   the ngrokd server NEVER terminates and NEVER sees plaintext for such tunnels. TLS terminates
   in the agent, which then speaks plaintext to the local upstream. This is the self-hosting
   differentiator commercial ngrok gates behind PAYG — here the server cert stops mattering
   entirely for these endpoints.
3. Everything that makes this fork useful must keep working over agent-terminated tunnels:
   header rewriting, X-Forwarded-For injection, response compression, the inspector/analyzer,
   client traffic policies (on_http_request / on_http_response run AGENT-side where plaintext
   is visible), and the 502-on-dead-upstream path.

## 2. Non-goals

- No mTLS / client-certificate authentication of public visitors (later cluster).
- No HTTP/3 / QUIC public edge (cluster 7 handles QUIC as agent transport).
- No changes to the control/proxy/mux listener TLS (server/tls.go single-cert stays for those).
- No Location-header rewriting, no hop-by-hop stripping (unchanged from cluster 1 decisions).
- No cert storage or ACME: certs are user files on the agent host.

## 3. Background (verified code anchors)

- https listener today: `server/main.go:193-203` passes a tlsConfig to `startHttpListener`
  (`server/http.go:122-145`); every accepted conn is TLS-wrapped in `conn.Listen`
  (`conn/conn.go:91`) BEFORE `httpHandler` (`server/http.go:292-408`) routes on the plaintext
  `Host` header (`hostFromHead`, `server/http.go:287-289`). No SNI anywhere.
- Registry keys are full URLs incl. scheme (`server/registry.go:109`), looked up with
  `proto+"://"+host` (`server/http.go:350`); registration requires a live listener for the
  scheme (`server/tunnel.go:371-374`); `defaultPortMap` http:80 https:443 (`server/tunnel.go:27-30`).
- Policy split today: `on_tcp_connect` runs pre-proxy in `httpHandler`/`listenTcp`
  (`server/tunnel.go:107` connectVerdict, `server/http.go:387`); `on_http_request` /
  `on_http_response` run as rewriter hooks on the server's PUBLIC leg inside `Tunnel.join`
  (`server/tunnel.go:690-728`) — i.e. they parse plaintext that will not exist in passthrough.
- Client: `serveProxyConnection` (`client/model.go:~655-744`) dials local plaintext
  (`conn.Dial(LocalAddr, "prv", nil)`), 502 written plaintext on dial failure
  (`client/model.go:670-678`), tee wrap on the LOCAL leg (`proto/http.go:83-91` — analyzer
  assumes plaintext, and the local leg STAYS plaintext here), header rewriter wraps the
  remote leg (`client/model.go:723-744`). http and https alias the same `proto.NewHttp()`
  (`client/model.go:150-154`). Client TLS config exists only for conns TO the server
  (`client/model.go:199-225`, `client/tls.go`).
- Wire: `ReqTunnel` already carries `RemotePort uint16` (`msg/msg.go:109`); `StartProxy{Url,
  ClientAddr}` unchanged. Add ONE new field (below).
- TCP binding: `server/tunnel.go:429-430` — `if m.RemotePort != 0 { return bindTcp(port) }`;
  random otherwise. No ownership tracking; a second claimant relies on EADDRINUSE.
- e2e runs with the https listener DISABLED (`scripts/e2e.sh:47`, `-proto=http` at :161-165) —
  the whole public https path is untested today; this cluster must add coverage.

## 4. Part 1 — fixed TCP remote port

### 4.1 Semantics

- Config (exists): `remote_port: 12345` under a tcp tunnel. CLI (NEW): `-remote-port N`,
  wired into default-tunnel synthesis exactly like the other proto options. Validation
  (client, exists + extend): tcp-only, exactly one protocol, 1-65535; add clear error for
  ports < 1024 noting the server process must be privileged for those to bind.
- Server ownership registry (NEW): `portClaims map[int]owner` guarded like URL buckets.
  On ReqTunnel with RemotePort != 0: if claimed by same owner → OK (reconnect/re-registration
  releases and re-claims atomically); if claimed by another owner → refuse with
  "remote port %d already claimed by another auth token". Claim released when the tunnel
  closes (existing tunnel teardown path). This mirrors the URL-bucket ownership fix from the
  hardening release and closes the release/rebind hijack window that raw EADDRINUSE leaves.
- Collision with server's own listeners (http/https/tunnel/admin ports) → explicit refusal
  with the listener named, not a raw bind error.
- bindTcp failure path surfaces the underlying error as today (e.g. privileged port, in-use
  by a non-ngrokd process).

### 4.2 Tests

- Unit: registry claim/refuse/release/same-owner-reclaim; own-listener collision error.
- e2e: two clients (different tokens), same port → second refused with named port; first
  client restart (reconnect) reclaims its own port successfully.

## 5. Part 2 — zero-knowledge TLS

### 5.1 Wire + config vocabulary (single source of truth in msg/)

- `ReqTunnel.TLSTermination string` — `""` (default) = edge (server terminates, today's
  behavior) | `"agent"` = passthrough + agent termination. Follow the existing msg codec
  field conventions in `msg/msg.go`; absent field must decode as "" on old servers.
- Config (client, per tunnel):
  ```yaml
  tunnels:
    api:
      proto: { https: 127.0.0.1:11434 }
      agent_tls_termination: true
      tls:
        crt: /path/cert.pem      # model 1: explicit leaf
        key: /path/key.pem
        # or model 2: CA mints leaves per SNI
        ca_crt: /path/ca.pem
        ca_key: /path/ca.key
        # model 3: neither set -> ephemeral self-signed + loud WARN (fingerprint logged)
  ```
- CLI flags (default tunnel): `-agent-tls-termination`, `-tls-crt`, `-tls-key`,
  `-tls-ca-crt`, `-tls-ca-key`.
- Validation (fail loudly, client-side at load): `agent_tls_termination` requires the
  tunnel's protocols to include https; `tls.crt` requires `tls.key` and vice versa; same
  for ca pair; crt/key AND ca pair together → error ("choose explicit cert or CA, not both");
  file paths must load and parse at config load (cert parse errors name the file).

### 5.2 Server: SNI peek + passthrough routing

New file `server/sni.go` (+ `server/sni_test.go`):

- `readClientHelloSNI(r io.Reader, max int) (sni string, peeked []byte, err error)` — walks
  TLS records (5-byte headers, type 0x16), handles ClientHello split across continuation
  records, parses handshake header (type 0x01), session-id / cipher-suites / compression
  skips, walks extensions for type 0x0000 (server_name, name_type 0). Bounded by `max`
  (64 KiB, same budget as the http head parser). Malformed/garbage → error (no SNI).
  Returns ALL consumed bytes so the caller can replay them — mirror the replayConn pattern
  from `server/http.go:161-176`.

https listener restructure (`server/main.go` / `server/http.go`):

- The https listener stops pre-wrapping conns with tls.Server. Per accepted conn:
  1. Peek ClientHello (bounded). No/failed parse → treat as SNI-absent.
  2. If SNI present: registry lookup `https://<sni-host>` (bucket, owner-agnostic resolve
     like the Host path).
     - Bucket found AND tunnel is agent-terminated → run connectVerdict (on_tcp_connect —
       still server-side, pre-proxy, exactly like the http path), then passthrough: send
       StartProxy, join replayed-bytes + rest AS RAW BYTES (no rewriter hooks — server
       cannot see plaintext; document loudly in Tunnel.join).
     - Bucket found, edge-terminated → wrap replayed conn in tls.Server (server cert as
       today) → existing httpHandler Host routing. No behavior change beyond the peek.
     - No bucket → terminate with server cert → httpHandler → today's 404-by-Host path.
  3. SNI absent → terminate with server cert → httpHandler (today's behavior).
- New edge case, explicit: Host-routed lookup finds an AGENT-terminated tunnel but the
  connection was already terminated (SNI absent or mismatched) → respond
  `421 Misdirected Request` (new response const + helper alongside notFoundResponse), log
  at WARN. Never pipe plaintext into an agent-terminated tunnel.
- The plain-http listener path is untouched.
- `startHttpListener`'s proto-derivation (`server/http.go:132-135`) stays; the peek happens
  inside the https variant only.

### 5.3 Agent: termination, certs, policy phases

New file `client/tlsagent.go` (+ tests):

- `agentTLSConfig(tunnelCfg) (*tls.Config, error)` implementing the three models in priority
  order: (1) explicit crt/key — loaded, parsed, leaf checked non-empty; (2) ca_crt/ca_key —
  `GetCertificate` mints a leaf per SNI on demand (ECDSA P-256, SANs = SNI name, 24h
  validity, small cache keyed by name; CA key never leaves the agent); (3) ephemeral
  self-signed (one per tunnel session) + WARN log with cert fingerprint and a hint to
  configure tls.crt/ca_crt. All models: MinVersion TLS 1.2, no client certs.

`serveProxyConnection` (`client/model.go`), when the tunnel is agent-terminated:

1. Dial local upstream first (unchanged order, `conn.Dial(LocalAddr, "prv", nil)`).
2. `plain := tls.Server(remoteConn /* the proxy/mux stream */, cfg)`; run Handshake with the
   established deadlines conventions. Handshake failure → close + WARN (public client gets a
   TLS alert; nothing leaks).
3. If local dial failed: complete handshake, write the existing plaintext HTTP/1.0 502 over
   `plain`, close. (Browsers then show a real 502 instead of a TLS decode error.)
4. Tee-wrap `plain` for the inspector (local-leg plumbing reused — analyzer sees plaintext,
   zero changes to proto/http.go).
5. Compile the tunnel's traffic policy doc client-side with the SAME policy package API the
   server uses in Tunnel.join; build RequestHook/ResponseHook; run on_http_request /
   on_http_response over `plain` via `rewriter.NewConnPair(plain, localConn, policy-with-
   hooks + the tunnel's existing header/compression policy)`; Join. If the policy has no
   http phases, hooks are nil and the rewriter carries only header/compression semantics —
   exactly today's path.
6. on_tcp_connect remains server-side (it runs before the proxy conn exists). Document the
   split in docs and in a comment at the compile site.

mvc.Tunnel gains the flag for display (PublicUrl scheme already https; show agent-tls in the
term view line if trivially available — do not contort state plumbing for it).

### 5.4 What keeps working, and why (the composition table)

| Feature | Over agent-terminated tunnels | Why |
|---|---|---|
| host_header / header add-remove | ✅ | applied on plaintext after termination |
| X-Forwarded-For / Proto / Host | ✅ | same |
| response compression | ✅ | local-leg egress, pre-encryption on responses |
| inspector / analyzer | ✅ | tee sits on plaintext |
| traffic policy on_http_* | ✅ (agent-side now) | §5.3 step 5 |
| traffic policy on_tcp_connect | ✅ (server-side) | pre-proxy, SNI-routed |
| 502 dead upstream | ✅ post-handshake | §5.3 step 3 |
| pooling / .internal / forward-to | ✅ | URL buckets unchanged; forward targets stay plaintext http legs |

## 6. File ownership (exclusive; no file touched by two agents)

- **Agent A (server)**: `server/sni.go`, `server/sni_test.go`, `server/http.go`,
  `server/tunnel.go`, `server/main.go`, `server/registry.go` (port claims if that's the
  natural home), `server/portclaims*.go` + tests, `msg/msg.go`, plus any server test files
  it needs (`server/*_test.go` new ones only — do not edit existing tests except where the
  listener restructure strictly requires it; note every such edit in the report).
- **Agent B (client)**: `client/cli.go`, `client/config.go`, `client/model.go`,
  `client/mvc/state.go`, `client/tlsagent.go`, `client/tlsagent_test.go`, new client test
  files only.
- **Agent C (after A+B)**: `scripts/e2e.sh`, `scripts/bench.sh` (optional passthrough vs
  terminated latency scenario), `docs/CHANGELOG.md`, `README.md` (docs section + Levis/IoT
  tcp example), `version/version.go` bump to 1.0.7.

## 7. Testing strategy

**A — SNI parser** (golden fixtures generated with `openssl s_client` / Go tls client):
single-record hello; multi-record (fragmented) hello; hello without SNI; TLS 1.2 and 1.3
shapes; garbage bytes; truncated stream; oversized (>64 KiB extensions) → error. Round-trip:
peeked bytes replayed into a real tls.Server complete a handshake.

**A — server routing**: pipe-conn fakes — SNI match + agent tunnel → raw passthrough to
proxy conn (bytes reaching the "agent" are verbatim TLS records incl. ClientHello); SNI
match + edge tunnel → terminated (plaintext head reaches httpHandler); no SNI → terminated;
Host-routed agent tunnel on terminated path → 421; port claims per §4.2.

**B — agent**: tls.Client (Go) dials the agent-wrapped conn — upstream receives plaintext
with rewritten Host + XFF; CA model: presented chain validates against the CA, per-SNI
names match; ephemeral model: handshake succeeds, WARN logged; dial-fail → 502 after
handshake; policy deny in on_http_request → terminated visitor gets the deny response;
compression still applied. All with `-race`.

**C — e2e (FIRST https-listener coverage ever)**: new scenario group with `-httpsAddr`
enabled (existing scenarios stay on the http listener untouched):
1. edge-terminated https basic (snakeoil, `curl -k`) → 200;
2. agent-terminated, CA-minted, `curl --cacert ca.pem https://host` → 200, and server log
   asserts NO plaintext head parsed (zero-knowledge proof);
3. SNI demux: one edge + one agent tunnel, same :443, different hostnames → both route;
4. no-SNI client (`curl --resolve` tricks / openssl without -servername) hitting agent
   tunnel → 421;
5. policy deny over agent tunnel → 403 after handshake;
6. `remote_port` e2e per §4.2.
Note: C must `chmod +x` / `git update-index --chmod=+x scripts/e2e.sh` — MCP writes have
dropped the exec bit twice before.

## 8. Review gates (architect)

1. `go build ./...`, `go vet ./...`, `go test ./...` (with `-tags debug`) green; new tests
   `-race` green.
2. Zero-knowledge invariant: NO code path sends agent-tunnel plaintext to the server; the
   server's join for these tunnels is raw bytes only; e2e scenario 2 proves it.
3. No behavior change for existing tunnels (edge http, edge https, tcp) beyond the SNI peek
   latency; existing e2e scenarios pass unmodified.
4. Fail-loudly: all config errors name the offending key/file; no silent fallbacks except
   the documented ephemeral-cert WARN.
5. Data-driven: cert models, SNI parse states, port-claim outcomes — registries/tables, not
   if-chains.
6. Deadlines/handshake timeouts consistent with existing conn conventions; no goroutine
   leaks (`-race` + manual audit of the handshake-failure path).

## 9. Success metrics

- `curl --cacert` against an agent-terminated tunnel serves a real local app end to end.
- Second token cannot steal a claimed remote port; same token reconnect reclaims it.
- Bench: passthrough latency within noise of edge https (peek cost ~one read).
- CHANGELOG documents the model split (server vs agent policy phases) honestly.
