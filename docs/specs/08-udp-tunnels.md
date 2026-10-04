# Spec 08 — UDP tunnels

Status: shipped (see the changelog entry for its release; this document is the design record)


## 1. Objectives

A new public protocol `udp` with the semantics UDP actually has: datagram-preserving,
lossy by design, per-flow ordering only. `proto: {udp: 127.0.0.1:53}` exposes a local UDP
service (DNS, ⟨PERSON_64·ad92ac97⟩ nodes, game servers, QUIC upstreams) on a public UDP port.

## 2. Non-goals

- No reliability, retransmission, or reordering (UDP must stay UDP; no FlowState semantics).
- No fragmentation/reassembly beyond what the socket gives us: a datagram larger than the
  path MTU is the sender's problem, but the pipe must carry up to 64 KiB datagrams whole.
- No inspector/analyzer, no header rewriting, no http policy phases for udp (on_tcp_connect
  runs per FLOW — the phase's existing tcp semantics, which already apply to conns).
- No `.internal`/forward_to for udp (same refusal tcp gets today).
- No ICMP errors (unreachable ports surface as silence, as UDP itself does).

## 3. Design

### 3.1 Server (per recon anchors)

- `msg.ProtoUDP = "udp"` (msg/msg.go:267-269 pattern). `validateRequest`: udp accepted as a
  public protocol; internal/forward_to refused with tcp's wording adapted; hostname/subdomain
  invalid (port-routed, like tcp). `register` switch gains the udp case; `defaultPortMap`
  gains nothing (udp urls always carry :port — tcp's invariant, tunnel.go:20-30).
- Per-tunnel `*net.UDPConn` bound like tcp's per-tunnel listener (tunnel.go:448-470 shape):
  `net.ListenUDP("udp", &net.UDPAddr{IP: 0.0.0.0, Port: port})`; url = `udp://<domain>:<port>`
  from the ACTUAL bound port; affinity-cache + pooling reuse the existing machinery for free
  (registry keys are url strings; the affinity cache is already protocol-namespaced).
- **Port claims gain a protocol dimension**: TCP and UDP port spaces are independent — claims
  key becomes (proto, port), so udp:5000 does not fight tcp:5000, and `ownListenerAt`
  (portclaims.go:158-176) learns to see UDP listeners (the cluster-7 QUIC listener included)
  so a udp tunnel cannot claim the server's own UDP port. Refcount/owner semantics unchanged.
- **Flow table**: `map[clientAddr]*udpFlow` on the tunnel, guarded; first datagram from an
  unknown addr = flow establishment: admission gates (publicLimiter/connLimiter per flow,
  incPublicConns per flow), `connectVerdict` (deny = drop silently — a UDP caller has no
  protocol to be answered in), GetProxy → `StartProxy{Url, ClientAddr: <ip:port>}` → the
  proxy conn serves the flow. Flow holds: connected `net.DialUDP` toward the client (replies
  need no per-packet routing), idle deadline (default 30s, config `udp_idle_timeout`),
  refreshed on activity in BOTH directions; expiry = close proxy conn + delete flow.
- **Datagram framing on the proxy leg** (a stream: TCP/smux/QUIC): 4-byte big-endian length
  prefix + payload per datagram, both directions (msg/conn.go's framing shape, datagram-sized).
  Reader bounds: single datagram ≤ 65507 bytes; a length field beyond that = protocol error,
  flow closed. Read buffer 64 KiB + overflow handling (truncated datagrams are dropped, logged).
- Pooling round-robin assignment happens per FLOW (bucket.Get on flow establishment);
  bucket cascade/DelBucket unchanged on `udp://` urls.

### 3.2 Client (agent)

- `protoMap[ProtoUDP] = proto.NewUdp()` — a new identity protocol like tcp (proto/tcp.go
  shape). `validateProtocol` accepts udp; `remote_port` validity extended to tcp|udp;
  hostname/subdomain refused for udp (config.go:262 shape).
- `serveProxyConnection` gains the udp branch: instead of `conn.Dial` + relay, open a
  connected `net.DialUDP(tunnel.LocalAddr)`, then pump: proxy-leg framed datagrams →
  local UDP write; local UDP reads → framed proxy-leg writes. Dead-local semantics: first
  send failure or ICMP-driven error closes the flow quietly (no 502 — IsHTTP is false for
  udp and stays so).
- Idle: same 30s default, mirrored client-side, so both ends agree a silent flow ends;
  either side's expiry tears down its half (proxy conn close propagates as today).

### 3.3 Composition

- QUIC proxy leg + udp public proto: the flow rides framed datagrams over whatever carrier
  the mux session is — one e2e scenario proves the combination.
- on_tcp_connect applies per flow with conn.client_ip/remote_addr = the flow's client addr.

## 4. File ownership (A: server, B: client, C: e2e/docs after)

- **A**: msg/msg.go (ProtoUDP), server/tunnel.go, server/udp.go (new: flow table, framing,
  listenUdp), server/portclaims.go (proto dimension + ownListenerAt UDP), server tests
  (server/udp_test.go + portclaims additions), server/config.go IF a server-side knob is
  needed (prefer none: idle timeout is a client+flow constant; only add `udp_idle_timeout`
  if A finds it must be server-controlled — document either way).
- **B**: client/model.go (udp branch in serveProxyConnection), client/config.go, client/cli.go
  (usage examples), proto/udp.go (new), client tests.
- **C**: scripts/e2e.sh (udp group: echo server via python, datagram round-trip, two clients
  = two flows, idle expiry, remote_port claim/refuse udp variant, QUIC-leg composition),
  docs/CHANGELOG.md 1.0.10, README, version/version.go Patch "10".

## 5. Testing strategy

- A: unit — flow table establish/expire/refresh; framing round-trip incl. max-size datagram
  and oversized-length refusal; port claims udp/tcp independence + QUIC-listener collision;
  gates + connectVerdict per flow (deny drops, no bytes); pooling per-flow assignment.
  Integration in TestTcpPoolingSharesOneListener's style: real ListenUDP + armProxyPool,
  send a datagram from a python/net client, assert StartProxy.ClientAddr == sender addr,
  reply routed back to the right flow among two concurrent flows.
- B: unit — udp branch pump both directions against a local UDP echo; idle expiry; framing
  decode; validation tables (protocol, remote_port).
- C e2e: python UDP echo upstream; two flows from different source ports both round-trip;
  idle flow expires (client+server logs); `-remote-port` udp claim vs tcp same-port (both
  succeed — independence proof); udp-over-QUIC-leg scenario.

## 6. Review gates

1. Full build/vet/test -race green; e2e green incl. all prior groups.
2. TCP behavior byte-identical (claim-space change is additive: tcp claims keep working).
3. No datagram may be silently coalesced or split — framing test pins boundary preservation.
4. Flows never leak: expiry test with -race, table emptied on tunnel Shutdown.
5. UDP amplification posture documented: gates + per-flow rate limiting exist, reply path
   only toward the flow's source addr (connected socket), and the changelog states the
   operator's exposure honestly (a public UDP forwarder reflects what the local service
   sends, bounded by the flow's idle timeout).
