package client

// The h1 pool bridge (SPEC-CLUSTER25): what `upstream_pool: true` puts in
// place of the plain TCP dial of serveProxyConnection. The default h1 local leg
// is a raw socket per proxy connection -- every proxy conn dials the upstream
// fresh -- because pooling a raw socket is unsound: the client cannot know
// whether a finished proxy conn ended on an h1 message boundary, so handing a
// still-open socket to the next proxy conn can splice half a request onto a
// new one. This file is the opt-in alternative: the local leg becomes two
// halves that meet at the shared scaffolding (client/upstream_shared.go),
//
//	relay bytes <-> net.Pipe <-> one-conn http.Server <-> httputil.ReverseProxy
//	<-> one shared *http.Transport per local address
//
// so N requests over k pooled local conns instead of N fresh dials. net/http
// owns both crossings -- the same line cluster 17 crossed for h2 -- and that
// ownership is what makes reuse sound: a connection returns to the pool only
// when a response has been framed to its end.
//
// The proxy leg is untouched -- the rewriter pair, the traffic-policy hooks,
// the inspector tee, XFF injection and compression all run on it exactly as on
// every other tunnel. Only the local leg is parsed, and the one observable
// difference is documented at the dial site in client/model.go.

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"sync"
	"time"

	"ngrok/client/mvc"
	"ngrok/conn"
)

// upstreamH1IdleTimeout bounds how long a pooled local connection may sit with
// no requests before the transport closes it. It mirrors upstreamH2IdleTimeout
// (SPEC-CLUSTER17) for the same reason that value is what it is: long enough
// that the quiet minutes between requests reuse the connection, short enough
// that a local service which went away is noticed by the next request instead
// of by the operator. It is also what reclaims the pool when a tunnel goes
// away: nothing here closes pooled connections eagerly, because the pool is
// shared by every tunnel on the address and no single connection's end owns it.
const upstreamH1IdleTimeout = 90 * time.Second

// upstreamH1MaxIdleConnsPerHost is the pool's capacity, spelled out because
// http.Transport's default -- 2 -- would silently defeat the feature under
// concurrency: the first three simultaneous proxy connections would leave at
// most two connections idle-pooled and dial a third fresh on every burst, and
// the accept collapse this feature exists for would quietly stop at k=2.
// 100 is DefaultTransport's own MaxIdleConns figure: far above the concurrency
// a single local service sees from one agent, while IdleConnTimeout stays the
// thing that reclaims whatever was pooled and never reused. There is
// deliberately NO MaxConnsPerHost: an active connection per in-flight request
// is the plain dial's own behavior, and capping it would queue requests the
// default path would have served.
const upstreamH1MaxIdleConnsPerHost = 100

// The per-address transport pool. Keyed by the tunnel's LocalAddr on purpose,
// never by the visitor's Host: what needs one value per pool is the address
// the sockets go to, and requests whose rewritten Host headers differ (or
// whose host_header setting rewrites the Host) must still share the same
// keep-alive connections. Same shape, and the same process lifetime, as the
// h2 pool in client/upstreamh2.go: a client that reconnects keeps its local
// connections, which is the keep-alive behavior the plain dial path gets from
// the local service.
var (
	upstreamH1Mu    sync.Mutex
	upstreamH1Pools = make(map[string]*upstreamH1Pool)
)

// upstreamH1PoolFor returns the pool for one local address, creating it on
// first use.
func upstreamH1PoolFor(addr string) *upstreamH1Pool {
	upstreamH1Mu.Lock()
	defer upstreamH1Mu.Unlock()

	p := upstreamH1Pools[addr]
	if p == nil {
		p = newUpstreamH1Pool(addr)
		upstreamH1Pools[addr] = p
	}

	return p
}

// upstreamH1Pool is one local address's h1 half: the keep-alive transport
// every proxy connection of every tunnel pointing at that address shares. It
// has no connection map of its own -- http.Transport keeps its idle pool
// internally and there is no per-connection handle to own -- so what the pool
// tracks is the one thing the transport cannot report: whether a request has
// ever succeeded through it (warm), which is what retires the liveness probe
// below.
type upstreamH1Pool struct {
	addr      string
	transport *http.Transport

	mu   sync.Mutex
	warm bool
}

func newUpstreamH1Pool(addr string) *upstreamH1Pool {
	p := &upstreamH1Pool{addr: addr}

	p.transport = &http.Transport{
		// See upstreamH1MaxIdleConnsPerHost: the default of 2 is the silent
		// defeat of the feature.
		MaxIdleConnsPerHost: upstreamH1MaxIdleConnsPerHost,
		IdleConnTimeout:     upstreamH1IdleTimeout,
		// The addr argument is derived from the request's URL.Host -- the
		// pool's own constant, set by the bridge's Rewrite hook -- and is
		// deliberately ignored anyway, for the same reason the h2 transport
		// ignores its authority: sockets go to the configured local address,
		// whatever the visitor's Host said. Pinning the dial here (rather than
		// letting URL.Host steer it) is what makes "per-address pool" mean
		// exactly that.
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, p.addr)
		},
		// Deliberately NO ResponseHeaderTimeout (the cluster-17 ruling, kept
		// for the h1 twin): a local service that takes a slow minute to
		// compute its answer gets exactly the deal the plain dial gives it --
		// the visitor waits, and the visitor's own timeout is the bound. A
		// header timeout here would add a failure vocabulary the default path
		// never had, on the opt-in path of all places.
	}

	return p
}

// ensureWarm is the eager half of the dead-local-service contract: with no
// request through this pool yet, a proxy connection's local dial runs one
// synchronous liveness probe, so that a dead local service fails HERE --
// answered by the caller's existing dead-upstream branch (same WARN, same 502
// page, no new failure vocabulary) -- instead of inside the first request,
// where the failure would wear a different shape (the bridge's own 502, below)
// than the plain dial's.
//
// It is a plain dial-and-close, and that is deliberate: http.Transport cannot
// pre-seed its internal idle pool, so the connection the probe opens cannot be
// handed to it -- the first RoundTrip dials again. The probe costs one extra
// loopback connect per address, once, and buys cold-failure parity with the
// plain dial. Once a RoundTrip has succeeded (markWarm) the probe retires for
// the life of the process: from then on death is detected per request by the
// transport itself, which is the "no poisoned pool" story -- the transport
// dials again on the next request, and if the service is back, the tunnel
// heals without operator action.
func (p *upstreamH1Pool) ensureWarm(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.warm {
		return nil
	}

	c, err := (&net.Dialer{}).DialContext(ctx, "tcp", p.addr)
	if err != nil {
		return err
	}
	c.Close()
	return nil
}

// markWarm records the first successful RoundTrip, retiring the liveness
// probe. Called from the bridge after every RoundTrip it is nearly free the
// first time and free forever after.
func (p *upstreamH1Pool) markWarm() {
	p.mu.Lock()
	p.warm = true
	p.mu.Unlock()
}

// dialUpstreamH1Pooled is the pooled road of serveProxyConnection's local
// dial: it returns a conn.Conn that behaves as the local leg -- the relay
// writes h1 requests into it and reads h1 responses from it, unchanged --
// while behind it every request rides the address's shared keep-alive
// connections.
func dialUpstreamH1Pooled(tunnel mvc.Tunnel) (conn.Conn, error) {
	pool := upstreamH1PoolFor(tunnel.LocalAddr)

	// The eager probe: a dead local service must fail HERE, so that the
	// caller's existing dead-upstream branch answers it. See ensureWarm.
	if err := pool.ensureWarm(context.Background()); err != nil {
		return nil, err
	}

	return startPipeBridge(&upstreamH1Bridge{
		pool:      pool,
		publicUrl: tunnel.PublicUrl,
		localAddr: tunnel.LocalAddr,
	}), nil
}

// upstreamH1Bridge is the h1 half's handler: one request at a time per proxy
// connection (the proxy leg is serial h1, as it has always been), concurrent
// across proxy connections (each has its own bridge, all sharing the pool).
// httputil.ReverseProxy is the whole crossing -- request splice, response
// splice, hop-by-hop rules, 101 upgrades -- because this codebase does not
// hand-roll framing on data paths, and a ReverseProxy pointed at net/http's
// own Transport is net/http talking to net/http.
type upstreamH1Bridge struct {
	pool      *upstreamH1Pool
	publicUrl string
	localAddr string
}

func (b *upstreamH1Bridge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b.reverseProxy().ServeHTTP(w, r)
}

// reverseProxy builds the crossing. Exposed as a method (rather than built
// inline in ServeHTTP) so the tests can pin the settings that are invisible on
// the wire -- FlushInterval, the transport identity -- the same way every
// other fixed constant of this fork is pinned.
func (b *upstreamH1Bridge) reverseProxy() *httputil.ReverseProxy {
	// Built per call, not per pool, on purpose: the 502 page names THIS
	// tunnel's public URL and local address, and two tunnels can share one
	// address's pool. The struct is a handful of pointers; the plain dial this
	// replaces opened a TCP connection per bridge.
	return &httputil.ReverseProxy{
		// The shared keep-alive pool: this field is what makes the requests
		// of concurrent proxy connections ride the same local connections
		// (and the missing-ConnPool bug class from cluster 17, h1 edition --
		// omit it and ReverseProxy falls back to http.DefaultTransport, which
		// would pool happily but not under THIS pool's settings, and e2e's
		// accept-count assertions would read the wrong transport).
		Transport: b.pool.transport,
		// FlushInterval -1: flush every write immediately, so a streaming
		// local service delivers at its own pace in the observable sense too
		// -- first bytes reach the visitor before the body is done. (SSE gets
		// this from ReverseProxy's Content-Type sniff as well; -1 extends the
		// same behavior to every streaming shape -- chunked bodies, long
		// polls -- because the plain dial's raw pipe never buffered either,
		// and streaming parity is a spec pin, not a bonus.)
		FlushInterval: -1,
		Rewrite: func(pr *httputil.ProxyRequest) {
			// Where the request goes: plaintext to the pool's address. The
			// Host header is NOT touched -- in Rewrite mode pr.Out starts as
			// a clone of the inbound request, so its Host is the (rewritten)
			// visitor Host the plain dial would have delivered verbatim;
			// setting pr.SetURL's Host="" behavior here would rewrite what
			// the fork deliberately preserves.
			pr.Out.URL.Scheme = "http"
			pr.Out.URL.Host = b.pool.addr

			// XFF suppression (SPEC-CLUSTER25, review gate 3). Rewrite-mode
			// ReverseProxy strips the inbound X-Forwarded-* headers before
			// this hook runs and never re-adds anything of its own -- that is
			// exactly WHY the fork uses Rewrite and not Director: Director
			// mode appends the proxy's view of the client IP, which would
			// leave the upstream two XFF values (the rewriter's injected one
			// plus ReverseProxy's) and break every XFF consumer. The fork's
			// rewriter already injected X-Forwarded-For and X-Forwarded-Proto
			// unconditionally on the proxy leg (client/headers.go
			// policyFromTunnel, rewriter's fixed tail), after removing
			// anything the visitor sent -- so carrying the inbound values
			// through VERBATIM reproduces, byte for value, what the plain
			// dial hands the upstream. Never append.
			for _, h := range []string{"X-Forwarded-For", "X-Forwarded-Proto", "X-Forwarded-Host"} {
				if vv, ok := pr.In.Header[h]; ok {
					pr.Out.Header[h] = vv
				}
			}
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			// The local service died under a warm pool (or between the eager
			// probe and this request): answer with the same 502 PAGE the
			// plain dial's failure produces, so the visitor sees one failure
			// body however the service died. No new failure vocabulary. (The
			// response line differs -- net/http writes HTTP/1.1 where
			// writeBadGateway writes HTTP/1.0 -- and that fingerprint is the
			// documented detection point: cold deaths fail at the dial and
			// take the existing branch; warm deaths are noticed by the first
			// request that rides a corpse. No h1 PING exists to notice it
			// sooner; weaker hygiene than h2's ReadIdleTimeout health check,
			// documented and accepted by the spec.)
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusBadGateway)
			fmt.Fprintf(w, BadGateway, b.publicUrl, b.localAddr, b.localAddr)
		},
		// The warm marker, at the only moment the name is honest: ModifyResponse
		// runs exactly when RoundTrip returned a response -- including a 101
		// (upgrades pass through: ReverseProxy's handleUpgradeResponse is the
		// TARGET behavior for websockets, SPEC-CLUSTER25 -- refusing them would
		// regress tunnels that work through today's raw pipe; e2e pins it) --
		// and never on the RoundTrip error road. From the first response on,
		// ensureWarm's probe stays retired, including after a later death,
		// whose recovery is the transport's own next dial, not a return to
		// probing.
		ModifyResponse: func(resp *http.Response) error {
			b.pool.markWarm()
			return nil
		},
	}
}
