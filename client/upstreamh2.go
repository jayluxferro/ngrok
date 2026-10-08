package client

// The agent-side h1<->h2c transcoder (SPEC-CLUSTER17): what
// `upstream_protocol: http2` puts in place of the plain TCP dial of
// serveProxyConnection. The proxy leg stays h1 -- the rewriter pair, the
// traffic-policy hooks, the inspector tee, XFF injection and compression all
// run on it exactly as they do on every other tunnel -- and the local leg
// becomes two halves that meet at this file:
//
//   - an h1 half: a one-connection http.Server fed by a net.Pipe. The pipe end
//     the relay writes requests into is read by the server, the server's
//     responses are read back by the relay, and net/http does every byte of
//     h1 parsing and framing on both crossings. This codebase does not
//     hand-roll framing on data paths, and the transcoder is a data path --
//     which is also why the h1 half is a server and not a client: a client
//     would need a fresh upstream connection per request or a request
//     queue, both of which re-implement what a server already does.
//   - an h2 half: one http2.Transport per local address (AllowHTTP + a plain
//     dial in DialTLSContext -- the h2c prior-knowledge shape), shared by
//     every proxy connection of every tunnel that points at that address, so
//     concurrent proxy connections pool their streams onto shared local h2c
//     connections, which is what an h2 local service wants.

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http/httpguts"
	"golang.org/x/net/http2"

	"ngrok/client/mvc"
	"ngrok/conn"
)

// upstreamH2IdleTimeout bounds how long a pooled local h2c connection may sit
// with no streams before the transport closes it. It is http.DefaultTransport's
// own idle timeout, for the same reason that value is what it is: long enough
// that the quiet minutes between requests reuse the connection, short enough
// that a local service which went away is noticed by the next request instead
// of by the operator. It is also what reclaims the pool when a tunnel goes
// away: nothing here closes pooled connections eagerly, because the pool is
// shared by every tunnel on the address and no single connection's end owns it.
const upstreamH2IdleTimeout = 90 * time.Second

// upstreamH2ReadIdleTimeout is pool hygiene, and only pool hygiene. A shared
// connection can die without an EOF -- a laptop sleeping, a container pausing,
// a service wedged mid-frame -- and a per-request TCP dial (the plain path)
// never has this problem because it never reuses a socket. The transport's
// health check closes that gap: a pooled connection that has received nothing
// for this long gets a PING, and one that cannot answer it (the transport's
// 15s default ping timeout) is closed -- which the pool sees as MarkDead, so
// the next request dials fresh instead of riding a corpse.
//
// What this deliberately is NOT is a response deadline. No
// ResponseHeaderTimeout sits on this transport: a local service that takes a
// slow minute to compute its answer gets exactly the deal the plain dial gives
// it -- the visitor waits, and the visitor's own timeout is the bound -- and
// that parity is the contract (no new failure vocabulary, including a "your
// service was too slow" one the h1 path never had).
const upstreamH2ReadIdleTimeout = 30 * time.Second

// upstreamUpgradeRefusal is the fixed 502 body for Upgrade requests
// (SPEC-CLUSTER17 non-goals). HTTP/2 has no way to upgrade a connection: the
// h1 mechanism requires rewriting the head mid-connection, and h2's only
// equivalent is extended CONNECT (RFC 8441), which this release does not
// implement. A half-upgraded answer would be worse than none -- the visitor
// believes it switched protocols while the bytes after the switch are still
// h1-framed -- so the request is refused outright, with the rule in the body.
// Built once, like every synthetic in this codebase: the text is a constant of
// the feature, not a per-request construction.
const upstreamUpgradeRefusal = `This tunnel dials its local service with upstream_protocol: http2, and HTTP/2 cannot honor an Upgrade request: upgrading is an HTTP/1.1 mechanism (rewrite the head mid-connection), and HTTP/2's only equivalent, extended CONNECT, is not implemented here. Websockets and other upgrades need the local service reached with upstream_protocol: http1.
`

// The per-address transport pool. Keyed by the tunnel's LocalAddr on purpose,
// never by the visitor's Host: one h2c connection can carry any number of
// :authority values (that is ordinary h2), so requests whose rewritten Host
// headers differ still share the service's connections, and what actually
// needs one value per pool is the address the sockets go to.
var (
	upstreamH2Mu    sync.Mutex
	upstreamH2Pools = make(map[string]*upstreamH2Pool)
)

// upstreamH2PoolFor returns the pool for one local address, creating it on
// first use. The map lives for the process, not for a control session: a
// client that reconnects keeps its local h2c connections, which is the same
// keep-alive behavior the plain dial path gets from the local service.
func upstreamH2PoolFor(addr string) *upstreamH2Pool {
	upstreamH2Mu.Lock()
	defer upstreamH2Mu.Unlock()
	p := upstreamH2Pools[addr]
	if p == nil {
		p = newUpstreamH2Pool(addr)
		upstreamH2Pools[addr] = p
	}

	return p
}

// upstreamH2Pool is one local address's h2 half: the transport plus the set of
// live h2c connections to that address. It implements http2.ClientConnPool, so
// the transport's RoundTrip consults it for a connection and it -- not the
// transport's built-in pool -- decides when a new one is dialed. Owning that
// decision is what makes the dead-local-service story work: the pool can
// establish its first connection EAGERLY, at dial time, so that a dead local
// service surfaces exactly where the plain dial's failure surfaces today --
// serveProxyConnection's existing 502 path -- instead of inside the first
// request.
type upstreamH2Pool struct {
	addr      string
	transport *http2.Transport

	mu    sync.Mutex
	conns map[*http2.ClientConn]struct{}
}

func newUpstreamH2Pool(addr string) *upstreamH2Pool {
	p := &upstreamH2Pool{
		addr:  addr,
		conns: make(map[*http2.ClientConn]struct{}),
	}

	p.transport = &http2.Transport{
		// h2c prior knowledge: the local leg is plaintext, so the "TLS" dial
		// is a plain TCP dial and no tls.Config is consulted. AllowHTTP is the
		// transport's gate for http:// scheme requests; the dial override is
		// the other half of the shape.
		AllowHTTP: true,
		// The pool this struct owns is the transport's pool: without this
		// field RoundTrip consults the transport's own internal cache -- which
		// never learns of connections made by ensureConn's direct
		// NewClientConn -- and dials its own, one per transport, silently
		// defeating the eager dial (its connection goes unused) and handing
		// every request to a connection this pool cannot see, cannot reuse
		// deliberately, and cannot report dead.
		ConnPool: p,
		DialTLSContext: func(ctx context.Context, network, _ string, _ *tls.Config) (net.Conn, error) {
			// The addr argument is derived from the request's authority -- the
			// rewritten visitor Host -- and is deliberately ignored: sockets
			// go to the configured local address, whatever hostname the
			// visitor used to get here.
			var d net.Dialer
			return d.DialContext(ctx, network, p.addr)
		},
		IdleConnTimeout: upstreamH2IdleTimeout,
		// See upstreamH2ReadIdleTimeout: silent-death eviction for the
		// shared pool, deliberately not a response deadline.
		ReadIdleTimeout: upstreamH2ReadIdleTimeout,
	}

	return p
}

// ensureConn establishes the pool's first connection to the local service,
// synchronously, unless a live one already exists. This is the eager half of
// the dead-local-service contract (see the pool doc above): its error is
// returned from the dial site in serveProxyConnection and answered by the
// same WARN and the same 502 page a failed plain dial produces.
//
// It is "first connection", not "every connection": once the pool is warm the
// construction of one more proxy bridge must not add a socket, or concurrent
// proxy connections would stop pooling onto shared local connections, which is
// the point of the shared transport.
func (p *upstreamH2Pool) ensureConn(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	for cc := range p.conns {
		// CanTakeNewRequest, not ReserveNewRequest: this call reserves nothing
		// -- the reservation belongs to GetClientConn, which the actual
		// request goes through. Reserving here would strand one stream slot
		// per proxy bridge on the connection nobody spends it from.
		if cc.CanTakeNewRequest() {
			return nil
		}
	}

	_, err := p.dialLocked(ctx)
	return err
}

// GetClientConn implements http2.ClientConnPool: hand out a connection with
// one concurrent-stream slot reserved for the request RoundTrip is about to
// send, dialing a new h2c connection when every live one is saturated (or when
// the pool is empty -- the lazy path, taken when a request arrives after the
// previous pool died of idleness).
func (p *upstreamH2Pool) GetClientConn(req *http.Request, _ string) (*http2.ClientConn, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for cc := range p.conns {
		if cc.ReserveNewRequest() {
			return cc, nil
		}
	}

	return p.dialLocked(req.Context())
}

// dialLocked establishes one h2c connection: plain TCP, then the h2 handshake
// (preface + SETTINGS) via NewClientConn on that socket. The handshake is what
// makes the eager call honest -- a service that accepts TCP but does not speak
// h2 fails here, at dial time, rather than mid-request. Callers must hold p.mu.
func (p *upstreamH2Pool) dialLocked(ctx context.Context) (*http2.ClientConn, error) {
	var d net.Dialer
	raw, err := d.DialContext(ctx, "tcp", p.addr)
	if err != nil {
		return nil, err
	}

	cc, err := p.transport.NewClientConn(raw)
	if err != nil {
		raw.Close()
		return nil, err
	}

	p.conns[cc] = struct{}{}
	return cc, nil
}

// MarkDead implements http2.ClientConnPool: the transport reports a connection
// as lost (EOF, protocol error, idle timeout) and the pool forgets it. The
// next request dials again -- the same self-healing a raw TCP relay gets from
// the local kernel refusing the next connect.
func (p *upstreamH2Pool) MarkDead(cc *http2.ClientConn) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if _, ok := p.conns[cc]; !ok {
		// Already removed (MarkDead is called from more than one path, and a
		// second close is harmless -- but a second map delete would not be
		// distinguishable from bookkeeping gone wrong, so guard it).
		return
	}
	delete(p.conns, cc)
	cc.Close()
}

// dialUpstreamH2 is the h2 road of serveProxyConnection's local dial: it
// returns a conn.Conn that behaves as the local leg -- the relay writes h1
// requests into it and reads h1 responses from it, unchanged -- while behind
// it every request is transcoded onto the address's shared h2c connections.
func dialUpstreamH2(tunnel mvc.Tunnel) (conn.Conn, error) {
	pool := upstreamH2PoolFor(tunnel.LocalAddr)

	// The eager dial: a dead local service must fail HERE, so that the caller's
	// existing dead-upstream branch answers it (same WARN, same 502 page, no
	// new failure vocabulary). See upstreamH2Pool.ensureConn.
	if err := pool.ensureConn(context.Background()); err != nil {
		return nil, err
	}

	// The h1 half. One pipe, one server, one connection: the end given to the
	// server reads what the relay writes and the relay reads what the server
	// writes -- net.Pipe's two ends are the two sides of the local leg.
	pipeLocal, pipeServer := net.Pipe()
	ln := newOneConnListener(pipeServer)

	srv := &http.Server{
		Handler: &upstreamBridge{
			pool:      pool,
			publicUrl: tunnel.PublicUrl,
			localAddr: tunnel.LocalAddr,
		},
	}
	go srv.Serve(ln)

	return &upstreamH2Conn{
		Conn: conn.Wrap(pipeLocal, "prv"),
		ln:   ln,
	}, nil
}

// upstreamH2Conn is the local leg the relay sees. Its Close tears down both
// halves of the bridge: the pipe end's close fails the server-side connection
// (which cancels the in-flight request context, which cancels the h2 stream),
// and the listener's close ends srv.Serve.
type upstreamH2Conn struct {
	conn.Conn
	ln *oneConnListener
}

func (c *upstreamH2Conn) Close() error {
	errLn := c.ln.Close()
	errConn := c.Conn.Close()
	// The pipe end's close is the one that matters (it is what unblocks the
	// server); the listener's is bookkeeping. Report the pipe error first.
	if errConn != nil {
		return errConn
	}
	return errLn
}

// oneConnListener is the classic single-connection listener adapter: it
// yields exactly the connection it was built with and then behaves as a closed
// listener. http.Server.Serve needs a listener; this is the smallest thing
// that is one.
type oneConnListener struct {
	ch   chan net.Conn
	done chan struct{}
	once sync.Once
}

func newOneConnListener(c net.Conn) *oneConnListener {
	l := &oneConnListener{
		ch:   make(chan net.Conn, 1),
		done: make(chan struct{}),
	}
	l.ch <- c
	return l
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *oneConnListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

// Addr has no real value: the server asks for it only to attach addresses to
// log lines, and a pipe connection has none. The tunnel's local address is the
// honest label for where this leg goes.
func (l *oneConnListener) Addr() net.Addr {
	return &upstreamH2Addr
}

var upstreamH2Addr = net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}

// upstreamBridge is the h1 half's handler: one request at a time per proxy
// connection (the proxy leg is serial h1, as it has always been), concurrent
// across proxy connections (each has its own bridge, all sharing the pool).
type upstreamBridge struct {
	pool      *upstreamH2Pool
	publicUrl string
	localAddr string
}

func (b *upstreamBridge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Upgrades are refused before anything is dialed (SPEC-CLUSTER17
	// non-goals): h2 cannot carry an h1 upgrade, and the transport would only
	// reject the head anyway -- with an error that would masquerade as a dead
	// upstream. The refusal names the actual rule instead.
	if isUpgradeRequest(r) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusBadGateway)
		io.WriteString(w, upstreamUpgradeRefusal)
		return
	}

	resp, err := b.pool.transport.RoundTrip(b.transcodeRequest(r))
	if err != nil {
		// The local service died under a warm pool (or between the eager dial
		// and this request): answer with the same 502 page the plain dial's
		// failure produces, so the visitor sees one failure shape however the
		// service died. No new failure vocabulary.
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadGateway)
		fmt.Fprintf(w, BadGateway, b.publicUrl, b.localAddr, b.localAddr)
		return
	}
	defer resp.Body.Close()

	// The h2 response head onto the h1 writer. net/http owns the hop-by-hop
	// rules on this crossing the same way the transport owns them on the
	// other (Connection-family fields cannot legally be in an h2 head at
	// all) -- with one exception the crossing itself creates: Content-Length
	// is a FRAMING header here, not a claim about the body. The h2 server
	// includes it only when it buffered the whole response before its handler
	// returned; copying it would pin the h1 side to identity framing for a
	// response the bridge streams chunk-by-chunk -- and a flushed handler
	// cannot emit declared trailers under identity framing, so whether
	// trailers survived would depend on the h2 server's HEADERS-vs-handler-
	// return RACE. Dropping it makes the h1 framing the h1 server's own
	// decision, deterministically: chunked once the first chunk flushes
	// (trailers ride it), or identity if the whole body fit and the handler
	// returned unflushed.
	for k, vv := range resp.Header {
		if strings.EqualFold(k, "Content-Length") {
			continue
		}
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}

	// h2 trailers that the service announced in its head are declared here, so
	// net/http will emit them as h1 chunk trailers once their values arrive.
	// Trailing HEADERS the service did NOT announce cannot be declared
	// retroactively on h1 without buffering the whole body, which this design
	// does not do -- they are dropped, the same trade httputil.ReverseProxy
	// makes between these two protocol versions.
	for k := range resp.Trailer {
		w.Header().Add("Trailer", k)
	}

	w.WriteHeader(resp.StatusCode)

	// The body streams: every read from the h2 stream is written through and
	// flushed immediately, so a slow local service delivers at its own pace in
	// both the literal sense (no whole-body buffering) and the observable one
	// (first bytes reach the visitor before the body is done). Flushing per
	// chunk is what keeps that promise on the h1 side -- without it the bytes
	// would sit in the server's output buffer until the handler returns.
	buf := make([]byte, 32*1024)
	flusher, _ := w.(http.Flusher)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				// The visitor went away mid-body; cancel the h2 stream by
				// returning (the request context dies with the h1 connection).
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		if err != nil {
			break
		}
	}

	// Trailer values, for whatever was declared above. Setting them into the
	// header map after the body is the documented net/http trailer mechanism.
	for k, vv := range resp.Trailer {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
}

// transcodeRequest builds the h2 request from the parsed h1 one: same method,
// same (rewritten) headers, same streaming body, with the URL the transport
// needs -- scheme http (AllowHTTP's gate) and an authority, which is the
// request's own Host: the rewriter may have rewritten it, and h2's :authority
// is the rewritten value the local service should see.
func (b *upstreamBridge) transcodeRequest(r *http.Request) *http.Request {
	authority := r.Host
	if authority == "" {
		// An HTTP/1.0 request with no Host header still needs an authority on
		// the wire; the local address is what the tunnel is for.
		authority = b.localAddr
	}

	outURL := *r.URL
	outURL.Scheme = "http"
	outURL.Host = authority

	// Clone for the deep copy of the header map: the transport adjusts what it
	// was handed, and the server's request must not be adjusted with it. The
	// body is deliberately NOT copied -- Clone shares it, which is the
	// streaming direction working as intended.
	out := r.Clone(r.Context())
	out.URL = &outURL
	// RequestURI is the h1 request-target as received; it is a server-side
	// field and must not ride on an outgoing request.
	out.RequestURI = ""

	return out
}

// isUpgradeRequest reports whether the request attempts the h1 upgrade
// mechanism: an Upgrade header at all, or the Upgrade token in Connection.
// The two spellings travel together in a conforming request, but either alone
// is an attempt this bridge cannot honor, so either alone is refused.
func isUpgradeRequest(r *http.Request) bool {
	if r.Header.Get("Upgrade") != "" {
		return true
	}
	return httpguts.HeaderValuesContainsToken(r.Header["Connection"], "Upgrade")
}

// upstreamProtocolOrDefault resolves the config value to what the dial site
// tests. The empty string -- the key's absence -- is the default, and the
// default is deliberately NOT written back into the config: LoadConfiguration
// leaving the field empty is what keeps `ngrok --save` (SaveAuthToken) from
// growing an upstream_protocol key into every tunnel that did not have one.
func upstreamProtocolOrDefault(v string) string {
	if v == "" {
		return UpstreamProtocolHTTP1
	}
	return v
}
