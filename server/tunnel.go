package server

import (
	"encoding/base64"
	"fmt"
	"net"
	"ngrok/conn"
	"ngrok/log"
	"ngrok/msg"
	"ngrok/policy"
	"ngrok/rewriter"
	"ngrok/util"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

var defaultPortMap = map[string]int{
	"http":  80,
	"https": 443,
	"smtp":  25,
}

// internalSuffix is the reserved namespace for internal endpoints. Nothing
// outside it can be registered as internal, and nothing inside it is ever
// reachable through the public listeners (SPEC 3.2).
const internalSuffix = ".internal"

/**
 * Tunnel: A control connection, metadata and proxy connections which
 *         route public traffic to a firewalled endpoint.
 */
type Tunnel struct {
	// request that opened the tunnel
	req *msg.ReqTunnel

	// time when the tunnel was opened
	start time.Time

	// public url
	url string

	// tcp listener
	listener *net.TCPListener

	// control connection
	ctl *Control

	// account this tunnel belongs to (SPEC 3.1): the auth token when the
	// server runs with -authToken, otherwise "default". It namespaces internal
	// endpoints and scopes forward_to resolution.
	owner string

	// policy is this endpoint's traffic policy, compiled once at registration
	// (SPEC 3.3). Nil means the endpoint has none. It is immutable and shared
	// by every connection of the tunnel; the per-connection state a policy
	// needs (its vars) lives in the hooks, which are built per connection.
	policy *policy.Compiled

	// logger
	log.Logger

	// closing
	closing int32
}

// internal reports whether this tunnel is an internal (.internal) endpoint.
func (t *Tunnel) internal() bool {
	return t.req != nil && t.req.Binding == BindingInternal
}

// forwardTo returns the raw forward_to target this tunnel was registered
// with, if any.
func (t *Tunnel) forwardTo() string {
	if t.req == nil {
		return ""
	}
	return t.req.ForwardTo
}

// policyFor returns the compiled policy that governs a connection arriving at
// this tunnel and terminating at target (which is this tunnel itself when it
// has no forward_to).
//
// The entry endpoint's policy comes first, and the terminus's is the fallback.
// The spec says "the target's policy", which is the right answer for the plain
// case -- they are the same tunnel -- but an entry endpoint with a forward_to
// would then silently skip its own policy, and an endpoint an operator has
// written a policy for is the last one that should have it ignored. Since the
// fallback only applies when the entry has no policy at all, nothing is
// overridden by it: a policy the operator attached to a public endpoint keeps
// running, and a policy attached only to the internal endpoint still protects
// it.
func (t *Tunnel) policyFor(target *Tunnel) *policy.Compiled {
	if t != nil && t.policy != nil {
		return t.policy
	}
	if target != nil {
		return target.policy
	}
	return nil
}

// connectVerdict runs the endpoint's on_tcp_connect phase against a public
// connection and returns what it decided. It is nil-safe in both the policy and
// the receiver -- no policy is the common case and costs one nil check -- and
// it does not log: the caller decides how a refusal looks in its protocol.
func (t *Tunnel) connectVerdict(c conn.Conn) policy.ConnectVerdict {
	if t == nil {
		return policy.ConnectVerdict{}
	}
	pol := t.policyFor(t)
	if pol == nil {
		return policy.ConnectVerdict{}
	}
	return pol.EvaluateConnect(c.RemoteAddr().String())
}

// Common functionality for registering virtually hosted protocols
func registerVhost(t *Tunnel, protocol string, servingPort int) (err error) {
	vhost := os.Getenv("VHOST")
	if vhost == "" {
		vhost = fmt.Sprintf("%s:%d", opts.domain, servingPort)
	}

	// Canonicalize virtual host by removing default port (e.g. :80 on HTTP)
	defaultPort, ok := defaultPortMap[protocol]
	if !ok {
		return fmt.Errorf("Couldn't find default port for protocol %s", protocol)
	}

	defaultPortSuffix := fmt.Sprintf(":%d", defaultPort)
	if strings.HasSuffix(vhost, defaultPortSuffix) {
		vhost = vhost[0 : len(vhost)-len(defaultPortSuffix)]
	}

	// Canonicalize by always using lower-case
	vhost = strings.ToLower(vhost)

	// Register for specific hostname
	hostname := strings.ToLower(strings.TrimSpace(t.req.Hostname))
	if hostname != "" {
		t.url = fmt.Sprintf("%s://%s", protocol, hostname)
		return tunnelRegistry.Register(t.url, t)
	}

	// Register for specific subdomain
	subdomain := strings.ToLower(strings.TrimSpace(t.req.Subdomain))
	if subdomain != "" {
		t.url = fmt.Sprintf("%s://%s.%s", protocol, subdomain, vhost)
		return tunnelRegistry.Register(t.url, t)
	}

	// Register for random URL
	t.url, err = tunnelRegistry.RegisterRepeat(func() string {
		return fmt.Sprintf("%s://%x.%s", protocol, util.GlobalInt31(), vhost)
	}, t)

	return
}

// registerInternal registers an internal endpoint (SPEC 3.2).
//
// The rules are deliberately narrower than the public ones: a hostname is
// required, it must live under .internal, and there is no subdomain
// assignment and no random URL generation to fall back on. The endpoint never
// touches the public listeners -- it is reachable only through forward_to --
// so it is registered even when the server is not listening for that protocol
// publicly.
func registerInternal(t *Tunnel, protocol string) error {
	// Canonicalize the same way public hostnames are canonicalized
	hostname := strings.ToLower(strings.TrimSpace(t.req.Hostname))
	if hostname == "" {
		return fmt.Errorf("Internal endpoints require a hostname ending in %s", internalSuffix)
	}
	if !strings.HasSuffix(hostname, internalSuffix) {
		return fmt.Errorf("Internal endpoint hostname %s must end in %s", hostname, internalSuffix)
	}

	t.url = fmt.Sprintf("%s://%s", protocol, hostname)
	return tunnelRegistry.Register(t.url, t)
}

// Create a new tunnel from a registration message received
// on a control channel
func NewTunnel(m *msg.ReqTunnel, ctl *Control) (t *Tunnel, err error) {
	t = &Tunnel{
		req:    m,
		start:  time.Now(),
		ctl:    ctl,
		owner:  ownerOf(ctl),
		Logger: log.NewPrefixLogger(),
	}

	if err = t.validateRequest(); err != nil {
		return
	}

	// Compile the traffic policy before the tunnel claims its url, so that a
	// policy the server cannot enforce fails the registration instead of
	// leaving an endpoint that looks protected and is not (SPEC 3.3). The
	// work is done once per tunnel, not once per connection.
	if !m.TrafficPolicy.IsZero() {
		if t.policy, err = m.TrafficPolicy.Compile(); err != nil {
			err = fmt.Errorf("invalid traffic policy: %w", err)
			return
		}
	}

	if err = t.register(); err != nil {
		return
	}

	// pre-encode the http basic auth for fast comparisons later
	if m.HttpAuth != "" {
		m.HttpAuth = "Basic " + base64.StdEncoding.EncodeToString([]byte(m.HttpAuth))
	}

	t.AddLogPrefix(t.Id())
	t.Info("Registered new tunnel on: %s", t.ctl.conn.Id())

	metrics.OpenTunnel(t)
	observe.onTunnelOpen(t)
	return
}

// validateRequest canonicalizes the endpoint request and rejects the
// combinations this server cannot serve (SPEC 3.2/3.5).
func (t *Tunnel) validateRequest() error {
	m := t.req

	// Canonicalize the binding once here, so that every comparison downstream
	// -- the registry key in particular -- is an exact match.
	m.Binding = strings.ToLower(strings.TrimSpace(m.Binding))
	switch m.Binding {
	case BindingPublic, BindingInternal:
	default:
		return fmt.Errorf("Binding %s is not supported", m.Binding)
	}

	switch m.Protocol {
	case "tcp":
		if m.Binding == BindingInternal {
			// ngrok also serves tcp://x.internal:port; this cluster does not
			return fmt.Errorf("Internal TCP endpoints are not supported yet, use http or https")
		}
		if m.ForwardTo != "" {
			// A TCP connection is dispatched to the bucket that owns the
			// listener and internal TCP endpoints cannot exist yet, so a
			// forward chain out of TCP could never resolve. Refuse the
			// registration instead of silently sending the traffic straight
			// to this client and ignoring forward_to.
			return fmt.Errorf("forward_to is only supported for http and https endpoints")
		}
	case "http", "https":
	default:
		return fmt.Errorf("Protocol %s is not supported", m.Protocol)
	}

	return nil
}

// register binds the endpoint and records it in the tunnel registry.
func (t *Tunnel) register() error {
	m := t.req

	switch m.Protocol {
	case "tcp":
		return t.registerTcp()

	case "http", "https":
		// Internal endpoints are invisible to the public listener, so they do
		// not need one to be running and never consult the vhost domain.
		if m.Binding == BindingInternal {
			return registerInternal(t, m.Protocol)
		}

		l, ok := listeners[m.Protocol]
		if !ok {
			return fmt.Errorf("Not listening for %s connections", m.Protocol)
		}

		return registerVhost(t, m.Protocol, l.Addr.(*net.TCPAddr).Port)
	}

	return fmt.Errorf("Protocol %s is not supported", m.Protocol)
}

// registerTcp binds a public TCP listener for this tunnel, or joins the
// listener that an existing pooling member already bound (SPEC 3.2).
func (t *Tunnel) registerTcp() error {
	m := t.req

	// A pooling TCP tunnel shares the port -- and therefore the listener --
	// that the first member bound; it never binds a second one. Which bucket
	// to join is identified by the remote port the client asked for, or by the
	// affinity cache for a client coming back to its old port. If neither
	// names a live pooling bucket, this tunnel is the one that binds.
	//
	// IsPooling and the bind that may follow it are not atomic: two pooling
	// clients racing for an unbound port would both try to bind, and the
	// second bind fails in the kernel. That is a clean error to the loser
	// rather than a corrupted pool, so the race is left alone.
	if m.Pooling {
		if url := t.pooledTcpUrl(); url != "" && tunnelRegistry.IsPooling(url) {
			t.url = url
			return tunnelRegistry.Register(t.url, t)
		}
	}

	bindTcp := func(port int) error {
		listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("0.0.0.0"), Port: port})
		if err != nil {
			return t.ctl.conn.Error("Error binding TCP listener: %v", err)
		}
		t.listener = listener

		// create the url
		addr := listener.Addr().(*net.TCPAddr)
		t.url = fmt.Sprintf("tcp://%s:%d", opts.domain, addr.Port)

		// register it
		if err = tunnelRegistry.RegisterAndCache(t.url, t); err != nil {
			// This should never be possible because the OS will
			// only assign available ports to us.
			listener.Close()
			t.listener = nil
			return fmt.Errorf("TCP listener bound, but failed to register %s", t.url)
		}

		go t.listenTcp(listener)
		return nil
	}

	// use the custom remote port you asked for
	if m.RemotePort != 0 {
		return bindTcp(int(m.RemotePort))
	}

	// try to return to you the same port you had before
	cachedUrl := tunnelRegistry.GetCachedRegistration(t)
	if cachedUrl != "" {
		parts := strings.Split(cachedUrl, ":")
		portPart := parts[len(parts)-1]
		port, parseErr := strconv.Atoi(portPart)
		if parseErr != nil {
			t.ctl.conn.Error("Failed to parse cached url port as integer: %s", portPart)
		} else if bindErr := bindTcp(port); bindErr != nil {
			// we have a valid, cached port, but we could not bind it
			t.ctl.conn.Warn("Failed to get custom port %d: %v, trying a random one", port, bindErr)
		} else {
			// success, we're done
			return nil
		}
	}

	// Bind for TCP connections
	return bindTcp(0)
}

// pooledTcpUrl returns the url this pooling TCP tunnel would share with an
// existing bucket, or "" when that cannot be known without binding a port.
func (t *Tunnel) pooledTcpUrl() string {
	if t.req.RemotePort != 0 {
		return fmt.Sprintf("tcp://%s:%d", opts.domain, t.req.RemotePort)
	}
	return tunnelRegistry.GetCachedRegistration(t)
}

func (t *Tunnel) Shutdown() {
	t.Info("Shutting down")

	// mark that we're shutting down
	atomic.StoreInt32(&t.closing, 1)

	// Close the public listener if this is the tunnel that bound it. Pooling
	// members share the creator's listener and must leave it open for the
	// others; the listener dies with its creator (SPEC 3.2).
	if t.listener != nil {
		t.listener.Close()
	}

	// remove only ourselves: the bucket disappears with its last member
	tunnelRegistry.Remove(t.url, t)

	// let the control connection know we're shutting down
	// currently, only the control connection shuts down tunnels,
	// so it doesn't need to know about it
	// t.ctl.stoptunnel <- t

	metrics.CloseTunnel(t)
	observe.onTunnelClose(t)
}

func (t *Tunnel) Id() string {
	return t.url
}

// Listens for new public tcp connections from the internet.
func (t *Tunnel) listenTcp(listener *net.TCPListener) {
	for {
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Warn("listenTcp failed with error %v", r)
				}
			}()

			// accept public connections
			tcpConn, err := listener.AcceptTCP()

			if err != nil {
				// not an error, we're shutting down this tunnel
				if atomic.LoadInt32(&t.closing) == 1 {
					return
				}

				t.Error("Failed to accept new TCP connection: %v", err)
				return
			}

			publicConn := conn.Wrap(tcpConn, "pub")
			publicConn.AddLogPrefix(t.Id())
			publicConn.Info("New connection from %v", publicConn.RemoteAddr())
			ip := remoteIP(publicConn.RemoteAddr())
			if !publicLimiter.allow(ip) {
				atomic.AddUint64(&rateDropCount, 1)
				observe.events.publish(map[string]interface{}{"type": "rate_limit_drop", "scope": "public_tcp", "ip": ip, "at": time.Now().UTC()})
				if warnSampler.allow("tcp-rate:" + ip) {
					publicConn.Warn("Rate-limited TCP public connection from %s", ip)
				}
				publicConn.Close()
				return
			}
			if !connLimiter.acquire(ip) {
				observe.events.publish(map[string]interface{}{"type": "connection_cap_drop", "scope": "public_tcp", "ip": ip, "at": time.Now().UTC()})
				if warnSampler.allow("tcp-cap:" + ip) {
					publicConn.Warn("Connection cap reached for %s", ip)
				}
				publicConn.Close()
				return
			}
			incPublicConns()

			go func(ip string, c conn.Conn) {
				defer connLimiter.release(ip)
				defer decPublicConns()

				// Hand the connection to a member of the bucket that shares
				// this listener, round-robin, so that pooling spreads TCP
				// connections across the agents that registered the port
				// (SPEC 3.2). A non-pooling bucket contains only us, and we
				// fall back to ourselves if our registration is already gone.
				member := t
				if tunnelRegistry != nil {
					if m := tunnelRegistry.Get(t.url); m != nil {
						member = m
					}
				}

				// The endpoint's on_tcp_connect phase, before an agent is
				// asked for a proxy connection at all (SPEC 3.3). A TCP
				// client has no protocol to be answered in, so a refusal is
				// the connection closing: the response the verdict carries is
				// for the HTTP path, where it means something.
				if v := member.connectVerdict(c); v.Deny {
					c.Info("Traffic policy refused the connection: %s", v.Reason)
					c.Close()
					return
				}

				member.HandlePublicConnection(c, member.policyFor(member))
			}(ip, publicConn)
		}()

		if atomic.LoadInt32(&t.closing) == 1 {
			return
		}
	}
}

// HandlePublicConnection serves one public connection over a proxy connection
// taken from the pool, joining the two until either side closes.
//
// pol is the endpoint's compiled traffic policy (nil when it has none). It is
// passed in rather than read off the receiver because the connection is served
// by whichever tunnel terminates a forward_to chain, and the policy that
// governs it was decided by the caller (see policyFor).
func (t *Tunnel) HandlePublicConnection(publicConn conn.Conn, pol *policy.Compiled) {
	defer publicConn.Close()
	defer func() {
		if r := recover(); r != nil {
			publicConn.Warn("HandlePublicConnection failed with error %v", r)
		}
	}()

	startTime := time.Now()
	metrics.OpenConnection(t, publicConn)
	observe.onConnOpen(t)

	var proxyConn conn.Conn
	var err error
	for i := 0; i < (2 * proxyMaxPoolSize); i++ {
		// get a proxy connection
		if proxyConn, err = t.ctl.GetProxy(); err != nil {
			t.Warn("Failed to get proxy connection: %v", err)
			return
		}
		defer proxyConn.Close()
		t.Info("Got proxy connection %s", proxyConn.Id())
		proxyConn.AddLogPrefix(t.Id())

		// tell the client we're going to start using this proxy connection
		startPxyMsg := &msg.StartProxy{
			Url:        t.url,
			ClientAddr: publicConn.RemoteAddr().String(),
		}

		if err = msg.WriteMsg(proxyConn, startPxyMsg); err != nil {
			proxyConn.Warn("Failed to write StartProxyMessage: %v, attempt %d", err, i)
			proxyConn.Close()
		} else {
			// success
			break
		}
	}

	if err != nil {
		// give up
		publicConn.Error("Too many failures starting proxy connection")
		return
	}

	// To reduce latency handling tunnel connections, we employ the following curde heuristic:
	// Whenever we take a proxy connection from the pool, replace it with a new one
	//
	// The pool does not care which transport a replacement arrives on: a client
	// that multiplexes answers this ReqProxy with a stream on its mux session,
	// a client that does not answers it with a fresh dial, and both are
	// registered into the pool by the same RegisterProxy call (SPEC 3.1). The
	// refill policy is therefore unchanged -- one conn per outstanding request,
	// plus one when the pool is empty (GetProxy) -- and only the cost of a
	// refill differs: no TCP+TLS handshake, no setup round trip.
	util.PanicToError(func() { t.ctl.out <- &msg.ReqProxy{} })

	// no timeouts while connections are joined
	proxyConn.SetDeadline(time.Time{})

	// join the public and proxy connections
	bytesIn, bytesOut := t.join(publicConn, proxyConn, pol)
	metrics.CloseConnection(t, publicConn, startTime, bytesIn, bytesOut)
	observe.onConnClose(t, bytesIn, bytesOut)
}

// join shuttles bytes between a public connection and the proxy connection
// that carries it to the agent, running the endpoint's traffic policy over the
// heads in both directions.
//
// The join direction mirrors the client's (client/model.go, relay): each
// rewriter wraps the *source* end of the direction it rewrites -- the request
// rewriter reads the public connection, the response rewriter reads the proxy
// connection -- and conn.Join(fromUpstream, toUpstream) therefore reports
// requests first and responses second, the same order the raw join reported,
// so bytesIn keeps its meaning.
//
// The server's rewriter policy carries the hooks and nothing else. Host
// rewriting, X-Forwarded-For injection and response compression are the
// client's work (its own rewriter does them on the way out), and doing them
// again here would do them twice on the same bytes. Without a policy the raw
// join runs, which is the path this server took before policies existed.
func (t *Tunnel) join(publicConn, proxyConn conn.Conn, pol *policy.Compiled) (bytesIn, bytesOut int64) {
	if pol == nil {
		return conn.Join(publicConn, proxyConn)
	}

	// The hooks are built per connection: they hold that connection's vars.
	// A phase with no actions produces no hook, and if neither phase has any,
	// the connection takes the raw join.
	clientAddr := publicConn.RemoteAddr().String()
	reqHook := pol.RequestHook(t, clientAddr)
	respHook := pol.ResponseHook(t, clientAddr)
	if reqHook == nil && respHook == nil {
		return conn.Join(publicConn, proxyConn)
	}

	toUpstream, fromUpstream := rewriter.NewConnPair(publicConn, proxyConn, &rewriter.Policy{
		RequestHook:  reqHook,
		ResponseHook: respHook,
	})
	return conn.Join(fromUpstream, toUpstream)
}
