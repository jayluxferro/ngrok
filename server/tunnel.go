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

// defaultPortMap is the port a tunnel whose url does not carry one is answered
// on. It has exactly the keys registerVhost can see: a protocol outside it is
// refused by validateRequest before the lookup, so an entry here that no
// protocol can reach (the "smtp": 25 this map used to carry, inherited from
// upstream ngrok, which served smtp) would only be dead weight. The reserved
// .internal namespace lives in package msg with the rest of the wire
// vocabulary: msg.InternalSuffix.
var defaultPortMap = map[string]int{
	msg.ProtoHTTP:  80,
	msg.ProtoHTTPS: 443,
}

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

	// claimedPort is the fixed remote port this tunnel holds a claim on in
	// the port ownership registry (SPEC-CLUSTER5 4.1), 0 when it holds none.
	// It is a field rather than a re-reading of req.RemotePort because a
	// claim can exist for a port the request did not name (the affinity-cache
	// rebind) and must not exist for a tunnel that only joined a pool.
	claimedPort int

	// logger
	log.Logger

	// closing
	closing int32
}

// internal reports whether this tunnel is an internal (.internal) endpoint.
func (t *Tunnel) internal() bool {
	return t.req != nil && t.req.Binding == msg.BindingInternal
}

// agentTLS reports whether this endpoint terminates public TLS in its agent
// (SPEC-CLUSTER5 5.1/5.2): the server routes such an endpoint's traffic by
// SNI and joins it as raw bytes, and never holds the certificate, the keys,
// or the plaintext.
//
// The protocol check is part of the definition, not a guard: agent
// termination is a property of the https leg only. A multi-leg request
// ("http+https") carries the field on every leg the server splits it into,
// so an http or tcp leg arrives with TLSTermination set and must simply have
// nothing to do with it -- validateRequest normalizes and checks the value's
// spelling, and this is where it takes effect.
func (t *Tunnel) agentTLS() bool {
	return t.req != nil && t.req.Protocol == msg.ProtoHTTPS && t.req.TLSTermination == msg.TLSTerminationAgent
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
// connection and returns what it decided. It is nil-safe in the policy -- no
// policy is the common case and costs one nil check -- and it does not log: the
// caller decides how a refusal looks in its protocol.
//
// The policy is passed in rather than read off a receiver because the verdict
// and the hooks that follow it have to be decided by the same policy: on the
// HTTP path both come from entry.policyFor(target), and evaluating the connect
// phase against the entry tunnel's own policy while the hooks run the target's
// meant an internal endpoint's restrict-ips never ran at all (see httpHandler).
func connectVerdict(pol *policy.Compiled, c conn.Conn) policy.ConnectVerdict {
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

	// A public binding derives its hostname from vhost (the domain or the
	// VHOST override): if the derivation ends in .internal, every derived url
	// would squat the reserved namespace through the public path.
	// validateRequest covers the explicit-hostname branch; this covers the
	// derived ones.
	if strings.HasSuffix(vhost, msg.InternalSuffix) {
		return fmt.Errorf("%s: the public vhost %q ends in %s, which would derive publicly bound %s hostnames; refusing to register",
			endpointName(t.req), vhost, msg.InternalSuffix, msg.InternalSuffix)
	}

	// Register for specific hostname
	hostname := strings.ToLower(strings.TrimSpace(t.req.Hostname))
	if hostname != "" {
		t.url = fmt.Sprintf("%s://%s", protocol, hostname)
		if err = tunnelRegistry.Register(t.url, t); err != nil {
			return fmt.Errorf("%s: %w", endpointName(t.req), err)
		}
		return nil
	}

	// Register for specific subdomain
	subdomain := strings.ToLower(strings.TrimSpace(t.req.Subdomain))
	if subdomain != "" {
		t.url = fmt.Sprintf("%s://%s.%s", protocol, subdomain, vhost)
		if err = tunnelRegistry.Register(t.url, t); err != nil {
			return fmt.Errorf("%s: %w", endpointName(t.req), err)
		}
		return nil
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
// required, it must live under .internal with a name in front of the suffix,
// and there is no subdomain assignment and no random URL generation to fall
// back on. The endpoint never touches the public listeners -- it is reachable
// only through forward_to -- so it is registered even when the server is not
// listening for that protocol publicly.
//
// These are the client's rules (client/config.go, validateInternalEndpoint),
// enforced here as well. A server cannot assume the client checked anything:
// the tokens namespace, so the reach of an internal endpoint is bounded by the
// owner either way, but the spelling is not cosmetic -- what gets registered is
// what forward_to has to resolve, and an endpoint whose name is not the
// canonical one (mixed case, a space in the middle, "https:///svc.internal")
// either cannot be reached by the url the operator wrote or is a different
// endpoint than the one they think they registered.
func registerInternal(t *Tunnel, protocol string) error {
	raw := t.req.Hostname
	hostname := strings.ToLower(strings.TrimSpace(raw))

	if hostname == "" {
		return fmt.Errorf("Internal endpoints require a hostname ending in %s (for example \"myapp%s\")", msg.InternalSuffix, msg.InternalSuffix)
	}
	// Checked on the raw value: a hostname that is only lowercase because the
	// server lowercased it is not the name the client wrote, and the mismatch
	// is exactly what this rejects (the client refuses it too, with the same
	// reasoning).
	if raw != hostname {
		return fmt.Errorf("Internal endpoint hostname %q must be lowercase and unpadded (use %q)", raw, hostname)
	}
	if strings.ContainsAny(hostname, " \t\r\n/") {
		return fmt.Errorf("Internal endpoint hostname %q must not contain spaces or '/'", hostname)
	}
	if !strings.HasSuffix(hostname, msg.InternalSuffix) {
		return fmt.Errorf("Internal endpoint hostname %q must end in %s (for example \"myapp%s\")", hostname, msg.InternalSuffix, msg.InternalSuffix)
	}
	if len(hostname) == len(msg.InternalSuffix) {
		// the suffix alone names nothing: ".internal" is not an endpoint
		return fmt.Errorf("Internal endpoint hostname %q needs a name in front of %s (for example \"myapp%s\")", hostname, msg.InternalSuffix, msg.InternalSuffix)
	}

	t.url = fmt.Sprintf("%s://%s", protocol, hostname)
	if err := tunnelRegistry.Register(t.url, t); err != nil {
		return fmt.Errorf("Internal endpoint %s could not be registered: %w", t.url, err)
	}
	return nil
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
//
// Every error names the endpoint it is about -- the protocol and the hostname
// or port the client asked for. The client correlates an error with the request
// it sent by ReqId (see Control.registerTunnel), but a client multiplexing
// several requests off one message, and a human reading the log, have nothing
// but the text.
func (t *Tunnel) validateRequest() error {
	m := t.req
	what := endpointName(m)

	// Canonicalize the binding once here, so that every comparison downstream
	// -- the registry key in particular -- is an exact match.
	m.Binding = strings.ToLower(strings.TrimSpace(m.Binding))
	switch m.Binding {
	case msg.BindingPublic, msg.BindingInternal:
	default:
		return fmt.Errorf("%s: Binding %s is not supported", what, m.Binding)
	}

	// The .internal namespace belongs to internal endpoints and to nothing
	// else. The public registry is keyed by the bare url and internal endpoints
	// by an owner-namespaced key, so a public endpoint named x.internal is
	// unreachable rather than dangerous -- but it is also a name the client
	// refuses to send (client/config.go) and an operator would read as private
	// while it is public: whoever registers it first wins the name, and the
	// public listener 404s it. Refuse the oxymoron instead of registering an
	// endpoint nobody can reach. This is the server-side half of a rule that
	// until now lived only in the client, and it is enforced before the url is
	// claimed (see Tunnel.register), so a refused hostname never occupies the
	// name it asked for.
	if m.Binding != msg.BindingInternal && strings.HasSuffix(strings.ToLower(strings.TrimSpace(m.Hostname)), msg.InternalSuffix) {
		return fmt.Errorf("%s: hostname %q ends in %s, which requires binding internal (the public listener never routes %s hosts)",
			what, strings.TrimSpace(m.Hostname), msg.InternalSuffix, msg.InternalSuffix)
	}

	switch m.Protocol {
	case msg.ProtoTCP:
		if m.Binding == msg.BindingInternal {
			// ngrok also serves tcp://x.internal:port; this cluster does not
			return fmt.Errorf("%s: Internal TCP endpoints are not supported yet, use http or https", what)
		}
		if m.ForwardTo != "" {
			// A TCP connection is dispatched to the bucket that owns the
			// listener and internal TCP endpoints cannot exist yet, so a
			// forward chain out of TCP could never resolve. Refuse the
			// registration instead of silently sending the traffic straight
			// to this client and ignoring forward_to.
			return fmt.Errorf("%s: forward_to is only supported for http and https endpoints", what)
		}
	case msg.ProtoHTTP, msg.ProtoHTTPS:
	default:
		return fmt.Errorf("%s: Protocol %s is not supported", what, m.Protocol)
	}

	// TLSTermination (SPEC-CLUSTER5 5.1) is canonicalized like Binding: an
	// exact spelling, accepted in exactly two values. A typo ("agents",
	// "Agent-side") is refused rather than read as the edge default, because
	// silently falling back to edge termination would register an endpoint
	// where the server holds the certificate the operator believes the agent
	// holds -- the one fallback this field must never take.
	//
	// It is honored only on the https leg (Tunnel.agentTLS). On the http and
	// tcp legs of a multi-leg request it is deliberately inert rather than an
	// error: the field rides on the request as a whole while the server
	// registers one leg at a time, so "http+https" with agent termination --
	// a legitimate endpoint pair -- would fail outright if the http leg
	// refused a value only the https leg can act on. There is no TLS on those
	// legs, so there is nothing whose termination could be misconfigured.
	m.TLSTermination = strings.ToLower(strings.TrimSpace(m.TLSTermination))
	switch m.TLSTermination {
	case msg.TLSTerminationEdge, msg.TLSTerminationAgent:
	default:
		return fmt.Errorf("%s: TLSTermination %q is not supported (use %q for server-side termination or %q for agent-side termination)",
			what, m.TLSTermination, msg.TLSTerminationEdge, msg.TLSTerminationAgent)
	}

	return nil
}

// endpointName describes the endpoint a request is asking for, for use in error
// messages: the protocol plus whatever names the endpoint (hostname, subdomain
// or remote port). It is deliberately built from the raw request rather than
// from a Tunnel, because every caller of it is a registration that failed
// before a Tunnel existed.
func endpointName(m *msg.ReqTunnel) string {
	name := m.Protocol
	if name == "" {
		name = "endpoint"
	}

	switch {
	case m.Hostname != "":
		return fmt.Sprintf("%s endpoint %s", name, strings.TrimSpace(m.Hostname))
	case m.Subdomain != "":
		return fmt.Sprintf("%s endpoint %s.%s", name, strings.TrimSpace(m.Subdomain), opts.domain)
	case m.RemotePort != 0:
		return fmt.Sprintf("%s endpoint %s:%d", name, opts.domain, m.RemotePort)
	}
	return name + " endpoint"
}

// register binds the endpoint and records it in the tunnel registry.
func (t *Tunnel) register() error {
	m := t.req

	switch m.Protocol {
	case msg.ProtoTCP:
		return t.registerTcp()

	case msg.ProtoHTTP, msg.ProtoHTTPS:
		// Internal endpoints are invisible to the public listener, so they do
		// not need one to be running and never consult the vhost domain.
		if m.Binding == msg.BindingInternal {
			return registerInternal(t, m.Protocol)
		}

		l, ok := listeners[m.Protocol]
		if !ok {
			return fmt.Errorf("%s: Not listening for %s connections", endpointName(m), m.Protocol)
		}

		return registerVhost(t, m.Protocol, l.Addr.(*net.TCPAddr).Port)
	}

	return fmt.Errorf("%s: Protocol %s is not supported", endpointName(m), m.Protocol)
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
		return t.bindClaimedTcp(int(m.RemotePort), bindTcp)
	}

	// try to return to you the same port you had before
	cachedUrl := tunnelRegistry.GetCachedRegistration(t)
	if cachedUrl != "" {
		parts := strings.Split(cachedUrl, ":")
		portPart := parts[len(parts)-1]
		port, parseErr := strconv.Atoi(portPart)
		if parseErr != nil {
			t.ctl.conn.Error("Failed to parse cached url port as integer: %s", portPart)
		} else if bindErr := t.bindClaimedTcp(port, bindTcp); bindErr != nil {
			// we have a valid, cached port, but we could not claim or bind it.
			// A claim refusal (another account took the port while we were
			// away) reads exactly like the bind failures it sits next to here:
			// the port is gone, and a random one is the fallback it always was.
			t.ctl.conn.Warn("Failed to get custom port %d: %v, trying a random one", port, bindErr)
		} else {
			// success, we're done
			return nil
		}
	}

	// Bind for TCP connections
	return bindTcp(0)
}

// bindClaimedTcp claims port for this tunnel's account and binds it, in that
// order: the ownership registry (SPEC-CLUSTER5 4.1) is consulted before the
// kernel sees the bind, so a port another account holds is refused with the
// claim's reason and never turns into the raw "address already in use" that
// hides who holds it.
//
// When the bind itself fails -- a privileged port, or a process outside this
// registry holding the number -- the claim is released again: a port this
// server could not bind must not stay locked against the account that asked
// for it, and the next registration starts from a clean slate either way.
// The claim that survives is recorded on the tunnel (t.claimedPort) so its
// teardown releases exactly what it holds, pooling joiners included by
// construction: a tunnel that joins a pooling bucket never binds, and so
// never claims, and its Shutdown has nothing to release.
func (t *Tunnel) bindClaimedTcp(port int, bindTcp func(int) error) error {
	if err := portClaims.Claim(port, t.owner); err != nil {
		return fmt.Errorf("%s: %w", endpointName(t.req), err)
	}

	t.claimedPort = port
	if err := bindTcp(port); err != nil {
		portClaims.Release(port, t.owner)
		t.claimedPort = 0
		return err
	}
	return nil
}

// pooledTcpUrl returns the url this pooling TCP tunnel would share with an
// existing bucket, or "" when that cannot be known without binding a port.
func (t *Tunnel) pooledTcpUrl() string {
	if t.req.RemotePort != 0 {
		return fmt.Sprintf("tcp://%s:%d", opts.domain, t.req.RemotePort)
	}
	return tunnelRegistry.GetCachedRegistration(t)
}

// Shutdown takes this endpoint down. A pooling member removes only itself; the
// tunnel that owns a listener takes the whole pool with it, because the
// listener every member was sharing dies here (SPEC 3.2).
func (t *Tunnel) Shutdown() {
	t.Info("Shutting down")

	// mark that we're shutting down
	atomic.StoreInt32(&t.closing, 1)

	// Release the fixed-port claim this tunnel holds (SPEC-CLUSTER5 4.1).
	// This is the release side of bindClaimedTcp's claim: the port becomes
	// available to other accounts here, at teardown, and not one socket
	// sooner -- which is the whole point of the registry. A tunnel that
	// joined a pooling bucket never claimed a port and releases nothing.
	if t.claimedPort != 0 {
		portClaims.Release(t.claimedPort, t.owner)
		t.claimedPort = 0
	}

	// Close the public listener if this is the tunnel that bound it. Pooling
	// members share the creator's listener and must leave it open for the
	// others; the listener dies with its creator (SPEC 3.2).
	if t.listener != nil {
		t.listener.Close()

		// The bucket is not this tunnel's alone: the members of the pool are
		// registered under the same url and reach the public world only through
		// the listener that just closed. Leaving the bucket behind would leave
		// a pool key pointing at a port nothing listens on -- IsPooling would
		// keep advertising it and a new pooling tunnel would join a bucket it
		// can never serve from. Take the bucket down and shut its orphaned
		// members down with it: their endpoint is gone, and a client that keeps
		// listing a tunnel that no longer exists is worse than one that is told
		// its tunnel closed.
		for _, orphan := range tunnelRegistry.DelBucket(t.url) {
			if orphan != t {
				orphan.Info("Shutting down: the pooling listener for %s was closed by its owner", t.url)
				orphan.Shutdown()
			}
		}
	} else {
		// remove only ourselves: a bucket of members disappears with its last
		// member
		tunnelRegistry.Remove(t.url, t)
	}

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
				observe.events.publishRateLimitDrop(scopePublicTCP, ip)
				if warnSampler.allow("tcp-rate:" + ip) {
					publicConn.Warn("Rate-limited TCP public connection from %s", ip)
				}
				publicConn.Close()
				return
			}
			if !connLimiter.acquire(ip) {
				observe.events.publishConnectionCapDrop(scopePublicTCP, ip)
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
				//
				// member is the terminus for TCP -- forward_to is refused for
				// TCP endpoints -- so policyFor(member) is the same policy the
				// join below runs.
				if v := connectVerdict(member.policyFor(member), c); v.Deny {
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
		t.Info("Got proxy connection %s", proxyConn.Id())
		proxyConn.AddLogPrefix(t.Id())

		// tell the client we're going to start using this proxy connection
		startPxyMsg := &msg.StartProxy{
			Url:        t.url,
			ClientAddr: publicConn.RemoteAddr().String(),
		}

		if err = msg.WriteMsg(proxyConn, startPxyMsg); err != nil {
			proxyConn.Warn("Failed to write StartProxyMessage: %v, attempt %d", err, i)
			// Close the conn that just failed, here, rather than deferring it:
			// a defer in this loop would pile up one Close per failed attempt
			// and run them all when this function returns, so every dead proxy
			// conn would stay open -- and stay registered on the client, which
			// keeps its end until the socket goes away -- for the whole life of
			// the public connection being retried. The successful conn is the
			// one the defer below closes.
			proxyConn.Close()
			continue
		}

		// success
		break
	}

	if err != nil {
		// give up
		publicConn.Error("Too many failures starting proxy connection")
		return
	}
	defer proxyConn.Close()

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
// ZERO-KNOWLEDGE PASSTHROUGH (SPEC-CLUSTER5 5.2/8.2). For an agent-terminated
// endpoint the join is RAW BYTES ONLY, whatever policies exist: the public leg
// is TLS whose keys this server does not hold, every byte on it is ciphertext,
// and there is no plaintext head here for a rewriter hook to parse -- pointing
// the request/response hooks at this stream would feed them TLS records, and
// worse, would mean the server was parsing traffic the whole design promises
// it cannot read. The on_http_request / on_http_response phases for such an
// endpoint run in the AGENT (client/model.go serveProxyConnection), where the
// plaintext exists; on_tcp_connect already ran server-side, in serveAgentTLS.
// Everything else about the endpoint keeps working over the raw join:
// rewriting, XFF and compression happen agent-side after it terminates the
// TLS, and the 502-on-dead-upstream path lives there too.
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
	if t.agentTLS() {
		return conn.Join(publicConn, proxyConn)
	}

	// A connection that arrived over an agent-terminated entry endpoint's SNI
	// route stays ciphertext even where its forward_to chain lands: if that is
	// a plain-HTTP endpoint, THIS tunnel holds no TLS key for the stream
	// either, and its hooks would be parsing TLS records. The marker set by
	// serveAgentTLS carries the entry endpoint's zero-knowledge property with
	// the connection (SPEC-CLUSTER5 8.2).
	if _, raw := publicConn.(*passthroughConn); raw {
		return conn.Join(publicConn, proxyConn)
	}

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
