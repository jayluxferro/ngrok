package server

// Tests for registry v2: pooling buckets, owner-namespaced internal endpoints
// and the forward_to chain (SPEC cluster 2, sections 3.1-3.3, 3.5).
//
// The production entry points -- NewTunnel and the public HTTP path -- read
// process globals (opts, tunnelRegistry, listeners), so every test that goes
// through them installs its own globals and restores the previous ones
// afterwards. The connections in these tests are real loopback TCP pairs
// because conn.Wrap only understands *net.TCPConn, which rules out net.Pipe.

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"ngrok/conn"
	"ngrok/msg"
	"ngrok/util"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// fixtures

// setupTestRegistry installs fresh process globals for a test and restores
// whatever was there before it.
func setupTestRegistry(t *testing.T) *TunnelRegistry {
	t.Helper()

	prevOpts, prevRegistry, prevListeners := opts, tunnelRegistry, listeners
	t.Cleanup(func() {
		opts, tunnelRegistry, listeners = prevOpts, prevRegistry, prevListeners
	})

	opts = &Options{domain: "ngrok.test"}
	tunnelRegistry = NewTunnelRegistry(1024, "")

	// Only Addr is read at registration time (to canonicalize away the
	// default port): these are not sockets, nothing is bound and no accept
	// loop runs.
	listeners = map[string]*conn.Listener{
		"http":  {Addr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 80}},
		"https": {Addr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}},
	}

	return tunnelRegistry
}

// tcpPair returns a connected loopback TCP pair.
func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()

	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("failed to listen for a test connection pair: %v", err)
	}
	defer listener.Close()

	client, err := net.DialTCP("tcp", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatalf("failed to dial the test connection pair: %v", err)
	}

	server, err := listener.AcceptTCP()
	if err != nil {
		client.Close()
		t.Fatalf("failed to accept the test connection pair: %v", err)
	}

	t.Cleanup(func() {
		client.Close()
		server.Close()
	})

	return client, server
}

// testControl returns a Control whose connection is a real loopback TCP
// connection: registration reads the remote address for the affinity cache,
// and conn.Wrap refuses anything that is not a *net.TCPConn.
//
// The four shutdowns are the ones NewControl installs. They are part of what a
// control is, not decoration: registerTunnel begins the control's shutdown when
// a registration fails on a control with no tunnels left, so a fixture that
// leaves them nil panics the moment a registration is refused.
func testControl(t *testing.T, user string) *Control {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen for a test control connection: %v", err)
	}
	t.Cleanup(func() { listener.Close() })

	netConn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial the test control connection: %v", err)
	}

	ctlConn := conn.Wrap(netConn, "ctl")
	if ctlConn == nil {
		t.Fatalf("the test control connection is not a *net.TCPConn")
	}
	t.Cleanup(func() { ctlConn.Close() })

	return &Control{
		auth:            &msg.Auth{User: user, OS: "linux"}, // metrics reads auth.OS
		conn:            ctlConn,
		out:             make(chan msg.Message, 16),
		in:              make(chan msg.Message, 16),
		proxies:         make(chan conn.Conn, 16),
		lastPing:        time.Now(),
		writerShutdown:  util.NewShutdown(),
		readerShutdown:  util.NewShutdown(),
		managerShutdown: util.NewShutdown(),
		shutdown:        util.NewShutdown(),
	}
}

// registerTestTunnel registers through the real NewTunnel entry point.
func registerTestTunnel(t *testing.T, ctl *Control, req msg.ReqTunnel) *Tunnel {
	t.Helper()

	tun, err := NewTunnel(&req, ctl)
	if err != nil {
		t.Fatalf("NewTunnel(%+v) failed: %v", req, err)
	}
	t.Cleanup(tun.Shutdown)
	return tun
}

// internalTunnel registers an internal endpoint straight into reg, with no
// control connection, so that chain tests stay focused on the registry.
func internalTunnel(t *testing.T, reg *TunnelRegistry, url, owner, forwardTo string) *Tunnel {
	t.Helper()

	protocol, hostname, ok := strings.Cut(url, "://")
	if !ok {
		t.Fatalf("bad test url %q", url)
	}

	tun := &Tunnel{
		url:   url,
		owner: owner,
		req: &msg.ReqTunnel{
			Protocol:  protocol,
			Hostname:  hostname,
			Binding:   msg.BindingInternal,
			ForwardTo: forwardTo,
		},
	}
	if err := reg.Register(url, tun); err != nil {
		t.Fatalf("registering internal endpoint %s failed: %v", url, err)
	}
	return tun
}

// publicTunnel is internalTunnel's public counterpart.
func publicTunnel(t *testing.T, reg *TunnelRegistry, url, owner, forwardTo string) *Tunnel {
	t.Helper()

	protocol, hostname, _ := strings.Cut(url, "://")
	tun := &Tunnel{
		url:   url,
		owner: owner,
		req:   &msg.ReqTunnel{Protocol: protocol, Hostname: hostname, ForwardTo: forwardTo},
	}
	if err := reg.Register(url, tun); err != nil {
		t.Fatalf("registering public endpoint %s failed: %v", url, err)
	}
	return tun
}

// internalChain registers n internal endpoints owned by owner, each one
// forwarding to the next, and returns them in order.
func internalChain(t *testing.T, reg *TunnelRegistry, prefix, owner string, n int) []*Tunnel {
	t.Helper()

	chain := make([]*Tunnel, n)
	for i := range chain {
		forwardTo := ""
		if i < n-1 {
			forwardTo = fmt.Sprintf("https://%s%d.internal", prefix, i+1)
		}
		chain[i] = internalTunnel(t, reg, fmt.Sprintf("https://%s%d.internal", prefix, i), owner, forwardTo)
	}
	return chain
}

// ---------------------------------------------------------------------------
// SPEC 3.2: pooling

// TestPoolingConflictMatrix covers the conflict rules: a registration is
// refused unless both the existing bucket and the newcomer are pooling.
func TestPoolingConflictMatrix(t *testing.T) {
	const url = "http://pool.ngrok.test"

	cases := []struct {
		name     string
		existing bool
		newcomer bool
		wantErr  bool
	}{
		{"pooling joins a pooling bucket", true, true, false},
		{"a non-pooling tunnel may not join a pooling bucket", true, false, true},
		{"pooling may not take over a non-pooling url", false, true, true},
		{"a duplicate non-pooling url is refused", false, false, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reg := NewTunnelRegistry(1024, "")

			first := &Tunnel{url: url, owner: defaultOwner, req: &msg.ReqTunnel{Pooling: tc.existing}}
			if err := reg.Register(url, first); err != nil {
				t.Fatalf("the first registration failed: %v", err)
			}

			second := &Tunnel{url: url, owner: defaultOwner, req: &msg.ReqTunnel{Pooling: tc.newcomer}}
			err := reg.Register(url, second)
			if tc.wantErr != (err != nil) {
				t.Fatalf("Register returned %v, want an error = %v", err, tc.wantErr)
			}

			want := 1
			if !tc.wantErr {
				want = 2
			}
			if got := len(reg.tunnels[url].tunnels); got != want {
				t.Fatalf("the bucket holds %d tunnels, want %d", got, want)
			}
		})
	}
}

// TestPoolRoundRobinsAcrossMembers checks that Get distributes connections
// over a bucket deterministically instead of picking at random: nine draws
// over three members must hit each member exactly three times.
func TestPoolRoundRobinsAcrossMembers(t *testing.T) {
	const url = "http://pool.ngrok.test"
	reg := NewTunnelRegistry(1024, "")

	members := make([]*Tunnel, 3)
	for i := range members {
		members[i] = &Tunnel{url: url, owner: defaultOwner, req: &msg.ReqTunnel{Pooling: true}}
		if err := reg.Register(url, members[i]); err != nil {
			t.Fatalf("member %d failed to register: %v", i, err)
		}
	}

	draws := map[*Tunnel]int{}
	for i := 0; i < 9; i++ {
		got := reg.Get(url)
		if got == nil {
			t.Fatalf("draw %d found no tunnel", i)
		}
		draws[got]++
	}

	for i, member := range members {
		if draws[member] != 3 {
			t.Fatalf("member %d served %d of 9 connections, want 3", i, draws[member])
		}
	}

	if got := reg.Get("http://nothing.ngrok.test"); got != nil {
		t.Fatalf("Get returned a tunnel for an unregistered url: %s", got.url)
	}
}

// ---------------------------------------------------------------------------
// SPEC 3.2: internal endpoints

// TestInternalEndpointsAreInvisibleToPublicLookup registers an internal
// endpoint and checks that the public lookup cannot see it, while forward_to
// resolution by the same owner can.
func TestInternalEndpointsAreInvisibleToPublicLookup(t *testing.T) {
	reg := NewTunnelRegistry(1024, "")
	const url = "https://svc.internal"

	internalTunnel(t, reg, url, "acct-1", "")

	if got := reg.Get(url); got != nil {
		t.Fatalf("the public lookup of %s returned a tunnel", url)
	}
	if got := reg.GetInternal(url, "acct-1"); got == nil {
		t.Fatalf("the owning account's lookup of %s found nothing", url)
	}
	if got := reg.GetInternal(url, "acct-2"); got != nil {
		t.Fatalf("another account's lookup of %s returned a tunnel", url)
	}
}

// TestInternalEndpointRules exercises the registration rules for internal
// endpoints: a hostname is required, it must live under .internal, the
// endpoint needs no public listener, and TCP internals are refused for now.
func TestInternalEndpointRules(t *testing.T) {
	setupTestRegistry(t)
	ctl := testControl(t, "")

	cases := []struct {
		name    string
		req     msg.ReqTunnel
		wantErr string
	}{
		{
			name:    "a hostname is required",
			req:     msg.ReqTunnel{Protocol: "http", Binding: msg.BindingInternal, Subdomain: "svc"},
			wantErr: "require a hostname",
		},
		{
			name:    "the hostname must be under .internal",
			req:     msg.ReqTunnel{Protocol: "http", Binding: msg.BindingInternal, Hostname: "svc.example.com"},
			wantErr: msg.InternalSuffix,
		},
		{
			// Registration used to canonicalize this to svc.internal. It no
			// longer does: two endpoints whose hostnames differ only in case
			// are the same hostname to every resolver, so accepting one of
			// them as a second name for the other is how a client ends up
			// holding an endpoint it did not ask for. The rule now matches the
			// client's own validator (client/config.go), so a client that got
			// here sent a hostname its own rules would have refused.
			name:    "a mixed case hostname is refused rather than canonicalized",
			req:     msg.ReqTunnel{Protocol: "http", Binding: msg.BindingInternal, Hostname: "SVC.Internal"},
			wantErr: "must be lowercase",
		},
		{
			name:    "the bare suffix is not a hostname",
			req:     msg.ReqTunnel{Protocol: "http", Binding: msg.BindingInternal, Hostname: msg.InternalSuffix},
			wantErr: "needs a name in front of",
		},
		{
			name:    "an internal hostname cannot contain a path",
			req:     msg.ReqTunnel{Protocol: "http", Binding: msg.BindingInternal, Hostname: "svc/evil.internal"},
			wantErr: "must not contain spaces or '/'",
		},
		{
			name:    "an internal hostname cannot contain a space",
			req:     msg.ReqTunnel{Protocol: "http", Binding: msg.BindingInternal, Hostname: "sv c.internal"},
			wantErr: "must not contain spaces or '/'",
		},
		{
			name:    "tcp internals are not supported yet",
			req:     msg.ReqTunnel{Protocol: "tcp", Binding: msg.BindingInternal, Hostname: "svc.internal"},
			wantErr: "not supported yet",
		},
		{
			name:    "unknown bindings are refused",
			req:     msg.ReqTunnel{Protocol: "http", Binding: "loopback", Hostname: "svc.internal"},
			wantErr: "Binding loopback is not supported",
		},
		{
			name:    "forward_to is http only",
			req:     msg.ReqTunnel{Protocol: "tcp", ForwardTo: "https://svc.internal"},
			wantErr: "only supported for http and https",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tun, err := NewTunnel(&tc.req, ctl)
			if err == nil {
				tun.Shutdown()
				t.Fatalf("NewTunnel(%+v) succeeded, want an error", tc.req)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not mention %q", err, tc.wantErr)
			}
		})
	}

	// An internal endpoint does not need a public listener at all: it registers
	// even when the server is not listening for the protocol, while a public
	// endpoint of the same protocol cannot.
	listeners = map[string]*conn.Listener{}

	if _, err := NewTunnel(&msg.ReqTunnel{Protocol: "http", Hostname: "pub.ngrok.test"}, ctl); err == nil {
		t.Fatal("a public http endpoint should require a public listener")
	}

	tun := registerTestTunnel(t, ctl, msg.ReqTunnel{Protocol: "http", Binding: msg.BindingInternal, Hostname: "svc.internal"})
	if tun.url != "http://svc.internal" {
		t.Fatalf("internal endpoint url = %q, want http://svc.internal", tun.url)
	}
	if tun.owner != defaultOwner {
		t.Fatalf("owner = %q, want %q without auth tokens", tun.owner, defaultOwner)
	}
	if got := tunnelRegistry.GetInternal(tun.url, defaultOwner); got != tun {
		t.Fatalf("GetInternal(%s, default) = %v, want the tunnel just registered", tun.url, got)
	}
	if got := tunnelRegistry.Get(tun.url); got != nil {
		t.Fatal("the public lookup found the internal endpoint")
	}
}

// ---------------------------------------------------------------------------
// SPEC 3.2: TCP listener sharing

// armProxyPool gives a control connection a proxy connection ready to hand
// out and returns the test's end of it, already wrapped.
//
// Both ends are wrapped here, and callers arm every proxy connection they
// will ever need *before* the TCP listener exists, i.e. before the listener's
// accept goroutine is created. That ordering is not incidental: conn.Wrap
// draws a random id from the process-wide generator (util.GetGlobalRand
// returns a shared *rand.Rand and conn/conn.go calls Int31 on it directly),
// the listener's accept loop calls conn.Wrap for every accepted connection,
// and nothing but goroutine creation ever orders the two. Wrapping after
// dialing would therefore be a genuine data race on the shared generator --
// a pre-existing one in util/id.go + conn/conn.go, outside this workstream's
// file ownership, which this test works around rather than paper over.
func armProxyPool(t *testing.T, ctl *Control) conn.Conn {
	t.Helper()

	proxyClient, proxyServer := tcpPair(t)
	ctl.proxies <- conn.Wrap(proxyServer, "pxy")
	return conn.Wrap(proxyClient, "pxy")
}

// dispatch opens a connection to a pooled TCP listener and returns the
// StartProxy message sent to the agent that received it. It fails the test
// instead of hanging when nothing is dispatched.
func dispatch(t *testing.T, listenerOwner *Tunnel, proxyConn conn.Conn) msg.StartProxy {
	t.Helper()

	publicClient, err := net.DialTCP("tcp", nil, listenerOwner.listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatalf("failed to dial the pooled port of %s: %v", listenerOwner.url, err)
	}
	t.Cleanup(func() { publicClient.Close() })

	if err := proxyConn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("failed to set a read deadline: %v", err)
	}

	var startProxy msg.StartProxy
	if err := msg.ReadMsgInto(proxyConn, &startProxy); err != nil {
		t.Fatalf("no agent received the connection dialed to %s: %v", listenerOwner.url, err)
	}
	return startProxy
}

// TestTcpPoolingSharesOneListener covers TCP pooling end to end: the first
// member binds the only listener, members join it without binding, the
// connections it accepts are handed to members round-robin, and shutdown
// takes the listener down only with its creator.
func TestTcpPoolingSharesOneListener(t *testing.T) {
	reg := setupTestRegistry(t)

	creatorCtl := testControl(t, "")
	memberCtl := testControl(t, "")

	// Arm every proxy connection up front, before registerTestTunnel below
	// creates the listener and its accept goroutine (see armProxyPool).
	creatorProxy, memberProxy := armProxyPool(t, creatorCtl), armProxyPool(t, memberCtl)
	creatorProxyAfterShutdown := armProxyPool(t, creatorCtl)

	creator := registerTestTunnel(t, creatorCtl, msg.ReqTunnel{Protocol: "tcp", Pooling: true})
	if creator.listener == nil {
		t.Fatal("the first pooling TCP tunnel must bind the listener")
	}
	port := creator.listener.Addr().(*net.TCPAddr).Port

	// The member asks to pool on the port the creator bound.
	member := registerTestTunnel(t, memberCtl, msg.ReqTunnel{Protocol: "tcp", Pooling: true, RemotePort: uint16(port)})
	if member.url != creator.url {
		t.Fatalf("the member registered %s, want %s", member.url, creator.url)
	}
	if member.listener != nil {
		t.Fatal("a pooling member must not bind a second listener")
	}
	if got := len(reg.tunnels[creator.url].tunnels); got != 2 {
		t.Fatalf("the bucket holds %d members, want 2", got)
	}

	// The two connections accepted by the single listener reach one agent
	// each, in round-robin order.
	if got := dispatch(t, creator, creatorProxy); got.Url != creator.url {
		t.Fatalf("the first connection was proxied for %s, want %s", got.Url, creator.url)
	}
	if got := dispatch(t, creator, memberProxy); got.Url != member.url {
		t.Fatalf("the second connection was proxied for %s, want %s", got.Url, member.url)
	}

	// Shutting down one member leaves the other member, the bucket and the
	// shared listener in place.
	member.Shutdown()

	if got := len(reg.tunnels[creator.url].tunnels); got != 1 {
		t.Fatalf("after the member shut down the bucket holds %d members, want 1", got)
	}
	if reg.Get(creator.url) != creator {
		t.Fatal("after the member shut down the bucket no longer serves the creator")
	}

	// Still accepting: a third connection arrives at the surviving member.
	if got := dispatch(t, creator, creatorProxyAfterShutdown); got.Url != creator.url {
		t.Fatalf("the connection after member shutdown was proxied for %s, want %s", got.Url, creator.url)
	}

	// The last member out removes the bucket entirely.
	creator.Shutdown()
	if _, ok := reg.tunnels[creator.url]; ok {
		t.Fatal("the bucket still exists after its last member shut down")
	}
}

// ---------------------------------------------------------------------------
// SPEC 3.3: forward_to

// TestForwardToChainResolvesWithinAccount walks a chain of internal endpoints
// owned by one account and checks that resolution lands on the terminal
// tunnel, that the longest allowed chain still works, and that one hop more
// is refused.
func TestForwardToChainResolvesWithinAccount(t *testing.T) {
	reg := NewTunnelRegistry(1024, "")
	const owner = "acct-1"

	// The longest chain we follow: the public entry point forwards to eight
	// internal endpoints, i.e. eight forward edges, the last of which is
	// terminal.
	chain := internalChain(t, reg, "ok", owner, maxForwardDepth)
	pub := publicTunnel(t, reg, "http://pub.ngrok.test", owner, "https://ok0.internal")

	target, err := reg.ResolveForward(pub)
	if err != nil {
		t.Fatalf("a chain of %d hops failed to resolve: %v", maxForwardDepth, err)
	}
	if target != chain[len(chain)-1] {
		t.Fatalf("the chain resolved to %s, want %s", target.url, chain[len(chain)-1].url)
	}

	// One hop past the limit is refused.
	deep := internalChain(t, reg, "deep", owner, maxForwardDepth+1)
	deepPub := publicTunnel(t, reg, "http://deep.ngrok.test", owner, "https://deep0.internal")

	if target, err := reg.ResolveForward(deepPub); !errors.Is(err, errForwardDepth) {
		t.Fatalf("a chain of %d hops resolved to %v (err %v), want %v", len(deep), target, err, errForwardDepth)
	}

	// An endpoint that does not forward resolves to itself, and the last hop
	// of a chain resolves to the terminal endpoint.
	if got, err := reg.ResolveForward(chain[len(chain)-1]); got != chain[len(chain)-1] || err != nil {
		t.Fatalf("a non-forwarding endpoint resolved to %v with err %v", got, err)
	}
	if got, err := reg.ResolveForward(chain[len(chain)-2]); got != chain[len(chain)-1] || err != nil {
		t.Fatalf("the second to last hop resolved to %v with err %v, want %s", got, err, chain[len(chain)-1].url)
	}
}

// TestForwardToRejections covers every way a chain is refused and checks that
// the failure is classified the way the public edge needs it to be.
func TestForwardToRejections(t *testing.T) {
	cases := []struct {
		name    string
		build   func(t *testing.T, reg *TunnelRegistry) *Tunnel
		wantErr error
	}{
		{
			name: "a target that is not registered",
			build: func(t *testing.T, reg *TunnelRegistry) *Tunnel {
				return publicTunnel(t, reg, "http://pub.ngrok.test", "acct-1", "https://offline.internal")
			},
			wantErr: errForwardTargetMissing,
		},
		{
			name: "a target owned by another account is indistinguishable from a missing one",
			build: func(t *testing.T, reg *TunnelRegistry) *Tunnel {
				internalTunnel(t, reg, "https://svc.internal", "acct-2", "")
				return publicTunnel(t, reg, "http://pub.ngrok.test", "acct-1", "https://svc.internal")
			},
			wantErr: errForwardTargetMissing,
		},
		{
			name: "a loop between two endpoints",
			build: func(t *testing.T, reg *TunnelRegistry) *Tunnel {
				internalTunnel(t, reg, "https://a.internal", "acct-1", "https://b.internal")
				internalTunnel(t, reg, "https://b.internal", "acct-1", "https://a.internal")
				return publicTunnel(t, reg, "http://pub.ngrok.test", "acct-1", "https://a.internal")
			},
			wantErr: errForwardCycle,
		},
		{
			name: "an endpoint forwarding to itself, spelled differently",
			build: func(t *testing.T, reg *TunnelRegistry) *Tunnel {
				internalTunnel(t, reg, "https://self.internal", "acct-1", "HTTPS://SELF.INTERNAL/")
				return publicTunnel(t, reg, "http://pub.ngrok.test", "acct-1", "https://self.internal")
			},
			wantErr: errForwardCycle,
		},
		{
			name: "a chain one hop past the depth limit",
			build: func(t *testing.T, reg *TunnelRegistry) *Tunnel {
				internalChain(t, reg, "deep", "acct-1", maxForwardDepth+1)
				return publicTunnel(t, reg, "http://pub.ngrok.test", "acct-1", "https://deep0.internal")
			},
			wantErr: errForwardDepth,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reg := NewTunnelRegistry(1024, "")
			entry := tc.build(t, reg)

			target, err := reg.ResolveForward(entry)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("ResolveForward returned %v (err %v), want %v", target, err, tc.wantErr)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// SPEC 3.1/3.3: owner derivation

// TestOwnerFallbackWithoutAuthTokens covers the namespacing rule: the auth
// token is the account identity only when tokens are configured, otherwise
// every client shares the "default" namespace.
func TestOwnerFallbackWithoutAuthTokens(t *testing.T) {
	setupTestRegistry(t)
	ctl := testControl(t, "token-1")

	opts.authTokens = nil
	if got := ownerOf(ctl); got != defaultOwner {
		t.Fatalf("ownerOf = %q without auth tokens, want %q", got, defaultOwner)
	}
	if got := ownerOf(nil); got != defaultOwner {
		t.Fatalf("ownerOf(nil) = %q, want %q", got, defaultOwner)
	}

	opts.authTokens = []string{"token-1"}
	if got := ownerOf(ctl); got != "token-1" {
		t.Fatalf("ownerOf = %q with auth tokens, want %q", got, "token-1")
	}

	// The owner is what namespaces internal endpoints: the account that
	// registered one can reach it, a different account cannot.
	tun := registerTestTunnel(t, ctl, msg.ReqTunnel{Protocol: "http", Binding: msg.BindingInternal, Hostname: "shared.internal"})
	if tun.owner != "token-1" {
		t.Fatalf("the tunnel owner is %q, want token-1", tun.owner)
	}
	if tunnelRegistry.GetInternal(tun.url, "token-1") != tun {
		t.Fatal("the owning account cannot reach its own internal endpoint")
	}
	if tunnelRegistry.GetInternal(tun.url, "token-2") != nil {
		t.Fatal("another account can reach an internal endpoint it does not own")
	}
}

// ---------------------------------------------------------------------------
// the public HTTP path

// publicRequest drives one request through the real public HTTP path (the
// vhost lookup and routing in http.go) and returns the status and body of the
// response. It fails the test instead of hanging when the path never answers.
func publicRequest(t *testing.T, host string) (int, string) {
	t.Helper()

	client, server := tcpPair(t)

	go httpHandler(conn.Wrap(server, "pub"), "http")

	if _, err := client.Write([]byte("GET / HTTP/1.1\r\nHost: " + host + "\r\n\r\n")); err != nil {
		t.Fatalf("failed to write the request: %v", err)
	}
	if err := client.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("failed to set a read deadline: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("no HTTP response for host %s: %v", host, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read the response body: %v", err)
	}
	return resp.StatusCode, string(body)
}

// TestPublicHttpPath covers http.go's routing of public requests: internal
// endpoints answer 404, an unresolvable forward_to chain answers an explicit
// 502, and a resolvable one is served by the target's agent, whose upstream
// response the public client sees verbatim.
func TestPublicHttpPath(t *testing.T) {
	const host = "pub.ngrok.test"

	t.Run("internal endpoints are not routable", func(t *testing.T) {
		setupTestRegistry(t)
		ctl := testControl(t, "")
		registerTestTunnel(t, ctl, msg.ReqTunnel{Protocol: "http", Binding: msg.BindingInternal, Hostname: "svc.internal"})

		status, body := publicRequest(t, "svc.internal")
		if status != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", status)
		}
		if !strings.Contains(body, "Tunnel svc.internal not found") {
			t.Fatalf("unexpected 404 body %q", body)
		}
	})

	t.Run("an unresolvable chain answers 502", func(t *testing.T) {
		cases := []struct {
			name    string
			entry   string
			chain   func(t *testing.T, reg *TunnelRegistry)
			wantMsg string
		}{
			{
				name:    "missing target",
				entry:   "https://offline.internal",
				wantMsg: "forward target offline",
			},
			{
				name:  "loop",
				entry: "https://a.internal",
				chain: func(t *testing.T, reg *TunnelRegistry) {
					internalTunnel(t, reg, "https://a.internal", defaultOwner, "https://b.internal")
					internalTunnel(t, reg, "https://b.internal", defaultOwner, "https://a.internal")
				},
				wantMsg: "forward loop detected",
			},
			{
				name:  "past the depth limit",
				entry: "https://deep0.internal",
				chain: func(t *testing.T, reg *TunnelRegistry) {
					internalChain(t, reg, "deep", defaultOwner, maxForwardDepth+1)
				},
				wantMsg: "forward chain too deep",
			},
		}

		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				reg := setupTestRegistry(t)
				if tc.chain != nil {
					tc.chain(t, reg)
				}
				publicTunnel(t, reg, "http://"+host, defaultOwner, tc.entry)

				status, body := publicRequest(t, host)
				if status != http.StatusBadGateway {
					t.Fatalf("status = %d, want 502", status)
				}
				if !strings.Contains(body, tc.wantMsg) {
					t.Fatalf("the 502 body %q does not mention %q", body, tc.wantMsg)
				}
			})
		}
	})

	t.Run("a resolvable chain is served by the target's agent", func(t *testing.T) {
		setupTestRegistry(t)
		ctl := testControl(t, "")

		internal := registerTestTunnel(t, ctl, msg.ReqTunnel{Protocol: "http", Binding: msg.BindingInternal, Hostname: "svc.internal"})
		registerTestTunnel(t, ctl, msg.ReqTunnel{Protocol: "http", Hostname: host, ForwardTo: internal.url})

		// the proxy connection the internal endpoint's agent opened
		proxyClient, proxyServer := tcpPair(t)
		internal.ctl.proxies <- conn.Wrap(proxyServer, "pxy")
		proxyConn := conn.Wrap(proxyClient, "pxy")

		publicClient, publicServer := tcpPair(t)
		handled := make(chan struct{})
		go func() {
			defer close(handled)
			httpHandler(conn.Wrap(publicServer, "pub"), "http")
		}()

		if _, err := publicClient.Write([]byte("GET /hello HTTP/1.1\r\nHost: " + host + "\r\n\r\n")); err != nil {
			t.Fatalf("failed to write the request: %v", err)
		}

		// The forwarding endpoint's agent never sees this connection: the
		// internal endpoint's agent gets it, and StartProxy tells it the real
		// public client's address (SPEC 3.3).
		if err := proxyConn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatalf("failed to set a read deadline: %v", err)
		}
		var startProxy msg.StartProxy
		if err := msg.ReadMsgInto(proxyConn, &startProxy); err != nil {
			t.Fatalf("the internal endpoint's agent never received the connection: %v", err)
		}
		if startProxy.Url != internal.url {
			t.Fatalf("StartProxy Url = %q, want %q", startProxy.Url, internal.url)
		}
		if want := publicClient.LocalAddr().String(); startProxy.ClientAddr != want {
			t.Fatalf("StartProxy ClientAddr = %q, want the public client's address %q", startProxy.ClientAddr, want)
		}

		// The public client sees the upstream response verbatim.
		upstream := "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
		if _, err := proxyConn.Write([]byte(upstream)); err != nil {
			t.Fatalf("failed to write the upstream response: %v", err)
		}

		got := make([]byte, len(upstream))
		if err := publicClient.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatalf("failed to set a read deadline: %v", err)
		}
		if _, err := io.ReadFull(publicClient, got); err != nil {
			t.Fatalf("failed to read the upstream response: %v", err)
		}
		if string(got) != upstream {
			t.Fatalf("the public client read %q, want %q", got, upstream)
		}

		// Tearing the connection down lets the handler finish.
		publicClient.Close()
		proxyClient.Close()
		select {
		case <-handled:
		case <-time.After(5 * time.Second):
			t.Fatal("the public connection was not torn down")
		}
	})
}
