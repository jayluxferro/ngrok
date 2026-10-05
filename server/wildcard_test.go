package server

// Tests for wildcard hostnames (SPEC 11): the registry's one public matcher
// (Match: exact first, then a one-label wildcard index), the registration
// grammar in validateRequest, and the interplay of both with the two public
// routing sites (SNI and Host) and with the 404/421 paths.
//
// Two levels are tested separately, for the reason registry_v2_test.go
// documents: the registry level exercises Match and the index directly
// (registering shapes the grammar refuses, like nested wildcards, which are
// reachable only through future ownership models), and the NewTunnel level
// exercises the grammar and the teardown path the way a real registration
// arrives. The wire-level tests run the real handlers over loopback pairs,
// reusing the fixtures from registry_v2_test.go / policy_test.go / sni_test.go.

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"ngrok/msg"
)

// registerWildcard is the registry-level wildcard fixture: it registers a
// pooling tunnel under the literal "*.base" key, the way NewTunnel's hostname
// branch would have (the key is what builds the index entry, so the fixture
// works for shapes the grammar currently refuses, which the Match tests need).
func registerWildcard(t *testing.T, reg *TunnelRegistry, url, owner string) *Tunnel {
	t.Helper()

	protocol, hostname, _ := strings.Cut(url, "://")
	tun := &Tunnel{
		url:   url,
		owner: owner,
		req:   &msg.ReqTunnel{Protocol: protocol, Hostname: hostname, Pooling: true},
	}
	if err := reg.Register(url, tun); err != nil {
		t.Fatalf("registering wildcard %s failed: %v", url, err)
	}
	return tun
}

// ---------------------------------------------------------------------------
// the matcher

func TestWildcardMatchesExactlyOneLabelUnderBase(t *testing.T) {
	reg := NewTunnelRegistry(1024, "")
	tun := registerWildcard(t, reg, "https://*.ngrok.test", "acct-1")

	// every one-label name under the base routes to the bucket
	if got := reg.Match("https", "foo.ngrok.test"); got != tun {
		t.Fatalf("Match(foo.ngrok.test) = %v, want the wildcard tunnel", got)
	}
	if got := reg.Match("https", "bar.ngrok.test"); got != tun {
		t.Fatalf("Match(bar.ngrok.test) = %v, want the wildcard tunnel", got)
	}

	// one label deep ONLY: the base itself, two labels under it, other
	// domains, and a name that merely carries the base as a substring all
	// miss -- the last one is the trap a HasSuffix implementation would walk
	// into (foongrok.test ends with ngrok.test but is not under it).
	for _, host := range []string{
		"ngrok.test",      // the base itself is not under the wildcard
		"a.b.ngrok.test",  // two labels deep
		"other.test",      // another domain
		"ungrok.test",     // different first label, same suffix shape
		"foongrok.test",   // the suffix trap: base appears, but not at a label boundary
		"x.foongrok.test", // the trap one label down
	} {
		if got := reg.Match("https", host); got != nil {
			t.Fatalf("Match(%s) = %v, want a miss (the wildcard is one label deep)", host, got)
		}
	}

	// and the wildcard never leaks across protocols: only https was
	// registered, so an http lookup of a covered name still misses
	if got := reg.Match("http", "foo.ngrok.test"); got != nil {
		t.Fatalf("Match(http, foo.ngrok.test) = %v, want a miss in the http namespace", got)
	}
}

func TestWildcardExactHitWinsAndNeverScans(t *testing.T) {
	reg := NewTunnelRegistry(1024, "")
	wild := registerWildcard(t, reg, "https://*.ngrok.test", "acct-1")
	exact := publicTunnel(t, reg, "https://api.ngrok.test", "acct-1", "")

	if got := reg.Match("https", "api.ngrok.test"); got != exact {
		t.Fatalf("Match(api.ngrok.test) = %v, want the exact tunnel (exact-first is the contract)", got)
	}
	// the wildcard keeps serving the names the exact registration leaves free
	if got := reg.Match("https", "other.ngrok.test"); got != wild {
		t.Fatalf("Match(other.ngrok.test) = %v, want the wildcard tunnel", got)
	}
	// Gate 2's "by construction" half: the exact branch above returned before
	// the index is consulted, so this hit cannot have been wildcard-priced --
	// Match's shape (map hit, return; only on miss compute the candidate
	// base) is what pins it, and this test pins the observable consequence:
	// an exact registration and a wildcard coexist with the exact one winning.
}

func TestWildcardLongestBaseWinsAmongNestedWildcards(t *testing.T) {
	reg := NewTunnelRegistry(1024, "")

	// The nested shape the grammar does not hand out today -- *.a.ngrok.test
	// under *.ngrok.test -- registered directly, same owner, pooling-joined:
	// this is the one way the spec says two covering wildcards can coexist,
	// and the case "longest base wins" exists for.
	deep1 := registerWildcard(t, reg, "https://*.a.ngrok.test", "acct-1")
	deep2 := registerWildcard(t, reg, "https://*.a.ngrok.test", "acct-1")
	shallow := registerWildcard(t, reg, "https://*.ngrok.test", "acct-1")

	if deep1 == deep2 {
		t.Fatal("the two deep members must be distinct tunnels")
	}

	// A one-label name under a.ngrok.test is covered by BOTH wildcards' shapes
	// only at the deep base: one-label-deep gives x.a.ngrok.test exactly one
	// candidate (base a.ngrok.test), so it serves the deep bucket -- and, in
	// round-robin over its two pooling members, never the shallow one.
	if got := reg.Match("https", "x.a.ngrok.test"); got != deep1 {
		t.Fatalf("first draw on x.a.ngrok.test = %v, want the deep bucket's first member", got)
	}
	if got := reg.Match("https", "x.a.ngrok.test"); got != deep2 {
		t.Fatalf("second draw on x.a.ngrok.test = %v, want the deep bucket's second member (round-robin, pooling-joined)", got)
	}

	// A name directly under ngrok.test has a.ngrok.test nowhere in its
	// reduction and serves the shallow bucket.
	if got := reg.Match("https", "y.ngrok.test"); got != shallow {
		t.Fatalf("Match(y.ngrok.test) = %v, want the shallow bucket's member", got)
	}

	// And a name two labels under ngrok.test is under neither wildcard: the
	// deeper base does not catch it, and -- the half a suffix walk would get
	// wrong -- neither does the shallower one.
	if got := reg.Match("https", "z.x.a.ngrok.test"); got != nil {
		t.Fatalf("Match(z.x.a.ngrok.test) = %v, want a miss under both wildcards", got)
	}
}

func TestWildcardHostPortStrippedOnlyForDefaultPort(t *testing.T) {
	reg := NewTunnelRegistry(1024, "")
	exact := publicTunnel(t, reg, "http://port.ngrok.test", "acct-1", "")
	wild := registerWildcard(t, reg, "http://*.ngrok.test", "acct-1")

	// the default port is the one the vhost derivation canonicalizes away at
	// registration, so a Host carrying it routes to the portless key
	if got := reg.Match("http", "port.ngrok.test:80"); got != exact {
		t.Fatalf("Match(port.ngrok.test:80) = %v, want the exact tunnel", got)
	}
	if got := reg.Match("http", "any.ngrok.test:80"); got != wild {
		t.Fatalf("Match(any.ngrok.test:80) = %v, want the wildcard tunnel", got)
	}

	// any other port is part of the name, exactly as it has always been:
	// no exact key, no wildcard base, one miss
	if got := reg.Match("http", "any.ngrok.test:8080"); got != nil {
		t.Fatalf("Match(any.ngrok.test:8080) = %v, want a miss (a non-default port is part of the name)", got)
	}

	// same rule in the https port space, independently
	registerWildcard(t, reg, "https://*.ngrok.test", "acct-1")
	if got := reg.Match("https", "any.ngrok.test:443"); got == nil {
		t.Fatal("Match(any.ngrok.test:443) missed; the https default port must strip")
	}
	if got := reg.Match("https", "any.ngrok.test:8443"); got != nil {
		t.Fatalf("Match(any.ngrok.test:8443) = %v, want a miss in the https space too", got)
	}
}

func TestWildcardNeverMatchesInternalNamespace(t *testing.T) {
	reg := NewTunnelRegistry(1024, "")
	registerWildcard(t, reg, "https://*.ngrok.test", "acct-1")
	internalTunnel(t, reg, "https://svc.internal", "acct-1", "")

	// gate 4: a host under .internal NEVER resolves through a wildcard,
	// whatever else is live
	for _, host := range []string{"svc.internal", "deep.svc.internal", "other.internal"} {
		if got := reg.Match("https", host); got != nil {
			t.Fatalf("Match(%s) = %v, want a miss (the internal namespace is exact-only)", host, got)
		}
	}

	// The index-side defense in depth: a wildcard over an internal base cannot
	// even be registered into the index (wildcardIndexKey refuses it), so a
	// direct registration behind validateRequest's back stays unreachable.
	registerWildcard(t, reg, "https://*.svc.internal", "acct-1")
	if _, ok := reg.wildcards["https://svc.internal"]; ok {
		t.Fatal("a wildcard over an internal base joined the index; internal bases must stay exact")
	}
	if got := reg.Match("https", "x.svc.internal"); got != nil {
		t.Fatalf("Match(x.svc.internal) = %v, want a miss for an internal-based wildcard", got)
	}

	// And through the wire: with a wildcard live and an internal endpoint
	// registered, the public listener answers a .internal Host with the same
	// 404 it always has -- routing it would be worse than not routing it.
	setup := setupTestRegistry(t)
	registerWildcard(t, setup, "http://*.ngrok.test", defaultOwner)
	ctl := testControl(t, "")
	registerTestTunnel(t, ctl, msg.ReqTunnel{Protocol: "http", Binding: msg.BindingInternal, Hostname: "svc.internal"})

	status, body := publicRequest(t, "svc.internal")
	if status != http.StatusNotFound {
		t.Fatalf("status = %d for svc.internal with a wildcard live, want 404", status)
	}
	if !strings.Contains(body, "Tunnel svc.internal not found") {
		t.Fatalf("unexpected 404 body %q", body)
	}
}

func TestWildcardCrossOwnerRefusedWithPoolingWording(t *testing.T) {
	reg := NewTunnelRegistry(1024, "")
	const url = "https://*.ngrok.test"

	registerWildcard(t, reg, url, "acct-1")

	// the owner joins its own wildcard bucket, pooling-joined
	if err := reg.Register(url, &Tunnel{url: url, owner: "acct-1", req: &msg.ReqTunnel{Pooling: true}}); err != nil {
		t.Fatalf("the owner failed to join its own wildcard bucket: %v", err)
	}
	if got := len(reg.tunnels[url].tunnels); got != 2 {
		t.Fatalf("the wildcard bucket holds %d members, want 2", got)
	}

	// another account's wildcard over the same base is refused with the
	// pooling refusal's wording -- a wildcard bucket serves other names' worth
	// of traffic exactly the way a pooled url does, so it is guarded exactly
	// the way one is
	err := reg.Register(url, &Tunnel{url: url, owner: "acct-2", req: &msg.ReqTunnel{Pooling: true}})
	if err == nil {
		t.Fatal("a second wildcard over the same base from another account was accepted")
	}
	if !strings.Contains(err.Error(), "already registered by a different account") {
		t.Fatalf("the refusal %q does not carry the pooling refusal's wording", err)
	}

	// and a non-pooling newcomer from anywhere but the bucket's owner is
	// refused too, as any pooled bucket refuses
	if err := reg.Register(url, &Tunnel{url: url, owner: "acct-2"}); err == nil {
		t.Fatal("a non-pooling tunnel joined a live wildcard bucket")
	}
}

func TestWildcardTeardownCleansTheIndex(t *testing.T) {
	setupTestRegistry(t)
	ctl := testControl(t, "")

	// through the real registration path: the hostname branch registers the
	// literal key, Register joins the index, Shutdown removes only itself --
	// and the bucket's last removal drops the index entry with it
	tun := registerTestTunnel(t, ctl, msg.ReqTunnel{Protocol: "http", Hostname: "*.ngrok.test"})
	if got := tunnelRegistry.Match("http", "covered.ngrok.test"); got != tun {
		t.Fatalf("Match(covered.ngrok.test) = %v, want the wildcard tunnel", got)
	}

	tun.Shutdown()
	if got := tunnelRegistry.Match("http", "covered.ngrok.test"); got != nil {
		t.Fatalf("Match after Shutdown = %v, want a miss: teardown must clean the index", got)
	}
	if len(tunnelRegistry.wildcards) != 0 {
		t.Fatalf("the wildcard index holds %d entries after teardown, want 0", len(tunnelRegistry.wildcards))
	}

	// re-registering the same wildcard after the close works, and routes again.
	// It registers pooling this time, because the member added below joins it.
	second := registerTestTunnel(t, ctl, msg.ReqTunnel{Protocol: "http", Hostname: "*.ngrok.test", Pooling: true})
	if got := tunnelRegistry.Match("http", "covered.ngrok.test"); got != second {
		t.Fatalf("Match after re-register = %v, want the new tunnel", got)
	}

	// a pooling join keeps the bucket alive through one member's shutdown
	other := testControl(t, "")
	member := registerTestTunnel(t, other, msg.ReqTunnel{Protocol: "http", Hostname: "*.ngrok.test", Pooling: true})
	if got := len(tunnelRegistry.tunnels[second.url].tunnels); got != 2 {
		t.Fatalf("the wildcard bucket holds %d members, want 2", got)
	}

	second.Shutdown()
	if got := tunnelRegistry.Match("http", "covered.ngrok.test"); got != member {
		t.Fatalf("Match after the first member shut down = %v, want the surviving member", got)
	}
	member.Shutdown()
	if got := tunnelRegistry.Match("http", "covered.ngrok.test"); got != nil {
		t.Fatalf("Match after the last member shut down = %v, want a miss", got)
	}
	if len(tunnelRegistry.wildcards) != 0 {
		t.Fatalf("the wildcard index holds %d entries after the last member left, want 0", len(tunnelRegistry.wildcards))
	}
}

// ---------------------------------------------------------------------------
// the registration grammar (validateRequest)

func TestWildcardRegistrationGrammar(t *testing.T) {
	cases := []struct {
		name    string
		req     msg.ReqTunnel
		wantErr string
	}{
		{
			name:    "a wildcard over another domain names the server's domain and the shape",
			req:     msg.ReqTunnel{Protocol: "http", Hostname: "*.other.test"},
			wantErr: "wildcard hostnames must be *.ngrok.test",
		},
		{
			name:    "a wildcard over a subdomain of the server domain is not the server domain",
			req:     msg.ReqTunnel{Protocol: "http", Hostname: "*.sub.ngrok.test"},
			wantErr: "wildcard hostnames must be *.ngrok.test",
		},
		{
			name:    "a mid-name star is refused by the grammar",
			req:     msg.ReqTunnel{Protocol: "http", Hostname: "api.*.ngrok.test"},
			wantErr: `is malformed`,
		},
		{
			name:    "the bare star is refused by the grammar",
			req:     msg.ReqTunnel{Protocol: "http", Hostname: "*"},
			wantErr: `is malformed`,
		},
		{
			name:    "a trailing star is refused by the grammar",
			req:     msg.ReqTunnel{Protocol: "http", Hostname: "ngrok.test.*"},
			wantErr: `is malformed`,
		},
		{
			name:    "a wildcard cannot bind internal",
			req:     msg.ReqTunnel{Protocol: "http", Binding: msg.BindingInternal, Hostname: "*.ngrok.test"},
			wantErr: "wildcard hostnames cannot bind internal",
		},
		{
			name:    "a wildcard on tcp names the http-only rule",
			req:     msg.ReqTunnel{Protocol: "tcp", Hostname: "*.ngrok.test"},
			wantErr: "only supported for http and https",
		},
		{
			// udp refuses any hostname before the grammar is consulted, with
			// the port-routed refusal this cluster gave it
			name:    "a wildcard on udp keeps udp's name refusal",
			req:     msg.ReqTunnel{Protocol: "udp", Hostname: "*.ngrok.test"},
			wantErr: "port-routed",
		},
		{
			name:    "a wildcard in the subdomain field is redirected to the hostname field",
			req:     msg.ReqTunnel{Protocol: "http", Subdomain: "*"},
			wantErr: "write the wildcard in the hostname field",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setupTestRegistry(t)
			t.Setenv("VHOST", "") // pin the derived domain to opts.domain
			ctl := testControl(t, "")

			tun, err := NewTunnel(&tc.req, ctl)
			if err == nil {
				tun.Shutdown()
				t.Fatalf("NewTunnel(%+v) succeeded, want a refusal", tc.req)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not mention %q", err, tc.wantErr)
			}
		})
	}

	t.Run("the accepted shape registers and routes", func(t *testing.T) {
		setupTestRegistry(t)
		t.Setenv("VHOST", "")
		ctl := testControl(t, "")

		tun := registerTestTunnel(t, ctl, msg.ReqTunnel{Protocol: "http", Hostname: "*.ngrok.test"})
		if tun.url != "http://*.ngrok.test" {
			t.Fatalf("url = %q, want the literal wildcard key", tun.url)
		}
		if got := tunnelRegistry.Match("http", "covered.ngrok.test"); got != tun {
			t.Fatalf("Match(covered.ngrok.test) = %v, want the wildcard tunnel just registered", got)
		}
	})
}

func TestWildcardBaseFollowsTheVHOSTDerivation(t *testing.T) {
	setupTestRegistry(t)
	ctl := testControl(t, "")

	// The base a wildcard must carry is the vhost the registration derives --
	// the -domain when VHOST is unset, the VHOST value when it is set -- so a
	// VHOST override moves the accepted wildcard with it. The derivation
	// strips only the protocol's OWN default port (443 for https), so the
	// override here carries :443 to be stripped; :80 would stay part of the
	// base, which the port case below pins.
	t.Setenv("VHOST", "Example.com:443")

	tun := registerTestTunnel(t, ctl, msg.ReqTunnel{Protocol: "https", Hostname: "*.example.com"})
	if tun.url != "https://*.example.com" {
		t.Fatalf("url = %q, want the VHOST-derived wildcard key", tun.url)
	}
	if got := tunnelRegistry.Match("https", "covered.example.com"); got != tun {
		t.Fatalf("Match(covered.example.com) = %v, want the VHOST wildcard", got)
	}

	// the server's own -domain is no longer the served base: refused, naming
	// the domain that IS served
	if _, err := NewTunnel(&msg.ReqTunnel{Protocol: "https", Hostname: "*.ngrok.test"}, ctl); err == nil {
		t.Fatal("a wildcard over -domain was accepted under a VHOST override")
	} else if !strings.Contains(err.Error(), "*.example.com") {
		t.Fatalf("the refusal %q does not name the served domain", err)
	}

	// a non-default port in the override is part of the base, and the
	// wildcard must carry it verbatim
	t.Setenv("VHOST", "example.com:8443")
	port := registerTestTunnel(t, ctl, msg.ReqTunnel{Protocol: "https", Hostname: "*.example.com:8443"})
	if port.url != "https://*.example.com:8443" {
		t.Fatalf("url = %q, want the port-carrying wildcard key", port.url)
	}
	if got := tunnelRegistry.Match("https", "covered.example.com:8443"); got != port {
		t.Fatalf("Match(covered.example.com:8443) = %v, want the port-carrying wildcard", got)
	}
	// the portless name stays under the portless wildcard from above -- it
	// must not resolve to the port-carrying base, whose one-label names all
	// carry :8443
	if got := tunnelRegistry.Match("https", "covered.example.com"); got != tun {
		t.Fatalf("Match(covered.example.com) = %v, want the portless wildcard (a port-carrying base does not catch portless names)", got)
	}
}

// ---------------------------------------------------------------------------
// the two public routing sites, on the wire

func TestWildcardSNIPassthroughAndEdgeVariants(t *testing.T) {
	t.Run("SNI under a wildcard passes through to an agent-terminated endpoint", func(t *testing.T) {
		setupTestRegistry(t)
		ctl := testControl(t, "")
		tun := registerTestTunnel(t, ctl, msg.ReqTunnel{
			Protocol:       msg.ProtoHTTPS,
			Hostname:       "*.ngrok.test",
			TLSTermination: msg.TLSTerminationAgent,
		})
		agentConn := armHTTPAgent(t, ctl)

		// a real visitor hello naming a name only the wildcard covers
		hello := captureClientHello(t, tlsClientConfig("covered.ngrok.test"))

		publicClient := startHTTPSHandler(t, testTLSConfig(t))
		if _, err := publicClient.Write(hello); err != nil {
			t.Fatalf("failed to write the ClientHello: %v", err)
		}

		startProxy := readStartProxy(t, agentConn, "the wildcard agent tunnel")
		if startProxy.Url != tun.url {
			t.Fatalf("StartProxy names %q, want the wildcard endpoint %q", startProxy.Url, tun.url)
		}

		// the zero-knowledge contract holds across the wildcard route: the
		// hello reaches the agent byte for byte
		if err := agentConn.SetReadDeadline(time.Now().Add(publicTimeout)); err != nil {
			t.Fatalf("failed to set a read deadline: %v", err)
		}
		got := make([]byte, len(hello))
		if _, err := io.ReadFull(agentConn, got); err != nil {
			t.Fatalf("the ClientHello never reached the agent: %v", err)
		}
		if !bytes.Equal(got, hello) {
			t.Fatal("the bytes reaching the agent differ from the visitor's ClientHello")
		}
	})

	t.Run("SNI under a wildcard edge endpoint terminates and routes by Host", func(t *testing.T) {
		setupTestRegistry(t)
		ctl := testControl(t, "")
		tun := registerTestTunnel(t, ctl, msg.ReqTunnel{Protocol: msg.ProtoHTTPS, Hostname: "*.ngrok.test"})
		agentConn := armHTTPAgent(t, ctl)

		publicClient := startHTTPSHandler(t, testTLSConfig(t))

		client := tls.Client(publicClient, tlsClientConfig("covered.ngrok.test"))
		if err := client.SetDeadline(time.Now().Add(publicTimeout)); err != nil {
			t.Fatalf("failed to set a deadline: %v", err)
		}
		head := "GET / HTTP/1.1\r\nHost: covered.ngrok.test\r\n\r\n"
		if _, err := client.Write([]byte(head)); err != nil {
			t.Fatalf("failed to write the request: %v", err)
		}

		startProxy := readStartProxy(t, agentConn, "the wildcard edge tunnel")
		if startProxy.Url != tun.url {
			t.Fatalf("StartProxy names %q, want the wildcard endpoint %q", startProxy.Url, tun.url)
		}
		if got := readHead(t, agentConn, "wildcard edge agent"); got != head {
			t.Fatalf("the agent received %q, want the request head verbatim", got)
		}
	})

	t.Run("a Host under an agent-terminated wildcard gets 421 on a terminated conn", func(t *testing.T) {
		// gate 3's teeth: the SAME name routes to the SAME endpoint whichever
		// site resolves it -- SNI passes the connection through (above), while
		// a Host arriving on a server-terminated connection is refused with
		// the 421 that has always answered this shape.
		//
		// An agent-terminated endpoint is an https endpoint, so the Host that
		// reaches it arrives the way
		// TestSNIHostReachingAgentTunnelOnTerminatedConnGets421 delivers its
		// Host: TLS terminated by this server (no SNI, so the peek names
		// nothing), then routed by Host. The plain listener looks up an http
		// url and never resolves an https endpoint at all.
		setupTestRegistry(t)
		ctl := testControl(t, "")
		registerTestTunnel(t, ctl, msg.ReqTunnel{
			Protocol:       msg.ProtoHTTPS,
			Hostname:       "*.ngrok.test",
			TLSTermination: msg.TLSTerminationAgent,
		})

		publicClient := startHTTPSHandler(t, testTLSConfig(t))

		client := tls.Client(publicClient, &tls.Config{InsecureSkipVerify: true, MaxVersion: tls.VersionTLS12})
		if err := client.SetDeadline(time.Now().Add(publicTimeout)); err != nil {
			t.Fatalf("failed to set a deadline: %v", err)
		}
		if _, err := client.Write([]byte("GET / HTTP/1.1\r\nHost: covered.ngrok.test\r\n\r\n")); err != nil {
			t.Fatalf("failed to write the request: %v", err)
		}

		resp, err := http.ReadResponse(bufio.NewReader(client), nil)
		if err != nil {
			t.Fatalf("no response for the agent-terminated wildcard reached by Host: %v", err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("the 421 body did not read to its Content-Length: %v", err)
		}
		if resp.StatusCode != http.StatusMisdirectedRequest {
			t.Fatalf("status = %d, want 421 for an agent-terminated wildcard reached by Host (body %q)", resp.StatusCode, body)
		}
		if !strings.Contains(string(body), "covered.ngrok.test") {
			t.Fatalf("the 421 body must name the host, got %q", body)
		}
	})

	t.Run("a name two labels under the wildcard misses all the way to 404", func(t *testing.T) {
		// the negative-routing contract through the SNI path: the SNI miss
		// terminates with the server certificate, the Host miss 404s, and
		// neither step invents a route for a name the wildcard does not cover
		setupTestRegistry(t)
		ctl := testControl(t, "")
		registerTestTunnel(t, ctl, msg.ReqTunnel{Protocol: msg.ProtoHTTPS, Hostname: "*.ngrok.test"})

		publicClient := startHTTPSHandler(t, testTLSConfig(t))

		client := tls.Client(publicClient, tlsClientConfig("a.b.ngrok.test"))
		if err := client.SetDeadline(time.Now().Add(publicTimeout)); err != nil {
			t.Fatalf("failed to set a deadline: %v", err)
		}
		if _, err := client.Write([]byte("GET / HTTP/1.1\r\nHost: a.b.ngrok.test\r\n\r\n")); err != nil {
			t.Fatalf("failed to write the request: %v", err)
		}

		resp, err := http.ReadResponse(bufio.NewReader(client), nil)
		if err != nil {
			t.Fatalf("no response for the uncovered name: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("status = %d, want 404 for a name two labels under the wildcard (body %q)", resp.StatusCode, body)
		}
		if !strings.Contains(string(body), "a.b.ngrok.test") {
			t.Fatalf("the 404 body must name the uncovered host, got %q", body)
		}
	})
}

func TestWildcardNegativeRoutingStill404s(t *testing.T) {
	setupTestRegistry(t)
	ctl := testControl(t, "")
	tun := registerTestTunnel(t, ctl, msg.ReqTunnel{Protocol: "http", Hostname: "*.ngrok.test"})
	agentConn := armHTTPAgent(t, ctl)

	// the positive half first, so the negatives below are proven against a
	// wildcard that demonstrably routes: one label under the base is served,
	// with the StartProxy naming the literal wildcard url
	res := startPublicRequest(t, "covered.ngrok.test", "/")
	if got := readStartProxy(t, agentConn, "the wildcard agent"); got.Url != tun.url {
		t.Fatalf("StartProxy names %q, want the wildcard endpoint %q", got.Url, tun.url)
	}
	if _, err := agentConn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")); err != nil {
		t.Fatalf("failed to write the upstream response: %v", err)
	}
	if resp, body := waitPublic(t, res); resp.StatusCode != http.StatusOK || body != "ok" {
		t.Fatalf("the covered name got %d %q, want 200 \"ok\"", resp.StatusCode, body)
	}

	// a wildcard over a base changes nothing about names it does not cover:
	// other domains, deeper names, the bare base all get the same 404 they
	// always got
	for _, host := range []string{"elsewhere.test", "ngrok.test", "deep.a.b.ngrok.test"} {
		status, body := publicRequest(t, host)
		if status != http.StatusNotFound {
			t.Fatalf("status = %d for %s, want 404", status, host)
		}
		if !strings.Contains(body, "Tunnel "+host+" not found") {
			t.Fatalf("unexpected 404 body for %s: %q", host, body)
		}
	}
}
