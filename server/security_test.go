package server

// Regression tests for the security findings fixed in server/ and msg/.
//
// The sections are named after the findings rather than the files they touch,
// because what is pinned here is a decision, not a function:
//
//	C1 / PT-M3  a pooling bucket belongs to one account
//	C2 / PT-C2  a client id is not a credential; the session secret is
//	M1          .internal is not a public namespace
//	M5          forward_to's connect phase runs the target's policy
//	PT-M7       a wrong token is answered before the version is disclosed
//	PT-M9       the 404 does not reflect the Host
//	C3          the public leg's head read is bounded
//
// The fixtures (setupTestRegistry, testControl, registerTestTunnel, tcpPair,
// armHTTPAgent, policyRoundTrip, muxTestControl, ...) come from
// registry_v2_test.go, policy_test.go and mux_test.go; scriptedConn, the
// connection a test drives completely, comes from lifecycle_test.go. The
// session tests drive the real NewControl entry point over a loopback TCP pair,
// because what a client is answered with is the thing under test.

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"ngrok/conn"
	"ngrok/log"
	"ngrok/msg"
	"ngrok/policy"
	"ngrok/version"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// C1 / PT-M3: a pooling bucket belongs to one account

// TestPoolingJoinRequiresTheSameOwner covers the registry's half of the rule:
// pooling shares the url, so it may only join a bucket that belongs to the same
// account. The same-account join is asserted too -- a rule that refused every
// join would pass a refusal-only test while breaking pooling entirely.
func TestPoolingJoinRequiresTheSameOwner(t *testing.T) {
	const url = "http://pool.ngrok.test"
	reg := NewTunnelRegistry(1024, "")

	owner := &Tunnel{url: url, owner: "acct-1", req: &msg.ReqTunnel{Pooling: true}}
	if err := reg.Register(url, owner); err != nil {
		t.Fatalf("the bucket's first registration failed: %v", err)
	}

	sameOwner := &Tunnel{url: url, owner: "acct-1", req: &msg.ReqTunnel{Pooling: true}}
	if err := reg.Register(url, sameOwner); err != nil {
		t.Fatalf("a same-account pooling join was refused: %v", err)
	}

	intruder := &Tunnel{url: url, owner: "acct-2", req: &msg.ReqTunnel{Pooling: true}}
	err := reg.Register(url, intruder)
	if err == nil {
		t.Fatal("another account joined a pooling bucket: it will be handed that bucket's traffic")
	}
	if !strings.Contains(err.Error(), "different account") {
		t.Fatalf("the refusal %q does not say why the join was refused", err)
	}
	if got := len(reg.tunnels[url].tunnels); got != 2 {
		t.Fatalf("the bucket holds %d members after the refusal, want 2", got)
	}

	// The refusal is not just bookkeeping: the intruder never serves the
	// bucket, however the round-robin cursor advances.
	for i := 0; i < 6; i++ {
		if got := reg.Get(url); got == intruder {
			t.Fatalf("draw %d handed the bucket's traffic to the refused account", i)
		}
	}
}

// TestPoolingJoinRequiresTheSameOwnerOnTheHttpPath is the same rule through the
// real registration entry point, where the owner comes from the control's auth
// token rather than from a literal. It also covers the second half of the rule:
// the refused registration leaves the url with its owner.
func TestPoolingJoinRequiresTheSameOwnerOnTheHttpPath(t *testing.T) {
	setupTestRegistry(t)
	opts.authTokens = []string{"token-1", "token-2"}

	ownerCtl := testControl(t, "token-1")
	otherCtl := testControl(t, "token-2")
	const host = "shared.ngrok.test"

	owner := registerTestTunnel(t, ownerCtl, msg.ReqTunnel{Protocol: "http", Hostname: host, Pooling: true})

	_, err := NewTunnel(&msg.ReqTunnel{Protocol: "http", Hostname: host, Pooling: true}, otherCtl)
	if err == nil {
		t.Fatal("another account pooled onto a hostname it does not own")
	}
	if !strings.Contains(err.Error(), "different account") {
		t.Fatalf("the refusal %q does not say why the join was refused", err)
	}

	// the bucket is still the owner's, and still a bucket of one
	if got := tunnelRegistry.Get(owner.url); got != owner {
		t.Fatal("the url is no longer served by the account that registered it")
	}
	if got := len(tunnelRegistry.tunnels[owner.url].tunnels); got != 1 {
		t.Fatalf("the bucket holds %d members after the refusal, want 1", got)
	}
	if !tunnelRegistry.IsPooling(owner.url) {
		t.Fatal("the owner's bucket stopped pooling after another account was refused")
	}
}

// TestPoolingJoinRequiresTheSameOwnerOnTheTcpPath covers the TCP half: a
// pooling TCP tunnel joins the listener its port already has, and that join is
// the same Register call, so the same account rule applies.
func TestPoolingJoinRequiresTheSameOwnerOnTheTcpPath(t *testing.T) {
	reg := setupTestRegistry(t)
	opts.authTokens = []string{"token-1", "token-2"}

	// arm every proxy connection before the listener exists, so nothing races
	// the accept goroutine's conn.Wrap (see armProxyPool)
	creatorCtl := testControl(t, "token-1")
	otherCtl := testControl(t, "token-2")
	armProxyPool(t, creatorCtl)
	armProxyPool(t, otherCtl)

	creator := registerTestTunnel(t, creatorCtl, msg.ReqTunnel{Protocol: "tcp", Pooling: true})
	if creator.listener == nil {
		t.Fatal("the first pooling TCP tunnel must bind the listener")
	}
	port := creator.listener.Addr().(*net.TCPAddr).Port

	_, err := NewTunnel(&msg.ReqTunnel{Protocol: "tcp", Pooling: true, RemotePort: uint16(port)}, otherCtl)
	if err == nil {
		t.Fatal("another account joined a pooling TCP port: it will be handed that port's connections")
	}
	if !strings.Contains(err.Error(), "different account") {
		t.Fatalf("the refusal %q does not say why the join was refused", err)
	}
	if got := len(reg.tunnels[creator.url].tunnels); got != 1 {
		t.Fatalf("the bucket holds %d members after the refusal, want 1", got)
	}

	// the owner can still join its own pool, and the member gets no listener
	memberCtl := testControl(t, "token-1")
	armProxyPool(t, memberCtl)
	member := registerTestTunnel(t, memberCtl, msg.ReqTunnel{Protocol: "tcp", Pooling: true, RemotePort: uint16(port)})
	if member.url != creator.url {
		t.Fatalf("the same-account member registered %s, want %s", member.url, creator.url)
	}
	if member.listener != nil {
		t.Fatal("a pooling member must not bind a second listener")
	}
}

// ---------------------------------------------------------------------------
// C2 / PT-C2: the session secret

// TestSessionSecretShape pins the two properties the rest of the design assumes:
// 32 bytes of entropy (64 hex characters) and a fresh value every time.
func TestSessionSecretShape(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 8; i++ {
		secret, err := newSessionSecret()
		if err != nil {
			t.Fatalf("newSessionSecret failed: %v", err)
		}
		if len(secret) != 2*sessionSecretBytes {
			t.Fatalf("the secret is %d characters, want %d (32 bytes, hex)", len(secret), 2*sessionSecretBytes)
		}
		if _, err := hex.DecodeString(secret); err != nil {
			t.Fatalf("the secret is not hex: %v", err)
		}
		if seen[secret] {
			t.Fatal("newSessionSecret repeated a value: a leaked secret would be resumable by anyone")
		}
		seen[secret] = true
	}
}

// TestSecretMatches covers the comparison rules, including the one that makes
// the whole thing fail closed: an empty stored secret matches nothing, so a
// control that was never given one (a fixture, or a bug) refuses resume instead
// of accepting the empty string an attacker would send.
func TestSecretMatches(t *testing.T) {
	cases := []struct {
		name      string
		stored    string
		candidate string
		want      bool
	}{
		{"the same value", "ab12", "ab12", true},
		{"a different value", "ab12", "ab13", false},
		{"a prefix", "ab12", "ab1", false},
		{"a value that extends it", "ab12", "ab123", false},
		{"nothing presented", "ab12", "", false},
		{"nothing stored", "", "ab12", false},
		{"both empty", "", "", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := secretMatches(tc.stored, tc.candidate); got != tc.want {
				t.Fatalf("secretMatches(%q, %q) = %v, want %v", tc.stored, tc.candidate, got, tc.want)
			}
		})
	}
}

// startTestControl drives the real NewControl entry point over a loopback TCP
// pair and returns what the client was answered with.
//
// The control is looked up in the registry by the id in the answer, which is
// also the assertion that an accepted session registered itself: nil means the
// answer was a refusal (or that registration did not happen).
//
// An accepted session is shut down again when the test ends, and waited for.
// Its four goroutines live until then, and the stopper reads -- and removes
// itself from -- the control registry on the way out, so a test that ends
// first leaves them to race the next test's fixtures, which is what a
// "--race" report about controlRegistry is: not a bug in the control, but a
// test that did not clean up after itself.
func startTestControl(t *testing.T, auth *msg.Auth) (ctl *Control, client conn.Conn, resp *msg.AuthResp) {
	t.Helper()

	clientTcp, serverTcp := tcpPair(t)
	client = conn.Wrap(clientTcp, "ctl")
	t.Cleanup(func() { client.Close() })

	server := conn.Wrap(serverTcp, "ctl")
	go NewControl(server, auth)

	if err := client.SetReadDeadline(time.Now().Add(publicTimeout)); err != nil {
		t.Fatalf("failed to set a read deadline: %v", err)
	}
	m, err := msg.ReadMsg(client)
	if err != nil {
		t.Fatalf("NewControl answered nothing: %v", err)
	}
	var ok bool
	if resp, ok = m.(*msg.AuthResp); !ok {
		t.Fatalf("the first message was %T, want *msg.AuthResp", m)
	}
	if resp.Error == "" {
		ctl = controlRegistry.Get(resp.ClientId)
		waitForControlShutdown(t, server, ctl)
	}
	return
}

// waitForControlShutdown arranges for a control built by NewControl to be shut
// down when the test ends, and waits for the shutdown to finish.
//
// The wait is the point: the stopper reads the control registry as it leaves,
// so the test's cleanup -- which restores the registry the fixture replaced --
// must not run until the last control goroutine is done with it. Closing the
// control's conn is what a client that went away looks like, and the shutdown
// follows from it.
func waitForControlShutdown(t *testing.T, ctlConn conn.Conn, ctl *Control) {
	t.Helper()

	t.Cleanup(func() {
		ctlConn.Close()
		if ctl == nil {
			return
		}

		done := make(chan struct{})
		go func() {
			defer close(done)
			ctl.shutdown.WaitComplete()
		}()

		select {
		case <-done:
		case <-time.After(publicTimeout):
			t.Errorf("the control did not finish shutting down within %s", publicTimeout)
		}
	})
}

// TestAuthResumeRequiresTheSessionSecret is the core of the finding: a client
// id is public (it is logged, cached and reported), so a connection that names
// one must present the secret the server minted for it -- or be refused without
// touching the session it tried to claim.
func TestAuthResumeRequiresTheSessionSecret(t *testing.T) {
	setupTestRegistry(t)
	reg := setupTestControlRegistry(t)

	live, _, first := startTestControl(t, &msg.Auth{Version: version.Proto})
	if first.Error != "" {
		t.Fatalf("the first session was refused: %s", first.Error)
	}
	if first.ClientId == "" || first.Secret == "" {
		t.Fatal("an accepted session was answered without an id and a secret")
	}
	if live == nil {
		t.Fatal("the accepted session is not in the control registry")
	}
	if live.secret != first.Secret {
		t.Fatal("the control does not carry the secret it handed out")
	}

	// 1. no secret at all -- an old client, or an attacker who read the id out
	// of a log line
	_, _, missing := startTestControl(t, &msg.Auth{Version: version.Proto, ClientId: first.ClientId})
	if !strings.Contains(missing.Error, "cannot be resumed") {
		t.Fatalf("a resume with no secret was answered %q, want a refusal", missing.Error)
	}

	// 2. a secret of the right shape that is not the real one
	wrong := strings.Repeat("0", 2*sessionSecretBytes)
	if wrong == first.Secret {
		t.Fatal("the test's wrong secret is the real one")
	}
	_, _, wrongResp := startTestControl(t, &msg.Auth{Version: version.Proto, ClientId: first.ClientId, Secret: wrong})
	if !strings.Contains(wrongResp.Error, "cannot be resumed") {
		t.Fatalf("a resume with a wrong secret was answered %q, want a refusal", wrongResp.Error)
	}

	// Neither attempt may have disturbed the session it named: the id still
	// belongs to the live control, which was not told it was replaced.
	if got := reg.Get(first.ClientId); got != live {
		t.Fatal("a refused resume changed the control registered for the id")
	}
	if live.wasReplaced() {
		t.Fatal("a refused resume evicted the live session")
	}

	// 3. the secret proves it: the resume is accepted, keeps the id, and takes
	// the id over from the control it replaces
	resumed, _, resumedResp := startTestControl(t, &msg.Auth{
		Version:  version.Proto,
		ClientId: first.ClientId,
		Secret:   first.Secret,
	})
	if resumedResp.Error != "" {
		t.Fatalf("a resume with the right secret was refused: %s", resumedResp.Error)
	}
	if resumedResp.ClientId != first.ClientId {
		t.Fatal("the resumed session was given a different id")
	}
	if resumedResp.Secret != first.Secret {
		t.Fatal("the session secret was rotated on resume: the client would lose the session on its next reconnect")
	}
	if resumed == nil || resumed == live {
		t.Fatal("the resumed connection did not become the registered control")
	}
	if !live.wasReplaced() {
		t.Fatal("the replaced control does not know it was replaced")
	}
	if got := reg.Get(first.ClientId); got != resumed {
		t.Fatal("the replaced control's shutdown took the replacement out of the registry")
	}
}

// TestAuthWithAnUnknownIdGetsAFreshIdentity covers the third outcome: an id the
// server has no live control for (a restart, or a session that ended) is not
// resumed and not reused -- a new id and secret are minted, so naming an id can
// never be a way to acquire one.
func TestAuthWithAnUnknownIdGetsAFreshIdentity(t *testing.T) {
	setupTestRegistry(t)
	reg := setupTestControlRegistry(t)

	const unknown = "client-that-was-never-assigned"
	ctl, _, resp := startTestControl(t, &msg.Auth{Version: version.Proto, ClientId: unknown})
	if resp.Error != "" {
		t.Fatalf("an unknown id was refused instead of given a new session: %s", resp.Error)
	}
	if resp.ClientId == unknown {
		t.Fatal("the requested id was handed back: a stale id is now a claim on the old session's tunnels")
	}
	if resp.ClientId == "" || resp.Secret == "" {
		t.Fatal("the new session was answered without an id and a secret")
	}
	if ctl == nil || reg.Get(resp.ClientId) != ctl {
		t.Fatal("the new session is not registered under its new id")
	}
}

// TestRegProxyRequiresTheSessionSecret covers the dialed proxy path, where the
// id used to be the only thing asked for: a conn with the wrong secret -- and
// an old client with no secret at all -- is closed and never pooled. The
// right-secret case is the control that keeps the test honest.
func TestRegProxyRequiresTheSessionSecret(t *testing.T) {
	cases := []struct {
		name       string
		secret     string
		wantPooled bool
	}{
		{"no secret", "", false},
		{"a wrong secret", strings.Repeat("f", 2*sessionSecretBytes), false},
		{"the right secret", testSessionSecret("client-1"), true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reg := setupTestControlRegistry(t)
			ctl := muxTestControl(t, reg, "client-1")

			client, server := tcpPair(t)
			go NewProxy(conn.Wrap(server, "pxy"), &msg.RegProxy{ClientId: "client-1", Secret: tc.secret})

			if tc.wantPooled {
				if got := waitForProxy(t, ctl); got == nil {
					t.Fatal("a proxy conn with the right secret was not pooled")
				}
				return
			}

			expectClosed(t, client, "the proxy conn")

			// the close is the last thing NewProxy does, so anything it pooled
			// would already be in the channel by now
			select {
			case c := <-ctl.proxies:
				c.Close()
				t.Fatal("a proxy conn that did not prove the session was pooled")
			default:
			}
		})
	}
}

// TestRegMuxRequiresTheSessionSecret is the same rule on the mux path, where the
// session it would attach is the whole proxy transport of a control.
func TestRegMuxRequiresTheSessionSecret(t *testing.T) {
	cases := []struct {
		name         string
		secret       string
		wantAttached bool
	}{
		{"no secret", "", false},
		{"a wrong secret", strings.Repeat("e", 2*sessionSecretBytes), false},
		{"the right secret", testSessionSecret("client-1"), true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reg := setupTestControlRegistry(t)
			ctl := muxTestControl(t, reg, "client-1")

			client, server := tcpPair(t)
			go NewMux(conn.Wrap(server, "mux"), &msg.RegMux{ClientId: "client-1", Secret: tc.secret})

			if tc.wantAttached {
				waitForMuxSession(t, ctl, anySession)
				return
			}

			expectClosed(t, client, "the mux conn")
			if m := ctl.MuxSession(); m != nil {
				t.Fatal("a mux session that did not prove the id was attached")
			}
		})
	}
}

// TestMuxStreamRejectsWrongSecret covers the check only a stream can be asked
// for: a stream is not authenticated on its own, so a session that is allowed
// does not make every stream on it allowed -- the id has to be the session's
// (TestMuxStreamRejectsAnotherClientId) and the secret has to prove it.
func TestMuxStreamRejectsWrongSecret(t *testing.T) {
	reg := setupTestControlRegistry(t)
	ctl := muxTestControl(t, reg, "client-a")

	sess := muxTestPair(t, "client-a")
	stream, err := sess.OpenStream()
	if err != nil {
		t.Fatalf("failed to open a proxy stream: %v", err)
	}
	streamConn := conn.Wrap(stream, "pxy")
	t.Cleanup(func() { streamConn.Close() })

	if err := msg.WriteMsg(streamConn, &msg.RegProxy{ClientId: "client-a", Secret: "not-the-session-secret"}); err != nil {
		t.Fatalf("failed to write RegProxy: %v", err)
	}

	streamConn.SetReadDeadline(time.Now().Add(publicTimeout))
	if _, err := streamConn.Read(make([]byte, 1)); err == nil {
		t.Fatal("a stream with a wrong secret was not closed")
	}

	select {
	case c := <-ctl.proxies:
		c.Close()
		t.Fatal("a stream that did not prove the session was pooled")
	default:
	}
}

// maskSecret replaces a secret with a placeholder in anything a test prints.
// The failure of the test below is exactly that the secret reached a sink, and
// a failure message is a sink too.
func maskSecret(s, secret string) string {
	if secret == "" {
		return s
	}
	return strings.ReplaceAll(s, secret, "<session-secret>")
}

// TestSessionSecretNeverAppearsInLogsOrEvents runs every path that handles the
// secret -- minting it, refusing a resume, refusing a proxy conn, refusing a mux
// session -- with the log at DEBUG and an event subscription open, and asserts
// the value is nowhere in either.
//
// The log writers are asynchronous (log4go hands records to a writer goroutine
// through a channel), so the test writes a marker after the operations and waits
// for the marker to appear before reading the file: everything the operations
// logged is on disk by then.
func TestSessionSecretNeverAppearsInLogsOrEvents(t *testing.T) {
	setupTestRegistry(t)
	setupTestControlRegistry(t)

	logFile := filepath.Join(t.TempDir(), "server.log")
	log.LogTo(logFile, "DEBUG", "text")

	events := observe.events.subscribe()
	t.Cleanup(func() { observe.events.unsubscribe(events) })

	_, _, resp := startTestControl(t, &msg.Auth{Version: version.Proto})
	if resp.Error != "" || resp.Secret == "" {
		t.Fatalf("the session under test was not established: %s", resp.Error)
	}
	secret := resp.Secret

	// every refusal path, so that the code that decides about the secret is the
	// code being watched: a session resumed with the wrong secret, a proxy conn
	// and a mux session presenting the wrong secret
	_, _, _ = startTestControl(t, &msg.Auth{
		Version:  version.Proto,
		ClientId: resp.ClientId,
		Secret:   strings.Repeat("a", 2*sessionSecretBytes),
	})

	pxyClient, pxyServer := tcpPair(t)
	go NewProxy(conn.Wrap(pxyServer, "pxy"), &msg.RegProxy{ClientId: resp.ClientId, Secret: strings.Repeat("b", 2*sessionSecretBytes)})
	expectClosed(t, pxyClient, "the proxy conn")

	muxClient, muxServer := tcpPair(t)
	go NewMux(conn.Wrap(muxServer, "mux"), &msg.RegMux{ClientId: resp.ClientId, Secret: strings.Repeat("c", 2*sessionSecretBytes)})
	expectClosed(t, muxClient, "the mux conn")

	// the control's own id is logged (it is public); the secret must not be
	const marker = "secret-scan-marker"
	log.Info(marker)

	content := waitForFileMarker(t, logFile, marker)
	if strings.Contains(content, secret) {
		t.Fatalf("the session secret reached the log file:\n%s", maskSecret(content, secret))
	}

	// and the event stream: every event published while the session was being
	// established and refused is checked, not just the ones about the secret
	drained := 0
	for {
		select {
		case payload := <-events.ch:
			drained++
			if strings.Contains(string(payload), secret) {
				t.Fatalf("the session secret reached an event: %s", maskSecret(string(payload), secret))
			}
			continue
		default:
		}
		break
	}
	if drained == 0 {
		t.Fatal("no events were observed: the assertion above proved nothing")
	}
}

// waitForFileMarker polls path until it contains marker and returns the file.
func waitForFileMarker(t *testing.T, path, marker string) string {
	t.Helper()

	var content []byte
	var err error
	deadline := time.Now().Add(publicTimeout)
	for time.Now().Before(deadline) {
		if content, err = os.ReadFile(path); err == nil && bytes.Contains(content, []byte(marker)) {
			return string(content)
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("the log file %s never received the marker %q (read %d bytes, err %v)", path, marker, len(content), err)
	return ""
}

// ---------------------------------------------------------------------------
// M1: .internal is not a public namespace

// TestAPublicBindingCannotClaimAnInternalHostname covers the server-side half of
// a rule that used to live only in the client: a public endpoint named
// x.internal is unreachable (the public listener never routes .internal hosts)
// and a name an operator would read as private. The refusal has to happen before
// the url is claimed, or the name is taken by a tunnel nobody can reach.
func TestAPublicBindingCannotClaimAnInternalHostname(t *testing.T) {
	setupTestRegistry(t)
	ctl := testControl(t, "")

	cases := []struct {
		name     string
		hostname string
	}{
		{"lower case", "svc.internal"},
		{"mixed case", "SVC.Internal"},
		{"padded", " svc.internal "},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewTunnel(&msg.ReqTunnel{Protocol: "http", Hostname: tc.hostname}, ctl)
			if err == nil {
				t.Fatal("a public endpoint registered an .internal hostname")
			}
			if !strings.Contains(err.Error(), "requires binding internal") {
				t.Fatalf("the refusal %q does not explain that .internal needs binding internal", err)
			}
			// the refusal names the hostname as it was sent (trimmed), so the
			// operator can tell which endpoint was refused
			if !strings.Contains(err.Error(), strings.TrimSpace(tc.hostname)) {
				t.Fatalf("the refusal %q does not name the hostname it refused", err)
			}
			if _, ok := tunnelRegistry.tunnels["http://svc.internal"]; ok {
				t.Fatal("the refused registration claimed the url anyway")
			}
			if tunnelRegistry.Get("http://svc.internal") != nil {
				t.Fatal("the refused registration is routable")
			}
		})
	}

	// the name is still available to the binding that owns the namespace
	internal := registerTestTunnel(t, ctl, msg.ReqTunnel{Protocol: "http", Binding: msg.BindingInternal, Hostname: "svc.internal"})
	if got := tunnelRegistry.GetInternal(internal.url, defaultOwner); got != internal {
		t.Fatal("the refusals left the name unusable by the internal endpoint it belongs to")
	}

	// and public endpoints are unaffected
	public := registerTestTunnel(t, ctl, msg.ReqTunnel{Protocol: "http", Hostname: "pub.ngrok.test"})
	if tunnelRegistry.Get(public.url) != public {
		t.Fatal("a public endpoint no longer registers")
	}
}

// TestInternalHostnamesAreNotRewrittenIntoShape is the M1 companion on the
// internal side: a hostname that is not the canonical spelling is refused
// rather than canonicalized, because what gets registered is what forward_to
// has to resolve. The refusal also leaves the name unclaimed.
func TestInternalHostnamesAreNotRewrittenIntoShape(t *testing.T) {
	setupTestRegistry(t)
	ctl := testControl(t, "")

	cases := []struct {
		name     string
		hostname string
		wantErr  string
	}{
		{"mixed case", "SVC.Internal", "must be lowercase"},
		{"a space", "sv c.internal", "must not contain spaces"},
		{"a path", "svc/evil.internal", "must not contain spaces"},
		{"the bare suffix", ".internal", "needs a name in front of"},
		{"no suffix", "svc.example.com", msg.InternalSuffix},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewTunnel(&msg.ReqTunnel{Protocol: "http", Binding: msg.BindingInternal, Hostname: tc.hostname}, ctl)
			if err == nil {
				t.Fatalf("the internal hostname %q was accepted", tc.hostname)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("the refusal %q does not mention %q", err, tc.wantErr)
			}
			claimed := "https://" + strings.ToLower(strings.TrimSpace(tc.hostname))
			if tunnelRegistry.GetInternal(claimed, defaultOwner) != nil {
				t.Fatal("the refused internal hostname was registered anyway")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// M5: forward_to's connect phase runs the target's policy

// TestForwardToConnectPhaseUsesTheTargetsPolicy is the finding: the connect
// verdict used to be taken against the entry endpoint's policy while the hooks
// ran the target's, so an entry with no policy of its own skipped the
// restrict-ips attached to the endpoint the traffic actually terminates at.
// Here the entry has no policy at all and the target refuses the client, so a
// connection that is admitted is a connection the target's policy never saw.
func TestForwardToConnectPhaseUsesTheTargetsPolicy(t *testing.T) {
	const entry = "entry.ngrok.test"

	setupTestRegistry(t)
	ctl := testControl(t, "")

	target := registerTestTunnel(t, ctl, msg.ReqTunnel{
		Protocol: "http", Binding: msg.BindingInternal, Hostname: "svc.internal",
		TrafficPolicy: &policy.TrafficPolicy{OnTCPConnect: []*policy.Action{
			// the public client is on 127.0.0.1, so this refuses it
			policyActionConfig("restrict-ips", map[string]interface{}{
				"allow": []interface{}{"10.0.0.0/8"},
			}),
		}},
	})
	registerTestTunnel(t, ctl, msg.ReqTunnel{Protocol: "http", Hostname: entry, ForwardTo: target.url})

	agent := armHTTPAgent(t, ctl)

	resp, body := policyRoundTrip(t, entry, "/")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: the target's connect policy did not run", resp.StatusCode)
	}
	if body != "" {
		t.Fatalf("body = %q, want an empty body", body)
	}
	expectNoBytes(t, agent, "the internal endpoint's agent")
}

// TestForwardToConnectPhaseLetsAPermittedClientThrough is the other half: the
// chain still works when the target's policy permits the client, so the test
// above cannot pass by refusing every forward_to connection.
func TestForwardToConnectPhaseLetsAPermittedClientThrough(t *testing.T) {
	const entry = "entry.ngrok.test"

	setupTestRegistry(t)
	ctl := testControl(t, "")

	target := registerTestTunnel(t, ctl, msg.ReqTunnel{
		Protocol: "http", Binding: msg.BindingInternal, Hostname: "svc.internal",
		TrafficPolicy: &policy.TrafficPolicy{OnTCPConnect: []*policy.Action{
			policyActionConfig("restrict-ips", map[string]interface{}{
				"allow": []interface{}{"127.0.0.1/32"},
			}),
		}},
	})
	registerTestTunnel(t, ctl, msg.ReqTunnel{Protocol: "http", Hostname: entry, ForwardTo: target.url})

	agent := armHTTPAgent(t, ctl)
	res := startPublicRequest(t, entry, "/hello")

	if got := readStartProxy(t, agent, "the internal endpoint's agent"); got.Url != target.url {
		t.Fatalf("StartProxy Url = %q, want the internal endpoint %s", got.Url, target.url)
	}
	if head := readHead(t, agent, "the agent"); !strings.HasPrefix(head, "GET /hello HTTP/1.1\r\n") {
		t.Fatalf("the agent got %q, want the request", head)
	}

	upstream := "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
	if _, err := agent.Write([]byte(upstream)); err != nil {
		t.Fatalf("failed to write the upstream response: %v", err)
	}

	resp, body := waitPublic(t, res)
	if resp.StatusCode != http.StatusOK || body != "hello" {
		t.Fatalf("the public client got %d %q, want 200 \"hello\"", resp.StatusCode, body)
	}
}

// ---------------------------------------------------------------------------
// PT-M7: the token is checked before the version

// TestNewControlChecksTheTokenBeforeTheVersion covers the order of the two
// checks: the version error names the server's version and tells the caller to
// download a matching one, so answering an unauthenticated caller with it
// discloses what the server runs. A wrong token gets the token error, whatever
// version it claims.
func TestNewControlChecksTheTokenBeforeTheVersion(t *testing.T) {
	setupTestRegistry(t)
	setupTestControlRegistry(t)
	opts.authTokens = []string{"good-token"}

	const badVersion = "0.0-not-a-version"

	_, _, refused := startTestControl(t, &msg.Auth{User: "bad-token", Version: badVersion})
	if !strings.Contains(refused.Error, "Invalid authentication token") {
		t.Fatalf("a wrong token was answered %q, want the token error", refused.Error)
	}
	if strings.Contains(refused.Error, "Incompatible versions") {
		t.Fatal("the version check ran before the token check: an unauthenticated caller learned the server version")
	}
	if refused.ClientId != "" || refused.Secret != "" {
		t.Fatal("a refused session was answered with an identity")
	}

	// the positive control: with the right token the version is checked, and
	// the version error is what a mismatched client is meant to receive
	_, _, versionMismatch := startTestControl(t, &msg.Auth{User: "good-token", Version: badVersion})
	if !strings.Contains(versionMismatch.Error, "Incompatible versions") {
		t.Fatalf("a matching token with a wrong version was answered %q, want the version error", versionMismatch.Error)
	}

	// and a session that passes both is accepted
	ctl, _, accepted := startTestControl(t, &msg.Auth{User: "good-token", Version: version.Proto})
	if accepted.Error != "" {
		t.Fatalf("a matching token and version was refused: %s", accepted.Error)
	}
	if ctl == nil || ctl.id != accepted.ClientId {
		t.Fatal("the accepted session was not registered under the id it was given")
	}
}

// ---------------------------------------------------------------------------
// PT-M9: the 404 does not reflect the Host

// evilHost is the Host the reflection tests send. It is deliberately a value
// that would execute if it were reflected raw and rendered by a browser.
func evilHost() string { return "<script>alert(1)</script>" }

// TestNotFoundEscapesTheHostnameAndTypesTheBody covers the 404 the public
// listener answers an unknown Host with. The Host is attacker-controlled and
// needs no authentication, so reflecting it raw would be XSS on the tunnel
// domain itself; the body is typed so a browser does not sniff one.
func TestNotFoundEscapesTheHostnameAndTypesTheBody(t *testing.T) {
	setupTestRegistry(t)

	resp, body := waitPublic(t, startPublicRequest(t, evilHost(), "/"))

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/plain; charset=utf-8" {
		t.Fatalf("Content-Type = %q, want text/plain; charset=utf-8", ct)
	}
	if strings.Contains(body, "<script>") {
		t.Fatalf("the Host was reflected unescaped: %q", body)
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Fatalf("body = %q, want the escaped hostname", body)
	}
	if !strings.Contains(body, "Tunnel ") {
		t.Fatalf("body = %q, want the 404 sentence", body)
	}
}

// TestNotFoundResponseIsByteAccurate pins the response the 404 helper builds:
// the declared Content-Length has to be the length of what is written, escaping
// included. It is a unit test because the failure it guards against -- a length
// measured against a body the format string renders differently -- makes the
// response truncated or unparseable, which is easier to see here than through a
// client.
func TestNotFoundResponseIsByteAccurate(t *testing.T) {
	for _, host := range []string{"svc.internal", evilHost(), `a&b"c`, ""} {
		raw := notFoundResponse(host)
		resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(raw)), nil)
		if err != nil {
			t.Fatalf("host %q: the response does not parse: %v", host, err)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("host %q: failed to read the body: %v", host, err)
		}
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("host %q: status = %d, want 404", host, resp.StatusCode)
		}
		if int64(len(body)) != resp.ContentLength {
			t.Fatalf("host %q: declared %d body bytes, wrote %d", host, resp.ContentLength, len(body))
		}
		if want := "Tunnel " + html.EscapeString(host) + " not found\n"; string(body) != want {
			t.Fatalf("host %q: body = %q, want %q", host, body, want)
		}
	}
}

// ---------------------------------------------------------------------------
// C3: the public leg's head read is bounded

// TestOversizedRequestHeadIsRefused covers the bound itself, end to end: a head
// that does not fit in maxHeadBytes is answered with a 4xx and never reaches a
// tunnel. The two cases are the two ways to exceed it -- one line that cannot
// fit in the read buffer, and many lines whose total does not.
func TestOversizedRequestHeadIsRefused(t *testing.T) {
	const host = "big.ngrok.test"

	cases := []struct {
		name string
		head func() string
	}{
		{
			name: "one header line past the cap",
			head: func() string {
				return "GET / HTTP/1.1\r\nHost: " + host + "\r\nX-Big: " + strings.Repeat("a", maxHeadBytes) + "\r\n\r\n"
			},
		},
		{
			name: "many header lines past the cap",
			head: func() string {
				var b strings.Builder
				b.WriteString("GET / HTTP/1.1\r\nHost: " + host + "\r\n")
				line := "X-Pad: " + strings.Repeat("b", 100) + "\r\n"
				for total := 0; total <= maxHeadBytes; total += len(line) {
					b.WriteString(line)
				}
				b.WriteString("\r\n")
				return b.String()
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setupTestRegistry(t)
			ctl := testControl(t, "")
			agent := armHTTPAgent(t, ctl)
			registerTestTunnel(t, ctl, msg.ReqTunnel{Protocol: "http", Hostname: host})

			client, server := tcpPair(t)
			go httpHandler(conn.Wrap(server, "pub"), "http")

			request := tc.head()
			if len(request) <= maxHeadBytes {
				t.Fatalf("the fixture head is %d bytes, which is not over the %d byte cap", len(request), maxHeadBytes)
			}
			if _, err := client.Write([]byte(request)); err != nil {
				t.Fatalf("failed to write the oversized head: %v", err)
			}

			if err := client.SetReadDeadline(time.Now().Add(publicTimeout)); err != nil {
				t.Fatalf("failed to set a read deadline: %v", err)
			}
			resp, err := http.ReadResponse(bufio.NewReader(client), nil)
			if err != nil {
				t.Fatalf("an oversized head was not answered: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
				t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusRequestHeaderFieldsTooLarge)
			}

			// nothing reached the tunnel: the request was refused while routing,
			// before an agent was asked for a proxy connection
			expectNoBytes(t, agent, "the agent")
		})
	}
}

// TestReadRequestHeadStopsAtTheCap pins the bound at the read itself, which is
// where the memory bound lives: the reader is the cap, so neither a long line
// nor a long head can make it hold more than maxHeadBytes. A head of exactly
// the cap is accepted -- the limit is a limit, not an off-by-one.
func TestReadRequestHeadStopsAtTheCap(t *testing.T) {
	t.Run("a head at the cap is accepted", func(t *testing.T) {
		request := requestWithPadding(maxHeadBytes)
		head, err := readRequestHeadAt(request)
		if err != nil {
			t.Fatalf("a head of exactly %d bytes was refused: %v", maxHeadBytes, err)
		}
		if len(head) != maxHeadBytes {
			t.Fatalf("the head read back is %d bytes, want %d", len(head), maxHeadBytes)
		}
	})

	t.Run("a line past the cap is refused", func(t *testing.T) {
		_, err := readRequestHeadAt("GET / HTTP/1.1\r\nHost: h.test\r\nX-Big: " + strings.Repeat("a", maxHeadBytes) + "\r\n\r\n")
		if !errors.Is(err, errHeadLineTooLong) {
			t.Fatalf("err = %v, want errHeadLineTooLong", err)
		}
	})

	t.Run("a head past the cap is refused", func(t *testing.T) {
		line := "X-Pad: " + strings.Repeat("d", 100) + "\r\n"
		if len(line) > maxHeadBytes {
			t.Fatal("the fixture line does not fit in the read buffer: it would be refused for the wrong reason")
		}

		var b strings.Builder
		b.WriteString("GET / HTTP/1.1\r\nHost: h.test\r\n")
		for total := 0; total <= maxHeadBytes; total += len(line) {
			b.WriteString(line)
		}
		b.WriteString("\r\n")

		if _, err := readRequestHeadAt(b.String()); !errors.Is(err, errHeadTooLarge) {
			t.Fatalf("err = %v, want errHeadTooLarge", err)
		}
	})

	t.Run("an unterminated head is refused", func(t *testing.T) {
		if _, err := readRequestHeadAt("GET / HTTP/1.1\r\nHost: h.test\r\n"); !errors.Is(err, io.EOF) {
			t.Fatalf("err = %v, want io.EOF", err)
		}
	})
}

// requestWithPadding builds a valid request head whose total length is want,
// the blank line that ends the head included: that is the length the cap is
// about, so "at the cap" is what the reader has to accept.
func requestWithPadding(want int) string {
	const prefix = "GET / HTTP/1.1\r\nHost: h.test\r\n"
	const pad = "X-Pad: "

	// the last padding line plus the one-byte line that ends the head
	fill := want - len(prefix) - len(pad) - 2*len("\r\n")
	if fill < 0 {
		panic("requestWithPadding: want is smaller than the request itself")
	}
	return prefix + pad + strings.Repeat("p", fill) + "\r\n\r\n"
}

// readRequestHeadAt runs the real head reader over a synthetic connection.
func readRequestHeadAt(request string) ([]byte, error) {
	head, _, err := readRequestHead(newScriptedConn(strings.NewReader(request)))
	return head, err
}

// TestHostIsExtractedTheWayTheVhostParserDid pins the routing input: the first
// Host field, found case-insensitively, value lowercased (the registry keys
// tunnel urls in lower case), port kept when one was sent. A parser that
// disagreed with the one the rest of the path assumes would route a request by
// one name and hand it to the agent under another.
func TestHostIsExtractedTheWayTheVhostParserDid(t *testing.T) {
	cases := []struct {
		name string
		head string
		want string
	}{
		{
			name: "lower case field and value",
			head: "GET / HTTP/1.1\r\nHost: pub.ngrok.test\r\n\r\n",
			want: "pub.ngrok.test",
		},
		{
			name: "the field name is case-insensitive",
			head: "GET / HTTP/1.1\r\nhOsT: pub.ngrok.test\r\n\r\n",
			want: "pub.ngrok.test",
		},
		{
			name: "the value is lowercased",
			head: "GET / HTTP/1.1\r\nHost: PUB.Ngrok.TEST\r\n\r\n",
			want: "pub.ngrok.test",
		},
		{
			name: "the value is trimmed",
			head: "GET / HTTP/1.1\r\nHost:   pub.ngrok.test  \r\n\r\n",
			want: "pub.ngrok.test",
		},
		{
			name: "the port is kept",
			head: "GET / HTTP/1.1\r\nHost: pub.ngrok.test:8080\r\n\r\n",
			want: "pub.ngrok.test:8080",
		},
		{
			name: "the first occurrence wins",
			head: "GET / HTTP/1.1\r\nHost: first.ngrok.test\r\nHost: second.ngrok.test\r\n\r\n",
			want: "first.ngrok.test",
		},
		{
			name: "no Host at all",
			head: "GET / HTTP/1.1\r\nAccept: */*\r\n\r\n",
			want: "",
		},
		{
			name: "a field whose value looks like one is not a Host",
			head: "GET / HTTP/1.1\r\nX-Forwarded-Host: other.ngrok.test\r\n\r\n",
			want: "",
		},
		{
			name: "the request line is not searched for fields",
			head: "GET http://line.ngrok.test/ HTTP/1.1\r\nHost: header.ngrok.test\r\n\r\n",
			want: "header.ngrok.test",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			head, _, err := readRequestHead(newScriptedConn(strings.NewReader(tc.head)))
			if err != nil {
				t.Fatalf("the head did not parse: %v", err)
			}
			if got := hostFromHead(head); got != tc.want {
				t.Fatalf("hostFromHead = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestHeadRoutingFollowsTheExtraction takes the same rule through the public
// path: a case variant reaches the tunnel (the request is routed by the
// lowercased name the tunnel registered) and a port variant does not (there is
// no tunnel for that name, and the port is part of the name the parser returns).
func TestHeadRoutingFollowsTheExtraction(t *testing.T) {
	const host = "pub.ngrok.test"

	setupTestRegistry(t)
	ctl := testControl(t, "")
	agent := armHTTPAgent(t, ctl)
	registerTestTunnel(t, ctl, msg.ReqTunnel{Protocol: "http", Hostname: host})

	res := startPublicRequest(t, strings.ToUpper(host), "/")
	if got := readStartProxy(t, agent, "the agent"); got.Url != "http://"+host {
		t.Fatalf("StartProxy Url = %q, want http://%s: the request was routed by a different name than it was registered under", got.Url, host)
	}
	if _, err := agent.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")); err != nil {
		t.Fatalf("failed to write the upstream response: %v", err)
	}
	if resp, body := waitPublic(t, res); resp.StatusCode != http.StatusOK || body != "ok" {
		t.Fatalf("the case variant got %d %q, want 200 \"ok\"", resp.StatusCode, body)
	}

	if status, _ := publicRequest(t, host+":8080"); status != http.StatusNotFound {
		t.Fatalf("status = %d for a port variant, want 404: the port is part of the name the vhost lookup uses", status)
	}
}

// TestBodyBeyondTheHeadReachesTheAgent is the other half of the bounded read:
// the bytes the reader over-read are replayed, so the agent receives the request
// head and the body byte for byte. The reader stops at the blank line, which
// means the body usually arrived in the same read as the head -- the exact case
// a bounded reader is most likely to lose.
func TestBodyBeyondTheHeadReachesTheAgent(t *testing.T) {
	const host = "post.ngrok.test"

	// small enough to arrive with the head, and then one that does not
	cases := []struct {
		name string
		size int
	}{
		{"a body that arrives with the head", 11},
		{"a body larger than the head buffer", 3 * maxHeadBytes},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setupTestRegistry(t)
			ctl := testControl(t, "")
			agent := armHTTPAgent(t, ctl)
			registerTestTunnel(t, ctl, msg.ReqTunnel{Protocol: "http", Hostname: host})

			body := strings.Repeat("x", tc.size)
			client, server := tcpPair(t)
			go httpHandler(conn.Wrap(server, "pub"), "http")

			head := "POST /echo HTTP/1.1\r\nHost: " + host + "\r\nContent-Length: " + fmt.Sprint(tc.size) + "\r\n\r\n"
			if _, err := client.Write([]byte(head + body)); err != nil {
				t.Fatalf("failed to write the request: %v", err)
			}

			if got := readStartProxy(t, agent, "the agent"); got.Url != "http://"+host {
				t.Fatalf("StartProxy Url = %q, want http://%s", got.Url, host)
			}
			if got := readHead(t, agent, "the agent"); got != head {
				t.Fatalf("the agent got the head %q, want %q", got, head)
			}

			got := make([]byte, len(body))
			if err := agent.SetReadDeadline(time.Now().Add(publicTimeout)); err != nil {
				t.Fatalf("failed to set a read deadline: %v", err)
			}
			if _, err := io.ReadFull(agent, got); err != nil {
				t.Fatalf("the body did not reach the agent: %v", err)
			}
			if string(got) != body {
				t.Fatalf("the agent got %d body bytes, want %d (first difference at %d)",
					len(got), len(body), firstDifference(got, []byte(body)))
			}

			// the agent's answer still reaches the client over the replayed conn
			upstream := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
			if _, err := agent.Write([]byte(upstream)); err != nil {
				t.Fatalf("failed to write the upstream response: %v", err)
			}
			if err := client.SetReadDeadline(time.Now().Add(publicTimeout)); err != nil {
				t.Fatalf("failed to set a read deadline: %v", err)
			}
			resp, err := http.ReadResponse(bufio.NewReader(client), nil)
			if err != nil {
				t.Fatalf("the client got no response: %v", err)
			}
			defer resp.Body.Close()
			respBody, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("failed to read the response body: %v", err)
			}
			if resp.StatusCode != http.StatusOK || string(respBody) != "ok" {
				t.Fatalf("the client got %d %q, want 200 \"ok\"", resp.StatusCode, respBody)
			}
		})
	}
}

// firstDifference reports where two byte slices first disagree, or -1.
func firstDifference(a, b []byte) int {
	for i := range a {
		if i >= len(b) || a[i] != b[i] {
			return i
		}
	}
	if len(a) != len(b) {
		return len(a)
	}
	return -1
}

// TestPublicRequestStillRoutes is the smoke test for the rewritten public path:
// an ordinary request over a host that has a tunnel is proxied as it always was,
// and one for a host that has none is a 404. Everything else in this file is
// about the edges; this is the middle.
func TestPublicRequestStillRoutes(t *testing.T) {
	const host = "plain.ngrok.test"

	setupTestRegistry(t)
	ctl := testControl(t, "")
	agent := armHTTPAgent(t, ctl)
	registerTestTunnel(t, ctl, msg.ReqTunnel{Protocol: "http", Hostname: host})

	res := startPublicRequest(t, host, "/path?q=1")
	if got := readStartProxy(t, agent, "the agent"); got.Url != "http://"+host || got.ClientAddr == "" {
		t.Fatalf("StartProxy = %+v, want the url and the client's address", got)
	}
	if head := readHead(t, agent, "the agent"); head != requestHead(host, "/path?q=1") {
		t.Fatalf("the agent got %q, want %q", head, requestHead(host, "/path?q=1"))
	}
	if _, err := agent.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nfine")); err != nil {
		t.Fatalf("failed to write the upstream response: %v", err)
	}
	resp, body := waitPublic(t, res)
	if resp.StatusCode != http.StatusOK || body != "fine" {
		t.Fatalf("the client got %d %q, want 200 \"fine\"", resp.StatusCode, body)
	}

	if _, body := publicRequest(t, "nobody.ngrok.test"); !strings.Contains(body, "not found") {
		t.Fatalf("an unknown host answered %q", body)
	}
}
