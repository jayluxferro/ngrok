package server

// Server-side tests for the oidc action's enforcement point (SPEC-CLUSTER18).
// The action's flow logic -- every verdict class, every refusal -- is tested
// in policy/oidc_test.go against its own fake IdP; what this file owns is the
// wiring around it: that the verdict is reached BEFORE a proxy connection is
// pulled (the whole point of the pre-dispatch seam), that a dispatch replays
// the head with the identity in it and the client's own identity fields out,
// that the join's hook still runs the policy's other actions on a dispatched
// connection, that an agent-terminated endpoint cannot register with the
// action at all, and that the session key reaches the policy package from the
// server config.
//
// The fake IdP here is the server-test sibling of policy/oidc_test.go's: test
// helpers do not travel between packages, and these tests are about the flow
// running FOR REAL through the public listener -- three connections and two
// external round trips, driven on loopback TCP -- so it stands its own four
// endpoints up rather than stubbing the verdict.

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"ngrok/conn"
	"ngrok/msg"
	"ngrok/policy"
)

// ---------------------------------------------------------------------------
// fixtures

// oidcFakeIdP is the four endpoints the flow consumes, on one httptest
// server. It is strict where real providers are strict -- a code is
// single-use, the authorization request must carry the PKCE parameters --
// because those are the behaviors the flow under test has to be the one to
// satisfy; everything permissive about it (any signed-in user, fixed
// claims) is what lets the tests stay readable.
type oidcFakeIdP struct {
	srv    *httptest.Server
	mu     sync.Mutex
	issuer string
	key    *rsa.PrivateKey
	kid    string

	authorizeCalls int
	lastAuthorize  url.Values
	usedCodes      map[string]bool
}

func newOIDCFakeIdP(t *testing.T) *oidcFakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating the IdP key: %v", err)
	}
	p := &oidcFakeIdP{key: key, kid: "server-test-key", usedCodes: map[string]bool{}}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", p.serveDiscovery)
	mux.HandleFunc("/authorize", p.serveAuthorize)
	mux.HandleFunc("/token", p.serveToken)
	mux.HandleFunc("/jwks.json", p.serveJWKS)
	p.srv = httptest.NewServer(mux)
	p.issuer = p.srv.URL
	t.Cleanup(p.srv.Close)
	return p
}

func (p *oidcFakeIdP) serveDiscovery(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"issuer":                 p.issuer,
		"authorization_endpoint": p.issuer + "/authorize",
		"token_endpoint":         p.issuer + "/token",
		"jwks_uri":               p.issuer + "/jwks.json",
	})
}

// serveAuthorize is the provider's login for an already signed-in user: the
// code and the state it was given, back to the redirect_uri it was given.
func (p *oidcFakeIdP) serveAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("state") == "" || q.Get("redirect_uri") == "" || q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	p.mu.Lock()
	p.authorizeCalls++
	p.lastAuthorize = q
	p.mu.Unlock()

	dest, err := url.Parse(q.Get("redirect_uri"))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	dq := dest.Query()
	dq.Set("code", "test-code")
	dq.Set("state", q.Get("state"))
	dest.RawQuery = dq.Encode()
	http.Redirect(w, r, dest.String(), http.StatusFound)
}

// serveToken exchanges the code for an RS256 ID token signed with the key
// the JWKS endpoint publishes. The nonce minted into the token is the one
// the authorization request it actually served carried -- that binding is
// what the flow's post-signature nonce check verifies.
func (p *oidcFakeIdP) serveToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	form := r.PostForm
	code := form.Get("code")
	if code == "" || p.usedCodes[code] || form.Get("grant_type") != "authorization_code" ||
		form.Get("client_id") == "" || form.Get("redirect_uri") == "" || form.Get("code_verifier") == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	p.usedCodes[code] = true

	now := time.Now()
	claims := jwt.MapClaims{
		"iss": p.issuer,
		"aud": form.Get("client_id"),
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
		"sub": "user-1",
		// empty when no authorization request was ever served: the flow must
		// catch it, and this fake must not mint a nonce out of thin air
		"nonce":              p.lastAuthorize.Get("nonce"),
		"email":              "user-1@example.com",
		"preferred_username": "User One",
		"hd":                 "example.com",
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = p.kid
	signed, err := tok.SignedString(p.key)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"id_token": signed, "token_type": "Bearer"})
}

// serveJWKS publishes the signing key, in the same shape (and with the same
// omissions) as policy/jwt_test.go's rsaJWK: the key the flow's tests are
// reviewed against is the key these tests verify with.
func (p *oidcFakeIdP) serveJWKS(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"keys": []interface{}{map[string]interface{}{
			"kty": "RSA",
			"kid": p.kid,
			"n":   base64.RawURLEncoding.EncodeToString(p.key.PublicKey.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(p.key.PublicKey.E)).Bytes()),
		}},
	})
}

// oidcAction builds the oidc rule a test's policy carries. Compilation
// touches no network (the discovery fetch waits for the first visitor), so
// the issuer may be the fake IdP's URL or any https URL the test never
// intends to reach.
func oidcAction(issuer string) *policy.Action {
	return policyActionConfig("oidc", map[string]interface{}{
		"issuer":        issuer,
		"client_id":     "test-client",
		"client_secret": "test-secret",
	})
}

// installOIDCTestKey pins a deterministic session key, so the cookies a test
// mints are the ones its assertions expect. The key is process state and the
// policy package exports no unsetter, so it is not restored: every oidc test
// here pins its own key before it drives anything, and no other server test
// reads the key, so nothing can order-depend on the leftover.
func installOIDCTestKey(t *testing.T) {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(0x5a + i)
	}
	if err := policy.SetOIDCSessionKey(key); err != nil {
		t.Fatalf("SetOIDCSessionKey: %v", err)
	}
}

// startPublicHead is startPublicRequest with the request head spelled by the
// caller: the flow's legs carry cookies and forged fields the fixed
// requestHead helper cannot express. Everything else -- a fresh loopback
// connection served by the real httpHandler, a reader goroutine that reports
// through a channel -- is the same.
func startPublicHead(t *testing.T, head string) <-chan publicResult {
	t.Helper()

	client, server := tcpPair(t)
	go httpHandler(conn.Wrap(server, "pub"), "http")

	if _, err := client.Write([]byte(head)); err != nil {
		t.Fatalf("failed to write the request: %v", err)
	}

	res := make(chan publicResult, 1)
	go func() {
		_ = client.SetReadDeadline(time.Now().Add(publicTimeout))
		resp, err := http.ReadResponse(bufio.NewReader(client), nil)
		if err != nil {
			res <- publicResult{err: err}
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		res <- publicResult{resp: resp, body: string(body)}
	}()
	return res
}

// browserClient plays the visitor's browser on the provider hop: it follows
// nothing, because the provider's 302 back to the tunnel hostname is the leg
// the test drives itself, and following it would try to resolve a name no
// DNS answers for.
var browserClient = &http.Client{
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// sessionCookieOf picks the minting response's session cookie out of its
// Set-Cookie headers without spelling the cookie's name (that name is the
// policy package's spelling, and the contract this side consumes is
// "a cookie scoped to the whole endpoint with a live Max-Age"): it is the
// one set at Path=/ with Max-Age > 0. The flow cookie retired beside it --
// same response, Max-Age=0 -- is asserted retired.
func sessionCookieOf(t *testing.T, resp *http.Response) *http.Cookie {
	t.Helper()

	var session *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Path == "/" && c.MaxAge > 0 {
			if session != nil {
				t.Fatalf("two live cookies at Path=/: %+v and %+v", session, c)
			}
			session = c
			continue
		}
		// The retired flow cookie: Max-Age=0, which net/http parses as -1.
		if c.MaxAge <= 0 {
			continue
		}
		t.Fatalf("unexpected cookie %+v on the minting response", c)
	}
	if session == nil {
		t.Fatalf("the minting response set no session cookie: %v", resp.Header["Set-Cookie"])
	}
	return session
}

// countField counts a head's fields carrying the given name, whatever the
// value -- hasField's complement, for the assertion that the injected
// identity appears exactly once.
func countField(head, name string) int {
	n := 0
	for _, line := range strings.Split(head, "\r\n") {
		f, _, ok := strings.Cut(line, ":")
		if ok && strings.EqualFold(strings.TrimSpace(f), name) {
			n++
		}
	}
	return n
}

// ---------------------------------------------------------------------------
// the enforcement point

// TestOIDCFirstRequestRedirectSpendsNoProxyConnection is the ordering the
// pre-dispatch seam exists for (review gate 3): a cookieless visit is
// answered with the flow's 302 at the edge, and the proxy connection armed
// for the endpoint is still sitting in the pool -- not pulled, not written
// to. Both halves are asserted: the channel still holds the connection (the
// pool counter), and the connection carries no bytes -- no StartProxy (that
// message is written before a policy could run, which is exactly the burn
// the hook layer cannot avoid), no head.
func TestOIDCFirstRequestRedirectSpendsNoProxyConnection(t *testing.T) {
	const host = "guarded.ngrok.test"

	installOIDCTestKey(t)
	idp := newOIDCFakeIdP(t)
	setupTestRegistry(t)
	ctl := testControl(t, "")
	agent := armHTTPAgent(t, ctl)
	registerTestTunnel(t, ctl, msg.ReqTunnel{
		Protocol: "http",
		Hostname: host,
		TrafficPolicy: &policy.TrafficPolicy{OnHTTPRequest: []*policy.Action{
			oidcAction(idp.issuer),
		}},
	})

	res := startPublicRequest(t, host, "/private")
	resp, _ := waitPublic(t, res)

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("a cookieless visit got %d, want the flow's 302", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, idp.issuer+"/authorize?") {
		t.Fatalf("the 302 goes to %q, want the fake IdP's authorization endpoint", loc)
	}
	flow := resp.Cookies()
	if len(flow) != 1 || flow[0].Value == "" || flow[0].Path != "/oauth2/callback" {
		t.Fatalf("the flow-begin response set %+v, want one flow cookie scoped to the callback path", flow)
	}

	// The pool was never drawn from...
	if got := len(ctl.proxies); got != 1 {
		t.Fatalf("the proxy pool holds %d connection(s) after a refused visit, want the armed one untouched", got)
	}
	// ...and the agent's end of it never heard about this visit at all.
	expectNoBytes(t, agent, "the agent")
}

// TestOIDCFlowDispatchesWithIdentityHeaders drives the whole three-connection
// loop through the public listener: 302 out, callback back, session minted,
// and the fourth connection -- the one the flow was for -- dispatched with
// the identity injected into the head. On that dispatched connection it also
// asserts the two things the pre-dispatch seam must not disturb: a
// client-supplied identity field does not survive next to the injected one,
// and the policy's other request-phase action still runs in the join's hook.
func TestOIDCFlowDispatchesWithIdentityHeaders(t *testing.T) {
	const host = "guarded.ngrok.test"

	installOIDCTestKey(t)
	idp := newOIDCFakeIdP(t)
	setupTestRegistry(t)
	ctl := testControl(t, "")
	agent := armHTTPAgent(t, ctl)
	registerTestTunnel(t, ctl, msg.ReqTunnel{
		Protocol: "http",
		Hostname: host,
		TrafficPolicy: &policy.TrafficPolicy{OnHTTPRequest: []*policy.Action{
			oidcAction(idp.issuer),
			// A second request-phase action on the same policy: consumed
			// pre-dispatch is the oidc action ONLY, so this one must appear
			// on the dispatched connection's head, added by the hook.
			policyActionConfig("add-headers", map[string]interface{}{
				"headers": map[string]interface{}{"X-Added": "yes"},
			}),
		}},
	})

	// leg 1: no cookie -> 302 to the provider, one flow cookie bound to
	// where the visitor was headed
	res := startPublicRequest(t, host, "/private?a=b")
	resp, _ := waitPublic(t, res)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("leg 1 answered %d, want 302", resp.StatusCode)
	}
	flow := resp.Cookies()
	if len(flow) != 1 {
		t.Fatalf("leg 1 set %+v, want one flow cookie", flow)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("the authorization URL did not parse: %v", err)
	}

	// leg 2: the browser hop. The provider's answer carries the code and the
	// state the flow sent out.
	authResp, err := browserClient.Get(loc.String())
	if err != nil {
		t.Fatalf("the authorization request failed: %v", err)
	}
	authResp.Body.Close()
	if authResp.StatusCode != http.StatusFound {
		t.Fatalf("the provider answered %d, want the 302 back to the callback", authResp.StatusCode)
	}
	callback, err := url.Parse(authResp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("the provider's redirect did not parse: %v", err)
	}
	if callback.Host != host || !strings.HasPrefix(callback.Path, "/oauth2/callback") {
		t.Fatalf("the provider sent the visitor to %s, want the callback on %s", callback, host)
	}

	// leg 3: the callback, flow cookie in hand -> the minting 302 back to
	// the bound original URL, session cookie set, flow cookie retired
	cbHead := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nCookie: %s=%s\r\n\r\n",
		callback.RequestURI(), host, flow[0].Name, flow[0].Value)
	res = startPublicHead(t, cbHead)
	resp, _ = waitPublic(t, res)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("the callback answered %d, want the minting 302", resp.StatusCode)
	}
	if got := resp.Header.Get("Location"); got != "http://"+host+"/private?a=b" {
		t.Fatalf("the minting 302 goes to %q, want the bound original URL", got)
	}
	session := sessionCookieOf(t, resp)

	// leg 4: the session admits. The visitor also forges both identity
	// fields -- the classic claim of an identity the token never vouched
	// for -- and the dispatched head must carry the verified identity, once,
	// and none of the forged one.
	visitHead := "GET /private HTTP/1.1\r\nHost: " + host + "\r\n" +
		"Cookie: " + session.Name + "=" + session.Value + "\r\n" +
		"X-Forwarded-User: admin\r\n" +
		"X-Forwarded-Email: admin@evil.test\r\n\r\n"
	res = startPublicHead(t, visitHead)

	// The dispatch pulls the armed proxy connection -- the proof that this
	// leg went through, spelled in bytes rather than counters.
	readStartProxy(t, agent, "the agent")
	agentHead := readHead(t, agent, "the agent")
	if !strings.HasPrefix(agentHead, "GET /private HTTP/1.1\r\n") {
		t.Fatalf("the agent got %q, want the visitor's request line first", agentHead)
	}
	for _, want := range [][2]string{
		{"X-Forwarded-User", "user-1"},
		{"X-Forwarded-Email", "user-1@example.com"},
		{"X-Forwarded-Preferred-Username", "User One"},
	} {
		if !hasField(agentHead, want[0], want[1]) {
			t.Fatalf("the agent's head %q does not carry %s: %s", agentHead, want[0], want[1])
		}
		if n := countField(agentHead, want[0]); n != 1 {
			t.Fatalf("the agent's head carries %s %d time(s), want exactly the injected one", want[0], n)
		}
	}
	if strings.Contains(agentHead, "admin@evil.test") {
		t.Fatalf("the forged identity reached the agent: %q", agentHead)
	}
	if !hasField(agentHead, "X-Added", "yes") {
		t.Fatalf("the join's hook did not run the policy's other action: %q", agentHead)
	}

	if _, err := agent.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")); err != nil {
		t.Fatalf("failed to write the upstream response: %v", err)
	}
	resp, body := waitPublic(t, res)
	if resp.StatusCode != http.StatusOK || body != "ok" {
		t.Fatalf("the visitor got %d %q, want 200 \"ok\"", resp.StatusCode, body)
	}
}

// TestOIDCPipelinedSecondRequestRidesTheFirstDecision pins the decision
// granularity in bytes: the FIRST request on a connection decides, and a
// request pipelined behind it reaches the agent as-is -- even when it
// carries no session cookie of its own, which is exactly the shape a
// re-run of the hook would answer with a 302 and a closed connection.
// Nothing about the wiring makes a re-run possible (routeHTTP parses the
// one head a connection leads with and then hands the stream to the join),
// and this test is what notices if that ever stops being true.
func TestOIDCPipelinedSecondRequestRidesTheFirstDecision(t *testing.T) {
	const host = "guarded.ngrok.test"

	installOIDCTestKey(t)
	idp := newOIDCFakeIdP(t)
	setupTestRegistry(t)
	ctl := testControl(t, "")
	agent := armHTTPAgent(t, ctl)
	registerTestTunnel(t, ctl, msg.ReqTunnel{
		Protocol: "http",
		Hostname: host,
		TrafficPolicy: &policy.TrafficPolicy{OnHTTPRequest: []*policy.Action{
			oidcAction(idp.issuer),
		}},
	})

	// Mint a session through the flow (condensed from the full test above:
	// leg 1, the provider hop, leg 3 -- the assertions on each leg live
	// there).
	res := startPublicRequest(t, host, "/private")
	resp, _ := waitPublic(t, res)
	flow := resp.Cookies()
	if resp.StatusCode != http.StatusFound || len(flow) != 1 {
		t.Fatalf("leg 1 answered %d with %+v, want the flow's 302 and one cookie", resp.StatusCode, flow)
	}
	authResp, err := browserClient.Get(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("the authorization request failed: %v", err)
	}
	authResp.Body.Close()
	callback, err := url.Parse(authResp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("the provider's redirect did not parse: %v", err)
	}
	cbHead := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nCookie: %s=%s\r\n\r\n",
		callback.RequestURI(), host, flow[0].Name, flow[0].Value)
	res = startPublicHead(t, cbHead)
	resp, _ = waitPublic(t, res)
	session := sessionCookieOf(t, resp)

	// The pipelined pair on ONE connection: the session-carrying head, then
	// a bare one -- no cookie, the shape the hook would refuse if it ever
	// saw it. Written in a single write, which is what pipelining is.
	pipelined := "GET /private HTTP/1.1\r\nHost: " + host + "\r\n" +
		"Cookie: " + session.Name + "=" + session.Value + "\r\n\r\n" +
		"GET /second HTTP/1.1\r\nHost: " + host + "\r\n\r\n"
	client, server := tcpPair(t)
	go httpHandler(conn.Wrap(server, "pub"), "http")
	if _, err := client.Write([]byte(pipelined)); err != nil {
		t.Fatalf("failed to write the pipelined requests: %v", err)
	}

	readStartProxy(t, agent, "the agent")
	first := readHead(t, agent, "the agent")
	if !strings.HasPrefix(first, "GET /private HTTP/1.1\r\n") || !strings.Contains(first, session.Value) {
		t.Fatalf("the agent's first head %q is not the session-carrying request", first)
	}
	second := readHead(t, agent, "the agent")
	if second != "GET /second HTTP/1.1\r\nHost: "+host+"\r\n\r\n" {
		t.Fatalf("the pipelined second head reached the agent as %q, want it verbatim and unrefused", second)
	}

	// Both requests are answered by the one upstream: the connection was
	// dispatched once and then joined, not re-decided per request.
	if _, err := agent.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok" +
		"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ntwo!")); err != nil {
		t.Fatalf("failed to write the upstream responses: %v", err)
	}
	_ = client.SetReadDeadline(time.Now().Add(publicTimeout))
	reader := bufio.NewReader(client)
	for _, want := range []string{"ok", "two!"} {
		resp, err := http.ReadResponse(reader, nil)
		if err != nil {
			t.Fatalf("no response for %q: %v", want, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || string(body) != want {
			t.Fatalf("the visitor got %d %q, want 200 %q", resp.StatusCode, body, want)
		}
	}
}

// ---------------------------------------------------------------------------
// registration refusal

// TestNewTunnelRefusesOIDCOnAnAgentTerminatedEndpoint is SPEC-CLUSTER18's
// refusal: the action needs Host, Cookie and plaintext redirects, and a
// zero-knowledge endpoint offers the server none of them. The registration
// fails before the url is claimed, and the message names both facts -- the
// action and the termination mode -- because the operator's fix is dropping
// one specific setting. The same policy on an edge-terminated endpoint
// registers, which is what pins the refusal to the combination and not to
// the action.
func TestNewTunnelRefusesOIDCOnAnAgentTerminatedEndpoint(t *testing.T) {
	const host = "guarded.ngrok.test"

	t.Run("agent termination is refused", func(t *testing.T) {
		setupTestRegistry(t)
		ctl := testControl(t, "")

		req := msg.ReqTunnel{
			Protocol:       "https",
			Hostname:       host,
			TLSTermination: msg.TLSTerminationAgent,
			TrafficPolicy: &policy.TrafficPolicy{OnHTTPRequest: []*policy.Action{
				oidcAction("https://idp.example.test"),
			}},
		}
		tun, err := NewTunnel(&req, ctl)
		if err == nil {
			tun.Shutdown()
			t.Fatal("an oidc policy on an agent-terminated endpoint must fail the registration")
		}
		for _, want := range []string{"oidc", "agent-terminated", msg.TLSTerminationAgent} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("the error %q does not name %q", err, want)
			}
		}
		if tunnelRegistry.Get("https://"+host) != nil {
			t.Fatal("the refused registration claimed the url anyway")
		}

		// The url is still available to a tunnel that can be enforced.
		got := registerTestTunnel(t, ctl, msg.ReqTunnel{Protocol: "https", Hostname: host})
		if got.url != "https://"+host {
			t.Fatalf("the url after the refused registration is %q, want https://%s", got.url, host)
		}
	})

	t.Run("edge termination registers", func(t *testing.T) {
		setupTestRegistry(t)
		ctl := testControl(t, "")

		tun := registerTestTunnel(t, ctl, msg.ReqTunnel{
			Protocol: "https",
			Hostname: host,
			TrafficPolicy: &policy.TrafficPolicy{OnHTTPRequest: []*policy.Action{
				oidcAction("https://idp.example.test"),
			}},
		})
		if tun.policy == nil || tun.policy.OIDC() == nil {
			t.Fatal("the registered tunnel carries no compiled oidc action")
		}
	})
}

// ---------------------------------------------------------------------------
// the session key

// TestInstallOIDCSessionKey is the startup wiring: unset is a no-op (the
// policy package then generates a key at first use and says so itself), a
// short key fails the boot naming the minimum, and a valid key installs.
// The empty case asserts on the *change* in configured state, not on the
// state, so the test stays order-independent wherever the other tests left
// the process key.
func TestInstallOIDCSessionKey(t *testing.T) {
	before := policy.OIDCSessionKeyConfigured()

	if err := installOIDCSessionKey(""); err != nil {
		t.Fatalf("an unset key must install nothing and never error: %v", err)
	}
	if policy.OIDCSessionKeyConfigured() != before {
		t.Fatal("installing the empty key changed the session-key state")
	}

	err := installOIDCSessionKey("too-short")
	if err == nil || !strings.Contains(err.Error(), "32") {
		t.Fatalf("a short key must fail the startup naming the minimum, got %v", err)
	}

	if err := installOIDCSessionKey(strings.Repeat("k", 32)); err != nil {
		t.Fatalf("a 32-byte key must install: %v", err)
	}
	if !policy.OIDCSessionKeyConfigured() {
		t.Fatal("SetOIDCSessionKey accepted the key but nothing reports it configured")
	}
}

// TestOIDCSessionKeyConfigPlumbing is the config-file half: the key parses
// into the options beside the other secret-ish fields, its absence is an
// empty value (the generated-key default), and a misspelled key is refused
// by the strict decode rather than silently dropped -- a dropped signing
// key is an endpoint that rotates every visitor's session on restart while
// the operator believes they configured stability.
func TestOIDCSessionKeyConfigPlumbing(t *testing.T) {
	const key = "0123456789abcdef0123456789abcdef" // the 32-byte floor, as an operator would paste it

	opts := parseServerArgs(t, []string{"ngrokd", "-config", writeServerConfig(t, "oidc_session_key: "+key+"\n")})
	if opts.oidcSessionKey != key {
		t.Errorf("oidcSessionKey: config file value ignored, got %q", opts.oidcSessionKey)
	}

	opts = parseServerArgs(t, []string{"ngrokd", "-config", writeServerConfig(t, "https_addr: :4443\n")})
	if opts.oidcSessionKey != "" {
		t.Errorf("oidcSessionKey: an absent key must leave the option empty, got %q", opts.oidcSessionKey)
	}

	// Directly against the loader: parseArgs exits the process on a bad
	// config (there is nothing to serve without one), and a unit test has no
	// business exercising os.Exit.
	_, err := loadServerConfig(writeServerConfig(t, "oidc_sessoin_key: "+key+"\n"))
	if err == nil || !strings.Contains(err.Error(), "oidc_sessoin_key") {
		t.Errorf("a misspelled oidc_session_key must fail the strict decode, got %v", err)
	}
}
