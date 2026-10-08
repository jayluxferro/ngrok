package policy

// Tests for the oidc action (SPEC-CLUSTER18): the whole flow against a fake
// IdP this file stands up (discovery, JWKS, authorization, token), and every
// failure class the spec lists, each asserted to answer its one fixed
// synthetic -- with the failure responses' fixedness checked by equality, so
// nothing request- or token-derived could be hiding in one.
//
// The fake IdP is deliberately strict where real providers are: a code is
// single-use (a replayed callback fails the token exchange with a non-200,
// the way a real provider refuses a second redemption), and the token
// endpoint echoes only the claims the tests configure. The permissive
// behaviors are the ones the flow under test must be the one to catch.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"ngrok/log"
)

var _ log.Logger = (*oidcTestLogger)(nil)

// --- the fake IdP ------------------------------------------------------------

// fakeIdP is the four-endpoint provider metadata document the flow consumes,
// served from one httptest server. Its fields are the test's controls: a
// status override poisons an endpoint, an override nonce breaks the nonce
// binding, and the captured token-exchange form is how a test proves the
// PKCE verifier that arrived is the one this flow published the challenge for.
type fakeIdP struct {
	srv    *httptest.Server
	mu     sync.Mutex
	issuer string
	doc    oidcDiscovery

	key *rsa.PrivateKey
	kid string

	sub   string
	email string
	pref  string
	hd    string
	// tokenNonce overrides the nonce minted into the ID token; empty means
	// echo the nonce the flow began with.
	tokenNonce string

	discoveryStatus int
	tokenStatus     int

	discoveryFetches int
	authorizeCalls   int
	tokenCalls       int

	// lastAuthorizeQuery is the query of the most recent authorization
	// request; lastTokenForm is the most recent token exchange's POST form.
	lastAuthorizeQuery url.Values
	lastTokenForm      url.Values

	// usedCodes makes codes single-use, the way real providers do: the
	// replay test needs the token endpoint to refuse the second redemption.
	usedCodes map[string]bool
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating the IdP key: %v", err)
	}
	p := &fakeIdP{
		key:       key,
		kid:       "oidc-test-key",
		sub:       "user-1",
		email:     "user-1@example.com",
		pref:      "User One",
		hd:        "example.com",
		usedCodes: map[string]bool{},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", p.serveDiscovery)
	mux.HandleFunc("/authorize", p.serveAuthorize)
	mux.HandleFunc("/token", p.serveToken)
	mux.HandleFunc("/jwks.json", p.serveJWKS)
	p.srv = httptest.NewServer(mux)
	p.issuer = p.srv.URL
	p.doc = p.metadata()
	t.Cleanup(p.close)
	return p
}

// close takes the server down. It is idempotent so a test can close it early
// (the transport-failure test does exactly that) without racing the cleanup.
func (p *fakeIdP) close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.srv != nil {
		p.srv.Close()
		p.srv = nil
	}
}

func (p *fakeIdP) metadata() oidcDiscovery {
	return oidcDiscovery{
		Issuer:                p.issuer,
		AuthorizationEndpoint: p.issuer + "/authorize",
		TokenEndpoint:         p.issuer + "/token",
		JWKSURI:               p.issuer + "/jwks.json",
	}
}

func (p *fakeIdP) serveDiscovery(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	p.discoveryFetches++
	status := p.discoveryStatus
	body, _ := json.Marshal(p.doc)
	p.mu.Unlock()
	if status != 0 {
		w.WriteHeader(status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(body)
}

// serveAuthorize is the provider's login: it answers any authorization
// request with the code and the state it was given, the behavior of a
// provider whose user is already signed in. The callback's job is to notice
// when the state that came back is not the one that went out.
func (p *fakeIdP) serveAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("state") == "" || q.Get("redirect_uri") == "" || q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	p.mu.Lock()
	p.authorizeCalls++
	p.lastAuthorizeQuery = q
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

// serveToken exchanges the code. It is strict about replays (a code is
// single-use) and about the shape of the request; the ID token it mints is
// signed with the key its JWKS publishes.
func (p *fakeIdP) serveToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.tokenCalls++
	p.lastTokenForm = r.PostForm

	if p.tokenStatus != 0 {
		w.WriteHeader(p.tokenStatus)
		return
	}
	code := r.PostForm.Get("code")
	if code == "" || p.usedCodes[code] {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	p.usedCodes[code] = true
	if r.PostForm.Get("grant_type") != "authorization_code" ||
		r.PostForm.Get("client_id") == "" ||
		r.PostForm.Get("redirect_uri") == "" ||
		r.PostForm.Get("code_verifier") == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	nonce := p.tokenNonce
	if nonce == "" {
		nonce = p.lastAuthorizeQuery.Get("nonce")
	}
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":   p.issuer,
		"aud":   r.PostForm.Get("client_id"),
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
		"sub":   p.sub,
		"nonce": nonce,
	}
	if p.email != "" {
		claims["email"] = p.email
	}
	if p.pref != "" {
		claims["preferred_username"] = p.pref
	}
	if p.hd != "" {
		claims["hd"] = p.hd
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

func (p *fakeIdP) serveJWKS(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"keys": []interface{}{rsaJWK(&p.key.PublicKey, p.kid)},
	})
}

// --- drivers and assertions ----------------------------------------------------

// oidcTestLogger is oidc_test.go's own log.Logger. testLogger's line capture
// exists for the hook tests; this file needs "did any logged line carry the
// marker bytes" and wants the raw slices to answer it, not a second opinion
// on formatting.
type oidcTestLogger struct {
	mu   sync.Mutex
	info []string
	warn []string
}

func (l *oidcTestLogger) AddLogPrefix(string)          {}
func (l *oidcTestLogger) ClearLogPrefixes()            {}
func (l *oidcTestLogger) Debug(string, ...interface{}) {}
func (l *oidcTestLogger) Info(format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.info = append(l.info, fmt.Sprintf(format, args...))
}
func (l *oidcTestLogger) Warn(format string, args ...interface{}) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.warn = append(l.warn, fmt.Sprintf(format, args...))
	return nil
}
func (l *oidcTestLogger) Error(format string, args ...interface{}) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.warn = append(l.warn, fmt.Sprintf(format, args...))
	return nil
}

// all returns every line, the material the leak assertions run over.
func (l *oidcTestLogger) all() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(append(append([]string{}, l.info...), l.warn...), "\n")
}

// compileOIDC builds one oidc action against a fresh fake IdP. Compilation
// touches no network, so the IdP is idle until the first decision.
func compileOIDC(t *testing.T, overrides map[string]interface{}) (*OIDCSettings, *fakeIdP) {
	t.Helper()
	p := newFakeIdP(t)
	cfg := map[string]interface{}{
		"issuer":        p.issuer,
		"client_id":     "test-client",
		"client_secret": "test-secret",
	}
	for k, v := range overrides {
		cfg[k] = v
	}
	s, err := buildOIDC("on_http_request[0] (oidc)", cfg)
	if err != nil {
		t.Fatalf("buildOIDC: %v", err)
	}
	return s, p
}

// installSessionKey pins a deterministic session key for the test and
// restores whatever was there before (the SetVaults pattern: the key is
// process state, and the tests must not order-depend on each other).
func installSessionKey(t *testing.T) {
	t.Helper()
	prev := oidcKey.Load()
	prevInstalled := oidcKeyInstalled.Load()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(0xa0 + i)
	}
	if err := SetOIDCSessionKey(key); err != nil {
		t.Fatalf("SetOIDCSessionKey: %v", err)
	}
	t.Cleanup(func() {
		oidcKey.Store(prev)
		oidcKeyInstalled.Store(prevInstalled)
	})
}

// decideOnce runs one decision with a fresh logger and returns the verdict
// and that logger.
func decideOnce(s *OIDCSettings, r OIDCRequest) (OIDCVerdict, *oidcTestLogger) {
	lg := &oidcTestLogger{}
	return s.DecideHook(lg)(r), lg
}

func locationOf(t *testing.T, v *OIDCVerdict) string {
	t.Helper()
	if v.Response == nil {
		t.Fatalf("verdict %v carries no response; no Location to find", v.Kind)
	}
	for _, h := range v.Response.Headers {
		if strings.HasPrefix(h, "Location: ") {
			return strings.TrimPrefix(h, "Location: ")
		}
	}
	t.Fatalf("no Location header in the response: %v", v.Response.Headers)
	return ""
}

// cookieOf extracts one cookie's value out of a verdict's Set-Cookie headers.
func cookieOf(t *testing.T, v *OIDCVerdict, name string) string {
	t.Helper()
	prefix := "Set-Cookie: " + name + "="
	for _, h := range v.Response.Headers {
		if strings.HasPrefix(h, prefix) {
			return strings.Split(strings.TrimPrefix(h, prefix), ";")[0]
		}
	}
	t.Fatalf("no Set-Cookie for %s in the response: %v", name, v.Response.Headers)
	return ""
}

func hasCookieHeader(v *OIDCVerdict, name string) bool {
	for _, h := range v.Response.Headers {
		if strings.HasPrefix(h, "Set-Cookie: "+name+"=") {
			return true
		}
	}
	return false
}

func headerValue(t *testing.T, v *OIDCVerdict, name string) (string, bool) {
	t.Helper()
	for _, h := range v.Response.Headers {
		if strings.HasPrefix(h, name+": ") {
			return strings.TrimPrefix(h, name+": "), true
		}
	}
	return "", false
}

// beginFlow drives the first leg: a cookieless visitor must be sent to the
// provider with one flow cookie bound to this endpoint.
func beginFlow(t *testing.T, s *OIDCSettings) (authURL *url.URL, flowCookieValue string) {
	t.Helper()
	v, lg := decideOnce(s, OIDCRequest{Method: "GET", Path: "/private", Query: "", Cookie: "", Scheme: "https", Host: "app.example"})
	if v.Kind != OIDCRedirect {
		t.Fatalf("the first visit produced %v, want a redirect to the provider (log: %s)", v.Kind, lg.all())
	}
	if v.Response.StatusCode != http.StatusFound {
		t.Fatalf("the flow-begin response is %d, want 302", v.Response.StatusCode)
	}
	if v.Response.Body != oidcBeginBody {
		t.Fatalf("the flow-begin body is not the fixed one: %q", v.Response.Body)
	}
	if cc, ok := headerValue(t, &v, "Cache-Control"); !ok || cc != "no-store" {
		t.Fatalf("the flow-begin response lacks Cache-Control: no-store (%v)", v.Response.Headers)
	}
	loc, err := url.Parse(locationOf(t, &v))
	if err != nil {
		t.Fatalf("the Location did not parse: %v", err)
	}
	// The browser leg, played for real: the visitor's browser is what carries
	// the authorization request to the provider, and the nonce the provider
	// mints into the ID token is the nonce of the request it actually served.
	// Skipping this GET would leave the fake to mint a token from an
	// authorization request it never saw -- an empty nonce, refused by the
	// flow's own check -- and every mint-path assertion below would be
	// testing the mock, not the flow. The bounded client refuses to follow
	// the 302 back to app.example (nothing is listening there), which is
	// exactly what the test wants: the redirect is the browser's next hop,
	// and the drivers below build that request themselves.
	resp, err := oidcHTTPClient.Get(loc.String())
	if err != nil {
		t.Fatalf("the authorization request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("the authorization endpoint answered %d, want the 302 back to the callback", resp.StatusCode)
	}
	return loc, cookieOf(t, &v, oidcFlowCookieName)
}

// finishFlow drives the callback: the provider's redirect, verbatim, plus the
// flow cookie.
func finishFlow(t *testing.T, s *OIDCSettings, authURL *url.URL, flowCookieValue string) OIDCVerdict {
	t.Helper()
	q := authURL.Query()
	v, lg := decideOnce(s, OIDCRequest{
		Method: "GET",
		Path:   "/oauth2/callback",
		Query:  url.Values{"code": {"test-code"}, "state": {q.Get("state")}}.Encode(),
		Cookie: oidcFlowCookieName + "=" + flowCookieValue,
		Scheme: "https",
		Host:   "app.example",
	})
	if lg := lg.all(); strings.Contains(lg, "test-secret") {
		t.Fatalf("the client secret reached a log line: %s", lg)
	}
	return v
}

// fullSession runs begin through mint and hands back the session cookie.
func fullSession(t *testing.T, s *OIDCSettings) (sessionCookieValue string) {
	t.Helper()
	authURL, flow := beginFlow(t, s)
	v, lg := finishFlowLogged(t, s, authURL, flow)
	if v.Kind != OIDCRedirect {
		t.Fatalf("the callback produced %v, want the minting redirect (resp: %+v, log: %s)", v.Kind, v.Response, lg.all())
	}
	if v.Response.StatusCode != http.StatusFound {
		t.Fatalf("the minting response is %d, want 302", v.Response.StatusCode)
	}
	return cookieOf(t, &v, oidcSessionCookieName)
}

// refuseCheck asserts the fixed 403: right kind, the compile-time response
// itself, and no marker bytes anywhere in a log line. The equality on the
// body is the strongest form of the leak assertion -- a body that equals a
// constant cannot carry anything else.
func refuseCheck(t *testing.T, s *OIDCSettings, v OIDCVerdict, lg *oidcTestLogger, markers ...string) {
	t.Helper()
	if v.Kind != OIDCForbidden {
		t.Fatalf("the failure produced %v, want the fixed 403 (resp: %+v, log: %s)", v.Kind, v.Response, lg.all())
	}
	if v.Response != s.refused {
		t.Fatalf("the 403 is not the compile-time response: %+v", v.Response)
	}
	if v.Response.Body != oidcRefusedBody {
		t.Fatalf("the 403 body is not the fixed one: %q", v.Response.Body)
	}
	logged := lg.all()
	for _, m := range markers {
		if m != "" && strings.Contains(logged, m) {
			t.Fatalf("request-derived material %q reached a log line:\n%s", m, logged)
		}
	}
}

// --- the happy path ------------------------------------------------------------

func TestOIDCHappyPathEndToEnd(t *testing.T) {
	installSessionKey(t)
	s, p := compileOIDC(t, nil)
	base := time.Now()
	s.now = func() time.Time { return base }

	// leg 1: no cookie -> 302 to the provider's authorization endpoint
	authURL, flow := beginFlow(t, s)
	if authURL.Scheme != "http" || authURL.Path != "/authorize" {
		t.Fatalf("the authorization endpoint is %s, want the fake IdP's /authorize", authURL)
	}
	q := authURL.Query()
	if got := q.Get("client_id"); got != "test-client" {
		t.Fatalf("client_id = %q", got)
	}
	if got := q.Get("redirect_uri"); got != "https://app.example/oauth2/callback" {
		t.Fatalf("redirect_uri = %q", got)
	}
	if got := q.Get("scope"); got != "openid email" {
		t.Fatalf("scope = %q, want the default \"openid email\"", got)
	}
	if got := q.Get("code_challenge_method"); got != "S256" {
		t.Fatalf("code_challenge_method = %q", got)
	}
	// the flow cookie is bound to this host and carries the same state
	fc := flowCookie{}
	if !verifyCookie(flow, &fc) {
		t.Fatalf("the flow cookie did not verify under the session key")
	}
	if fc.Host != "app.example" || fc.State != q.Get("state") || fc.Nonce != q.Get("nonce") {
		t.Fatalf("the flow cookie does not bind what the authorization request announces: %+v vs %v", fc, q)
	}
	if fc.URL != "https://app.example/private" {
		t.Fatalf("the flow cookie lost the original URL: %+v", fc)
	}

	// leg 2: the provider's redirect -> token exchange -> minting 302 back
	v, cbLog := finishFlowLogged(t, s, authURL, flow)
	if v.Kind != OIDCRedirect || v.Response.StatusCode != http.StatusFound {
		t.Fatalf("the callback produced %v (%+v), want the minting 302 (log: %s)", v.Kind, v.Response, cbLog.all())
	}
	if loc := locationOf(t, &v); loc != "https://app.example/private" {
		t.Fatalf("the minting 302 goes to %q, want the bound original URL", loc)
	}
	session := cookieOf(t, &v, oidcSessionCookieName)
	sess := sessionCookie{}
	if !verifyCookie(session, &sess) {
		t.Fatalf("the session cookie did not verify under the session key")
	}
	if sess.Sub != "user-1" || sess.Name != "user-1@example.com" || sess.Pref != "User One" {
		t.Fatalf("the session cookie carries the wrong identity: %+v", sess)
	}
	// the session's TTL is the configured one; the flow cookie is retired
	if want := base.Add(s.sessionTTL).Unix(); sess.Exp != want {
		t.Fatalf("session exp = %d, want %d", sess.Exp, want)
	}
	for _, h := range v.Response.Headers {
		if strings.HasPrefix(h, "Set-Cookie: "+oidcFlowCookieName+"=") && !strings.Contains(h, "Max-Age=0") {
			t.Fatalf("the flow cookie was not retired, it was re-set: %q", h)
		}
	}

	// the exchange carried this flow's verifier: the challenge the
	// authorization request published is the hash of the verifier the token
	// exchange presented -- the PKCE binding, end to end
	form := p.lastTokenForm
	verifier := form.Get("code_verifier")
	if verifier == "" {
		t.Fatalf("the token exchange carried no code_verifier")
	}
	sum := sha256.Sum256([]byte(verifier))
	if got, want := base64.RawURLEncoding.EncodeToString(sum[:]), q.Get("code_challenge"); got != want {
		t.Fatalf("the verifier does not hash to the published challenge: %q vs %q", got, want)
	}
	if got := form.Get("client_secret"); got != "test-secret" {
		t.Fatalf("the token exchange carried the wrong client secret")
	}
	if got := form.Get("redirect_uri"); got != "https://app.example/oauth2/callback" {
		t.Fatalf("the exchange's redirect_uri = %q, want the same one the flow began with", got)
	}

	// leg 3: the session admits -- with the identity in headers
	dv, lg := decideOnce(s, OIDCRequest{Method: "GET", Path: "/private", Scheme: "https", Host: "app.example", Cookie: oidcSessionCookieName + "=" + session})
	if dv.Kind != OIDCDispatch {
		t.Fatalf("a valid session produced %v, want dispatch (log: %s)", dv.Kind, lg.all())
	}
	want := []string{
		"X-Forwarded-User: user-1",
		"X-Forwarded-Email: user-1@example.com",
		"X-Forwarded-Preferred-Username: User One",
	}
	if len(dv.Headers) != len(want) {
		t.Fatalf("identity headers = %v, want %v", dv.Headers, want)
	}
	for i := range want {
		if dv.Headers[i] != want[i] {
			t.Fatalf("identity header %d = %q, want %q", i, dv.Headers[i], want[i])
		}
	}
}

// Two flows begun back to back must not share a state, a nonce or a verifier:
// the state and nonce are the replay guards, and a shared verifier would make
// one flow's proof valid for another's code.
func TestOIDCFlowVerifiersAreUniquePerFlow(t *testing.T) {
	installSessionKey(t)
	s, _ := compileOIDC(t, nil)

	_, flow1 := beginFlow(t, s)
	_, flow2 := beginFlow(t, s)
	f1, f2 := flowCookie{}, flowCookie{}
	if !verifyCookie(flow1, &f1) || !verifyCookie(flow2, &f2) {
		t.Fatalf("the flow cookies did not verify")
	}
	if f1.Verifier == f2.Verifier || f1.State == f2.State || f1.Nonce == f2.Nonce {
		t.Fatalf("two flows shared secrets: %+v / %+v", f1, f2)
	}
}

// --- failure classes: the flow's own checks -------------------------------------

func TestOIDCStateTamperIsRefused(t *testing.T) {
	installSessionKey(t)
	s, _ := compileOIDC(t, nil)
	_, flow := beginFlow(t, s)

	// the attacker controls the query's copy of the state; the forged value
	// is also a leak marker, so the refusal's fixedness is checked with it
	v, lg := decideOnce(s, OIDCRequest{
		Method: "GET",
		Path:   "/oauth2/callback",
		Query:  url.Values{"code": {"test-code"}, "state": {"forged-state-marker"}}.Encode(),
		Cookie: oidcFlowCookieName + "=" + flow,
		Scheme: "https",
		Host:   "app.example",
	})
	refuseCheck(t, s, v, lg, "forged-state-marker")
}

func TestOIDCCrossHostCallbackIsRefused(t *testing.T) {
	installSessionKey(t)
	s, _ := compileOIDC(t, nil)
	authURL, flow := beginFlow(t, s)
	q := authURL.Query()

	// the flow was begun on app.example; redeeming it on other.example is
	// exactly the cross-host redemption the host binding exists for
	v, lg := decideOnce(s, OIDCRequest{
		Method: "GET",
		Path:   "/oauth2/callback",
		Query:  url.Values{"code": {"test-code"}, "state": {q.Get("state")}}.Encode(),
		Cookie: oidcFlowCookieName + "=" + flow,
		Scheme: "https",
		Host:   "other.example",
	})
	refuseCheck(t, s, v, lg)
}

func TestOIDCExpiredFlowCookieIsRefused(t *testing.T) {
	installSessionKey(t)
	s, _ := compileOIDC(t, nil)
	base := time.Now()
	s.now = func() time.Time { return base }

	authURL, flow := beginFlow(t, s)

	// eleven minutes later the flow cookie is past its ten-minute TTL
	s.now = func() time.Time { return base.Add(11 * time.Minute) }
	q := authURL.Query()
	v, lg := decideOnce(s, OIDCRequest{
		Method: "GET",
		Path:   "/oauth2/callback",
		Query:  url.Values{"code": {"test-code"}, "state": {q.Get("state")}}.Encode(),
		Cookie: oidcFlowCookieName + "=" + flow,
		Scheme: "https",
		Host:   "app.example",
	})
	refuseCheck(t, s, v, lg)
}

func TestOIDCCallbackGarbageIsRefused(t *testing.T) {
	installSessionKey(t)
	s, _ := compileOIDC(t, nil)

	cases := []struct {
		name   string
		query  string
		cookie string
		marker string
	}{
		{"no flow cookie", "code=c&state=s", "", "unvisited-code-marker"},
		{"unparseable query", "a=%zz", "", ""},
		{"provider error reply", "error=access_denied", "", ""},
		{"no code", "state=s", "", ""},
		{"forged flow cookie", "code=c&state=s", oidcFlowCookieName + "=not.a.realvalue", "forged-cookie-marker"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, lg := decideOnce(s, OIDCRequest{
				Method: "GET",
				Path:   "/oauth2/callback",
				Query:  tc.query,
				Cookie: tc.cookie,
				Scheme: "https",
				Host:   "app.example",
			})
			refuseCheck(t, s, v, lg, tc.marker)
		})
	}
}

func TestOIDCCodeReplayIsRefused(t *testing.T) {
	installSessionKey(t)
	s, _ := compileOIDC(t, nil)

	// the first redemption mints; the second -- same cookie, same code -- is
	// refused by the provider (the fake IdP makes codes single-use the way
	// real ones do), which the flow answers with the fixed 403
	authURL, flow := beginFlow(t, s)
	if v := finishFlow(t, s, authURL, flow); v.Kind != OIDCRedirect {
		t.Fatalf("the first redemption produced %v, want a mint", v.Kind)
	}
	v, lg := finishFlowLogged(t, s, authURL, flow)
	refuseCheck(t, s, v, lg)
}

// finishFlowLogged is finishFlow with the logger handed back, for the tests
// that assert on what the callback logged.
func finishFlowLogged(t *testing.T, s *OIDCSettings, authURL *url.URL, flowCookieValue string) (OIDCVerdict, *oidcTestLogger) {
	t.Helper()
	q := authURL.Query()
	return decideOnce(s, OIDCRequest{
		Method: "GET",
		Path:   "/oauth2/callback",
		Query:  url.Values{"code": {"test-code"}, "state": {q.Get("state")}}.Encode(),
		Cookie: oidcFlowCookieName + "=" + flowCookieValue,
		Scheme: "https",
		Host:   "app.example",
	})
}

// --- failure classes: the IdP ----------------------------------------------------

func TestOIDCDiscoveryPoisonIsRefused(t *testing.T) {
	installSessionKey(t)
	s, p := compileOIDC(t, nil)

	// a document that does not name the configured issuer is refused whole:
	// 503, the fixed body, and nothing of the stranger's spelling anywhere
	p.mu.Lock()
	p.doc = p.metadata()
	p.doc.Issuer = "https://evil.example"
	p.mu.Unlock()

	v, lg := decideOnce(s, OIDCRequest{Method: "GET", Path: "/private", Scheme: "https", Host: "app.example"})
	if v.Kind != OIDCUnavailable || v.Response != s.unavailable || v.Response.Body != oidcUnavailableBody {
		t.Fatalf("a poisoned discovery produced %v (%+v), want the fixed 503", v.Kind, v.Response)
	}
	if logged := lg.all(); strings.Contains(logged, "evil.example") {
		t.Fatalf("the log line quoted the poisoned document's issuer:\n%s", logged)
	}
}

func TestOIDCTokenEndpointNon200IsRefused(t *testing.T) {
	installSessionKey(t)
	s, p := compileOIDC(t, nil)
	p.mu.Lock()
	p.tokenStatus = 500
	p.mu.Unlock()

	authURL, flow := beginFlow(t, s)
	// an endpoint that answers and refuses is the 403 class, not the 503
	// class: the IdP being wrong about this exchange is not the IdP being
	// unreachable, and the difference is what an operator triages on
	v, lg := finishFlowLogged(t, s, authURL, flow)
	refuseCheck(t, s, v, lg)
}

func TestOIDCIdPDownAnswers503AndThrottlesFetches(t *testing.T) {
	installSessionKey(t)
	s, p := compileOIDC(t, nil)
	base := time.Now()
	s.now = func() time.Time { return base }

	p.mu.Lock()
	p.discoveryStatus = 500
	p.mu.Unlock()

	decide := func() OIDCVerdict {
		v, _ := decideOnce(s, OIDCRequest{Method: "GET", Path: "/private", Scheme: "https", Host: "app.example"})
		if v.Kind != OIDCUnavailable || v.Response.Body != oidcUnavailableBody {
			t.Fatalf("a down IdP produced %v (%+v), want the fixed 503", v.Kind, v.Response)
		}
		return v
	}

	decide() // fetch 1
	s.now = func() time.Time { return base.Add(time.Second) }
	decide() // inside the failure TTL: refused from memory, no fetch
	s.now = func() time.Time { return base.Add(31 * time.Second) }
	decide() // past it: one more attempt

	p.mu.Lock()
	fetches := p.discoveryFetches
	p.mu.Unlock()
	if fetches != 2 {
		t.Fatalf("the discovery endpoint was fetched %d times, want 2 (the failure TTL must make attempts, not requests, scarce)", fetches)
	}
}

func TestOIDCTokenTransportFailureAnswers503(t *testing.T) {
	installSessionKey(t)
	s, p := compileOIDC(t, nil)

	// discovery succeeds once and is cached; the IdP then goes away, so the
	// callback's token exchange fails in transport -- the 503 class, not the
	// 403 class
	authURL, flow := beginFlow(t, s)
	p.close()

	v, lg := finishFlowLogged(t, s, authURL, flow)
	if v.Kind != OIDCUnavailable || v.Response != s.unavailable {
		t.Fatalf("a token transport failure produced %v (%+v), want the fixed 503", v.Kind, v.Response)
	}
	if logged := lg.all(); !strings.Contains(logged, "token endpoint") {
		t.Fatalf("the transport failure was not logged for the operator:\n%s", logged)
	}
}

func TestOIDCDiscoveryCacheAndTTL(t *testing.T) {
	installSessionKey(t)
	s, p := compileOIDC(t, nil)
	base := time.Now()
	s.now = func() time.Time { return base }

	decide := func() {
		v, _ := decideOnce(s, OIDCRequest{Method: "GET", Path: "/private", Scheme: "https", Host: "app.example"})
		if v.Kind != OIDCRedirect {
			t.Fatalf("a healthy visit produced %v", v.Kind)
		}
	}

	decide() // fetch 1
	s.now = func() time.Time { return base.Add(time.Minute) }
	decide() // cached: still 1
	s.now = func() time.Time { return base.Add(11 * time.Minute) }
	decide() // past the 10-minute TTL: fetch 2

	p.mu.Lock()
	fetches := p.discoveryFetches
	p.mu.Unlock()
	if fetches != 2 {
		t.Fatalf("the discovery endpoint was fetched %d times, want 2 (cached for the TTL, refetched after)", fetches)
	}
}

// --- failure classes: the token's contents ----------------------------------------

func TestOIDCNonceMismatchIsRefused(t *testing.T) {
	installSessionKey(t)
	s, p := compileOIDC(t, nil)
	p.mu.Lock()
	p.tokenNonce = "attacker-chosen-nonce"
	p.mu.Unlock()

	authURL, flow := beginFlow(t, s)
	v, lg := finishFlowLogged(t, s, authURL, flow)
	refuseCheck(t, s, v, lg)
}

func TestOIDCAllowedDomains(t *testing.T) {
	installSessionKey(t)

	t.Run("miss refuses", func(t *testing.T) {
		s, _ := compileOIDC(t, map[string]interface{}{"allowed_domains": []interface{}{"corp.example"}})
		authURL, flow := beginFlow(t, s)
		v, lg := finishFlowLogged(t, s, authURL, flow)
		refuseCheck(t, s, v, lg)
	})

	t.Run("hd hit admits", func(t *testing.T) {
		s, _ := compileOIDC(t, map[string]interface{}{"allowed_domains": []interface{}{"example.com"}})
		session := fullSession(t, s)
		v, _ := decideOnce(s, OIDCRequest{Method: "GET", Path: "/private", Scheme: "https", Host: "app.example", Cookie: oidcSessionCookieName + "=" + session})
		if v.Kind != OIDCDispatch {
			t.Fatalf("a listed domain produced %v", v.Kind)
		}
	})

	t.Run("email domain hit admits, case-insensitively", func(t *testing.T) {
		s, p := compileOIDC(t, map[string]interface{}{"allowed_domains": []interface{}{"EXAMPLE.COM"}})
		p.mu.Lock()
		p.hd = "" // no hd claim: the email's domain is the evidence
		p.mu.Unlock()
		session := fullSession(t, s)
		v, _ := decideOnce(s, OIDCRequest{Method: "GET", Path: "/private", Scheme: "https", Host: "app.example", Cookie: oidcSessionCookieName + "=" + session})
		if v.Kind != OIDCDispatch {
			t.Fatalf("a listed email domain produced %v", v.Kind)
		}
	})
}

func TestOIDCClaimsExactMatch(t *testing.T) {
	installSessionKey(t)

	t.Run("hit admits", func(t *testing.T) {
		s, _ := compileOIDC(t, map[string]interface{}{"claims": map[string]interface{}{"hd": "example.com"}})
		authURL, flow := beginFlow(t, s)
		if v := finishFlow(t, s, authURL, flow); v.Kind != OIDCRedirect {
			t.Fatalf("a matching claim produced %v", v.Kind)
		}
	})

	t.Run("miss refuses", func(t *testing.T) {
		s, _ := compileOIDC(t, map[string]interface{}{"claims": map[string]interface{}{"hd": "other.example"}})
		authURL, flow := beginFlow(t, s)
		v, lg := finishFlowLogged(t, s, authURL, flow)
		refuseCheck(t, s, v, lg)
	})
}

// --- the session cookie -------------------------------------------------------------

func TestOIDCSessionForgeryRedirectsAndLeaksNothing(t *testing.T) {
	installSessionKey(t)
	s, _ := compileOIDC(t, nil)

	// a payload that LOOKS admitted, MACed under the wrong key: the answer
	// is the provider, never dispatch, and the forged claims reach nothing
	forged := sessionCookie{Exp: time.Now().Add(time.Hour).Unix(), Sub: "attacker", Name: "attacker@evil.example", Pref: "attacker", Mint: "mint"}
	raw, _ := json.Marshal(forged)
	payload := base64.RawURLEncoding.EncodeToString(raw)
	mac := hmac.New(sha256.New, []byte("a wrong key of thirty-two bytes!"))
	mac.Write([]byte(payload))
	value := payload + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	v, lg := decideOnce(s, OIDCRequest{Method: "GET", Path: "/private", Scheme: "https", Host: "app.example", Cookie: oidcSessionCookieName + "=" + value})
	if v.Kind != OIDCRedirect {
		t.Fatalf("a forged session produced %v, want the redirect to the provider", v.Kind)
	}
	if v.Response.StatusCode != http.StatusFound {
		t.Fatalf("the forged session's response is %d, want 302", v.Response.StatusCode)
	}
	// no dispatch means no headers at all -- and none of the forged identity
	// may reach the response or the log in any other spelling
	if len(v.Headers) > 0 {
		t.Fatalf("a refused session produced headers: %v", v.Headers)
	}
	if hv := locationOf(t, &v) + v.Response.Body; strings.Contains(hv, "attacker") {
		t.Fatalf("the forged identity leaked into the response: %q", hv)
	}
	if logged := lg.all(); strings.Contains(logged, "attacker") {
		t.Fatalf("the forged identity leaked into a log line:\n%s", logged)
	}
}

func TestOIDCSessionExpirySendsBackToTheProvider(t *testing.T) {
	installSessionKey(t)
	s, _ := compileOIDC(t, nil)
	base := time.Now()
	s.now = func() time.Time { return base }
	session := fullSession(t, s)

	v, _ := decideOnce(s, OIDCRequest{Method: "GET", Path: "/private", Scheme: "https", Host: "app.example", Cookie: oidcSessionCookieName + "=" + session})
	if v.Kind != OIDCDispatch {
		t.Fatalf("a fresh session produced %v", v.Kind)
	}

	s.now = func() time.Time { return base.Add(s.sessionTTL + time.Minute) }
	v, _ = decideOnce(s, OIDCRequest{Method: "GET", Path: "/private", Scheme: "https", Host: "app.example", Cookie: oidcSessionCookieName + "=" + session})
	if v.Kind != OIDCRedirect {
		t.Fatalf("an expired session produced %v, want the redirect to the provider", v.Kind)
	}
}

func TestOIDCCookieVerifyRejectsGarbage(t *testing.T) {
	installSessionKey(t)
	sess := sessionCookie{Exp: time.Now().Add(time.Hour).Unix(), Sub: "u", Mint: "m"}
	signed := signCookie(sess)

	good := sessionCookie{}
	if !verifyCookie(signed, &good) || good.Sub != "u" {
		t.Fatalf("a signed cookie did not verify")
	}

	// a flipped payload byte under the original MAC: the MAC no longer fits
	parts := strings.Split(signed, ".")
	raw, _ := base64.RawURLEncoding.DecodeString(parts[0])
	raw[0] ^= 0xff
	if verifyCookie(base64.RawURLEncoding.EncodeToString(raw)+"."+parts[1], &sessionCookie{}) {
		t.Fatal("a tampered payload verified")
	}
	// the original payload under a tampered MAC
	mac, _ := base64.RawURLEncoding.DecodeString(parts[1])
	mac[0] ^= 0xff
	if verifyCookie(parts[0]+"."+base64.RawURLEncoding.EncodeToString(mac), &sessionCookie{}) {
		t.Fatal("a tampered MAC verified")
	}
	for _, garbage := range []string{"", "nodot", "a.b", signed + ".extra"} {
		if verifyCookie(garbage, &sessionCookie{}) {
			t.Fatalf("garbage %q verified", garbage)
		}
	}
}

// --- the decision's edges -------------------------------------------------------------

func TestOIDCUnusableHeadsClose(t *testing.T) {
	installSessionKey(t)
	s, _ := compileOIDC(t, nil)

	for _, r := range []OIDCRequest{
		{Method: "GET", Path: "/x", Scheme: "https", Host: ""},
		{Method: "GET", Path: "/x", Scheme: "ftp", Host: "app.example"},
		{Method: "GET", Path: "", Scheme: "https", Host: "app.example"},
		{Method: "GET", Path: "/x", Scheme: "https", Host: "app.example", Query: "a=1\r\nX-Evil: 1"},
		{Method: "GET", Path: "/x\r\nEvil", Scheme: "https", Host: "app.example"},
	} {
		v, _ := decideOnce(s, r)
		if v.Kind != OIDCClose {
			t.Fatalf("an unusable head %+v produced %v, want close", r, v.Kind)
		}
	}
}

func TestOIDCDecideHookOnNilSettingsCloses(t *testing.T) {
	var s *OIDCSettings
	v := s.DecideHook(nil)(OIDCRequest{Method: "GET", Path: "/x", Scheme: "https", Host: "h"})
	if v.Kind != OIDCClose {
		t.Fatalf("a nil settings' hook produced %v, want close", v.Kind)
	}
}

// --- load-time validation ------------------------------------------------------------

func TestOIDCCompileValidation(t *testing.T) {
	// The vaults are installed for the whole table: one case resolves a
	// secret("...") reference and one case must refuse when they are NOT
	// installed, which is checked separately below, after the restore.
	cases := []struct {
		name      string
		cfg       map[string]interface{}
		wantErr   string
		after     func(t *testing.T, s *OIDCSettings)
		needVault bool
	}{
		{
			name: "defaults",
			cfg:  map[string]interface{}{"issuer": "http://127.0.0.1:1234", "client_id": "c", "client_secret": "s"},
			after: func(t *testing.T, s *OIDCSettings) {
				if s.callbackPath != defaultOIDCCallbackPath {
					t.Fatalf("callbackPath = %q, want the default", s.callbackPath)
				}
				if s.sessionTTL != 3600*time.Second {
					t.Fatalf("sessionTTL = %v, want the default hour", s.sessionTTL)
				}
				if got := strings.Join(s.scopes, " "); got != "openid email" {
					t.Fatalf("scopes = %q, want the default", got)
				}
			},
		},
		{
			name: "openid is forced first when the operator omits it",
			cfg:  map[string]interface{}{"issuer": "http://127.0.0.1:1234", "client_id": "c", "client_secret": "s", "scopes": []interface{}{"profile"}},
			after: func(t *testing.T, s *OIDCSettings) {
				if got := strings.Join(s.scopes, " "); got != "openid profile" {
					t.Fatalf("scopes = %q, want openid forced first", got)
				}
			},
		},
		{
			name:    "issuer over plain http is refused",
			cfg:     map[string]interface{}{"issuer": "http://idp.example", "client_id": "c", "client_secret": "s"},
			wantErr: "must be an https URL",
		},
		{
			name:    "issuer with userinfo is refused",
			cfg:     map[string]interface{}{"issuer": "https://bob@idp.example", "client_id": "c", "client_secret": "s"},
			wantErr: "userinfo",
		},
		{
			name:    "issuer with a query is refused",
			cfg:     map[string]interface{}{"issuer": "https://idp.example/?x=1", "client_id": "c", "client_secret": "s"},
			wantErr: "query or fragment",
		},
		{
			name:    "issuer must be a string",
			cfg:     map[string]interface{}{"issuer": 7, "client_id": "c", "client_secret": "s"},
			wantErr: "must be a string",
		},
		{
			name:    "client_id is required",
			cfg:     map[string]interface{}{"issuer": "http://127.0.0.1:1234", "client_secret": "s"},
			wantErr: "client_id",
		},
		{
			name:    "an empty client_secret is refused",
			cfg:     map[string]interface{}{"issuer": "http://127.0.0.1:1234", "client_id": "c", "client_secret": ""},
			wantErr: "empty",
		},
		{
			name:    "a client_secret with a newline is refused",
			cfg:     map[string]interface{}{"issuer": "http://127.0.0.1:1234", "client_id": "c", "client_secret": "one\ntwo"},
			wantErr: "CR or LF",
		},
		{
			name:    "a digested client_secret is refused",
			cfg:     map[string]interface{}{"issuer": "http://127.0.0.1:1234", "client_id": "c", "client_secret": "sha256:abcd"},
			wantErr: "digest",
		},
		{
			name: "a vault reference resolves to the plaintext",
			cfg:  map[string]interface{}{"issuer": "http://127.0.0.1:1234", "client_id": "c", "client_secret": `secret("main/oidc")`},
			after: func(t *testing.T, s *OIDCSettings) {
				if s.clientSecret != "oidc-vault-secret" {
					t.Fatalf("the vault reference did not resolve: %q", s.clientSecret)
				}
			},
			needVault: true,
		},
		{
			name:    "scopes with a space are refused",
			cfg:     map[string]interface{}{"issuer": "http://127.0.0.1:1234", "client_id": "c", "client_secret": "s", "scopes": []interface{}{"openid email"}},
			wantErr: "one token",
		},
		{
			name:    "duplicate scopes are refused",
			cfg:     map[string]interface{}{"issuer": "http://127.0.0.1:1234", "client_id": "c", "client_secret": "s", "scopes": []interface{}{"email", "email"}},
			wantErr: "twice",
		},
		{
			name:    "callback_path must start with a slash",
			cfg:     map[string]interface{}{"issuer": "http://127.0.0.1:1234", "client_id": "c", "client_secret": "s", "callback_path": "oauth2/callback"},
			wantErr: "must start with",
		},
		{
			name:    "callback_path may not carry a query",
			cfg:     map[string]interface{}{"issuer": "http://127.0.0.1:1234", "client_id": "c", "client_secret": "s", "callback_path": "/cb?x=1"},
			wantErr: `or a "#":`,
		},
		{
			name:    "callback_path may not carry control characters",
			cfg:     map[string]interface{}{"issuer": "http://127.0.0.1:1234", "client_id": "c", "client_secret": "s", "callback_path": "/cb\r\nX-Evil: 1"},
			wantErr: "CR or LF",
		},
		{
			name:    "session duration zero is refused",
			cfg:     map[string]interface{}{"issuer": "http://127.0.0.1:1234", "client_id": "c", "client_secret": "s", "session_duration_seconds": 0},
			wantErr: "must be positive",
		},
		{
			name:    "session duration past the ceiling is refused",
			cfg:     map[string]interface{}{"issuer": "http://127.0.0.1:1234", "client_id": "c", "client_secret": "s", "session_duration_seconds": 86401},
			wantErr: "ceiling",
		},
		{
			name: "session duration at the ceiling compiles",
			cfg:  map[string]interface{}{"issuer": "http://127.0.0.1:1234", "client_id": "c", "client_secret": "s", "session_duration_seconds": 86400},
			after: func(t *testing.T, s *OIDCSettings) {
				if s.sessionTTL != 86400*time.Second {
					t.Fatalf("sessionTTL = %v, want 24h", s.sessionTTL)
				}
			},
		},
		{
			name:    "a registered claim in claims is refused",
			cfg:     map[string]interface{}{"issuer": "http://127.0.0.1:1234", "client_id": "c", "client_secret": "s", "claims": map[string]interface{}{"iss": "x"}},
			wantErr: "iss",
		},
		{
			name:    "a non-string claim value is refused",
			cfg:     map[string]interface{}{"issuer": "http://127.0.0.1:1234", "client_id": "c", "client_secret": "s", "claims": map[string]interface{}{"hd": 5}},
			wantErr: "must be a string",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.needVault {
				installVaults(t, mainVaultSources(t, map[string]string{"oidc": "oidc-vault-secret"}))
			}
			cfg := map[string]interface{}{}
			for k, v := range tc.cfg {
				cfg[k] = v
			}
			s, err := buildOIDC("on_http_request[0] (oidc)", cfg)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("buildOIDC error = %v, want it to contain %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("buildOIDC: %v", err)
			}
			if tc.after != nil {
				tc.after(t, s)
			}
		})
	}

	// out here the vaults are restored: an unresolved reference is a load
	// error naming the seam, on both sides
	t.Run("an unresolvable vault reference is refused", func(t *testing.T) {
		_, err := buildOIDC("on_http_request[0] (oidc)", map[string]interface{}{
			"issuer": "http://127.0.0.1:1234", "client_id": "c", "client_secret": `secret("main/absent")`,
		})
		if err == nil || !strings.Contains(err.Error(), "vault") {
			t.Fatalf("buildOIDC error = %v, want the vault seam's refusal", err)
		}
	})
}

func TestOIDCPolicyShapeRules(t *testing.T) {
	cfg := func() map[string]interface{} {
		return map[string]interface{}{"issuer": "http://127.0.0.1:1234", "client_id": "c", "client_secret": "s"}
	}

	t.Run("two oidc actions are refused", func(t *testing.T) {
		_, err := reqPolicy(
			rule(ActionOIDC, nil, cfg()),
			rule(ActionOIDC, nil, cfg()),
		).build()
		if err == nil || !strings.Contains(err.Error(), "at most one") {
			t.Fatalf("two oidc actions compiled: %v", err)
		}
	})

	t.Run("conditions are refused", func(t *testing.T) {
		_, err := reqPolicy(
			rule(ActionOIDC, []string{"req.url.path != '/health'"}, cfg()),
		).build()
		if err == nil || !strings.Contains(err.Error(), "cannot carry conditions") {
			t.Fatalf("a conditioned oidc action compiled: %v", err)
		}
	})

	t.Run("an unknown field is refused", func(t *testing.T) {
		// the allowed-field check lives in buildAction's case, so this one
		// goes through the policy build, the way an operator's document would
		bad := cfg()
		bad["provider"] = "google"
		_, err := reqPolicy(rule(ActionOIDC, nil, bad)).build()
		if err == nil || !strings.Contains(err.Error(), "unknown config field") {
			t.Fatalf("an oidc action with a typo'd field compiled: %v", err)
		}
	})

	t.Run("one oidc action compiles and is reachable through the accessor", func(t *testing.T) {
		c, err := reqPolicy(
			rule(ActionAddHeaders, nil, map[string]interface{}{"headers": map[string]interface{}{"X-Probe": "1"}}),
			rule(ActionOIDC, nil, cfg()),
		).build()
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		if c.OIDC() == nil {
			t.Fatal("Compiled.OIDC() is nil for a policy carrying the action")
		}
	})

	t.Run("no oidc action means a nil accessor", func(t *testing.T) {
		c, err := reqPolicy(rule(ActionAddHeaders, nil, map[string]interface{}{"headers": map[string]interface{}{"X-Probe": "1"}})).build()
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		if c.OIDC() != nil {
			t.Fatal("Compiled.OIDC() is not nil for a policy without the action")
		}
	})

	t.Run("oidc is refused outside the request phase", func(t *testing.T) {
		tp := &TrafficPolicy{OnHTTPResponse: []*Action{rule(ActionOIDC, nil, cfg())}}
		_, err := tp.build()
		if err == nil || !strings.Contains(err.Error(), "on_http_response") {
			t.Fatalf("oidc compiled in the response phase: %v", err)
		}
	})

	t.Run("the authenticate shim is fail-closed", func(t *testing.T) {
		c, err := reqPolicy(rule(ActionOIDC, nil, cfg())).build()
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		v := c.OIDC().authenticate(nil, nil)
		if v == nil || v.StatusCode != http.StatusForbidden {
			t.Fatalf("the storage shim admitted a request: %+v", v)
		}
	})
}

// --- the session key -------------------------------------------------------------------

func TestOIDCSessionKeySetter(t *testing.T) {
	t.Run("a short key is a startup error", func(t *testing.T) {
		if err := SetOIDCSessionKey([]byte("short")); err == nil {
			t.Fatal("a short key was accepted")
		}
	})

	t.Run("a generated key is one key, generated once", func(t *testing.T) {
		prev := oidcKey.Load()
		prevInstalled := oidcKeyInstalled.Load()
		t.Cleanup(func() {
			oidcKey.Store(prev)
			oidcKeyInstalled.Store(prevInstalled)
		})
		oidcKey.Store(nil)
		oidcKeyInstalled.Store(false)

		k1 := oidcSessionKey()
		k2 := oidcSessionKey()
		if len(k1) != 32 || string(k1) != string(k2) {
			t.Fatalf("the generated key is not stable at 32 bytes: %d / %d", len(k1), len(k2))
		}
	})
}
