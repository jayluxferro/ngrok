package policy

// Tests for the jwt-validation action (SPEC-CLUSTER6).
//
// Everything is generated in the test: the RSA, ECDSA and Ed25519 keys are
// created here, the JWKS is served by an httptest server whose key set the
// test can rewrite mid-flight (that is what makes rotation a testable event
// rather than a story), and the tokens are signed with jwt/v5 itself -- the
// same library the action verifies with, which keeps the failures honest: a
// token that fails here failed on the wire shapes, not on a fixture artifact.
//
// The verdicts are asserted like the other auth actions', plus one property
// that only jwt has: the rejected token itself must appear nowhere -- not in
// the response body, not in the log. A JWT is a bearer credential even when
// this engine refuses it (the common case being an expired one), so the logs
// carry fixed labels only.

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"ngrok/rewriter"
)

// --- fixtures ----------------------------------------------------------------

// testIdP is a JWKS endpoint with a key set the test rewrites between
// requests. It counts fetches, because the refetch-on-unknown-kid policy is
// one of the behaviors under test and "it worked" is not the same as "it
// worked because it refetched exactly once".
type testIdP struct {
	srv *httptest.Server

	mu    sync.Mutex
	keys  [][]byte // JWK documents, pre-marshalled
	live  bool     // false until the first publish: an empty IdP serves nothing
	fetch int
}

func newTestIdP(t *testing.T) *testIdP {
	t.Helper()
	idp := &testIdP{}
	idp.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		idp.mu.Lock()
		defer idp.mu.Unlock()
		idp.fetch++
		if !idp.live || len(idp.keys) == 0 {
			http.Error(w, "no keys published", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"keys":[`))
		for i, doc := range idp.keys {
			if i > 0 {
				w.Write([]byte(","))
			}
			w.Write(doc)
		}
		w.Write([]byte(`]}`))
	}))
	t.Cleanup(idp.srv.Close)
	return idp
}

// publish replaces the served key set -- a rotation, in the eyes of the
// action -- and starts serving.
func (idp *testIdP) publish(t *testing.T, jwks ...map[string]interface{}) {
	t.Helper()
	docs := make([][]byte, len(jwks))
	for i, k := range jwks {
		b, err := json.Marshal(k)
		if err != nil {
			t.Fatalf("marshalling a JWK: %v", err)
		}
		docs[i] = b
	}
	idp.mu.Lock()
	defer idp.mu.Unlock()
	idp.keys = docs
	idp.live = true
}

func (idp *testIdP) fetches() int {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	return idp.fetch
}

// testKeys holds the in-test identities: three private keys, a second RSA key
// for wrong-signature cases, and their JWKS renderings.
type testKeys struct {
	rsaKey      *rsa.PrivateKey
	otherRSA    *rsa.PrivateKey // a second RSA key, published under the same kid
	ecKey       *ecdsa.PrivateKey
	edKey       ed25519.PrivateKey
	rsaJWK      map[string]interface{}
	otherRSAJWK map[string]interface{}
	ecJWK       map[string]interface{}
	edJWK       map[string]interface{}
	rotatedJWK  map[string]interface{} // the second RSA key under a fresh kid
}

func genTestKeys(t *testing.T) *testKeys {
	t.Helper()
	k := &testKeys{}
	var err error
	if k.rsaKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
		t.Fatalf("generating the RSA key: %v", err)
	}
	if k.otherRSA, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
		t.Fatalf("generating the second RSA key: %v", err)
	}
	if k.ecKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		t.Fatalf("generating the ECDSA key: %v", err)
	}
	if _, k.edKey, err = ed25519.GenerateKey(rand.Reader); err != nil {
		t.Fatalf("generating the Ed25519 key: %v", err)
	}
	k.rsaJWK = rsaJWK(&k.rsaKey.PublicKey, "rsa-1")
	// The same kid as rsaJWK but a different key: the wrong-signature case.
	k.otherRSAJWK = rsaJWK(&k.otherRSA.PublicKey, "rsa-1")
	k.ecJWK = ecJWK(&k.ecKey.PublicKey, "ec-1")
	k.edJWK = okpJWK(k.edKey.Public().(ed25519.PublicKey), "ed-1")
	k.rotatedJWK = rsaJWK(&k.otherRSA.PublicKey, "rsa-2")
	return k
}

// rsaJWK renders one RSA public key as a JWK (RFC 7518 6.3): base64url
// big-endian, no padding.
func rsaJWK(pub *rsa.PublicKey, kid string) map[string]interface{} {
	return map[string]interface{}{
		"kty": "RSA",
		"kid": kid,
		"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

func ecJWK(pub *ecdsa.PublicKey, kid string) map[string]interface{} {
	size := (pub.Curve.Params().BitSize + 7) / 8
	return map[string]interface{}{
		"kty": "EC",
		"kid": kid,
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(pub.X.FillBytes(make([]byte, size))),
		"y":   base64.RawURLEncoding.EncodeToString(pub.Y.FillBytes(make([]byte, size))),
	}
}

func okpJWK(pub ed25519.PublicKey, kid string) map[string]interface{} {
	return map[string]interface{}{
		"kty": "OKP",
		"kid": kid,
		"crv": "Ed25519",
		"x":   base64.RawURLEncoding.EncodeToString(pub),
	}
}

// signToken builds a signed JWT the way a client would send it.
func signToken(t *testing.T, method jwt.SigningMethod, key interface{}, kid string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(method, claims)
	if kid != "" {
		tok.Header["kid"] = kid
	}
	signed, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("signing a %s token: %v", method.Alg(), err)
	}
	return signed
}

// standardClaims is the common shape: issued now, expiring in an hour, the
// issuer and audience the tests' configs ask for. Each test overrides the one
// field it is about.
func standardClaims() jwt.MapClaims {
	now := time.Now()
	return jwt.MapClaims{
		"iss": "https://idp.example",
		"aud": "my-endpoint",
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
	}
}

// jwtHook compiles a one-rule jwt-validation policy and returns its request
// hook. Overrides are the test's way to configure algorithms, leeway, claims
// -- anything the defaults do not cover.
func jwtHook(t *testing.T, jwksURL string, overrides map[string]interface{}) func(*http.Request) *rewriter.RequestVerdict {
	t.Helper()
	cfg := map[string]interface{}{
		"jwks_uri": jwksURL,
		"issuer":   "https://idp.example",
		"audience": "my-endpoint",
	}
	for k, v := range overrides {
		cfg[k] = v
	}
	c, err := reqPolicy(rule(ActionJWTValidation, nil, cfg)).Compile()
	if err != nil {
		t.Fatalf("compiling the jwt-validation policy: %v", err)
	}
	hook := c.RequestHook(&testLogger{}, "1.2.3.4:1")
	if hook == nil {
		t.Fatal("no request hook for a jwt-validation policy")
	}
	return hook
}

// bearerRequest wraps a token the way a client sends it.
func bearerRequest(token string) *http.Request {
	return get("/", map[string]string{"Authorization": "Bearer " + token})
}

// jwtRefused asserts the 401 and the challenge, and that the token (when the
// caller hands it over) appears nowhere in what goes back on the wire.
func jwtRefused(t *testing.T, v *rewriter.RequestVerdict, token string) {
	t.Helper()
	s := terminated(t, v)
	wire := wireHeaders(s)
	if !strings.Contains(wire, `WWW-Authenticate: Bearer error="invalid_token"`) {
		t.Fatalf("the challenge on the wire is wrong:\n%s", wire)
	}
	if token != "" && strings.Contains(wire, token) {
		t.Fatalf("the wire response echoes the token")
	}
}

// --- the suite ----------------------------------------------------------------

// TestJWTValidationAcceptsAndRejects is the main table: one key set, one IdP,
// every failure mode the spec names.
func TestJWTValidationAcceptsAndRejects(t *testing.T) {
	keys := genTestKeys(t)
	idp := newTestIdP(t)
	idp.publish(t, keys.rsaJWK, keys.ecJWK, keys.edJWK)

	t.Run("a valid token is admitted", func(t *testing.T) {
		hook := jwtHook(t, idp.srv.URL, nil)
		token := signToken(t, jwt.SigningMethodRS256, keys.rsaKey, "rsa-1", standardClaims())
		admitted(t, hook(bearerRequest(token)))
	})

	t.Run("an expired token is refused", func(t *testing.T) {
		hook := jwtHook(t, idp.srv.URL, nil)
		claims := standardClaims()
		claims["exp"] = time.Now().Add(-time.Hour).Unix()
		jwtRefused(t, hook(bearerRequest(signToken(t, jwt.SigningMethodRS256, keys.rsaKey, "rsa-1", claims))), "")
	})

	t.Run("leeway forgives a recently expired token", func(t *testing.T) {
		hook := jwtHook(t, idp.srv.URL, map[string]interface{}{"leeway_seconds": 3 * 3600})
		claims := standardClaims()
		claims["exp"] = time.Now().Add(-2 * time.Hour).Unix()
		admitted(t, hook(bearerRequest(signToken(t, jwt.SigningMethodRS256, keys.rsaKey, "rsa-1", claims))))
	})

	t.Run("a not-yet-valid token is refused", func(t *testing.T) {
		hook := jwtHook(t, idp.srv.URL, nil)
		claims := standardClaims()
		claims["nbf"] = time.Now().Add(2 * time.Hour).Unix()
		jwtRefused(t, hook(bearerRequest(signToken(t, jwt.SigningMethodRS256, keys.rsaKey, "rsa-1", claims))), "")
	})

	t.Run("leeway forgives a token that is almost valid", func(t *testing.T) {
		hook := jwtHook(t, idp.srv.URL, map[string]interface{}{"leeway_seconds": 3 * 3600})
		claims := standardClaims()
		claims["nbf"] = time.Now().Add(2 * time.Hour).Unix()
		admitted(t, hook(bearerRequest(signToken(t, jwt.SigningMethodRS256, keys.rsaKey, "rsa-1", claims))))
	})

	t.Run("a wrong issuer is refused, and so is a missing one", func(t *testing.T) {
		hook := jwtHook(t, idp.srv.URL, nil)
		claims := standardClaims()
		claims["iss"] = "https://evil.example"
		jwtRefused(t, hook(bearerRequest(signToken(t, jwt.SigningMethodRS256, keys.rsaKey, "rsa-1", claims))), "")

		delete(claims, "iss")
		jwtRefused(t, hook(bearerRequest(signToken(t, jwt.SigningMethodRS256, keys.rsaKey, "rsa-1", claims))), "")
	})

	t.Run("a wrong audience is refused, a listed one is accepted", func(t *testing.T) {
		hook := jwtHook(t, idp.srv.URL, nil)
		claims := standardClaims()
		claims["aud"] = "someone-elses-endpoint"
		jwtRefused(t, hook(bearerRequest(signToken(t, jwt.SigningMethodRS256, keys.rsaKey, "rsa-1", claims))), "")

		// RFC 7519 lets aud be a list; membership is what "matches" means.
		claims["aud"] = []string{"other", "my-endpoint"}
		admitted(t, hook(bearerRequest(signToken(t, jwt.SigningMethodRS256, keys.rsaKey, "rsa-1", claims))))
	})

	t.Run("exact-match claims are enforced", func(t *testing.T) {
		hook := jwtHook(t, idp.srv.URL, map[string]interface{}{
			"claims": map[string]interface{}{"scope": "tunnels:read"},
		})

		claims := standardClaims()
		claims["scope"] = "tunnels:write"
		jwtRefused(t, hook(bearerRequest(signToken(t, jwt.SigningMethodRS256, keys.rsaKey, "rsa-1", claims))), "")

		delete(claims, "scope")
		jwtRefused(t, hook(bearerRequest(signToken(t, jwt.SigningMethodRS256, keys.rsaKey, "rsa-1", claims))), "")

		// A claim that is present but not a string cannot match a string
		// comparison; refusing it is the only honest answer.
		claims["scope"] = 12345
		jwtRefused(t, hook(bearerRequest(signToken(t, jwt.SigningMethodRS256, keys.rsaKey, "rsa-1", claims))), "")

		claims["scope"] = "tunnels:read"
		admitted(t, hook(bearerRequest(signToken(t, jwt.SigningMethodRS256, keys.rsaKey, "rsa-1", claims))))
	})

	t.Run("alg none is refused", func(t *testing.T) {
		hook := jwtHook(t, idp.srv.URL, nil)
		token := signToken(t, jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType, "rsa-1", standardClaims())
		jwtRefused(t, hook(bearerRequest(token)), "")
	})

	t.Run("an HS token signed with the RSA public key is refused", func(t *testing.T) {
		// The classic confusion attack: the attacker takes the (public) RSA
		// key out of the same JWKS and feeds its bytes to HMAC-SHA256 as the
		// MAC key. It never gets that far here -- HS* is not in any allowlist
		// this build's validator accepts -- but the test pins that the refusal
		// happens rather than trusting the argument.
		pubDER, err := x509.MarshalPKIXPublicKey(&keys.rsaKey.PublicKey)
		if err != nil {
			t.Fatalf("marshalling the public key: %v", err)
		}
		hook := jwtHook(t, idp.srv.URL, nil)
		token := signToken(t, jwt.SigningMethodHS256, pubDER, "rsa-1", standardClaims())
		jwtRefused(t, hook(bearerRequest(token)), "")
	})

	t.Run("a token signed by the wrong RSA key is refused", func(t *testing.T) {
		hook := jwtHook(t, idp.srv.URL, nil)
		token := signToken(t, jwt.SigningMethodRS256, keys.otherRSA, "rsa-1", standardClaims())
		jwtRefused(t, hook(bearerRequest(token)), "")
	})

	t.Run("ES256 and EdDSA work when allowlisted", func(t *testing.T) {
		hook := jwtHook(t, idp.srv.URL, map[string]interface{}{
			"algorithms": []interface{}{"ES256", "EdDSA"},
		})
		admitted(t, hook(bearerRequest(signToken(t, jwt.SigningMethodES256, keys.ecKey, "ec-1", standardClaims()))))
		admitted(t, hook(bearerRequest(signToken(t, jwt.SigningMethodEdDSA, keys.edKey, "ed-1", standardClaims()))))

		// ...and an RS token is refused when RS is not what the config allows.
		token := signToken(t, jwt.SigningMethodRS256, keys.rsaKey, "rsa-1", standardClaims())
		jwtRefused(t, hook(bearerRequest(token)), "")
	})

	t.Run("a token without a kid is judged against a single-key JWKS and refused against a two-key one", func(t *testing.T) {
		one := newTestIdP(t)
		one.publish(t, keys.rsaJWK)
		hook := jwtHook(t, one.srv.URL, nil)
		admitted(t, hook(bearerRequest(signToken(t, jwt.SigningMethodRS256, keys.rsaKey, "", standardClaims()))))

		two := newTestIdP(t)
		two.publish(t, keys.rsaJWK, keys.ecJWK)
		hook = jwtHook(t, two.srv.URL, nil)
		jwtRefused(t, hook(bearerRequest(signToken(t, jwt.SigningMethodRS256, keys.rsaKey, "", standardClaims()))), "")
	})
}

// shortRefetchInterval shrinks the compiled action's JWKS refetch throttle to
// something a test can sleep past, and returns how long to sleep to be past
// it. Production runs at jwksMinRefetchInterval (30s); the interval is a
// field on the cache precisely so tests can do this instead of sleeping.
func shortRefetchInterval(t *testing.T, c *Compiled) time.Duration {
	t.Helper()
	if len(c.request) != 1 {
		t.Fatalf("the compiled policy has %d request rules, want 1", len(c.request))
	}
	a, ok := c.request[0].auth.(*jwtValidationAction)
	if !ok {
		t.Fatalf("the rule is %T, want *jwtValidationAction", c.request[0].auth)
	}
	a.keys.minRefetchInterval = 40 * time.Millisecond
	return 3 * a.keys.minRefetchInterval
}

// TestJWTValidationRotatesKeysOnUnknownKid covers the refetch policy: an
// unknown kid earns at most one refetch per minimum interval, a refreshed
// document that names the kid admits the token, and the refreshed set
// *replaces* the old one -- a key the IdP withdrew stops verifying. The
// interval itself is the amplification bound (a kid is attacker-chosen
// bytes): inside it, a miss is refused from memory, without a fetch.
func TestJWTValidationRotatesKeysOnUnknownKid(t *testing.T) {
	keys := genTestKeys(t)
	idp := newTestIdP(t)
	idp.publish(t, keys.rsaJWK)

	c, lg := compileRequest(t, reqPolicy(rule(ActionJWTValidation, nil, map[string]interface{}{
		"jwks_uri": idp.srv.URL,
		"issuer":   "https://idp.example",
		"audience": "my-endpoint",
	})))
	pastInterval := shortRefetchInterval(t, c)
	hook := c.RequestHook(lg, "1.2.3.4:1")

	// The first token populates the cache (fetch one).
	old := signToken(t, jwt.SigningMethodRS256, keys.rsaKey, "rsa-1", standardClaims())
	admitted(t, hook(bearerRequest(old)))
	if got := idp.fetches(); got != 1 {
		t.Fatalf("after the first request the IdP was fetched %d times, want 1", got)
	}

	// A token under a just-rotated kid misses -- and, inside the interval,
	// is refused WITHOUT a fetch. This is the throttle's fail-closed face:
	// rotation propagates within one interval, and until it does the miss is
	// a 401, never a network round trip the token's kid asked for.
	idp.publish(t, keys.rotatedJWK)
	replacement := signToken(t, jwt.SigningMethodRS256, keys.otherRSA, "rsa-2", standardClaims())
	jwtRefused(t, hook(bearerRequest(replacement)), replacement)
	if got := idp.fetches(); got != 1 {
		t.Fatalf("a miss inside the refetch interval cost %d fetches, want 0 (refused from memory)", got)
	}

	// Past the interval, the same token earns the refetch (fetch two) and
	// verifies.
	time.Sleep(pastInterval)
	admitted(t, hook(bearerRequest(replacement)))
	if got := idp.fetches(); got != 2 {
		t.Fatalf("the post-interval rotation cost %d fetches, want exactly one refetch (2 total)", got)
	}

	// The old kid is gone from the served document, so the old token is
	// refused: inside the new interval, without a fetch (still 2)...
	jwtRefused(t, hook(bearerRequest(old)), old)
	if got := idp.fetches(); got != 2 {
		t.Fatalf("a refusal inside the interval cost %d fetches, want 0 more", got)
	}

	// ...and past it, one more refetch (fetch three) confirms the withdrawal,
	// then the verdict again.
	time.Sleep(pastInterval)
	jwtRefused(t, hook(bearerRequest(old)), old)
	if got := idp.fetches(); got != 3 {
		t.Fatalf("the post-interval confirmation cost %d fetches, want exactly one more (3 total)", got)
	}

	// A cached kid does not re-fetch: this request is answered from the cache.
	admitted(t, hook(bearerRequest(replacement)))
	if got := idp.fetches(); got != 3 {
		t.Fatalf("a cached kid re-fetched (%d fetches), want the cache to answer", got)
	}
}

// TestJWTValidationUnknownKidSprayFetchesOnce is the amplification bound,
// from the request side: the kid in a token is attacker-chosen, so the spray
// of invented kids an attacker can afford must not be answered with a fetch
// per request. A burst of fifty concurrent misses buys the IdP ONE fetch --
// the singleflight shares it and the interval refuses the rest -- and every
// token fails closed; a sequential spray over invented kids likewise costs
// one fetch total, because the interval is per-cache, global across
// connections; and past the interval exactly one refetch happens, which is
// the honest-rotation path.
func TestJWTValidationUnknownKidSprayFetchesOnce(t *testing.T) {
	keys := genTestKeys(t)

	newHookOver := func(t *testing.T, idp *testIdP) func(*http.Request) *rewriter.RequestVerdict {
		c, lg := compileRequest(t, reqPolicy(rule(ActionJWTValidation, nil, map[string]interface{}{
			"jwks_uri": idp.srv.URL,
			"issuer":   "https://idp.example",
			"audience": "my-endpoint",
		})))
		return c.RequestHook(lg, "1.2.3.4:1")
	}

	// hooksOverOnePolicy compiles the policy ONCE -- one compiled action, one
	// jwks cache, the shape production shares across connections -- and hands
	// back a distinct hook per connection. (Compiling per hook, as a first
	// draft of this test did, silently gives every connection its own cache,
	// and the burst fetches once per cache -- which is exactly the bug the
	// test exists to catch, so the compile happens here, where it cannot.)
	hooksOverOnePolicy := func(t *testing.T, idp *testIdP, n int) []func(*http.Request) *rewriter.RequestVerdict {
		c, lg := compileRequest(t, reqPolicy(rule(ActionJWTValidation, nil, map[string]interface{}{
			"jwks_uri": idp.srv.URL,
			"issuer":   "https://idp.example",
			"audience": "my-endpoint",
		})))
		hooks := make([]func(*http.Request) *rewriter.RequestVerdict, n)
		for i := range hooks {
			hooks[i] = c.RequestHook(lg, "1.2.3.4:1")
		}
		return hooks
	}

	t.Run("a burst of fifty concurrent unknown kids fetches once", func(t *testing.T) {
		idp := newTestIdP(t)
		idp.publish(t, keys.rsaJWK) // served set: does NOT name the sprayed kids

		const n = 50
		// one hook per goroutine over ONE compiled policy: a hook is one
		// connection (its eval state is per-connection), and the shared cache
		// across the connections is what the bound is on.
		hooks := hooksOverOnePolicy(t, idp, n)

		start := make(chan struct{})
		var wg sync.WaitGroup
		verdicts := make([]*rewriter.RequestVerdict, n)
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				tok := signToken(t, jwt.SigningMethodRS256, keys.rsaKey, fmt.Sprintf("invented-%d", i), standardClaims())
				verdicts[i] = hooks[i](bearerRequest(tok))
			}(i)
		}
		close(start)
		wg.Wait()

		if got := idp.fetches(); got != 1 {
			t.Fatalf("%d concurrent misses cost %d fetches, want exactly 1", n, got)
		}
		for i, v := range verdicts {
			if v == nil || v.Terminate == nil {
				t.Fatalf("invented kid %d was admitted: a miss must fail closed", i)
			}
		}
	})

	t.Run("a sequential spray over unknown kids fetches once", func(t *testing.T) {
		idp := newTestIdP(t)
		idp.publish(t, keys.rsaJWK)
		hook := newHookOver(t, idp)

		for i := 0; i < 50; i++ {
			tok := signToken(t, jwt.SigningMethodRS256, keys.rsaKey, fmt.Sprintf("invented-%d", i), standardClaims())
			jwtRefused(t, hook(bearerRequest(tok)), tok)
		}
		if got := idp.fetches(); got != 1 {
			t.Fatalf("50 sequential misses cost %d fetches, want exactly 1 (the interval is global per cache)", got)
		}
	})

	t.Run("past the interval a refetch happens", func(t *testing.T) {
		idp := newTestIdP(t)
		idp.publish(t, keys.rsaJWK)

		c, lg := compileRequest(t, reqPolicy(rule(ActionJWTValidation, nil, map[string]interface{}{
			"jwks_uri": idp.srv.URL,
			"issuer":   "https://idp.example",
			"audience": "my-endpoint",
		})))
		pastInterval := shortRefetchInterval(t, c)
		hook := c.RequestHook(lg, "1.2.3.4:1")

		miss := signToken(t, jwt.SigningMethodRS256, keys.rsaKey, "invented", standardClaims())
		jwtRefused(t, hook(bearerRequest(miss)), miss)
		if got := idp.fetches(); got != 1 {
			t.Fatalf("the first miss cost %d fetches, want 1", got)
		}

		jwtRefused(t, hook(bearerRequest(miss)), miss)
		if got := idp.fetches(); got != 1 {
			t.Fatalf("a miss inside the interval cost %d fetches, want still 1", got)
		}

		time.Sleep(pastInterval)
		jwtRefused(t, hook(bearerRequest(miss)), miss)
		if got := idp.fetches(); got != 2 {
			t.Fatalf("the post-interval miss cost %d fetches, want exactly one refetch (2 total)", got)
		}
	})
}

// TestJWTValidationJWKSURIRequiresHTTPSOffLoopback pins the transport rule:
// a JWKS is fetched over https, because the key document is the trust root
// and cleartext delivery makes it whatever the network path says. The one
// exception is loopback -- 127.0.0.0/8, ::1, "localhost" -- where a local
// test server may serve one over http. Anything that only looks local
// ("localhost.example.com") is refused like any other cleartext.
func TestJWTValidationJWKSURIRequiresHTTPSOffLoopback(t *testing.T) {
	cases := []struct {
		name    string
		uri     string
		wantErr string // empty: the config must be accepted
	}{
		{"https anywhere", "https://idp.example/jwks.json", ""},
		{"http off-loopback is refused", "http://idp.example/jwks.json", "must be an https URL"},
		{"http to a public IP is refused", "http://93.184.216.34/jwks.json", "must be an https URL"},
		{"http to a lookalike name is refused", "http://localhost.example.com/jwks.json", "must be an https URL"},
		{"http to a loopback IP is allowed", "http://127.0.0.1:9000/jwks.json", ""},
		{"http to another loopback IP is allowed", "http://127.5.6.7/jwks.json", ""},
		{"http to ::1 is allowed", "http://[::1]:9000/jwks.json", ""},
		{"http to localhost is allowed", "http://localhost/jwks.json", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := reqPolicy(rule(ActionJWTValidation, nil, map[string]interface{}{"jwks_uri": tc.uri}))
			err := doc.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("the config was refused:\n%v", err)
				}
				// compiling must stay network-free; this proves it
				if _, err := doc.Compile(); err != nil {
					t.Fatalf("compile:\n%v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error does not name the requirement.\n got: %v\nwant substring: %s", err, tc.wantErr)
			}
			if !strings.Contains(err.Error(), "loopback") {
				t.Fatalf("the error does not say loopback is the exception:\n%v", err)
			}
		})
	}
}

// TestJWTValidationRequiresExp pins the exp requirement: a token that cannot
// say when it dies is refused, under the fixed label -- an unexpirying bearer
// credential is exactly what this action exists to make impossible to admit
// by misconfiguration.
func TestJWTValidationRequiresExp(t *testing.T) {
	keys := genTestKeys(t)
	idp := newTestIdP(t)
	idp.publish(t, keys.rsaJWK)

	c, lg := compileRequest(t, reqPolicy(rule(ActionJWTValidation, nil, map[string]interface{}{
		"jwks_uri": idp.srv.URL,
		"issuer":   "https://idp.example",
		"audience": "my-endpoint",
	})))
	hook := c.RequestHook(lg, "1.2.3.4:1")

	claims := standardClaims()
	delete(claims, "exp")
	token := signToken(t, jwt.SigningMethodRS256, keys.rsaKey, "rsa-1", claims)
	jwtRefused(t, hook(bearerRequest(token)), token)

	logged := lg.lines(lg.info)
	if !strings.Contains(logged, "a required claim is missing") {
		t.Fatalf("the missing-exp refusal was not logged under its label:\n%s", logged)
	}
}

// TestJWTValidationFailsClosedWhenJWKSIsUnavailable is the fail-closed gate:
// with the JWKS unreachable, every request is refused, the fetch failure is
// logged once per connection, and nothing about the failure turns into an
// admission.
func TestJWTValidationFailsClosedWhenJWKSIsUnavailable(t *testing.T) {
	keys := genTestKeys(t)
	idp := newTestIdP(t)
	idp.publish(t, keys.rsaJWK)
	jwksURL := idp.srv.URL
	idp.srv.Close() // down before the first request: the cache was never filled

	c, lg := compileRequest(t, reqPolicy(rule(ActionJWTValidation, nil, map[string]interface{}{
		"jwks_uri": jwksURL,
	})))
	hook := c.RequestHook(lg, "1.2.3.4:1")

	token := signToken(t, jwt.SigningMethodRS256, keys.rsaKey, "rsa-1", standardClaims())
	jwtRefused(t, hook(bearerRequest(token)), token)
	jwtRefused(t, hook(bearerRequest(token)), token)

	logged := lg.lines(lg.warn)
	if !strings.Contains(logged, "JWKS fetch failed") {
		t.Fatalf("the fetch failure was not logged:\n%s", logged)
	}
	if n := strings.Count(logged, "JWKS fetch failed"); n != 1 {
		t.Fatalf("the fetch failure was logged %d times, want once per connection:\n%s", n, logged)
	}
	if strings.Contains(logged, token) {
		t.Fatalf("the log line carries the token:\n%s", logged)
	}
}

// TestJWTValidationLogsFixedLabels pins the logging rule across failure modes:
// whatever went wrong, the fixed labels are all the log ever says -- no raw
// token, no library error text.
func TestJWTValidationLogsFixedLabels(t *testing.T) {
	keys := genTestKeys(t)
	idp := newTestIdP(t)
	idp.publish(t, keys.rsaJWK)

	lg := &testLogger{}
	doc := reqPolicy(rule(ActionJWTValidation, nil, map[string]interface{}{
		"jwks_uri": idp.srv.URL,
		"issuer":   "https://idp.example",
		"audience": "my-endpoint",
	}))
	c, err := doc.Compile()
	if err != nil {
		t.Fatalf("compiling: %v", err)
	}
	hook := c.RequestHook(lg, "1.2.3.4:1")

	expired := standardClaims()
	expired["exp"] = time.Now().Add(-time.Hour).Unix()
	cases := map[string]string{
		"garbage":       "not-a-jwt",
		"expired":       signToken(t, jwt.SigningMethodRS256, keys.rsaKey, "rsa-1", expired),
		"bad-signature": signToken(t, jwt.SigningMethodRS256, keys.otherRSA, "rsa-1", standardClaims()),
	}
	for name, token := range cases {
		if v := hook(bearerRequest(token)); v == nil || v.Terminate == nil {
			t.Fatalf("%s: the token was admitted", name)
		}
	}

	logged := lg.lines(lg.info) + "\n" + lg.lines(lg.warn)
	for name, token := range cases {
		if strings.Contains(logged, token) {
			t.Fatalf("%s: the log carries the raw token:\n%s", name, logged)
		}
	}
	for _, want := range []string{"expired", "signature"} {
		if !strings.Contains(logged, want) {
			t.Fatalf("the log does not carry the %q fixed label:\n%s", want, logged)
		}
	}
}
