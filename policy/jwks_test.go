package policy

// Tests for the JWKS client itself, below the jwt-validation action: what a
// document must look like to be believed, what the fetch is allowed to spend,
// and the fact that every refusal leaves the previous key set standing.
//
// These drive newJWKSCache directly against httptest servers, so each refusal
// is tested against exactly the bytes that cause it rather than through a
// fixture that also involves a token.

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// rsaKey2048 is generated once for the package's JWKS tests; the keys these
// tests feed the parser do not need to be secret, they need to be *shaped*
// like real ones.
var rsaKey2048 = func() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err) // only reachable if crypto/rand is broken
	}
	return k
}()

// serveJWKS serves the given document bytes verbatim, with a status. The
// verbatim part is the point: these tests are about how the client reads a
// document, so the test controls every byte.
func serveJWKS(t *testing.T, status int, body []byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// mustFetch runs one fetch and reports whether it failed, failing the test on
// surprises either way.
func mustFetch(t *testing.T, c *jwksCache) error {
	t.Helper()
	return c.fetch()
}

func TestJWKSCacheFetchesAndCachesByKid(t *testing.T) {
	doc := fmt.Sprintf(`{"keys":[%s,%s,%s]}`,
		jwkDoc(rsaJWK(&rsaKey2048.PublicKey, "rsa-1")),
		jwkDoc(ecJWK(&mustECKey.PublicKey, "ec-1")),
		jwkDoc(okpJWK(mustEdKey.Public().(ed25519.PublicKey), "ed-1")))
	srv := serveJWKS(t, http.StatusOK, []byte(doc))

	c := newJWKSCache(mustURL(t, srv))
	if err := mustFetch(t, c); err != nil {
		t.Fatalf("fetch: %v", err)
	}

	for kid, kty := range map[string]string{"rsa-1": "RSA", "ec-1": "EC", "ed-1": "OKP"} {
		key, ok := c.byKid(kid)
		if !ok {
			t.Fatalf("kid %q was not cached", kid)
		}
		if key.kty != kty {
			t.Fatalf("kid %q cached with kty %q, want %q", kid, key.kty, kty)
		}
		if key.pub == nil {
			t.Fatalf("kid %q cached with no key", kid)
		}
	}
	if _, ok := c.byKid("rsa-404"); ok {
		t.Fatal("an unknown kid resolved")
	}
}

// TestJWKSCacheBoundsTheBody pins the 1 MiB cap. The document is junk, but the
// size check must fire before the parser ever sees it -- and the error should
// say which bound tripped, so the message distinguishes this from a JSON
// error.
func TestJWKSCacheBoundsTheBody(t *testing.T) {
	big := make([]byte, maxJWKSBytes+16)
	for i := range big {
		big[i] = 'a'
	}
	srv := serveJWKS(t, http.StatusOK, big)

	c := newJWKSCache(mustURL(t, srv))
	err := mustFetch(t, c)
	if err == nil {
		t.Fatal("an over-cap body was fetched")
	}
	if !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("the error does not name the size bound: %v", err)
	}

	// A body exactly at the cap is inside the bound (it then fails JSON
	// parsing, which is the check after -- either error proves the size check
	// did not eat the exact-cap case).
	exact := make([]byte, maxJWKSBytes)
	for i := range exact {
		exact[i] = 'a'
	}
	srv = serveJWKS(t, http.StatusOK, exact)
	c = newJWKSCache(mustURL(t, srv))
	if err := mustFetch(t, c); err == nil {
		t.Fatal("a cap-sized junk document was accepted")
	} else if strings.Contains(err.Error(), "larger than") {
		t.Fatalf("a body exactly at the cap was refused for size: %v", err)
	}
}

func TestJWKSCacheRefusesNon200(t *testing.T) {
	srv := serveJWKS(t, http.StatusServiceUnavailable, []byte(`{"keys":[]}`))
	c := newJWKSCache(mustURL(t, srv))
	err := mustFetch(t, c)
	if err == nil {
		t.Fatal("a 503 document was accepted")
	}
	if !strings.Contains(err.Error(), "503") {
		t.Fatalf("the error does not name the status: %v", err)
	}
}

func TestJWKSCacheRefusesMalformedDocuments(t *testing.T) {
	for _, tt := range []struct {
		name string
		body string
		want string
	}{
		{"not JSON", "not json at all", "parsing the JWKS"},
		{"no keys", `{"keys":[]}`, "carries no keys"},
		{"keys not a list", `{"keys":{}}`, "cannot unmarshal"},
		{"two keys with one kid", `{"keys":[{"kty":"RSA","kid":"k","n":"` + b64(n2048()) + `","e":"AQAB"},{"kty":"RSA","kid":"k","n":"` + b64(n2048()) + `","e":"AQAB"}]}`, "two keys named kid"},
		{"symmetric key", `{"keys":[{"kty":"oct","kid":"s","k":"a2V5"}]}`, "symmetric key"},
		{"unknown kty", `{"keys":[{"kty":"fancy","kid":"f"}]}`, "unsupported key type"},
		{"tiny RSA", `{"keys":[{"kty":"RSA","kid":"r","n":"` + b64(n1024()) + `","e":"AQAB"}]}`, "fewer than"},
		{"RSA without an exponent", `{"keys":[{"kty":"RSA","kid":"r","n":"` + b64(n2048()) + `"}]}`, "bad RSA exponent"},
		{"EC point off the curve", `{"keys":[{"kty":"EC","kid":"e","crv":"P-256","x":"` + b64([]byte{1}) + `","y":"` + b64([]byte{2}) + `"}]}`, "not on P-256"},
		{"unsupported curve", `{"keys":[{"kty":"EC","kid":"e","crv":"secp256k1","x":"` + b64([]byte{1}) + `","y":"` + b64([]byte{2}) + `"}]}`, "unsupported EC curve"},
		{"Ed25519 key of the wrong size", `{"keys":[{"kty":"OKP","kid":"o","crv":"Ed25519","x":"` + b64([]byte{1, 2, 3}) + `"}]}`, "want 32"},
		{"over the key cap", overCapKeys(), "cache holds at most"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			srv := serveJWKS(t, http.StatusOK, []byte(tt.body))
			c := newJWKSCache(mustURL(t, srv))
			err := mustFetch(t, c)
			if err == nil {
				t.Fatalf("%q was accepted", tt.name)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error does not name the reason.\n got: %v\nwant substring: %s", err, tt.want)
			}
			// A refused document must leave nothing behind to verify with.
			if _, ok := c.byKid(""); ok {
				t.Fatal("a refused document left keys in the cache")
			}
		})
	}
}

// TestJWKSCacheKeepsTheOldKeysWhenARefetchFails is the property that makes the
// refetch-on-unknown-kid policy safe: a fetch that fails (here, mid-rotation,
// with the IdP answering 500) leaves the previous key set verifying traffic.
// Failures close the *request*, never the cache.
func TestJWKSCacheKeepsTheOldKeysWhenARefetchFails(t *testing.T) {
	status := http.StatusOK
	good := []byte(`{"keys":[{"kty":"RSA","kid":"k","n":"` + b64(n2048()) + `","e":"AQAB"}]}`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		w.Write(good)
	}))
	t.Cleanup(srv.Close)

	c := newJWKSCache(mustURL(t, srv))
	if err := mustFetch(t, c); err != nil {
		t.Fatalf("first fetch: %v", err)
	}

	status = http.StatusInternalServerError
	if err := mustFetch(t, c); err == nil {
		t.Fatal("a failed refetch reported success")
	}
	if _, ok := c.byKid("k"); !ok {
		t.Fatal("a failed refetch wiped the previous key set")
	}
}

// TestJWKSCacheReplacesWholesaleOnRotation: after a successful refetch, a kid
// the new document does not name is gone from the cache. A merged cache would
// keep trusting a withdrawn key.
func TestJWKSCacheReplacesWholesaleOnRotation(t *testing.T) {
	docs := [][]byte{
		[]byte(`{"keys":[{"kty":"RSA","kid":"old","n":"` + b64(n2048()) + `","e":"AQAB"}]}`),
		[]byte(`{"keys":[{"kty":"RSA","kid":"new","n":"` + b64(n2048()) + `","e":"AQAB"}]}`),
	}
	i := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(docs[i])
	}))
	t.Cleanup(srv.Close)

	c := newJWKSCache(mustURL(t, srv))
	if err := mustFetch(t, c); err != nil {
		t.Fatalf("first fetch: %v", err)
	}
	if _, ok := c.byKid("old"); !ok {
		t.Fatal("the first document's kid is not cached")
	}

	i = 1
	if err := mustFetch(t, c); err != nil {
		t.Fatalf("second fetch: %v", err)
	}
	if _, ok := c.byKid("old"); ok {
		t.Fatal("the withdrawn kid is still cached")
	}
	if _, ok := c.byKid("new"); !ok {
		t.Fatal("the rotated kid is not cached")
	}
}

// TestJWKSCacheConcurrentUse exists for -race: one compiled policy is shared
// by every connection, so the cache is hit from several goroutines at once.
func TestJWKSCacheConcurrentUse(t *testing.T) {
	good := []byte(`{"keys":[{"kty":"RSA","kid":"k","n":"` + b64(n2048()) + `","e":"AQAB"}]}`)
	srv := serveJWKS(t, http.StatusOK, good)
	c := newJWKSCache(mustURL(t, srv))

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				if _, ok := c.byKid("k"); !ok {
					_ = c.fetch()
				}
			}
		}()
	}
	wg.Wait()
	if err := mustFetch(t, c); err != nil {
		t.Fatalf("final fetch: %v", err)
	}
}

// TestJWKSCacheDoesNotFollowRedirects: a JWKS URL must not silently hand its
// authority to wherever a 3xx points. The client surfaces the redirect as the
// non-200 it is, and the request fails closed.
func TestJWKSCacheDoesNotFollowRedirects(t *testing.T) {
	srv := serveJWKS(t, http.StatusOK, []byte(`{"keys":[]}`))
	redirecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srv.URL, http.StatusFound)
	}))
	t.Cleanup(redirecting.Close)

	c := newJWKSCache(mustURL(t, redirecting))
	err := mustFetch(t, c)
	if err == nil {
		t.Fatal("a redirect was followed to a document")
	}
	if !strings.Contains(err.Error(), "302") {
		t.Fatalf("the error does not name the redirect status: %v", err)
	}
}

// --- small fixtures -----------------------------------------------------------

var mustECKey = func() *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return k
}()

var mustEdKey = func() ed25519.PrivateKey {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return priv
}()

// jwkDoc marshals a rendered JWK map back to compact JSON, so the documents
// above can be built from the same helpers the jwt tests use.
func jwkDoc(m map[string]interface{}) string {
	b, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func overCapKeys() string {
	keys := make([]string, maxCachedKeys+1)
	for i := range keys {
		keys[i] = `{"kty":"RSA","kid":"k` + fmt.Sprint(i) + `","n":"` + b64(n2048()) + `","e":"AQAB"}`
	}
	return `{"keys":[` + strings.Join(keys, ",") + `]}`
}

// n2048/n1024 are fixed RSA-shaped moduli (random bytes with the top bit set,
// 2048/1024 bits): the parser only reads the bit length here, and generating
// two more real keys for that would spend seconds of test time.
func n2048() []byte { return modulusWithTopBit(256) }
func n1024() []byte { return modulusWithTopBit(128) }

func modulusWithTopBit(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7 + 1)
	}
	b[0] |= 0x80
	return b
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func mustURL(t *testing.T, srv *httptest.Server) *url.URL {
	t.Helper()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parsing the test server's URL: %v", err)
	}
	return u
}
