package policy

// The JWKS client jwt-validation uses to fetch the keys it verifies signatures
// with (RFC 7517). It is deliberately small and deliberately paranoid, because
// everything it refuses has to be refused *closed*: a JWKS this client cannot
// parse is an endpoint that 401s every request, not an endpoint that trusts
// whoever is listening on the other end of the URL.
//
// The constraints, and why they are what they are:
//
//   - The fetch is bounded twice: a 10s client timeout (a slow IdP must not
//     park the request that needed the key), and a 1 MiB body cap (a JWKS for
//     one issuer is a few KiB; a body growing past 1 MiB is an attack on the
//     memory of the process serving policy, not a key set).
//   - Keys are cached by kid, and an unknown kid earns exactly one refetch --
//     that is key rotation (the IdP published a new key after we cached), and
//     after the refetch an unknown kid is a refused token, not another fetch.
//     Each request refetches at most once, so an attacker spraying invented
//     kids buys one bounded HTTPS GET per request, never a loop.
//   - The refetched set replaces the cached one wholesale, on purpose: a
//     rotation that removes a kid should stop trusting that kid the moment the
//     IdP's document does. A merged cache would keep verifying with a key the
//     issuer has withdrawn, which is the one direction a cache must never
//     drift in.
//   - The cache is bounded at 32 keys, enforced at parse: a JWKS naming more
//     is refused whole rather than truncated, because a truncated cache would
//     401 kids the issuer did publish and nobody would ever connect that to
//     the cap.
//   - Symmetric keys ("kty":"oct") are refused at parse, before they can ever
//     reach a signature check. There is no honest use for a shared secret in a
//     fetched key set, and a symmetric entry is the raw material of the
//     classic algorithm-confusion attacks this action exists to make
//     impossible (jwt.go checks the key *type* against the token's alg again
//     at verification time, so a document that lies about kty still loses).
//
// Concurrency: one compiled policy is shared by every connection using it, so
// one cache is hit from several rewriter goroutines. The mutex covers the map
// only; the network fetch runs outside it, so a slow IdP does not serialize
// every request through this action. The cost of that choice: concurrent
// requests missing the same just-rotated kid may each fetch once. Each still
// fetches at most once, the fetches are bounded, and the last complete parse
// wins the cache -- correctness does not depend on who wins.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"sync"
	"time"
)

const (
	// jwksFetchTimeout bounds one fetch, start to body.
	jwksFetchTimeout = 10 * time.Second

	// maxJWKSBytes bounds the response body; read one byte past the cap so a
	// body of exactly the cap is distinguishable from an over-long one.
	maxJWKSBytes = 1 << 20

	// maxCachedKeys is the cache bound. See the file comment: enforced at
	// parse, not by eviction.
	maxCachedKeys = 32

	// minRSABits is the floor below which an RSA key in a fetched JWKS is
	// refused. 2048 is the smallest size still treated as safe for new
	// signatures; a document offering less is misconfigured or hostile, and
	// either way the honest answer is to refuse it loudly at parse instead of
	// verifying against a key everyone can factor.
	minRSABits = 2048
)

// cachedKey is one JWK in the form verification needs: the public key, plus
// the kty it claims, which jwt-validation cross-checks against the token's alg
// (a signature check with a key of the wrong type fails anyway, but the
// explicit check is what turns the confusion into a named refusal at the
// lookup instead of an opaque signature error after it).
type cachedKey struct {
	pub crypto.PublicKey
	kty string
}

// jwksCache is the key set of one jwks_uri: fetched, parsed, and cached by
// kid. Build one with newJWKSCache; jwt-validation owns the refetch policy.
type jwksCache struct {
	uri    *url.URL
	client *http.Client

	mu   sync.Mutex
	keys map[string]cachedKey
}

func newJWKSCache(uri *url.URL) *jwksCache {
	return &jwksCache{
		uri: uri,
		client: &http.Client{
			Timeout: jwksFetchTimeout,
			// A JWKS endpoint has no business redirecting to somewhere else
			// with the endpoint's authority; the default client follows up to
			// 10 hops and this is a document, not a page: one hop, no cookies,
			// no referer, nothing to leak.
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		keys: map[string]cachedKey{},
	}
}

// byKid looks a key up by the token's kid. A token with no kid can only be
// judged against a document carrying exactly one key -- with two, the choice
// would be a guess, and verification by guess is not verification -- so the
// empty kid is answered only when the answer is unambiguous.
func (c *jwksCache) byKid(kid string) (cachedKey, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if kid != "" {
		k, ok := c.keys[kid]
		return k, ok
	}
	if len(c.keys) == 1 {
		for _, k := range c.keys {
			return k, true
		}
	}
	return cachedKey{}, false
}

// fetch gets the document, parses it, and -- only if every key in it parsed --
// replaces the cache with it. A failed fetch leaves the old cache standing:
// the request that triggered it is refused by its caller, but the keys the
// issuer published yesterday keep verifying the requests that still use them.
func (c *jwksCache) fetch() error {
	resp, err := c.client.Get(c.uri.String())
	if err != nil {
		return fmt.Errorf("fetching the JWKS: %w", err)
	}
	defer resp.Body.Close()

	// A non-200 is refused without reading the body: an error page is not a
	// key set, and draining it buys nothing.
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("the JWKS endpoint answered with status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes+1))
	if err != nil {
		return fmt.Errorf("reading the JWKS: %w", err)
	}
	if len(body) > maxJWKSBytes {
		return fmt.Errorf("the JWKS body is larger than %d bytes", maxJWKSBytes)
	}

	keys, err := parseJWKS(body)
	if err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.keys = keys
	return nil
}

// parseJWKS converts a JWKS document to the by-kid map that replaces the
// cache. Every key in the document must parse for the document to be used:
// a partial cache would be a silent disagreement with what the issuer
// published, and the document that produced it is broken enough to refuse.
func parseJWKS(body []byte) (map[string]cachedKey, error) {
	var doc struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("parsing the JWKS: %w", err)
	}
	if len(doc.Keys) == 0 {
		return nil, fmt.Errorf("the JWKS carries no keys")
	}
	if len(doc.Keys) > maxCachedKeys {
		return nil, fmt.Errorf("the JWKS carries %d keys; the cache holds at most %d", len(doc.Keys), maxCachedKeys)
	}

	keys := make(map[string]cachedKey, len(doc.Keys))
	for i, k := range doc.Keys {
		pub, err := k.publicKey()
		if err != nil {
			return nil, fmt.Errorf("the JWKS's key %d (kid %q): %w", i, k.Kid, err)
		}
		if _, dup := keys[k.Kid]; dup {
			return nil, fmt.Errorf("the JWKS carries two keys named kid %q", k.Kid)
		}
		keys[k.Kid] = cachedKey{pub: pub, kty: k.Kty}
	}
	return keys, nil
}

// jwk is one JSON Web Key, narrowed to the fields this client understands.
type jwk struct {
	Kty string `json:"kty"` // key type: RSA, EC, OKP -- oct is refused below
	Kid string `json:"kid"` // key id; may be empty
	Crv string `json:"crv"` // EC / OKP curve
	N   string `json:"n"`   // RSA modulus
	E   string `json:"e"`   // RSA exponent
	X   string `json:"x"`   // EC x coordinate, OKP public key
	Y   string `json:"y"`   // EC y coordinate
}

// publicKey converts a JWK to the crypto.PublicKey a signature check needs.
// Every refusal here is a JWKS this client will not fetch twice: the caller
// throws the whole document away when any key refuses, so these errors are
// load-bearing for the fail-closed property.
func (j jwk) publicKey() (crypto.PublicKey, error) {
	switch j.Kty {
	case "RSA":
		n, err := decodeJWKInt(j.N)
		if err != nil {
			return nil, fmt.Errorf("bad RSA modulus: %w", err)
		}
		e, err := decodeJWKInt(j.E)
		if err != nil {
			return nil, fmt.Errorf("bad RSA exponent: %w", err)
		}
		if !e.IsInt64() || e.Int64() < 2 || e.Int64() > int64(^uint(0)>>1) {
			return nil, fmt.Errorf("RSA exponent %s does not fit an int or is not a usable public exponent", j.E)
		}
		if n.BitLen() < minRSABits {
			return nil, fmt.Errorf("the RSA key is %d bits; fewer than %d is refused", n.BitLen(), minRSABits)
		}
		return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil

	case "EC":
		var curve elliptic.Curve
		switch j.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported EC curve %q", j.Crv)
		}
		x, err := decodeJWKInt(j.X)
		if err != nil {
			return nil, fmt.Errorf("bad EC x coordinate: %w", err)
		}
		y, err := decodeJWKInt(j.Y)
		if err != nil {
			return nil, fmt.Errorf("bad EC y coordinate: %w", err)
		}
		// The point is what an attacker controls if they control the JWKS; the
		// on-curve check is what keeps an off-curve point from becoming a key
		// this client verifies with (invalid-curve attacks spend their effort
		// exactly here).
		if !curve.IsOnCurve(x, y) {
			return nil, fmt.Errorf("the EC point is not on %s", j.Crv)
		}
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil

	case "OKP":
		if j.Crv != "Ed25519" {
			return nil, fmt.Errorf("unsupported OKP curve %q", j.Crv)
		}
		x, err := base64.RawURLEncoding.DecodeString(j.X)
		if err != nil {
			return nil, fmt.Errorf("bad Ed25519 public key: %w", err)
		}
		if len(x) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("the Ed25519 public key is %d bytes, want %d", len(x), ed25519.PublicKeySize)
		}
		return ed25519.PublicKey(x), nil

	case "oct":
		return nil, fmt.Errorf("a symmetric key (kty oct) has no place in a fetched key set and is refused")

	default:
		return nil, fmt.Errorf("unsupported key type %q", j.Kty)
	}
}

// decodeJWKInt decodes a JWK's Base64urlUInt field (RFC 7518 section 6.3) --
// base64url without padding, big-endian, no leading zero octets -- as a big
// integer.
func decodeJWKInt(s string) (*big.Int, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("empty value")
	}
	return new(big.Int).SetBytes(raw), nil
}
