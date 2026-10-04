package policy

// The jwt-validation action: bearer-token requests judged against a JWKS --
// signature, registered claims, and any exact-match claims the policy config
// names -- with a 401 challenge for everything that does not pass.
//
// The shape of the security argument, since the pieces are scattered across
// two files: an attacker controls the token, and (if they can serve the
// jwks_uri's TLS name) the key document. Every step therefore refuses by
// default:
//
//   - the token's alg must be in the config's allowlist, and the allowlist the
//     config may name is itself fixed at {RS256,RS384,RS512,ES256,ES384,ES512,
//     EdDSA} -- "none" and every HMAC algorithm are outside it, so alg=none
//     and the sign-an-HS256-token-with-the-public-key confusion attack are
//     refused before any key is looked up;
//   - the key for a kid is refused unless its JWK key type (kty) matches the
//     algorithm family the token claims, so a document that labels an RSA key
//     as something else -- or a token whose alg disagrees with the key it
//     names -- fails at the lookup, with a reason, instead of at the
//     signature check without one;
//   - the JWKS itself must parse whole (jwks.go) or the cache keeps standing;
//     an unfetchable JWKS means every request 401s. That is fail-closed on
//     purpose: the endpoint exists to require these signatures, and answering
//     a request whose proof cannot be checked is exactly the failure the
//     action is deployed to prevent. The cost is stated plainly: an IdP outage
//     becomes an outage of the protected endpoint, with one warning line per
//     connection to say so.
//
// No token material ever reaches a log line or an error string. The library's
// errors are deliberately *not* formatted anywhere: jwt/v5's messages name the
// failed check, but the JSON layer under it can quote claim values, and a
// claim value is credential material. The failures are mapped to fixed labels
// (jwtFailureLabel) and only the label is emitted.

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"ngrok/rewriter"
)

// allowedJWTAlgorithms is the set a policy's `algorithms` allowlist is drawn
// from. It is deliberately all-asymmetric: every HMAC algorithm would need a
// shared secret configured here to verify anything honestly, and none is --
// which makes an allowlisted HS* nothing but an invitation to the confusion
// attack where the (public) RSA key is fed to the HMAC as its secret.
var allowedJWTAlgorithms = []string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "EdDSA"}

// jwtClaim is one exact-match requirement from the config's `claims` map: the
// claim must be present in the token, must be a string, and must equal this
// value byte for byte.
type jwtClaim struct {
	key   string
	value string
}

type jwtValidationAction struct {
	where    string     // the rule's identity, for the fetch-failure warning
	issuer   string     // required in the token when non-empty
	audience string     // required in the token when non-empty
	claims   []jwtClaim // sorted by key, so a refusal's claims are checked in a stable order

	parser *jwt.Parser
	keys   *jwksCache

	required *rewriter.SyntheticResponse // no bearer token on the request
	invalid  *rewriter.SyntheticResponse // a token that failed any check
}

// buildJWTValidation validates jwt-validation's config and builds its runtime:
//
//	jwks_uri: https://idp.example/.well-known/jwks.json
//	issuer: https://idp.example
//	audience: my-endpoint
//	algorithms: [RS256]        # default RS256; allowlist enforced
//	leeway_seconds: 30         # exp/nbf clock skew, default 0
//	claims:                    # optional exact-match required claims
//	  scope: tunnels:read
//
// Nothing here touches the network: compilation happens at policy load, and a
// fetch happens on the first request that needs a key. As with the other auth
// builders, the allowed-field check lives in buildAction's case.
func buildJWTValidation(where string, cfg map[string]interface{}) (*jwtValidationAction, error) {
	rawURI, ok := cfg["jwks_uri"]
	if !ok {
		return nil, fmt.Errorf("%s: config field \"jwks_uri\" is required", where)
	}
	uriStr, ok := rawURI.(string)
	if !ok {
		return nil, fmt.Errorf("%s: config field \"jwks_uri\" must be a string, got %s", where, typeName(rawURI))
	}
	uri, err := checkJWKSURI(where, uriStr)
	if err != nil {
		return nil, err
	}

	algs := []string{"RS256"}
	if v, ok := cfg["algorithms"]; ok {
		items, ok := asList(v)
		if !ok {
			return nil, fmt.Errorf("%s: config field \"algorithms\" must be a list of algorithm names, got %s", where, typeName(v))
		}
		if len(items) == 0 {
			return nil, fmt.Errorf("%s: config field \"algorithms\" must have at least one entry (an empty allowlist would refuse every token)", where)
		}
		algs = make([]string, 0, len(items))
		for i, item := range items {
			s, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("%s: config field \"algorithms\" entry %d must be a string, got %s", where, i, typeName(item))
			}
			if !contains(allowedJWTAlgorithms, s) {
				return nil, fmt.Errorf("%s: config field \"algorithms\" entry %d: %q is not an algorithm this build allows (it allows: %s)",
					where, i, s, strings.Join(allowedJWTAlgorithms, ", "))
			}
			if contains(algs, s) {
				return nil, fmt.Errorf("%s: config field \"algorithms\" entry %d: %q is listed twice", where, i, s)
			}
			algs = append(algs, s)
		}
	}

	var leeway time.Duration
	if v, ok := cfg["leeway_seconds"]; ok {
		n, ok := asInt(v)
		if !ok {
			return nil, fmt.Errorf("%s: config field \"leeway_seconds\" must be an integer, got %s", where, typeName(v))
		}
		if n < 0 {
			return nil, fmt.Errorf("%s: config field \"leeway_seconds\" is %d; a negative leeway would refuse tokens whose clock is merely ahead", where, n)
		}
		leeway = time.Duration(n) * time.Second
	}

	var claims []jwtClaim
	if v, ok := cfg["claims"]; ok {
		m, ok := asMap(v)
		if !ok {
			return nil, fmt.Errorf("%s: config field \"claims\" must be an object of claim name to exact value, got %s", where, typeName(v))
		}
		for _, key := range sortedKeys(m) {
			if err := checkExactMatchClaim(where, key); err != nil {
				return nil, err
			}
			val, ok := m[key].(string)
			if !ok {
				return nil, fmt.Errorf("%s: config field \"claims\" entry %q must be a string, got %s (exact match compares strings; registered claims are validated by their own fields)", where, key, typeName(m[key]))
			}
			claims = append(claims, jwtClaim{key: key, value: val})
		}
		sort.Slice(claims, func(i, j int) bool { return claims[i].key < claims[j].key })
	}

	action := &jwtValidationAction{
		where: where,
		keys:  newJWKSCache(uri),
		required: unauthorized(challengeHeader("WWW-Authenticate", `Bearer error="invalid_token"`),
			"jwt-validation: this endpoint requires a bearer token"),
		invalid: unauthorized(challengeHeader("WWW-Authenticate", `Bearer error="invalid_token"`),
			"jwt-validation: the bearer token is invalid"),
	}

	// The parser is built once and shared by every request every connection
	// serves: it is pure configuration (v5's Parser is stateless between
	// calls), and building it here is what makes "what the config said" and
	// "what the tokens are judged against" the same object.
	var opts []jwt.ParserOption
	opts = append(opts, jwt.WithValidMethods(algs))
	if v, ok := cfg["issuer"]; ok {
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("%s: config field \"issuer\" must be a string, got %s", where, typeName(v))
		}
		if s == "" {
			return nil, fmt.Errorf("%s: config field \"issuer\" is empty; omit it rather than require an issuer no token can carry", where)
		}
		action.issuer = s
		opts = append(opts, jwt.WithIssuer(s))
	}
	if v, ok := cfg["audience"]; ok {
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("%s: config field \"audience\" must be a string, got %s", where, typeName(v))
		}
		if s == "" {
			return nil, fmt.Errorf("%s: config field \"audience\" is empty; omit it rather than require an audience no token can carry", where)
		}
		action.audience = s
		opts = append(opts, jwt.WithAudience(s))
	}
	if leeway > 0 {
		opts = append(opts, jwt.WithLeeway(leeway))
	}
	action.parser = jwt.NewParser(opts...)

	return action, nil
}

func (v *jwtValidationAction) authenticate(req *http.Request, st *evalState) *rewriter.SyntheticResponse {
	raw, ok := bearerToken(req)
	if !ok {
		return v.required
	}

	tok, err := v.parser.ParseWithClaims(raw, jwt.MapClaims{}, func(t *jwt.Token) (interface{}, error) {
		return v.verifyKey(t, st)
	})
	if err != nil {
		// The library's error stays here: its JSON layer can quote claim
		// values, and a claim value is credential material. The log line and
		// the response body get a fixed label.
		st.info("jwt-validation: token rejected (%s)", jwtFailureLabel(err))
		return v.invalid
	}

	// The exact-match claims, checked after the signature: a claim comparison
	// before it would let an unverified token steer which rules match. A claim
	// that is present but not a string fails -- a non-string can never match a
	// string comparison, and silently coercing one would make the config's
	// "exact match" mean "loosely resembles".
	mc, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		return v.invalid
	}
	for _, c := range v.claims {
		got, ok := mc[c.key].(string)
		if !ok || got != c.value {
			st.info("jwt-validation: token rejected (claim %q does not match)", c.key)
			return v.invalid
		}
	}
	return nil
}

// verifyKey is the parser's keyfunc: it resolves the token's kid to a key from
// the JWKS cache, refetching once on a miss (rotation), and refuses the pair
// when the token's algorithm family and the key's type disagree.
func (v *jwtValidationAction) verifyKey(t *jwt.Token, st *evalState) (interface{}, error) {
	kid, _ := t.Header["kid"].(string)

	key, found := v.keys.byKid(kid)
	if !found {
		// One refetch, then this token is refused. The fetch's failure is
		// worth exactly one line per connection -- it is the "the IdP is down
		// and the endpoint is refusing everything" signal -- and it carries
		// the transport error, which names hosts and certificates but no
		// request material. A kid that stays unknown after a *successful*
		// fetch is quiet: a token with an invented kid is a routine event,
		// not an operational problem.
		if err := v.keys.fetch(); err != nil {
			st.warnOnceAbout(v.where, "traffic policy %s: JWKS fetch failed: %v; requests needing a key are refused", v.where, err)
			return nil, err
		}
		key, found = v.keys.byKid(kid)
		if !found {
			return nil, fmt.Errorf("the JWKS names no key for kid %q", kid)
		}
	}

	// The kty/alg cross-check. The signature check underneath would also fail
	// on a type mismatch (there is no rsa.Verify for an ECDSA key), but it
	// would fail as "signature is invalid" -- which reads as "wrong token"
	// when the truth is "the key document and the algorithm disagree", a
	// misconfiguration worth naming.
	if !algMatchesKeyType(t.Method.Alg(), key.kty) {
		return nil, fmt.Errorf("the token's algorithm %s does not match the key's type %s", t.Method.Alg(), key.kty)
	}
	return key.pub, nil
}

// algMatchesKeyType maps an allowlisted algorithm to the JWK kty that can
// carry its keys. RS* are RSA (RS1 is not allowlisted: RSASSA-PKCS1-v1_5 with
// SHA-1 is nobody's choice in a new document), ES* are elliptic-curve keys on
// the NIST curves, EdDSA is an Octet Key Pair.
func algMatchesKeyType(alg, kty string) bool {
	var want string
	switch {
	case strings.HasPrefix(alg, "RS"):
		want = "RSA"
	case strings.HasPrefix(alg, "ES"):
		want = "EC"
	case alg == "EdDSA":
		want = "OKP"
	}
	return want != "" && want == kty
}

// jwtFailureLabel maps a parse/validation failure to one fixed label, for the
// log line. The mapping is by errors.Is over jwt/v5's sentinel errors; the
// error itself is never formatted, for the reason in the file comment.
func jwtFailureLabel(err error) string {
	switch {
	case errors.Is(err, jwt.ErrTokenMalformed):
		return "malformed token"
	case errors.Is(err, jwt.ErrTokenSignatureInvalid):
		return "signature check failed"
	case errors.Is(err, jwt.ErrTokenExpired):
		return "token is expired"
	case errors.Is(err, jwt.ErrTokenNotValidYet), errors.Is(err, jwt.ErrTokenUsedBeforeIssued):
		return "token is not valid yet"
	case errors.Is(err, jwt.ErrTokenInvalidIssuer):
		return "issuer does not match"
	case errors.Is(err, jwt.ErrTokenInvalidAudience):
		return "audience does not match"
	case errors.Is(err, jwt.ErrTokenInvalidClaims):
		return "claims do not satisfy the config"
	case errors.Is(err, jwt.ErrTokenUnverifiable):
		return "token could not be verified"
	}
	return "token rejected"
}

// checkJWKSURI validates the jwks_uri config field: an absolute http(s) URL
// with a host, and no userinfo -- the fetch failure's log line carries the URL
// (an operator debugging a JWKS needs it), and a URL with an embedded
// "user:password@" would put a credential in that line. Refusing it at load
// is what makes logging the URL safe later.
func checkJWKSURI(where, raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: config field \"jwks_uri\": %q is not a URL: %v", where, raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("%s: config field \"jwks_uri\": %q must be an http or https URL", where, raw)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("%s: config field \"jwks_uri\": %q names no host", where, raw)
	}
	if u.User != nil {
		return nil, fmt.Errorf("%s: config field \"jwks_uri\": a userinfo component is refused (credentials do not belong in a URL)", where)
	}
	return u, nil
}

// checkExactMatchClaim refuses a `claims` entry that names a registered claim
// this action already validates through its own fields. `exp`, `nbf` and
// `iat` are numeric dates -- a string exact-match against them can only fail
// (the config would 401 every token, loudly but incomprehensibly), and `iss`/
// `aud` set through claims would duplicate the parser's own checks, so two
// disagreeing configs would have to be reconciled by reading the action's
// source. The error says which field to use instead.
func checkExactMatchClaim(where, key string) error {
	switch key {
	case "iss":
		return fmt.Errorf("%s: config field \"claims\": the \"iss\" claim is validated by the \"issuer\" field", where)
	case "aud":
		return fmt.Errorf("%s: config field \"claims\": the \"aud\" claim is validated by the \"audience\" field", where)
	case "exp", "nbf", "iat":
		return fmt.Errorf("%s: config field \"claims\": the %q claim is a numeric date validated on its own; exact match is for string claims", where, key)
	}
	return nil
}
