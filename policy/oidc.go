package policy

// The oidc action (SPEC-CLUSTER18): visitors of an edge-terminated tunnel are
// redirected through an OIDC provider's authorization-code + PKCE flow and
// admitted only with a valid session cookie, with the identity claims
// forwarded to the local service as headers.
//
// Unlike every other request-phase action, this one does not run in the
// rewriter hook. Its verdict has to survive three connections and two
// external round trips -- public client to the edge, the edge's redirect to
// the IdP, the IdP's redirect back to the callback -- and the hook machinery
// is shaped for one request on one connection: a proxy stream would be burned
// per unauthenticated visit and per callback, a hook's synthetic response
// ends the connection after itself (which a redirect survives, but which
// buys nothing), and the callback needs routing-layer interception the
// rewriter cannot do. So the action is compiled here, consumed pre-dispatch
// by the server (server/http.go, the seam where HttpAuth and connectVerdict
// already intercept), and SKIPPED by the hook: evalRequest's dispatch table
// deliberately has no case for ActionOIDC, and the authenticate method below
// -- a fixed 403 -- exists only so the compiled action can ride the
// compiledAction.auth storage slot. An engine that someday dispatches the
// action through a hook gets that fixed 403, fail-closed, rather than a
// silently unprotected endpoint.
//
// The seam is the spec's: the caller parses the first request's fields and
// hands them over with the scheme and request host (OIDCRequest); this side
// owns all of the crypto and all HTTP toward the IdP, and answers with
// exactly one verdict (OIDCVerdict) -- dispatch with injected headers, a
// synthetic 302 carrying cookies, a fixed 403, a fixed 503, or close. The
// caller renders the synthetic responses through the same path every other
// terminating action uses and never touches the IdP.
//
// The security shape, since it is spread over the whole file:
//
//   - Every failure is fail-closed and fixed-shaped. A discovery that cannot
//     be fetched or that names another issuer answers 503; a flow cookie,
//     state, nonce, ID token, allowed_domains or claims failure answers the
//     one fixed 403. No response body, log line, or error string carries
//     anything request- or token-derived: the responses are built at compile
//     time (the 302s' static parts) or from fixed strings, and the log lines
//     carry fixed labels -- the jwt.go discipline, for the same reason.
//   - The ID token is validated by the same machinery jwt-validation uses:
//     the asymmetric-only algorithm allowlist, exp required, iss = configured
//     issuer, aud = client_id, the kid resolved through the jwks.go cache
//     with its refetch throttle and singleflight, and the kty/alg
//     cross-check. The nonce is compared only after the signature verifies.
//   - No server-side session state. The flow cookie (one per authorization
//     attempt, 10-minute TTL) and the session cookie are HMAC-SHA256 signed
//     under a process-wide key -- signed, not encrypted: the identity claims
//     are the visitor's own and visible to them. The ID token itself never
//     enters a cookie; only the three claims the headers need do.
//   - The plaintext client secret is the one credential this package holds
//     past compile, because the token exchange needs it at runtime (the spec
//     states this divergence plainly). It resolves through the same
//     resolveCredential seam the digest actions use -- the REFERENCE travels
//     the registration wire, each side resolves against its own vaults -- and
//     it never reaches a log line, an error string, or a response.
//
// Reuse, not re-solve (the spec's objective 2): the token, discovery and
// JWKS HTTP paths copy jwks.go's bounded-client discipline -- a 10-second
// timeout, a 1 MiB body cap, redirects refused, non-200s refused -- the
// discovery cache adds the singleflight and the failure throttle jwks.go
// applies to unknown kids (a failed discovery is attacker-provocable in
// exactly the same way), and the constant-time compares use the
// fixed-length digest discipline of auth_actions.go's credential loop.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"ngrok/log"
	"ngrok/rewriter"
)

// ActionOIDC is the action type a policy document names. It is defined here,
// beside its runtime, rather than in policy.go's table, so that adding the
// action is one file: the validator's registry row lives in validate.go, the
// hook's dispatch table deliberately has no row for it, and this constant is
// the one name all three refer to.
const ActionOIDC = "oidc"

const (
	// defaultOIDCCallbackPath is the callback path an operator gets when the
	// config does not name one. The path is RESERVED for the whole endpoint:
	// requests to it never reach the local service (spec section 1).
	defaultOIDCCallbackPath = "/oauth2/callback"

	// defaultOIDCSessionSeconds and maxOIDCSessionSeconds bound
	// session_duration_seconds: an hour by default, a hard ceiling of one
	// day. Logout is cookie expiry, and a session that outlives a day is
	// exactly the "no revocation" behavior the spec says out loud; the
	// ceiling is what keeps a mistyped 360000 from shipping it.
	defaultOIDCSessionSeconds = 3600
	maxOIDCSessionSeconds     = 86400

	// oidcFlowTTL is the flow cookie's lifetime: long enough for a human to
	// come back from their provider's login page, short enough that a flow
	// begun and abandoned is dead weight for minutes, not hours.
	oidcFlowTTL = 10 * time.Minute

	// oidcDiscoveryTTL is how long a fetched discovery document is cached
	// per issuer. The document names the endpoints every flow needs; fetching
	// it per request would put the IdP on the data path twice per login.
	oidcDiscoveryTTL = 10 * time.Minute

	// oidcDiscoveryFailureTTL is the negative cache for a failed discovery
	// fetch. A first fetch that fails (or a poisoned one) must not be chased
	// once per visitor request: the discovery URL is config, not
	// attacker-chosen bytes, but an IdP outage plus a busy endpoint would
	// otherwise aim one bounded GET per request at it, paid for by this
	// process. It is jwks.go's refetch interval under another name; the
	// reasoning there (attempts, not successes, count) is why a failure
	// starts the clock too.
	oidcDiscoveryFailureTTL = 30 * time.Second

	// oidcMaxBodyBytes is the body cap for every document this action
	// fetches -- the discovery document and the token response, the same
	// class of thing jwks.go caps at its own maximum: a few KiB from an
	// honest issuer, and a growing body is an attack on this process's
	// memory, not a document.
	oidcMaxBodyBytes = maxJWKSBytes

	// oidcMinKeyBytes is the floor for a configured session key. HMAC-SHA256
	// wants a 32-byte key; an operator pasting a password into
	// oidc_session_key gets a startup refusal naming the minimum, not a
	// session cookie whose signing key a GPU grinds through.
	oidcMinKeyBytes = 32
)

const (
	// The two cookie names. Distinct names, one purpose each: the flow
	// cookie lives for one authorization attempt and is scoped to the
	// callback path; the session cookie lives for session_duration_seconds
	// and is scoped to the whole endpoint.
	oidcFlowCookieName    = "ngrok_oidc_flow"
	oidcSessionCookieName = "ngrok_oidc_session"

	// The header names the identity rides in on dispatch. Present only when
	// the token carried the claim (spec section 2).
	oidcUserHeader    = "X-Forwarded-User"
	oidcEmailHeader   = "X-Forwarded-Email"
	oidcPreferredUser = "X-Forwarded-Preferred-Username"
)

// The fixed bodies. Built at compile time; nothing request- or token-derived
// is ever formatted into one. The two 302 bodies are deliberately short: a
// browser follows the Location and renders none of it.
const (
	oidcBeginBody = "Redirecting to your identity provider..."
	oidcDoneBody  = "Authenticated. Redirecting..."

	// One refusal for every verification failure -- a forged flow cookie, a
	// state mismatch, a bad nonce, a refused domain, a failed exchange. Like
	// webhook.go's fixed 403, it does not teach a probing client which part
	// of its forgery was wrong.
	oidcRefusedBody = "oidc: authentication failed"

	// The one shape an IdP problem answers with. It says nothing about which
	// part was unreachable.
	oidcUnavailableBody = "oidc: the identity provider is unavailable; try again shortly"
)

// --- the session key ---------------------------------------------------------

// The process-wide session key, the SetVaults precedent (vault.go): process
// configuration, stored behind a pointer so compiles and decisions racing a
// test's re-install read one coherent value. Production sets it once at
// startup from the server config's oidc_session_key.
var (
	oidcKey          atomic.Pointer[[]byte]
	oidcKeyInstalled atomic.Bool
)

// SetOIDCSessionKey installs the process-wide key the OIDC flow and session
// cookies are signed with. Call it once, at startup, before any endpoint with
// an oidc policy serves traffic: a key installed later invalidates every
// cookie minted before it (they fail their MAC), and cookies minted under a
// generated key (below) do not survive the process.
//
// The key must be at least oidcMinKeyBytes bytes; anything shorter is a
// startup error naming the minimum, not a silently weak signing key. The
// same key fronting multiple ngrokds with one hostname keeps sessions valid
// across the nodes -- that, and surviving restarts, is the entire reason to
// configure one.
func SetOIDCSessionKey(key []byte) error {
	if len(key) < oidcMinKeyBytes {
		return fmt.Errorf("the oidc session key is %d bytes; at least %d are required (it signs every flow and session cookie)", len(key), oidcMinKeyBytes)
	}
	k := make([]byte, len(key))
	copy(k, key)
	oidcKey.Store(&k)
	oidcKeyInstalled.Store(true)
	return nil
}

// OIDCSessionKeyConfigured reports whether SetOIDCSessionKey has installed a
// key. False after startup means every OIDC endpoint in this process is
// signing under a key generated at first use -- sessions die with the
// process, which is the documented default but not something a caller should
// discover by accident.
func OIDCSessionKeyConfigured() bool {
	return oidcKeyInstalled.Load()
}

// oidcSessionKey returns the key in force, generating one on first use when
// no key was ever installed. The CAS makes the generation and its one INFO
// line happen exactly once per process, whatever the concurrency: the loser
// of the race adopts the winner's key.
func oidcSessionKey() []byte {
	if k := oidcKey.Load(); k != nil {
		return *k
	}
	raw := make([]byte, oidcMinKeyBytes)
	if _, err := rand.Read(raw); err != nil {
		// crypto/rand failing is a broken process, not a degraded one: every
		// credential this package compares and every cookie it signs assumes
		// these bytes.
		panic(fmt.Sprintf("policy oidc: the system random source failed: %v", err))
	}
	if oidcKey.CompareAndSwap(nil, &raw) {
		defaultLog.Info("traffic policy oidc: no session key was configured; generated a random one for this process (sessions will not survive a restart)")
		return raw
	}
	return *oidcKey.Load()
}

// --- the contract the server consumes ----------------------------------------

// OIDCRequest is the parsed first request of a connection, as the server
// hands it over: the fields the flow needs and nothing more. The server is
// the parser -- this type is deliberately not an *http.Request, because the
// pre-dispatch seam runs on a bounded head parser, not on net/http's.
//
// Every field is checked against the wire rule before it is used anywhere a
// response is built (a CR or LF in any of them closes the connection: this
// side does not trust the parser above it with response splitting), but the
// fields are otherwise taken as parsed -- Host exactly as it will be matched,
// lower-cased, with any port; Path with its leading slash; Query without its
// "?"; Cookie the raw Cookie header value, empty when there was none.
type OIDCRequest struct {
	// Method is the request's method. v1 does not branch on it -- every
	// method is authenticated the same way -- but the field is part of the
	// contract so that adding a branch is not a seam change.
	Method string

	// Path is the request path, with its leading slash.
	Path string

	// Query is the raw query string, without its "?" ("" when there is none).
	Query string

	// Cookie is the raw Cookie header value ("" when the request carried
	// none). Both cookies this action manages are read out of it.
	Cookie string

	// Scheme is the scheme the public client used: "https" or "http". It is
	// what the redirect_uri and the bound original URL are built from, so a
	// value outside those two is a closed connection, not a guess.
	Scheme string

	// Host is the request's Host, lower-cased, port kept as sent. It names
	// the endpoint in the redirect_uri, and it is what a flow cookie is
	// bound to: a code obtained for one host must not be redeemable on
	// another.
	Host string
}

// OIDCVerdictKind enumerates the one verdict per request this side returns.
type OIDCVerdictKind int

const (
	// OIDCDispatch: the request carries a valid session. The caller injects
	// Verdict.Headers into the replayed head and dispatches.
	OIDCDispatch OIDCVerdictKind = iota

	// OIDCRedirect: the caller sends Verdict.Response -- a 302 to the
	// provider's authorization endpoint (flow start) or back to the bound
	// original URL (flow completion) -- carrying the Set-Cookie headers this
	// side built. The connection ends with it, as every synthetic response
	// does.
	OIDCRedirect

	// OIDCForbidden: the caller sends Verdict.Response -- the fixed 403. One
	// shape for every verification failure, built at compile time.
	OIDCForbidden

	// OIDCUnavailable: the caller sends Verdict.Response -- the fixed 503.
	// The IdP could not be reached or refused to describe itself.
	OIDCUnavailable

	// OIDCClose: the caller closes the connection without a response. The
	// request head was unusable in a way no honest response fixes (no Host,
	// a scheme that is neither http nor https, control characters in a
	// field this side would have to echo).
	OIDCClose
)

func (k OIDCVerdictKind) String() string {
	switch k {
	case OIDCDispatch:
		return "dispatch"
	case OIDCRedirect:
		return "redirect"
	case OIDCForbidden:
		return "forbidden"
	case OIDCUnavailable:
		return "unavailable"
	case OIDCClose:
		return "close"
	}
	return "unknown"
}

// OIDCVerdict is the one answer per first request. Which fields mean
// something is decided by Kind, and the zero value is deliberately useless:
// a verdict nobody set a Kind on is not a dispatch.
type OIDCVerdict struct {
	Kind OIDCVerdictKind

	// Response is the synthetic response to send, for the three synthetic
	// kinds. The 302s carry their Location and Set-Cookie headers in it;
	// the 403 and 503 are this action's fixed, compile-time responses.
	// Nil for OIDCDispatch and OIDCClose.
	Response *rewriter.SyntheticResponse

	// Headers are the identity headers to inject into the replayed head for
	// OIDCDispatch, in the "Key: value" shape a rewriter verdict carries.
	// X-Forwarded-User is always present; the email and preferred-username
	// headers only when the token carried those claims, and only with
	// values that are legal header values.
	Headers []string
}

// --- the compiled settings ---------------------------------------------------

// OIDCSettings is the compiled runtime of one oidc action: everything the
// flow needs, resolved at compile time, shared by every connection the
// endpoint serves. The server reaches it through Compiled.OIDC.
//
// It holds the client secret in plaintext for the tunnel's lifetime -- the
// one credential this package keeps past compile, because the token exchange
// needs it at runtime. It is never logged, never rendered, and never placed
// in a response; the build that put it here validated it the way the digest
// actions validate what they digest.
type OIDCSettings struct {
	// where is the rule's identity ("on_http_request[0] (oidc)"), for the
	// log lines this action writes.
	where string

	// issuerRaw is the configured issuer, exactly as written; the discovery
	// document's issuer field must equal it or the document is refused.
	issuerRaw string
	// discoveryAddr is the issuer with the well-known path joined on,
	// precomputed at compile.
	discoveryAddr string

	clientID     string
	clientSecret string // plaintext; see the type comment
	scopes       []string
	callbackPath string
	sessionTTL   time.Duration
	// allowedDomains, when non-empty, is the post-verification check: the
	// token's hd claim or its email domain must be listed.
	allowedDomains []string
	// claims is the exact-match map, sorted by key -- jwt-validation's shape,
	// checked the same way after the signature verifies.
	claims []jwtClaim

	// parser validates the ID token: the asymmetric-only allowlist, exp
	// required, iss and aud pinned to this action's issuer and client_id.
	parser *jwt.Parser

	// refused and unavailable are the fixed verdicts, built once at compile.
	refused     *rewriter.SyntheticResponse
	unavailable *rewriter.SyntheticResponse

	// now is the clock, a field so the tests can freeze or advance it
	// instead of sleeping through TTLs (the minRefetchInterval precedent).
	now func() time.Time

	// Test seams for the discovery cache's TTLs, as jwksCache's
	// minRefetchInterval is for its throttle.
	discoveryTTL        time.Duration
	discoveryFailureTTL time.Duration

	// The discovery cache and the pinned JWKS, guarded by mu. The mutex is
	// held for bookkeeping, never for the network; a burst of first visits
	// shares one fetch (the singleflight) rather than each fetching.
	mu           sync.Mutex
	disc         *oidcDiscovery
	discAt       time.Time
	discErr      error
	discErrAt    time.Time
	discFetching bool
	discDone     chan struct{}
	// jwks is the key cache, built from the FIRST discovery document that
	// verified and pinned there: a later document naming a different
	// jwks_uri is a re-pointing of the trust root, and it is refused (the
	// pinned cache keeps verifying, fail-closed) until the process
	// restarts -- the same remedy the session key's rotation story states.
	jwks *jwksCache
	// jwksURI is the URI the cache was built from, kept beside it so the
	// pinning has something to compare a later document's jwks_uri against.
	jwksURI string
}

// Compiled.OIDC returns the compiled oidc action of this policy, or nil when
// the policy carries none -- the accessor the pre-dispatch seam consumes:
//
//	if s := compiled.OIDC(); s != nil {
//	    v := s.DecideHook(conn.Logger())(policy.OIDCRequest{...})
//	    ...
//	}
//
// A policy carries at most one (build refuses more, and refuses it with
// expressions: the action applies to the whole endpoint -- the callback path
// it reserves and the session key it signs under are not per-rule), so the
// scan below finds the one or finds none. The nil answer is the cheap path:
// every endpoint without the action pays one walk over its own request rules.
func (c *Compiled) OIDC() *OIDCSettings {
	if c == nil {
		return nil
	}
	for _, a := range c.request {
		if s, ok := a.auth.(*OIDCSettings); ok {
			return s
		}
	}
	return nil
}

// DecideHook binds the action to one connection: it returns the function the
// server calls exactly once, on the connection's first request, with the
// parsed head (spec: the first request on each connection decides; keep-alive
// requests on a dispatched connection ride the session established at its
// head). The returned function owns every branch -- session check, callback,
// flow start -- so the caller never learns what a callback is.
//
// lg receives this action's log lines: fixed labels for the refusals, and the
// IdP-unreachability warning once per connection (the JWKS discipline -- the
// transport error may name hosts and certificates, never request material).
//
// A nil receiver yields a function that always closes: there is no honest
// answer to give a request when there is no action, and installing the hook
// anyway is a wiring bug the answer should be loud about. A nil logger is
// replaced by the package's own.
func (s *OIDCSettings) DecideHook(lg log.Logger) func(OIDCRequest) OIDCVerdict {
	if s == nil {
		return func(OIDCRequest) OIDCVerdict { return OIDCVerdict{Kind: OIDCClose} }
	}
	if lg == nil {
		lg = defaultLog
	}
	st := &oidcState{lg: lg}
	return func(r OIDCRequest) OIDCVerdict { return s.decide(st, r) }
}

// authenticate puts OIDCSettings in the compiledAction.auth storage slot
// beside the other request-phase actions. It must never run -- the action is
// consumed pre-dispatch, and the hook's dispatch table has no case for it --
// and if an engine ever does dispatch it there, this is the fixed 403:
// fail-closed, never a no-op that would leave an endpoint that looks
// protected and is not.
func (s *OIDCSettings) authenticate(_ *http.Request, _ *evalState) *rewriter.SyntheticResponse {
	return s.refused
}

var _ authAction = (*OIDCSettings)(nil)

// buildOIDC validates the oidc action's config and builds its runtime:
//
//	issuer: https://accounts.google.com   # https, loopback-exempt
//	client_id: "....apps.googleusercontent.com"
//	client_secret: secret("main/google")  # vault-composable; inline allowed
//	scopes: [openid, email]               # default shown; openid is forced
//	                                      # first if the list omits it
//	callback_path: /oauth2/callback       # default shown; reserved endpoint-wide
//	session_duration_seconds: 3600        # (0, 86400]
//	allowed_domains: [example.com]        # optional post-verification check
//	claims: { hd: example.com }           # optional exact match
//
// Nothing here touches the network: compilation happens at policy load and
// at registration, and the first fetch happens on the first request that
// needs a session. As with every other action, the allowed-field check lives
// in buildAction's case.
func buildOIDC(where string, cfg map[string]interface{}) (*OIDCSettings, error) {
	rawIssuer, ok := cfg["issuer"]
	if !ok {
		return nil, fmt.Errorf("%s: config field \"issuer\" is required", where)
	}
	issuerStr, ok := rawIssuer.(string)
	if !ok {
		return nil, fmt.Errorf("%s: config field \"issuer\" must be a string, got %s", where, typeName(rawIssuer))
	}
	if err := checkIssuerURL(where, issuerStr); err != nil {
		return nil, err
	}

	clientID, err := requiredString(where, cfg, "client_id")
	if err != nil {
		return nil, err
	}

	rawSecret, ok := cfg["client_secret"]
	if !ok {
		return nil, fmt.Errorf("%s: config field \"client_secret\" is required", where)
	}
	secretRef, ok := rawSecret.(string)
	if !ok {
		return nil, fmt.Errorf("%s: config field \"client_secret\" must be a string, got %s", where, typeName(rawSecret))
	}
	// The vault seam, not a plain read: a whole-value secret("vault/key")
	// reference is resolved HERE, on each side, against the vaults that side
	// installed -- which is why the reference, never the plaintext, travels
	// the registration wire. The resolution happens before the shape checks,
	// so a vault-sourced secret obeys the same rules as the literal it
	// stands for.
	cred, err := resolveCredential(secretRef)
	if err != nil {
		return nil, fmt.Errorf("%s: config field \"client_secret\": %v", where, err)
	}
	prov := ""
	if cred.vault != "" {
		prov = fmt.Sprintf(" (vault %q key %q)", cred.vault, cred.key)
	}
	if cred.value == "" {
		return nil, fmt.Errorf("%s: config field \"client_secret\"%s is empty, which no token exchange could succeed with", where, prov)
	}
	if strings.ContainsAny(cred.value, "\r\n") {
		return nil, fmt.Errorf("%s: config field \"client_secret\"%s contains a CR or LF, which no client secret should carry", where, prov)
	}
	if strings.HasPrefix(cred.value, digestPrefix) {
		// A digest cannot authenticate anyone at the token endpoint: the
		// secret is sent AS the secret, not compared -- so the digest form is
		// refused, the same refusal webhook.go makes for its signing keys,
		// and on the resolved value, so it covers both an inline sha256:...
		// literal and a vault entry stored pre-digested (the credential
		// actions' convenience, which resolveCredential passes through).
		return nil, fmt.Errorf("%s: config field \"client_secret\"%s is a sha256: digest; the token exchange needs the plaintext client secret (a digest cannot authenticate the client)", where, prov)
	}

	scopes := []string{"openid", "email"}
	if v, ok := cfg["scopes"]; ok {
		items, ok := asList(v)
		if !ok {
			return nil, fmt.Errorf("%s: config field \"scopes\" must be a list of scope tokens, got %s", where, typeName(v))
		}
		scopes = nil
		for i, item := range items {
			s, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("%s: config field \"scopes\" entry %d must be a string, got %s", where, i, typeName(item))
			}
			if s == "" {
				return nil, fmt.Errorf("%s: config field \"scopes\" entry %d is empty", where, i)
			}
			// A scope travels as one space-joined token list in the
			// authorization request, so whitespace (and the control
			// characters that would survive URL-encoding into it) is refused
			// at load rather than silently splitting one scope into two.
			if strings.ContainsAny(s, " \t\r\n\"\\") {
				return nil, fmt.Errorf("%s: config field \"scopes\" entry %d carries a space, quote or control character; a scope is one token", where, i)
			}
			if contains(scopes, s) {
				return nil, fmt.Errorf("%s: config field \"scopes\" entry %d: %q is listed twice", where, i, s)
			}
			scopes = append(scopes, s)
		}
	}
	// openid forced first: the flow is OpenID Connect, and a provider asked
	// for scopes without it returns no id_token at all -- an endpoint that
	// 403s every login for a reason no error message names. An operator may
	// drop email and profile; they may not drop the scope that makes the
	// response an authentication.
	if !contains(scopes, "openid") {
		scopes = append([]string{"openid"}, scopes...)
	}

	callbackPath := defaultOIDCCallbackPath
	if v, ok := cfg["callback_path"]; ok {
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("%s: config field \"callback_path\" must be a string, got %s", where, typeName(v))
		}
		if !strings.HasPrefix(s, "/") {
			return nil, fmt.Errorf("%s: config field \"callback_path\" is %q; it must start with \"/\"", where, s)
		}
		if strings.ContainsAny(s, "?#") {
			return nil, fmt.Errorf("%s: config field \"callback_path\" may not carry a \"?\" or a \"#\": the code and state arrive as the query", where)
		}
		if strings.ContainsAny(s, "\r\n") {
			return nil, fmt.Errorf("%s: config field \"callback_path\" contains a CR or LF, which would split the cookie's Path attribute in two", where)
		}
		callbackPath = s
	}

	sessionTTL := defaultOIDCSessionSeconds
	if v, ok := cfg["session_duration_seconds"]; ok {
		n, ok := asInt(v)
		if !ok {
			return nil, fmt.Errorf("%s: config field \"session_duration_seconds\" must be an integer, got %s", where, typeName(v))
		}
		if n <= 0 {
			return nil, fmt.Errorf("%s: config field \"session_duration_seconds\" is %d; it must be positive (a session that never lives is no session)", where, n)
		}
		if n > maxOIDCSessionSeconds {
			return nil, fmt.Errorf("%s: config field \"session_duration_seconds\" is %d; the ceiling is %d (logout is cookie expiry in this build, and a session that outlives a day outlives its welcome)", where, n, maxOIDCSessionSeconds)
		}
		sessionTTL = n
	}

	var allowedDomains []string
	if v, ok := cfg["allowed_domains"]; ok {
		items, ok := asList(v)
		if !ok {
			return nil, fmt.Errorf("%s: config field \"allowed_domains\" must be a list of domain names, got %s", where, typeName(v))
		}
		if len(items) == 0 {
			return nil, fmt.Errorf("%s: config field \"allowed_domains\" is empty; omit it rather than refuse every identity", where)
		}
		for i, item := range items {
			s, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("%s: config field \"allowed_domains\" entry %d must be a string, got %s", where, i, typeName(item))
			}
			if s == "" {
				return nil, fmt.Errorf("%s: config field \"allowed_domains\" entry %d is empty", where, i)
			}
			allowedDomains = append(allowedDomains, s)
		}
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
	}

	s := &OIDCSettings{
		where:               where,
		issuerRaw:           issuerStr,
		discoveryAddr:       strings.TrimSuffix(issuerStr, "/") + "/.well-known/openid-configuration",
		clientID:            clientID,
		clientSecret:        cred.value,
		scopes:              scopes,
		callbackPath:        callbackPath,
		sessionTTL:          time.Duration(sessionTTL) * time.Second,
		allowedDomains:      allowedDomains,
		claims:              claims,
		now:                 time.Now,
		discoveryTTL:        oidcDiscoveryTTL,
		discoveryFailureTTL: oidcDiscoveryFailureTTL,
		refused: &rewriter.SyntheticResponse{
			StatusCode: http.StatusForbidden,
			Body:       oidcRefusedBody,
		},
		unavailable: &rewriter.SyntheticResponse{
			StatusCode: http.StatusServiceUnavailable,
			Body:       oidcUnavailableBody,
		},
	}

	// The ID-token parser, built once and shared by every callback: the
	// same construction jwt-validation uses, with this action's issuer and
	// client_id in the iss/aud seats and the asymmetric-only allowlist that
	// leaves alg=none and the HMAC confusion attack outside the door before
	// any key is looked up. exp is required: a login that cannot say when
	// its proof dies is not a login this endpoint accepts.
	s.parser = jwt.NewParser(
		jwt.WithValidMethods(allowedJWTAlgorithms),
		jwt.WithExpirationRequired(),
		jwt.WithIssuer(s.issuerRaw),
		jwt.WithAudience(s.clientID),
	)

	return s, nil
}

// requiredString reads one required non-empty string field, for the two
// identifiers (client_id) this action demands and names individually.
func requiredString(where string, cfg map[string]interface{}, field string) (string, error) {
	v, ok := cfg[field]
	if !ok {
		return "", fmt.Errorf("%s: config field %q is required", where, field)
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("%s: config field %q must be a string, got %s", where, field, typeName(v))
	}
	if s == "" {
		return "", fmt.Errorf("%s: config field %q is empty", where, field)
	}
	return s, nil
}

// checkIssuerURL applies checkJWKSURI's exact rule (jwt.go) to the issuer: an
// absolute https URL with a host and no userinfo, with the one transport
// exception for loopback http so a local test server can serve as its own
// provider. It is spelled out here rather than called because checkJWKSURI's
// error strings name the jwks_uri field; the rule is byte-identical, the
// field name is this one. The one addition is the query/fragment refusal: the
// well-known path is joined onto the issuer, and a URL with a query or a
// fragment cannot be joined onto sensibly -- a load error now instead of a
// discovery fetch that 404s at runtime.
func checkIssuerURL(where, raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%s: config field \"issuer\": %q is not a URL: %v", where, raw, err)
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && isLoopbackHost(u.Hostname())) {
		return fmt.Errorf("%s: config field \"issuer\": %q must be an https URL -- the discovery document fetched over http would trust whichever host answers the connection (only loopback hosts are exempt, so a local test server can serve as a provider)", where, raw)
	}
	if u.Host == "" {
		return fmt.Errorf("%s: config field \"issuer\": %q names no host", where, raw)
	}
	if u.User != nil {
		return fmt.Errorf("%s: config field \"issuer\": a userinfo component is refused (credentials do not belong in a URL)", where)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("%s: config field \"issuer\": a query or fragment is refused (the well-known discovery path is joined onto the issuer)", where)
	}
	return nil
}

// --- the decision ------------------------------------------------------------

// oidcState is the per-connection decision context: where the log lines go
// and the once-per-connection warning bookkeeping (the evalState rule: the
// same failure failing on every request is one line, not one per request).
type oidcState struct {
	lg     log.Logger
	warned map[string]bool
}

func (st *oidcState) info(format string, args ...interface{}) {
	st.lg.Info(format, args...)
}

func (st *oidcState) warnOnce(key, format string, args ...interface{}) {
	if st.warned == nil {
		st.warned = map[string]bool{}
	}
	if st.warned[key] {
		return
	}
	st.warned[key] = true
	st.lg.Warn(format, args...)
}

// decide is the whole action. The order is the flow's: a request to the
// reserved callback path is a flow completion even when it carries a session
// (the callback has its own answers); anything else is admitted by session or
// sent to the provider.
func (s *OIDCSettings) decide(st *oidcState, r OIDCRequest) OIDCVerdict {
	// The head fields are echoed into responses (the Location, the URL the
	// flow binds), so each is held to the wire rule first. A field that
	// fails it closes the connection: there is no response to build that
	// does not carry the bytes.
	if r.Host == "" || r.Path == "" || (r.Scheme != "https" && r.Scheme != "http") ||
		!rewriter.ValidHeaderValue(r.Host) || !rewriter.ValidHeaderValue(r.Path) ||
		!rewriter.ValidHeaderValue(r.Query) {
		st.info("oidc: the request head names no usable endpoint; closing")
		return OIDCVerdict{Kind: OIDCClose}
	}

	if r.Path == s.callbackPath {
		return s.callback(st, r)
	}

	if sess, ok := s.sessionOf(st, r.Cookie); ok {
		return OIDCVerdict{Kind: OIDCDispatch, Headers: identityHeaders(sess)}
	}

	return s.beginAuth(st, r)
}

// beginAuth starts a flow: fetch (or reuse) the provider's discovery
// document, mint the flow's secrets, bind them in one signed cookie, and
// send the visitor to the authorization endpoint.
func (s *OIDCSettings) beginAuth(st *oidcState, r OIDCRequest) OIDCVerdict {
	doc, err := s.discover(st)
	if err != nil {
		st.warnOnce("discovery", "traffic policy %s: discovery failed: %v; refusing with 503", s.where, err)
		return OIDCVerdict{Kind: OIDCUnavailable, Response: s.unavailable}
	}

	state := randomToken()
	nonce := randomToken()
	verifier := pkceVerifier()

	original := r.Scheme + "://" + r.Host + r.Path
	if r.Query != "" {
		original += "?" + r.Query
	}

	flow := flowCookie{
		State:    state,
		Nonce:    nonce,
		URL:      original,
		Host:     r.Host,
		Verifier: verifier,
		Exp:      s.now().Add(oidcFlowTTL).Unix(),
	}

	// The authorization request. url.Values encodes deterministically
	// (sorted keys), so the same flow always asks the same question the same
	// way -- and the redirect_uri here is the one the token exchange will
	// present, byte for byte, which is what PKCE's binding and the
	// provider's own redirect_uri check both assume.
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", s.clientID)
	q.Set("redirect_uri", s.redirectURI(r))
	q.Set("scope", strings.Join(s.scopes, " "))
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", pkceChallenge(verifier))
	q.Set("code_challenge_method", "S256")

	resp := &rewriter.SyntheticResponse{
		StatusCode: http.StatusFound,
		Headers: []string{
			"Location: " + doc.AuthorizationEndpoint + "?" + q.Encode(),
			setCookieLine(oidcFlowCookieName, signCookie(flow), s.callbackPath, int(oidcFlowTTL/time.Second)),
			"Cache-Control: no-store",
		},
		Body: oidcBeginBody,
	}
	return OIDCVerdict{Kind: OIDCRedirect, Response: resp}
}

// redirectURI is the callback's absolute URL on THIS endpoint: the scheme and
// host the visitor used plus the reserved path. The same string goes into the
// authorization request and the token exchange; the provider checks them
// against each other, and the flow cookie's host binding is what makes sure
// the host part has not changed between the two.
func (s *OIDCSettings) redirectURI(r OIDCRequest) string {
	return r.Scheme + "://" + r.Host + s.callbackPath
}

// callback completes a flow: the provider sent the visitor back with a code
// and the state we sent them out with. Every check refuses closed, and every
// refusal is the one fixed 403 under a fixed label -- the labels are the only
// record of which check failed, by design.
func (s *OIDCSettings) callback(st *oidcState, r OIDCRequest) OIDCVerdict {
	q, err := url.ParseQuery(r.Query)
	if err != nil {
		return s.refuse(st, "the callback query did not parse")
	}
	// The provider's own error reply (the visitor declined, the client is
	// unknown): refused like every other failure. The error code is the
	// provider's wording about the provider; none of it is echoed.
	if q.Get("error") != "" {
		return s.refuse(st, "the provider reported an authorization error")
	}

	flow := flowCookie{}
	raw := cookieValue(r.Cookie, oidcFlowCookieName)
	if raw == "" || !verifyCookie(raw, &flow) {
		return s.refuse(st, "the flow cookie is missing or was not signed by this endpoint")
	}
	if s.now().After(time.Unix(flow.Exp, 0)) {
		return s.refuse(st, "the flow cookie has expired")
	}
	// The host binding: a code obtained for one host must not be redeemable
	// on another -- the attacker's own hostname is a working redirect_uri
	// for a provider that registered this one, and the code is sent back
	// through the visitor's browser, which will go wherever the attacker
	// points it.
	if flow.Host != r.Host {
		return s.refuse(st, "the flow was begun on another host")
	}
	// The state, compared in constant time over fixed-length digests: the
	// attacker controls the query's copy, and the compare's running time
	// says nothing about how much of it matched (digestListMatches's
	// discipline).
	if !constantTimeEquals(q.Get("state"), flow.State) {
		return s.refuse(st, "the state does not match the flow")
	}
	code := q.Get("code")
	if code == "" {
		return s.refuse(st, "the callback carries no code")
	}

	doc, err := s.discover(st)
	if err != nil {
		st.warnOnce("discovery", "traffic policy %s: discovery failed: %v; refusing with 503", s.where, err)
		return OIDCVerdict{Kind: OIDCUnavailable, Response: s.unavailable}
	}

	rawToken, err := s.exchange(doc.TokenEndpoint, code, s.redirectURI(r), flow.Verifier)
	if err != nil {
		if s.isTransportError(err) {
			st.warnOnce("token", "traffic policy %s: the token endpoint could not be reached: %v; refusing with 503", s.where, err)
			return OIDCVerdict{Kind: OIDCUnavailable, Response: s.unavailable}
		}
		return s.refuse(st, "the token exchange failed")
	}

	claims, ok := s.validateIDToken(st, rawToken, flow.Nonce)
	if !ok {
		return s.refuse(st, "the identity token was refused")
	}

	sess, ok := s.mintSession(claims)
	if !ok {
		return s.refuse(st, "the identity token carries no subject")
	}

	// Back to where the visitor was headed, with the session set and the
	// flow cookie retired: it has done its one job, and a cookie left
	// behind is a second live proof for the same flow.
	resp := &rewriter.SyntheticResponse{
		StatusCode: http.StatusFound,
		Headers: []string{
			"Location: " + flow.URL,
			setCookieLine(oidcSessionCookieName, signCookie(sess), "/", int(s.sessionTTL/time.Second)),
			clearCookieLine(oidcFlowCookieName, s.callbackPath),
			"Cache-Control: no-store",
		},
		Body: oidcDoneBody,
	}
	return OIDCVerdict{Kind: OIDCRedirect, Response: resp}
}

// refuse logs one fixed label and answers the one fixed 403. Every
// verification failure in the flow goes through here, which is what makes
// the action's refusal a single shape no failure can vary.
func (s *OIDCSettings) refuse(st *oidcState, label string) OIDCVerdict {
	st.info("traffic policy %s: oidc refused (%s)", s.where, label)
	return OIDCVerdict{Kind: OIDCForbidden, Response: s.refused}
}

// isTransportError reports whether an exchange error means "could not reach
// the token endpoint" (the 503 class) rather than "the endpoint answered and
// refused this exchange" (the 403 class). exchange marks the difference on
// the error it returns; this side never inspects a transport error's text,
// which may name hosts and certificates -- the log line may carry it, the
// response may not.
type transportError struct{ err error }

func (e transportError) Error() string { return e.err.Error() }
func (e transportError) Unwrap() error { return e.err }

func (s *OIDCSettings) isTransportError(err error) bool {
	var te transportError
	return errors.As(err, &te)
}

// sessionOf reads and verifies the session cookie. A missing cookie is the
// common first-visit state and logs nothing; a cookie that is present but
// fails its MAC or its expiry is a forgery or a stale artifact and logs one
// INFO line -- either way the answer is the same: the visitor goes to the
// provider.
func (s *OIDCSettings) sessionOf(st *oidcState, cookieHeader string) (*sessionCookie, bool) {
	raw := cookieValue(cookieHeader, oidcSessionCookieName)
	if raw == "" {
		return nil, false
	}
	sess := sessionCookie{}
	if !verifyCookie(raw, &sess) {
		st.info("traffic policy %s: the session cookie was not signed by this endpoint", s.where)
		return nil, false
	}
	if s.now().After(time.Unix(sess.Exp, 0)) {
		st.info("traffic policy %s: the session cookie has expired", s.where)
		return nil, false
	}
	if sess.Sub == "" {
		st.info("traffic policy %s: the session cookie carries no subject", s.where)
		return nil, false
	}
	return &sess, true
}

// --- the cookies -------------------------------------------------------------

// flowCookie is the signed state of one authorization attempt. It is the
// only server-side storage a flow has -- signed, not encrypted: the visitor
// can read their own flow, and nothing in it helps them admit themselves.
// The Verifier is here because PKCE's proof must survive the round trip
// through the browser, and the visitor holding it is the design: the proof
// is what an attacker who intercepts only the code lacks.
type flowCookie struct {
	State    string `json:"state"`
	Nonce    string `json:"nonce"`
	URL      string `json:"url"`
	Host     string `json:"host"`
	Verifier string `json:"verifier"`
	Exp      int64  `json:"exp"`
}

// sessionCookie is the admitted identity. The Mint nonce makes every minted
// blob unique, so an identity maps to no single recognizable cookie value an
// observer could collect and replay -- the replay they could attempt is the
// cookie they already hold, which is the session.
type sessionCookie struct {
	Exp  int64  `json:"exp"`
	Sub  string `json:"sub"`
	Name string `json:"email,omitempty"`
	Pref string `json:"pref,omitempty"`
	Mint string `json:"mint"`
}

// signCookie renders a signed cookie value: base64url(JSON) "." base64url(
// HMAC-SHA256(key, payload)). The MAC covers the encoded payload -- the
// exact bytes on the wire -- so a value cannot be re-split or re-ordered
// under the signature.
func signCookie(v interface{}) string {
	raw, err := json.Marshal(v)
	if err != nil {
		// Both payloads are fixed-shape structs of strings and an int; this
		// cannot fail short of a broken runtime. A panic here would take a
		// connection down, so it is a fixed-value cookie instead -- which
		// verifies for nothing, fail-closed.
		return "0.0"
	}
	payload := base64.RawURLEncoding.EncodeToString(raw)
	return payload + "." + signPayload(payload)
}

// verifyCookie checks a cookie value's MAC in constant time (hmac.Equal)
// and decodes the payload into v. Anything malformed -- no dot, a bad
// base64, a MAC that is not this key's, a payload that is not this shape --
// is false, and the caller refuses. The MACs are compared in their encoded
// form: both sides are fixed-length base64url strings, so the compare has
// the same constant-time property one decode earlier.
func verifyCookie(value string, v interface{}) bool {
	payload, macB64, ok := strings.Cut(value, ".")
	if !ok {
		return false
	}
	if !hmac.Equal([]byte(signPayload(payload)), []byte(macB64)) {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return false
	}
	return json.Unmarshal(raw, v) == nil
}

// signPayload is the MAC of one cookie payload under the session key.
func signPayload(payload string) string {
	mac := hmac.New(sha256.New, oidcSessionKey())
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// setCookieLine renders one Set-Cookie header for a minted cookie. HttpOnly
// keeps it away from any script on the page; SameSite=Lax is what lets the
// provider's top-level redirect bring it back; Max-Age mirrors the signed
// expiry so the browser stops offering the cookie before the MAC check
// would refuse it.
func setCookieLine(name, value, path string, maxAge int) string {
	return fmt.Sprintf("Set-Cookie: %s=%s; Path=%s; Max-Age=%d; HttpOnly; SameSite=Lax", name, value, path, maxAge)
}

// clearCookieLine retires one cookie: same name and path, empty value, an
// expired Max-Age -- the spelling that makes a browser drop it.
func clearCookieLine(name, path string) string {
	return fmt.Sprintf("Set-Cookie: %s=; Path=%s; Max-Age=0; HttpOnly; SameSite=Lax", name, path)
}

// cookieValue reads one cookie out of a raw Cookie header, by net/http's
// own parser: the header is the one thing on the wire with a grammar fiddly
// enough (quoted values, escaped semicolons) that hand-splitting it is how
// parsers drift.
func cookieValue(header, name string) string {
	if header == "" {
		return ""
	}
	req := &http.Request{Header: http.Header{}}
	req.Header.Add("Cookie", header)
	c, err := req.Cookie(name)
	if err != nil {
		return ""
	}
	return c.Value
}

// --- the identity ------------------------------------------------------------

// mintSession lifts the three identity claims out of the verified token.
// The ID token itself goes no further than this call: the session carries
// the claims, not the token -- a cookie holding a second bearer credential
// (the token) would make every cookie theft a token theft.
func (s *OIDCSettings) mintSession(mc jwt.MapClaims) (*sessionCookie, bool) {
	sub, _ := mc["sub"].(string)
	if sub == "" {
		return nil, false
	}
	email, _ := mc["email"].(string)
	pref, _ := mc["preferred_username"].(string)
	return &sessionCookie{
		Exp:  s.now().Add(s.sessionTTL).Unix(),
		Sub:  sub,
		Name: email,
		Pref: pref,
		Mint: randomToken(),
	}, true
}

// identityHeaders renders the dispatch headers. Each claim is present only
// when the token carried it, and each value is held to the wire rule: a
// claim is IdP-chosen bytes, and a CR or LF inside one would ride the header
// straight into the replayed request head.
func identityHeaders(sess *sessionCookie) []string {
	var out []string
	if sess.Sub != "" && rewriter.ValidHeaderValue(sess.Sub) {
		out = append(out, oidcUserHeader+": "+sess.Sub)
	}
	if sess.Name != "" && rewriter.ValidHeaderValue(sess.Name) {
		out = append(out, oidcEmailHeader+": "+sess.Name)
	}
	if sess.Pref != "" && rewriter.ValidHeaderValue(sess.Pref) {
		out = append(out, oidcPreferredUser+": "+sess.Pref)
	}
	return out
}

// domainsOK is the allowed_domains post-verification check: with a list
// configured, the token's hd claim or its email's domain must be listed.
// Domains compare case-insensitively (both are DNS names in practice); the
// list's spelling is the operator's, and this is a check, not a rendering.
func (s *OIDCSettings) domainsOK(mc jwt.MapClaims) bool {
	if len(s.allowedDomains) == 0 {
		return true
	}
	if hd, _ := mc["hd"].(string); hd != "" && domainListed(s.allowedDomains, hd) {
		return true
	}
	if email, _ := mc["email"].(string); email != "" {
		if i := strings.LastIndex(email, "@"); i >= 0 && domainListed(s.allowedDomains, email[i+1:]) {
			return true
		}
	}
	return false
}

func domainListed(domains []string, d string) bool {
	for _, want := range domains {
		if strings.EqualFold(want, d) {
			return true
		}
	}
	return false
}

// --- the IdP: discovery, exchange, token validation ---------------------------

// oidcDiscovery is the slice of the provider metadata document (OpenID
// Connect Discovery 1.0) this action uses.
type oidcDiscovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// oidcHTTPClient is the bounded client every fetch in this file uses. The
// discipline is jwks.go's, verbatim: a 10-second timeout (a slow IdP must
// not park the visitor), and redirects refused -- an endpoint's authority is
// not transferable, and the default client's ten hops would follow it
// anywhere. Non-200s and over-long bodies are refused by the callers.
var oidcHTTPClient = &http.Client{
	Timeout: jwksFetchTimeout,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// discover returns the provider metadata for this action's issuer, cached
// per issuer with a TTL. The fetch is bounded (oidcHTTPClient, 1 MiB cap)
// and the document is refused whole unless it names this action's issuer and
// carries three usable endpoints: a metadata document is the trust root this
// action fetches by itself, and one that does not describe the issuer the
// operator configured describes someone else.
//
// The cache adds the two bounds jwks.go pins on its own fetch path, for the
// same reasons:
//
//   - singleflight: a burst of first visits shares one fetch instead of one
//     fetch per visitor;
//   - a failure TTL: a failed attempt starts a clock, and fetches inside it
//     are refused from memory -- attempts count, not successes, or a hostile
//     (or merely down) endpoint failing on demand would leave the clock
//     untouched and put one bounded GET per request back on sale.
//
// A failed refresh never discards the last good document: an IdP that goes
// down after serving metadata once keeps serving logins from the cached
// document -- the same "the old cache keeps standing" rule jwks.go applies
// to keys, with the same fail-closed consequence that a document never
// served means every visitor is refused.
func (s *OIDCSettings) discover(st *oidcState) (*oidcDiscovery, error) {
	s.mu.Lock()
	now := s.now()
	if s.disc != nil && now.Sub(s.discAt) < s.discoveryTTL {
		d := s.disc
		s.mu.Unlock()
		return d, nil
	}
	if s.discFetching {
		done := s.discDone
		s.mu.Unlock()
		<-done

		// Share the result, the way jwksCache.refetch's waiters do: the
		// fetch that just finished recorded what it saw before closing the
		// channel, and no new fetch can start inside the failure TTL of it.
		s.mu.Lock()
		d, err := s.disc, s.discErr
		s.mu.Unlock()
		if d != nil {
			return d, nil
		}
		return nil, err
	}
	if !s.discErrAt.IsZero() && now.Sub(s.discErrAt) < s.discoveryFailureTTL {
		ago := now.Sub(s.discErrAt).Round(time.Second)
		s.mu.Unlock()
		return nil, fmt.Errorf("discovery was attempted %s ago and failed; it is refused without another fetch (the minimum between attempts is %s)", ago, s.discoveryFailureTTL)
	}

	s.discFetching = true
	done := make(chan struct{})
	s.discDone = done
	s.mu.Unlock()

	d, err := s.fetchDiscovery()
	// A fetched document is only as good as its trust root: binding the JWKS
	// here (pin on first sight, refuse a re-point afterwards) makes a
	// re-pointed document fail exactly like a fetch failure, so the stale-doc
	// and failure-TTL handling below covers both alike.
	if err == nil {
		if berr := s.bindJWKS(d); berr != nil {
			d, err = nil, berr
		}
	}

	s.mu.Lock()
	s.discFetching = false
	if err != nil {
		// A document that stood keeps standing, and its TTL is NOT renewed:
		// the next visitor inside the failure TTL is refused from memory,
		// and one past it earns a refetch attempt.
		s.discErrAt = s.now()
		s.discErr = err
		stale := s.disc
		s.mu.Unlock()
		// The singleflight channel closes on every path: the waiters parked
		// on it are answered by the state this branch just recorded, and a
		// channel left open here would park them forever.
		close(done)
		if stale != nil {
			st.warnOnce("discovery-refresh", "traffic policy %s: discovery refresh failed (%v); the last good document keeps serving", s.where, err)
			return stale, nil
		}
		return nil, err
	}
	s.disc = d
	s.discAt = s.now()
	s.discErr = nil
	s.mu.Unlock()
	close(done)
	return d, nil
}

// fetchDiscovery gets and judges one metadata document. Every refusal here
// is the whole document refused: half a description of an issuer is not a
// description of the issuer.
func (s *OIDCSettings) fetchDiscovery() (*oidcDiscovery, error) {
	var doc oidcDiscovery
	if err := oidcGetJSON(s.discoveryAddr, &doc); err != nil {
		return nil, err
	}
	if doc.Issuer != s.issuerRaw {
		// The comparison is exact: the operator's spelling is what the
		// document must repeat. The document's value is not echoed back --
		// it is whatever answered the fetch, and the refusal's job is to
		// say that the two disagree, not to quote the stranger.
		return nil, fmt.Errorf("the discovery document does not name the configured issuer; the document is refused")
	}
	for field, endpoint := range map[string]*string{
		"authorization_endpoint": &doc.AuthorizationEndpoint,
		"token_endpoint":         &doc.TokenEndpoint,
		"jwks_uri":               &doc.JWKSURI,
	} {
		if err := checkIDPEndpoint(field, *endpoint); err != nil {
			return nil, err
		}
	}
	return &doc, nil
}

// checkIDPEndpoint validates one endpoint URL out of a fetched discovery
// document: absolute, a host, no userinfo, and https -- with the same
// loopback exception as everywhere else, because the fake IdP a test (or a
// curious operator) stands up serves http from 127.0.0.1. The document is
// the IdP's own description of itself, fetched over the TLS name the
// operator configured, so the endpoints get no second look beyond "can this
// be fetched without leaking": a userinfo component would ride the endpoint
// into the discovery-failure log line, and a fragment cannot travel.
func checkIDPEndpoint(field, raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("the discovery document's %s is not a URL", field)
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && isLoopbackHost(u.Hostname())) {
		return fmt.Errorf("the discovery document's %s is not an https URL", field)
	}
	if u.Host == "" {
		return fmt.Errorf("the discovery document's %s names no host", field)
	}
	if u.User != nil {
		return fmt.Errorf("the discovery document's %s carries userinfo", field)
	}
	if u.Fragment != "" {
		return fmt.Errorf("the discovery document's %s carries a fragment", field)
	}
	return nil
}

// oidcGetJSON is the bounded GET every document fetch uses: the shared
// client's timeout and redirect refusal, a non-200 refused without reading
// the body (an error page is not a document), the body capped at 1 MiB --
// read one byte past the cap so a body of exactly the cap is
// distinguishable from an over-long one -- and a JSON decode into dst. The
// error names the failure class and, where the URL matters for debugging, is
// the transport error's own text: that names the configured issuer's host,
// which the operator already knows, and no request material.
func oidcGetJSON(addr string, dst interface{}) error {
	resp, err := oidcHTTPClient.Get(addr)
	if err != nil {
		return transportError{fmt.Errorf("fetching %s: %w", addr, err)}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("the endpoint answered with status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, oidcMaxBodyBytes+1))
	if err != nil {
		return transportError{fmt.Errorf("reading the response: %w", err)}
	}
	if len(body) > oidcMaxBodyBytes {
		return fmt.Errorf("the response body is larger than %d bytes", oidcMaxBodyBytes)
	}
	if err := json.Unmarshal(body, dst); err != nil {
		return fmt.Errorf("parsing the response: %v", err)
	}
	return nil
}

// exchange trades the code for the token response: one bounded POST, form
// encoded, the client secret in the body it belongs in. The transport
// failure is marked as such (the 503 class); everything else -- a non-200,
// an unparseable body, a response with no id_token -- is this exchange
// failing, the 403 class: an expired or replayed code answers exactly the
// same as an IdP misconfiguration, and neither is the visitor's way in.
func (s *OIDCSettings) exchange(tokenEndpoint, code, redirectURI, verifier string) (string, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {s.clientID},
		"client_secret": {s.clientSecret},
		"code_verifier": {verifier},
	}
	req, err := http.NewRequest("POST", tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("the token endpoint is not a usable URL")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := oidcHTTPClient.Do(req)
	if err != nil {
		return "", transportError{fmt.Errorf("posting to the token endpoint: %w", err)}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("the token endpoint answered with status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, oidcMaxBodyBytes+1))
	if err != nil {
		return "", transportError{fmt.Errorf("reading the token response: %w", err)}
	}
	if len(body) > oidcMaxBodyBytes {
		return "", fmt.Errorf("the token response is larger than %d bytes", oidcMaxBodyBytes)
	}
	var tok struct {
		IDToken string `json:"id_token"`
	}
	if err := json.Unmarshal(body, &tok); err != nil {
		return "", fmt.Errorf("parsing the token response: %v", err)
	}
	if tok.IDToken == "" {
		return "", fmt.Errorf("the token response carries no id_token")
	}
	return tok.IDToken, nil
}

// validateIDToken runs the verified token through every check the flow
// needs, in order: the parser's (signature against the JWKS, the
// asymmetric-only allowlist, exp required, iss, aud), then the nonce -- only
// after the signature, so an unverified token never steers anything -- then
// the exact-match claims, then allowed_domains. Each failure logs its fixed
// label and refuses; the labels are jwtFailureLabel's for the parser's
// checks, so a refused login and a refused bearer token read the same way
// in the log.
func (s *OIDCSettings) validateIDToken(st *oidcState, raw, nonce string) (jwt.MapClaims, bool) {
	tok, err := s.parser.ParseWithClaims(raw, jwt.MapClaims{}, func(t *jwt.Token) (interface{}, error) {
		return s.tokenKey(t, st)
	})
	if err != nil {
		// The library's error stays here: its text can quote claim values,
		// and a claim value is identity material. The label is what the log
		// gets (jwt.go's rule).
		st.info("traffic policy %s: the identity token was refused (%s)", s.where, jwtFailureLabel(err))
		return nil, false
	}
	mc, ok := tok.Claims.(jwt.MapClaims)
	if !ok {
		st.info("traffic policy %s: the identity token was refused (claims are not a map)", s.where)
		return nil, false
	}
	if got, _ := mc["nonce"].(string); !constantTimeEquals(got, nonce) {
		st.info("traffic policy %s: the identity token was refused (the nonce does not match the flow)", s.where)
		return nil, false
	}
	for _, c := range s.claims {
		got, ok := mc[c.key].(string)
		if !ok || got != c.value {
			st.info("traffic policy %s: the identity token was refused (claim %q does not match)", s.where, c.key)
			return nil, false
		}
	}
	if !s.domainsOK(mc) {
		st.info("traffic policy %s: the identity token was refused (the identity's domain is not allowed)", s.where)
		return nil, false
	}
	return mc, true
}

// tokenKey is the parser's keyfunc, jwt-validation's verifyKey over the
// JWKS this action pinned from its discovery document: the kid resolves
// through the cache, a miss earns one throttled refetch (the cache owns the
// singleflight and the interval), and the algorithm family must agree with
// the key's type. The kid is attacker-chosen bytes; every bound that makes
// that survivable lives in jwks.go and is reused, not re-solved here.
func (s *OIDCSettings) tokenKey(t *jwt.Token, st *oidcState) (interface{}, error) {
	keys := s.pinnedJWKS()
	if keys == nil {
		// Unreachable from the flow (validation runs only after a discovery
		// that pinned the cache), but a nil map would panic instead of
		// refusing, and refusing is the only honest answer to a key question
		// asked before any key was fetched.
		return nil, fmt.Errorf("no key set has been fetched for this issuer")
	}

	kid, _ := t.Header["kid"].(string)
	key, found := keys.byKid(kid)
	if !found {
		if err := keys.refetch(); err != nil {
			st.warnOnce("jwks", "traffic policy %s: JWKS fetch failed: %v; tokens needing a key are refused", s.where, err)
			return nil, err
		}
		key, found = keys.byKid(kid)
		if !found {
			return nil, fmt.Errorf("the JWKS names no key for kid %q", kid)
		}
	}
	if !algMatchesKeyType(t.Method.Alg(), key.kty) {
		return nil, fmt.Errorf("the token's algorithm %s does not match the key's type %s", t.Method.Alg(), key.kty)
	}
	return key.pub, nil
}

// pinnedJWKS returns the key cache, building it from the discovery document
// when no cache stands yet. A cache, once built, is pinned: a later document
// naming a different jwks_uri is refused (one warning per connection), and
// the pinned cache keeps verifying -- fail-closed against a re-pointed trust
// root, which is what a changed jwks_uri is. Key ROTATION needs no such
// drama: the cache's own refetch discipline picks up new keys at the same
// URI.
func (s *OIDCSettings) pinnedJWKS() *jwksCache {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.jwks
}

// bindJWKS is the discovery path's half of the pinning: called with a
// verified document, it builds the cache on first sight and refuses to
// re-point it afterwards. The refusal travels to the caller of discover,
// which answers 503 -- the provider changed its own description into one
// this endpoint cannot act on.
func (s *OIDCSettings) bindJWKS(doc *oidcDiscovery) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.jwks != nil {
		if s.jwksURI != doc.JWKSURI {
			return fmt.Errorf("the discovery document names a different jwks_uri than the one this endpoint pinned; the document is refused")
		}
		return nil
	}
	u, err := url.Parse(doc.JWKSURI)
	if err != nil {
		return fmt.Errorf("the discovery document's jwks_uri does not parse")
	}
	s.jwks = newJWKSCache(u)
	s.jwksURI = doc.JWKSURI
	return nil
}

// constantTimeEquals compares two secrets' SHA-256 digests: fixed length,
// constant time, the auth_actions.go discipline for credential compares.
func constantTimeEquals(a, b string) bool {
	da := sha256.Sum256([]byte(a))
	db := sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(da[:], db[:]) == 1
}

// --- randomness and PKCE -------------------------------------------------------

// randomToken is one 128-bit random value, base64url: the state, the nonce,
// the mint marker. 128 bits is past the birthday bound for any realistic
// login volume, and 22 characters keep every payload it rides small.
func randomToken() string {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		panic(fmt.Sprintf("policy oidc: the system random source failed: %v", err))
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

// pkceVerifier is RFC 7636's code_verifier: 32 random bytes, base64url --
// 43 characters of [A-Za-z0-9_-], inside the grammar's 43-128.
func pkceVerifier() string {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		panic(fmt.Sprintf("policy oidc: the system random source failed: %v", err))
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

// pkceChallenge is RFC 7636's S256 challenge: base64url(SHA256(verifier)),
// no padding. The proof of possession the token exchange presents is the
// verifier; the challenge is what the authorization request publishes, and
// a code intercepted on the way back is worthless without the verifier that
// stays in the signed flow cookie.
func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
