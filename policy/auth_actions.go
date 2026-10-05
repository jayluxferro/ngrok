package policy

// The request-phase authentication actions that check a static credential:
// basic-auth, bearer-auth and apikey-auth (jwt-validation lives in jwt.go and
// shares the challenge-building and bearer-parsing helpers here).
//
// The three actions are one shape with different plumbing, which is why they
// share this file: read one header, compare what it carries against the
// configured credentials, answer a 401 with the scheme's challenge or admit
// the request as a no-op. Everything that could differ badly between them --
// the comparison discipline, the refusal of CR/LF, the shape of the synthetic
// response -- is written once here.
//
// The comparison discipline, since it is the part worth saying twice: every
// credential is compared as a SHA-256 digest with crypto/subtle's
// ConstantTimeCompare, which is server/auth.go's own pattern for the session
// secrets (tokenDigest/tokenMatches) lifted into the policy engine. Digesting
// first means the two byte strings handed to the constant-time compare are
// always the same length (64 hex characters), so the compare's running time
// says nothing about how long any configured credential is, and it means a
// compiled policy carries digests where it can -- a heap dump of a running
// edge does not contain the credentials. The loop over the configured
// credentials never short-circuits: it ORs every comparison's result and runs
// to the end, so the time to a refusal is the same whether the match sat in
// entry one or was never there.
//
// Credential entries may also come from a vault (SPEC-CLUSTER9 3): a
// whole-value secret("vault/key") reference in the config is resolved inside
// credentialList, which is the seam between "read the config's shape" and
// "digest for comparison" -- the last point at which a credential exists as
// plaintext. Both sides of the protocol resolve there, each against the
// vaults its own configuration installed (vault.go): the client at load, the
// server at registration, identically, and a vault the server lacks fails the
// registration loudly rather than standing up an endpoint that enforces less
// than its document says.

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/textproto"
	"strings"

	"ngrok/rewriter"
)

// authAction is the runtime half of a request-phase authentication action. The
// validator builds one per rule at load time (buildAction stores it on the
// compiled action); evalRequest asks it to judge every matching request.
//
// authenticate returns nil to admit the request -- the action is then a no-op
// and later rules proceed -- or the synthetic response the client is answered
// with: the 401 challenge for the credential actions, the fixed 403 for
// webhook-verification (webhook.go), which implements this interface too.
// An implementation must never place credential material (a password, a
// token, a key, a JWT, or a fragment of any of them) in the response or in a
// log line: the responses are built once, at load time, from static strings,
// and the logging goes through the evalState so that the package's
// once-per-connection discipline covers it too.
type authAction interface {
	authenticate(req *http.Request, st *evalState) *rewriter.SyntheticResponse
}

// --- shared parsing and comparison -----------------------------------------

// schemeAndValue splits an Authorization-style header value into its scheme
// and the value after it, at exactly one space, both parts required non-empty.
//
// The strictness is deliberate and it is cheap to defend: a client that sends
// "Basic  abcd" (two spaces) or "Bearer" with nothing after it has sent a
// header this engine cannot read, and the challenge -- sent again -- is the
// correct answer to a malformed credential header in every one of these
// schemes. RFC 7617 would allow runs of spaces before Basic's credentials;
// this build answers those with the challenge too, which no compliant client
// ever sees.
func schemeAndValue(header string) (scheme, value string, ok bool) {
	scheme, value, found := strings.Cut(header, " ")
	if !found || scheme == "" || value == "" {
		return "", "", false
	}
	return scheme, value, true
}

// credentialDigest is the comparison form of one credential (see the file
// comment): hex-encoded SHA-256, the exact shape server/auth.go's
// tokenDigest produces for a "sha256:"-prefixed session secret.
func credentialDigest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// digestListMatches reports whether candidate equals any of the configured
// credentials, given as their digests. It iterates the whole list: there is no
// early return to leak how far into the list a match sat, and no length
// signal, because every compared pair is a fixed-length digest.
func digestListMatches(digests []string, candidate string) bool {
	got := credentialDigest(candidate)
	match := 0
	for _, want := range digests {
		match |= subtle.ConstantTimeCompare([]byte(want), []byte(got))
	}
	return match == 1
}

// unauthorized builds the synthetic 401 the auth actions answer with. The
// body names what failed in a fixed string chosen at load time; nothing that
// varies with the request is ever formatted into one, which is what keeps
// credential material out of the verdict's string forms by construction.
func unauthorized(headers []string, body string) *rewriter.SyntheticResponse {
	return &rewriter.SyntheticResponse{
		StatusCode: http.StatusUnauthorized,
		Headers:    headers,
		Body:       body,
	}
}

// challengeHeader renders one "Name: value" entry, the shape a
// rewriter.SyntheticResponse carries headers in.
func challengeHeader(name, value string) []string {
	return []string{name + ": " + value}
}

// --- basic-auth --------------------------------------------------------------

// defaultBasicRealm is what basic-auth answers with when its config does not
// name a realm -- ngrok's documented default.
const defaultBasicRealm = "ngrok"

type basicAuthAction struct {
	digests []string // of each "user:password" entry, in config order

	required  *rewriter.SyntheticResponse // no Authorization header, or not Basic
	malformed *rewriter.SyntheticResponse // bad base64, or no colon in the decoded bytes
	invalid   *rewriter.SyntheticResponse // well-formed, wrong credentials
}

// buildBasicAuth validates basic-auth's config and builds its runtime. The
// allowed-field check lives in buildAction's case (one list, checked once --
// a second list here could drift from it); this function reads the fields.
//
//	realm: restricted          # default "ngrok"
//	credentials:               # "user:password" entries; several allowed
//	  - alice:secret
func buildBasicAuth(where string, cfg map[string]interface{}) (*basicAuthAction, error) {
	realm := defaultBasicRealm
	if v, ok := cfg["realm"]; ok {
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("%s: config field \"realm\" must be a string, got %s", where, typeName(v))
		}
		if err := checkRealm(where, "realm", s); err != nil {
			return nil, err
		}
		realm = s
	}

	creds, err := credentialList(where, "credentials", cfg, ":")
	if err != nil {
		return nil, err
	}

	challenge := challengeHeader("WWW-Authenticate", fmt.Sprintf("Basic realm=%q", realm))
	return &basicAuthAction{
		digests: digestsOf(creds),
		required: unauthorized(challenge,
			"basic-auth: this endpoint requires credentials"),
		malformed: unauthorized(challenge,
			"basic-auth: credentials are malformed"),
		invalid: unauthorized(challenge,
			"basic-auth: credentials are invalid"),
	}, nil
}

func (a *basicAuthAction) authenticate(req *http.Request, _ *evalState) *rewriter.SyntheticResponse {
	scheme, b64, ok := schemeAndValue(req.Header.Get("Authorization"))
	if !ok || !strings.EqualFold(scheme, "Basic") {
		return a.required
	}
	// RFC 7617's charset is base64 with padding, which is encoding.StdEncoding;
	// anything else decodes to an error and earns the challenge again. The
	// decoded user-id and password are then one "user:password" string, which
	// is the shape the config stores and the unit the comparison runs on --
	// comparing the pair as one string rather than each half separately keeps
	// the constant-time property over the whole credential.
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return a.malformed
	}
	if _, _, hasColon := strings.Cut(string(raw), ":"); !hasColon {
		return a.malformed
	}
	if !digestListMatches(a.digests, string(raw)) {
		return a.invalid
	}
	return nil
}

// --- bearer-auth -------------------------------------------------------------

type bearerAuthAction struct {
	digests []string // of each configured token

	required *rewriter.SyntheticResponse // no Authorization header, or not Bearer
	invalid  *rewriter.SyntheticResponse // well-formed, wrong token
}

// buildBearerAuth validates bearer-auth's config and builds its runtime:
//
//	tokens:
//	  - "tok_abcdef"
func buildBearerAuth(where string, cfg map[string]interface{}) (*bearerAuthAction, error) {
	creds, err := credentialList(where, "tokens", cfg, "")
	if err != nil {
		return nil, err
	}

	// The spec fixes the challenge at a bare "Bearer": no realm, no params.
	challenge := challengeHeader("WWW-Authenticate", "Bearer")
	return &bearerAuthAction{
		digests: digestsOf(creds),
		required: unauthorized(challenge,
			"bearer-auth: this endpoint requires a bearer token"),
		invalid: unauthorized(challenge,
			"bearer-auth: the bearer token is invalid"),
	}, nil
}

func (a *bearerAuthAction) authenticate(req *http.Request, _ *evalState) *rewriter.SyntheticResponse {
	token, ok := bearerToken(req)
	if !ok {
		return a.required
	}
	if !digestListMatches(a.digests, token) {
		return a.invalid
	}
	return nil
}

// bearerToken reads the "Bearer <token>" credential out of a request's
// Authorization header: scheme matched case-insensitively (RFC 7235 makes
// auth-scheme matching case-insensitive), exactly one space, non-empty token
// with no space in it. Anything else is reported as "no bearer token", which
// earns the challenge -- the answer every malformed variant deserves.
//
// jwt-validation reuses this so that both actions read the same header the
// same way; it is the one place that decides what a bearer credential is.
func bearerToken(req *http.Request) (token string, ok bool) {
	scheme, value, found := schemeAndValue(req.Header.Get("Authorization"))
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	if strings.ContainsAny(value, " \t") {
		return "", false // "Bearer x y" is two credentials-shaped things; neither is the token
	}
	return value, true
}

// --- apikey-auth -------------------------------------------------------------

// defaultAPIKeyHeader is the header apikey-auth reads when its config does not
// name one.
const defaultAPIKeyHeader = "X-Api-Key"

type apiKeyAuthAction struct {
	header    string // as configured, for the response body's name
	canonical string // canonical MIME form, for the lookup

	digests  []string
	required *rewriter.SyntheticResponse // header absent (or empty)
	invalid  *rewriter.SyntheticResponse // header present, wrong value
}

// buildAPIKeyAuth validates apikey-auth's config and builds its runtime:
//
//	header: X-Api-Key          # default; case-insensitive lookup
//	keys:
//	  - "ak-live-0001"
func buildAPIKeyAuth(where string, cfg map[string]interface{}) (*apiKeyAuthAction, error) {
	header := defaultAPIKeyHeader
	if v, ok := cfg["header"]; ok {
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("%s: config field \"header\" must be a string, got %s", where, typeName(v))
		}
		if !rewriter.ValidHeaderToken(s) {
			return nil, fmt.Errorf("%s: config field \"header\": %q is not a valid header name", where, s)
		}
		header = s
	}
	// The lookup goes through http.Header.Get, which canonicalizes; a valid
	// header token has exactly one canonical form, so a config that says
	// "x-api-key" and a wire that says "X-API-KEY" meet at "X-Api-Key".
	canonical := textproto.CanonicalMIMEHeaderKey(header)

	creds, err := credentialList(where, "keys", cfg, "")
	if err != nil {
		return nil, err
	}

	// No WWW-Authenticate here on purpose: there is no standard challenge for
	// a custom API-key header, and inventing one (`X-Api-Key: ...`?) would
	// teach clients to send credentials to whatever header this error names.
	// The body names the configured header instead.
	return &apiKeyAuthAction{
		header:    header,
		canonical: canonical,
		digests:   digestsOf(creds),
		required: unauthorized(nil,
			fmt.Sprintf("apikey-auth: the %s header is required", header)),
		invalid: unauthorized(nil,
			fmt.Sprintf("apikey-auth: the %s header value is invalid", header)),
	}, nil
}

func (a *apiKeyAuthAction) authenticate(req *http.Request, _ *evalState) *rewriter.SyntheticResponse {
	// Get returns "" for an absent header, and an empty key is refused by the
	// validator, so an empty lookup can never match: both cases are "required".
	key := req.Header.Get(a.canonical)
	if key == "" {
		return a.required
	}
	if !digestListMatches(a.digests, key) {
		return a.invalid
	}
	return nil
}

// --- shared config shapes ----------------------------------------------------

// credentialList reads one action's credential list: a required, non-empty
// list of strings whose entries are resolved through the installed vaults
// (vault.go) -- a whole-value secret("vault/key") reference is replaced by the
// vault's value here, which makes this the resolution seam between "read the
// config's shape" and the digests the callers take of what is returned.
//
// The shape checks run on the RESOLVED value: for an inline entry that is the
// config string itself (and these are the checks it has always gotten, in the
// words it has always gotten them), while a vault-sourced value must obey the
// same rules as the literal it stands for -- post-resolution is the only
// point where both forms meet them. Each entry is refused when it carries a
// CR or LF (a credential is never written to a wire by this package, but a
// document that hides a line break inside a credential is a header-injection
// payload waiting for the first code path that echoes it, and there is no
// credential an operator means to write that way) and, when sep is non-empty,
// refused unless it contains exactly the separator (basic-auth's
// "user:password" shape) -- with one carve-out: a vault entry stored
// pre-digested (sha256:<hex>) skips the separator check, because a bare
// digest cannot carry a colon and the plaintext whose shape it is was
// discarded on purpose. With no separator, an empty value is refused, since
// no request could ever match one.
func credentialList(where, field string, cfg map[string]interface{}, sep string) ([]resolvedCredential, error) {
	v, ok := cfg[field]
	if !ok {
		return nil, fmt.Errorf("%s: config field %q is required", where, field)
	}
	items, ok := asList(v)
	if !ok {
		return nil, fmt.Errorf("%s: config field %q must be a list of strings, got %s", where, field, typeName(v))
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("%s: config field %q must have at least one entry (an empty list would refuse every request)", where, field)
	}
	out := make([]resolvedCredential, 0, len(items))
	for i, item := range items {
		s, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("%s: config field %q entry %d must be a string, got %s", where, field, i, typeName(item))
		}

		// Vault resolution (SPEC-CLUSTER9 3.1): load-time, loud, naming the
		// vault and key it failed on. A reference the vaults cannot satisfy
		// stops the load (client) or the registration (server) here.
		cred, err := resolveCredential(s)
		if err != nil {
			return nil, fmt.Errorf("%s: config field %q entry %d: %v", where, field, i, err)
		}

		// provenance: entries resolved from a vault say which one, so the
		// operator is sent to the vault file or environment, not the policy
		prov := ""
		if cred.vault != "" {
			prov = fmt.Sprintf(" (vault %q key %q)", cred.vault, cred.key)
		}

		if strings.ContainsAny(cred.value, "\r\n") {
			return nil, fmt.Errorf("%s: config field %q entry %d%s contains a CR or LF, which no credential should carry (header injection)", where, field, i, prov)
		}
		// The separator check runs on the resolved value -- except when that
		// value came pre-digested from a vault. A sha256: entry's value is a
		// bare hex digest, which cannot carry a colon by construction: the
		// operator digested a well-formed "user:password", and the digest no
		// longer contains the plaintext whose shape this check asks about.
		// Blaming the digest for a missing separator would refuse exactly the
		// digests-only-on-disk setup the vault file format advertises. The
		// skip is licensed by the VAULT provenance, not by the sha256:
		// prefix: an inline "sha256:<hex>" string is a literal credential
		// with no vault behind it, and it is shape-checked like any other
		// literal (a colon-less one is refused below, as it always was).
		if sep != "" && !cred.digested {
			if _, _, found := strings.Cut(cred.value, sep); !found {
				return nil, fmt.Errorf("%s: config field %q entry %d%s is not \"user:password\"-shaped: a %q separator is required (an empty user or password is allowed)", where, field, i, prov, sep)
			}
		} else if cred.value == "" {
			return nil, fmt.Errorf("%s: config field %q entry %d%s is empty, which no request could ever match", where, field, i, prov)
		}
		out = append(out, cred)
	}
	return out, nil
}

// checkRealm refuses a realm that could not travel inside the quoted-string
// grammar of a WWW-Authenticate value: a CR or LF is header injection (the
// realm is the one piece of auth config this package writes to the wire), and
// a quote or a backslash would end or escape the quoted-string early, turning
// the challenge into something no client parses the same way twice.
func checkRealm(where, field, realm string) error {
	if strings.ContainsAny(realm, "\r\n") {
		return fmt.Errorf("%s: config field %q contains a CR or LF, which would inject a header into the challenge", where, field)
	}
	if strings.ContainsAny(realm, `"\\`) {
		return fmt.Errorf("%s: config field %q contains a quote or a backslash, which the quoted-string grammar of a challenge cannot carry", where, field)
	}
	return nil
}

// digestsOf converts the resolved credential entries to their comparison form,
// once at load time. After this the plaintext credentials are
// garbage-collectable: the compiled policy -- the object that lives for the
// tunnel's lifetime and is shared across connections -- holds only digests. A
// vault entry that was stored pre-digested (sha256:<hex> in the vault file or
// environment) passes its stored hex straight through: digesting it again
// would compare the digest of a digest, which no request could ever produce,
// and the pre-digested form is exactly how a deployment keeps plaintext out of
// the credential store entirely (vault.go).
func digestsOf(credentials []resolvedCredential) []string {
	out := make([]string, len(credentials))
	for i, c := range credentials {
		out[i] = c.digest()
	}
	return out
}
