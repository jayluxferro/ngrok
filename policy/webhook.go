package policy

// The webhook-verification action (SPEC-CLUSTER10 4): request-phase
// verification of the signatures Stripe, GitHub and Svix put on their webhook
// deliveries, judged over the request body before it reaches the local
// service.
//
// The action is a terminator shaped like the authentication actions
// (auth_actions.go): a request whose signature does not verify is answered
// with a fixed 403 built at load time, and a request whose signature does
// verify is a no-op -- later rules proceed. The differences from the
// credential actions are the two things a signature scheme needs and a
// credential check does not:
//
//   - the body. Every scheme here HMACs the payload, so the rewriter must
//     buffer the request before the hook can run. Compiled.RequestBodyCap
//     reports the cap (webhookBodyCap, spec section 3); the call sites that
//     build a rewriter.Policy copy it onto BodyBufferCap, and the rewriter
//     hands the buffered bytes to the hook on the head object's Body. A nil
//     Body at the hook means buffering did not happen -- chunked,
//     close-delimited, over cap, or a rewriter that was never told this
//     policy needs a body -- and the action refuses (bufferedBody, below,
//     has the full argument for why refusing is the only safe reading).
//   - a clock. Stripe and Svix sign the send time into the header, so a
//     captured delivery stops verifying once tolerance_seconds have passed.
//     GitHub signs the payload alone; its configs may still set
//     tolerance_seconds (rotation configs get copied between providers),
//     where it is simply unused.
//
// Everything refuses closed, and every refusal is the same fixed 403: a
// malformed signature header, a timestamp outside the tolerance, a signature
// that does not match, and a body that could not be buffered are one answer.
// This action exists because the operator does not want unverified bodies
// reaching the local service, so no failure shape may become a pass-through,
// and none of them earns a 400 -- a 400 would teach a probing client which
// part of its forgery was wrong.
//
// Secrets are plaintext HMAC keys, which is why this action is stricter than
// the credential path at one point: a sha256: digest cannot verify anything
// here (you cannot compute an HMAC with a digest of the key), so the vault's
// pre-digested form is refused at build instead of accepted. The plaintext is
// held in the compiled action for the tunnel's lifetime and is never logged
// and never rendered: the refusal responses are built once, at load, from
// static strings, the same construction auth_actions.go uses to keep
// credential material out of its verdicts.

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"ngrok/rewriter"
)

// webhookBodyCap is the request-body size the rewriter is told to buffer for
// a policy whose request phase verifies webhook signatures -- spec section 3's
// 1 MiB, carried from Compiled.RequestBodyCap onto rewriter.Policy.BodyBufferCap.
// The rewriter checks a declared Content-Length against it before buffering;
// this action checks it too (bufferedBody), because a control that leans on
// another package's pre-check is a control waiting for that check to move.
const webhookBodyCap = 1 << 20

// defaultWebhookTolerance is what tolerance_seconds defaults to: the value
// Stripe's and Svix's own SDKs use, and a number loose enough for queueing
// between the sender and the edge without being loose enough to matter for a
// replay.
const defaultWebhookTolerance = 300 * time.Second

// svixSecretPrefix is the spelling Svix issues signing secrets in. The text
// after it is base64 of the real key -- the svix scheme computes its HMAC
// with the DECODED bytes, which is why a raw (unprefixed, non-base64) secret
// cannot be silently accepted: there is no key to derive from it that a
// sender could have signed with.
const svixSecretPrefix = "whsec_"

// webhookVerify is one scheme-judgement call: the buffered request, one key
// to try, and the tolerance. The scheme functions are pure over this struct,
// which is what makes a fourth provider "one table entry and one verify
// function" (spec review gate 5) -- and what lets the tests drive a scheme
// with a frozen clock for the exact tolerance boundary.
type webhookVerify struct {
	header    http.Header // the request's headers
	body      []byte      // the buffered body, exactly as it will be forwarded
	key       []byte      // the HMAC key being tried this call
	tolerance time.Duration
	now       time.Time

	// failLabel is set when verify returns false: one fixed string for the
	// log line ("malformed signature entry", "timestamp outside the
	// tolerance", "signature does not match"). The schemes deliberately do
	// not log -- they have no evalState -- and deliberately do not format
	// anything request-derived into the label; with rotation, the label of
	// the last key tried wins, which is right: every key sees the same
	// headers, so the label describes the request, not the key.
	failLabel string
}

// webhookProvider is one entry of the provider table: the headers a scheme
// reads, how a configured secret becomes an HMAC key, how one key is judged,
// and the fixed refusal every failure answers with. Adding a provider is one
// entry here plus its scheme function; nothing else in the action knows
// their names.
type webhookProvider struct {
	// name is the config's provider value, and the one word of it that the
	// fixed 403's body carries.
	name string

	// headers are the request headers the scheme requires, lower-cased (the
	// lookup canonicalizes the way http.Header.Get does). One missing is a
	// request the scheme cannot judge, and it is refused before any key is
	// tried -- the shared pre-check in authenticate walks this list.
	headers []string

	// secretKey turns one resolved secret (inline text or a vault value,
	// already CR/LF- and digest-checked) into the HMAC key. For stripe and
	// github that is the string's bytes; svix demands the whsec_ spelling
	// and base64-decodes it, so a paste of the wrong credential type is a
	// load error rather than a webhook that 403s everything for a year.
	secretKey func(secret string) ([]byte, error)

	// verify judges the request against v.key. It never short-circuits the
	// caller's rotation loop, and it answers false -- never an error -- for
	// every refusal shape, setting v.failLabel on the way.
	verify func(v *webhookVerify) bool

	// deny is the fixed 403, built once at package load: the same bytes for
	// a malformed header, a stale timestamp, a wrong secret, and an
	// unbufferable body. Nothing request-derived is in it, and (review gate
	// 4) no secret material can be.
	deny *rewriter.SyntheticResponse
}

// webhookProviders is the table, in the order its name list renders in error
// messages. Lookup is linear over three entries, which is fine, and in a
// slice -- not a map -- so the message order is fixed by this file.
var webhookProviders = []*webhookProvider{
	{
		name:      "stripe",
		headers:   []string{"stripe-signature"},
		secretKey: rawSecretKey,
		verify:    stripeVerify,
		deny:      webhookForbidden("stripe"),
	},
	{
		name:      "github",
		headers:   []string{"x-hub-signature-256"},
		secretKey: rawSecretKey,
		verify:    githubVerify,
		deny:      webhookForbidden("github"),
	},
	{
		name:      "svix",
		headers:   []string{"svix-id", "svix-timestamp", "svix-signature"},
		secretKey: svixSecretKey,
		verify:    svixVerify,
		deny:      webhookForbidden("svix"),
	},
}

// webhookForbidden builds the fixed 403 one provider's failures answer with.
// It is called once per provider, at package load, from the table above: the
// same bytes answer every failure of that provider, for every connection, so
// nothing request-derived and nothing secret-derived can reach a client
// through it.
func webhookForbidden(provider string) *rewriter.SyntheticResponse {
	return &rewriter.SyntheticResponse{
		StatusCode: http.StatusForbidden,
		Body:       "webhook-verification: the request failed " + provider + " signature verification",
	}
}

func webhookProviderByName(name string) *webhookProvider {
	for _, p := range webhookProviders {
		if p.name == name {
			return p
		}
	}
	return nil
}

// webhookProviderNames renders the table for "is not a provider this build
// verifies" -- in table order, which is fixed, so the message is the same on
// every run.
func webhookProviderNames() []string {
	names := make([]string, len(webhookProviders))
	for i, p := range webhookProviders {
		names[i] = p.name
	}
	return names
}

// --- the schemes -------------------------------------------------------------

// timestampFresh is the tolerance rule both timestamped schemes share: the
// send time sits within tolerance on EITHER side of now. Strictly within --
// the exact boundary second is admitted -- because a timestamp whose skew is
// precisely the configured tolerance is the operator's own stated "accept",
// not something to tighten by a nanosecond of wall clock. The schemes call
// this rather than carrying two copies of the comparison, and the boundary
// test pins it with a frozen clock.
func timestampFresh(sec int64, tolerance time.Duration, now time.Time) bool {
	d := now.Sub(time.Unix(sec, 0))
	return d <= tolerance && d >= -tolerance
}

// stripeVerify judges the Stripe-Signature scheme: "t=<unix>,v1=<hex>",
// comma-separated, possibly several v1 entries (Stripe sends one per
// currently-live endpoint key) and every one of them checked. The signed
// content is the RAW t string, a dot, and the body -- the string as sent,
// not a re-rendering of its integer, because that is what Stripe signed.
func stripeVerify(v *webhookVerify) bool {
	t, sigs, ok := parseStripeSignature(v.header.Get("Stripe-Signature"))
	if !ok {
		v.failLabel = "malformed signature header"
		return false
	}
	sec, err := strconv.ParseInt(t, 10, 64)
	if err != nil {
		v.failLabel = "malformed timestamp"
		return false
	}
	if !timestampFresh(sec, v.tolerance, v.now) {
		v.failLabel = "timestamp outside the tolerance"
		return false
	}

	mac := hmac.New(sha256.New, v.key)
	mac.Write([]byte(t))
	mac.Write([]byte("."))
	mac.Write(v.body)
	want := mac.Sum(nil)

	matched := false
	for _, sig := range sigs {
		got, err := hex.DecodeString(sig)
		if err != nil || len(got) != sha256.Size {
			// Strict, per the spec's header-parsing rule: a v1 entry this
			// engine cannot read refuses the whole header, rather than being
			// skipped and leaving the request to be judged by whichever
			// entries happen to parse. Stripe's own SDK skips instead; a
			// sender that never sends malformed entries sees no difference.
			v.failLabel = "malformed signature entry"
			return false
		}
		if subtle.ConstantTimeCompare(want, got) == 1 {
			matched = true // keep scanning: no early signal of which entry matched
		}
	}
	if !matched {
		v.failLabel = "signature does not match"
		return false
	}
	return true
}

// parseStripeSignature splits Stripe-Signature into its t and its v1
// entries. Entries without "=" are malformed (strict); well-formed keys the
// scheme does not carry (Stripe has issued v0 historically) are ignored --
// the scheme versions its entries the way svix's does, and ignoring an
// unknown version cannot admit anything, because admission still requires a
// verified v1. Two t values are malformed: the header would not say which
// one signed the payload.
func parseStripeSignature(raw string) (t string, v1s []string, ok bool) {
	seenT := false
	for _, part := range strings.Split(raw, ",") {
		key, value, found := strings.Cut(part, "=")
		if !found || key == "" || value == "" {
			return "", nil, false
		}
		switch key {
		case "t":
			if seenT {
				return "", nil, false
			}
			seenT, t = true, value
		case "v1":
			v1s = append(v1s, value)
		}
	}
	if !seenT || len(v1s) == 0 {
		return "", nil, false
	}
	return t, v1s, true
}

// githubVerify judges x-hub-signature-256: "sha256=" and the HMAC of the
// body alone -- no timestamp, so there is no tolerance to apply and a replay
// of a genuinely-signed body verifies for as long as the secret lives. That
// is GitHub's scheme, not a choice of ours; the rotation story (a leaked key
// removed from the config) is what retires it.
func githubVerify(v *webhookVerify) bool {
	scheme, hexSig, found := strings.Cut(v.header.Get("X-Hub-Signature-256"), "=")
	if !found || !strings.EqualFold(scheme, "sha256") || hexSig == "" {
		v.failLabel = "malformed signature header"
		return false
	}
	got, err := hex.DecodeString(hexSig)
	if err != nil || len(got) != sha256.Size {
		v.failLabel = "malformed signature entry"
		return false
	}
	mac := hmac.New(sha256.New, v.key)
	mac.Write(v.body)
	if subtle.ConstantTimeCompare(mac.Sum(nil), got) != 1 {
		v.failLabel = "signature does not match"
		return false
	}
	return true
}

// svixVerify judges the svix scheme: svix-id, svix-timestamp and
// svix-signature, the last carrying space-separated "version,signature"
// entries of which only v1 is understood (and only v1 can admit). The signed
// content is id, the RAW timestamp string, and the body, joined with dots.
// Signatures are base64, not hex.
func svixVerify(v *webhookVerify) bool {
	id := v.header.Get("Svix-Id")
	ts := v.header.Get("Svix-Timestamp")
	if id == "" || ts == "" {
		// The shared pre-check refuses this first; the scheme stays
		// self-sufficient so the tests (and a fourth entry reusing it) can
		// call it without re-implementing the rule.
		v.failLabel = "a required signature header is missing"
		return false
	}
	sec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		v.failLabel = "malformed timestamp"
		return false
	}
	if !timestampFresh(sec, v.tolerance, v.now) {
		v.failLabel = "timestamp outside the tolerance"
		return false
	}

	mac := hmac.New(sha256.New, v.key)
	mac.Write([]byte(id))
	mac.Write([]byte("."))
	mac.Write([]byte(ts))
	mac.Write([]byte("."))
	mac.Write(v.body)
	want := mac.Sum(nil)

	matched, sawV1 := false, false
	for _, entry := range strings.Split(v.header.Get("Svix-Signature"), " ") {
		version, sig, found := strings.Cut(entry, ",")
		if !found || sig == "" {
			v.failLabel = "malformed signature entry"
			return false
		}
		if version != "v1" {
			continue // v1 only (spec section 4); unknown versions are skipped, never trusted
		}
		sawV1 = true
		got, err := base64.StdEncoding.DecodeString(sig)
		if err != nil || len(got) != sha256.Size {
			v.failLabel = "malformed signature entry"
			return false
		}
		if subtle.ConstantTimeCompare(want, got) == 1 {
			matched = true
		}
	}
	if !sawV1 {
		v.failLabel = "no v1 signature entry"
		return false
	}
	if !matched {
		v.failLabel = "signature does not match"
		return false
	}
	return true
}

// --- the config --------------------------------------------------------------

// buildWebhookVerification validates webhook-verification's config and builds
// its runtime:
//
//	provider: stripe          # stripe | github | svix
//	secrets:                  # one or more, for rotation; inline or
//	  - "whsec_..."           # secret("vault/key") whole-value references
//	tolerance_seconds: 300    # default 300, >= 0
//
// As with the auth builders, the allowed-field check lives in buildAction's
// case; this function reads the fields.
func buildWebhookVerification(where string, cfg map[string]interface{}) (*webhookAction, error) {
	rawProvider, ok := cfg["provider"]
	if !ok {
		return nil, fmt.Errorf("%s: config field \"provider\" is required", where)
	}
	providerName, ok := rawProvider.(string)
	if !ok {
		return nil, fmt.Errorf("%s: config field \"provider\" must be a string, got %s", where, typeName(rawProvider))
	}
	provider := webhookProviderByName(providerName)
	if provider == nil {
		return nil, fmt.Errorf("%s: config field \"provider\": %q is not a provider this build verifies (it verifies: %s)",
			where, providerName, strings.Join(webhookProviderNames(), ", "))
	}

	tolerance := defaultWebhookTolerance
	if v, ok := cfg["tolerance_seconds"]; ok {
		n, ok := asInt(v)
		if !ok {
			return nil, fmt.Errorf("%s: config field \"tolerance_seconds\" must be an integer, got %s", where, typeName(v))
		}
		if n < 0 {
			// jwt.go's wording for the same shape: a negative bound here
			// would refuse events whose clock is merely ahead, which is a
			// misconfiguration the operator wants named at load.
			return nil, fmt.Errorf("%s: config field \"tolerance_seconds\" is %d; a negative tolerance would refuse events whose clock is merely ahead", where, n)
		}
		tolerance = time.Duration(n) * time.Second
	}

	keys, err := webhookSecretList(where, cfg, provider)
	if err != nil {
		return nil, err
	}

	return &webhookAction{provider: provider, keys: keys, tolerance: tolerance}, nil
}

// webhookSecretList reads and resolves the secrets: a required, non-empty
// list of strings, each either inline or a whole-value secret("vault/key")
// reference resolved HERE, at build time -- the same seam the credential
// actions resolve at, which is what makes a document plus its vaults produce
// the same compiled keys on the client (at load) and the server (at
// registration). Resolution goes through ResolveSecretRef, not the
// credential path's resolver, on purpose: the credential resolver silently
// passes pre-digested (sha256:) vault entries through as hex, and a digest
// is exactly what this action must refuse -- an HMAC is computed WITH the
// key, so there is no digest form of a signing secret to accept.
func webhookSecretList(where string, cfg map[string]interface{}, provider *webhookProvider) ([][]byte, error) {
	v, ok := cfg["secrets"]
	if !ok {
		return nil, fmt.Errorf("%s: config field \"secrets\" is required", where)
	}
	items, ok := asList(v)
	if !ok {
		return nil, fmt.Errorf("%s: config field \"secrets\" must be a list of strings, got %s", where, typeName(v))
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("%s: config field \"secrets\" must have at least one entry (an empty list would refuse every request)", where)
	}

	keys := make([][]byte, 0, len(items))
	for i, item := range items {
		s, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("%s: config field \"secrets\" entry %d must be a string, got %s", where, i, typeName(item))
		}

		secret, err := ResolveSecretRef(s)
		if err != nil {
			return nil, fmt.Errorf("%s: config field \"secrets\" entry %d: %v", where, i, err)
		}
		// provenance: a resolved entry says which vault it came from, so the
		// operator is sent to the vault file, not the policy document.
		prov := ""
		if strings.HasPrefix(s, secretRefCall) {
			if vault, key, parseErr := parseSecretRef(s); parseErr == nil {
				prov = fmt.Sprintf(" (vault %q key %q)", vault, key)
			}
		}

		// The checks run on the RESOLVED value, post-vault: for an inline
		// entry that is the config string itself, and a vault-sourced value
		// must obey the same rules as the literal it stands for -- the same
		// post-resolution discipline credentialList applies.
		if strings.ContainsAny(secret, "\r\n") {
			return nil, fmt.Errorf("%s: config field \"secrets\" entry %d%s contains a CR or LF, which no signing secret should carry (header injection)", where, i, prov)
		}
		if secret == "" {
			return nil, fmt.Errorf("%s: config field \"secrets\" entry %d%s is empty, which no signature could ever verify against", where, i, prov)
		}
		if strings.HasPrefix(secret, digestPrefix) {
			return nil, fmt.Errorf("%s: config field \"secrets\" entry %d%s is a sha256: digest; webhook verification needs the plaintext secret (an HMAC is computed with the key itself, so the credential path's digest allowance does not apply here)", where, i, prov)
		}

		key, err := provider.secretKey(secret)
		if err != nil {
			return nil, fmt.Errorf("%s: config field \"secrets\" entry %d%s: %v", where, i, prov, err)
		}
		keys = append(keys, key)
	}
	return keys, nil
}

// rawSecretKey is the stripe/github key derivation: the secret's bytes. A
// signing secret needs no shaping, so there is nothing to refuse here --
// every check that could refuse already ran on the resolved value.
func rawSecretKey(secret string) ([]byte, error) {
	return []byte(secret), nil
}

// svixSecretKey is the svix key derivation: whsec_, then base64. The prefix
// is required, not optional -- Svix issues its secrets in exactly this
// spelling, so a value without it is not a variant, it is the wrong
// credential pasted into the wrong provider's config -- and the base64 must
// decode, because the svix scheme HMACs the DECODED bytes and a value that
// cannot decode has no key in it. Refusing both at load is what stands
// between an operator's typo and a webhook that 403s every real delivery.
func svixSecretKey(secret string) ([]byte, error) {
	if !strings.HasPrefix(secret, svixSecretPrefix) {
		return nil, fmt.Errorf("an svix signing secret is %q followed by base64 (the form Svix's dashboard issues), and this value does not carry the prefix", svixSecretPrefix)
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(secret, svixSecretPrefix))
	if err != nil || len(key) == 0 {
		return nil, fmt.Errorf("the value after %q is not base64 the svix scheme can decode into a key", svixSecretPrefix)
	}
	return key, nil
}

// --- the action --------------------------------------------------------------

// webhookAction is the compiled runtime of one webhook-verification rule:
// the provider's table entry, the resolved HMAC keys in config order, and
// the tolerance. It implements the authAction interface, so evalRequest
// dispatches it on the same line as the credential actions and it inherits
// their discipline: the refusal is built once at load, the plaintext keys
// are never logged, and a matching request is a no-op.
type webhookAction struct {
	provider  *webhookProvider
	keys      [][]byte
	tolerance time.Duration
}

// bodyCap is the bodyConsumer half: this action's verdict needs the request
// body, which is what tells build() to set Compiled.requestBodyCap and the
// rewriter to buffer.
func (a *webhookAction) bodyCap() int { return webhookBodyCap }

// bodyConsumer is implemented by request-phase actions whose verdict needs
// the request body to be buffered before the hook runs. build() walks the
// request phase looking for it; a second implementer would simply report its
// own cap and the max wins.
type bodyConsumer interface {
	bodyCap() int
}

// requestBodyCapOf reports the largest body cap any request-phase action
// declares: 0 when none does, which is the shape of every policy that has no
// body-consuming action and the shape the rewriter must keep free.
func requestBodyCapOf(actions []*compiledAction) int {
	out := 0
	for _, a := range actions {
		bc, ok := a.auth.(bodyConsumer)
		if !ok {
			continue
		}
		if n := bc.bodyCap(); n > out {
			out = n
		}
	}
	return out
}

func (a *webhookAction) authenticate(req *http.Request, st *evalState) *rewriter.SyntheticResponse {
	// The headers the scheme reads, checked before anything else: a request
	// missing one is not a failed verification, it is not even shaped like
	// one, and no key should be spent on it.
	for _, name := range a.provider.headers {
		if req.Header.Get(name) == "" {
			st.info("%s: a required signature header (%s) is missing; refusing", ActionWebhookVerification, name)
			return a.provider.deny
		}
	}

	body, ok := a.bufferedBody(req, st)
	if !ok {
		return a.provider.deny
	}

	v := webhookVerify{header: req.Header, body: body, tolerance: a.tolerance, now: time.Now()}
	matched := 0
	for _, key := range a.keys {
		v.key = key
		if a.provider.verify(&v) {
			matched = 1
		}
		// No break: the rotation runs to the end, so the time to a refusal
		// says nothing about which entry matched -- digestListMatches's
		// discipline, paid for with one extra HMAC per configured key.
	}
	if matched == 0 {
		st.info("%s: %s %s refused with status %d (%s)",
			ActionWebhookVerification, req.Method, requestTarget(req), a.provider.deny.StatusCode, v.failLabel)
		return a.provider.deny
	}
	return nil
}

// bufferedBody returns the request body the rewriter buffered, or false --
// refusing, never verifying -- for every shape a body-consuming verdict
// cannot honestly judge.
//
// The first check is the pinned contract with the rewriter
// (rewriter.Policy.BodyBufferCap): a policy that needs the body gets it on
// the head object's Body, and a nil means buffering did not happen -- the
// chunked, close-delimited and over-cap cases the rewriter refuses itself,
// or a rewriter that was never told this policy needs a body at all (the
// BodyBufferCap copy at the two call sites is what carries it; a copy left
// out lands here, loudly, as a 403 on everything). http.ReadRequest never
// produces a nil Body, so nil at this point is unambiguous: the rewriter set
// it on purpose.
//
// The remaining checks are defense in depth against the same mis-wiring,
// each shaped to fire ONLY when buffering demonstrably did not happen, so
// none of them can misfire against a rewriter that populates the head
// slightly differently than we assume:
//
//   - chunked: the buffering path is Content-Length-delimited by definition
//     (the cap is checked against CL up front); v1 never de-chunks, so a
//     chunked head here was never buffered -- and reading its Body would
//     consume the live stream.
//   - a declared length below zero (close-delimited) or above the cap: the
//     buffering path only ever carries a body of [0, cap] declared bytes.
//     These bounds are also what keep io.ReadAll bounded: it runs only when
//     the head declared a sane, capped length.
//   - a declared body that arrived empty: this is the fail-OPEN shape. With
//     an empty verification body, a sender's own signature over the empty
//     string verifies against any wire body -- sign nothing, smuggle
//     anything. On the buffering path the shape cannot occur (a declared
//     length above zero buffers that many bytes), so its presence means the
//     body was never buffered, and the request is refused.
func (a *webhookAction) bufferedBody(req *http.Request, st *evalState) ([]byte, bool) {
	if req.Body == nil {
		st.info("%s: the request body could not be buffered; refusing", ActionWebhookVerification)
		return nil, false
	}
	for _, te := range req.TransferEncoding {
		if strings.EqualFold(te, "chunked") {
			st.info("%s: the request is chunked, which is not buffered or de-chunked; refusing", ActionWebhookVerification)
			return nil, false
		}
	}
	if req.ContentLength < 0 || req.ContentLength > webhookBodyCap {
		st.info("%s: the request declares %d body bytes, outside the %d the engine buffers; refusing",
			ActionWebhookVerification, req.ContentLength, webhookBodyCap)
		return nil, false
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		st.info("%s: the buffered body could not be read; refusing", ActionWebhookVerification)
		return nil, false
	}
	if req.ContentLength > 0 && int64(len(body)) == 0 {
		st.info("%s: the request declares %d body bytes but none arrived for verification; refusing",
			ActionWebhookVerification, req.ContentLength)
		return nil, false
	}
	return body, true
}
