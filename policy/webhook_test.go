package policy

// Tests for the webhook-verification action (SPEC-CLUSTER10 4). Every golden
// signature is generated in-test with real HMAC -- there is no fixture to go
// stale -- and the test's signers are written against the SPEC's scheme
// descriptions, as an independent expression of the same construction the
// production code performs: a scheme refactor that changes the signed content
// fails here, not in production.
//
// The executors run through the real request hook -- the same
// Compiled.RequestHook call the server's Tunnel.join and the client's
// attachPolicyHooks make -- and a "buffered" request is modeled the way the
// buffering rewriter will present one: a POST whose Body carries the bytes
// and whose ContentLength says how many. The unbuffered shapes (nil Body,
// chunked, out-of-bounds Content-Length) are constructed by knocking those
// fields off that model, which is exactly the failure mode of a rewriter
// that was never told to buffer.

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"ngrok/rewriter"
)

// --- signature construction (the tests' own expression of each scheme) ------

// thmac is HMAC-SHA256 over the concatenation of parts -- the shape every
// scheme here shares; only what goes into the parts differs.
func thmac(key []byte, parts ...string) []byte {
	mac := hmac.New(sha256.New, key)
	for _, p := range parts {
		mac.Write([]byte(p))
	}
	return mac.Sum(nil)
}

func stripeHeaders(key []byte, ts string, body []byte) map[string]string {
	return map[string]string{
		"Stripe-Signature": fmt.Sprintf("t=%s,v1=%s", ts, hex.EncodeToString(thmac(key, ts+".", string(body)))),
	}
}

func githubHeaders(key []byte, body []byte) map[string]string {
	return map[string]string{
		"X-Hub-Signature-256": "sha256=" + hex.EncodeToString(thmac(key, string(body))),
	}
}

// svixHeaders signs the svix scheme: id.timestamp.body, the signature base64
// under a v1 version tag. The id is fixed here; no rule under test depends on
// which one it is.
func svixHeaders(key []byte, ts string, body []byte) map[string]string {
	const id = "msg_test_01"
	return map[string]string{
		"Svix-Id":        id,
		"Svix-Timestamp": ts,
		"Svix-Signature": "v1," + base64.StdEncoding.EncodeToString(thmac(key, id+".", ts+".", string(body))),
	}
}

// whsec wraps a plain svix key into the spelling a config or vault stores:
// the prefix plus base64. The scheme's key is the DECODED bytes, so the
// tests carry the plain key and derive the stored spelling from it.
func whsec(key []byte) string {
	return "whsec_" + base64.StdEncoding.EncodeToString(key)
}

// tsAt renders a webhook timestamp d from now -- the send time as the
// provider's header carries it, seconds since the epoch.
func tsAt(d time.Duration) string {
	return strconv.FormatInt(time.Now().Add(d).Unix(), 10)
}

// --- the provider table under test -------------------------------------------

// webhookCase is one provider wired to its in-test signer: the config
// spelling of a secret, the real HMAC key behind it, and the header set a
// signature over (ts, body) produces.
type webhookCase struct {
	name     string
	provider string
	secret   string // as the config (or vault) stores it
	key      []byte // what the scheme actually HMACs with
	timed    bool   // the scheme signs a send time (stripe, svix)
	sign     func(key []byte, ts string, body []byte) map[string]string
	// spin is the config spelling of an arbitrary key -- the inverse of the
	// (secret -> key) derivation the provider's secretKey performs -- so the
	// rotation test can mint a second credential without hand-building a
	// base64 string.
	spin func(key []byte) string
}

var webhookCases = []webhookCase{
	{
		name:     "stripe",
		provider: "stripe",
		secret:   "rk_live_test_signing_secret",
		key:      []byte("rk_live_test_signing_secret"),
		timed:    true,
		sign:     stripeHeaders,
		spin:     func(key []byte) string { return string(key) },
	},
	{
		name:     "github",
		provider: "github",
		secret:   "gh_webhook_signing_secret_01",
		key:      []byte("gh_webhook_signing_secret_01"),
		sign: func(key []byte, _ string, body []byte) map[string]string {
			return githubHeaders(key, body)
		},
		spin: func(key []byte) string { return string(key) },
	},
	{
		name:     "svix",
		provider: "svix",
		secret:   whsec([]byte("svix-plain-signing-key-7")),
		key:      []byte("svix-plain-signing-key-7"),
		timed:    true,
		sign:     svixHeaders,
		spin:     whsec,
	},
}

// --- shared harness ----------------------------------------------------------

// webhookDoc is a one-rule webhook policy over the given secrets, with an
// optional tolerance_seconds (nil omits the field, which must mean the
// default).
func webhookDoc(provider string, secrets []string, toleranceSeconds interface{}) *TrafficPolicy {
	items := make([]interface{}, len(secrets))
	for i, s := range secrets {
		items[i] = s
	}
	cfg := map[string]interface{}{
		"provider": provider,
		"secrets":  items,
	}
	if toleranceSeconds != nil {
		cfg["tolerance_seconds"] = toleranceSeconds
	}
	return reqPolicy(rule(ActionWebhookVerification, nil, cfg))
}

// webhookHook compiles doc and returns the request hook, the same
// Compiled.RequestHook call the enforcement points make.
func webhookHook(t *testing.T, doc *TrafficPolicy) func(*http.Request) *rewriter.RequestVerdict {
	t.Helper()
	c, lg := compileRequest(t, doc)
	return c.RequestHook(lg, "1.2.3.4:1")
}

// signedPost builds the head the buffering rewriter hands the hook: a POST
// whose Body carries the buffered bytes and whose ContentLength says so.
func signedPost(target string, body []byte, headers map[string]string) *http.Request {
	r := httptest.NewRequest("POST", target, bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

// refused digs the synthetic response out of a verdict, failing the test when
// the hook admitted the request instead. The answer is always a 403 -- never
// a 400, however malformed the request was (spec section 4).
func refused(t *testing.T, v *rewriter.RequestVerdict) *rewriter.SyntheticResponse {
	t.Helper()
	if v == nil || v.Terminate == nil {
		t.Fatalf("the request was admitted, want a 403 verdict")
	}
	if v.Terminate.StatusCode != http.StatusForbidden {
		t.Fatalf("the verdict answers %d, want 403", v.Terminate.StatusCode)
	}
	return v.Terminate
}

// --- the executor ------------------------------------------------------------

func TestWebhookVerificationExecutes(t *testing.T) {
	body := []byte(`{"event":"charge.succeeded","amount":100}`)

	for _, tc := range webhookCases {
		t.Run(tc.name, func(t *testing.T) {
			hook := webhookHook(t, webhookDoc(tc.provider, []string{tc.secret}, nil))

			t.Run("a genuine signature is admitted", func(t *testing.T) {
				admitted(t, hook(signedPost("/hook", body, tc.sign(tc.key, tsAt(0), body))))
			})
			t.Run("an empty body can be genuine too", func(t *testing.T) {
				// A declared-empty body is a real buffered body: the
				// unbuffered guards must not read it as a missing one.
				admitted(t, hook(signedPost("/hook", nil, tc.sign(tc.key, tsAt(0), nil))))
			})
			t.Run("a tampered body is refused", func(t *testing.T) {
				sent := []byte(`{"event":"charge.succeeded","amount":100000}`)
				refused(t, hook(signedPost("/hook", sent, tc.sign(tc.key, tsAt(0), body))))
			})
			t.Run("a wrong secret is refused", func(t *testing.T) {
				refused(t, hook(signedPost("/hook", body, tc.sign([]byte("not-the-secret"), tsAt(0), body))))
			})
			t.Run("the refusal is fixed and carries no material", func(t *testing.T) {
				deny := refused(t, hook(signedPost("/hook", body, tc.sign([]byte("nope"), tsAt(0), body))))
				wire := string(deny.Render())
				if strings.Contains(wire, tc.secret) || strings.Contains(wire, string(tc.key)) {
					t.Fatalf("the 403 carries secret material:\n%s", wire)
				}
				if strings.Contains(wire, string(body)) {
					t.Fatalf("the 403 carries request-derived material:\n%s", wire)
				}
				// The one variable thing in it is the provider's name, and
				// the body names the action.
				if !strings.Contains(wire, "webhook-verification") || !strings.Contains(wire, tc.provider) {
					t.Fatalf("the 403 is not the fixed per-provider body:\n%s", wire)
				}
			})
			if tc.timed {
				t.Run("a stale timestamp is refused", func(t *testing.T) {
					refused(t, hook(signedPost("/hook", body, tc.sign(tc.key, tsAt(-2*time.Hour), body))))
				})
				t.Run("a future timestamp beyond the tolerance is refused", func(t *testing.T) {
					refused(t, hook(signedPost("/hook", body, tc.sign(tc.key, tsAt(2*time.Hour), body))))
				})
				t.Run("a timestamp inside the tolerance is admitted", func(t *testing.T) {
					admitted(t, hook(signedPost("/hook", body, tc.sign(tc.key, tsAt(-4*time.Minute), body))))
				})
			}
		})
	}
}

// TestWebhookStripeChecksEveryV1Entry pins the part of the stripe scheme the
// rotation story leans on: Stripe sends one v1 entry per live endpoint key,
// and the check runs over all of them, not just the first.
func TestWebhookStripeChecksEveryV1Entry(t *testing.T) {
	hook := webhookHook(t, webhookDoc("stripe", []string{"rk_live_v1_entry"}, nil))
	body := []byte(`{"multi":1}`)
	ts := tsAt(0)
	sig := stripeHeaders([]byte("rk_live_v1_entry"), ts, body)["Stripe-Signature"]
	v1 := strings.TrimPrefix(sig, "t="+ts+",v1=")

	// valid entry second: still admitted
	header := fmt.Sprintf("t=%s,v1=%s,v1=%s", ts, strings.Repeat("ab", 32), v1)
	admitted(t, hook(signedPost("/hook", body, map[string]string{"Stripe-Signature": header})))

	// valid entry first, garbage after: the garbage is strict-refused, not
	// skipped -- a header this engine cannot fully read never verifies.
	header = fmt.Sprintf("t=%s,v1=%s,v1=zz", ts, v1)
	refused(t, hook(signedPost("/hook", body, map[string]string{"Stripe-Signature": header})))
}

func TestWebhookRotationSecondSecretMatches(t *testing.T) {
	for _, tc := range webhookCases {
		t.Run(tc.name, func(t *testing.T) {
			// The hand-over shape: the old key and the new key are both
			// configured, senders switch at their leisure, and a signature
			// from either admits.
			fresh := []byte("rotated-key-for-" + tc.name)
			hook := webhookHook(t, webhookDoc(tc.provider, []string{tc.secret, tc.spin(fresh)}, nil))

			body := []byte(`{"rotate":true}`)
			t.Run("the new key admits", func(t *testing.T) {
				admitted(t, hook(signedPost("/hook", body, tc.sign(fresh, tsAt(0), body))))
			})
			t.Run("the old key still admits while configured", func(t *testing.T) {
				admitted(t, hook(signedPost("/hook", body, tc.sign(tc.key, tsAt(0), body))))
			})
			t.Run("a third key refuses", func(t *testing.T) {
				refused(t, hook(signedPost("/hook", body, tc.sign([]byte("neither-key"), tsAt(0), body))))
			})
		})
	}
}

// --- strict header parsing ----------------------------------------------------

func TestWebhookMalformedHeadersRefuse(t *testing.T) {
	const body = `{"m":1}`
	ts := tsAt(0)

	for _, tc := range webhookCases {
		t.Run(tc.name, func(t *testing.T) {
			hook := webhookHook(t, webhookDoc(tc.provider, []string{tc.secret}, nil))

			// Every set of headers here is refused with the same fixed 403:
			// a header the scheme cannot fully read is fail-closed, never a
			// 400 that teaches the prober which part was wrong.
			var variants []struct {
				name    string
				headers map[string]string
			}
			switch tc.name {
			case "stripe":
				h := func(v string) map[string]string { return map[string]string{"Stripe-Signature": v} }
				variants = []struct {
					name    string
					headers map[string]string
				}{
					{"header absent", nil},
					{"timestamp only", h("t=" + ts)},
					{"signature only", h("v1=" + strings.Repeat("ab", 32))},
					{"t is not a number", h("t=yesterday,v1=" + strings.Repeat("ab", 32))},
					{"two timestamps", h("t=" + ts + ",t=" + ts + ",v1=" + strings.Repeat("ab", 32))},
					{"v1 is not hex", h("t=" + ts + ",v1=not-hex-at-all")},
					{"v1 is short", h("t=" + ts + ",v1=" + strings.Repeat("ab", 31))},
					{"entry without equals", h("t=" + ts + ",v1")},
					{"empty signature value", h("t=" + ts + ",v1=")},
					{"empty value", h("")},
				}
			case "github":
				h := func(v string) map[string]string { return map[string]string{"X-Hub-Signature-256": v} }
				variants = []struct {
					name    string
					headers map[string]string
				}{
					{"header absent", nil},
					{"scheme only", h("sha256")},
					{"wrong scheme", h("md5=" + strings.Repeat("ab", 32))},
					{"signature is not hex", h("sha256=not-hex-at-all")},
					{"signature is short", h("sha256=" + strings.Repeat("ab", 31))},
					{"empty signature", h("sha256=")},
				}
			case "svix":
				h := func(id, ts2, sig string) map[string]string {
					return map[string]string{"Svix-Id": id, "Svix-Timestamp": ts2, "Svix-Signature": sig}
				}
				variants = []struct {
					name    string
					headers map[string]string
				}{
					{"id absent", h("", ts, "v1,"+strings.Repeat("ab", 32))},
					{"timestamp absent", h("msg_x", "", "v1,"+strings.Repeat("ab", 32))},
					{"signature absent", h("msg_x", ts, "")},
					{"timestamp is not a number", h("msg_x", "yesterday", "v1,"+strings.Repeat("ab", 32))},
					{"entry without comma", h("msg_x", ts, "v1")},
					{"entry with empty signature", h("msg_x", ts, "v1,")},
					{"signature is not base64", h("msg_x", ts, "v1,!!!not-base64!!!")},
					{"signature is short", h("msg_x", ts, "v1,"+base64.StdEncoding.EncodeToString([]byte("3by")))},
					{"only unknown versions", h("msg_x", ts, "v1a,"+base64.StdEncoding.EncodeToString(make([]byte, 32))+" v2,"+base64.StdEncoding.EncodeToString(make([]byte, 32)))},
					{"uppercase version tag", h("msg_x", ts, "V1,"+base64.StdEncoding.EncodeToString(make([]byte, 32)))},
					{"double space splits an empty entry", h("msg_x", ts, "v1,"+base64.StdEncoding.EncodeToString(make([]byte, 32))+"  v1,"+base64.StdEncoding.EncodeToString(make([]byte, 32)))},
				}
			}

			for _, v := range variants {
				t.Run(v.name, func(t *testing.T) {
					refused(t, hook(signedPost("/hook", []byte(body), v.headers)))
				})
			}
		})
	}
}

// --- fail-closed on the body -------------------------------------------------

func TestWebhookFailsClosedOnUnbufferedBody(t *testing.T) {
	for _, tc := range webhookCases {
		t.Run(tc.name, func(t *testing.T) {
			hook := webhookHook(t, webhookDoc(tc.provider, []string{tc.secret}, nil))
			body := []byte(`{"x":1}`)
			// Every request below carries a GENUINE signature over its body;
			// what they have in common is a body the hook cannot honestly
			// judge, and every one of them is refused anyway.
			headers := tc.sign(tc.key, tsAt(0), body)

			t.Run("nil body", func(t *testing.T) {
				// The pinned contract: nil Body is the rewriter saying
				// "could not buffer". http's own readers never produce one,
				// so nil is unambiguous.
				r := signedPost("/hook", body, headers)
				r.Body = nil
				refused(t, hook(r))
			})
			t.Run("chunked", func(t *testing.T) {
				r := signedPost("/hook", body, headers)
				r.TransferEncoding = []string{"chunked"}
				refused(t, hook(r))
			})
			t.Run("over the cap", func(t *testing.T) {
				r := signedPost("/hook", body, headers)
				r.ContentLength = webhookBodyCap + 1
				refused(t, hook(r))
			})
			t.Run("close-delimited", func(t *testing.T) {
				r := signedPost("/hook", body, headers)
				r.ContentLength = -1
				refused(t, hook(r))
			})
			t.Run("declared body, empty delivery", func(t *testing.T) {
				// The fail-OPEN shape: a signature over the empty string is
				// the sender's own and would verify against any wire body.
				// Sign nothing, smuggle anything -- so an empty verification
				// body under a declared length refuses.
				wire := []byte(`{"smuggled":true}`)
				r := signedPost("/hook", wire, tc.sign(tc.key, tsAt(0), nil))
				r.Body = http.NoBody
				r.ContentLength = int64(len(wire))
				refused(t, hook(r))
			})
		})
	}
}

// --- the config ---------------------------------------------------------------

func TestWebhookConfigRejects(t *testing.T) {
	// One vault set for the table's reference-shaped cases; the inline
	// literals ignore it.
	installVaults(t, mainVaultSources(t, nil))

	tests := []struct {
		name string
		doc  *TrafficPolicy
		want string // a substring of the error
	}{
		{
			"missing provider",
			reqPolicy(rule(ActionWebhookVerification, nil, map[string]interface{}{"secrets": []interface{}{"s"}})),
			`config field "provider" is required`,
		},
		{
			"unknown provider",
			webhookDoc("slack", []string{"s"}, nil),
			`config field "provider": "slack" is not a provider this build verifies (it verifies: stripe, github, svix)`,
		},
		{
			"provider is not a string",
			reqPolicy(rule(ActionWebhookVerification, nil, map[string]interface{}{"provider": 3, "secrets": []interface{}{"s"}})),
			`config field "provider" must be a string, got a number`,
		},
		{
			"missing secrets",
			reqPolicy(rule(ActionWebhookVerification, nil, map[string]interface{}{"provider": "stripe"})),
			`config field "secrets" is required`,
		},
		{
			"empty secrets",
			webhookDoc("stripe", nil, nil),
			`config field "secrets" must have at least one entry (an empty list would refuse every request)`,
		},
		{
			"secrets is not a list",
			reqPolicy(rule(ActionWebhookVerification, nil, map[string]interface{}{"provider": "stripe", "secrets": "s"})),
			`config field "secrets" must be a list of strings, got a string`,
		},
		{
			"secret is not a string",
			reqPolicy(rule(ActionWebhookVerification, nil, map[string]interface{}{"provider": "stripe", "secrets": []interface{}{42}})),
			`config field "secrets" entry 0 must be a string, got a number`,
		},
		{
			"empty secret",
			webhookDoc("stripe", []string{""}, nil),
			`config field "secrets" entry 0 is empty, which no signature could ever verify against`,
		},
		{
			"secret with a CR",
			webhookDoc("stripe", []string{"a\rb"}, nil),
			`config field "secrets" entry 0 contains a CR or LF, which no signing secret should carry (header injection)`,
		},
		{
			"digest-prefixed secret, inline",
			webhookDoc("stripe", []string{"sha256:" + strings.Repeat("ab", 32)}, nil),
			`config field "secrets" entry 0 is a sha256: digest; webhook verification needs the plaintext secret`,
		},
		{
			"digest-prefixed secret from a vault",
			webhookDoc("stripe", []string{`secret("main/digested")`}, nil),
			`config field "secrets" entry 0 (vault "main" key "digested") is a sha256: digest; webhook verification needs the plaintext secret`,
		},
		{
			"negative tolerance",
			webhookDoc("stripe", []string{"s"}, -1),
			`config field "tolerance_seconds" is -1; a negative tolerance would refuse events whose clock is merely ahead`,
		},
		{
			"tolerance is not an integer",
			webhookDoc("stripe", []string{"s"}, "soon"),
			`config field "tolerance_seconds" must be an integer, got a string`,
		},
		{
			"unknown config field",
			reqPolicy(rule(ActionWebhookVerification, nil, map[string]interface{}{
				"provider": "stripe",
				"secrets":  []interface{}{"s"},
				"url":      "https://hooks.example",
			})),
			`unknown config field "url" (this action documents: provider, secrets, tolerance_seconds)`,
		},
		{
			"svix secret without the prefix",
			webhookDoc("svix", []string{"plain-secret"}, nil),
			`an svix signing secret is "whsec_" followed by base64`,
		},
		{
			"svix secret is not base64",
			webhookDoc("svix", []string{"whsec_!!!not-base64!!!"}, nil),
			`the value after "whsec_" is not base64 the svix scheme can decode into a key`,
		},
		{
			"vault the configuration does not have",
			webhookDoc("stripe", []string{`secret("other/key")`}, nil),
			`no vault named "other" is configured`,
		},
		{
			"response phase",
			&TrafficPolicy{OnHTTPResponse: []*Action{rule(ActionWebhookVerification, nil, map[string]interface{}{
				"provider": "stripe", "secrets": []interface{}{"s"},
			})}},
			`the webhook-verification action is not implemented in the on_http_response phase`,
		},
		{
			"connect phase",
			&TrafficPolicy{OnTCPConnect: []*Action{rule(ActionWebhookVerification, nil, map[string]interface{}{
				"provider": "stripe", "secrets": []interface{}{"s"},
			})}},
			`the webhook-verification action is not implemented in the on_tcp_connect phase`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.doc.Validate()
			if err == nil {
				t.Fatalf("Validate accepted a policy it should refuse")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error does not name the field and the reason.\n got: %v\nwant substring: %s", err, tt.want)
			}
			// The error names the rule it came from: the action is in the
			// message, per the package's load-error rule. The one exception
			// is the vault resolution error, which names the reference, not
			// the action (vault errors never leak policy shape -- vault.go's
			// no-enumeration rule).
			if !strings.Contains(err.Error(), ActionWebhookVerification) && !strings.Contains(tt.want, "vault") {
				t.Fatalf("error does not name the action: %v", err)
			}
		})
	}
}

func TestWebhookConfigAccepts(t *testing.T) {
	installVaults(t, mainVaultSources(t, map[string]string{
		"whsec": whsec([]byte("vault-svix-key")),
	}))

	docs := []*TrafficPolicy{
		// Every provider inline, at the default tolerance.
		webhookDoc("stripe", []string{"rk_live_one"}, nil),
		webhookDoc("github", []string{"gh_one", "gh_two"}, nil),
		webhookDoc("svix", []string{whsec([]byte("svix-one"))}, nil),
		// tolerance_seconds: 0 is legal -- "no clock slack at all".
		webhookDoc("stripe", []string{"rk_live_one"}, 0),
		// An explicit tolerance.
		webhookDoc("github", []string{"gh_one"}, 600),
		// Vault references compose, including svix's whsec spelling.
		webhookDoc("stripe", []string{`secret("main/alpha")`}, nil),
		webhookDoc("svix", []string{`secret("main/whsec")`}, nil),
		// Rotation across sources.
		webhookDoc("stripe", []string{`secret("main/alpha")`, "rk_inline"}, nil),
	}
	for i, doc := range docs {
		if err := doc.Validate(); err != nil {
			t.Fatalf("doc %d: Validate refused a valid policy: %v", i, err)
		}
		if _, err := doc.Compile(); err != nil {
			t.Fatalf("doc %d: Compile refused a valid policy: %v", i, err)
		}
	}
}

// --- vault composition ---------------------------------------------------------

func TestWebhookVaultSecretRoundTrip(t *testing.T) {
	plain := []byte("vault-svix-plain-key")
	installVaults(t, mainVaultSources(t, map[string]string{
		"rk":    "rk_live_vault_secret",
		"whsec": whsec(plain),
	}))

	body := []byte(`{"vault":true}`)

	t.Run("stripe resolves at build and verifies", func(t *testing.T) {
		hook := webhookHook(t, webhookDoc("stripe", []string{`secret("main/rk")`}, nil))
		admitted(t, hook(signedPost("/hook", body, stripeHeaders([]byte("rk_live_vault_secret"), tsAt(0), body))))
	})
	t.Run("svix composes whsec with the vault", func(t *testing.T) {
		hook := webhookHook(t, webhookDoc("svix", []string{`secret("main/whsec")`}, nil))
		admitted(t, hook(signedPost("/hook", body, svixHeaders(plain, tsAt(0), body))))
	})
	t.Run("a wrong vault key refuses", func(t *testing.T) {
		hook := webhookHook(t, webhookDoc("stripe", []string{`secret("main/rk")`}, nil))
		refused(t, hook(signedPost("/hook", body, stripeHeaders([]byte("rk_wrong"), tsAt(0), body))))
	})
	t.Run("the reference text itself is not a key", func(t *testing.T) {
		hook := webhookHook(t, webhookDoc("stripe", []string{`secret("main/rk")`}, nil))
		refused(t, hook(signedPost("/hook", body, stripeHeaders([]byte(`secret("main/rk")`), tsAt(0), body))))
	})
}

// TestWebhookRefusesDigestPrefixedSecret is the vault composition's sharp
// edge, its own test because it is the deliberate difference from the
// credential path: there, a sha256: vault entry is the point; here, an HMAC
// key cannot be a digest, so the same vault entry that basic-auth accepts
// must fail this action's build.
func TestWebhookRefusesDigestPrefixedSecret(t *testing.T) {
	digest := "sha256:" + strings.Repeat("ab", 32)

	t.Run("from a vault", func(t *testing.T) {
		installVaults(t, map[string]VaultSource{"main": {File: writeVaultFile(t, map[string]string{"dig": digest})}})
		err := webhookDoc("stripe", []string{`secret("main/dig")`}, nil).Validate()
		const want = `entry 0 (vault "main" key "dig") is a sha256: digest; webhook verification needs the plaintext secret`
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("Validate = %v, want the digest refusal naming the provenance", err)
		}
	})
}

// TestWebhookRefusesCRLFPostResolution mirrors TestVaultRefusesCRAndLFPostResolution
// for the webhook path: the CR/LF rule must hold for a value the vault
// produced, not just for an inline literal. The double-quoted YAML scalar is
// how a line break gets into a vault value.
func TestWebhookRefusesCRLFPostResolution(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vault.yml")
	if err := os.WriteFile(path, []byte("bad: \"rk_live\\r\\nsecret\"\n"), 0600); err != nil {
		t.Fatalf("failed to write vault file: %v", err)
	}
	installVaults(t, map[string]VaultSource{"main": {File: path}})

	err := webhookDoc("stripe", []string{`secret("main/bad")`}, nil).Validate()
	const want = `entry 0 (vault "main" key "bad") contains a CR or LF, which no signing secret should carry (header injection)`
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("Validate = %v, want the CR/LF refusal naming the provenance", err)
	}
}

// --- composition with the rest of the engine -----------------------------------

func TestWebhookSuccessIsANoopForLaterRules(t *testing.T) {
	doc := reqPolicy(
		rule(ActionWebhookVerification, nil, map[string]interface{}{
			"provider": "stripe", "secrets": []interface{}{"rk_live_noop"},
		}),
		rule(ActionAddHeaders, nil, map[string]interface{}{
			"headers": map[string]interface{}{"X-Verified": "webhook"},
		}),
	)
	hook := webhookHook(t, doc)

	body := []byte(`{"ok":1}`)
	v := hook(signedPost("/hook", body, stripeHeaders([]byte("rk_live_noop"), tsAt(0), body)))
	if v == nil || v.Terminate != nil || len(v.Add) != 1 || v.Add[0] != "x-verified: webhook" {
		t.Fatalf("a verified webhook must be a no-op for itself and let later rules run: %+v", v)
	}
}

func TestWebhookHonorsConditions(t *testing.T) {
	doc := reqPolicy(rule(ActionWebhookVerification, []string{`req.url.path.startsWith('/webhook')`}, map[string]interface{}{
		"provider": "github", "secrets": []interface{}{"gh_cond"},
	}))
	hook := webhookHook(t, doc)

	body := []byte(`{"cond":1}`)
	// Off the gated path the rule does not apply: even a garbage signature
	// sails through, because this policy never promised to verify it.
	admitted(t, hook(signedPost("/other", body, githubHeaders([]byte("wrong"), body))))
	// On the path, the garbage earns its 403.
	refused(t, hook(signedPost("/webhook", body, githubHeaders([]byte("wrong"), body))))
	// And a genuine signature on the path is admitted.
	admitted(t, hook(signedPost("/webhook", body, githubHeaders([]byte("gh_cond"), body))))
}

// --- the body-cap capability -----------------------------------------------------

func TestRequestBodyCap(t *testing.T) {
	var nilCompiled *Compiled
	if got := nilCompiled.RequestBodyCap(); got != 0 {
		t.Fatalf("a nil compiled policy reports cap %d, want 0", got)
	}
	if got := (&Compiled{}).RequestBodyCap(); got != 0 {
		t.Fatalf("an empty compiled policy reports cap %d, want 0", got)
	}

	c, _ := compileRequest(t, reqPolicy(
		rule(ActionAddHeaders, nil, map[string]interface{}{"headers": map[string]interface{}{"X-A": "1"}}),
		rule(ActionBasicAuth, nil, map[string]interface{}{"credentials": []interface{}{"a:b"}}),
	))
	if got := c.RequestBodyCap(); got != 0 {
		t.Fatalf("a policy without a body-consuming action reports cap %d, want 0", got)
	}

	// Every provider declares the same need; one rule is enough to make the
	// rewriter buffer.
	for _, tc := range webhookCases {
		c, _ := compileRequest(t, webhookDoc(tc.provider, []string{tc.secret}, nil))
		if got := c.RequestBodyCap(); got != webhookBodyCap {
			t.Fatalf("%s: RequestBodyCap = %d, want %d", tc.provider, got, webhookBodyCap)
		}
	}

	// Validate and Compile share the traversal, so a policy that validates
	// has the flag set in its compiled form too -- there is no spelling of
	// "verified webhooks" that leaves it unset.
	c, _ = compileRequest(t, reqPolicy(
		rule(ActionWebhookVerification, nil, map[string]interface{}{
			"provider": "stripe", "secrets": []interface{}{"rk"},
		}),
		rule(ActionLog, nil, map[string]interface{}{"metadata": map[string]interface{}{"p": "1"}}),
	))
	if got := c.RequestBodyCap(); got != webhookBodyCap {
		t.Fatalf("a combined request policy reports cap %d, want %d", got, webhookBodyCap)
	}
}

// --- the tolerance boundary --------------------------------------------------------

// TestWebhookToleranceBoundaryIsInclusive drives the schemes with a frozen
// clock, which is the only way to hit the exact second deterministically: the
// refusal is strict (skew of exactly the tolerance is admitted), because a
// timestamp at the configured bound is the operator's stated "accept".
func TestWebhookToleranceBoundaryIsInclusive(t *testing.T) {
	key := []byte("rk_live_boundary")
	body := []byte(`{"b":1}`)
	now := time.Unix(1_700_000_000, 0)

	newVerify := func() *webhookVerify {
		return &webhookVerify{header: http.Header{}, body: body, key: key, tolerance: 300 * time.Second, now: now}
	}

	for ts, want := range map[string]bool{
		"1700000300": true,  // exactly the tolerance ahead of now
		"1700000301": false, // one second past it
		"1699999700": true,  // exactly the tolerance behind now
		"1699999699": false, // one second past it
	} {
		v := newVerify()
		v.header.Set("Stripe-Signature", stripeHeaders(key, ts, body)["Stripe-Signature"])
		if got := stripeVerify(v); got != want {
			t.Fatalf("stripeVerify at ts %s = %v, want %v", ts, got, want)
		}

		// svix shares the tolerance rule through timestampFresh; drive it
		// through the scheme so both callers stay pinned to the helper.
		v = newVerify()
		headers := svixHeaders(key, ts, body)
		for k, val := range headers {
			v.header.Set(k, val)
		}
		if got := svixVerify(v); got != want {
			t.Fatalf("svixVerify at ts %s = %v, want %v", ts, got, want)
		}
	}
}
