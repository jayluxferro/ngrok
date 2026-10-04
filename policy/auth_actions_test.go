package policy

// Tests for the static-credential authentication actions (SPEC-CLUSTER6):
// basic-auth, bearer-auth and apikey-auth. The validators are tables of
// documents that must be refused with an error naming the field, the way
// TestValidateRejects does for the older actions; the executors are driven
// through the real request hook -- the same Compiled.RequestHook call the
// server's Tunnel.join makes for edge-terminated tunnels and client
// attachPolicyHooks makes for agent-terminated ones -- so that what is
// asserted is what the rewriter would answer with.
//
// The 401s are asserted on the rendered wire bytes (SyntheticResponse.Render),
// not just on the verdict struct: the WWW-Authenticate challenge is the part
// of these actions a client actually interoperates with, and Render is the
// last place it gets shaped before a public client reads it.

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"ngrok/rewriter"
)

// --- validators -------------------------------------------------------------

func TestAuthActionsValidateRejects(t *testing.T) {
	tests := []struct {
		name string
		doc  *TrafficPolicy
		want string // a substring of the error: the field, and why
	}{
		// basic-auth
		{
			"basic-auth without credentials",
			reqPolicy(rule(ActionBasicAuth, nil, nil)),
			`config field "credentials" is required`,
		},
		{
			"basic-auth with an empty credential list",
			reqPolicy(rule(ActionBasicAuth, nil, map[string]interface{}{"credentials": []interface{}{}})),
			`config field "credentials" must have at least one entry (an empty list would refuse every request)`,
		},
		{
			"basic-auth entry without a colon",
			reqPolicy(rule(ActionBasicAuth, nil, map[string]interface{}{"credentials": []interface{}{"alice-secret"}})),
			`config field "credentials" entry 0 is not "user:password"-shaped: a ":" separator is required (an empty user or password is allowed)`,
		},
		{
			"basic-auth entry that is not a string",
			reqPolicy(rule(ActionBasicAuth, nil, map[string]interface{}{"credentials": []interface{}{42}})),
			`config field "credentials" entry 0 must be a string, got a number`,
		},
		{
			"basic-auth entry with a CR",
			reqPolicy(rule(ActionBasicAuth, nil, map[string]interface{}{"credentials": []interface{}{"alice:sec\rret"}})),
			`config field "credentials" entry 0 contains a CR or LF`,
		},
		{
			"basic-auth realm with an LF",
			reqPolicy(rule(ActionBasicAuth, nil, map[string]interface{}{
				"credentials": []interface{}{"a:b"},
				"realm":       "no\nsuch realm",
			})),
			`config field "realm" contains a CR or LF, which would inject a header into the challenge`,
		},
		{
			"basic-auth realm with a quote",
			reqPolicy(rule(ActionBasicAuth, nil, map[string]interface{}{
				"credentials": []interface{}{"a:b"},
				"realm":       `rea"lms`,
			})),
			`config field "realm" contains a quote or a backslash, which the quoted-string grammar of a challenge cannot carry`,
		},
		{
			"basic-auth with an unknown field",
			reqPolicy(rule(ActionBasicAuth, nil, map[string]interface{}{
				"credentials": []interface{}{"a:b"},
				"users":       []interface{}{"a"},
			})),
			`unknown config field "users" (this action documents: realm, credentials)`,
		},
		{
			"basic-auth credentials that are not a list",
			reqPolicy(rule(ActionBasicAuth, nil, map[string]interface{}{"credentials": "alice:secret"})),
			`config field "credentials" must be a list of strings, got a string`,
		},

		// bearer-auth
		{
			"bearer-auth without tokens",
			reqPolicy(rule(ActionBearerAuth, nil, nil)),
			`config field "tokens" is required`,
		},
		{
			"bearer-auth with an empty token list",
			reqPolicy(rule(ActionBearerAuth, nil, map[string]interface{}{"tokens": []interface{}{}})),
			`config field "tokens" must have at least one entry`,
		},
		{
			"bearer-auth with an empty token",
			reqPolicy(rule(ActionBearerAuth, nil, map[string]interface{}{"tokens": []interface{}{""}})),
			`config field "tokens" entry 0 is empty, which no request could ever match`,
		},
		{
			"bearer-auth token with a CR",
			reqPolicy(rule(ActionBearerAuth, nil, map[string]interface{}{"tokens": []interface{}{"tok\r"}})),
			`config field "tokens" entry 0 contains a CR or LF`,
		},

		// apikey-auth
		{
			"apikey-auth without keys",
			reqPolicy(rule(ActionAPIKeyAuth, nil, nil)),
			`config field "keys" is required`,
		},
		{
			"apikey-auth with an empty key list",
			reqPolicy(rule(ActionAPIKeyAuth, nil, map[string]interface{}{"keys": []interface{}{}})),
			`config field "keys" must have at least one entry`,
		},
		{
			"apikey-auth with an empty key",
			reqPolicy(rule(ActionAPIKeyAuth, nil, map[string]interface{}{"keys": []interface{}{""}})),
			`config field "keys" entry 0 is empty, which no request could ever match`,
		},
		{
			"apikey-auth with an invalid header name",
			reqPolicy(rule(ActionAPIKeyAuth, nil, map[string]interface{}{
				"header": "bad name",
				"keys":   []interface{}{"k"},
			})),
			`config field "header": "bad name" is not a valid header name`,
		},
		{
			"apikey-auth header that is not a string",
			reqPolicy(rule(ActionAPIKeyAuth, nil, map[string]interface{}{
				"header": 7,
				"keys":   []interface{}{"k"},
			})),
			`config field "header" must be a string, got a number`,
		},
		{
			"apikey-auth with an unknown field",
			reqPolicy(rule(ActionAPIKeyAuth, nil, map[string]interface{}{
				"keys":    []interface{}{"k"},
				"secrets": []interface{}{"s"},
			})),
			`unknown config field "secrets" (this action documents: header, keys)`,
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
		})
	}
}

func TestAuthActionsValidateAccepts(t *testing.T) {
	docs := []*TrafficPolicy{
		// basic-auth's optional fields at their defaults, and every shape the
		// colon rule allows: empty user, empty password.
		reqPolicy(rule(ActionBasicAuth, nil, map[string]interface{}{
			"credentials": []interface{}{"alice:secret", ":nopassword", "nouser:"},
		})),
		reqPolicy(rule(ActionBasicAuth, nil, map[string]interface{}{
			"realm":       "restricted area",
			"credentials": []interface{}{"alice:secret"},
		})),
		reqPolicy(rule(ActionBearerAuth, nil, map[string]interface{}{
			"tokens": []interface{}{"tok_1", "tok_2"},
		})),
		reqPolicy(rule(ActionAPIKeyAuth, nil, map[string]interface{}{
			"keys": []interface{}{"ak-live-0001"},
		})),
		reqPolicy(rule(ActionAPIKeyAuth, nil, map[string]interface{}{
			"header": "x-custom-key", // any case: the lookup canonicalizes
			"keys":   []interface{}{"k"},
		})),
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

// --- executors --------------------------------------------------------------

// basicCreds encodes the "user:password" pair the way a client's
// Authorization header would carry it.
func basicCreds(user, pass string) string {
	return base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
}

// terminated digs the synthetic response out of a verdict, failing the test
// when the hook admitted the request instead.
func terminated(t *testing.T, v *rewriter.RequestVerdict) *rewriter.SyntheticResponse {
	t.Helper()
	if v == nil || v.Terminate == nil {
		t.Fatalf("the request was admitted, want a 401 verdict")
	}
	if v.Terminate.StatusCode != http.StatusUnauthorized {
		t.Fatalf("the verdict answers %d, want 401", v.Terminate.StatusCode)
	}
	return v.Terminate
}

// admit asserts the other direction: no verdict at all, which is what the
// rewriter reads as "nothing to do".
func admitted(t *testing.T, v *rewriter.RequestVerdict) {
	t.Helper()
	if v != nil {
		t.Fatalf("the request was refused with %+v, want a nil verdict", v)
	}
}

// wireHeaders renders the synthetic response the way it reaches the client,
// so the challenges are asserted as the exact bytes on the wire.
func wireHeaders(s *rewriter.SyntheticResponse) string {
	return string(s.Render())
}

func TestBasicAuthExecutes(t *testing.T) {
	doc := reqPolicy(rule(ActionBasicAuth, nil, map[string]interface{}{
		"credentials": []interface{}{"alice:secret", "bob:hunter2"},
	}))
	c, lg := compileRequest(t, doc)
	hook := c.RequestHook(lg, "1.2.3.4:1")

	t.Run("a missing header earns the default-realm challenge", func(t *testing.T) {
		s := terminated(t, hook(get("/", nil)))
		if body := s.Body; body != "basic-auth: this endpoint requires credentials" {
			t.Fatalf("body = %q", body)
		}
		if wire := wireHeaders(s); !strings.Contains(wire, "WWW-Authenticate: Basic realm=\"ngrok\"\r\n") {
			t.Fatalf("the challenge on the wire is wrong:\n%s", wire)
		}
	})

	t.Run("a wrong password is refused without echoing it", func(t *testing.T) {
		const attempted = "secret-but-wrong"
		s := terminated(t, hook(get("/", map[string]string{
			"Authorization": "Basic " + basicCreds("alice", attempted),
		})))
		if body := s.Body; body != "basic-auth: credentials are invalid" {
			t.Fatalf("body = %q", body)
		}
		// The refused credential must appear nowhere in what goes back on the
		// wire or into the log: spec section 4's rule, checked where a
		// regression would first show up.
		if wire := wireHeaders(s); strings.Contains(wire, attempted) {
			t.Fatalf("the wire response echoes the attempted credential:\n%s", wire)
		}
		if logged := lg.lines(lg.info) + lg.lines(lg.warn); strings.Contains(logged, attempted) {
			t.Fatalf("a log line carries the attempted credential:\n%s", logged)
		}
	})

	t.Run("each configured credential is accepted", func(t *testing.T) {
		for _, user := range []string{"alice", "bob"} {
			pass := "secret"
			if user == "bob" {
				pass = "hunter2"
			}
			admitted(t, hook(get("/", map[string]string{
				"Authorization": "Basic " + basicCreds(user, pass),
			})))
		}
	})

	t.Run("the scheme is case-insensitive", func(t *testing.T) {
		admitted(t, hook(get("/", map[string]string{
			"Authorization": "basic " + basicCreds("alice", "secret"),
		})))
	})

	t.Run("malformed credentials earn the challenge", func(t *testing.T) {
		for _, nameAndValue := range [][2]string{
			{"not base64", "Basic !!!not-base64!!!"},
			{"no colon inside", "Basic " + base64.StdEncoding.EncodeToString([]byte("alice-secret"))},
			{"wrong scheme", "Bearer " + basicCreds("alice", "secret")},
			{"no space after the scheme", "Basic" + basicCreds("alice", "secret")},
			{"empty credentials", "Basic "},
		} {
			s := terminated(t, hook(get("/", map[string]string{"Authorization": nameAndValue[1]})))
			if body := s.Body; !strings.HasPrefix(body, "basic-auth: ") {
				t.Fatalf("%s: body = %q", nameAndValue[0], body)
			}
		}
	})

	t.Run("a configured realm travels in the challenge", func(t *testing.T) {
		doc := reqPolicy(rule(ActionBasicAuth, nil, map[string]interface{}{
			"realm":       "restricted",
			"credentials": []interface{}{"alice:secret"},
		}))
		hook := mustRequestHook(t, doc)
		if wire := wireHeaders(terminated(t, hook(get("/", nil)))); !strings.Contains(wire, `WWW-Authenticate: Basic realm="restricted"`) {
			t.Fatalf("the configured realm is not in the challenge:\n%s", wire)
		}
	})

	t.Run("the log line names the action and never the credential", func(t *testing.T) {
		hook(get("/", map[string]string{"Authorization": "Basic " + basicCreds("alice", "hunter2-wrong")}))
		logged := lg.lines(lg.info)
		if !strings.Contains(logged, "basic-auth:") || !strings.Contains(logged, "refused with status 401") {
			t.Fatalf("the refusal is not logged with the action and the outcome:\n%s", logged)
		}
		if strings.Contains(logged, "alice") || strings.Contains(logged, "hunter2") {
			t.Fatalf("the log line carries credential material:\n%s", logged)
		}
	})
}

func TestBearerAuthExecutes(t *testing.T) {
	doc := reqPolicy(rule(ActionBearerAuth, nil, map[string]interface{}{
		"tokens": []interface{}{"tok_abcdef", "tok_2"},
	}))
	c, lg := compileRequest(t, doc)
	hook := c.RequestHook(lg, "1.2.3.4:1")

	t.Run("a missing token earns a bare Bearer challenge", func(t *testing.T) {
		s := terminated(t, hook(get("/", nil)))
		if body := s.Body; body != "bearer-auth: this endpoint requires a bearer token" {
			t.Fatalf("body = %q", body)
		}
		wire := wireHeaders(s)
		if !strings.Contains(wire, "WWW-Authenticate: Bearer\r\n") {
			t.Fatalf("the challenge on the wire is wrong:\n%s", wire)
		}
		// The spec fixes this challenge at a bare "Bearer": no realm, no
		// parameters after it.
		if strings.Contains(wire, "WWW-Authenticate: Bearer ") {
			t.Fatalf("the challenge carries parameters it must not:\n%s", wire)
		}
	})

	t.Run("a wrong token is refused and never echoed", func(t *testing.T) {
		s := terminated(t, hook(get("/", map[string]string{"Authorization": "Bearer tok_wrong"})))
		if body := s.Body; body != "bearer-auth: the bearer token is invalid" {
			t.Fatalf("body = %q", body)
		}
		if strings.Contains(wireHeaders(s), "tok_wrong") {
			t.Fatalf("the wire response echoes the attempted token")
		}
		if logged := lg.lines(lg.info); strings.Contains(logged, "tok_wrong") {
			t.Fatalf("the log line carries the attempted token:\n%s", logged)
		}
	})

	t.Run("each configured token is accepted, scheme case-insensitive", func(t *testing.T) {
		for _, value := range []string{"Bearer tok_abcdef", "bearer tok_2", "BEARER tok_abcdef"} {
			admitted(t, hook(get("/", map[string]string{"Authorization": value})))
		}
	})

	t.Run("anything but one space and one token is refused", func(t *testing.T) {
		for _, value := range []string{"Bearer", "Bearer ", "Bearer tok extra", "Bearer  tok_abcdef", "Basic dXNlcjpwYXNz"} {
			terminated(t, hook(get("/", map[string]string{"Authorization": value})))
		}
	})
}

func TestAPIKeyAuthExecutes(t *testing.T) {
	doc := reqPolicy(rule(ActionAPIKeyAuth, nil, map[string]interface{}{
		"keys": []interface{}{"ak-live-0001"},
	}))
	c, lg := compileRequest(t, doc)
	hook := c.RequestHook(lg, "1.2.3.4:1")

	t.Run("a missing key names the header and sends no challenge", func(t *testing.T) {
		s := terminated(t, hook(get("/", nil)))
		if body := s.Body; body != "apikey-auth: the X-Api-Key header is required" {
			t.Fatalf("body = %q", body)
		}
		// No standard challenge exists for a custom header, and inventing one
		// would teach clients to send credentials wherever the error points.
		if wire := wireHeaders(s); strings.Contains(wire, "WWW-Authenticate") {
			t.Fatalf("an apikey refusal carries a challenge it must not:\n%s", wire)
		}
	})

	t.Run("a wrong key is refused", func(t *testing.T) {
		s := terminated(t, hook(get("/", map[string]string{"X-Api-Key": "ak-live-wrong"})))
		if body := s.Body; body != "apikey-auth: the X-Api-Key header value is invalid" {
			t.Fatalf("body = %q", body)
		}
		if strings.Contains(wireHeaders(s), "ak-live-wrong") {
			t.Fatalf("the wire response echoes the attempted key")
		}
	})

	t.Run("the key is accepted", func(t *testing.T) {
		admitted(t, hook(get("/", map[string]string{"X-Api-Key": "ak-live-0001"})))
	})

	t.Run("a custom header is looked up case-insensitively", func(t *testing.T) {
		// The config names the header one way and the request spells it
		// another; on the wire both arrive as canonical "X-Custom-Key"
		// (http.ReadRequest canonicalizes names), which is what the lookup
		// compares against.
		doc := reqPolicy(rule(ActionAPIKeyAuth, nil, map[string]interface{}{
			"header": "X-Custom-Key",
			"keys":   []interface{}{"k"},
		}))
		hook := mustRequestHook(t, doc)

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("x-cUsToM-kEy", "k")
		admitted(t, hook(req))

		s := terminated(t, hook(get("/", nil)))
		if body := s.Body; body != "apikey-auth: the X-Custom-Key header is required" {
			t.Fatalf("body = %q, want the configured spelling", body)
		}
	})
}

// TestAuthActionsComposeInDeclaredOrder pins the composition semantics the
// spec documents: actions run in declared order and the first failure
// terminates -- they are not an OR of credentials. A basic-auth failure must
// stop the chain before apikey-auth is even asked, and a pass must hand off to
// the next action normally.
func TestAuthActionsComposeInDeclaredOrder(t *testing.T) {
	doc := reqPolicy(
		rule(ActionBasicAuth, nil, map[string]interface{}{
			"credentials": []interface{}{"alice:secret"},
		}),
		rule(ActionAPIKeyAuth, nil, map[string]interface{}{
			"header": "X-Tier-2",
			"keys":   []interface{}{"k2"},
		}),
	)

	t.Run("the first failure terminates", func(t *testing.T) {
		hook := mustRequestHook(t, doc)
		s := terminated(t, hook(get("/", map[string]string{"X-Tier-2": "k2"})))
		if body := s.Body; !strings.HasPrefix(body, "basic-auth:") {
			t.Fatalf("the chain answered %q, want the first action's refusal", body)
		}
	})

	t.Run("a pass hands off to the next action", func(t *testing.T) {
		hook := mustRequestHook(t, doc)
		req := get("/", map[string]string{"X-Tier-2": "k2"})
		req.Header.Set("Authorization", "Basic "+basicCreds("alice", "secret"))
		terminated(t, hook(req)) // refused by the *second* action
	})

	t.Run("both passing is a no-op verdict", func(t *testing.T) {
		hook := mustRequestHook(t, doc)
		req := get("/", map[string]string{"X-Tier-2": "k2"})
		req.Header.Set("Authorization", "Basic "+basicCreds("alice", "secret"))
		admitted(t, hook(req))
	})

	t.Run("an auth action before a rewrite does not stop the rewrite", func(t *testing.T) {
		doc := reqPolicy(
			rule(ActionBasicAuth, nil, map[string]interface{}{"credentials": []interface{}{"alice:secret"}}),
			rule(ActionAddHeaders, nil, map[string]interface{}{"headers": map[string]interface{}{"X-Authed": "yes"}}),
		)
		hook := mustRequestHook(t, doc)
		req := get("/", nil)
		req.Header.Set("Authorization", "Basic "+basicCreds("alice", "secret"))
		v := hook(req)
		admitted(t, v)
		if len(v.Add) != 1 || v.Add[0] != "x-authed: yes" {
			t.Fatalf("the later add-headers did not run: %+v", v.Add)
		}
	})
}

// TestAuthActionRunsOnTheAgentSideHookPath is the both-side check the spec
// asks for: the client-side policy evaluation shipped in SPEC-CLUSTER5
// (client/model.go attachPolicyHooks) installs exactly this --
// Compiled.RequestHook(logger, clientAddr) into the connection's rewriter
// policy -- for agent-terminated tunnels. The same compiled policy, the same
// API, so an auth action that passes here travels with the policy everywhere
// the engine runs. No client code is needed to prove that: the hook is the
// contract.
func TestAuthActionRunsOnTheAgentSideHookPath(t *testing.T) {
	doc := reqPolicy(rule(ActionBearerAuth, nil, map[string]interface{}{
		"tokens": []interface{}{"tok_agent"},
	}))
	c, lg := compileRequest(t, doc)

	// attachPolicyHooks's call, verbatim (its logger is the client model, its
	// clientAddr the public connection's remote address).
	hook := c.RequestHook(lg, "203.0.113.9:41234")
	if hook == nil {
		t.Fatal("a compiled auth policy produced no request hook on the agent side")
	}

	terminated(t, hook(get("/", nil)))
	admitted(t, hook(get("/", map[string]string{"Authorization": "Bearer tok_agent"})))

	if logged := lg.lines(lg.info); !strings.Contains(logged, "bearer-auth: GET / refused with status 401") {
		t.Fatalf("the refusal was not logged the way the executor logs it:\n%s", logged)
	}
}

// mustRequestHook compiles a request-phase policy and returns its hook: the
// one-liner most of these tests want.
func mustRequestHook(t *testing.T, doc *TrafficPolicy) func(*http.Request) *rewriter.RequestVerdict {
	t.Helper()
	c, lg := compileRequest(t, doc)
	hook := c.RequestHook(lg, "1.2.3.4:1")
	if hook == nil {
		t.Fatal("no request hook for a policy with request rules")
	}
	return hook
}
