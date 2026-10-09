package server

// Tests for the workbench API (SPEC-CLUSTER19 §1), the static SPA routes
// (§6), the tightened CSP, and the enriched snapshots (§7). Everything here
// walks the same handler stack startAdminServer serves
// (httptest.NewServer(adminHandler(...))), which is the point: the tests pin
// what an operator's browser actually receives, headers included.
//
// The harness uses rate 0 (both limiters off) everywhere except the one rate
// test, so test order and request counts never trip a 429 by accident.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"ngrok/client"
	"ngrok/msg"
	"ngrok/policy"

	"gopkg.in/yaml.v3"
)

// testAdminToken is the token auth the auth-requiring tests present.
const testAdminToken = "test-admin-token"

// newAdminTestServer builds the admin handler with token auth and no rate
// limit. auth may be nil for the no-auth harness.
func newAdminTestServer(t *testing.T, auth *adminAuth) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(adminHandler(false, auth, 0))
	t.Cleanup(srv.Close)
	return srv
}

// adminGet issues a GET against srv presenting the admin token.
func adminGet(t *testing.T, srv *httptest.Server, path string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, srv.URL+path, nil)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	if testAdminToken != "" {
		req.Header.Set("X-Ngrok-Admin-Token", testAdminToken)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return resp
}

// adminPost issues a POST with a JSON envelope against srv, presenting the
// admin token.
func adminPost(t *testing.T, srv *httptest.Server, path, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, srv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	req.Header.Set("Content-Type", "application/json")
	if testAdminToken != "" {
		req.Header.Set("X-Ngrok-Admin-Token", testAdminToken)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return resp
}

// decodeAPILogin-free body reader: every API answer must be JSON.
func decodeJSONBody(t *testing.T, resp *http.Response) map[string]interface{} {
	t.Helper()
	defer resp.Body.Close()
	var payload map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("response is not JSON (status %d): %v", resp.StatusCode, err)
	}
	return payload
}

// validConfigDoc is a config document the agent's own validator accepts.
const validConfigDoc = `server_addr: "127.0.0.1:4443"
tunnels:
  web:
    proto:
      http: 8080
`

// invalidConfigDoc fails in the negative-int refusal LoadConfiguration has
// always raised, so the verdict message is the validator's own words.
const invalidConfigDoc = `server_addr: "127.0.0.1:4443"
inspect_max_body_bytes: -5
`

// validPolicyDoc is a one-action policy the engine accepts.
const validPolicyDoc = `on_http_request:
  - name: deny
    config:
      status_code: 404
`

// invalidPolicyDoc names a config field deny does not document.
const invalidPolicyDoc = `on_http_request:
  - name: deny
    config:
      bogus_field: 1
`

// --- the 5x arithmetic (§2) -------------------------------------------------

func TestAPIRateForArithmetic(t *testing.T) {
	cases := []struct {
		adminRate int
		want      int
	}{
		{120, 600}, // the defaults: 600/min = 10 validations/s sustained
		{1, 5},
		{10, 50},
		{0, 0},  // -adminRate 0 unthrottles the API too
		{-1, 0}, // and a nonsense negative is off, not a negative budget
	}
	for _, c := range cases {
		if got := apiRateFor(c.adminRate); got != c.want {
			t.Errorf("apiRateFor(%d) = %d, want %d", c.adminRate, got, c.want)
		}
	}
}

// TestAPIRateLimitHasItsOwnBudget walks a handler with -adminRate 1: five
// workbench calls must survive (the 5x budget) and the sixth must be dropped
// by the API limiter -- not by the pages limiter, which it never shares.
func TestAPIRateLimitHasItsOwnBudget(t *testing.T) {
	srv := httptest.NewServer(adminHandler(false, nil, 1))
	defer srv.Close()

	body := fmt.Sprintf(`{"content": %q}`, validConfigDoc)
	var got429 bool
	for i := 1; i <= 6; i++ {
		resp, err := http.Post(srv.URL+"/api/validate/config", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		resp.Body.Close()
		switch {
		case resp.StatusCode == http.StatusOK:
			if got429 {
				t.Fatalf("request %d succeeded after a 429; the limiter's window reset mid-test", i)
			}
		case resp.StatusCode == http.StatusTooManyRequests:
			got429 = true
			if i != 6 {
				t.Fatalf("request %d of 6 was rate-limited; the API budget is not 5x adminRate", i)
			}
		default:
			t.Fatalf("request %d: unexpected status %d", i, resp.StatusCode)
		}
	}
	if !got429 {
		t.Fatal("the sixth request was not rate-limited; the API budget is not capped")
	}
}

// --- wrapper semantics: auth and method pinning ------------------------------

func TestAPIRoutesRequireAuthAndPinMethods(t *testing.T) {
	srv := newAdminTestServer(t, &adminAuth{Token: testAdminToken, Required: true})

	// No token: every API route answers 401 when spoken to with the method
	// it serves. (The wrapper pins methods before it checks auth, so a wrong
	// method without credentials is a 405 -- pinned below, with credentials.)
	unauthed := map[string]string{
		"/api/schema":          http.MethodGet,
		"/api/presets":         http.MethodGet,
		"/api/validate/config": http.MethodPost,
		"/api/validate/policy": http.MethodPost,
		"/api/render":          http.MethodPost,
		"/static/app.js":       http.MethodGet,
	}
	for path, method := range unauthed {
		req, err := http.NewRequest(method, srv.URL+path, strings.NewReader("{}"))
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s without credentials: got %d, want 401", path, resp.StatusCode)
		}
	}

	// Wrong method, with credentials: the wrapper answers 405 before the
	// handler runs.
	wrongMethod := map[string]string{
		"/api/schema":          http.MethodPost,
		"/api/presets":         http.MethodPost,
		"/api/validate/config": http.MethodGet,
		"/api/validate/policy": http.MethodGet,
		"/api/render":          http.MethodGet,
	}
	for path, method := range wrongMethod {
		req, err := http.NewRequest(method, srv.URL+path, strings.NewReader("{}"))
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		req.Header.Set("X-Ngrok-Admin-Token", testAdminToken)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("%s with %s: got %d, want 405", path, method, resp.StatusCode)
		}
	}
}

// --- POST /api/validate/config ----------------------------------------------

func TestAPIValidateConfig(t *testing.T) {
	srv := newAdminTestServer(t, &adminAuth{Token: testAdminToken, Required: true})

	// 200, valid.
	resp := adminPost(t, srv, "/api/validate/config", fmt.Sprintf(`{"content": %q}`, validConfigDoc))
	payload := decodeJSONBody(t, resp)
	if resp.StatusCode != http.StatusOK || payload["valid"] != true {
		t.Errorf("valid config: got %d %v, want 200 {valid:true}", resp.StatusCode, payload)
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("valid config: Cache-Control %q, want no-store", resp.Header.Get("Cache-Control"))
	}

	// 200, invalid, with the validator's message verbatim.
	resp = adminPost(t, srv, "/api/validate/config", fmt.Sprintf(`{"content": %q}`, invalidConfigDoc))
	payload = decodeJSONBody(t, resp)
	if resp.StatusCode != http.StatusOK || payload["valid"] != false {
		t.Errorf("invalid config: got %d %v, want 200 {valid:false,...}", resp.StatusCode, payload)
	}
	msg, _ := payload["error"].(string)
	if !strings.Contains(msg, "inspect_max_body_bytes must not be negative") {
		t.Errorf("invalid config: error %q does not carry the validator's message", msg)
	}

	// A document with no keys at all is valid: every default applies.
	resp = adminPost(t, srv, "/api/validate/config", `{"content": ""}`)
	payload = decodeJSONBody(t, resp)
	if resp.StatusCode != http.StatusOK || payload["valid"] != true {
		t.Errorf("empty config: got %d %v, want 200 {valid:true}", resp.StatusCode, payload)
	}

	// The old single-token format is a parse error, not a valid document.
	// SPEC-CLUSTER19 §5's parenthetical ("a token-only doc is valid") is
	// contradicted by the loader's own reality, and parity wins: the legacy
	// branch sits behind the YAML parse, and yaml.v3 refuses to decode a
	// scalar into the struct -- so LoadConfiguration has refused a bare token
	// since the parser swap. The workbench is not going to be the one road
	// that accepts what the agent refuses. Pinned the same way on the client
	// side (client/config_test.go, TestValidateConfigurationDocLegacyToken).
	resp = adminPost(t, srv, "/api/validate/config", `{"content": "a1b2c3d4"}`)
	payload = decodeJSONBody(t, resp)
	if resp.StatusCode != http.StatusOK || payload["valid"] != false {
		t.Errorf("token-only config: got %d %v, want 200 {valid:false,...}", resp.StatusCode, payload)
	}
	if msg, _ := payload["error"].(string); !strings.Contains(msg, "cannot unmarshal !!str") {
		t.Errorf("token-only config: error %q is not the loader's parse refusal", msg)
	}

	// 422: the vault refusal, in both spellings the raw scan catches.
	for name, doc := range map[string]string{
		"secret reference": `tunnels:
  web:
    traffic_policy:
      on_http_request:
        - name: log
          config:
            metadata:
              key: secret("db/password")
`,
		"vaults block": `vaults:
  db:
    type: env
`,
	} {
		resp := adminPost(t, srv, "/api/validate/config", fmt.Sprintf(`{"content": %q}`, doc))
		payload := decodeJSONBody(t, resp)
		if resp.StatusCode != http.StatusUnprocessableEntity {
			t.Errorf("%s: got %d, want 422", name, resp.StatusCode)
		}
		if msg, _ := payload["error"].(string); msg != client.ErrVaultRefused.Error() {
			t.Errorf("%s: 422 body %q, want the sentinel's own wording", name, msg)
		}
	}

	// 400: malformed envelope, two ways.
	for name, body := range map[string]string{
		"not json":     `{not json`,
		"wrong type":   `{"content": 42}`,
		"not an array": `[1, 2, 3]`,
	} {
		resp := adminPost(t, srv, "/api/validate/config", body)
		payload := decodeJSONBody(t, resp)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: got %d, want 400", name, resp.StatusCode)
		}
		if _, ok := payload["error"].(string); !ok {
			t.Errorf("%s: 400 body %v names no error", name, payload)
		}
	}

	// 413: one byte past the cap.
	oversize := fmt.Sprintf(`{"content": %q}`, strings.Repeat("a", apiMaxBodyBytes))
	resp = adminPost(t, srv, "/api/validate/config", oversize)
	payload = decodeJSONBody(t, resp)
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("oversize body: got %d, want 413", resp.StatusCode)
	}
	if msg, _ := payload["error"].(string); !strings.Contains(msg, fmt.Sprintf("%d byte", apiMaxBodyBytes)) {
		t.Errorf("413 body %q does not name the cap", msg)
	}
}

// --- POST /api/validate/policy ----------------------------------------------

func TestAPIValidatePolicy(t *testing.T) {
	srv := newAdminTestServer(t, &adminAuth{Token: testAdminToken, Required: true})

	resp := adminPost(t, srv, "/api/validate/policy", fmt.Sprintf(`{"content": %q}`, validPolicyDoc))
	payload := decodeJSONBody(t, resp)
	if resp.StatusCode != http.StatusOK || payload["valid"] != true {
		t.Errorf("valid policy: got %d %v, want 200 {valid:true}", resp.StatusCode, payload)
	}

	resp = adminPost(t, srv, "/api/validate/policy", fmt.Sprintf(`{"content": %q}`, invalidPolicyDoc))
	payload = decodeJSONBody(t, resp)
	if resp.StatusCode != http.StatusOK || payload["valid"] != false {
		t.Errorf("invalid policy: got %d %v, want 200 {valid:false,...}", resp.StatusCode, payload)
	}
	if msg, _ := payload["error"].(string); !strings.Contains(msg, `unknown config field "bogus_field"`) {
		t.Errorf("invalid policy: error %q is not the engine's message", msg)
	}

	// A document that does not parse is an invalid document, not a fault.
	resp = adminPost(t, srv, "/api/validate/policy", `{"content": "on_http_request: ["}`)
	payload = decodeJSONBody(t, resp)
	if resp.StatusCode != http.StatusOK || payload["valid"] != false {
		t.Errorf("unparseable policy: got %d %v, want 200 {valid:false,...}", resp.StatusCode, payload)
	}

	// 422: the raw scan refuses secret( before any parsing -- even somewhere
	// a policy could never carry one, because fail-closed is the point.
	resp = adminPost(t, srv, "/api/validate/policy",
		fmt.Sprintf(`{"content": %q}`, "on_http_request: [] # secret(vault/key)"))
	payload = decodeJSONBody(t, resp)
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("policy with secret(: got %d, want 422", resp.StatusCode)
	}
	if msg, _ := payload["error"].(string); msg != client.ErrVaultRefused.Error() {
		t.Errorf("422 body %q, want the sentinel's own wording", msg)
	}

	// 400 and 413 as on every POST endpoint.
	if resp := adminPost(t, srv, "/api/validate/policy", `{`); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("malformed envelope: got %d, want 400", resp.StatusCode)
	}
	oversize := fmt.Sprintf(`{"content": %q}`, strings.Repeat("a", apiMaxBodyBytes))
	if resp := adminPost(t, srv, "/api/validate/policy", oversize); resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("oversize body: got %d, want 413", resp.StatusCode)
	}
}

// --- POST /api/render --------------------------------------------------------

func TestAPIRender(t *testing.T) {
	srv := newAdminTestServer(t, &adminAuth{Token: testAdminToken, Required: true})

	// A config round trip: the rendered document must itself validate, and
	// must carry the keys the operator wrote (canonical form, not a lossy
	// guess).
	resp := adminPost(t, srv, "/api/render", fmt.Sprintf(`{"kind": "config", "content": %q}`, validConfigDoc))
	payload := decodeJSONBody(t, resp)
	if resp.StatusCode != http.StatusOK || payload["valid"] != true {
		t.Fatalf("render config: got %d %v, want 200 {valid:true,...}", resp.StatusCode, payload)
	}
	rendered, _ := payload["rendered"].(string)
	if rendered == "" {
		t.Fatal("render config: empty rendered document")
	}
	if !strings.Contains(rendered, "server_addr: 127.0.0.1:4443") {
		t.Errorf("render config: rendered document does not carry the normalized key:\n%s", rendered)
	}
	// 2-space indent: the style a config file is written in.
	if !strings.Contains(rendered, "\n  web:\n") {
		t.Errorf("render config: rendered document is not 2-space indented:\n%s", rendered)
	}

	// The round trip closes: the rendered text re-validates.
	resp = adminPost(t, srv, "/api/validate/config", fmt.Sprintf(`{"content": %q}`, rendered))
	payload = decodeJSONBody(t, resp)
	if payload["valid"] != true {
		t.Errorf("rendered config does not re-validate: %v", payload)
	}

	// A policy round trip, same story.
	resp = adminPost(t, srv, "/api/render", fmt.Sprintf(`{"kind": "policy", "content": %q}`, validPolicyDoc))
	payload = decodeJSONBody(t, resp)
	if resp.StatusCode != http.StatusOK || payload["valid"] != true {
		t.Fatalf("render policy: got %d %v, want 200 {valid:true,...}", resp.StatusCode, payload)
	}
	rendered, _ = payload["rendered"].(string)
	if !strings.Contains(rendered, "on_http_request:") || !strings.Contains(rendered, "name: deny") {
		t.Errorf("render policy: unexpected rendered document:\n%s", rendered)
	}

	// An invalid document is a 200 verdict, both kinds.
	for _, body := range []string{
		fmt.Sprintf(`{"kind": "config", "content": %q}`, invalidConfigDoc),
		fmt.Sprintf(`{"kind": "policy", "content": %q}`, invalidPolicyDoc),
		`{"kind": "widget", "content": "x"}`,
	} {
		resp := adminPost(t, srv, "/api/render", body)
		payload := decodeJSONBody(t, resp)
		if resp.StatusCode != http.StatusOK || payload["valid"] != false {
			t.Errorf("render %q: got %d %v, want 200 {valid:false,...}", body, resp.StatusCode, payload)
		}
		if _, ok := payload["rendered"]; ok {
			t.Errorf("render %q: an invalid document rendered anyway", body)
		}
	}

	// The refusals travel with render: a vault-bearing document is not
	// renderable either, in either kind.
	resp = adminPost(t, srv, "/api/render", fmt.Sprintf(`{"kind": "config", "content": %q}`, "vaults:\n  db:\n    type: env\n"))
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("render config with vaults: got %d, want 422", resp.StatusCode)
	}
	resp = adminPost(t, srv, "/api/render", fmt.Sprintf(`{"kind": "policy", "content": %q}`, "on_http_request: [] # secret(vault/key)"))
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("render policy with secret(: got %d, want 422", resp.StatusCode)
	}
}

// --- GET /api/schema ---------------------------------------------------------

func TestAPISchemaShape(t *testing.T) {
	srv := newAdminTestServer(t, &adminAuth{Token: testAdminToken, Required: true})

	resp := adminGet(t, srv, "/api/schema")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/api/schema: got %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("/api/schema Content-Type %q, want application/json", ct)
	}
	payload := decodeJSONBody(t, resp)

	configMap, ok := payload["config"].(map[string]interface{})
	if !ok {
		t.Fatalf("/api/schema: config is %T, want an object", payload["config"])
	}
	for _, table := range []string{"top_level", "tunnel"} {
		rows, ok := configMap[table].([]interface{})
		if !ok || len(rows) == 0 {
			t.Fatalf("/api/schema: config.%s is missing or empty", table)
		}
		for i, raw := range rows {
			row, ok := raw.(map[string]interface{})
			if !ok {
				t.Fatalf("config.%s[%d] is %T, want an object", table, i, raw)
			}
			for _, field := range []string{"key", "type", "default", "summary"} {
				if s, _ := row[field].(string); s == "" {
					t.Errorf("config.%s[%d] has an empty %q", table, i, field)
				}
			}
		}
	}

	policyMap, ok := payload["policy"].(map[string]interface{})
	if !ok {
		t.Fatalf("/api/schema: policy is %T, want an object", payload["policy"])
	}
	matrix := policy.PhaseActionMatrix()
	phases, ok := policyMap["phases"].(map[string]interface{})
	if !ok || len(phases) != len(matrix) {
		t.Fatalf("/api/schema: policy.phases is %v, want the %d phases the matrix exports", policyMap["phases"], len(matrix))
	}
	actions, ok := policyMap["actions"].([]interface{})
	if !ok || len(actions) == 0 {
		t.Fatalf("/api/schema: policy.actions is missing or empty")
	}
	seen := map[string]bool{}
	for i, raw := range actions {
		row, ok := raw.(map[string]interface{})
		if !ok {
			t.Fatalf("policy.actions[%d] is %T, want an object", i, raw)
		}
		name, _ := row["name"].(string)
		summary, _ := row["summary"].(string)
		phaseList, _ := row["phases"].([]interface{})
		if name == "" || summary == "" || len(phaseList) == 0 {
			t.Errorf("policy.actions[%d] (%s): name, phases and summary must all be present", i, name)
		}
		if seen[name] {
			t.Errorf("policy.actions names %q twice", name)
		}
		seen[name] = true
		// The phases the payload claims must be the phases the engine's
		// matrix claims -- the derived matrix is the contract, this payload
		// is its rendering.
		want := map[string]bool{}
		for phaseName, actions := range matrix {
			if containsSorted(actions, name) {
				want[phaseName] = true
			}
		}
		got := map[string]bool{}
		for _, p := range phaseList {
			got[p.(string)] = true
		}
		if !reflect.DeepEqual(want, got) {
			t.Errorf("policy.actions[%q]: phases %v, want %v", name, got, want)
		}
	}
}

// TestConfigSchemaRowsMatchStructTags is the reflection pin (review gate 3):
// every yaml-tagged field of client.Configuration and client.TunnelConfiguration
// has a schema table row keyed by its yaml name, and every row names a real
// field. A new config key without a row fails here; a row for a retired key
// fails here. The UI's schema cannot drift from the structs.
func TestConfigSchemaRowsMatchStructTags(t *testing.T) {
	yamlNamesOf := func(typ reflect.Type) map[string]bool {
		names := make(map[string]bool)
		for i := 0; i < typ.NumField(); i++ {
			tag := typ.Field(i).Tag.Get("yaml")
			if tag == "" || tag == "-" {
				continue
			}
			names[strings.Split(tag, ",")[0]] = true
		}
		return names
	}
	rowKeysOf := func(rows []apiSchemaRow) map[string]bool {
		keys := make(map[string]bool, len(rows))
		for _, r := range rows {
			if keys[r.Key] {
				t.Errorf("schema table names %q twice", r.Key)
			}
			keys[r.Key] = true
		}
		return keys
	}
	compare := func(table string, rows []apiSchemaRow, typ reflect.Type) {
		rowKeys := rowKeysOf(rows)
		fieldNames := yamlNamesOf(typ)
		for key := range rowKeys {
			if !fieldNames[key] {
				t.Errorf("%s: row %q names no yaml-tagged field of %s (retired key, or a typo in the table)", table, key, typ)
			}
		}
		for name := range fieldNames {
			if !rowKeys[name] {
				t.Errorf("%s: %s carries yaml key %q with no schema row (new key, undocmented table)", table, typ, name)
			}
		}
		if len(rowKeys) != len(fieldNames) {
			t.Errorf("%s: %d rows for %d fields", table, len(rowKeys), len(fieldNames))
		}
	}

	compare("top_level", configTopLevelSchema, reflect.TypeOf(client.Configuration{}))
	compare("tunnel", configTunnelSchema, reflect.TypeOf(client.TunnelConfiguration{}))
}

// TestPolicyActionSummariesMatchTheMatrix is the summaries pin, both
// directions: every action the engine's matrix implements has a one-line
// summary, and every summary names a matrix action.
func TestPolicyActionSummariesMatchTheMatrix(t *testing.T) {
	matrix := policy.PhaseActionMatrix()

	for _, actions := range matrix {
		for _, name := range actions {
			if summary, ok := policyActionSummaries[name]; !ok {
				t.Errorf("matrix action %q has no summary; the UI would render a blank line", name)
			} else if summary == "" {
				t.Errorf("matrix action %q has an empty summary", name)
			}
		}
	}
	for name := range policyActionSummaries {
		known := false
		for _, actions := range matrix {
			if containsSorted(actions, name) {
				known = true
				break
			}
		}
		if !known {
			t.Errorf("summary for %q names no action the matrix implements (retired action, or a typo)", name)
		}
	}
}

// --- GET /api/presets (SPEC-CLUSTER26 §4) --------------------------------------

// TestPresetsAreValidPolicyDocuments is the pin that keeps the curated
// fragments from rotting under the engine. Per preset it checks, in order:
//
//	(a) the fragment validates through the REAL handler stack -- POSTed to
//	    /api/validate/policy, the same code the operator's insert hits;
//	(b) the whole served payload greps clean of secret( -- the raw scan
//	    422s it at insert, so a preset carrying one would land red;
//	(c) the fragment's phase key is a key of the engine's action matrix and
//	    every rule name sits in that phase's action list -- an engine
//	    phase-move or action rename fails the build here;
//	(d) the fragment round-trips /api/render (kind=policy) to a non-empty
//	    canonical document.
//
// A preset that cannot fail is decoration, so every check reads the served
// bytes and the live matrix, never the table's own claims about itself.
func TestPresetsAreValidPolicyDocuments(t *testing.T) {
	srv := newAdminTestServer(t, &adminAuth{Token: testAdminToken, Required: true})

	// The endpoint rides secureAPI like every other /api route: 200 JSON with
	// no-store, the envelope the operator's browser actually receives.
	resp := adminGet(t, srv, "/api/presets")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/api/presets: got %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("/api/presets Content-Type %q, want application/json", ct)
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("/api/presets Cache-Control %q, want no-store", resp.Header.Get("Cache-Control"))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("/api/presets: %v", err)
	}
	var presets []apiPreset
	if err := json.Unmarshal(body, &presets); err != nil {
		t.Fatalf("/api/presets is not a JSON preset array: %v", err)
	}
	if len(presets) == 0 {
		t.Fatal("/api/presets served an empty array; the workbench would offer nothing to start from")
	}
	if len(presets) != len(apiPresets) {
		t.Errorf("/api/presets served %d presets, the table carries %d", len(presets), len(apiPresets))
	}

	// Table hygiene on the SERVED payload: sorted by name at table order is a
	// payload contract (a slice encodes in slice order), so it is pinned
	// against the bytes, not against the table variable.
	prev := ""
	seen := map[string]bool{}
	for _, p := range presets {
		if p.Name == "" || p.Title == "" || p.Phase == "" || p.Description == "" || p.YAML == "" {
			t.Errorf("preset %q: name, title, phase, description and yaml must all be present", p.Name)
		}
		if p.Kind != "policy" {
			t.Errorf("preset %q: kind %q, want \"policy\"", p.Name, p.Kind)
		}
		if seen[p.Name] {
			t.Errorf("preset %q is served twice", p.Name)
		}
		seen[p.Name] = true
		if prev != "" && p.Name <= prev {
			t.Errorf("presets not sorted by name: %q after %q", p.Name, prev)
		}
		prev = p.Name
	}

	// (b) the 422 trap, guarded at the source: not one preset may carry the
	// spelling the workbench's raw scan refuses at insert.
	marshaled, err := json.Marshal(presets)
	if err != nil {
		t.Fatalf("re-marshaling the served payload failed: %v", err)
	}
	if strings.Contains(string(marshaled), "secret(") {
		t.Error("the served payload contains secret(; the raw scan would 422 that preset at insert")
	}

	matrix := policy.PhaseActionMatrix()

	for _, p := range presets {
		t.Run(p.Name, func(t *testing.T) {
			// (a) the war-path pin: the fragment is judged by the validator
			// itself, through the endpoint, not by a test-local re-derivation
			// that could drift from the handler.
			vresp := adminPost(t, srv, "/api/validate/policy", fmt.Sprintf(`{"content": %q}`, p.YAML))
			vpayload := decodeJSONBody(t, vresp)
			if vresp.StatusCode != http.StatusOK || vpayload["valid"] != true {
				t.Fatalf("validate: got %d %v, want 200 {valid:true}", vresp.StatusCode, vpayload)
			}

			// (c) the matrix cross-join: parse the fragment generically, so a
			// phase key the engine does not know (and a rule name the phase
			// does not implement) both show up as disagreements with the
			// matrix rather than as a plausible-looking verdict.
			var frag map[string][]struct {
				Name string `yaml:"name"`
			}
			if err := yaml.Unmarshal([]byte(p.YAML), &frag); err != nil {
				t.Fatalf("fragment does not parse as a policy document: %v", err)
			}
			if len(frag) != 1 {
				t.Fatalf("fragment carries %d phase keys; a preset teaches exactly one phase", len(frag))
			}
			for phaseKey, rules := range frag {
				if phaseKey != p.Phase {
					t.Errorf("fragment phase key %q disagrees with the phase field %q", phaseKey, p.Phase)
				}
				actions, ok := matrix[phaseKey]
				if !ok {
					t.Fatalf("phase key %q is not a key of the action matrix; the engine moved underneath this preset", phaseKey)
				}
				if len(rules) == 0 {
					t.Fatalf("phase %q carries no rules", phaseKey)
				}
				for _, r := range rules {
					if r.Name == "" {
						t.Fatalf("phase %q carries a rule with no name", phaseKey)
					}
					if !containsSorted(actions, r.Name) {
						t.Errorf("rule %q is not implemented in phase %q (the matrix lists %v); the engine moved underneath this preset",
							r.Name, phaseKey, actions)
					}
				}
			}

			// (d) the render round trip: what insert puts in the editor must
			// come back out as a non-empty canonical document.
			rresp := adminPost(t, srv, "/api/render", fmt.Sprintf(`{"kind": "policy", "content": %q}`, p.YAML))
			rpayload := decodeJSONBody(t, rresp)
			if rresp.StatusCode != http.StatusOK || rpayload["valid"] != true {
				t.Fatalf("render: got %d %v, want 200 {valid:true,...}", rresp.StatusCode, rpayload)
			}
			if rendered, _ := rpayload["rendered"].(string); rendered == "" {
				t.Error("render: empty rendered document")
			}
		})
	}
}

// --- the tightened CSP (§6, review gate 4) ------------------------------------

// TestAdminCSPHasNoInlineScripts pins the exact CSP the admin surface sends:
// every script is an external file now, so script-src carries no
// 'unsafe-inline' -- an injected inline <script> must not run. The full value
// is pinned verbatim so the header cannot drift a directive at a time.
func TestAdminCSPHasNoInlineScripts(t *testing.T) {
	srv := newAdminTestServer(t, &adminAuth{Token: testAdminToken, Required: true})

	want := "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'"
	if want != adminContentSecurityPolicy {
		t.Fatalf("the const and the pin disagree; decide which is right and update both: %q", adminContentSecurityPolicy)
	}

	for _, path := range []string{"/", "/static/app.js", "/static/style.css", "/api/schema"} {
		resp := adminGet(t, srv, path)
		defer resp.Body.Close()
		got := resp.Header.Get("Content-Security-Policy")
		if got != want {
			t.Errorf("%s: Content-Security-Policy %q, want %q", path, got, want)
		}
		if strings.Contains(got, "script-src 'self' 'unsafe-inline'") {
			t.Errorf("%s: script-src still allows inline scripts", path)
		}
		if resp.Header.Get("Cache-Control") != "no-store" {
			t.Errorf("%s: Cache-Control %q, want no-store", path, resp.Header.Get("Cache-Control"))
		}
	}
}

// --- the static routes (§6) ----------------------------------------------------

func TestStaticAssetsServed(t *testing.T) {
	srv := newAdminTestServer(t, &adminAuth{Token: testAdminToken, Required: true})

	for name, mime := range map[string]string{
		"index.html": "text/html",
		"style.css":  "text/css",
		"app.js":     "text/javascript",
	} {
		resp := adminGet(t, srv, "/static/"+name)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("/static/%s: got %d, want 200", name, resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, mime) {
			t.Errorf("/static/%s: Content-Type %q, want %s", name, ct, mime)
		}
		if resp.Header.Get("Cache-Control") != "no-store" {
			t.Errorf("/static/%s: Cache-Control %q, want no-store", name, resp.Header.Get("Cache-Control"))
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Errorf("/static/%s: %v", name, err)
		}
		if len(body) == 0 {
			t.Errorf("/static/%s: served an empty body", name)
		}
	}

	// Anything that is not exactly one of the three names 404s.
	for _, path := range []string{"/static/nope.js", "/static/", "/static/dashboard/app.js", "/static/app.js.bak"} {
		resp := adminGet(t, srv, path)
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s: got %d, want 404", path, resp.StatusCode)
		}
	}
}

// TestStaticNamesCannotTraverse drives serveDashboardStatic directly (bypassing
// the mux's own path cleaning, which would have redirected these before the
// handler ran): the lookup is a fixed table, so a traversal-shaped name misses
// it and 404s. There is no path join in the handler to escape from.
func TestStaticNamesCannotTraverse(t *testing.T) {
	for _, name := range []string{
		"../../etc/passwd",
		"../admin.go",
		"sub/../app.js",
		"app.js/../style.css",
		"",
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/static/"+name, nil)
		serveDashboardStatic(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("/static/%s: got %d, want 404", name, rec.Code)
		}
	}
}

// TestRootServesTheDashboardAsset pins "/" to the embedded asset, not an
// inline const: the served document is the SPA's entry, HTML with the
// stylesheet and script links the /static routes answer.
func TestRootServesTheDashboardAsset(t *testing.T) {
	srv := newAdminTestServer(t, &adminAuth{Token: testAdminToken, Required: true})

	resp := adminGet(t, srv, "/")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/: got %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Errorf("/: Content-Type %q, want text/html; charset=utf-8", ct)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("/: %v", err)
	}
	// Content-agnostic on purpose beyond the shape: the dashboard subtree is
	// workstream C's and may change under these tests. What is pinned here is
	// that "/" serves the embedded entry document (an HTML document that
	// loads the SPA from /static/), not an inline const.
	if lower := strings.ToLower(string(body)); !strings.HasPrefix(lower, "<!doctype html>") {
		t.Errorf("/: served %.80q, want an HTML document", string(body))
	}
	if !strings.Contains(string(body), "/static/app.js") {
		t.Errorf("/: served document does not load the SPA's script:\n%.400s", string(body))
	}
}

// --- snapshot enrichment (§7) ---------------------------------------------------

// TestTunnelSnapshotCarriesRegistrationFacts opens a synthetic tunnel the way
// the registration path does -- observe.onTunnelOpen -- and reads it back off
// /tunnels: the new fields must be there, filled from the Tunnel, beside the
// fields that were already served.
func TestTunnelSnapshotCarriesRegistrationFacts(t *testing.T) {
	tun := &Tunnel{
		url: "https://probe.admin.test",
		req: &msg.ReqTunnel{
			Protocol:       msg.ProtoHTTPS,
			TLSTermination: msg.TLSTerminationAgent,
			Pooling:        true,
			ForwardTo:      "http://127.0.0.1:9000",
		},
		owner:       "probe-token",
		claimedPort: 4711,
		policy:      &policy.Compiled{},
	}
	observe.onTunnelOpen(tun)
	defer observe.onTunnelClose(tun)

	srv := newAdminTestServer(t, nil)
	resp := adminGet(t, srv, "/tunnels")
	defer resp.Body.Close()
	var payload struct {
		Tunnels []tunnelSnapshot `json:"tunnels"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("/tunnels is not JSON: %v", err)
	}

	var found *tunnelSnapshot
	for i := range payload.Tunnels {
		if payload.Tunnels[i].URL == tun.url {
			found = &payload.Tunnels[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("/tunnels does not carry %s: %+v", tun.url, payload.Tunnels)
	}

	want := tunnelSnapshot{
		URL:            "https://probe.admin.test",
		Protocol:       msg.ProtoHTTPS,
		Owner:          "probe-token",
		Internal:       false,
		AgentTLS:       true,
		ForwardTo:      "http://127.0.0.1:9000",
		ClaimedPort:    4711,
		Pooling:        true,
		PolicyAttached: true,
	}
	if found.Owner != want.Owner || found.Internal != want.Internal || found.AgentTLS != want.AgentTLS ||
		found.ForwardTo != want.ForwardTo || found.ClaimedPort != want.ClaimedPort ||
		found.Pooling != want.Pooling || found.PolicyAttached != want.PolicyAttached {
		t.Errorf("snapshot facts: got owner=%q internal=%v agent_tls=%v forward_to=%q claimed_port=%d pooling=%v policy_attached=%v,\nwant owner=%q internal=%v agent_tls=%v forward_to=%q claimed_port=%d pooling=%v policy_attached=%v",
			found.Owner, found.Internal, found.AgentTLS, found.ForwardTo, found.ClaimedPort, found.Pooling, found.PolicyAttached,
			want.Owner, want.Internal, want.AgentTLS, want.ForwardTo, want.ClaimedPort, want.Pooling, want.PolicyAttached)
	}

	// A bare tunnel -- no policy, no forward_to, plain http -- reads as the
	// zero of every new fact, so an old-style registration is not mistaken
	// for a configured one.
	bare := &Tunnel{url: "http://bare.admin.test", req: &msg.ReqTunnel{Protocol: msg.ProtoHTTP}}
	observe.onTunnelOpen(bare)
	defer observe.onTunnelClose(bare)

	resp2 := adminGet(t, srv, "/tunnels")
	defer resp2.Body.Close()
	var payload2 struct {
		Tunnels []tunnelSnapshot `json:"tunnels"`
	}
	if err := json.NewDecoder(resp2.Body).Decode(&payload2); err != nil {
		t.Fatalf("/tunnels is not JSON: %v", err)
	}
	for i := range payload2.Tunnels {
		if payload2.Tunnels[i].URL != bare.url {
			continue
		}
		got := payload2.Tunnels[i]
		if got.Owner != "" || got.Internal || got.AgentTLS || got.ForwardTo != "" || got.ClaimedPort != 0 || got.Pooling || got.PolicyAttached {
			t.Errorf("bare tunnel carries configured facts: %+v", got)
		}
		return
	}
	t.Fatalf("/tunnels does not carry %s", bare.url)
}
