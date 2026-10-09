package server

// The workbench API (SPEC-CLUSTER19 §1): four endpoints under /api/ that let
// an authenticated operator validate and render the exact documents the agent
// (client.ValidateConfigurationDoc) and the policy engine
// (TrafficPolicy.Validate) consume, against the exact code that consumes them.
//
// The transport rules, in one place:
//
//   - Validation verdicts are 200s. The endpoint succeeded; the document is
//     bad. {"valid": true} or {"valid": false, "error": "<message>"}.
//   - 4xx is for transport faults only: 400 malformed envelope, 413 over the
//     body cap, 422 the vault refusal (§3). Wrong method and missing auth are
//     answered by the wrapper, as for every admin route.
//   - Every body this file writes is JSON, including every error path -- the
//     SPA parses JSON, so http.Error's text/plain bodies never appear here.
//   - Documents enter as {"content": "..."} JSON envelopes and never touch
//     the filesystem: no file is read (traffic_policy_file is refused by the
//     validator), no file is written (render is download-only), and no
//     process-global vault state is consulted (the validators refuse the
//     document instead).

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"ngrok/client"
	"ngrok/policy"
)

// apiMaxBodyBytes caps every POST body (§1). A config or policy document is a
// few kilobytes; a megabyte is three orders of magnitude past that and still
// small enough that a stuck or hostile client cannot park the handler on it.
// The 413 body names this number.
const apiMaxBodyBytes = 1 << 20

// apiEnvelope is the request shape all three POST endpoints take; kind is
// only meaningful to /api/render.
type apiEnvelope struct {
	Content string `json:"content"`
	Kind    string `json:"kind"`
}

// apiVerdict is a validation answer: 200 either way, the validator's message
// verbatim when the document is bad.
type apiVerdict struct {
	Valid bool   `json:"valid"`
	Error string `json:"error,omitempty"`
}

// apiRenderVerdict adds the canonical re-marshaled document to the verdict.
type apiRenderVerdict struct {
	Valid    bool   `json:"valid"`
	Error    string `json:"error,omitempty"`
	Rendered string `json:"rendered,omitempty"`
}

// writeJSONError answers a transport fault with a JSON body naming it.
func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// writeJSONVerdict answers 200 with a validation verdict.
func writeJSONVerdict(w http.ResponseWriter, v apiVerdict) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// writeJSONRenderVerdict is writeJSONVerdict for /api/render, whose answers
// carry the rendered document as well.
func writeJSONRenderVerdict(w http.ResponseWriter, v apiRenderVerdict) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// readJSONEnvelope reads and decodes the request body under the 1 MiB cap.
// Every POST endpoint opens with it; a false return means the answer has
// already been written (400 malformed, 413 oversize).
func readJSONEnvelope(w http.ResponseWriter, r *http.Request) (apiEnvelope, bool) {
	var env apiEnvelope

	r.Body = http.MaxBytesReader(w, r.Body, apiMaxBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		// MaxBytesError is what the capped reader returns when the cap is
		// what tripped; anything else is a body that never parsed as bytes,
		// which is the 400.
		var capErr *http.MaxBytesError
		if errors.As(err, &capErr) {
			writeJSONError(w, http.StatusRequestEntityTooLarge,
				fmt.Sprintf("request body exceeds the %d byte cap", apiMaxBodyBytes))
			return env, false
		}
		writeJSONError(w, http.StatusBadRequest, "could not read request body: "+err.Error())
		return env, false
	}

	if err := json.Unmarshal(body, &env); err != nil {
		writeJSONError(w, http.StatusBadRequest, "malformed JSON envelope: "+err.Error())
		return env, false
	}
	return env, true
}

// --- GET /api/schema -------------------------------------------------------

// apiSchemaRow is one config key as the schema serves it: the YAML spelling,
// the value's shape, the default when the key is absent, and one line of
// summary in the repo's comment voice. The tables below are hand-tabled, and
// the reflection test in admin_api_test.go pins them to the struct tags in
// both directions: a field without a row and a row without a field both fail
// the build, so this table cannot drift from what the structs actually
// decode.
type apiSchemaRow struct {
	Key     string `json:"key"`
	Type    string `json:"type"`
	Default string `json:"default"`
	Summary string `json:"summary"`
}

// apiActionInfo is one policy action as the schema serves it: its name, the
// phases it may appear in (from PhaseActionMatrix, the map the engine
// enforces), and a one-line summary.
type apiActionInfo struct {
	Name    string   `json:"name"`
	Phases  []string `json:"phases"`
	Summary string   `json:"summary"`
}

// configTopLevelSchema is the top-level config table (client.Configuration's
// yaml keys). Defaults are the values LoadConfiguration applies when the key
// is absent; "none" means the zero value and no applied default.
var configTopLevelSchema = []apiSchemaRow{
	{"server_addr", "string", `"ngrokd.ngrok.com:443"`, "host:port of the ngrokd server this agent registers with."},
	{"auth_token", "string", "none", "token authenticating this agent to the server; also accepted as the whole document (the old single-token format)."},
	{"tunnels", "mapping", "none", "named tunnel definitions; each entry is a tunnel document -- see the tunnel table."},
	{"http_proxy", "string", "http_proxy env", "URL of an HTTP(S) proxy the agent dials through; falls back to the http_proxy environment variable when unset."},
	{"inspect_addr", "string", `"127.0.0.1:4040"`, "address the local web inspector binds; \"disabled\" turns the inspector off."},
	{"inspect_auth", "string", "none", "basic-auth credentials (user:password) the web inspector requires."},
	{"inspect_token", "string", "none", "bearer token that authenticates web inspector API requests."},
	{"inspect_max_body_bytes", "int", "1048576", "cap on how much of a request body the inspector captures; a negative value is refused, not clamped."},
	{"proxy_max_concurrency", "int", "64", "cap on concurrent proxied connections; a negative value is refused, not clamped."},
	{"proxy_transport", "string", `"auto"`, "carrier for the multiplexed proxy connection: auto (QUIC when the server offers it, else TCP), quic, or tcp."},
	{"trust_host_root_certs", "bool", "false", "verify the server's TLS certificate against the operating system's roots instead of the embedded CA."},
	{"vaults", "mapping", "none", "named secret vault sources that secret(\"vault/key\") references in traffic policies resolve against; sources per README."},
}

// configTunnelSchema is the per-tunnel table (client.TunnelConfiguration's
// yaml keys), keyed by the bare key as written under tunnels.<name>:
var configTunnelSchema = []apiSchemaRow{
	{"proto", "mapping", "none", "map of protocol (http, https, tcp) to the local port to serve; the legacy spelling, still the usual one."},
	{"subdomain", "string", "none", "requested subdomain of the server's domain for this endpoint."},
	{"hostname", "string", "none", "requested custom hostname for this endpoint (the server checks ownership)."},
	{"remote_port", "int", "none", "fixed public port to claim for a tcp endpoint (the server's port-ownership rules apply)."},
	{"auth", "string", "none", "basic-auth credentials (user:password) required on this endpoint's http traffic."},
	{"host_header", "string", "none", "Host header set on requests proxied to the local service."},
	{"request_header", "mapping", "none", "headers to add (add:) or remove (remove:) on requests toward the local service."},
	{"response_header", "mapping", "none", "headers to add (add:) or remove (remove:) on responses toward the visitor."},
	{"binding", "string", `"public"`, "endpoint kind: public, or internal (a .internal endpoint only forward_to can reach)."},
	{"pooling", "bool", "false", "share this url with other agents, round-robin per connection."},
	{"forward_to", "string", "none", "route this endpoint's traffic to an internal endpoint (\"https://svc.internal\") instead of a local service."},
	{"agent_tls_termination", "bool", "false", "terminate this endpoint's public https TLS in the agent: the server routes by SNI and relays the bytes unread; pairs with tls."},
	{"tls", "mapping", "none", "certificate material for agent TLS termination -- crt/key, or ca_crt/ca_key to mint per-hostname leaves; shapes per README."},
	{"alpn", "list", "none", "application protocols the public TLS handshake advertises, in preference order (e.g. [h2, http/1.1]); nil advertises nothing."},
	{"upstream_protocol", "string", `"http1"`, "what the agent speaks to the local service: http1 (default) or http2 (h2c, via the transcoder)."},
	{"upstream_pool", "bool", "false", "pool keep-alive connections to the local http service (an opt-in parsed local leg; the default leg dials fresh per visitor connection); refused beside forward_to, upstream_protocol: http2, or alpn containing h2."},
	{"compression", "bool", "true", "allow gzip of responses; on by default, false turns it off."},
	{"traffic_policy", "mapping", "none", "inline traffic policy document (on_tcp_connect / on_http_request / on_http_response); the action set is the changelog's to list."},
	{"traffic_policy_file", "path", "none", "file holding the traffic policy document, read once at load; naming both this and traffic_policy is refused."},
	{"carrier_dedup", "bool", "false", "experimental: carry repeated chunks on the agent-server proxy stream as references (content-defined chunking, blake2b); refused with any udp protocol or agent_tls_termination."},
}

// policyActionSummaries is the one line per action the schema serves beside
// the matrix. Prose only: the config *shapes* are the changelog's job (SPEC
// §4). Pinned in both directions against PhaseActionMatrix -- every matrix
// action has a summary here, every entry here names a matrix action -- so a
// new action without a summary, or a summary for a retired one, fails the
// build.
var policyActionSummaries = map[string]string{
	policy.ActionAddHeaders:          "sets headers on the message (at most ten; values may interpolate).",
	policy.ActionRemoveHeaders:       "removes named headers from the message (at most ten; never user-agent).",
	policy.ActionDeny:                "refuses the message with a status code (403 default; the connect phase has no response to configure).",
	policy.ActionCustomResponse:      "answers the request with a fabricated response: status, body, headers.",
	policy.ActionLog:                 "writes a structured log line with the configured metadata.",
	policy.ActionSetVars:             "assigns ${vars.*} values later actions and conditions read.",
	policy.ActionRestrictIPs:         "allows or denies the connection by source CIDR (connect phase).",
	policy.ActionBasicAuth:           "requires basic credentials; challenges with WWW-Authenticate.",
	policy.ActionBearerAuth:          "requires a bearer token in the Authorization header (or access_token).",
	policy.ActionAPIKeyAuth:          "requires a named header to carry one of the configured keys.",
	policy.ActionJWTValidation:       "validates the bearer JWT against a JWKS endpoint (issuer, audience, algorithms, claims).",
	policy.ActionWebhookVerification: "verifies the provider's webhook signature over the request body.",
	policy.ActionOIDC:                "requires an OpenID Connect login for the whole endpoint (authorization code + PKCE); at most one per policy.",
}

// --- GET /api/presets --------------------------------------------------------

// apiPreset is one curated policy fragment as /api/presets serves it: the
// slug, the human title, the one phase the fragment speaks in, a line of
// description, the fragment itself (insertable as-is into the workbench's
// policy editor), the hint lines shown after an insert, and the payload kind.
type apiPreset struct {
	Name        string   `json:"name"` // sort key, unique
	Title       string   `json:"title"`
	Phase       string   `json:"phase"` // on_http_request | on_http_response | on_tcp_connect
	Description string   `json:"description"`
	YAML        string   `json:"yaml"`  // the fragment, insertable as-is
	Notes       []string `json:"notes"` // hint lines rendered after insert
	Kind        string   `json:"kind"`  // "policy" (v1)
}

// apiPresets is the curated fragment table (SPEC-CLUSTER26 §3), hand-tabled
// beside the schema tables, sorted by name at table order. JSON encodes a
// slice in slice order, so the payload is byte-stable -- no map iteration
// anywhere in it.
//
// The one rule this table obeys above every other: shapes are copied from
// policy/validate.go, never from the README. Documentation drift is the rot
// class this cluster exists to kill -- the README's own restrict-ips example
// carried a `cidrs:` key the validator has always refused -- and a preset
// that copied the README would ship the rot with a badge on it. Each
// fragment is therefore pinned to the real validator by
// TestPresetsAreValidPolicyDocuments, which POSTs every one through
// /api/validate/policy -- the same handler stack the operator's keystrokes
// hit -- so an engine move underneath a preset fails the build instead of
// the operator's insert.
//
// No preset contains secret(: the workbench's raw scan 422s it at insert
// (handleAPIValidatePolicy), so such a fragment would land red. Every
// credential field carries REPLACE_ME instead, which both validates clean
// and reads as edit-me at insert time.
var apiPresets = []apiPreset{
	{
		Name:        "admin-path-deny",
		Title:       "Deny /admin paths",
		Phase:       "on_http_request",
		Description: "Refuse every request whose path starts with /admin, by CEL condition, with a 403.",
		YAML: `on_http_request:
  - name: deny
    expressions:
      - 'req.url.path.startsWith("/admin")'
    config:
      status_code: 403
`,
		Notes: []string{
			"expressions is CEL over the phase variables: req.url.path (leading slash kept), req.url.query, req.method, req.headers.",
			"A rule with no expressions matches everything; deny's status_code is optional (403 default).",
		},
		Kind: "policy",
	},
	{
		Name:        "basic-auth-gate",
		Title:       "Basic-auth gate",
		Phase:       "on_http_request",
		Description: "Require a browser basic-auth login before any request is forwarded.",
		YAML: `on_http_request:
  - name: basic-auth
    config:
      realm: restricted
      credentials:
        - alice:REPLACE_ME
`,
		Notes: []string{
			"List several user:password entries for rotation; each is held as a SHA-256 digest and compared in constant time.",
			"Missing or wrong credentials earn 401 with WWW-Authenticate: Basic realm=\"restricted\".",
		},
		Kind: "policy",
	},
	{
		Name:        "bearer-token-gate",
		Title:       "Bearer token gate",
		Phase:       "on_http_request",
		Description: "Require an Authorization: Bearer header carrying one of the configured tokens.",
		YAML: `on_http_request:
  - name: bearer-auth
    config:
      tokens:
        - REPLACE_ME
`,
		Notes: []string{
			"Several tokens are allowed -- one per client, so one can be revoked without touching the rest; digested like every credential.",
			"A request without, or with a wrong, token gets 401 and the bare WWW-Authenticate: Bearer challenge.",
		},
		Kind: "policy",
	},
	{
		Name:        "ip-allowlist",
		Title:       "IP allowlist",
		Phase:       "on_tcp_connect",
		Description: "Refuse every connection whose source address is outside the allow list, before any HTTP is spoken.",
		YAML: `on_tcp_connect:
  - name: restrict-ips
    config:
      enforce: true
      allow:
        - 10.0.0.0/24
`,
		Notes: []string{
			"The accepted keys are exactly enforce, allow and deny -- ip_policies is refused (it needs the ngrok API).",
			"A bare address is accepted as a host CIDR (203.0.113.7 means /32); enforce: false reports would-be refusals instead of refusing.",
		},
		Kind: "policy",
	},
	{
		Name:        "jwt-gate",
		Title:       "JWT validation gate",
		Phase:       "on_http_request",
		Description: "Require a bearer JWT your identity provider signed, validated against its JWKS endpoint.",
		YAML: `on_http_request:
  - name: jwt-validation
    config:
      jwks_uri: https://idp.example.com/.well-known/jwks.json
      issuer: https://idp.example.com
      audience: my-endpoint
      algorithms:
        - RS256
      leeway_seconds: 30
`,
		Notes: []string{
			"The algorithm allowlist is enforced (RS256 here; no HS*, no \"none\"), and exp is required in every token.",
			"jwks_uri must be https (loopback http is allowed, so a local test server can serve one); issuer and audience are optional but an empty one is refused.",
		},
		Kind: "policy",
	},
	{
		Name:        "oidc-protect",
		Title:       "OpenID Connect login",
		Phase:       "on_http_request",
		Description: "Put the whole endpoint behind an OpenID Connect login (authorization code + PKCE).",
		YAML: `on_http_request:
  - name: oidc
    config:
      issuer: https://idp.example.com
      client_id: REPLACE_ME
      client_secret: REPLACE_ME
`,
		Notes: []string{
			"At most one oidc action per policy: the callback path (default /oauth2/callback) and the session cookies belong to the endpoint.",
			"Refused on agent-TLS-terminated endpoints: over a zero-knowledge tunnel the server holds only ciphertext, so the login flow has nothing to run on -- register with server-side TLS termination.",
		},
		Kind: "policy",
	},
	{
		Name:        "request-logging",
		Title:       "Request logging",
		Phase:       "on_http_request",
		Description: "The smallest valid policy document -- one phase, one rule, one action. Start here.",
		YAML: `on_http_request:
  - name: log
    config:
      metadata:
        event: request
        service: my-app
`,
		Notes: []string{
			"metadata values may interpolate phase variables: ${req.url.path}, ${req.method}, ${req.headers['x-request-id']}.",
			"Every phase document has this shape: a phase key, a list of rules, each rule a name plus optional expressions plus config.",
		},
		Kind: "policy",
	},
	{
		Name:        "security-headers",
		Title:       "Security response headers",
		Phase:       "on_http_response",
		Description: "Add HSTS and X-Content-Type-Options to every response -- and the only preset here that shows the response phase exists.",
		YAML: `on_http_response:
  - name: add-headers
    config:
      headers:
        strict-transport-security: max-age=31536000; includeSubDomains
        x-content-type-options: nosniff
`,
		Notes: []string{
			"The response phase implements add-headers, remove-headers (never user-agent) and log; its conditions read res.* variables.",
			"At most ten headers per action; names are lower-cased on the wire.",
		},
		Kind: "policy",
	},
	{
		Name:        "webhook-verify",
		Title:       "Webhook signature verification",
		Phase:       "on_http_request",
		Description: "Verify the provider's signature over the request body and forward only what verifies.",
		YAML: `on_http_request:
  - name: webhook-verification
    config:
      provider: stripe
      secrets:
        - REPLACE_ME
`,
		Notes: []string{
			"Providers: stripe, github, svix (svix secrets carry the whsec_ prefix Svix's dashboard issues).",
			"Several secrets are allowed for rotation; tolerance_seconds defaults to 300.",
		},
		Kind: "policy",
	},
}

// handleAPIPresets answers GET /api/presets: one json.Encode of the curated
// table. A slice encodes in slice order, so the answer is byte-stable for a
// given table -- the /api/schema property, one more artifact of the same
// shape.
func handleAPIPresets(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(apiPresets)
}

// handleAPISchema answers GET /api/schema: the config key tables and the
// policy action matrix with its summaries.
func handleAPISchema(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"config": map[string]interface{}{
			"top_level": configTopLevelSchema,
			"tunnel":    configTunnelSchema,
		},
		"policy": map[string]interface{}{
			"phases":  policy.PhaseActionMatrix(),
			"actions": schemaPolicyActions(),
		},
	})
}

// schemaPolicyActions flattens the exported matrix into the actions list,
// sorted by name, each with the phases it runs in and its summary. Both the
// names and the per-action phase lists come out sorted, so the payload is
// byte-stable for a given matrix.
func schemaPolicyActions() []apiActionInfo {
	matrix := policy.PhaseActionMatrix()

	phaseNames := make([]string, 0, len(matrix))
	for phaseName := range matrix {
		phaseNames = append(phaseNames, phaseName)
	}
	sort.Strings(phaseNames)

	names := make([]string, 0, len(policyActionSummaries))
	for name := range policyActionSummaries {
		names = append(names, name)
	}
	sort.Strings(names)

	out := make([]apiActionInfo, 0, len(names))
	for _, name := range names {
		phases := make([]string, 0, len(phaseNames))
		for _, phaseName := range phaseNames {
			if containsSorted(matrix[phaseName], name) {
				phases = append(phases, phaseName)
			}
		}
		out = append(out, apiActionInfo{Name: name, Phases: phases, Summary: policyActionSummaries[name]})
	}
	return out
}

// containsSorted is a binary search over a sorted list (the matrix's lists
// are sorted by contract).
func containsSorted(list []string, s string) bool {
	i := sort.SearchStrings(list, s)
	return i < len(list) && list[i] == s
}

// --- POST /api/validate/config ---------------------------------------------

// handleAPIValidateConfig validates a client config document with the agent's
// own validator. A vault-bearing document is the 422 (below); every other
// validator verdict is a 200.
func handleAPIValidateConfig(w http.ResponseWriter, r *http.Request) {
	env, ok := readJSONEnvelope(w, r)
	if !ok {
		return
	}

	err := client.ValidateConfigurationDoc([]byte(env.Content))
	switch {
	case err == nil:
		writeJSONVerdict(w, apiVerdict{Valid: true})
	case errors.Is(err, client.ErrVaultRefused):
		// Both 422 bodies are the same sentence, and it is the sentinel's
		// own -- the one place the wording lives -- rather than a second
		// copy here that could drift from it.
		writeJSONError(w, http.StatusUnprocessableEntity, client.ErrVaultRefused.Error())
	default:
		writeJSONVerdict(w, apiVerdict{Valid: false, Error: err.Error()})
	}
}

// --- POST /api/validate/policy ----------------------------------------------

// handleAPIValidatePolicy validates one traffic policy document with the
// engine's own Validate. The raw secret( scan runs here, not in the policy
// package: the package stays workbench-agnostic, and the refusal is this
// endpoint's concern (§3).
func handleAPIValidatePolicy(w http.ResponseWriter, r *http.Request) {
	env, ok := readJSONEnvelope(w, r)
	if !ok {
		return
	}

	// The same deliberately crude scan the config validator runs on its side:
	// a header value that merely contains "secret(" is refused too. Fail-
	// closed with an explanation beats a clever parse that might miss a
	// spelling.
	if strings.Contains(env.Content, "secret(") {
		writeJSONError(w, http.StatusUnprocessableEntity, client.ErrVaultRefused.Error())
		return
	}

	tp := new(policy.TrafficPolicy)
	if err := yaml.Unmarshal([]byte(env.Content), tp); err != nil {
		// A document that does not parse is an invalid document, not a
		// transport fault: 200 with the parse error.
		writeJSONVerdict(w, apiVerdict{Valid: false, Error: err.Error()})
		return
	}

	if err := tp.Validate(); err != nil {
		writeJSONVerdict(w, apiVerdict{Valid: false, Error: err.Error()})
		return
	}
	writeJSONVerdict(w, apiVerdict{Valid: true})
}

// --- POST /api/render --------------------------------------------------------

// handleAPIRender parses either document kind and re-marshals it canonically
// (YAML, 2-space indent). Render runs the same refusals as the matching
// validate endpoint -- a vault-bearing document is not renderable either --
// and never writes a file: the SPA turns the response into a download.
func handleAPIRender(w http.ResponseWriter, r *http.Request) {
	env, ok := readJSONEnvelope(w, r)
	if !ok {
		return
	}

	var doc interface{}
	switch env.Kind {
	case "config":
		// ValidateConfigurationDoc carries the raw scan itself; a
		// vault-bearing config is the same 422 here as on the validate
		// endpoint.
		if err := client.ValidateConfigurationDoc([]byte(env.Content)); err != nil {
			if errors.Is(err, client.ErrVaultRefused) {
				writeJSONError(w, http.StatusUnprocessableEntity, client.ErrVaultRefused.Error())
				return
			}
			writeJSONRenderVerdict(w, apiRenderVerdict{Valid: false, Error: err.Error()})
			return
		}
		c := new(client.Configuration)
		if err := yaml.Unmarshal([]byte(env.Content), c); err != nil {
			writeJSONRenderVerdict(w, apiRenderVerdict{Valid: false, Error: err.Error()})
			return
		}
		doc = c
	case "policy":
		if strings.Contains(env.Content, "secret(") {
			writeJSONError(w, http.StatusUnprocessableEntity, client.ErrVaultRefused.Error())
			return
		}
		tp := new(policy.TrafficPolicy)
		if err := yaml.Unmarshal([]byte(env.Content), tp); err != nil {
			writeJSONRenderVerdict(w, apiRenderVerdict{Valid: false, Error: err.Error()})
			return
		}
		if err := tp.Validate(); err != nil {
			writeJSONRenderVerdict(w, apiRenderVerdict{Valid: false, Error: err.Error()})
			return
		}
		doc = tp
	default:
		writeJSONRenderVerdict(w, apiRenderVerdict{Valid: false,
			Error: `kind must be "config" or "policy"`})
		return
	}

	rendered, err := marshalYAMLIndent2(doc)
	if err != nil {
		writeJSONRenderVerdict(w, apiRenderVerdict{Valid: false, Error: err.Error()})
		return
	}
	writeJSONRenderVerdict(w, apiRenderVerdict{Valid: true, Rendered: rendered})
}

// marshalYAMLIndent2 marshals v as YAML with the 2-space indent a config file
// is written in (yaml.v3's own default is 4).
func marshalYAMLIndent2(v interface{}) (string, error) {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(v); err != nil {
		return "", err
	}
	if err := enc.Close(); err != nil {
		return "", err
	}
	return buf.String(), nil
}
