package policy

// Validation: the traversal that both Validate and Compile run, so that what a
// policy document may say and what the engine enforces are decided in one
// place, and cannot drift.
//
// Everything here is load-time and loud. The action set, the phases an action
// may appear in, the CEL expressions, the shape of each action's config and
// every CIDR in it are all checked here, and every error names the rule it came
// from, so that a policy that does not mean what its author thinks fails at
// load rather than at three in the morning:
//
//	on_http_request[1] (deny): unknown config field "body" (deny sets no body; use custom-response)
//
// The config shapes are ngrok's, field for field, from the docs clone
// (gateway/traffic-policy/actions/*.mdx). The one systematic difference is the
// rule shape: this build's Action is {name, expressions, config}, one action
// per rule, where ngrok nests a list of actions inside a named rule. Same
// configs, same expressions, flatter document.

import (
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/http"
	"sort"
	"strings"

	"ngrok/rewriter"
)

// actionPhases is the phase matrix this build implements. ngrok documents a
// wider one -- set-vars and restrict-ips in more phases, custom-response in
// on_http_response -- and the spec for this cluster deliberately narrows it to
// what the edge can enforce cheaply. An action in a phase that is not here is a
// load-time error, not a rule that quietly does nothing.
var actionPhases = map[string][]phase{
	ActionRestrictIPs:    {phaseConnect},
	ActionDeny:           {phaseConnect, phaseRequest},
	ActionLog:            {phaseConnect, phaseRequest, phaseResponse},
	ActionAddHeaders:     {phaseRequest, phaseResponse},
	ActionRemoveHeaders:  {phaseRequest, phaseResponse},
	ActionCustomResponse: {phaseRequest},
	ActionSetVars:        {phaseRequest},

	// The authentication actions (SPEC-CLUSTER6) are request-phase only: they
	// read credentials out of request heads, and a TCP connection in the
	// connect phase has no headers to read, and a response in the response
	// phase is the wrong time to be asking who sent it.
	ActionBasicAuth:     {phaseRequest},
	ActionBearerAuth:    {phaseRequest},
	ActionAPIKeyAuth:    {phaseRequest},
	ActionJWTValidation: {phaseRequest},

	// Webhook verification (SPEC-CLUSTER10) is request-phase only, for the
	// credential actions' reason and a steeper one besides: its verdict is
	// computed over the request body, which only the request phase ever
	// has -- and only when the rewriter buffers it, which is why compiling
	// one sets the compiled policy's body cap.
	ActionWebhookVerification: {phaseRequest},

	// The oidc action (SPEC-CLUSTER18) is request-phase only, for the
	// authentication actions' reason and a structural one besides: it does
	// not run in the hook at all. Its verdict must survive three connections
	// and two external round trips, so the server consumes the compiled
	// action pre-dispatch (Compiled.OIDC); the row here is what makes the
	// name known at load and the phase wrong everywhere else.
	ActionOIDC: {phaseRequest},
}

// phaseActions lists, in a stable order, the actions a phase implements, for
// error messages that tell an operator what they could have written instead.
//
// The names come out of actionPhases rather than a second, hand-maintained
// list, because a second list can disagree with the first: the error message
// says "this build implements X, Y, Z", and an action added to the matrix but
// forgotten here would make that message a lie -- the one thing an error
// message must not be. Sorted, so the message is deterministic for a given
// matrix whatever order the map is walked in.
func phaseActions(p phase) []string {
	names := make([]string, 0, len(actionPhases))
	for name := range actionPhases {
		names = append(names, name)
	}
	sort.Strings(names)

	var out []string
	for _, name := range names {
		for _, ph := range actionPhases[name] {
			if ph == p {
				out = append(out, name)
				break
			}
		}
	}
	return out
}

// PhaseActionMatrix returns, keyed by phase name ("on_tcp_connect",
// "on_http_request", "on_http_response" -- the YAML spellings, via
// phase.String), the sorted action names that phase implements.
//
// It is derived from actionPhases -- the same map the engine enforces -- by
// way of phaseActions, so a consumer of this table (the admin workbench's
// schema endpoint is the one that motivated it) cannot disagree with the build
// about what is legal where. An action added to the matrix lands here
// automatically; the next UI change for a new action is none at all.
func PhaseActionMatrix() map[string][]string {
	out := make(map[string][]string, 3)
	for _, p := range []phase{phaseConnect, phaseRequest, phaseResponse} {
		out[p.String()] = phaseActions(p)
	}
	return out
}

func (p phase) supports(action string) bool {
	for _, ph := range actionPhases[action] {
		if ph == p {
			return true
		}
	}
	return false
}

// maxHeaderEntries is ngrok's documented cap on the headers an add-headers or
// custom-response action may set (and on the headers remove-headers may name).
const maxHeaderEntries = 10

// maxActionsPerPolicy bounds the total number of actions one policy may carry,
// summed over its three phases. ngrok documents no such limit, and this build
// did not have one: a policy is whatever the document says, and every action in
// it is evaluated against every message of every connection on the endpoint.
//
// The bound is about cost, not correctness. Nothing here is superlinear in the
// action count -- each action is one boolean per condition and one pass over
// its config -- so a document with ten thousand actions does not break the
// engine, it just spends the connection's time before the origin ever sees the
// request. A policy is also the one part of a config that is enforced on the
// data path rather than at load, so its size is a size an attacker who can talk
// an operator into a document (or one who can write to the config) gets to
// choose. The measured cost is roughly 35-55us per action for conditions of the
// shape the docs use (most of it the CEL evaluation), so the cap below is on
// the order of 40ms of a connection's first request at the limit, and a
// hand-written policy is a few dozen actions at most: the limit is three orders
// of magnitude past anything a person writes, and it is checked at load time
// where the answer is an error the operator can read.
const maxActionsPerPolicy = 1000

// build is the one traversal: it validates the whole policy and returns the
// compiled form. Validate drops the result, Compile keeps it.
func (tp *TrafficPolicy) build() (*Compiled, error) {
	c := &Compiled{}
	if tp == nil {
		return c, nil
	}
	if n := len(tp.OnTCPConnect) + len(tp.OnHTTPRequest) + len(tp.OnHTTPResponse); n > maxActionsPerPolicy {
		return nil, fmt.Errorf("the policy has %d actions in total (on_tcp_connect %d, on_http_request %d, on_http_response %d); the maximum is %d",
			n, len(tp.OnTCPConnect), len(tp.OnHTTPRequest), len(tp.OnHTTPResponse), maxActionsPerPolicy)
	}

	var err error
	if c.connect, err = buildPhase(phaseConnect, tp.OnTCPConnect); err != nil {
		return nil, err
	}
	if c.request, err = buildPhase(phaseRequest, tp.OnHTTPRequest); err != nil {
		return nil, err
	}
	// At most one oidc action per policy (SPEC-CLUSTER18). The flow's state
	// belongs to the endpoint: two actions would reserve (possibly different)
	// callback paths on the same public host and mint session cookies under
	// the same endpoint, and the pre-dispatch seam hands the server one
	// runtime, not two. The scan is over the built actions -- the same place
	// the runtime lives -- so it cannot disagree with what compiled.
	oidcCount := 0
	for _, a := range c.request {
		if _, ok := a.auth.(*OIDCSettings); ok {
			oidcCount++
		}
	}
	if oidcCount > 1 {
		return nil, fmt.Errorf("the policy carries %d oidc actions; an endpoint carries at most one (its callback path and session cookies belong to the endpoint, not to a rule)", oidcCount)
	}
	// The body cap comes out of the same traversal, so a policy cannot
	// contain a body-consuming action the rewriter was never told about:
	// the flag is derived from the built actions, not declared beside them,
	// and cannot drift from what actually compiled.
	c.requestBodyCap = requestBodyCapOf(c.request)
	if c.response, err = buildPhase(phaseResponse, tp.OnHTTPResponse); err != nil {
		return nil, err
	}
	return c, nil
}

func buildPhase(p phase, rules []*Action) ([]*compiledAction, error) {
	if len(rules) == 0 {
		return nil, nil
	}
	out := make([]*compiledAction, 0, len(rules))
	for i, r := range rules {
		// "on_http_request[1] (deny)": the position in the phase, the action,
		// and no more. An index into a list the operator is looking at is the
		// most useful way to name a rule.
		if r == nil {
			return nil, fmt.Errorf("%s[%d]: action is empty", p, i)
		}
		if r.Name == "" {
			return nil, fmt.Errorf("%s[%d]: action has no name (this build implements %s)",
				p, i, strings.Join(phaseActions(p), ", "))
		}
		where := fmt.Sprintf("%s[%d] (%s)", p, i, r.Name)
		if _, known := actionPhases[r.Name]; !known {
			return nil, fmt.Errorf("%s: unknown action (this build implements %s)",
				where, strings.Join(phaseActions(p), ", "))
		}
		if !p.supports(r.Name) {
			return nil, fmt.Errorf("%s: the %s action is not implemented in the %s phase (this build implements %s there)",
				where, r.Name, p, strings.Join(phaseActions(p), ", "))
		}
		a, err := buildAction(p, where, r)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, nil
}

func buildAction(p phase, where string, r *Action) (*compiledAction, error) {
	a := &compiledAction{action: r.Name, where: where}

	for i, src := range r.Expressions {
		prg, err := compileExpr(p, src, true)
		if err != nil {
			return nil, fmt.Errorf("%s: condition %d: %v", where, i, err)
		}
		a.when = append(a.when, prg)
	}

	cfg := r.Config
	if cfg == nil {
		cfg = map[string]interface{}{}
	}

	switch r.Name {
	case ActionAddHeaders:
		// "headers" and nothing else. The check is not decoration: a typo in
		// the field name ("headerss") is a config the author believes is doing
		// something and an engine that does nothing, and the difference only
		// shows up when the header is missing from a production request.
		if err := checkConfigKeys(where, cfg, "headers"); err != nil {
			return nil, err
		}
		pairs, err := buildHeaders(p, where, cfg, true)
		if err != nil {
			return nil, err
		}
		a.addHeaders = pairs

	case ActionRemoveHeaders:
		names, err := buildRemoveHeaders(where, cfg)
		if err != nil {
			return nil, err
		}
		a.removeHeaders = names

	case ActionDeny:
		// A denied connection is answered with an empty body, so the only
		// config there is to give it is the status code -- and in
		// on_tcp_connect there is none at all, because there is no HTTP
		// response to give it a status. Both are ngrok's documented shapes.
		if p == phaseConnect {
			if err := checkConfigKeys(where, cfg); err != nil {
				return nil, err
			}
			a.statusCode = defaultDenyStatus
			break
		}
		if err := checkConfigKeys(where, cfg, "status_code"); err != nil {
			return nil, err
		}
		code, err := configStatus(where, cfg, defaultDenyStatus)
		if err != nil {
			return nil, err
		}
		a.statusCode = code

	case ActionCustomResponse:
		if err := checkConfigKeys(where, cfg, "status_code", "body", "headers"); err != nil {
			return nil, err
		}
		code, err := configStatus(where, cfg, defaultCustomResponseStatus)
		if err != nil {
			return nil, err
		}
		a.statusCode = code

		rawBody := ""
		if v, ok := cfg["body"]; ok {
			s, ok := v.(string)
			if !ok {
				return nil, fmt.Errorf("%s: config field \"body\" must be a string, got %s", where, typeName(v))
			}
			rawBody = s
		}
		if a.body, err = compileInterpolation(p, rawBody); err != nil {
			return nil, fmt.Errorf("%s: config field \"body\": %v", where, err)
		}

		if a.addHeaders, err = buildHeaders(p, where, cfg, false); err != nil {
			return nil, err
		}
		// ngrok infers a content-type when the config does not give one, and
		// so does this: sniffed from the configured body at load time (the
		// sniff sees the literal text, so a body that is entirely
		// interpolation sniffs as text/plain). Only when there is a body: a
		// bodiless response has no content to describe.
		if rawBody != "" && !hasHeader(a.addHeaders, "content-type") {
			a.addHeaders = append(a.addHeaders, headerPair{
				name:  "content-type",
				value: &interpolated{raw: sniffedContentType(rawBody), parts: []interpPart{{text: sniffedContentType(rawBody)}}},
			})
		}

	case ActionLog:
		md, err := buildMetadata(p, where, cfg)
		if err != nil {
			return nil, err
		}
		a.metadata = md

	case ActionSetVars:
		if err := checkConfigKeys(where, cfg, "vars"); err != nil {
			return nil, err
		}
		v, ok := cfg["vars"]
		if !ok {
			return nil, fmt.Errorf("%s: config field \"vars\" is required", where)
		}
		items, ok := asList(v)
		if !ok {
			return nil, fmt.Errorf("%s: config field \"vars\" must be a list of one-entry maps, got %s", where, typeName(v))
		}
		for i, item := range items {
			m, ok := asMap(item)
			if !ok || len(m) != 1 {
				return nil, fmt.Errorf("%s: config field \"vars\" entry %d: each entry must be a map with exactly one key, got %s",
					where, i, typeName(item))
			}
			// One key by the check above, so the order here cannot vary; sorted
			// anyway, so that a future relaxation of that check does not quietly
			// make this error non-deterministic.
			for _, name := range sortedKeys(m) {
				if !isIdent(name) {
					return nil, fmt.Errorf("%s: config field \"vars\" entry %d: %q is not a usable variable name (letters, digits and _ only, not starting with a digit; it is referenced as ${vars.%s})",
						where, i, name, name)
				}
				iv, err := interpolatedValue(p, fmt.Sprintf("%s: config field \"vars\" entry %d (%s)", where, i, name), m[name])
				if err != nil {
					return nil, err
				}
				a.assignments = append(a.assignments, assignment{name: name, value: iv})
			}
		}

	case ActionRestrictIPs:
		if err := checkConfigKeys(where, cfg, "enforce", "allow", "deny", "ip_policies"); err != nil {
			return nil, err
		}
		if _, ok := cfg["ip_policies"]; ok {
			return nil, fmt.Errorf("%s: config field \"ip_policies\" is not implemented in this build (it needs the ngrok API); use allow/deny CIDRs", where)
		}
		a.enforce = true
		if v, ok := cfg["enforce"]; ok {
			b, ok := v.(bool)
			if !ok {
				return nil, fmt.Errorf("%s: config field \"enforce\" must be a boolean, got %s", where, typeName(v))
			}
			a.enforce = b
		}
		var err error
		if a.allow, err = buildCIDRs(where, "allow", cfg["allow"]); err != nil {
			return nil, err
		}
		if a.deny, err = buildCIDRs(where, "deny", cfg["deny"]); err != nil {
			return nil, err
		}
		if len(a.allow) == 0 && len(a.deny) == 0 {
			return nil, fmt.Errorf("%s: restrict-ips needs at least one CIDR in \"allow\" or \"deny\"", where)
		}

	case ActionBasicAuth:
		// The four authentication actions follow (SPEC-CLUSTER6). Each is
		// built by the function that owns its runtime (auth_actions.go,
		// jwt.go); this case only checks the keys first, so that a typo'd
		// field is refused with the same "unknown config field" message every
		// other action gives, and hands the rest of the validation over.
		if err := checkConfigKeys(where, cfg, "realm", "credentials"); err != nil {
			return nil, err
		}
		auth, err := buildBasicAuth(where, cfg)
		if err != nil {
			return nil, err
		}
		a.auth = auth

	case ActionBearerAuth:
		if err := checkConfigKeys(where, cfg, "tokens"); err != nil {
			return nil, err
		}
		auth, err := buildBearerAuth(where, cfg)
		if err != nil {
			return nil, err
		}
		a.auth = auth

	case ActionAPIKeyAuth:
		if err := checkConfigKeys(where, cfg, "header", "keys"); err != nil {
			return nil, err
		}
		auth, err := buildAPIKeyAuth(where, cfg)
		if err != nil {
			return nil, err
		}
		a.auth = auth

	case ActionJWTValidation:
		if err := checkConfigKeys(where, cfg, "jwks_uri", "issuer", "audience", "algorithms", "leeway_seconds", "claims"); err != nil {
			return nil, err
		}
		auth, err := buildJWTValidation(where, cfg)
		if err != nil {
			return nil, err
		}
		a.auth = auth

	case ActionWebhookVerification:
		// The webhook verification action follows the authentication actions'
		// shape: keys first, so a typo'd field is refused with the standard
		// "unknown config field" message every other action gives, then the
		// builder that owns its runtime (webhook.go), which resolves the
		// secrets and freezes the per-provider refusal.
		if err := checkConfigKeys(where, cfg, "provider", "secrets", "tolerance_seconds"); err != nil {
			return nil, err
		}
		auth, err := buildWebhookVerification(where, cfg)
		if err != nil {
			return nil, err
		}
		a.auth = auth

	case ActionOIDC:
		// The oidc action (SPEC-CLUSTER18) follows the authentication
		// actions' shape too: keys first, then the builder that owns its
		// runtime (oidc.go). Conditions are refused rather than compiled --
		// the one refusal in this switch -- because the action applies to the
		// whole endpoint: the callback path it reserves and the session its
		// cookies mint are not per-rule, and the pre-dispatch seam it is
		// consumed at has one verdict per connection, not one per rule. An
		// operator asking for "authenticate everyone except /health" is
		// asking for path exemptions, a different feature; a condition that
		// parsed and was then ignored would look like it meant something.
		if len(r.Expressions) > 0 {
			return nil, fmt.Errorf("%s: the %s action cannot carry conditions; it applies to the whole endpoint (the callback path it reserves is not per-rule)", where, r.Name)
		}
		if err := checkConfigKeys(where, cfg, "issuer", "client_id", "client_secret", "scopes", "callback_path", "session_duration_seconds", "allowed_domains", "claims"); err != nil {
			return nil, err
		}
		auth, err := buildOIDC(where, cfg)
		if err != nil {
			return nil, err
		}
		a.auth = auth
	}

	return a, nil
}

// buildHeaders builds the `headers` object of an add-headers (required) or
// custom-response (optional) action. Names are lower-cased, as ngrok documents,
// and sorted so that what is emitted is the same on every run: the config is a
// map and a map has no order.
//
// The entries are walked in sorted order too, not for the output (the sort
// below fixes the emitted bytes either way) but for the error: a config with
// two bad entries has to report the same one every time, or the same document
// fails differently on consecutive runs and an operator chasing a flake is
// chasing the map's iteration order.
func buildHeaders(ph phase, where string, cfg map[string]interface{}, required bool) ([]headerPair, error) {
	v, ok := cfg["headers"]
	if !ok {
		if required {
			return nil, fmt.Errorf("%s: config field \"headers\" is required", where)
		}
		return nil, nil
	}
	m, ok := asMap(v)
	if !ok {
		return nil, fmt.Errorf("%s: config field \"headers\" must be an object of header name to value, got %s", where, typeName(v))
	}
	if required && len(m) == 0 {
		return nil, fmt.Errorf("%s: config field \"headers\" must have at least one header", where)
	}
	if len(m) > maxHeaderEntries {
		return nil, fmt.Errorf("%s: config field \"headers\" has %d headers; the maximum is %d", where, len(m), maxHeaderEntries)
	}

	pairs := make([]headerPair, 0, len(m))
	for _, k := range sortedKeys(m) {
		v := m[k]
		if err := checkHeaderName(where, k); err != nil {
			return nil, err
		}
		val, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("%s: config field \"headers\" entry %q must be a string, got %s", where, k, typeName(v))
		}
		// A CR or an LF in a configured value is a header-injection payload
		// aimed at whatever reads the request next, and it is not something an
		// author ever means to write. The rule is rewriter.ValidHeaderValue, the
		// same one the rewriter applies before it writes a value. This
		// package's runtime path drops such a value (the rewriter refuses to
		// write it, newHookRewrite's rule), so without this check the failure
		// mode is a header that is simply missing from production traffic --
		// and a value that is *supposed* to carry a line break can say so as
		// ${...} interpolation, which is evaluated after the check and is the
		// author's own expression rather than their document's literal bytes.
		// Refusing it here is the same choice the rest of this file makes: a
		// control that cannot run as written is a load error, not a silent
		// no-op.
		if !rewriter.ValidHeaderValue(val) {
			return nil, fmt.Errorf("%s: config field \"headers\" entry %q contains a CR or LF, which would split the header in two on the wire (%q)", where, k, val)
		}
		iv, err := compileInterpolation(ph, val)
		if err != nil {
			return nil, fmt.Errorf("%s: config field \"headers\" entry %q: %v", where, k, err)
		}
		pairs = append(pairs, headerPair{name: strings.ToLower(k), value: iv})
	}
	// Sorted by the name that actually goes on the wire, so that a config map
	// (which has no order) emits the same bytes on every run.
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].name < pairs[j].name })
	return pairs, nil
}

// buildRemoveHeaders builds remove-headers' `headers`: a list of names, which
// ngrok caps at ten and does not let touch user-agent.
func buildRemoveHeaders(where string, cfg map[string]interface{}) ([]string, error) {
	if err := checkConfigKeys(where, cfg, "headers"); err != nil {
		return nil, err
	}
	v, ok := cfg["headers"]
	if !ok {
		return nil, fmt.Errorf("%s: config field \"headers\" is required", where)
	}
	items, ok := asList(v)
	if !ok {
		return nil, fmt.Errorf("%s: config field \"headers\" must be a list of header names, got %s", where, typeName(v))
	}
	if len(items) == 0 {
		return nil, fmt.Errorf("%s: config field \"headers\" must name at least one header", where)
	}
	if len(items) > maxHeaderEntries {
		return nil, fmt.Errorf("%s: config field \"headers\" names %d headers; the maximum is %d", where, len(items), maxHeaderEntries)
	}
	out := make([]string, 0, len(items))
	for i, item := range items {
		name, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("%s: config field \"headers\" entry %d must be a string, got %s", where, i, typeName(item))
		}
		if err := checkHeaderName(where, name); err != nil {
			return nil, err
		}
		out = append(out, strings.ToLower(name))
	}
	return out, nil
}

// buildMetadata builds the log action's `metadata`, which ngrok marks required.
func buildMetadata(ph phase, where string, cfg map[string]interface{}) ([]headerPair, error) {
	if err := checkConfigKeys(where, cfg, "metadata"); err != nil {
		return nil, err
	}
	v, ok := cfg["metadata"]
	if !ok {
		return nil, fmt.Errorf("%s: config field \"metadata\" is required", where)
	}
	m, ok := asMap(v)
	if !ok {
		return nil, fmt.Errorf("%s: config field \"metadata\" must be an object of name to value, got %s", where, typeName(v))
	}
	pairs := make([]headerPair, 0, len(m))
	for _, k := range sortedKeys(m) {
		val, err := interpolatedValue(ph, fmt.Sprintf("%s: config field \"metadata\" entry %q", where, k), m[k])
		if err != nil {
			return nil, err
		}
		pairs = append(pairs, headerPair{name: k, value: val})
	}
	return pairs, nil
}

// buildCIDRs parses one allow/deny list. A bare address is accepted as a
// host CIDR ("203.0.113.7" is "203.0.113.7/32"), which is a superset of what
// ngrok accepts and cannot mean anything else.
func buildCIDRs(where, field string, v interface{}) ([]*net.IPNet, error) {
	if v == nil {
		return nil, nil
	}
	items, ok := asList(v)
	if !ok {
		return nil, fmt.Errorf("%s: config field %q must be a list of CIDRs, got %s", where, field, typeName(v))
	}
	out := make([]*net.IPNet, 0, len(items))
	for i, item := range items {
		s, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("%s: config field %q entry %d must be a CIDR string, got %s", where, field, i, typeName(item))
		}
		s = strings.TrimSpace(s)
		if !strings.Contains(s, "/") {
			if ip := net.ParseIP(s); ip != nil {
				bits := 128
				if ip.To4() != nil {
					bits = 32
				}
				s = fmt.Sprintf("%s/%d", s, bits)
			}
		}
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return nil, fmt.Errorf("%s: config field %q entry %d: %q is not a CIDR: %v", where, field, i, item, err)
		}
		out = append(out, n)
	}
	return out, nil
}

// configStatus reads a status code, which may have arrived as any of the
// integer types YAML and JSON decode into: the YAML decoder gives int (or uint64
// for a value past MaxInt64), encoding/json gives float64. The two are not
// interchangeable and this reads both.
func configStatus(where string, cfg map[string]interface{}, def int) (int, error) {
	v, ok := cfg["status_code"]
	if !ok {
		return def, nil
	}
	code, ok := asInt(v)
	if !ok {
		return 0, fmt.Errorf("%s: config field \"status_code\" must be an integer, got %s", where, typeName(v))
	}
	if code < 100 || code > 599 {
		return 0, fmt.Errorf("%s: config field \"status_code\" is %d, which is not an HTTP status code (100-599)", where, code)
	}
	return code, nil
}

// interpolatedValue turns one config value into something that can be rendered
// at runtime: a string is compiled for ${...} interpolation, a bool or a number
// is rendered once into a literal (there is nothing in it to interpolate), and
// a list or a map is refused rather than guessed at.
func interpolatedValue(ph phase, where string, v interface{}) (*interpolated, error) {
	switch t := v.(type) {
	case string:
		iv, err := compileInterpolation(ph, t)
		if err != nil {
			return nil, fmt.Errorf("%s: %v", where, err)
		}
		return iv, nil
	case bool, int, int64, uint64, float64, nil:
		text := formatValue(v)
		return &interpolated{raw: text, parts: []interpPart{{text: text}}}, nil
	default:
		return nil, fmt.Errorf("%s: must be a string, boolean or number in this build, got %s (the phase variable map holds strings)", where, typeName(v))
	}
}

// checkConfigKeys refuses a config field the action does not document. It is
// the difference between a policy that does less than its author thinks and one
// that fails to load.
func checkConfigKeys(where string, cfg map[string]interface{}, allowed ...string) error {
	for _, k := range sortedKeys(cfg) {
		if !contains(allowed, k) {
			return fmt.Errorf("%s: unknown config field %q (this action documents: %s)",
				where, k, strings.Join(allowed, ", "))
		}
	}
	return nil
}

// checkHeaderName enforces the header rules ngrok documents for add-headers and
// remove-headers: a valid header name, and never user-agent.
//
// The grammar is rewriter.ValidHeaderToken's -- the same RFC 7230 token rule
// the rewriter applies to a name before it writes it, and the client applies to
// a name before it loads it -- so a name that satisfies one of the three
// satisfies all three. The messages here stay policy's: an operator reading
// "on_http_request[0] (add-headers): config field "headers"..." needs the rule's
// path in the document, which the other two callers have no way to produce.
func checkHeaderName(where, name string) error {
	if name == "" {
		return fmt.Errorf("%s: a header name is empty", where)
	}
	if !rewriter.ValidHeaderToken(name) {
		return fmt.Errorf("%s: %q is not a valid header name", where, name)
	}
	if strings.EqualFold(name, "user-agent") {
		return fmt.Errorf("%s: the user-agent header may not be added or removed", where)
	}
	return nil
}

// sniffedContentType is what the custom-response action infers when its config
// does not set a content-type. net/http's sniffing is the same one the Go
// standard library applies to a response whose type nobody set, which is as
// good an answer as "infer the correct content-type" has.
func sniffedContentType(body string) string {
	return http.DetectContentType([]byte(body))
}

// hasHeader reports whether a built header list already sets a name.
func hasHeader(pairs []headerPair, name string) bool {
	for _, p := range pairs {
		if strings.EqualFold(p.name, name) {
			return true
		}
	}
	return false
}

// --- small helpers over the shapes a config value arrives in ---------------

// asMap accepts both map shapes a config value can arrive in: map[string]interface{}
// from a programmatic or JSON source, and map[interface{}]interface{} from the
// YAML decoder, which produces that shape -- with no hook to do otherwise -- for
// any nested map that has a key which is not a string, and which therefore
// arrives here only for a document this function is about to refuse.
func asMap(v interface{}) (map[string]interface{}, bool) {
	switch t := v.(type) {
	case map[string]interface{}:
		return t, true
	case map[interface{}]interface{}:
		out := make(map[string]interface{}, len(t))
		for k, val := range t {
			ks, ok := k.(string)
			if !ok {
				return nil, false
			}
			out[ks] = val
		}
		return out, true
	}
	return nil, false
}

// asList accepts the list shapes: []interface{} from YAML and JSON, and []string
// from a policy built in Go (which is how the tests write one).
func asList(v interface{}) ([]interface{}, bool) {
	switch t := v.(type) {
	case []interface{}:
		return t, true
	case []string:
		out := make([]interface{}, len(t))
		for i, s := range t {
			out[i] = s
		}
		return out, true
	}
	return nil, false
}

// asInt accepts every integer type a decoder may produce for an int-valued
// field, plus json.Number.
func asInt(v interface{}) (int, bool) {
	switch t := v.(type) {
	case int:
		return t, true
	case int8:
		return int(t), true
	case int16:
		return int(t), true
	case int32:
		return int(t), true
	case int64:
		return int(t), true
	case uint:
		return int(t), true
	case uint8:
		return int(t), true
	case uint16:
		return int(t), true
	case uint32:
		return int(t), true
	case uint64:
		return int(t), true
	case float32:
		return int(t), float64(t) == math.Trunc(float64(t))
	case float64:
		return int(t), t == math.Trunc(t)
	case json.Number:
		i, err := t.Int64()
		return int(i), err == nil
	}
	return 0, false
}

// typeName names the type of a config value for an error message, using the
// names a policy author would recognise rather than Go's.
func typeName(v interface{}) string {
	switch v.(type) {
	case nil:
		return "null"
	case string:
		return "a string"
	case bool:
		return "a boolean"
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, float32, float64, json.Number:
		return "a number"
	}
	if _, ok := asMap(v); ok {
		return "an object"
	}
	if _, ok := asList(v); ok {
		return "a list"
	}
	return fmt.Sprintf("%T", v)
}

// isIdent reports whether s can be referenced as a CEL field name
// (${vars.<name>}), which is stricter than rewriter.ValidHeaderToken (the token
// grammar this file used to carry a copy of): a variable named "a-b" could be
// stored but never read.
func isIdent(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '_':
		case c >= '0' && c <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
