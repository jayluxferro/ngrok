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

	"github.com/google/cel-go/cel"
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
}

// phaseActions lists, in a stable order, the actions a phase implements, for
// error messages that tell an operator what they could have written instead.
func phaseActions(p phase) []string {
	var out []string
	for _, name := range []string{
		ActionRestrictIPs, ActionDeny, ActionLog,
		ActionAddHeaders, ActionRemoveHeaders, ActionCustomResponse, ActionSetVars,
	} {
		for _, ph := range actionPhases[name] {
			if ph == p {
				out = append(out, name)
				break
			}
		}
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

// build is the one traversal: it validates the whole policy and returns the
// compiled form. Validate drops the result, Compile keeps it.
func (tp *TrafficPolicy) build() (*Compiled, error) {
	c := &Compiled{}
	if tp == nil {
		return c, nil
	}

	var err error
	if c.connect, err = buildPhase(phaseConnect, tp.OnTCPConnect); err != nil {
		return nil, err
	}
	if c.request, err = buildPhase(phaseRequest, tp.OnHTTPRequest); err != nil {
		return nil, err
	}
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
	env := celEnvs[p]
	a := &compiledAction{action: r.Name, rule: r.Name, where: where}

	for i, src := range r.Expressions {
		prg, err := compileExpr(env, src, true)
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
		pairs, err := buildHeaders(env, where, cfg, true)
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
		if a.body, err = compileInterpolation(env, rawBody); err != nil {
			return nil, fmt.Errorf("%s: config field \"body\": %v", where, err)
		}

		if a.addHeaders, err = buildHeaders(env, where, cfg, false); err != nil {
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
		md, err := buildMetadata(env, where, cfg)
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
			for name, val := range m {
				if !isIdent(name) {
					return nil, fmt.Errorf("%s: config field \"vars\" entry %d: %q is not a usable variable name (letters, digits and _ only, not starting with a digit; it is referenced as ${vars.%s})",
						where, i, name, name)
				}
				val, err := interpolatedValue(env, fmt.Sprintf("%s: config field \"vars\" entry %d (%s)", where, i, name), val)
				if err != nil {
					return nil, err
				}
				a.assignments = append(a.assignments, assignment{name: name, value: val})
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
	}

	return a, nil
}

// buildHeaders builds the `headers` object of an add-headers (required) or
// custom-response (optional) action. Names are lower-cased, as ngrok documents,
// and sorted so that what is emitted is the same on every run: the config is a
// map and a map has no order.
func buildHeaders(env *cel.Env, where string, cfg map[string]interface{}, required bool) ([]headerPair, error) {
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
	for k, v := range m {
		if err := checkHeaderName(where, k); err != nil {
			return nil, err
		}
		val, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("%s: config field \"headers\" entry %q must be a string, got %s", where, k, typeName(v))
		}
		iv, err := compileInterpolation(env, val)
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
func buildMetadata(env *cel.Env, where string, cfg map[string]interface{}) ([]headerPair, error) {
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
		val, err := interpolatedValue(env, fmt.Sprintf("%s: config field \"metadata\" entry %q", where, k), m[k])
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
// integer types YAML and JSON decode into: yaml.v1 gives int (or uint64 for a
// large value), encoding/json gives float64.
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
func interpolatedValue(env *cel.Env, where string, v interface{}) (*interpolated, error) {
	switch t := v.(type) {
	case string:
		iv, err := compileInterpolation(env, t)
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
func checkHeaderName(where, name string) error {
	if name == "" {
		return fmt.Errorf("%s: a header name is empty", where)
	}
	if !isToken(name) {
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
// from a programmatic or JSON source, and map[interface{}]interface{} from yaml.v1,
// which decodes nested maps that way and has no hook to do otherwise.
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

// isToken reports whether s is an RFC 7230 token, which is what a header name
// has to be to reach the wire.
func isToken(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return len(s) > 0
}

// isIdent reports whether s can be referenced as a CEL field name
// (${vars.<name>}), which is stricter than isToken: a variable named "a-b"
// could be stored but never read.
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
