package policy

// Tests for the policy engine: what a policy document may say (validation),
// what it does at runtime (the hooks), and what it does to a connection before
// any HTTP exists (EvaluateConnect).
//
// They are written as tables of documents, because that is the shape of the
// thing being tested: a policy is a document, and the interesting assertions
// are "this document is refused, and the error says why" and "this document
// changes this message like so". The runtime tests drive the real hooks --
// RequestHook/ResponseHook with an http.Request/http.Response and a logger
// that records what was written -- rather than the internals, so that what is
// asserted is what the rewriter would see.

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"ngrok/log"
)

// testLogger implements log.Logger and records what the policy wrote. The mutex
// is not strictly needed -- one test, one goroutine per hook -- but the hooks
// are called from the rewriter's goroutines in production and a test logger
// that would race if it were is a trap for the next person.
type testLogger struct {
	mu   sync.Mutex
	info []string
	warn []string
}

func (l *testLogger) record(dst *[]string, format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	*dst = append(*dst, fmt.Sprintf(format, args...))
}

func (l *testLogger) AddLogPrefix(string)      {}
func (l *testLogger) SetLogPrefixes(...string) {}
func (l *testLogger) Debug(string, ...interface{}) {
}
func (l *testLogger) Info(format string, args ...interface{}) {
	l.record(&l.info, format, args...)
}
func (l *testLogger) Warn(format string, args ...interface{}) error {
	l.record(&l.warn, format, args...)
	return nil
}
func (l *testLogger) Error(format string, args ...interface{}) error {
	l.record(&l.warn, format, args...)
	return nil
}

func (l *testLogger) lines(which []string) string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(which, "\n")
}

var _ log.Logger = (*testLogger)(nil)

// --- document builders ------------------------------------------------------

// rule builds one rule the way a policy document would, with config given as a
// plain map (the callers below use the same shapes the YAML decoder and
// encoding/json produce: ints, strings, nested maps).
func rule(name string, expressions []string, config map[string]interface{}) *Action {
	return &Action{Name: name, Expressions: expressions, Config: config}
}

func reqPolicy(rules ...*Action) *TrafficPolicy {
	return &TrafficPolicy{OnHTTPRequest: rules}
}

// --- validation -------------------------------------------------------------

func TestValidateRejects(t *testing.T) {
	long := map[string]interface{}{}
	for i := 0; i < 11; i++ {
		long[fmt.Sprintf("x-h-%d", i)] = "v"
	}
	longList := []interface{}{}
	for i := 0; i < 11; i++ {
		longList = append(longList, fmt.Sprintf("x-h-%d", i))
	}

	tests := []struct {
		name string
		doc  *TrafficPolicy
		want string // a substring of the error: the action, and why
	}{
		{
			"unknown action",
			reqPolicy(rule("no-such-action", nil, nil)),
			`on_http_request[0] (no-such-action): unknown action`,
		},
		{
			"empty action name",
			reqPolicy(rule("", nil, nil)),
			`on_http_request[0]: action has no name`,
		},
		{
			"nil action",
			reqPolicy(nil),
			`on_http_request[0]: action is empty`,
		},
		{
			"action in a phase it does not belong to",
			reqPolicy(rule("restrict-ips", nil, map[string]interface{}{"deny": []interface{}{"10.0.0.0/8"}})),
			`on_http_request[0] (restrict-ips): the restrict-ips action is not implemented in the on_http_request phase`,
		},
		{
			"set-vars in the response phase",
			&TrafficPolicy{OnHTTPResponse: []*Action{rule("set-vars", nil, map[string]interface{}{
				"vars": []interface{}{map[interface{}]interface{}{"a": "b"}},
			})}},
			`on_http_response[0] (set-vars): the set-vars action is not implemented in the on_http_response phase`,
		},
		{
			"bad CEL",
			reqPolicy(rule("deny", []string{"req.method ="}, nil)),
			`on_http_request[0] (deny): condition 0: expression "req.method =" does not compile`,
		},
		{
			// A literal has a known type, so this one is refused at load time.
			// (Everything a policy can name is typed now, so this is the common
			// case rather than the special one; the dyn carve-out exists for
			// shapes like `[1, 'a'][0]`, whose type the compiler will not pin
			// down, and those are checked when they are read --
			// TestCompileExprRejectsNonBoolOnlyWhenKnown and
			// TestPolicyConditionThatIsNotABoolIsRefusedAtLoad.)
			"condition that is not a condition",
			reqPolicy(rule("deny", []string{"1 + 1"}, nil)),
			`expression "1 + 1" is not a condition: it evaluates to int, not bool`,
		},
		{
			// A name this build does not declare at all is a compile error.
			"variable outside the subset",
			reqPolicy(rule("deny", []string{"endpoint.id == 'ep_1'"}, nil)),
			`undeclared reference to 'endpoint'`,
		},
		{
			"time variable outside the subset",
			&TrafficPolicy{OnTCPConnect: []*Action{rule("deny", []string{"time.now() < time.now()"}, nil)}},
			`undeclared reference to 'time'`,
		},
		{
			"response variable in the request phase",
			reqPolicy(rule("deny", []string{"res.status_code == 500"}, nil)),
			`undeclared reference to 'res'`,
		},
		{
			"request variable in the response phase",
			&TrafficPolicy{OnHTTPResponse: []*Action{rule("log", []string{"req.method == 'GET'"}, map[string]interface{}{
				"metadata": map[string]interface{}{"m": "x"},
			})}},
			`undeclared reference to 'req'`,
		},
		{
			"deny with a body",
			reqPolicy(rule("deny", nil, map[string]interface{}{"body": "no"})),
			`unknown config field "body"`,
		},
		{
			"deny status out of range",
			reqPolicy(rule("deny", nil, map[string]interface{}{"status_code": 99})),
			`config field "status_code" is 99, which is not an HTTP status code`,
		},
		{
			"deny status that is not a number",
			reqPolicy(rule("deny", nil, map[string]interface{}{"status_code": "403"})),
			`config field "status_code" must be an integer, got a string`,
		},
		{
			"add-headers without headers",
			reqPolicy(rule("add-headers", nil, nil)),
			`config field "headers" is required`,
		},
		{
			"add-headers with too many headers",
			reqPolicy(rule("add-headers", nil, map[string]interface{}{"headers": long})),
			`has 11 headers; the maximum is 10`,
		},
		{
			"add-headers with user-agent",
			reqPolicy(rule("add-headers", nil, map[string]interface{}{"headers": map[string]interface{}{"user-agent": "x"}})),
			`the user-agent header may not be added or removed`,
		},
		{
			"add-headers with an invalid name",
			reqPolicy(rule("add-headers", nil, map[string]interface{}{"headers": map[string]interface{}{"bad name": "x"}})),
			`"bad name" is not a valid header name`,
		},
		{
			"add-headers with a non-string value",
			reqPolicy(rule("add-headers", nil, map[string]interface{}{"headers": map[string]interface{}{"x-a": 3}})),
			`entry "x-a" must be a string, got a number`,
		},
		{
			"remove-headers with an empty list",
			reqPolicy(rule("remove-headers", nil, map[string]interface{}{"headers": []interface{}{}})),
			`must name at least one header`,
		},
		{
			"remove-headers with too many",
			reqPolicy(rule("remove-headers", nil, map[string]interface{}{"headers": longList})),
			`names 11 headers; the maximum is 10`,
		},
		{
			"remove-headers with user-agent",
			reqPolicy(rule("remove-headers", nil, map[string]interface{}{"headers": []interface{}{"User-Agent"}})),
			`the user-agent header may not be added or removed`,
		},
		{
			"custom-response with an unterminated interpolation",
			reqPolicy(rule("custom-response", nil, map[string]interface{}{"body": "hi ${vars.a"})),
			`is missing its closing '}'`,
		},
		{
			"custom-response with an empty interpolation",
			reqPolicy(rule("custom-response", nil, map[string]interface{}{"body": "hi ${}"})),
			`has an empty expression`,
		},
		{
			"custom-response header interpolation that cannot compile",
			reqPolicy(rule("custom-response", nil, map[string]interface{}{
				"headers": map[string]interface{}{"x-a": "${endpoint.id}"},
			})),
			`config field "headers" entry "x-a": expression "endpoint.id" does not compile`,
		},
		{
			"log without metadata",
			reqPolicy(rule("log", nil, nil)),
			`config field "metadata" is required`,
		},
		{
			"log metadata that is not an object",
			reqPolicy(rule("log", nil, map[string]interface{}{"metadata": "x"})),
			`config field "metadata" must be an object of name to value, got a string`,
		},
		{
			"set-vars without vars",
			reqPolicy(rule("set-vars", nil, nil)),
			`config field "vars" is required`,
		},
		{
			"set-vars entry with two keys",
			reqPolicy(rule("set-vars", nil, map[string]interface{}{
				"vars": []interface{}{map[interface{}]interface{}{"a": "1", "b": "2"}},
			})),
			`each entry must be a map with exactly one key`,
		},
		{
			"set-vars entry with an unusable name",
			reqPolicy(rule("set-vars", nil, map[string]interface{}{
				"vars": []interface{}{map[interface{}]interface{}{"a-b": "1"}},
			})),
			`"a-b" is not a usable variable name`,
		},
		{
			"set-vars value that is a list",
			reqPolicy(rule("set-vars", nil, map[string]interface{}{
				"vars": []interface{}{map[interface{}]interface{}{"a": []interface{}{1, 2}}},
			})),
			`must be a string, boolean or number in this build, got a list`,
		},
		{
			"restrict-ips with ip_policies",
			&TrafficPolicy{OnTCPConnect: []*Action{rule("restrict-ips", nil, map[string]interface{}{
				"ip_policies": []interface{}{"pol_1"},
			})}},
			`config field "ip_policies" is not implemented in this build`,
		},
		{
			"restrict-ips with a bad CIDR",
			&TrafficPolicy{OnTCPConnect: []*Action{rule("restrict-ips", nil, map[string]interface{}{
				"deny": []interface{}{"10.0.0.0/33"},
			})}},
			`config field "deny" entry 0: "10.0.0.0/33" is not a CIDR`,
		},
		{
			"restrict-ips with nothing to match",
			&TrafficPolicy{OnTCPConnect: []*Action{rule("restrict-ips", nil, map[string]interface{}{
				"enforce": true,
			})}},
			`restrict-ips needs at least one CIDR in "allow" or "deny"`,
		},
		{
			"restrict-ips with a non-boolean enforce",
			&TrafficPolicy{OnTCPConnect: []*Action{rule("restrict-ips", nil, map[string]interface{}{
				"enforce": "yes", "deny": []interface{}{"10.0.0.0/8"},
			})}},
			`config field "enforce" must be a boolean, got a string`,
		},
		{
			"unknown config field",
			reqPolicy(rule("log", nil, map[string]interface{}{"metadata": map[string]interface{}{"a": "b"}, "level": "info"})),
			`unknown config field "level" (this action documents: metadata)`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.doc.Validate()
			if err == nil {
				t.Fatalf("Validate accepted a policy it should refuse")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error does not name the action and the reason.\n got: %v\nwant substring: %s", err, tt.want)
			}
			// Compile runs the same traversal, so it must refuse the same
			// document rather than building a half-compiled policy.
			if _, cerr := tt.doc.Compile(); cerr == nil {
				t.Fatalf("Compile accepted a policy Validate refuses")
			}
		})
	}
}

func TestValidateAccepts(t *testing.T) {
	doc := &TrafficPolicy{
		OnTCPConnect: []*Action{
			rule("log", []string{"conn.client_ip == '1.2.3.4'"}, map[string]interface{}{
				"metadata": map[string]interface{}{"message": "connected"},
			}),
			rule("restrict-ips", nil, map[string]interface{}{
				"enforce": true,
				"allow":   []interface{}{"203.0.113.0/24", "2001:db8::/32"},
				"deny":    []interface{}{"203.0.113.7"},
			}),
			rule("deny", nil, nil),
		},
		OnHTTPRequest: []*Action{
			rule("set-vars", nil, map[string]interface{}{
				"vars": []interface{}{map[interface{}]interface{}{"who": "${req.headers['x-user']}"}},
			}),
			rule("add-headers", []string{"req.method == 'GET'"}, map[string]interface{}{
				"headers": map[interface{}]interface{}{"x-user": "${vars.who}"},
			}),
			rule("remove-headers", nil, map[string]interface{}{"headers": []string{"X-Internal"}}),
			rule("custom-response", []string{"req.url.path.startsWith('/maintenance')"}, map[string]interface{}{
				"status_code": int64(503),
				"body":        "<html><body>${vars.who}</body></html>",
				"headers":     map[string]interface{}{"retry-after": "60"},
			}),
			rule("deny", []string{"req.url.path == '/admin'"}, map[string]interface{}{"status_code": 403}),
			rule("log", nil, map[string]interface{}{"metadata": map[string]interface{}{"m": "x"}}),
		},
		OnHTTPResponse: []*Action{
			rule("add-headers", []string{"res.status_code >= 500"}, map[string]interface{}{
				"headers": map[string]interface{}{"x-degraded": "1"},
			}),
			rule("remove-headers", nil, map[string]interface{}{"headers": []interface{}{"server"}}),
			rule("log", nil, map[string]interface{}{"metadata": map[string]interface{}{"status": "${res.status_code}"}}),
		},
	}

	if err := doc.Validate(); err != nil {
		t.Fatalf("Validate refused a valid policy: %v", err)
	}
	if doc.IsZero() {
		t.Fatalf("a policy with rules reports itself as empty")
	}
	if _, err := doc.Compile(); err != nil {
		t.Fatalf("Compile of a valid policy failed: %v", err)
	}
}

func TestValidateNilAndEmpty(t *testing.T) {
	var nilPolicy *TrafficPolicy
	if err := nilPolicy.Validate(); err != nil {
		t.Fatalf("a nil policy (no policy) must be valid, got %v", err)
	}
	if !nilPolicy.IsZero() || !(&TrafficPolicy{}).IsZero() {
		t.Fatalf("a policy with no rules must report itself empty")
	}
	c, err := nilPolicy.Compile()
	if err != nil {
		t.Fatalf("compiling a nil policy: %v", err)
	}
	// A compiled empty policy must be inert on every path, including the
	// connect one, which the server calls without a nil check.
	if v := c.EvaluateConnect("1.2.3.4:1"); v.Deny {
		t.Fatalf("an empty policy denied a connection")
	}
	if c.RequestHook(nil, "1.2.3.4:1") != nil || c.ResponseHook(nil, "1.2.3.4:1") != nil {
		t.Fatalf("an empty policy produced a hook; the rewriter would take the hook path for nothing")
	}
	var nilCompiled *Compiled
	if v := nilCompiled.EvaluateConnect("1.2.3.4:1"); v.Deny {
		t.Fatalf("a nil compiled policy denied a connection")
	}
	if nilCompiled.RequestHook(nil, "1.2.3.4:1") != nil {
		t.Fatalf("a nil compiled policy produced a request hook")
	}
	if nilCompiled.ResponseHook(nil, "1.2.3.4:1") != nil {
		t.Fatalf("a nil compiled policy produced a response hook")
	}
}

// --- the request hook -------------------------------------------------------

func compileRequest(t *testing.T, tp *TrafficPolicy) (*Compiled, *testLogger) {
	t.Helper()
	c, err := tp.Compile()
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return c, &testLogger{}
}

func get(target string, headers map[string]string) *http.Request {
	r := httptest.NewRequest("GET", target, nil)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func TestRequestHookConditions(t *testing.T) {
	tests := []struct {
		name       string
		expr       []string
		target     string
		headers    map[string]string
		cookie     string
		clientAddr string
		wantDeny   bool // the rule was deny
	}{
		{"method matches", []string{"req.method == 'GET'"}, "/", nil, "", "1.2.3.4:1", true},
		{"method does not match", []string{"req.method == 'POST'"}, "/", nil, "", "1.2.3.4:1", false},
		{"path matches", []string{"req.url.path == '/admin'"}, "/admin", nil, "", "1.2.3.4:1", true},
		{"path does not match", []string{"req.url.path == '/admin'"}, "/admin/1", nil, "", "1.2.3.4:1", false},
		{"path prefix", []string{"req.url.path.startsWith('/admin/')"}, "/admin/users", nil, "", "1.2.3.4:1", true},
		{"query", []string{"req.url.query == 'debug=1'"}, "/?debug=1", nil, "", "1.2.3.4:1", true},
		{"raw target", []string{"req.url.raw == '/?debug=1'"}, "/?debug=1", nil, "", "1.2.3.4:1", true},
		{"header", []string{"req.headers['x-api-key'] == 'secret'"}, "/", map[string]string{"X-Api-Key": "secret"}, "", "1.2.3.4:1", true},
		{"header name is case-insensitive", []string{"req.headers['x-api-key'] == 'secret'"}, "/", map[string]string{"X-API-KEY": "secret"}, "", "1.2.3.4:1", true},
		{"cookie", []string{"req.cookies['session'] == 'abc'"}, "/", map[string]string{"Cookie": "session=abc"}, "", "1.2.3.4:1", true},
		{"client ip", []string{"conn.client_ip == '1.2.3.4'"}, "/", nil, "", "1.2.3.4:1234", true},
		{"client ip does not match", []string{"conn.client_ip == '1.2.3.4'"}, "/", nil, "", "5.6.7.8:1234", false},
		{"remote addr", []string{"conn.remote_addr == '1.2.3.4:1234'"}, "/", nil, "", "1.2.3.4:1234", true},
		{"anonymous ipv6", []string{"conn.client_ip == '::1'"}, "/", nil, "", "[::1]:1234", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := reqPolicy(rule("deny", tt.expr, nil))
			c, lg := compileRequest(t, doc)
			hook := c.RequestHook(lg, tt.clientAddr)
			if hook == nil {
				t.Fatalf("no request hook for a policy with a request rule")
			}
			verdict := hook(get(tt.target, tt.headers))
			denied := verdict != nil && verdict.Terminate != nil
			if denied != tt.wantDeny {
				t.Fatalf("denied = %v, want %v (verdict %+v)", denied, tt.wantDeny, verdict)
			}
			if tt.wantDeny && verdict.Terminate.StatusCode != 403 {
				t.Fatalf("deny without a status_code answered %d, want the documented default 403", verdict.Terminate.StatusCode)
			}
			// A rule that did not match must leave no trace at all: the
			// rewriter treats a nil verdict as "nothing to do".
			if !tt.wantDeny && verdict != nil {
				t.Fatalf("a rule that did not match returned a verdict: %+v", verdict)
			}
		})
	}
}

func TestRequestHookExpressionsAreAnded(t *testing.T) {
	doc := reqPolicy(rule("deny", []string{"req.method == 'GET'", "req.url.path == '/admin'"}, nil))
	c, lg := compileRequest(t, doc)
	hook := c.RequestHook(lg, "1.2.3.4:1")

	if v := hook(get("/admin", nil)); v == nil || v.Terminate == nil {
		t.Fatalf("both conditions hold, want a denial, got %+v", v)
	}
	if v := hook(get("/other", nil)); v != nil {
		t.Fatalf("one condition fails, the rule must not apply, got %+v", v)
	}
}

func TestRequestHookDenyAndCustomResponse(t *testing.T) {
	doc := reqPolicy(
		rule("deny", []string{"req.url.path == '/admin'"}, map[string]interface{}{"status_code": 404}),
		rule("custom-response", []string{"req.url.path == '/maintenance'"}, map[string]interface{}{
			"status_code": 503,
			"body":        "back soon",
			"headers":     map[interface{}]interface{}{"retry-after": "60"},
		}),
	)
	c, lg := compileRequest(t, doc)
	hook := c.RequestHook(lg, "1.2.3.4:1")

	v := hook(get("/admin", nil))
	if v == nil || v.Terminate == nil || v.Terminate.StatusCode != 404 {
		t.Fatalf("deny: want a 404 synthetic response, got %+v", v)
	}
	if v.Terminate.Body != "" {
		t.Fatalf("deny sets no body, got %q", v.Terminate.Body)
	}

	v = hook(get("/maintenance", nil))
	if v == nil || v.Terminate == nil || v.Terminate.StatusCode != 503 {
		t.Fatalf("custom-response: want a 503, got %+v", v)
	}
	if v.Terminate.Body != "back soon" {
		t.Fatalf("custom-response body = %q, want %q", v.Terminate.Body, "back soon")
	}
	// The configured header, plus the content-type ngrok infers when the
	// config does not give one.
	headers := strings.Join(v.Terminate.Headers, "|")
	if !strings.Contains(headers, "retry-after: 60") {
		t.Fatalf("custom-response dropped a configured header: %v", v.Terminate.Headers)
	}
	if !strings.Contains(headers, "content-type: text/plain; charset=utf-8") {
		t.Fatalf("custom-response did not infer a content-type: %v", v.Terminate.Headers)
	}
}

func TestCustomResponseDefaultsAndContentType(t *testing.T) {
	doc := reqPolicy(rule("custom-response", []string{"req.url.path == '/x'"}, map[string]interface{}{
		"body": "<html><body>hi</body></html>",
	}))
	c, lg := compileRequest(t, doc)
	v := c.RequestHook(lg, "1.2.3.4:1")(get("/x", nil))
	if v == nil || v.Terminate == nil {
		t.Fatalf("want a synthetic response")
	}
	if v.Terminate.StatusCode != 200 {
		t.Fatalf("custom-response without a status_code answered %d, want 200", v.Terminate.StatusCode)
	}
	if len(v.Terminate.Headers) != 1 || !strings.EqualFold(v.Terminate.Headers[0], "Content-Type: text/html; charset=utf-8") {
		t.Fatalf("content-type was not inferred from the body: %v", v.Terminate.Headers)
	}
}

func TestCustomResponseKeepsConfiguredContentType(t *testing.T) {
	doc := reqPolicy(rule("custom-response", nil, map[string]interface{}{
		"body":    `{"a":1}`,
		"headers": map[string]interface{}{"Content-Type": "application/json"},
	}))
	c, lg := compileRequest(t, doc)
	v := c.RequestHook(lg, "1.2.3.4:1")(get("/", nil))
	if v == nil || v.Terminate == nil {
		t.Fatalf("want a synthetic response")
	}
	// Exactly one content-type, and it is the configured one, not the sniffed
	// one: a configured value is never overridden.
	types := 0
	for _, h := range v.Terminate.Headers {
		if strings.HasPrefix(strings.ToLower(h), "content-type:") {
			types++
			if !strings.HasSuffix(h, "application/json") {
				t.Fatalf("configured content-type was replaced: %v", v.Terminate.Headers)
			}
		}
	}
	if types != 1 {
		t.Fatalf("want exactly one content-type, got %v", v.Terminate.Headers)
	}
}

func TestRequestHookHeaderActions(t *testing.T) {
	doc := reqPolicy(
		rule("add-headers", nil, map[string]interface{}{
			"headers": map[interface{}]interface{}{"x-added": "yes", "X-Second": "${req.headers['x-user']}"},
		}),
		rule("remove-headers", nil, map[string]interface{}{"headers": []interface{}{"X-Internal"}}),
	)
	c, lg := compileRequest(t, doc)
	v := c.RequestHook(lg, "1.2.3.4:1")(get("/", map[string]string{"X-User": "jay"}))
	if v == nil {
		t.Fatalf("header actions returned no verdict")
	}
	if v.Terminate != nil {
		t.Fatalf("header actions must not terminate the request")
	}
	gotAdds := strings.Join(v.Add, "|")
	// Sorted by name, lower-cased, values interpolated.
	if gotAdds != "x-added: yes|x-second: jay" {
		t.Fatalf("adds = %q, want %q", gotAdds, "x-added: yes|x-second: jay")
	}
	if strings.Join(v.Remove, ",") != "x-internal" {
		t.Fatalf("removes = %v, want [x-internal]", v.Remove)
	}
}

func TestSetVarsVisibleToLaterActions(t *testing.T) {
	doc := reqPolicy(
		rule("set-vars", nil, map[string]interface{}{
			"vars": []interface{}{
				map[interface{}]interface{}{"a": "Hello,"},
				map[interface{}]interface{}{"b": "${req.headers['x-name']}"},
			},
		}),
		rule("custom-response", []string{"req.url.path == '/greet'"}, map[string]interface{}{
			"body":    "${vars.a} ${vars.b}!",
			"headers": map[string]interface{}{"x-who": "${vars.b}"},
		}),
		rule("add-headers", []string{"req.url.path == '/other'"}, map[string]interface{}{
			"headers": map[string]interface{}{"x-who": "${vars.b}"},
		}),
	)
	c, lg := compileRequest(t, doc)
	hook := c.RequestHook(lg, "1.2.3.4:1")

	v := hook(get("/greet", map[string]string{"X-Name": "Jay"}))
	if v == nil || v.Terminate == nil {
		t.Fatalf("want a synthetic response, got %+v", v)
	}
	if v.Terminate.Body != "Hello, Jay!" {
		t.Fatalf("body = %q, want %q", v.Terminate.Body, "Hello, Jay!")
	}
	if len(v.Terminate.Headers) < 1 || !strings.Contains(strings.Join(v.Terminate.Headers, "|"), "x-who: Jay") {
		t.Fatalf("header interpolation: %v", v.Terminate.Headers)
	}

	v = hook(get("/other", map[string]string{"X-Name": "Ada"}))
	if v == nil || strings.Join(v.Add, "|") != "x-who: Ada" {
		t.Fatalf("adds = %+v, want x-who: Ada", v)
	}

	// The vars belong to one message: the next request starts empty, so the
	// interpolation of an unset var is empty rather than the previous value.
	v = hook(get("/other", nil))
	if v == nil || strings.Join(v.Add, "|") != "x-who: " {
		t.Fatalf("vars leaked between messages: %+v", v)
	}
}

func TestVarsAreOrderedByPhaseOrder(t *testing.T) {
	// The add-headers rule runs before set-vars, so it sees the empty value:
	// ngrok evaluates actions in the order they are written, and so does this.
	doc := reqPolicy(
		rule("add-headers", nil, map[string]interface{}{"headers": map[string]interface{}{"x-a": "${vars.a}"}}),
		rule("set-vars", nil, map[string]interface{}{"vars": []interface{}{map[interface{}]interface{}{"a": "late"}}}),
	)
	c, lg := compileRequest(t, doc)
	v := c.RequestHook(lg, "1.2.3.4:1")(get("/", nil))
	if v == nil || strings.Join(v.Add, "|") != "x-a: " {
		t.Fatalf("phase order was not honored: %+v", v)
	}
}

func TestLogAction(t *testing.T) {
	doc := reqPolicy(rule("log", []string{"req.url.path == '/logged'"}, map[string]interface{}{
		"metadata": map[interface{}]interface{}{
			"message": "hello",
			"path":    "${req.url.path}",
			"code":    7,
			"flag":    true,
		},
	}))
	c, lg := compileRequest(t, doc)
	hook := c.RequestHook(lg, "1.2.3.4:1")

	if v := hook(get("/logged", nil)); v != nil {
		t.Fatalf("log is non-terminating: %+v", v)
	}
	if v := hook(get("/other", nil)); v != nil {
		t.Fatalf("the rule did not match, nothing should happen: %+v", v)
	}

	line := lg.lines(lg.info)
	if !strings.Contains(line, "traffic policy log action") {
		t.Fatalf("no log line was written:\n%s", line)
	}
	if !strings.Contains(line, "on_http_request") {
		t.Fatalf("the log line does not name the phase:\n%s", line)
	}
	// Metadata keys are sorted, values interpolated and quoted.
	if !strings.Contains(line, `code="7" flag="true" message="hello" path="/logged"`) {
		t.Fatalf("the log line does not carry the metadata:\n%s", line)
	}
	if len(lg.warn) != 0 {
		t.Fatalf("a healthy policy wrote warnings: %v", lg.warn)
	}
}

func TestRequestHookFailsOpenOnRuntimeErrors(t *testing.T) {
	// Both expressions compile and both fail at evaluation. With every name
	// declared by its own dotted name these are the two shapes that are left,
	// and neither can be moved to load time: a map key that is not there (CEL's
	// `no such key` is a runtime error, not a compile one), and a conversion
	// whose input the compiler cannot see -- int() of a header value is
	// well-typed and fails on the value itself. (This test used to carry a third
	// shape, `req.headers[req.method]`, which was dyn under the map-typed
	// declarations and is a load-time type error now; that it moved is the point
	// of the strict variable set, and TestCompileExprRejectsNonBoolOnlyWhenKnown
	// asserts it.)
	doc := reqPolicy(
		rule("deny", []string{"req.headers['x-missing'] == 'yes'"}, nil),
		rule("deny", []string{"int(req.headers['x-count']) > 3"}, nil),
	)
	c, lg := compileRequest(t, doc)
	hook := c.RequestHook(lg, "1.2.3.4:1")

	if v := hook(get("/", map[string]string{"x-count": "many"})); v != nil {
		t.Fatalf("a failing expression must not apply the rule, got %+v", v)
	}
	if warns := lg.lines(lg.warn); !strings.Contains(warns, "on_http_request[0] (deny)") ||
		!strings.Contains(warns, "the rule does not apply") {
		t.Fatalf("a runtime failure must be logged against the rule that failed, got:\n%q", warns)
	}

	// Once per connection per rule: the same failure on the next message must
	// not write another line. Two rules with the same action name are two
	// rules, which is why the warning is keyed on the rule's position.
	before := len(lg.warn)
	hook(get("/", map[string]string{"x-count": "many"}))
	if len(lg.warn) != before {
		t.Fatalf("the same failure was logged again: %v", lg.warn[before:])
	}
	if len(lg.warn) != 2 {
		t.Fatalf("want one warning per failing rule, got %d: %v", len(lg.warn), lg.warn)
	}
}

// TestUnknownNestedVariableIsRefusedAtLoad is the same mistake the test below
// used to demonstrate *failing open*, and it is the finding that changed: with
// the phase variables declared as maps, req.geo was an ordinary key lookup, so
// a policy that relies on a field this build does not provide (geo, endpoint,
// time) compiled and then never matched -- one warning per connection as its
// only trace. The dotted declarations make every one of those an undeclared
// reference at load time, so the operator sees it where they can fix it.
//
// Failing load is the *stronger* behavior for a rule: the alternative is a
// control the operator believes is running and that serves every request. What
// has to hold is that the error names the action, names the field, and lists
// what does exist -- otherwise the operator is left guessing which build has
// which variables, which is the complaint the hint exists to answer.
func TestUnknownNestedVariableIsRefusedAtLoad(t *testing.T) {
	doc := reqPolicy(rule("deny", []string{"req.geo.country == 'US'"}, nil))
	if _, err := doc.Compile(); err == nil {
		t.Fatal("a rule matching on a field this build does not provide compiled; it would serve every request")
	} else {
		for _, want := range []string{"on_http_request[0] (deny)", "does not compile", "req.geo.country", "req.headers (map(string, string))"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("the refusal does not cite %q, so the operator has to guess: %v", want, err)
			}
		}
	}
	if verr := doc.Validate(); verr == nil {
		t.Error("Compile refused the rule and Validate accepted it")
	} else if !strings.Contains(verr.Error(), "req.geo.country") {
		t.Errorf("Validate refused it for a different reason than Compile: %v", verr)
	}
}

// --- the response hook ------------------------------------------------------

func resp(status int, headers map[string]string) *http.Response {
	r := &http.Response{StatusCode: status, Header: http.Header{}, Proto: "HTTP/1.1"}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func TestResponseHook(t *testing.T) {
	doc := &TrafficPolicy{OnHTTPResponse: []*Action{
		rule("log", []string{"res.status_code >= 500"}, map[string]interface{}{
			"metadata": map[string]interface{}{"status": "${res.status_code}"},
		}),
		rule("remove-headers", []string{"res.status_code >= 500"}, map[string]interface{}{
			"headers": []interface{}{"Server", "X-Internal"},
		}),
		rule("add-headers", []string{"res.status_code >= 500"}, map[string]interface{}{
			"headers": map[string]interface{}{"x-degraded": "true"},
		}),
	}}
	c, err := doc.Compile()
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	lg := &testLogger{}
	hook := c.ResponseHook(lg, "1.2.3.4:1")
	if hook == nil {
		t.Fatalf("no response hook for a policy with response rules")
	}

	if v := hook(resp(200, nil)); v != nil {
		t.Fatalf("the rule did not match a 200, got %+v", v)
	}

	v := hook(resp(503, nil))
	if v == nil {
		t.Fatalf("the rule matched a 503 and produced nothing")
	}
	if strings.Join(v.Remove, ",") != "server,x-internal" {
		t.Fatalf("removes = %v", v.Remove)
	}
	if strings.Join(v.Add, "|") != "x-degraded: true" {
		t.Fatalf("adds = %v", v.Add)
	}
	if line := lg.lines(lg.info); !strings.Contains(line, `status="503"`) {
		t.Fatalf("res.status_code interpolation: %q", line)
	}
}

func TestResponseHookDoesNotSeeRequestVariables(t *testing.T) {
	// This is a compile error, and the point of the test is that it is: the
	// response hook has no request, so a document that reads one is refused at
	// load instead of evaluating against a zero value.
	doc := &TrafficPolicy{OnHTTPResponse: []*Action{rule("log", []string{"req.method == 'GET'"}, map[string]interface{}{
		"metadata": map[string]interface{}{"m": "x"},
	})}}
	if err := doc.Validate(); err == nil || !strings.Contains(err.Error(), "undeclared reference to 'req'") {
		t.Fatalf("want a compile error about req.*, got %v", err)
	}
}

// --- EvaluateConnect --------------------------------------------------------

func connectPolicy(t *testing.T, config map[string]interface{}) (*Compiled, *testLogger) {
	t.Helper()
	doc := &TrafficPolicy{OnTCPConnect: []*Action{rule("restrict-ips", nil, config)}}
	c, err := doc.Compile()
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	return c, &testLogger{}
}

func TestEvaluateConnectCIDRMatrix(t *testing.T) {
	allowDeny := map[string]interface{}{
		"enforce": true,
		"allow":   []interface{}{"203.0.113.0/24", "2001:db8::/32"},
		"deny":    []interface{}{"203.0.113.7/32", "10.0.0.0/8"},
	}
	allowOnly := map[string]interface{}{
		"allow": []interface{}{"203.0.113.0/24", "2001:db8::/32"},
	}
	denyOnly := map[string]interface{}{
		"deny": []interface{}{"10.0.0.0/8", "2001:db8::/32"},
	}
	hostForm := map[string]interface{}{
		"allow": []interface{}{"203.0.113.7"},
	}

	tests := []struct {
		name    string
		config  map[string]interface{}
		addr    string
		want    bool // want the connection refused
		wantWhy string
	}{
		{"allow list, address allowed", allowOnly, "203.0.113.5:1000", false, ""},
		{"allow list, address outside", allowOnly, "198.51.100.5:1000", true, "matches no allowed CIDR"},
		{"allow list, ipv6 address allowed", allowOnly, "[2001:db8::5]:1000", false, ""},
		{"allow list, ipv6 address outside", allowOnly, "[2001:db9::5]:1000", true, "matches no allowed CIDR"},
		{"deny list, address denied", denyOnly, "10.1.2.3:1000", true, "matches denied CIDR 10.0.0.0/8"},
		{"deny list, address allowed", denyOnly, "192.0.2.9:1000", false, ""},
		{"deny list, ipv6 address denied", denyOnly, "[2001:db8::1]:1000", true, "matches denied CIDR"},
		{"both lists, allowed", allowDeny, "203.0.113.5:1000", false, ""},
		{"both lists, denied by the deny list", allowDeny, "10.9.9.9:1000", true, "matches denied CIDR"},
		{"both lists, deny wins over allow", allowDeny, "203.0.113.7:1000", true, "matches denied CIDR 203.0.113.7/32"},
		{"both lists, outside both", allowDeny, "198.51.100.5:1000", true, "matches no allowed CIDR"},
		{"host form allow", hostForm, "203.0.113.7:1000", false, ""},
		{"host form allow, other host", hostForm, "203.0.113.8:1000", true, "matches no allowed CIDR"},
		{"address that is not an IP", allowOnly, "not-an-address:1000", true, "is not an IP address"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := connectPolicy(t, tt.config)
			v := c.EvaluateConnect(tt.addr)
			if v.Deny != tt.want {
				t.Fatalf("Deny = %v, want %v (reason %q)", v.Deny, tt.want, v.Reason)
			}
			if tt.want && !strings.Contains(v.Reason, tt.wantWhy) {
				t.Fatalf("reason = %q, want it to mention %q", v.Reason, tt.wantWhy)
			}
			if tt.want && (v.Response == nil || v.Response.StatusCode != 403) {
				t.Fatalf("a refused connection must carry the 403 an HTTP caller can send: %+v", v.Response)
			}
		})
	}
}

func TestEvaluateConnectEnforceFalse(t *testing.T) {
	doc := &TrafficPolicy{OnTCPConnect: []*Action{rule("restrict-ips", nil, map[string]interface{}{
		"enforce": false,
		"allow":   []interface{}{"203.0.113.0/24"},
	})}}
	c, err := doc.Compile()
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if v := c.EvaluateConnect("198.51.100.5:1000"); v.Deny {
		t.Fatalf("enforce: false must not refuse the connection, got %+v", v)
	}
}

func TestEvaluateConnectDenyAndConditions(t *testing.T) {
	doc := &TrafficPolicy{OnTCPConnect: []*Action{
		rule("deny", []string{"conn.client_ip == '203.0.113.9'"}, nil),
		rule("log", []string{"conn.client_ip == '203.0.113.9'"}, map[string]interface{}{
			"metadata": map[string]interface{}{"ip": "${conn.client_ip}"},
		}),
	}}
	c, err := doc.Compile()
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if v := c.EvaluateConnect("192.0.2.1:1000"); v.Deny {
		t.Fatalf("the condition did not match, the connection must proceed: %+v", v)
	}
	v := c.EvaluateConnect("203.0.113.9:1000")
	if !v.Deny {
		t.Fatalf("deny in on_tcp_connect must refuse the connection")
	}
	if v.Reason != "deny" {
		t.Fatalf("reason = %q, want %q", v.Reason, "deny")
	}
	if v.Response == nil || v.Response.StatusCode != 403 {
		t.Fatalf("deny must carry the default 403: %+v", v.Response)
	}
}

func TestConnectPhaseSeesNoHTTPVariables(t *testing.T) {
	doc := &TrafficPolicy{OnTCPConnect: []*Action{rule("deny", []string{"req.method == 'GET'"}, nil)}}
	if err := doc.Validate(); err == nil || !strings.Contains(err.Error(), "undeclared reference to 'req'") {
		t.Fatalf("want a compile error about req.* in on_tcp_connect, got %v", err)
	}
}

func TestConnectDenyFromConfigStatusIsIgnored(t *testing.T) {
	// deny in on_tcp_connect documents no config at all, so a status code
	// there is a mistake worth refusing rather than a value worth honoring.
	doc := &TrafficPolicy{OnTCPConnect: []*Action{rule("deny", nil, map[string]interface{}{"status_code": 404})}}
	if err := doc.Validate(); err == nil {
		t.Fatalf("want the config to be refused")
	}
}

// TestConnectDenyAnswersWithTheCompiledStatus is the Q-M12 regression test: the
// deny branch of EvaluateConnect used to answer with the package's hardcoded
// default (403) rather than the status the compiled action carries, which is
// where the config's status_code -- or the default, when it names none -- was
// resolved at load time. In the HTTP phases the two agree by construction
// (a.statusCode is what the hook answers with), so the connect phase was the
// one place the drift could live: a rule the operator configured, validated,
// and then never got.
//
// The loader cannot build the interesting shape today: connect-phase deny
// documents no config at all (the test above pins that), so a.statusCode is
// always defaultDenyStatus there. That is exactly why the second half of this
// test constructs the compiled form by hand rather than loading it. It is a
// drift guard, and it is the assertion that fails on the hardcoded-default
// implementation: the day the connect phase learns status_code, this test fails
// if the branch was not reading the field.
func TestConnectDenyAnswersWithTheCompiledStatus(t *testing.T) {
	// The reachable shape: no config, so the default is the answer.
	doc := &TrafficPolicy{OnTCPConnect: []*Action{rule("deny", nil, nil)}}
	c, err := doc.Compile()
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	v := c.EvaluateConnect("203.0.113.9:1000")
	if !v.Deny {
		t.Fatalf("deny in on_tcp_connect must refuse the connection: %+v", v)
	}
	if v.Response == nil || v.Response.StatusCode != defaultDenyStatus {
		t.Fatalf("want the default %d, got %+v", defaultDenyStatus, v.Response)
	}

	// The drift guard: a compiled connect-phase deny whose status is not the
	// default. Nothing but this test can produce one today.
	const want = http.StatusTeapot
	hand := &Compiled{connect: []*compiledAction{
		{action: ActionDeny, where: "on_tcp_connect[0] (deny)", statusCode: want},
	}}
	hv := hand.EvaluateConnect("203.0.113.9:1000")
	if !hv.Deny {
		t.Fatalf("the hand-built deny did not refuse the connection: %+v", hv)
	}
	if hv.Response == nil || hv.Response.StatusCode != want {
		t.Fatalf("EvaluateConnect answered %+v; the deny branch must answer with the compiled action's status (%d), not the package default (%d)",
			hv.Response, want, defaultDenyStatus)
	}
}

// TestActionCountIsCappedAtLoad is the FZ-M1 regression test. A policy is
// enforced on the data path -- every action is evaluated against every message
// of every connection on the endpoint -- and its size is chosen by whoever
// writes the document, so an unbounded action count is unbounded per-message
// work. maxActionsPerPolicy bounds it at load time; the number itself and the
// reasoning behind it are in validate.go.
//
// What the test pins is the shape of the bound rather than the number: the cap
// is inclusive, it sums the three phases, and the refusal names the total, the
// cap, and the per-phase breakdown, because an operator with a 1200-action
// document needs to know which section to cut.
func TestActionCountIsCappedAtLoad(t *testing.T) {
	// The cheapest legal action in each phase: one with no conditions and the
	// smallest config it will accept.
	conn := func(n int) []*Action {
		out := make([]*Action, 0, n)
		for i := 0; i < n; i++ {
			out = append(out, rule("log", nil, map[string]interface{}{"metadata": map[string]interface{}{"a": "1"}}))
		}
		return out
	}
	req := func(n int) []*Action {
		out := make([]*Action, 0, n)
		for i := 0; i < n; i++ {
			out = append(out, rule("deny", nil, nil))
		}
		return out
	}
	resp := func(n int) []*Action {
		out := make([]*Action, 0, n)
		for i := 0; i < n; i++ {
			out = append(out, rule("remove-headers", nil, map[string]interface{}{"headers": []interface{}{"x-a"}}))
		}
		return out
	}

	// Exactly at the cap, spread over all three phases: accepted, and it
	// compiles. A cap that refuses the last legal action is a cap that breaks
	// documents that worked.
	at := &TrafficPolicy{
		OnTCPConnect:   conn(1),
		OnHTTPRequest:  req(maxActionsPerPolicy - 2),
		OnHTTPResponse: resp(1),
	}
	if err := at.Validate(); err != nil {
		t.Fatalf("a policy at the cap (%d actions) was refused: %v", maxActionsPerPolicy, err)
	}
	if _, err := at.Compile(); err != nil {
		t.Fatalf("a policy at the cap validates and does not compile: %v", err)
	}

	// One over: refused, by both entry points, with an error that names the
	// total, the cap, and the phase that pushed it over.
	over := &TrafficPolicy{
		OnTCPConnect:   conn(1),
		OnHTTPRequest:  req(maxActionsPerPolicy - 1),
		OnHTTPResponse: resp(1),
	}
	werr := over.Validate()
	if werr == nil {
		t.Fatalf("a policy with %d actions validated (the cap is %d)", maxActionsPerPolicy+1, maxActionsPerPolicy)
	}
	for _, want := range []string{
		fmt.Sprintf("has %d actions", maxActionsPerPolicy+1),
		fmt.Sprintf("maximum is %d", maxActionsPerPolicy),
		fmt.Sprintf("on_tcp_connect %d", 1),
		fmt.Sprintf("on_http_request %d", maxActionsPerPolicy-1),
		fmt.Sprintf("on_http_response %d", 1),
	} {
		if !strings.Contains(werr.Error(), want) {
			t.Errorf("the refusal does not cite %q, so the operator cannot tell which phase to cut: %v", want, werr)
		}
	}
	if _, cerr := over.Compile(); cerr == nil {
		t.Fatal("Validate refused an over-cap policy and Compile accepted it")
	}

	// The cap counts the whole document, not each phase: three phases that are
	// each under the cap and together are not.
	spread := &TrafficPolicy{
		OnTCPConnect:   conn(maxActionsPerPolicy/3 + 1),
		OnHTTPRequest:  req(maxActionsPerPolicy/3 + 1),
		OnHTTPResponse: resp(maxActionsPerPolicy/3 + 1),
	}
	if n := len(spread.OnTCPConnect) + len(spread.OnHTTPRequest) + len(spread.OnHTTPResponse); n <= maxActionsPerPolicy {
		t.Fatalf("the test's own arithmetic is wrong: %d is not over the cap", n)
	}
	if err := spread.Validate(); err == nil {
		t.Fatalf("three phases of %d actions each validated; the cap must sum the phases", maxActionsPerPolicy/3+1)
	}
}

// TestHeaderValuesWithACRLFAreRefusedAtLoad is the CRLF-in-a-header-value
// finding, on the load path this time. A configured value carrying CR or LF is a
// header-injection payload aimed at whatever reads the request next, and the
// rewriter already refuses to write one (that is asserted from the rewriter's
// side, where the bytes are actually emitted). What was missing is the load-time
// half: the value was accepted, and then silently dropped at write time, so the
// operator's header was missing from production traffic with nothing anywhere
// saying why.
//
// The two halves of the check that make it safe to be strict are asserted here
// too: the *literal* bytes are what is refused (a YAML double-quoted scalar is
// the way a document actually carries them), and ${...} is untouched -- an
// author who means a line break can say it as interpolation, which is their own
// expression rather than their document's bytes.
func TestHeaderValuesWithACRLFAreRefusedAtLoad(t *testing.T) {
	// A YAML double-quoted scalar is how a CRLF reaches a policy document from a
	// file: the escapes are real bytes by the time validate.go sees them.
	cases := []struct {
		what string
		doc  string
	}{
		{
			what: "an injected second header (CRLF)",
			doc:  "on_http_request:\n  - name: add-headers\n    config:\n      headers:\n        X-A: \"ok\\r\\nX-Admin: true\"\n",
		},
		{
			what: "a bare LF",
			doc:  "on_http_request:\n  - name: add-headers\n    config:\n      headers:\n        X-A: \"ok\\nX-Admin: true\"\n",
		},
		{
			what: "a trailing CR",
			doc:  "on_http_request:\n  - name: add-headers\n    config:\n      headers:\n        X-A: \"ok\\r\"\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.what, func(t *testing.T) {
			tp, err := fzYAML(t, []byte(tc.doc))
			if err != nil {
				t.Fatalf("the document does not decode: %v", err)
			}
			verr := tp.Validate()
			if verr == nil {
				t.Fatal("a header value carrying CR or LF validated; it would be dropped at write time with no explanation")
			}
			for _, want := range []string{"on_http_request[0] (add-headers)", `config field "headers" entry "X-A"`, "CR or LF"} {
				if !strings.Contains(verr.Error(), want) {
					t.Errorf("the refusal does not cite %q, so the operator cannot find the value: %v", want, verr)
				}
			}
			if _, cerr := tp.Compile(); cerr == nil {
				t.Fatal("Validate refused the document and Compile accepted it")
			}
		})
	}

	// custom-response builds its headers with the same code and refuses them the
	// same way: this is one check on the header path, not one per action.
	cr := &TrafficPolicy{OnHTTPRequest: []*Action{rule("custom-response", nil, map[string]interface{}{
		"status_code": 200,
		"headers":     map[string]interface{}{"X-A": "ok\r\nX-Admin: true"},
	})}}
	if err := cr.Validate(); err == nil {
		t.Fatal("custom-response accepted a header value carrying CRLF")
	}

	// The escape hatch, asserted so the check does not read as a blanket ban on
	// newlines: an interpolated value is an expression, and the check is on the
	// document's literal bytes.
	iv := &TrafficPolicy{OnHTTPRequest: []*Action{rule("add-headers", nil, map[string]interface{}{
		"headers": map[string]interface{}{"X-A": "${req.headers['x-a']}"},
	})}}
	if err := iv.Validate(); err != nil {
		t.Fatalf("an interpolated header value was refused; the check must only see the document's literal bytes: %v", err)
	}
}
