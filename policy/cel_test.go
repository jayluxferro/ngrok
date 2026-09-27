package policy

// Tests for the CEL surface itself: the environment each phase compiles in, the
// ${...} interpolation, and the rendering of an evaluated value into text.
//
// The interesting assertions here are about *names and types*, because that is
// where this subset differs from ngrok's. Every documented field is declared by
// its own dotted name, so a name that does not exist -- a variable this build
// does not provide (endpoint.id), a field it does not provide (conn.geo), or a
// typo in one it does (req.headerss) -- is a compile error at load time rather
// than a rule that never matches. The types are the ones the docs promise
// (res.status_code is an integer, conn.client_ip is a string, req.headers is a
// map of strings), so an expression that cannot mean what it says is refused
// here too.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEnvIsPerPhase(t *testing.T) {
	tests := []struct {
		phase phase
		ok    []string // expressions that must compile in this phase
		bad   []string // expressions that must not
	}{
		{
			phaseConnect,
			[]string{"conn.client_ip == '1.2.3.4'", "conn.remote_addr != ''"},
			[]string{"req.method == 'GET'", "res.status_code == 200", "vars.a == 'b'"},
		},
		{
			phaseRequest,
			[]string{
				"req.method == 'GET'",
				"req.url.path == '/'",
				"req.url.query == 'a=1'",
				"req.url.raw == '/'",
				"req.headers['x-a'] == 'b'",
				"req.cookies['c'] == 'v'",
				"conn.client_ip == '1.2.3.4'",
				"vars.anything == 'x'",
			},
			[]string{"res.status_code == 200", "endpoint.id == 'x'"},
		},
		{
			phaseResponse,
			[]string{"res.status_code == 500", "conn.client_ip == '1.2.3.4'", "vars.a == 'b'"},
			[]string{"req.method == 'GET'", "req.headers['x-a'] == 'b'"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.phase.String(), func(t *testing.T) {
			for _, src := range tt.ok {
				if _, err := compileExpr(tt.phase, src, true); err != nil {
					t.Errorf("expression %q should compile in %s: %v", src, tt.phase, err)
				}
			}
			for _, src := range tt.bad {
				if _, err := compileExpr(tt.phase, src, true); err == nil {
					t.Errorf("expression %q should not compile in %s", src, tt.phase)
				}
			}
		})
	}
}

// TestUndeclaredNamesAreCompileErrors is the property the subset is declared
// for: a name this build does not provide must fail where the author can see
// it, not at evaluation time on a connection nobody is watching. The cases are
// the three shapes of the same mistake -- a variable that does not exist, a
// field of one that does, and a typo in a field that does -- in each of the
// phases that could plausibly be written.
func TestUndeclaredNamesAreCompileErrors(t *testing.T) {
	tests := []struct {
		phase phase
		src   string
	}{
		{phaseConnect, "conn.geo == 'US'"},
		{phaseConnect, "conn.client_IP == '1.2.3.4'"},
		{phaseConnect, "endpoint.id == 'x'"},
		{phaseRequest, "conn.geo == 'US'"},
		{phaseRequest, "req.headerss['x'] == 'y'"},
		{phaseRequest, "req.url.pat == '/'"},
		{phaseRequest, "req.url == '/'"},
		{phaseRequest, "conn == 'x'"},
		{phaseRequest, "request.method == 'GET'"},
		{phaseResponse, "res.status == 500"},
		{phaseResponse, "res.status_code_str == '500'"},
	}
	for _, tt := range tests {
		err := func() error {
			_, err := compileExpr(tt.phase, tt.src, true)
			return err
		}()
		if err == nil {
			t.Errorf("%s: %q names something this build does not provide, and it compiled", tt.phase, tt.src)
			continue
		}
		// The message has to say what does exist: the compiler names the object
		// it could not resolve ("undeclared reference to 'conn'"), which on its
		// own reads as if there were no conn at all.
		if !strings.Contains(err.Error(), "does not compile") {
			t.Errorf("%s: %q: the error does not say it is a compile error: %v", tt.phase, tt.src, err)
		}
		if !strings.Contains(err.Error(), tt.phase.String()+" has: ") {
			t.Errorf("%s: %q: the error does not list the phase's variables: %v", tt.phase, tt.src, err)
		}
	}

	// A whole-object reference is the one thing the dotted declarations give
	// up, and it is worth pinning: req.headers is declared as a map and stays
	// usable as one, while conn and req.url are not values at all.
	if _, err := compileExpr(phaseRequest, "size(req.headers) > 0", true); err != nil {
		t.Errorf("req.headers is declared as a whole map and must stay usable: %v", err)
	}
	if _, err := compileExpr(phaseRequest, "req.url.path.startsWith('/')", true); err != nil {
		t.Errorf("a field of req.url must be usable: %v", err)
	}
}

func TestCELTypesMatchTheDocs(t *testing.T) {
	// Where a type is declared it is enforced: res.status_code is an integer
	// (the docs say int32), so comparing it to a string is a type error and not
	// a rule that never matches. conn.client_ip is a string and vars is a map
	// of strings, so comparing either to the wrong shape is an error too. This
	// is the payoff of declaring the variable set rather than leaving
	// everything dyn.
	for _, src := range []string{
		"res.status_code == '500'",
		"res.status_code.size() > 0",
	} {
		if _, err := compileExpr(phaseResponse, src, true); err == nil {
			t.Errorf("%q should not compile: res.status_code is an integer", src)
		}
	}
	for _, src := range []string{"conn.client_ip > 1", "vars == 'x'", "req.headers == 'x'"} {
		if _, err := compileExpr(phaseRequest, src, true); err == nil {
			t.Errorf("%q should not compile: the types on both sides of the comparison do not exist", src)
		}
	}

	// The CEL standard library is available (macros included): policies in the
	// wild use matches/in and the string functions.
	for _, src := range []string{
		"req.method in ['GET', 'HEAD']",
		"req.url.path.matches('^/admin')",
		"req.headers['x-a'].contains('b')",
		"req.url.path.size() > 0",
		"has(req.headers.authorization)",
	} {
		if _, err := compileExpr(phaseRequest, src, true); err != nil {
			t.Errorf("standard library expression %q should compile: %v", src, err)
		}
	}
}

func TestCompileExprRejectsNonBoolOnlyWhenKnown(t *testing.T) {
	// A condition whose type the compiler knows and is not bool is refused at
	// load time. req.method is declared as a string, so a rule of
	// `expressions: ["req.method"]` is a mistake the author can be told about
	// now, with the action named, instead of one warning per connection forever.
	if _, err := compileExpr(phaseRequest, "req.method", true); err == nil {
		t.Fatalf("req.method is a string, which can never be a condition")
	}
	if _, err := compileExpr(phaseRequest, "'GET'", true); err == nil {
		t.Fatalf("a string literal can never be a condition")
	}
	// The dyn carve-out is the other half and stays: when the result's type is
	// genuinely unknown until it is read -- a mixed list indexed with a constant
	// is a shape the compiler will not pin down -- the expression loads and the
	// evaluation refuses it (evalBool requires a bool). Refusing it here would
	// mean refusing expressions that do resolve to bool at runtime.
	if _, err := compileExpr(phaseRequest, "[1, 'a'][0]", true); err != nil {
		t.Fatalf("a dyn result is deferred to evaluation time, not refused at load: %v", err)
	}
	// Interpolation has the opposite requirement: everything is renderable.
	for _, src := range []string{"'GET'", "req.method"} {
		if _, err := compileExpr(phaseRequest, src, false); err != nil {
			t.Fatalf("interpolation accepts any expression (%q): %v", src, err)
		}
	}
}

func TestInterpolation(t *testing.T) {
	act := requestTestActivation()

	tests := []struct {
		src  string
		want string
	}{
		{"plain text", "plain text"},
		{"", ""},
		{"${conn.client_ip}", "203.0.113.9"},
		{"a ${req.method} b", "a GET b"},
		{"${vars.greeting}, ${req.headers['x-name']}!", "hello, Jay!"},
		{"${vars.n}${vars.n}", "33"},
		{"${  req.method  }", "GET"}, // whitespace around the expression
		{"${'lit'}", "lit"},
		{"${vars.greeting} ${vars.greeting}", "hello hello"},
	}

	for _, tt := range tests {
		iv, err := compileInterpolation(phaseRequest, tt.src)
		if err != nil {
			t.Errorf("compile %q: %v", tt.src, err)
			continue
		}
		got := iv.eval(act, func(error) {})
		if got != tt.want {
			t.Errorf("interpolate %q = %q, want %q", tt.src, got, tt.want)
		}
	}
}

// requestTestActivation is a hand-built on_http_request activation in the flat
// dotted shape the environment declares (see connActivation in policy.go, which
// is the runtime's own version of this).
func requestTestActivation() map[string]interface{} {
	return map[string]interface{}{
		"conn.client_ip":   "203.0.113.9",
		"conn.remote_addr": "203.0.113.9:1",
		"req.method":       "GET",
		"req.url.path":     "/a",
		"req.url.query":    "",
		"req.url.raw":      "/a",
		"req.headers":      map[string]string{"x-name": "Jay"},
		"req.cookies":      map[string]string{},
		"vars":             map[string]string{"greeting": "hello", "n": "3"},
	}
}

func TestInterpolationErrorsAreRefusedAtCompileTime(t *testing.T) {
	for _, src := range []string{
		"${}",               // empty
		"${   }",            // whitespace only
		"${req.method",      // unterminated
		"${nope.nope}",      // does not compile
		"${req.headerss}",   // a name this build does not provide
		"ok ${1 + 'a'}",     // does not compile
		"${req.url.path.$}", // does not compile
	} {
		if _, err := compileInterpolation(phaseRequest, src); err == nil {
			t.Errorf("interpolation %q should not compile", src)
		}
	}
}

func TestInterpolationFailureRendersEmptyAndWarnsOnce(t *testing.T) {
	// A compile-time-clean expression that fails when it is read: the header
	// gets the empty string, the rest of the value survives, and the operator
	// gets one warning rather than a broken connection. A missing map key is
	// the remaining way an expression can fail at runtime -- every variable
	// that does not exist is a compile error now.
	iv, err := compileInterpolation(phaseRequest, "prefix-${req.headers['x-missing']}-suffix")
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	act := map[string]interface{}{
		"req.headers": map[string]string{},
		"vars":        map[string]string{},
	}
	warns := 0
	got := iv.eval(act, func(error) { warns++ })
	if got != "prefix--suffix" {
		t.Fatalf("a failed placeholder must render as empty text, got %q", got)
	}
	if warns != 1 {
		t.Fatalf("want one error reported, got %d", warns)
	}
}

func TestInterpolationFastPathIsALiteral(t *testing.T) {
	iv, err := compileInterpolation(phaseRequest, "no placeholders here")
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if hasInterpolation(iv.raw) {
		t.Fatalf("hasInterpolation should be false for a literal")
	}
	if len(iv.parts) != 1 || iv.parts[0].expr != nil {
		t.Fatalf("a literal is one part with no program, got %+v", iv.parts)
	}
	if iv.eval(nil, nil) != "no placeholders here" {
		t.Fatalf("a literal must render as itself")
	}
	// A nested brace stops the placeholder at the first '}', so ${'a}b'} is not
	// the expression 'a}b'. It does not silently misparse either: what is left
	// ("'a") is not a valid expression, so it is refused when the policy loads.
	// Braces inside a placeholder need a real parser, which ngrok has and this
	// subset documents not having.
	if _, err := compileInterpolation(phaseRequest, "${'a}b'}"); err == nil {
		t.Fatalf("a placeholder is split at the first closing brace; the fragment should not compile")
	}
}

// TestEveryDeclaredVariableResolvesFromTheActivation is the guard against the
// one way the dotted declarations and the runtime can drift apart: CEL resolves
// conn.client_ip out of the *activation map by that exact name*, so a variable
// declared here and not provided there is a rule that compiles at load time and
// fails on every message -- the silent no-op this package is built to avoid,
// reintroduced by a rename in one file and not the other.
//
// Every declared name is compiled as a bare expression and evaluated against
// the activation the phase actually builds, which is the strongest form the
// check can take: not "the key exists" but "a program that reads it runs".
func TestEveryDeclaredVariableResolvesFromTheActivation(t *testing.T) {
	req := httptest.NewRequest("GET", "/a?b=1", nil)
	req.Header.Set("X-A", "b")
	resp := &http.Response{StatusCode: 500}

	st := newEvalState(nil, "203.0.113.9:1234")
	acts := map[phase]map[string]interface{}{
		phaseConnect:  st.connectActivation(),
		phaseRequest:  st.requestActivation(req),
		phaseResponse: st.responseActivation(resp),
	}

	for ph, act := range acts {
		t.Run(ph.String(), func(t *testing.T) {
			declared := map[string]bool{}
			for _, v := range celSubset[ph] {
				declared[v.name] = true
				prg, err := compileExpr(ph, v.name, false)
				if err != nil {
					t.Fatalf("declared variable %q does not compile in its own phase: %v", v.name, err)
				}
				if _, err := prg.eval(act); err != nil {
					t.Errorf("declared variable %q is not resolvable from this phase's activation: %v", v.name, err)
				}
			}
			for name := range act {
				if !declared[name] {
					t.Errorf("the activation provides %q, which %s does not declare: a policy can never read it", name, ph)
				}
			}
		})
	}
}

func TestFormatValue(t *testing.T) {
	tests := []struct {
		in   interface{}
		want string
	}{
		{nil, ""},
		{"s", "s"},
		{true, "true"},
		{false, "false"},
		{int64(7), "7"},
		{uint64(7), "7"},
		{float64(1.5), "1.5"},
		{float64(2), "2"},
	}
	for _, tt := range tests {
		if got := formatValue(tt.in); got != tt.want {
			t.Errorf("formatValue(%#v) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestSortedKeysIsStable(t *testing.T) {
	m := map[string]interface{}{"b": 1, "a": 2, "c": 3}
	for i := 0; i < 5; i++ {
		if got := strings.Join(sortedKeys(m), ","); got != "a,b,c" {
			t.Fatalf("sortedKeys = %q, want a,b,c", got)
		}
	}
}
