package policy

// Tests for the CEL surface itself: the environment each phase compiles in, the
// ${...} interpolation, and the rendering of an evaluated value into text.
//
// The interesting assertions here are about *typing*, because that is where
// this subset differs from ngrok's: the variables are declared as maps, so a
// misspelled nested name is dyn and compiles, and the value types a policy
// author writes against (res.status_code is an integer, conn.client_ip is a
// string) are the ones the docs promise.

import (
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
			env := celEnvs[tt.phase]
			for _, src := range tt.ok {
				if _, err := compileExpr(env, src, true); err != nil {
					t.Errorf("expression %q should compile in %s: %v", src, tt.phase, err)
				}
			}
			for _, src := range tt.bad {
				if _, err := compileExpr(env, src, true); err == nil {
					t.Errorf("expression %q should not compile in %s", src, tt.phase)
				}
			}
		})
	}
}

func TestCELTypesMatchTheDocs(t *testing.T) {
	env := celEnvs[phaseRequest]

	// Where a type is declared it is enforced: res.status_code is an integer
	// (the docs say int32), so comparing it to a string is a type error and not
	// a rule that never matches. conn and vars are map[string]string, so
	// comparing them to a scalar is an error too. This is the payoff of
	// declaring the variable set rather than leaving everything dyn.
	for _, src := range []string{
		"res.status_code == '500'",
		"res.status_code.size() > 0",
	} {
		if _, err := compileExpr(celEnvs[phaseResponse], src, true); err == nil {
			t.Errorf("%q should not compile: res.status_code is an integer", src)
		}
	}
	for _, src := range []string{"conn == 'x'", "conn.client_ip > 1", "vars == 'x'"} {
		if _, err := compileExpr(env, src, true); err == nil {
			t.Errorf("%q should not compile: conn and vars are maps of strings", src)
		}
	}
	// req is declared as map[string]dyn, so a field of it is dyn: this is the
	// documented cost of the cheap declaration (see the package comment in
	// cel.go). It compiles, and fails when it is read.
	if _, err := compileExpr(env, "req.headers == 'x'", true); err != nil {
		t.Fatalf("req.* is dyn by construction; this should compile: %v", err)
	}

	// The CEL standard library is available (macros included): policies in the
	// wild use matches/in and the string functions.
	for _, src := range []string{
		"req.method in ['GET', 'HEAD']",
		"req.url.path.matches('^/admin')",
		"req.headers['x-a'].contains('b')",
		"req.url.path.size() > 0",
	} {
		if _, err := compileExpr(env, src, true); err != nil {
			t.Errorf("standard library expression %q should compile: %v", src, err)
		}
	}
}

func TestCompileExprRejectsNonBoolOnlyWhenKnown(t *testing.T) {
	env := celEnvs[phaseRequest]
	if _, err := compileExpr(env, "req.method", true); err != nil {
		t.Fatalf("a dyn value is allowed as a condition (it is checked when read): %v", err)
	}
	if _, err := compileExpr(env, "'GET'", true); err == nil {
		t.Fatalf("a string literal can never be a condition")
	}
	// Interpolation has the opposite requirement: everything is renderable.
	if _, err := compileExpr(env, "'GET'", false); err != nil {
		t.Fatalf("interpolation accepts any expression: %v", err)
	}
}

func TestInterpolation(t *testing.T) {
	env := celEnvs[phaseRequest]
	act := map[string]interface{}{
		"conn": map[string]string{"client_ip": "203.0.113.9", "remote_addr": "203.0.113.9:1"},
		"req": map[string]interface{}{
			"method": "GET",
			"url":    map[string]string{"path": "/a", "query": "", "raw": "/a"},
			"headers": map[string]string{
				"x-name": "Jay",
			},
			"cookies": map[string]string{},
		},
		"vars": map[string]string{"greeting": "hello", "n": "3"},
	}

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
		iv, err := compileInterpolation(env, tt.src)
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

func TestInterpolationErrorsAreRefusedAtCompileTime(t *testing.T) {
	env := celEnvs[phaseRequest]
	for _, src := range []string{
		"${}",               // empty
		"${   }",            // whitespace only
		"${req.method",      // unterminated
		"${nope.nope}",      // does not compile
		"ok ${1 + 'a'}",     // does not compile
		"${req.url.path.$}", // does not compile
	} {
		if _, err := compileInterpolation(env, src); err == nil {
			t.Errorf("interpolation %q should not compile", src)
		}
	}
}

func TestInterpolationFailureRendersEmptyAndWarnsOnce(t *testing.T) {
	// A compile-time-clean expression that fails when it is read: the header
	// gets the empty string, the rest of the value survives, and the operator
	// gets one warning rather than a broken connection.
	env := celEnvs[phaseRequest]
	iv, err := compileInterpolation(env, "prefix-${req.headers['x-missing']}-suffix")
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	act := map[string]interface{}{
		"req":  map[string]interface{}{"headers": map[string]string{}},
		"vars": map[string]string{},
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
	env := celEnvs[phaseRequest]
	iv, err := compileInterpolation(env, "no placeholders here")
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
	if _, err := compileInterpolation(env, "${'a}b'}"); err == nil {
		t.Fatalf("a placeholder is split at the first closing brace; the fragment should not compile")
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
