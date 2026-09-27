package policy

// The CEL surface: the environment the policy's expressions are compiled in,
// and the interpolation of ${...} inside config strings.
//
// The variable set is deliberately the documented subset and nothing else. A
// policy that names a variable this build does not provide -- conn.geo.city,
// endpoint.id, conn.tls.client.pem -- fails at Validate time with a compile
// error naming the action, rather than silently never matching. That is the
// same choice the rest of the policy package makes: a control that does not run
// is far worse than a control that refuses to load.
//
// Everything is declared as a map, which is what makes the subset cheap to
// declare and cheap to fill: `conn.client_ip` is CEL's field selection on a
// map, so it costs one string key rather than a protobuf message. The cost is
// that a *misspelled* key compiles (any string key does) and errors at
// evaluation time; evaluation errors are treated as "this action does not
// apply" and logged once, which is the fail-open rule this package lives by.

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/google/cel-go/cel"
)

// celEnvs holds the three phase environments. They are built once per process
// (not per policy): compiling an environment walks a standard library, and
// nothing in these declarations depends on the policy being compiled.
var celEnvs = func() map[phase]*cel.Env {
	vars := cel.MapType(cel.StringType, cel.StringType)
	req := cel.MapType(cel.StringType, cel.DynType)
	res := cel.MapType(cel.StringType, cel.IntType)

	must := func(opts ...cel.EnvOption) *cel.Env {
		env, err := cel.NewEnv(opts...)
		if err != nil {
			// A fixed set of declarations: if one of them is invalid the
			// process cannot enforce any policy, and failing at startup beats
			// serving traffic that is silently unprotected.
			panic(fmt.Sprintf("policy: cel environment: %v", err))
		}
		return env
	}

	return map[phase]*cel.Env{
		// on_tcp_connect sees a connection, not a message: conn.* is all
		// there is to match on.
		phaseConnect: must(
			cel.Variable("conn", vars),
		),
		// on_http_request sees the request (and conn.*), and the vars that
		// earlier set-vars actions in the same phase defined.
		phaseRequest: must(
			cel.Variable("conn", vars),
			cel.Variable("req", req),
			cel.Variable("vars", vars),
		),
		// on_http_response sees the response and conn.*. req.* is not declared
		// here: the response hook is handed a head-only *http.Response and has
		// no request to read, so a policy that refers to req.* in this phase is
		// rejected at load time rather than evaluating against a zero value
		// that would quietly be wrong.
		phaseResponse: must(
			cel.Variable("conn", vars),
			cel.Variable("res", res),
			cel.Variable("vars", vars),
		),
	}
}()

// program is one compiled CEL expression, however it is used: a rule
// condition, or one ${...} placeholder inside a config string.
type program struct {
	src string
	prg cel.Program
}

// compileExpr compiles one expression for a phase. The result type is checked
// here rather than at evaluation time: an expression that cannot be a condition
// is a load-time error, and an expression that cannot be a string is not
// something ${...} can splice into a header value.
func compileExpr(env *cel.Env, src string, mustBeBool bool) (*program, error) {
	ast, iss := env.Compile(src)
	if err := iss.Err(); err != nil {
		return nil, fmt.Errorf("expression %q does not compile: %v", src, err)
	}
	if mustBeBool && ast.OutputType() != cel.BoolType && ast.OutputType() != cel.DynType {
		// A dyn result is allowed through: it is what a map lookup whose
		// contents only exist at runtime produces, and the evaluation below
		// still requires a bool. Anything else -- a string, an int, a list --
		// can never be a condition.
		return nil, fmt.Errorf("expression %q is not a condition: it evaluates to %s, not bool",
			src, ast.OutputType())
	}
	prg, err := env.Program(ast)
	if err != nil {
		return nil, fmt.Errorf("expression %q cannot be built into a program: %v", src, err)
	}
	return &program{src: src, prg: prg}, nil
}

// eval runs the program against an activation and returns its value, or an
// error. The caller decides what an error means; for everything in this package
// it means "the action does not apply".
func (p *program) eval(act map[string]interface{}) (interface{}, error) {
	val, _, err := p.prg.Eval(act)
	if err != nil {
		return nil, fmt.Errorf("expression %q failed: %v", p.src, err)
	}
	return val.Value(), nil
}

// evalBool runs a condition. A program whose result is not a bool -- which the
// compiler only lets through as dyn -- does not apply either.
func (p *program) evalBool(act map[string]interface{}) (bool, error) {
	v, err := p.eval(act)
	if err != nil {
		return false, err
	}
	b, ok := v.(bool)
	if !ok {
		return false, fmt.Errorf("expression %q evaluated to %T, not bool", p.src, v)
	}
	return b, nil
}

// interpolated is one config string that may contain ${...} placeholders. A
// string with no placeholder is a single literal part and costs one allocation
// at compile time and none at evaluation time.
type interpolated struct {
	raw   string
	parts []interpPart
}

// interpPart is either literal text or one compiled expression.
type interpPart struct {
	text string
	expr *program
}

// hasInterpolation reports whether s contains a placeholder at all, which is
// what keeps every config string without one out of the compile path.
func hasInterpolation(s string) bool {
	return strings.Contains(s, "${")
}

// compileInterpolation splits a config string at its ${...} placeholders and
// compiles each expression. This is ngrok's CEL interpolation, with one
// deliberate difference: this build always splices the *string* form of the
// result, so an interpolation of a list or a map is not supported (ngrok
// resolves a whole-string "${vars.x}" to the value's own type).
func compileInterpolation(env *cel.Env, s string) (*interpolated, error) {
	if !hasInterpolation(s) {
		return &interpolated{raw: s, parts: []interpPart{{text: s}}}, nil
	}

	out := &interpolated{raw: s}
	for len(s) > 0 {
		start := strings.Index(s, "${")
		if start < 0 {
			out.parts = append(out.parts, interpPart{text: s})
			break
		}
		if start > 0 {
			out.parts = append(out.parts, interpPart{text: s[:start]})
		}
		rest := s[start+2:]
		// The placeholder ends at the first closing brace. Nested maps and
		// strings containing '}' would need a real parse (which is what ngrok
		// has); this subset documents the simple form.
		end := strings.IndexByte(rest, '}')
		if end < 0 {
			return nil, fmt.Errorf("interpolation %q is missing its closing '}'", s)
		}
		expr := strings.TrimSpace(rest[:end])
		if expr == "" {
			return nil, fmt.Errorf("interpolation %q has an empty expression", s)
		}
		prg, err := compileExpr(env, expr, false)
		if err != nil {
			return nil, err
		}
		out.parts = append(out.parts, interpPart{expr: prg})
		s = rest[end+1:]
	}
	return out, nil
}

// eval renders the string: literal parts are copied, expressions are evaluated
// and their result spliced in as text. An expression that fails -- an unknown
// variable name, a missing map key, a type error that only exists at runtime --
// contributes the empty string, and the caller records the failure once. The
// alternative, failing the request, is exactly what fail-open forbids.
func (ip *interpolated) eval(act map[string]interface{}, onErr func(error)) string {
	if len(ip.parts) == 1 && ip.parts[0].expr == nil {
		return ip.parts[0].text
	}
	var b strings.Builder
	for _, part := range ip.parts {
		if part.expr == nil {
			b.WriteString(part.text)
			continue
		}
		v, err := part.expr.eval(act)
		if err != nil {
			if onErr != nil {
				onErr(err)
			}
			continue
		}
		b.WriteString(formatValue(v))
	}
	return b.String()
}

// formatValue renders an evaluated CEL value the way a policy author expects to
// see it in a header or a body. Strings are used as they are; the numeric and
// boolean types are rendered in their literal forms. A composite value is
// rendered by fmt, which is a guess -- but interpolation of a list or map into
// a header value has no correct answer to give.
func formatValue(v interface{}) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case bool:
		return strconv.FormatBool(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case uint64:
		return strconv.FormatUint(t, 10)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	default:
		return fmt.Sprint(v)
	}
}
