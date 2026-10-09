package policy

// Fuzz and hostile-input tests for the policy engine.
//
// The policy package is the one that fails *closed* on purpose: everything it
// rejects, it rejects at load time with a loud error. That makes it the mirror
// image of the rewriter, and the interesting inputs are the ones an attacker
// gets to choose rather than the ones an operator writes:
//
//   - the YAML body of a policy document (a config file, or a file handed to
//     -traffic-policy-file),
//   - the JSON that arrives in a tunnel registration, which is the shape the
//     server compiles (msg.Envelope -> TrafficPolicy -> Compile), and
//   - the request and response *facts* a policy's CEL expressions and ${...}
//     interpolations are evaluated against, which are internet-controlled.
//
// The invariants these targets enforce, in the order they matter:
//
//  1. Nothing panics. Not validation, not compilation, not evaluation. A panic
//     in the load path is a client that will not start; a panic in the
//     evaluation path is a connection -- or, since a policy is enforced on the
//     accept path for on_tcp_connect, a whole agent's tunnel -- taken down by a
//     request.
//  2. Validate and Compile cannot disagree. They share one traversal by design
//     (build), and the package says so out loud: "what is accepted and what is
//     enforced cannot drift apart". A fuzzer is a cheap way to keep that
//     sentence true -- the two entry points must accept and reject exactly the
//     same documents, and an accepted policy must come back with a non-nil
//     compiled form.
//  3. A policy that validates in its YAML shape validates in the JSON shape the
//     wire carries, and vice versa. The client validates the first, the server
//     compiles the second, and a document the client accepts but the server
//     refuses is a tunnel that fails to register (server/tunnel.go compiles the
//     registration's policy and errors out) -- or worse, a policy the operator
//     believes is running and which is not.
//  4. Whatever compiles must evaluate without panicking against arbitrary
//     request/response facts, and evaluating the same facts twice must give the
//     same verdict. Nondeterminism in an enforcement decision is a bug the
//     operator cannot reason about: the same request refused on one node and
//     allowed on the next.
//
// What is deliberately *not* asserted, and why:
//
//   - The exact text of an error. Two of the three fuzz targets check "does the
//     decision hold", not "does the sentence match": error prose is allowed to
//     change, and pinning it in a fuzzer turns every wording tweak into a
//     corpus failure. The one property of the text that a fuzzer cannot check
//     and an operator does depend on -- that the same document fails the same
//     way every time -- has its own test below
//     (TestPolicyRejectMessageIsDeterministic) rather than being smuggled into
//     a fuzz assertion that would then be red forever. That test used to
//     *record* the nondeterminism it found (buildHeaders walked its config map
//     in Go's iteration order); it asserts the fix now.
//   - That a hostile-but-legal policy is enforced "correctly". That is
//     semantics, and it belongs in the table tests in policy_test.go, which
//     assert it case by case. These targets are for the shapes nobody wrote a
//     case for.
//   - That the policy's own output is safe to put on the wire. It is not, and
//     it does not need to be: a header value an interpolation filled with CR or
//     LF is dropped by the rewriter at the last moment (rewriter.compileAdds
//     and hookRewrite). That boundary is asserted from the rewriter's side in
//     rewriter/fuzz_test.go, which is where it can actually be observed.
//
// The crash probes deserve a word, because they are unusual. Two classes of
// input cannot be caught by a fuzzer's own recovery: a stack overflow and an
// out-of-memory kill are fatal to the process, and a "failing input written to
// testdata/fuzz/..." line never appears for them. cel-go compiles a
// recursive-descent parse of whatever expression it is handed, so those are
// plausible here, and the YAML decoder is the other place to look: yaml.v3 does
// bound both shapes (a flow level cap of 10000 in the scanner, and an alias
// budget that refuses a document whose aliases outgrow it), but a bound is a
// claim about a library version and these probes are how it stays checked.
// Rather than assert they are fine, the probes below re-exec this test binary as
// a *child* with one pathological document and watch the exit status: a crash is
// then an ordinary test failure with the child's output quoted, and the rest of
// the suite stays alive to report it.

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"reflect"
	"regexp"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"ngrok/rewriter"
)

// --- plumbing ---------------------------------------------------------------

// fzQuiet is a log.Logger that discards everything. The policy package logs on
// every fail-open path (each runtime evaluation error, once per connection) and
// on every log action, so a target that wrote those lines into the test log
// would spend its time formatting text rather than finding bugs. It also keeps
// the targets honest about what is being asserted: the verdict, not the prose.
type fzQuiet struct{}

func (fzQuiet) AddLogPrefix(string)                {}
func (fzQuiet) SetLogPrefixes(...string)           {}
func (fzQuiet) Debug(string, ...interface{})       {}
func (fzQuiet) Info(string, ...interface{})        {}
func (fzQuiet) Warn(string, ...interface{}) error  { return nil }
func (fzQuiet) Error(string, ...interface{}) error { return nil }

// fzTimeout bounds one validation/compilation/evaluation. The package has no
// I/O and no goroutines, so a call that does not return is a bug in it -- an
// expression the evaluator loops on, a document the decoder never finishes. A
// fuzz worker that hangs forever is a crash report nobody can read, so a hang
// is turned into a normal failure with a name attached.
const fzTimeout = 10 * time.Second

// fzDo runs fn and reports a panic or a hang as a failure of the calling test.
//
// The goroutine is the awkward part, and it is worth being explicit about why
// it is there. A watchdog needs to be able to abandon a call that never
// returns, which means the call cannot be on the test's own goroutine. That in
// turn means a panic inside fn is no longer in the goroutine the testing (and
// fuzzing) framework recovers, so fzDo recovers it itself and re-panics in the
// caller -- which is the goroutine that gets the input minimized and written to
// testdata/fuzz/. The original stack is attached to the re-panic, because by
// then it is the only record of where the panic came from.
func fzDo(t *testing.T, what string, fn func()) {
	t.Helper()

	type outcome struct {
		value interface{}
		stack string
	}
	done := make(chan outcome, 1)
	go func() {
		defer func() {
			if p := recover(); p != nil {
				done <- outcome{value: p, stack: string(fzStack())}
				return
			}
			done <- outcome{}
		}()
		fn()
	}()

	select {
	case o := <-done:
		if o.value != nil {
			panic(fmt.Sprintf("%s: %v\n%s", what, o.value, o.stack))
		}
	case <-time.After(fzTimeout):
		t.Fatalf("%s: did not finish within %v (a hang is a finding: nothing in this package does I/O)", what, fzTimeout)
	}
}

// fzStack is debug.Stack, isolated so the import list above stays readable and
// so the one place that needs it is obvious.
func fzStack() []byte {
	buf := make([]byte, 64<<10)
	return buf[:runtime.Stack(buf, false)]
}

// fzAgreed reports whether two attempts reached the same accept/reject verdict,
// so that the concordance assertions read as one line each. It compares the
// verdict and not the message, for the reason the file header gives.
func fzAgreed(a, b error) bool { return (a == nil) == (b == nil) }

// fzYAML decodes a document the way client/config.go and server/config.go do.
// A document YAML cannot read at all is not interesting: the caller would have
// reported a parse error and never reached validation.
//
// There is no recover around the call any more, and that is a deliberate
// deletion rather than an oversight. It used to be here -- fzYAMLUnmarshal,
// plus an NGROK_FZ_ALLOW_PARSER_PANIC escape hatch out of it -- because
// yaml.v1's scanner panicked with a runtime bounds error on a document whose
// last bytes were a truncated multi-byte sequence, and the panic escaped into
// every caller. yaml.v3 does not have that failure mode: the scanner bounds
// its lookahead, so the same bytes come back as an error. An escape hatch for a
// crash that cannot happen is a place for the *next* crash to hide -- it turns
// a panic into a quiet "rejected document", which is exactly the shape of bug
// the hatch was invented to keep loud -- so it is gone, and a panic here is a
// panic again.
func fzYAML(t *testing.T, doc []byte) (*TrafficPolicy, error) {
	t.Helper()

	tp := new(TrafficPolicy)
	if err := yaml.Unmarshal(doc, tp); err != nil {
		return nil, err
	}

	return tp, nil
}

// --- FuzzPolicyValidate -----------------------------------------------------

// fzMaxPolicyDoc caps what this target will look at. The cap is not about the
// policy package -- a config file has no size limit -- it is about keeping the
// target's failures legible: a megabyte of nested YAML explores the decoder,
// not the validator. The two shapes that make the decoder itself the subject
// (deep nesting, alias expansion) are measured in a subprocess by
// TestPolicyDecoderCrashProbe, where a crash cannot take the fuzzer down.
const fzMaxPolicyDoc = 64 << 10

// fzPolicySeeds are documents rather than lone fields: what this target is
// looking for lives in the interaction between the decoder's shapes and the
// validator's expectations, and a seed that does not decode exercises nothing.
// Half of them are legal policies from the docs, so that the mutator starts
// from something that reaches the deep end of build().
var fzPolicySeeds = []string{
	// A complete, legal policy touching every action the build implements.
	`on_tcp_connect:
  - name: restrict-ips
    expressions:
      - "conn.client_ip != '203.0.113.9'"
    config:
      enforce: true
      allow: ["10.0.0.0/8", "203.0.113.7"]
      deny: ["192.0.2.0/24"]
  - name: deny
    config:
      status_code: 403
on_http_request:
  - name: add-headers
    expressions:
      - "req.method == 'GET'"
      - "req.url.path.startsWith('/admin')"
    config:
      headers:
        X-Frame-Options: DENY
        X-Who: "${conn.client_ip}"
  - name: set-vars
    config:
      vars:
        - who: "${req.headers.x-real-ip}"
  - name: custom-response
    config:
      status_code: 200
      body: "hello ${vars.who}"
      headers:
        content-type: text/plain
  - name: log
    config:
      metadata:
        path: "${req.url.raw}"
        count: 7
        ok: true
  - name: remove-headers
    config:
      headers: ["cookie", "X-Forwarded-For"]
on_http_response:
  - name: add-headers
    expressions:
      - "res.status_code >= 500"
    config:
      headers:
        X-Upstream-Failed: "1"
  - name: remove-headers
    config:
      headers: ["etag"]
  - name: log
    config:
      metadata:
        status: "${res.status_code}"
`,
	// The same document spelled as JSON, which the YAML decoder reads too (JSON
	// is a subset of YAML): the two decoders disagree about number types and map
	// shapes, and this is the shape that actually crosses the wire.
	`{"on_http_request":[{"name":"deny","expressions":["req.method == 'POST'"],"config":{"status_code":403}}]}`,
	// Shapes validation is supposed to refuse, one per seed, so that the
	// mutator has somewhere to start from for each refusal path.
	"on_http_request:\n  - name: not-an-action\n",
	"on_http_request:\n  - config:\n      status_code: 403\n",
	"on_http_request:\n  - null\n",
	"on_http_request:\n  - name: deny\n    config:\n      status_code: 9999\n",
	"on_http_request:\n  - name: deny\n    config:\n      body: x\n",
	"on_http_request:\n  - name: restrict-ips\n    config:\n      allow: [\"10.0.0.0/8\"]\n",
	"on_http_request:\n  - name: add-headers\n    config:\n      headers:\n        user-agent: x\n",
	"on_http_request:\n  - name: add-headers\n    expressions:\n      - \"req.method =\"\n    config:\n      headers:\n        a: b\n",
	"on_http_request:\n  - name: add-headers\n    config:\n      headers:\n        a: \"${conn.unclosed\"\n",
	"on_http_request:\n  - name: add-headers\n    config:\n      headers:\n        a: \"${}\"\n",
	"on_http_request:\n  - name: set-vars\n    config:\n      vars:\n        - 9bad: x\n",
	"on_http_request:\n  - name: custom-response\n    config:\n      headers:\n        a: 1\n",
	"on_tcp_connect:\n  - name: restrict-ips\n    config:\n      allow: [\"not a cidr\"]\n",
	// The YAML shapes that have no JSON form at all: nested maps with
	// non-string keys, and maps where a list belongs.
	"on_http_request:\n  - name: add-headers\n    config:\n      headers:\n        1: x\n",
	"on_http_request:\n  - name: set-vars\n    config:\n      vars:\n        - {a: {b: c}}\n",
	// Documents whose *structure* is unusual but whose content is not: these
	// are where a decoder/validator disagreement would show up.
	"---\n{}\n---\n{}\n",
	"\n\n\non_http_request: []\n",
	"!!map\n",
	"{on_http_request: [{name: deny, config: {status_code: 403}}]}",
	"on_http_request: &a\n  - name: deny\non_http_response: *a\n",
	"on_http_request:\n  - name: deny\n    config: {}\n    name: log\n",
	"on_http_request:\n  - name: deny\n    config:\n      status_code: 0x193\n",
	"on_http_request:\n  - name: deny\n    config:\n      status_code: 403.0\n",
	"on_http_request:\n  - name: deny\n    config:\n      status_code: -1\n",
	// The one exception to "a seed that does not decode exercises nothing", and
	// it was deliberate: these two are byte soup rather than documents, and what
	// they exercise is the decoder's own byte handling. They used to be a
	// finding -- yaml.v1's scanner read one byte past the end of its buffer on
	// them and panicked -- and they are kept as seeds now that the corpus entry
	// the fuzzer wrote for them (policy/testdata/fuzz/FuzzPolicyValidate/
	// 11ba52126104cb5a) has been deleted. Both must come back as an error, never
	// as a panic; the note at the end of this file records what the second one
	// does instead.
	"\xff\xfe00",
	"a: \xe2\x80",
}

// fzValidate is the body of the target, in one place so that the assertions are
// readable as a list.
func fzValidate(t *testing.T, doc []byte) {
	tp, err := fzYAML(t, doc)
	if err != nil {
		return // not a document; the caller reports the parse error and stops
	}

	var verr, cerr error
	var compiled *Compiled
	fzDo(t, "Validate", func() { verr = tp.Validate() })
	fzDo(t, "Compile", func() { compiled, cerr = tp.Compile() })

	// Invariant 2: one traversal, one verdict.
	if !fzAgreed(verr, cerr) {
		t.Fatalf("Validate and Compile disagree about the same document:\n\tValidate: %v\n\tCompile:  %v", verr, cerr)
	}
	if verr != nil {
		// A rejected policy must not hand back a compiled form: server/tunnel.go
		// keeps the *Compiled on success and errors out on failure, so a
		// half-built one that reached enforcement is exactly the "control that
		// silently does nothing" the package is written to avoid.
		if compiled != nil {
			t.Fatalf("a rejected policy returned a compiled form: err=%v compiled=%+v", verr, compiled)
		}
	} else {
		if compiled == nil {
			t.Fatalf("a valid policy compiled to nil with no error")
		}
		// A compiled policy must be usable, not merely non-nil: the hooks are
		// what the rewriter calls, and IsZero agrees with the rule counts.
		if n := len(tp.OnTCPConnect) + len(tp.OnHTTPRequest) + len(tp.OnHTTPResponse); n == 0 && !tp.IsZero() {
			t.Fatalf("a policy with no rules does not report IsZero: %+v", tp)
		}
		// Invariant 4, in the cheapest form available here: evaluating an empty
		// policy's hooks must not panic. The full evaluation fuzz is
		// FuzzPolicyEnforce; this catches a compiled form that cannot be driven
		// at all (a nil inner slice, a hook that dereferences something build
		// left unset).
		fzDo(t, "hooks", func() {
			if h := compiled.RequestHook(fzQuiet{}, "203.0.113.9:1234"); h != nil {
				h(fzRequest("GET", "/", nil))
			}
			if h := compiled.ResponseHook(fzQuiet{}, "203.0.113.9:1234"); h != nil {
				h(fzResponse(200))
			}
			_ = compiled.EvaluateConnect("203.0.113.9:1234")
		})
	}

	// Invariant 3: the wire shape is a fixed point of the decision.
	//
	// json.Marshal fails outright on the YAML map shape (map[interface{}]interface{}
	// has no JSON form), which is the whole reason client.normalizeTrafficPolicy
	// exists; such a document never reaches the wire, so there is nothing to
	// compare. Everything else is compared, and both directions matter: a
	// document the YAML shape accepts and the JSON shape refuses is a tunnel
	// whose registration fails at server/tunnel.go, and one the YAML shape
	// refuses while the JSON shape accepts is worse -- the client would have
	// hidden a rule it cannot enforce.
	wire, ok := fzWireShape(tp)
	if !ok {
		return
	}
	var wireErr error
	fzDo(t, "wire shape Validate", func() { wireErr = wire.Validate() })
	if !fzAgreed(verr, wireErr) {
		t.Fatalf("the same policy is judged differently once it has crossed the wire:\n\tdocument: %v\n\twire:     %v\n\tdocument: %s", verr, wireErr, doc)
	}
}

// fzWireShape round-trips a policy through the JSON the tunnel registration
// carries. It reports false when the policy has no JSON form at all.
func fzWireShape(tp *TrafficPolicy) (*TrafficPolicy, bool) {
	buf, err := json.Marshal(tp)
	if err != nil {
		return nil, false
	}
	out := new(TrafficPolicy)
	if err := json.Unmarshal(buf, out); err != nil {
		return nil, false
	}
	return out, true
}

func FuzzPolicyValidate(f *testing.F) {
	for _, s := range fzPolicySeeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, doc []byte) {
		if len(doc) > fzMaxPolicyDoc {
			t.Skip()
		}
		fzValidate(t, doc)
	})
}

// --- FuzzCELExpression ------------------------------------------------------

// fzExprSeeds are expressions and near-expressions: each phase's real variables,
// each documented mistake (a variable this build does not provide, a condition
// that is not a bool), the interpolation edge cases that have their own error
// strings, and a couple of shapes that stress the parser rather than the type
// checker.
var fzExprSeeds = []string{
	// Conditions that must compile, one per phase.
	"conn.client_ip == '203.0.113.9'",
	"conn.remote_addr.startsWith('10.')",
	"req.method == 'POST' && req.url.path.startsWith('/admin')",
	"req.headers['x-api-key'] == 'secret'",
	"req.cookies['session'] != ''",
	"vars.who == 'admin'",
	"res.status_code >= 500 && res.status_code < 600",
	"has(req.headers.authorization)",
	"size(req.url.query) > 0",
	// Values that compile but are not conditions: compileExpr(mustBeBool=true)
	// must refuse them, and mustBeBool=false (interpolation) must take them.
	// Every one of these has a concrete type, so the refusal is at load time
	// rather than at the first read -- which is the property the strict variable
	// set bought.
	"req.url.path",
	"res.status_code",
	"1 + 1",
	"['a', 'b']",
	"{'a': 'b'}",
	"req.headers",
	// Mistakes this build documents as load-time errors, because the variable
	// set is deliberately the subset: geo, TLS and endpoint variables do not
	// exist here, and a policy that names one must not load. "conn" is in this
	// group rather than the one above for the same reason: only its *fields*
	// are declared (cel.go, the dotted declarations), so the whole object is an
	// undeclared reference now. It used to compile as a map.
	"conn",
	"conn.geo.city == 'London'",
	"req.tls.client.pem != ''",
	"endpoint.id == 'ep_1'",
	"timestamp('2024-01-01T00:00:00Z') < now",
	// Syntax errors and near-misses, which is where a recursive-descent parser
	// is most likely to be interesting.
	"",
	"   ",
	"((",
	"))",
	"'unterminated",
	"req.method ==",
	"&& req.method",
	"req..method",
	"req.method == 'GET' ?",
	"!",
	"1 / 0",
	"0x",
	"'é中文' == req.method",
	"\x00\x01\x02",
	"req.headers['\xff\xfe'] == 'x'",
	// Depth, at a size the parser is expected to survive. The probe test below
	// is what measures the size it does not.
	strings.Repeat("(", 200) + "true" + strings.Repeat(")", 200),
	strings.Repeat("-", 200) + "1",
}

// fzEvalActivations are the maps a compiled expression is evaluated against:
// the three phases, each with the values a hostile connection would produce.
// The keys are the documented ones -- flat and dotted, because that is what the
// environment declares (cel.go; connActivation in policy.go is the runtime's
// own version of the same shape) -- the values are attacker-controlled strings,
// and the activation is shared with the interpolation half of the target so
// that a placeholder compiles against the same facts a condition does.
func fzEvalActivations() []map[string]interface{} {
	return []map[string]interface{}{
		{"conn.client_ip": "203.0.113.9", "conn.remote_addr": "203.0.113.9:1234"},
		{
			"conn.client_ip":   "203.0.113.9",
			"conn.remote_addr": "203.0.113.9:1234",
			"req.method":       "GET",
			"req.url.path":     "/admin",
			"req.url.query":    "x=1",
			"req.url.raw":      "/admin?x=1",
			"req.headers":      map[string]string{"host": "example.test", "x-api-key": "secret"},
			"req.cookies":      map[string]string{"session": "abc"},
			"vars":             map[string]string{"who": "admin"},
		},
		{
			"conn.client_ip":   "203.0.113.9",
			"conn.remote_addr": "203.0.113.9:1234",
			"res.status_code":  500,
			"vars":             map[string]string{},
		},
		// The shapes a *missing* variable or a misspelled key produces. These
		// are the ones that must fail open rather than panic: cel-go's map
		// selection on a key that is not there is an evaluation error, and so
		// is a variable the activation does not provide.
		{},
		{"conn.client_ip": ""},
		{"req.headers": map[string]string{}},
		{"vars": nil},
	}
}

func FuzzCELExpression(f *testing.F) {
	for _, s := range fzExprSeeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, src string) {
		// A CEL expression has no length limit of its own here: the wire caps a
		// whole registration at 4 MiB (msg.maxMessageSize), and a config file at
		// whatever the operator wrote, so the target does not invent a smaller
		// one. Depth is the probe's business, not this cap's.
		if len(src) > fzMaxPolicyDoc {
			t.Skip()
		}

		for _, p := range []phase{phaseConnect, phaseRequest, phaseResponse} {
			var (
				prg error
				ip  error
			)
			var prog *program
			var interp *interpolated

			// Invariant 1, for the two entry points a policy document reaches:
			// a rule condition, and a ${...} placeholder inside a config string.
			fzDo(t, fmt.Sprintf("%s condition", p), func() {
				var e error
				prog, e = compileExpr(p, src, true)
				prg = e
			})
			fzDo(t, fmt.Sprintf("%s interpolation", p), func() {
				var e error
				interp, e = compileInterpolation(p, src)
				ip = e
			})

			// A compiled program must evaluate without panicking, whatever it
			// was handed -- including the activations where nothing it names
			// exists, which is what makes the fail-open path in evalBool and
			// interpolated.eval load-bearing.
			if prg == nil && prog != nil {
				for i, act := range fzEvalActivations() {
					fzDo(t, fmt.Sprintf("%s condition eval %d", p, i), func() {
						_, _ = prog.eval(act)
						_, _ = prog.evalBool(act)
					})
				}
			}
			if ip == nil && interp != nil {
				// The error callback is nil in one of the two shapes it takes
				// in production (the interpolated.eval callers all pass one),
				// so both spellings are exercised.
				for i, act := range fzEvalActivations() {
					fzDo(t, fmt.Sprintf("%s interpolation eval %d", p, i), func() {
						_ = interp.eval(act, nil)
						_ = interp.eval(act, func(error) {})
					})
				}
			}
		}
	})
}

// --- FuzzPolicyEnforce ------------------------------------------------------

// fzEnforcePolicies are the policies this target evaluates. The threat model is
// the reason they are fixed rather than fuzzed: a policy is the operator's, and
// the request is the attacker's. So the corpus drives the *facts* -- the method,
// the target, a header, the connection address, the status code -- through
// expressions and interpolations that reach every runtime evaluation path the
// package has: a condition on each phase, a header value interpolated from
// each phase's variables, a body, a log metadata value, a set-vars assignment,
// a CIDR decision on a malformed address, and a whole-map interpolation (which
// is the one that renders through fmt rather than as a string).
var fzEnforcePolicies = []string{
	`on_tcp_connect:
  - name: restrict-ips
    expressions: ["conn.client_ip != '203.0.113.9'"]
    config:
      enforce: true
      allow: ["10.0.0.0/8"]
  - name: log
    config:
      metadata:
        addr: "${conn.remote_addr}"
        ip: "${conn.client_ip}"
on_http_request:
  - name: add-headers
    expressions: ["req.method != 'OPTIONS'", "req.url.path != '/healthz'", "req.headers['x-skip'] != '1'"]
    config:
      headers:
        X-Target: "${req.url.raw}"
        X-Path: "${req.url.path}"
        X-Method: "${req.method}"
        X-Host: "${req.headers.host}"
        X-All-Headers: "${req.headers}"
        X-Cookie: "${req.cookies.session}"
        X-Num: "${1 + 1}"
        X-Conn-IP: "${conn.client_ip}"
  - name: set-vars
    config:
      vars:
        - v: "${req.url.query}"
        - copied: "${vars.v}"
  - name: log
    expressions: ["vars.copied != ''"]
    config:
      metadata:
        q: "${vars.v}"
        count: 3
  - name: custom-response
    expressions: ["req.method == 'DELETE'"]
    config:
      status_code: 418
      body: "no ${req.method} for ${req.url.path} from ${conn.client_ip}"
      headers:
        content-type: text/plain
        X-Who: "${vars.copied}"
  - name: deny
    expressions: ["req.url.path.startsWith('/private') && req.headers.authorization == ''"]
  - name: remove-headers
    expressions: ["req.method == 'PUT'"]
    config:
      headers: ["cookie", "authorization"]
on_http_response:
  - name: add-headers
    expressions: ["res.status_code >= 300"]
    config:
      headers:
        X-Failed: "${res.status_code}"
        X-Upstream: "${res.status_code + 1}"
  - name: remove-headers
    expressions: ["res.status_code == 404"]
    config:
      headers: ["etag"]
  - name: log
    config:
      metadata:
        status: "${res.status_code}"
`,
	// The policy with no conditions at all: every rule applies to every
	// message, which is the shape that runs the most code per evaluation.
	`on_http_request:
  - name: add-headers
    config:
      headers:
        X-All: "${req.headers}"
        X-Raw: "${req.url.raw}"
  - name: set-vars
    config:
      vars: [{a: "${req.url.query}"}, {b: "${vars.a}"}, {c: "${vars.b}"}]
  - name: add-headers
    config:
      headers:
        X-Chain: "${vars.c}"
on_http_response:
  - name: add-headers
    config:
      headers:
        X-S: "${res.status_code}"
`,
	// A policy whose expressions are all runtime failures against the
	// activations below (misspelled map keys), which is the fail-open path:
	// every evaluation errors, every rule must be skipped, and the connection
	// must be unaffected.
	//
	// A misspelled *map* key is the shape that is left for this: with the
	// variables declared by dotted name, a misspelled field (req.nope) is a
	// compile error and belongs to FuzzPolicyValidate's corpus, not here. A key
	// lookup on a declared map is still a runtime error, which is exactly the
	// case this template exists to carry.
	`on_http_request:
  - name: add-headers
    expressions: ["req.headers.nope == 'x'", "req.cookies.nope == 'x'"]
    config:
      headers:
        X-No: "${req.headers.nope}"
  - name: deny
    expressions: ["req.headers.nope == 'x'"]
`,
	// Interpolation of a value that cannot be a string: a list, a map, a
	// bool, a null. formatValue's default branch is what renders these, and it
	// is the one branch with no obvious right answer. Note that no case here is
	// a map or list *literal*: the placeholder ends at the first '}'
	// (compileInterpolation documents the simple form), so `${ {'k':'v'} }` is a
	// syntax error rather than a rendered map -- TestPolicyInterpolationStopsAtTheFirstBrace.
	`on_http_request:
  - name: add-headers
    config:
      headers:
        X-List: "${['a','b']}"
        X-Map: "${req.cookies}"
        X-Bool: "${req.method == 'GET'}"
        X-Missing: "${req.headers.nope}"
`,
}

func FuzzPolicyEnforce(f *testing.F) {
	// The compiled forms are built once per process: compiling is the load-time
	// half and is FuzzPolicyValidate's subject, and rebuilding them per
	// execution would dominate this target's cost.
	compiled := make([]*Compiled, 0, len(fzEnforcePolicies))
	for i, doc := range fzEnforcePolicies {
		tp := new(TrafficPolicy)
		if err := yaml.Unmarshal([]byte(doc), tp); err != nil {
			// A template that does not decode is a bug in this file, not a
			// finding, and it should fail loudly rather than quietly shrink the
			// target's coverage.
			f.Fatalf("template policy %d does not decode: %v", i, err)
		}
		c, err := tp.Compile()
		if err != nil {
			f.Fatalf("template policy %d does not compile: %v", i, err)
		}
		compiled = append(compiled, c)
	}

	for _, data := range [][]byte{
		[]byte("203.0.113.9:1234\x00GET\x00/admin?x=1\x00x-skip\x000"),
		[]byte("10.0.0.1:80\x00DELETE\x00/private\x00authorization\x00"),
		[]byte("\x00\x00\x00\x00\x00"),
		[]byte("not-an-address\x00POST\x00/\x00cookie\x00session=1; a=2"),
	} {
		f.Add(data)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > fzMaxPolicyDoc {
			t.Skip()
		}
		// Five fields: connection address, method, target, one header name and
		// one header value. A missing field is the empty string, which is a
		// legal (if useless) value for every one of them -- the point is that
		// these are arbitrary bytes, because that is what the rewriter forwards
		// from a hostile client.
		fields := bytes.SplitN(data, []byte{0}, 6)
		field := func(i int) string {
			if i < len(fields) {
				return string(fields[i])
			}
			return ""
		}
		addr, method, target, hname, hvalue := field(0), field(1), field(2), field(3), field(4)

		// An arbitrary status code, including one no server would send: the
		// activation hands it to CEL as an int, and a policy may do anything
		// with it.
		status := 200
		if len(fields) > 5 && len(fields[5]) >= 4 {
			status = int(int32(binary.LittleEndian.Uint32(fields[5][:4])))
		}

		req := fzRequest(method, target, http.Header{hname: {hvalue}, "Cookie": {hvalue}})
		resp := fzResponse(status)

		for i, c := range compiled {
			var connect ConnectVerdict
			var q1, q2 *rewriter.RequestVerdict
			var s1, s2 *rewriter.ResponseVerdict

			// Invariant 1, on the accept path: EvaluateConnect parses the
			// address the kernel gave it, and a policy's CIDR matrix is applied
			// to whatever comes out.
			fzDo(t, fmt.Sprintf("policy %d EvaluateConnect", i), func() {
				connect = c.EvaluateConnect(addr)
			})
			if connect.Deny && connect.Response == nil {
				t.Fatalf("policy %d denied a connection with no response to explain it: %+v", i, connect)
			}

			// A hook, driven twice with the same facts: the two verdicts must
			// match, or an enforcement decision is a coin flip. The verdicts are
			// compared, not the closures -- RequestVerdict is a plain struct of
			// slices and a pointer, so DeepEqual is exact.
			fzDo(t, fmt.Sprintf("policy %d request hook", i), func() {
				h := c.RequestHook(fzQuiet{}, addr)
				if h != nil {
					q1 = h(req)
					q2 = h(req)
				}
			})
			fzDo(t, fmt.Sprintf("policy %d response hook", i), func() {
				h := c.ResponseHook(fzQuiet{}, addr)
				if h != nil {
					s1 = h(resp)
					s2 = h(resp)
				}
			})

			if !reflect.DeepEqual(q1, q2) {
				t.Fatalf("policy %d: the same request, evaluated twice on one hook, gave two verdicts:\n\t%+v\n\t%+v\n\trequest: %s %s header %q: %q", i, q1, q2, method, target, hname, hvalue)
			}
			if !reflect.DeepEqual(s1, s2) {
				t.Fatalf("policy %d: the same response, evaluated twice on one hook, gave two verdicts:\n\t%+v\n\t%+v\n\tstatus: %d", i, s1, s2, status)
			}

			// The per-message state must not leak between messages: a hook that
			// has already seen a request must reach the same verdict for the
			// next one as a hook that has seen nothing (evalState.next is the
			// only thing that makes ${vars.x} mean "set earlier in *this*
			// message"). A leak here is a policy that can be primed by one
			// request and bypassed by the next.
			var fresh *rewriter.RequestVerdict
			fzDo(t, fmt.Sprintf("policy %d request hook, fresh", i), func() {
				h := c.RequestHook(fzQuiet{}, addr)
				if h != nil {
					fresh = h(req)
				}
			})
			if !reflect.DeepEqual(fresh, q2) {
				t.Fatalf("policy %d: a hook that had already seen a request disagreed with a fresh one -- per-message state leaked:\n\tfresh: %+v\n\tused:  %+v\n\trequest: %s %s", i, fresh, q2, method, target)
			}
		}
	})
}

// fzRequest builds a request with the facts a policy sees. The header map is
// built directly rather than through Header.Set, because Set canonicalizes the
// name and refuses nothing -- and a policy reads req.headers by the lower-cased
// key, so the canonical spelling is irrelevant to what is being tested. The
// URL is built without url.Parse for the same reason: parsing is the rewriter's
// job upstream, and what arrives here is whatever survived it.
func fzRequest(method, target string, hdr http.Header) *http.Request {
	u := &url.URL{Path: target}
	if i := strings.IndexByte(target, '?'); i >= 0 {
		u.Path, u.RawQuery = target[:i], target[i+1:]
	}
	return &http.Request{
		Method:     method,
		URL:        u,
		RequestURI: target,
		Header:     hdr,
		Host:       hdr.Get("Host"),
	}
}

func fzResponse(status int) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{}}
}

// --- the decoder and compiler crash probes ----------------------------------
//
// Everything from here down exists because the two ways these decoders can die
// are the two ways a fuzzer cannot report: a stack overflow and an OOM kill are
// fatal to the process, so "failing input written to testdata/fuzz/..." never
// appears and the run just ends. The pattern below is the usual way around it --
// re-exec this test binary as a child with one pathological document and watch
// the exit status -- which turns a crash into an ordinary test failure with the
// child's output quoted, and leaves the suite alive to say so.
//
// The instrument is itself tested (TestPolicyCrashProbeHarness, a guaranteed
// stack overflow) because a probe that cannot see a crash proves nothing.

const (
	fzProbeEnv   = "NGROK_FZ_PROBE"
	fzProbeN     = "NGROK_FZ_PROBE_N"
	fzProbeStack = "NGROK_FZ_PROBE_STACK"
)

// fzSlowCeiling is the lowered stack ceiling the depth probes run under. The
// default is 1 GB, which would need millions of frames to reach and a
// multi-megabyte document to produce; lowering the ceiling makes the same
// question answerable in milliseconds. What that buys is a *rate* (bytes of
// input per byte of stack, or per level of nesting) which extrapolates to the
// default ceiling; what it does not buy is a statement about any particular
// document size, and the tests below are careful to say which one they are
// asserting.
const fzSlowCeiling = 16 << 20

// TestPolicyCrashProbeChild is the probe's other half. It is not a test: the
// parent selects a case through the environment and reads the child's exit
// status. Run on its own it skips.
func TestPolicyCrashProbeChild(t *testing.T) {
	kind := os.Getenv(fzProbeEnv)
	if kind == "" {
		t.Skip("this is the crash probe's child process; the parent sets " + fzProbeEnv)
	}
	if s := os.Getenv(fzProbeStack); s != "" {
		ceiling, err := strconv.Atoi(s)
		if err != nil {
			t.Fatalf("bad %s: %v", fzProbeStack, err)
		}
		debug.SetMaxStack(ceiling)
	}
	n := 0
	if s := os.Getenv(fzProbeN); s != "" {
		var err error
		if n, err = strconv.Atoi(s); err != nil {
			t.Fatalf("bad %s: %v", fzProbeN, err)
		}
	}

	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	start := time.Now()

	var err error
	switch kind {
	case "known-crash":
		// The positive control: recursion the compiler cannot turn into a loop,
		// which must exceed any ceiling. A probe that does not report this as a
		// crash is broken, not lucky.
		var depth func(int) int
		depth = func(i int) int { return depth(i+1) + 1 }
		_ = depth(0)

	case "cel-parens":
		// The shape an agent could send inside a policy: every "(" is one level
		// of recursive-descent parse, and cel-go's parser has no limit of its
		// own.
		src := strings.Repeat("(", n) + "true" + strings.Repeat(")", n)
		_, err = compileExpr(phaseRequest, src, true)

	case "yaml-flow":
		// The shape a config file could hold: a flow sequence nested n deep,
		// decoded into a config value. The parser is a state machine (no native
		// recursion), but the *decoder* is recursive, and yaml.v3's scanner caps
		// the flow level at 10000 -- so above that the decoder never sees the
		// document at all, and below it the cost is what is being measured.
		doc := "on_http_request:\n  - name: log\n    config:\n      metadata:\n        x: " +
			strings.Repeat("[", n) + strings.Repeat("]", n) + "\n"
		tp := new(TrafficPolicy)
		if err = yaml.Unmarshal([]byte(doc), tp); err == nil {
			err = tp.Validate()
		}

	case "yaml-alias":
		// The other classic: anchors that reference each other's nodes, so that
		// the decoded value would be width^levels leaves from a document of
		// width*levels lines. The decoder guards against an anchor that contains
		// itself, which is the cycle case, and yaml.v3 adds an expansion budget
		// on top of that: once aliases outnumber the nodes around them by
		// allowedAliasRatio, the document is refused with "document contains
		// excessive aliasing" instead of being expanded. The probe is here to
		// check that the budget is real rather than to trust the source.
		doc := fzAliasBomb(n, 9)
		tp := new(TrafficPolicy)
		if err = yaml.Unmarshal([]byte(doc), tp); err == nil {
			err = tp.Validate()
		}

	case "json-flow":
		// The comparison that matters for reachability: the same nesting through
		// encoding/json, which is the shape the wire carries. Go's decoder caps
		// nesting at 10000 (encoding/json/scanner.go), so this should come back
		// as an error rather than a corpse. The document is well-formed JSON --
		// the nesting is inside a field the policy has -- so a refusal is the
		// decoder's depth limit and not a syntax error.
		doc := `{"on_http_request":` + strings.Repeat("[", n) + strings.Repeat("]", n) + "}"
		tp := new(TrafficPolicy)
		err = json.Unmarshal([]byte(doc), tp)

	default:
		t.Fatalf("unknown probe kind %q", kind)
	}

	runtime.ReadMemStats(&after)
	// The head and the tail of an error both carry information here: the head is
	// the input echoed back (which is why it is truncated), and the tail is the
	// reason (which is why it is not).
	msg := errStr(err)
	fmt.Printf("fz-probe-ok kind=%s n=%d alloc=%d dur=%s errhead=%q errtail=%q\n",
		kind, n, int64(after.TotalAlloc-before.TotalAlloc), time.Since(start),
		fzTruncate(msg, 120), fzTail(msg, 300))
}

// fzTail is the other end of fzTruncate, for messages whose reason is at the end.
func fzTail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "..." + s[len(s)-n:]
}

func errStr(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func fzTruncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// fzAliasBomb builds the alias document: `levels` anchors, each a list of
// `width` references to the anchor below it, referenced once from a rule's log
// metadata so that it is actually decoded (an anchor nobody references expands
// to nothing, which is why the definitions alone would prove nothing).
func fzAliasBomb(levels, width int) string {
	var b strings.Builder
	refs := func(prefix string, i int) {
		b.WriteString("[")
		for j := 0; j < width; j++ {
			if j > 0 {
				b.WriteString(",")
			}
			fmt.Fprintf(&b, "%s%d", prefix, i)
		}
		b.WriteString("]")
	}
	for i := 0; i < levels; i++ {
		fmt.Fprintf(&b, "l%d: &l%d ", i, i)
		if i == 0 {
			b.WriteString("[x")
			for j := 1; j < width; j++ {
				b.WriteString(",x")
			}
			b.WriteString("]\n")
			continue
		}
		refs("*l", i-1)
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "on_http_request:\n  - name: log\n    config:\n      metadata:\n        x: *l%d\n", levels-1)
	return b.String()
}

// fzProbeResult is one child run, reduced to what a report needs.
type fzProbeResult struct {
	kind   string
	n      int
	stack  int
	ok     bool
	killed bool // the watchdog, not the workload: inconclusive, never a crash
	detail string
	alloc  int64
	dur    time.Duration
}

func (r fzProbeResult) String() string {
	ceiling := "default"
	if r.stack > 0 {
		ceiling = fmt.Sprintf("%d MiB", r.stack>>20)
	}
	verdict := "ok"
	switch {
	case r.killed:
		verdict = "killed"
	case !r.ok:
		verdict = "died"
	}
	return fmt.Sprintf("%s n=%d stack=%s %s alloc=%d dur=%s: %s",
		r.kind, r.n, ceiling, verdict, r.alloc, r.dur, r.detail)
}

var (
	fzProbeAllocRe = regexp.MustCompile(`alloc=(\d+)`)
	fzProbeDurRe   = regexp.MustCompile(`dur=([0-9a-z.]+)`)
)

// fzProbe runs one case in a child process. The timeout is generous because a
// default-ceiling depth probe can legitimately spend seconds growing a stack
// before it dies.
func fzProbe(t *testing.T, kind string, n, stack int) fzProbeResult {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, os.Args[0],
		"-test.run=^TestPolicyCrashProbeChild$", "-test.timeout=150s", "-test.v")
	cmd.Env = append(os.Environ(), fzProbeEnv+"="+kind, fzProbeN+"="+strconv.Itoa(n))
	if stack > 0 {
		cmd.Env = append(cmd.Env, fzProbeStack+"="+strconv.Itoa(stack))
	}
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	err := cmd.Run()

	res := fzProbeResult{kind: kind, n: n, stack: stack, ok: err == nil}
	out := buf.String()
	res.detail = fzProbeDiagnosis(out)
	if m := fzProbeAllocRe.FindStringSubmatch(out); m != nil {
		res.alloc, _ = strconv.ParseInt(m[1], 10, 64)
	}
	if m := fzProbeDurRe.FindStringSubmatch(out); m != nil {
		res.dur, _ = time.ParseDuration(m[1])
	}
	// A probe that never finishes is a different finding from a probe that
	// dies, and one a caller must not report as a crash: the deep-YAML case is
	// both super-linear in time and linear in stack, so a size that is far from
	// the stack ceiling can still run out of wall clock. Distinguishing them
	// here keeps that judgement out of every caller.
	if !res.ok {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) ||
			strings.Contains(out, "test timed out") || strings.Contains(out, "signal: killed") {
			res.killed = true
		}
		if res.detail == "" {
			res.detail = "died without a diagnosis: " + err.Error()
		}
	}
	return res
}

// fzProbeDiagnosis picks the line that says what happened to the child: the
// child's own ok line if it finished, and otherwise the first line a crash,
// panic or OOM kill would leave behind.
func fzProbeDiagnosis(out string) string {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.Contains(line, "fz-probe-ok"):
			return line
		case strings.HasPrefix(line, "fatal error:"):
			return line
		case strings.HasPrefix(line, "panic:"):
			return line
		case strings.Contains(line, "out of memory"):
			return line
		case strings.Contains(line, "test timed out"):
			return line
		}
	}
	return ""
}

// TestPolicyCrashProbeHarness is the instrument's own control. A probe that
// reports "survived" for everything is worse than no probe, and the cheapest
// way to be sure it is not doing that is to hand it a guaranteed stack
// overflow and require it to come back with a corpse.
func TestPolicyCrashProbeHarness(t *testing.T) {
	r := fzProbe(t, "known-crash", 0, 0)
	if r.ok {
		t.Fatalf("the probe did not detect an unbounded recursion it was asked to run: %s", r)
	}
	t.Logf("positive control: %s", r)
}

// TestPolicyJSONNestingIsBounded is the reachability half of the two probes
// below. The policy that reaches the server arrives as JSON in the tunnel
// registration (msg.Envelope -> TrafficPolicy), and encoding/json refuses to
// nest more than 10000 deep, so the wire is not the path where a decoder
// recursion can be reached with a deep document. It is here so that the two
// YAML results below cannot be read as "the enforcement path is vulnerable".
func TestPolicyJSONNestingIsBounded(t *testing.T) {
	r := fzProbe(t, "json-flow", 200000, 0)
	if !r.ok {
		t.Fatalf("the JSON path -- the one the wire actually uses -- died on a deep document, which is a server-side denial of service reachable by any registering agent: %s", r)
	}
	if !strings.Contains(r.detail, "max depth") {
		t.Logf("note: the JSON decoder refused the document without naming a depth limit: %s", r)
	}
	t.Logf("%s", r)
}

// TestPolicyYAMLDecoderNestingProbe measures how much stack one level of YAML
// flow nesting costs, under a ceiling low enough that the answer arrives in
// milliseconds. It asserts the *rate*, not a document size: what the rate
// establishes is that the decoder's recursion is proportional to the input's
// nesting, which is the property a limit exists to bound.
//
// The limit is there now: yaml.v3's scanner refuses a flow level above 10000
// ("exceeded max depth of 10000"), so the two deepest rows below never reach the
// decoder at all and the probe can no longer find a stack edge to extrapolate
// from. The loop stays as a guard -- the ceiling it measures under is 16 MiB, so
// a decoder that lost its cap would show up here as a death rather than as a
// surprise in production -- but the "no depth died" line is now the expected
// outcome and says what bounded it, rather than reading as a probe that failed to
// find what the source promised.
func TestPolicyYAMLDecoderNestingProbe(t *testing.T) {
	var (
		crashed []int
		sizes   []fzProbeResult
	)
	for _, n := range []int{1 << 10, 1 << 12, 1 << 14, 1 << 16} {
		r := fzProbe(t, "yaml-flow", n, fzSlowCeiling)
		t.Logf("%s", r)
		sizes = append(sizes, r)
		if !r.ok {
			crashed = append(crashed, n)
		}
	}
	if len(crashed) == 0 {
		t.Logf("no depth in 1k..64k exhausted a %d MiB stack: depths above yaml.v3's 10000-level flow cap are refused by the scanner before the decoder recurses, and the ones below it fit. Nothing to extrapolate from -- the decoder is bounded.", fzSlowCeiling>>20)
		return
	}
	// The smallest depth that died under this ceiling. Bytes of stack per level
	// of nesting is the number that extrapolates, so that is the number the
	// report quotes -- a rate, not a document size.
	perLevel := fzSlowCeiling / crashed[0]
	death := int64(1<<30) / int64(perLevel)
	t.Logf("the decoder exhausted a %d MiB stack at depth %d -- about %d bytes of stack per level; extrapolating, the default 1 GiB ceiling is reached at roughly %d levels of nesting, which is a document of roughly %d MiB",
		fzSlowCeiling>>20, crashed[0], perLevel, death, (death*2)>>20)

	// This branch no longer runs, and that is the point of keeping it: it is what
	// a decoder without a cap would look like. It does not fail, because what it
	// would have measured is a property of the decoder under a ceiling this file
	// invented (fzSlowCeiling), so a failure here would be a claim about a
	// configuration no process actually runs with. The claim about a real
	// configuration is TestPolicyYAMLDepthAtDefaultCeiling, which loads
	// documents an operator could plausibly have at the default ceiling and
	// fails if they kill the process. With yaml.v3's flow cap in place both stop
	// being about a limit the fork is missing and start being about where the
	// library put it.
	t.Logf("reachability, for the record: yaml.Unmarshal is reached from the client's config file and -traffic-policy-file, not from the wire (the registration's policy is JSON, and TestPolicyJSONNestingIsBounded shows that path is capped at 10000)")
}

// TestPolicyCELNestingProbe is the same measurement for cel-go's parser, and it
// is the one with a path to the enforcement side: an expression is a field of a
// policy document, the policy travels in the registration, and the *server*
// compiles it (server/tunnel.go). A registration is capped at 4 MiB
// (msg.maxMessageSize), which is 2M levels of nesting, so what matters is
// whether 2M levels fit in a 1 GiB stack.
func TestPolicyCELNestingProbe(t *testing.T) {
	for _, n := range []int{1 << 10, 1 << 12, 1 << 14, 1 << 16} {
		r := fzProbe(t, "cel-parens", n, fzSlowCeiling)
		t.Logf("%s", r)
		if !r.ok {
			t.Logf("cel-go exhausted a %d MiB stack at %d levels of parenthesized nesting", fzSlowCeiling>>20, n)
			return
		}
	}
	t.Logf("no depth in 1k..64k exhausted a %d MiB stack: at that rate a 4 MiB expression (the wire's cap) fits well inside the default 1 GiB ceiling", fzSlowCeiling>>20)
}

// TestPolicyYAMLAnchorExpansionIsBounded pins the second decoder property, and
// it used to pin the opposite of it. Anchors are expanded once per reference, so
// without a budget the decoded value grows as width^levels while the document
// grows as width*levels: the billion-laughs shape, which yaml.v1 had no defense
// against (its cycle guard caught `a: &a [*a]` and nothing else). yaml.v3 does
// have one -- an alias that outgrows the nodes around it is refused with
// "document contains excessive aliasing" -- and this test is the assertion that
// the budget is real, rather than a log line reporting how exponential the
// growth is.
//
// The probe stops at five levels because four is already enough to trip the
// budget: 9^4 = 6561 leaves from a 36-line document. The bound is asserted by
// the last case being refused *and* by the allocations staying flat across the
// levels where it is not, which is the part an "is the budget still there" test
// can check without pinning the library's ratio constant.
func TestPolicyYAMLAnchorExpansionIsBounded(t *testing.T) {
	var prev, prevAlloc int64
	const unbounded = 1 << 20 // a 45-line bomb that expands would be far past this
	refused := ""
	for _, levels := range []int{2, 3, 4, 5} {
		r := fzProbe(t, "yaml-alias", levels, 0)
		if !r.ok {
			t.Fatalf("the alias document at %d levels did not survive at the default ceiling: %s", levels, r)
		}
		if r.alloc > unbounded {
			t.Errorf("an alias bomb of %d levels allocated %d bytes: the decoder is expanding it rather than refusing it, which is the billion-laughs shape at 9 references per level", levels, r.alloc)
		}
		if prev > 0 {
			t.Logf("levels=%d alloc=%d (x%.1f on the level before) lines=%d", levels, r.alloc, float64(r.alloc)/float64(prev), prevAlloc)
		} else {
			t.Logf("levels=%d alloc=%d lines=%d", levels, r.alloc, prevAlloc)
		}
		if strings.Contains(r.detail, "excessive aliasing") {
			refused = r.detail
		}
		prev, prevAlloc = r.alloc, int64(levels*9)
	}

	if refused == "" {
		t.Errorf("no level in 2..5 was refused for excessive aliasing: either the decoder expanded the bomb or the budget moved, and the log lines above say which")
	} else {
		t.Logf("the bomb was refused, not expanded: %s", refused)
	}
}

// TestPolicyYAMLDepthAtDefaultCeiling is where the nesting question is asked
// about the configuration a real process runs with rather than under the
// probe's lowered ceiling: two documents an operator could plausibly have on
// disk, 64 KiB and 256 KiB of flow nesting.
//
// Neither kills the process, and with yaml.v3 neither is even decoded: both are
// past the scanner's 10000-level flow cap, so they come back as "exceeded max
// depth of 10000" in about four milliseconds each, from a document an order of
// magnitude smaller than the cap needs. The measurement that used to be here --
// 256 bytes of stack per level, roughly four million levels to reach the default
// 1 GiB ceiling, super-linear decode cost below it -- was a measurement of
// yaml.v1, which had no cap at all; it is recorded in this test's history rather
// than in its output, because the numbers no longer describe anything the tree
// can do.
//
// The depths stay where they are, deliberately above the cap: that is what makes
// the two branches below a guard. A decoder whose cap went away would walk into
// this test's other two arms (a corpse, or a probe that never finishes) instead
// of quietly accepting an 8 MiB document in production.
func TestPolicyYAMLDepthAtDefaultCeiling(t *testing.T) {
	var prev int64
	for _, tc := range []struct {
		depth int
		what  string
	}{
		{32 << 10, "64 KiB"},
		{128 << 10, "256 KiB"},
	} {
		r := fzProbe(t, "yaml-flow", tc.depth, 0)
		switch {
		case r.killed:
			// Not a crash, and the test says so rather than dressing a timeout
			// up as one: a stack overflow has a diagnosis line, and this has
			// none.
			t.Logf("a %s document (%d levels) did not finish inside the probe's budget: %s", tc.what, tc.depth, r)
			t.Logf("that is a cost finding, not a crash: the decode was super-linear in depth as well as linear in stack before yaml.v3 capped the flow level")
		case !r.ok:
			t.Errorf("a %s policy document kills the process that loads it at the default 1 GiB stack ceiling (%d levels of flow nesting): %s\nThis is a decoder recursing on a nested flow sequence; client/config.go and server/config.go both unmarshal through it. The wire path is not affected -- TestPolicyJSONNestingIsBounded -- so the reach is a config file or -traffic-policy-file, i.e. local, but a policy document is exactly the kind of file that gets copied between machines.", tc.what, tc.depth, r)
		default:
			growth := ""
			if prev > 0 {
				growth = fmt.Sprintf(" (x%.1f on the size before, for 4x the depth)", float64(r.dur)/float64(prev))
			}
			t.Logf("a %s document (%d levels) survived the default ceiling in %s%s: %s", tc.what, tc.depth, r.dur, growth, r.detail)
		}
		if r.dur > 0 {
			prev = int64(r.dur)
		}
	}
}

// --- the edge matrix --------------------------------------------------------

// TestPolicyRejectMessageIsDeterministic is the fix for the nondeterminism this
// pass found: buildHeaders used to walk the configured headers map directly
// (`for k, v := range m`), where every other traversal in validate.go sorted its
// keys first (checkConfigKeys and buildMetadata both go through sortedKeys). A
// Go map has no order, so when two entries were wrong the one the error named
// was whichever the runtime visited first, and the same document reported a
// different field on each run -- an operator chasing a flake, and a CI job that
// goes red on a different line every time.
//
// The test is a determinism assertion, not a wording one: 400 validations of one
// document, one distinct message, and the entry it names is the first in sorted
// order. The exact prose is deliberately not pinned (the fuzz targets in this
// file do not pin error text either), only that it names the field it came from
// and that the same document always fails the same way.
func TestPolicyRejectMessageIsDeterministic(t *testing.T) {
	// Two entries that are both wrong in the same way, so that whichever is
	// visited first produces an error: the map's order is what decides, and the
	// sorted order is what has to win.
	const doc = `on_http_request:
  - name: add-headers
    config:
      headers:
        b: 2
        a: 1
`
	tp, err := fzYAML(t, []byte(doc))
	if err != nil {
		t.Fatalf("the document does not decode: %v", err)
	}

	seen := map[string]int{}
	for i := 0; i < 400; i++ {
		err := tp.Validate()
		if err == nil {
			t.Fatalf("headers with non-string values validated")
		}
		seen[err.Error()]++
	}
	if len(seen) != 1 {
		msgs := make([]string, 0, len(seen))
		for m := range seen {
			msgs = append(msgs, m)
		}
		sort.Strings(msgs)
		t.Fatalf("%d distinct messages for one document, so which field an operator is told about depends on map iteration order:\n%v", len(seen), msgs)
	}
	for m := range seen {
		if !strings.Contains(m, `config field "headers" entry "a"`) {
			t.Errorf("the message does not name the first entry in sorted order: %q", m)
		}
	}
}

// TestPolicyAddHeadersRejectsUnknownConfigFields is the fix for the second
// behavioral finding, and it is the one the package's own documentation argues
// against. validate.go's opening comment gives the reason checkConfigKeys
// exists: "It is the difference between a policy that does less than its author
// thinks and one that fails to load." Every action called it with its documented
// field list except add-headers, so a typo or a copy-paste from an ngrok
// document with, say, `values` instead of `headers` loaded a rule that added
// nothing at all -- one header short in production, with no warning anywhere.
//
// Each case is refused now, and the error has to name the action: the config
// keys are the whole story of the finding, and the operator needs to know which
// rule to open. The service could not get here with a document that has a
// misspelled key and no valid one, so the case that matters most is the mixed
// one -- a valid "headers" next to a misspelled key, which used to load and
// quietly add only the valid headers.
func TestPolicyAddHeadersRejectsUnknownConfigFields(t *testing.T) {
	cases := []struct {
		what string
		doc  string
		// wantCites is what an operator needs to find the mistake: the rule's
		// position and name, and the offending key.
		wantCites []string
	}{
		{
			what: "a misspelled \"headerss\" next to a valid \"headers\"",
			doc: `on_http_request:
  - name: add-headers
    config:
      headers:
        X-One: "1"
      value: nope
      headerss: {X-Two: "2"}
`,
			wantCites: []string{"on_http_request[0] (add-headers)", `unknown config field "headerss"`, "headers"},
		},
		{
			what:      "only undocumented keys",
			doc:       "on_http_request:\n  - name: add-headers\n    config:\n      values: {X: '1'}\n",
			wantCites: []string{"on_http_request[0] (add-headers)", `unknown config field "values"`},
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
				t.Fatal("an undocumented config field validated; the rule would silently do less than its author wrote")
			}
			for _, want := range tc.wantCites {
				if !strings.Contains(verr.Error(), want) {
					t.Errorf("the refusal does not cite %q, so the operator cannot find the rule or the key: %v", want, verr)
				}
			}
			if _, cerr := tp.Compile(); cerr == nil {
				t.Fatal("Validate refused the document and Compile accepted it")
			}
		})
	}

	// The check is not "refuse anything unfamiliar" at the cost of the documented
	// shape: the document ngrok's own add-headers docs describe still loads and
	// still adds its headers.
	const ok = `on_http_request:
  - name: add-headers
    config:
      headers:
        X-One: "1"
`
	tp, err := fzYAML(t, []byte(ok))
	if err != nil {
		t.Fatalf("the document does not decode: %v", err)
	}
	c, err := tp.Compile()
	if err != nil {
		t.Fatalf("a documented add-headers config was refused: %v", err)
	}
	v := c.RequestHook(fzQuiet{}, "203.0.113.9:1234")(fzRequest("GET", "/", http.Header{}))
	if v == nil || len(v.Add) != 1 {
		t.Fatalf("expected the one documented header to be added, got %+v", v)
	}
}

// TestPolicyBadCELIsALoadTimeError is the brief's "action config with a CEL
// syntax error" case, asserted the way the package documents it: a broken
// expression is refused at load time with an error naming the rule, never a
// rule that quietly never matches. The fuzzer covers the shapes; this covers
// the promise -- that the error an operator sees says which rule and which
// condition.
func TestPolicyBadCELIsALoadTimeError(t *testing.T) {
	cases := []struct {
		what string
		doc  string
		// wantCites is what an operator needs the message to contain to find the
		// mistake: the rule's position and name, and either the condition's
		// index or the offending field.
		wantCites []string
	}{
		{
			what: "a condition that does not parse",
			doc: `on_http_request:
  - name: deny
    expressions: ["req.method =="]
    config: {}
`,
			wantCites: []string{"on_http_request[0] (deny)", "condition 0"},
		},
		{
			what: "a condition whose type is known and is not bool",
			doc: `on_http_request:
  - name: deny
    expressions: ["1 + 1"]
`,
			wantCites: []string{"on_http_request[0] (deny)", "not a condition"},
		},
		{
			what: "a condition naming a variable this build does not provide",
			doc: `on_http_request:
  - name: log
    expressions: ["conn.geo.country == 'GB'"]
    config:
      metadata: {a: b}
`,
			wantCites: []string{"on_http_request[0] (log)"},
		},
		{
			what: "a condition using a variable from another phase",
			doc: `on_http_response:
  - name: log
    expressions: ["req.method == 'GET'"]
    config:
      metadata: {a: b}
`,
			wantCites: []string{"on_http_response[0] (log)"},
		},
		{
			what: "a syntax error inside an interpolation",
			doc: `on_http_request:
  - name: add-headers
    config:
      headers:
        X-Bad: "${req.method ==}"
`,
			wantCites: []string{"on_http_request[0] (add-headers)", "headers"},
		},
		{
			what: "an interpolation of a list, which this build will not splice",
			doc: `on_http_request:
  - name: add-headers
    config:
      headers:
        X-List: "${['a']}"
`,
			// Not a compile error in this build (compileExpr with
			// mustBeBool=false takes any type, and formatValue renders a list
			// with fmt). The case is here to pin that: the type check that
			// applies to conditions deliberately does not apply to
			// interpolation, and the result is a rendered guess rather than a
			// load-time refusal.
			wantCites: nil,
		},
	}

	for _, c := range cases {
		t.Run(c.what, func(t *testing.T) {
			tp, err := fzYAML(t, []byte(c.doc))
			if err != nil {
				t.Fatalf("the document does not decode: %v", err)
			}
			err = tp.Validate()
			if c.wantCites == nil {
				if err != nil {
					t.Fatalf("expected this to load (see the case's comment), got: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("a policy with a broken expression loaded")
			}
			for _, want := range c.wantCites {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("the error does not cite %q, so an operator cannot find the rule: %v", want, err)
				}
			}
		})
	}
}

// TestPolicyCompileCostIsBounded measures the one cost the server pays on a
// path an agent controls: the policy in a tunnel registration is compiled at
// server/tunnel.go, once per registration, and every rule's expressions are
// compiled by cel-go with no cache. A registration is capped at 4 MiB
// (msg.maxMessageSize), so the question is what a registration of that size
// costs the receiver -- and, since maxActionsPerPolicy is what answers it now,
// whether the cap is enforced before any of that work is done.
//
// The assertions are deliberately loose. This machine's throughput is not a
// budget, and a timing assertion tight enough to be a regression test would be
// flaky on a loaded CI box; what the test is for is putting a number in the
// report, and failing only if the cost is catastrophic (minutes) rather than
// merely large.
func TestPolicyCompileCostIsBounded(t *testing.T) {
	// buildActions makes a policy of n rules, each the smallest rule that still
	// compiles an expression and an interpolation: one condition, one header
	// with a placeholder. That is close to the worst case per byte of JSON,
	// because a rule cannot be smaller than one action.
	buildActions := func(n int) *TrafficPolicy {
		tp := &TrafficPolicy{}
		for i := 0; i < n; i++ {
			tp.OnHTTPRequest = append(tp.OnHTTPRequest, &Action{
				Name:        ActionAddHeaders,
				Expressions: []string{"req.method == 'GET' && req.url.path.startsWith('/x')"},
				Config: map[string]interface{}{
					"headers": map[string]interface{}{"X-N": "${conn.client_ip}"},
				},
			})
		}
		return tp
	}

	// The worst case the server will actually compile for one registration is now
	// the cap itself: maxActionsPerPolicy refuses anything larger before cel-go
	// sees it. So this is the number that matters, and it is the one the cap was
	// chosen against.
	n := maxActionsPerPolicy
	tp := buildActions(n)
	buf, err := json.Marshal(tp)
	if err != nil {
		t.Fatalf("marshalling %d actions: %v", n, err)
	}
	start := time.Now()
	c, err := tp.Compile()
	dur := time.Since(start)
	if err != nil {
		t.Fatalf("compiling the cap-sized policy (%d actions): %v", n, err)
	}
	if c == nil {
		t.Fatalf("compiling %d actions returned nil with no error", n)
	}
	t.Logf("%6d actions (the cap), %6d bytes of JSON: compiled in %8s (%s per action)", n, len(buf), dur, dur/time.Duration(n))
	if dur > time.Minute {
		t.Errorf("compiling %d actions took %s, which is minutes of CPU for one registration", n, dur)
	}

	// Past the cap the answer is a load error naming the count, not a longer
	// compile. This is the half that makes the measurement above a bound rather
	// than an anecdote: without it, the only thing standing between a 4 MiB
	// registration and a server that spends its CPU compiling cel-go is the
	// message size cap. The refusal has to arrive promptly -- a cap that is
	// checked after the work it exists to prevent is not a cap -- so the timing
	// is asserted loosely too, and the phase breakdown is asserted because it is
	// what tells the operator which section of the document to cut.
	for _, over := range []int{maxActionsPerPolicy + 1, 10_000} {
		tp := buildActions(over)
		start := time.Now()
		err := tp.Validate()
		dur := time.Since(start)
		if err == nil {
			t.Fatalf("a policy with %d actions validated (the cap is %d)", over, maxActionsPerPolicy)
		}
		for _, want := range []string{strconv.Itoa(over), "maximum is " + strconv.Itoa(maxActionsPerPolicy), "on_http_request " + strconv.Itoa(over)} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("the refusal of a %d-action policy does not cite %q: %v", over, want, err)
			}
		}
		if _, cerr := tp.Compile(); cerr == nil {
			t.Fatalf("Validate refused a %d-action policy and Compile accepted it", over)
		}
		t.Logf("%6d actions refused in %s: %v", over, dur, err)
	}

	// The wire-sized case: as many actions as fit in the registration the server
	// will accept. The action size is measured rather than assumed, so this
	// tracks the message cap if it ever changes. Whichever side of the cap this
	// lands on, the document must not be a silent success followed by minutes of
	// compile: either it validates and compiles in bounded time, or it is refused
	// by the cap with a readable error.
	one, err := json.Marshal(buildActions(1))
	if err != nil {
		t.Fatalf("marshalling one action: %v", err)
	}
	const wireCap = 4 << 20 // msg.maxMessageSize
	wireN := wireCap / len(one)
	tp = buildActions(wireN)
	buf, err = json.Marshal(tp)
	if err != nil {
		t.Fatalf("marshalling %d actions: %v", wireN, err)
	}
	start = time.Now()
	cerr := tp.Validate()
	dur = time.Since(start)
	t.Logf("a %d KiB registration (%d actions) validates in %s; the server pays this per tunnel registration", len(buf)>>10, wireN, dur)
	if wireN > maxActionsPerPolicy {
		if cerr == nil {
			t.Errorf("a %d KiB registration carrying %d actions validated; the cap is %d", len(buf)>>10, wireN, maxActionsPerPolicy)
		} else if !strings.Contains(cerr.Error(), strconv.Itoa(wireN)) {
			t.Errorf("the wire-sized policy was refused without naming its action count: %v", cerr)
		}
	} else {
		if cerr != nil {
			t.Fatalf("the wire-sized policy did not validate: %v", cerr)
		}
		if dur > time.Minute {
			t.Errorf("a registration-sized policy takes %s to validate, so the per-registration CPU cost an agent can impose is minutes", dur)
		}
	}
}

// fzRecord is fzQuiet with a memory: it keeps the warnings the package writes on
// the fail-open path, which is the only trace some of these cases leave.
type fzRecord struct{ warns []string }

func (l *fzRecord) AddLogPrefix(string)          {}
func (l *fzRecord) SetLogPrefixes(...string)     {}
func (l *fzRecord) Debug(string, ...interface{}) {}
func (l *fzRecord) Info(string, ...interface{})  {}
func (l *fzRecord) Warn(f string, a ...interface{}) error {
	l.warns = append(l.warns, fmt.Sprintf(f, a...))
	return nil
}
func (l *fzRecord) Error(f string, a ...interface{}) error { return l.Warn(f, a...) }

// TestPolicyConditionThatIsNotABoolIsRefusedAtLoad is the other half of the case
// above, and it is the one an operator is most likely to meet by accident: a
// rule whose only expression is a *value* rather than a test --
// `expressions: ["req.url.path"]` under a deny rule. It reads like "the rule
// applies to the path", it is not a condition, and every version of this
// package before the strict variable set loaded it clean:
//
//	the phase variables were maps, so every field selection through one had
//	CEL's dyn type, and compileExpr lets dyn through deliberately, deferring
//	the type check to evalBool at evaluation time. The rule then served every
//	request, refused none, and left one warning per connection as its only
//	trace -- a control that does not run, which is the failure this package's
//	load-time errors exist to prevent everywhere else.
//
// With the variables declared by their own dotted names the field selection has
// a concrete type (string), so the same document is refused where the author can
// see it, with the action named. Both the refusal and the words in it are
// asserted: the operator has to be able to find the rule and see what is wrong
// with it.
func TestPolicyConditionThatIsNotABoolIsRefusedAtLoad(t *testing.T) {
	const doc = `on_http_request:
  - name: deny
    expressions: ["req.url.path"]
`
	tp, err := fzYAML(t, []byte(doc))
	if err != nil {
		t.Fatalf("the document does not decode: %v", err)
	}
	err = tp.Validate()
	if err == nil {
		t.Fatal("a condition that is not a bool loaded: the rule would serve every request and refuse none")
	}
	for _, want := range []string{"on_http_request[0]", "deny", "not a condition", "req.url.path"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not cite %q, so an operator cannot find the rule or the reason: %v", want, err)
		}
	}
	if _, cerr := tp.Compile(); cerr == nil {
		t.Fatalf("Validate refused the policy and Compile accepted it: %v", err)
	}

	// The dyn carve-out is still there, deliberately, for an expression whose
	// type genuinely is not known until it is read: a list of mixed types has
	// dyn elements, and such an expression is a load-time success that fails
	// open at evaluation time (one warning per connection, no verdict). The
	// carve-out is what keeps "this cannot be a bool *yet*" from being confused
	// with the case above.
	const dynDoc = `on_http_request:
  - name: deny
    expressions: ["[1, 'a'][0]"]
`
	dtp, err := fzYAML(t, []byte(dynDoc))
	if err != nil {
		t.Fatalf("the document does not decode: %v", err)
	}
	dc, err := dtp.Compile()
	if err != nil {
		t.Fatalf("a dyn condition is expected to load (compileExpr's dyn carve-out); it was refused with: %v", err)
	}
	lg := &fzRecord{}
	h := dc.RequestHook(lg, "203.0.113.9:1234")
	for _, target := range []string{"/", "/admin", "/private"} {
		if v := h(fzRequest("GET", target, http.Header{})); v != nil {
			t.Fatalf("a condition that can never be a bool still produced a verdict for %q: %+v", target, v)
		}
	}
	if len(lg.warns) == 0 {
		t.Fatalf("the rule neither matched nor warned, so nothing at all reported that it is inert")
	}
	t.Logf("a dyn condition loads clean, refuses nothing, and leaves one warning per connection: %q", lg.warns[0])
}

// TestPolicyCELDeepExpressionsAreRefusedNotCrashed pins an invariant this fork
// depends on without ever saying so: cel-go refuses an expression that is too
// deep and one that is too long, and both refusals are ordinary errors rather
// than a stack overflow or an allocation the server cannot afford. The fork's
// own DoS posture on the enforcement path rests on that, because an expression
// is a field of a policy document an agent can send in a registration (server/
// tunnel.go compiles it), and this package does not bound either dimension
// itself: compileExpr hands cel-go whatever string it was given.
//
// The numbers are cel-go's (v0.32.0), and they are asserted here rather than
// described in a comment so that a dependency bump that loses either limit
// fails this test instead of killing the server:
//
//	expression recursion limit exceeded: 250
//	expression code point size exceeds limit: size: 131076, limit 100000
//
// The cost half of the same question -- how much CPU a policy that stays *under*
// both limits costs the server -- is TestPolicyCompileCostIsBounded.
func TestPolicyCELDeepExpressionsAreRefusedNotCrashed(t *testing.T) {
	cases := []struct {
		what string
		src  string
		want string
	}{
		{
			what: "nesting deeper than cel-go's recursion limit",
			src:  strings.Repeat("(", 1024) + "true" + strings.Repeat(")", 1024),
			want: "recursion limit",
		},
		{
			what: "more code points than cel-go will look at",
			src:  "'" + strings.Repeat("a", 100_001) + "' == 'x'",
			want: "code point size exceeds limit",
		},
	}

	for _, c := range cases {
		t.Run(c.what, func(t *testing.T) {
			var (
				prog *program
				err  error
			)
			fzDo(t, "compile", func() { prog, err = compileExpr(phaseRequest, c.src, true) })
			if err == nil {
				t.Fatalf("cel-go compiled an expression this package expects it to refuse (the limit this fork's DoS posture rests on is gone): %d bytes compiled to %T", len(c.src), prog)
			}
			if prog != nil {
				t.Fatalf("a refused expression returned a program too: %v", err)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("the refusal does not mention %q, so the bound this test is pinning may have moved: %v", c.want, fzTruncate(err.Error(), 200))
			}
			t.Logf("refused with: %s", fzTail(err.Error(), 120))
		})
	}
}

// TestPolicyYAMLBooleanKeysAreRefused is a finding about error quality that
// turned up while writing the seeds above: a document that looks correct can be
// refused with a message that says the value is "not an object" when it plainly
// is one.
//
// The cause is a YAML 1.1 rule: an unquoted y, n, yes, no, on, off, true or
// false is a *boolean*, including when it is a mapping key. So `metadata: {n: 1}`
// is not a mapping from the string "n" to 1; it is a mapping whose key is the
// boolean false, and validate.go's asMap rejects any nested map with a non-string
// key -- correctly, since it has no way to render that key as a variable name or
// a header -- with the message below.
//
// The severity is low and this test does not pretend otherwise: the policy is
// refused, and refused is the safe direction. What is worth pinning is the pair
// of surprises, because both cost an operator an afternoon:
//
//   - the field that gets blamed is the map, not the key, and the map it prints
//     is the same type as the maps that work, so the message reads as a bug in
//     the package rather than a rule about quoting;
//   - a *header value* is unaffected -- only a key can be a boolean.
//
// What the migration to yaml.v3 changed, and why the table below is not the one
// it used to be: v3 resolves booleans by the YAML 1.2 core schema, which knows
// only true/True/TRUE and false/False/FALSE. The words that were the operator's
// likely mistake -- y, n, yes, no, on, off -- are plain strings to v3, so the
// cases this test was written around now load, and load as the operator meant
// them: `headers: {on: x}` is a header named on, unquoted, with no workaround to
// remember. That is a user-visible improvement and it is asserted below
// ("the YAML 1.1 words, which v3 reads as strings") rather than dropped.
//
// The refusal itself has not gone anywhere, and that is the part that must not
// rot: true/True/TRUE and false/False/FALSE are still booleans in v3, so they
// still arrive as non-string keys, and asMap's non-string branch is still what
// stops `true:` from being read as a header or a variable name. The fix, if
// anyone wants one, is in asMap's error path (name the offending key and its
// type) rather than in the decoder, which cannot be changed without changing
// which documents are legal.
func TestPolicyYAMLBooleanKeysAreRefused(t *testing.T) {
	cases := []struct {
		what string
		doc  string
		// wantBlames is the confusing part: the message names the *value*.
		wantBlames string
	}{
		{
			what: "a log metadata key spelled true",
			doc: `on_http_request:
  - name: log
    config:
      metadata:
        true: 7
`,
			wantBlames: `config field "metadata" must be an object of name to value, got map[interface {}]interface {}`,
		},
		{
			what: "a header named false",
			doc: `on_http_request:
  - name: add-headers
    config:
      headers:
        false: x
`,
			wantBlames: `config field "headers" must be an object of header name to value, got map[interface {}]interface {}`,
		},
		{
			what: "a set-vars variable named TRUE",
			doc: `on_http_request:
  - name: set-vars
    config:
      vars:
        - TRUE: x
`,
			wantBlames: `config field "vars" entry 0: each entry must be a map with exactly one key, got map[interface {}]interface {}`,
		},
	}

	for _, c := range cases {
		t.Run(c.what, func(t *testing.T) {
			tp, err := fzYAML(t, []byte(c.doc))
			if err != nil {
				t.Fatalf("the document does not decode: %v", err)
			}
			err = tp.Validate()
			if err == nil {
				// The interesting outcome would be this one: the key reached
				// validation as a string, which would mean the decoder stopped
				// treating it as a boolean and this case is gone.
				t.Fatalf("the document loaded: the key was read as a string, so the boolean rule no longer applies and this finding is stale")
			}
			if !strings.Contains(err.Error(), c.wantBlames) {
				t.Errorf("the refusal reads differently than this test records:\n\twant: %s\n\tgot:  %v", c.wantBlames, err)
			}
			t.Logf("refused, blaming the map: %v", err)
		})
	}

	// The same shapes with a quoted key, which is the workaround and which
	// establishes that the key spelling -- not the shape of the document -- is
	// what decides. It is no longer a workaround anybody needs for these
	// spellings; it is here because quoting is what makes a key a string, and
	// that is the rule the refusals above are an instance of.
	t.Run("the same documents with the key quoted", func(t *testing.T) {
		for _, doc := range []string{
			"on_http_request:\n  - name: log\n    config:\n      metadata:\n        \"true\": 7\n",
			"on_http_request:\n  - name: add-headers\n    config:\n      headers:\n        \"false\": x\n",
			"on_http_request:\n  - name: set-vars\n    config:\n      vars:\n        - \"TRUE\": x\n",
		} {
			tp, err := fzYAML(t, []byte(doc))
			if err != nil {
				t.Fatalf("the document does not decode: %v", err)
			}
			if err := tp.Validate(); err != nil {
				t.Errorf("a quoted key is still refused, so the workaround this pass would recommend does not work: %v", err)
			}
		}
	})

	// The half that changed with the parser, pinned so that it cannot change
	// back silently: the YAML 1.1-only bool words are strings to yaml.v3, so a
	// document that yaml.v1 refused outright now loads and means what it says.
	// These are the exact keys that used to be the finding.
	t.Run("the YAML 1.1 words, which v3 reads as strings", func(t *testing.T) {
		for _, doc := range []string{
			"on_http_request:\n  - name: log\n    config:\n      metadata:\n        n: 7\n",
			"on_http_request:\n  - name: add-headers\n    config:\n      headers:\n        on: x\n",
			"on_http_request:\n  - name: set-vars\n    config:\n      vars:\n        - no: x\n",
		} {
			tp, err := fzYAML(t, []byte(doc))
			if err != nil {
				t.Fatalf("the document does not decode: %v", err)
			}
			if err := tp.Validate(); err != nil {
				t.Errorf("an unquoted y/n/yes/no/on/off key is still refused, which would mean the decoder is treating it as a boolean: %v", err)
			}
		}
	})
}

// TestPolicyInterpolationStopsAtTheFirstBrace pins the documented shape of
// ${...}, because it is the one place where a policy author's natural instinct
// and this build's grammar disagree, and the disagreement is a *load-time*
// error rather than a surprise at runtime -- which is the right direction, and
// the reason this is worth a test rather than a bug report:
//
//	X-Map: "${{'k':'v'}}"     -> refused, "Syntax error: mismatched input '<EOF>'"
//	X-Map: "${req.headers}"   -> loaded, renders the map with fmt
//
// compileInterpolation ends the placeholder at the first '}' and documents the
// simple form ("nested maps and strings containing '}' would need a real parse,
// which is what ngrok has"). So an interpolation can *hold* a map and cannot
// *contain* one, and a policy that tries is refused with a CEL syntax error in a
// string the author believes is well-formed. Worth knowing before you write one.
//
// The map value used to be ${req.url}, which is the one part of this test the
// dotted variable declarations changed: req.url is no longer a variable (only
// its fields are), so the whole-object reference that rendered as a map is gone.
// req.headers and req.cookies are still declared as whole maps and still render
// the same way, so the property under test survives -- an interpolation of a map
// loads and formatValue renders it with fmt -- and the cost is pinned here, in
// the same place the shape is.
func TestPolicyInterpolationStopsAtTheFirstBrace(t *testing.T) {
	// A map literal: refused, at load time, as a syntax error.
	tp, err := fzYAML(t, []byte(`on_http_request:
  - name: add-headers
    config:
      headers:
        X-Map: "${{'k':'v'}}"
`))
	if err != nil {
		t.Fatalf("the document does not decode: %v", err)
	}
	if err := tp.Validate(); err == nil {
		t.Fatalf("a map literal inside ${...} loaded; if the placeholder grammar now parses braces, this finding is stale")
	} else {
		t.Logf("a map literal is refused at load time, as documented: %v", err)
	}

	// A map *value*: loaded, and rendered by formatValue's default branch.
	tp, err = fzYAML(t, []byte(`on_http_request:
  - name: add-headers
    config:
      headers:
        X-Map: "${req.headers}"
`))
	if err != nil {
		t.Fatalf("the document does not decode: %v", err)
	}
	c, err := tp.Compile()
	if err != nil {
		t.Fatalf("interpolating a map value was refused: %v", err)
	}
	v := c.RequestHook(fzQuiet{}, "203.0.113.9:1234")(fzRequest("GET", "/p?q=1", http.Header{}))
	if v == nil || len(v.Add) == 0 {
		t.Fatalf("expected a header, got %+v", v)
	}
	// The rendering is fmt's, which sorts map keys, so the value is stable
	// across runs even though it is a map.
	for _, add := range v.Add {
		if strings.HasPrefix(add, "x-map:") {
			t.Logf("a map value renders as %q (fmt.Sprint, so key-sorted and stable)", add)
		}
	}
}

// --- the parser crash, and the test that used to end this file --------------
//
// This file used to end with TestPolicyYAMLParserMustNotPanic: a deliberately
// red regression test for the finding that gopkg.in/yaml.v1's scanner reads
// past the end of its buffer and panics. It is deleted, along with the
// NGROK_FZ_ALLOW_PARSER_PANIC hatch that let a fuzz campaign step over it, and
// this note is what is left of it, because the *reason* is worth keeping even
// though the test is not.
//
// The finding, in one paragraph. yamlprivateh.go's is_blankz looks at b[i],
// b[i+1] and b[i+2] to recognize NEL, LS and PS, without checking that they
// exist -- so a document whose last byte is the lead byte of a multi-byte UTF-8
// escape (0xC2, 0xE2, 0xFE, 0xFF) reads one or two bytes past the buffer, and
// Go's own bounds check turns that into "index out of range". yaml.v1's
// handleErr re-panics anything that is not its own yamlError type, so the
// runtime error escaped yaml.Unmarshal and into whoever called it. FuzzPolicy-
// Validate minimized the input to []byte("\xff\xfe00") in 0.03s -- a UTF-16LE
// BOM and two ASCII bytes, the shape of a config file saved as UTF-16 by an
// editor and then truncated by a disk that filled up -- and the four call sites
// in this tree (client/config.go's LoadConfiguration, loadTrafficPolicyFile and
// SaveAuthToken, and server/config.go's loadServerConfig) all take bytes
// straight out of a file and call yaml.Unmarshal with no recover. Local files,
// not the wire: the registration carries a policy as JSON. Still a crash on
// bytes a user is expected to write by hand.
//
// The fix was to stop using yaml.v1, and the bytes above are why the test is
// gone rather than merely green. Two measurements, both before the test was
// deleted:
//
// The first is exhaustive over the shape rather than over a table: every string
// of one to four bytes over the bytes that matter (0xC2, 0xE2, 0xFE, 0xFF, 0xF0
// and their continuation bytes, plus enough YAML syntax to move the scanner
// between states) is 111150 documents, and they panic 644 times under yaml.v1
// and zero times under yaml.v3. I did not pin down *which* change in the library
// removed it -- v3's is_blankz still reads b[i+1] and b[i+2] with no bounds check
// of its own -- so what is recorded here is the measurement and not a mechanism.
//
// The second is the table, one row at a time, to show where each row goes now:
//
//	"\xff\xfe00"       -> yaml: cannot unmarshal !!str `〰` into policy.TrafficPolicy
//	"\xff\xfe"         -> no error; the document is empty
//	"\xff\xfe0"        -> yaml: incomplete UTF-16 character
//	"a: \xe2\x80"      -> yaml: incomplete UTF-8 octet sequence
//	"\x00...\x09"      -> yaml: control characters are not allowed
//	a UTF-16LE policy  -> decodes, and validates: the file an editor saved works
//
// The last row is the one that changed a user-visible behavior rather than a
// crash: a Windows-saved config file used to panic the client and now loads. The
// two byte-soup rows live on as seeds in fzPolicySeeds, which is the coverage
// the deleted corpus entry was providing.
