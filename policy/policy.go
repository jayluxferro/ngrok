// Package policy implements ngrok's traffic policy engine for this fork: the
// actions an operator writes in a policy document, evaluated at the edge
// (ngrokd) against the connection and the message heads flowing through it.
//
// A policy is a document with three phases, each holding an ordered list of
// rules. This build supports the cheap subset of ngrok's action set:
//
//	on_tcp_connect   restrict-ips, deny, log
//	on_http_request  add-headers, remove-headers, deny, custom-response, log, set-vars,
//	                 basic-auth, bearer-auth, apikey-auth, jwt-validation
//	on_http_response add-headers, remove-headers, log
//
// A rule is one action with an optional name and optional conditions:
//
//	on_http_request:
//	  - name: deny
//	    expressions:
//	      - "req.url.path.startsWith('/admin')"
//	    config:
//	      status_code: 403
//
// which is ngrok's rule shape flattened to one action per rule, so that the
// exported Action type stays what section 3.2 of the cluster-4 spec defines.
// The action *type* is the rule's `name`; the conditions are its
// `expressions`, all of which must hold (they are ANDed); `config` is the same
// object ngrok documents, field for field, for each action.
//
// Conditions are CEL, over the documented variable subset and nothing else:
//
//	conn.client_ip    string   source IP of the connection
//	conn.remote_addr  string   source address, "ip:port"
//	req.method        string   on_http_request
//	req.url.path      string   on_http_request, with its leading slash
//	req.url.query     string   on_http_request, without its "?"
//	req.url.raw       string   on_http_request, the request target as sent
//	req.headers       map[string]string, lower-cased names
//	req.cookies       map[string]string
//	res.status_code   int      on_http_response
//	vars              map[string]string, what set-vars stored in this phase
//
// Everything else ngrok exposes -- geo, TLS, endpoint, time, ip-intel, request
// bodies, the action result variables -- is deliberately absent, so that a
// policy written against it fails to load instead of quietly never matching.
// Each field in the table is declared in the CEL environment by its own dotted
// name (see cel.go for why), which is what makes that sentence true of *nested*
// names too: `conn.geo.country` and the typo `req.headerss` are compile errors
// at load time, not rules that never match. The cost is real and is stated in
// cel.go: the objects are not values, so `req.headers` is still a map
// (size(req.headers) and ${req.headers} work) while `conn` and `req.url` are
// not variables at all -- only their fields are.
//
// Config strings support ngrok's ${...} interpolation over the same variables.
//
// The package is built to fail open at runtime and loud at load time. Load
// time (Validate/Compile) is where an unknown action, a bad expression, a
// malformed CIDR, a config field with the wrong shape, a header value carrying
// a CR or an LF, or a document with more than maxActionsPerPolicy actions in
// total is an error naming the action: an operator must never believe a control
// is running when it is not, and the action cap is about the cost every
// message of every connection pays for the document (validate.go has the
// reasoning and the measured per-action number). Runtime is where nothing may
// break a connection the old code would have carried: an expression that fails
// to evaluate, a hook that panics, an interpolation with no value are all
// absorbed, logged once, and treated as "this action does not apply".
package policy

import (
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"

	"ngrok/log"
	"ngrok/rewriter"
)

// The action types this build implements. They are ngrok's own type strings,
// because they are what a policy document names.
const (
	ActionAddHeaders     = "add-headers"
	ActionRemoveHeaders  = "remove-headers"
	ActionDeny           = "deny"
	ActionCustomResponse = "custom-response"
	ActionLog            = "log"
	ActionSetVars        = "set-vars"
	ActionRestrictIPs    = "restrict-ips"

	// The request-phase authentication actions (SPEC-CLUSTER6). They are
	// terminators like deny, but they answer with the challenge their scheme
	// prescribes -- always a 401, never a configured status -- and they are
	// no-ops for a request that carries acceptable credentials.
	ActionBasicAuth     = "basic-auth"
	ActionBearerAuth    = "bearer-auth"
	ActionAPIKeyAuth    = "apikey-auth"
	ActionJWTValidation = "jwt-validation"
)

// phase is one of the three points in a connection's life a policy can act on.
type phase int

const (
	phaseConnect phase = iota
	phaseRequest
	phaseResponse
)

func (p phase) String() string {
	switch p {
	case phaseConnect:
		return "on_tcp_connect"
	case phaseRequest:
		return "on_http_request"
	case phaseResponse:
		return "on_http_response"
	}
	return "unknown"
}

// defaultDenyStatus is what the deny action answers with when its config does
// not say, for both HTTP phases and the connect phase.
const defaultDenyStatus = http.StatusForbidden

// defaultCustomResponseStatus is the custom-response action's default status
// code (ngrok's default is 200).
const defaultCustomResponseStatus = http.StatusOK

// defaultLogPrefix labels the log lines the package writes when a caller has no
// logger of its own: EvaluateConnect is called from the accept path, which has
// no connection logger yet.
var defaultLog = log.NewPrefixLogger("policy")

// TrafficPolicy is one endpoint's traffic policy, as it travels: the client
// parses it from its config file and sends it in the tunnel registration, and
// the server compiles and enforces it. Nil means "no policy at all", which is
// every pre-cluster-4 client and every endpoint that does not configure one.
type TrafficPolicy struct {
	OnTCPConnect   []*Action `yaml:"on_tcp_connect" json:"on_tcp_connect"`
	OnHTTPRequest  []*Action `yaml:"on_http_request" json:"on_http_request"`
	OnHTTPResponse []*Action `yaml:"on_http_response" json:"on_http_response"`
}

// Action is one rule: the action's type in Name, its conditions in Expressions,
// and the action's configuration in Config. The types are ngrok's own (they
// travel through a JSON envelope and a YAML config file), which is why every
// config value is an interface{}: the shape of Config depends on the action.
type Action struct {
	Name        string                 `yaml:"name" json:"name"`
	Expressions []string               `yaml:"expressions" json:"expressions"`
	Config      map[string]interface{} `yaml:"config" json:"config"`
}

// Compiled is a TrafficPolicy that has been checked and prepared: every
// expression is compiled, every config field is parsed, every CIDR is parsed
// into a net.IPNet. It is what the server stores on a tunnel and what the
// per-connection hooks are built from, and it is immutable and safe to share.
type Compiled struct {
	connect  []*compiledAction
	request  []*compiledAction
	response []*compiledAction
}

// compiledAction is one rule with everything it needs resolved once, at
// compile time, rather than per message. Only the fields the rule's action type
// uses are set; a config field for another type is rejected by validation
// before this is ever built.
type compiledAction struct {
	action string // one of the Action* constants
	where  string // "on_http_request[1] (deny)", the rule's identity in a phase

	when []*program // conditions; all must hold (they are ANDed)

	addHeaders    []headerPair  // add-headers, custom-response
	removeHeaders []string      // remove-headers
	statusCode    int           // deny, custom-response
	body          *interpolated // custom-response
	metadata      []headerPair  // log
	assignments   []assignment  // set-vars

	enforce     bool         // restrict-ips
	allow, deny []*net.IPNet // restrict-ips

	// auth carries the whole runtime of a request-phase authentication action
	// (basic-auth, bearer-auth, apikey-auth, jwt-validation): the digests of
	// the configured credentials, the prebuilt 401 challenge, and -- for
	// jwt-validation -- the parser and the JWKS cache. Only set for those four
	// action types; built by the same traversal that validates their config
	// (auth_actions.go, jwt.go), which is why a compiled policy holds no
	// credential material it does not need: the static-credential actions keep
	// only digests.
	auth authAction
}

// headerPair is one header a rule wants set: the name as configured and the
// value, which may carry ${...} interpolation.
type headerPair struct {
	name  string
	value *interpolated
}

// assignment is one set-vars entry. Values are strings in this build: the phase
// variable map is declared as map[string]string, so a list or a map has no type
// to live in.
type assignment struct {
	name  string
	value *interpolated
}

// Validate checks a policy without building the compiled form: every action
// name is implemented in the phase it appears in, every expression compiles
// (in that phase's variable set), and every config field has the shape and the
// values the action's documentation gives it. Errors name the action, so a
// typo in a policy document is a load-time failure with a line about the rule
// that caused it -- never a control that silently does nothing.
//
// A nil policy is valid: it is the absence of a policy, which is what every
// endpoint without one has.
func (tp *TrafficPolicy) Validate() error {
	_, err := tp.build()
	return err
}

// Compile validates the policy and returns the form the enforcement path uses:
// compiled expressions, parsed config, parsed CIDRs, and per-connection hooks.
// It is Validate with the compiled form kept, and the two share one traversal
// so that what is accepted and what is enforced cannot drift apart.
func (tp *TrafficPolicy) Compile() (*Compiled, error) {
	return tp.build()
}

// IsZero reports whether the policy has no rules at all, which lets a caller
// treat "an empty policy object" exactly like "no policy": there is nothing to
// enforce, and the connection takes the byte-identical path.
func (tp *TrafficPolicy) IsZero() bool {
	return tp == nil || (len(tp.OnTCPConnect) == 0 && len(tp.OnHTTPRequest) == 0 && len(tp.OnHTTPResponse) == 0)
}

// ConnectVerdict is what the on_tcp_connect phase decided about a connection,
// before any protocol bytes were read.
type ConnectVerdict struct {
	// Deny is true when a terminating action (deny, restrict-ips) refused the
	// connection. The caller closes it.
	Deny bool

	// Response is the response the edge fabricated, for a caller that is
	// speaking HTTP and can send one. It is nil when nothing was fabricated.
	// A TCP caller ignores it and closes the connection silently: there is no
	// protocol to answer in.
	Response *rewriter.SyntheticResponse

	// Reason is the human-readable ground for the verdict ("restrict-ips:
	// 203.0.113.9 matches denied CIDR 203.0.113.0/24"), for the log line the
	// caller writes.
	Reason string
}

// EvaluateConnect runs the on_tcp_connect rules against a connection's remote
// address ("ip:port") and reports whether the connection may proceed. It is
// called from the accept path, before the connection is handed to an agent.
//
// The connection has no HTTP request yet, so only conn.* variables exist in
// this phase, and only the three actions the phase documents are accepted:
// restrict-ips, deny and log.
func (c *Compiled) EvaluateConnect(connAddr string) ConnectVerdict {
	if c == nil || len(c.connect) == 0 {
		return ConnectVerdict{}
	}

	st := newEvalState(defaultLog, connAddr)
	act := st.connectActivation()

	for _, a := range c.connect {
		if !a.matches(act, st) {
			continue
		}
		switch a.action {
		case ActionLog:
			st.logLine(a, act)

		case ActionDeny:
			// The status comes off the compiled action, which is where the
			// config's status_code (or the default, when it names none) was
			// resolved at load time. Hardcoding the default here instead would
			// make "deny with status_code: 404" answer 403 -- a config the
			// operator wrote, validated, and never got -- and it is exactly the
			// drift the one-traversal rule exists to prevent: the HTTP phases
			// answer with a.statusCode, and this phase has to agree with them.
			st.info("deny: refusing the connection with status %d", a.statusCode)
			return ConnectVerdict{
				Deny:     true,
				Response: &rewriter.SyntheticResponse{StatusCode: a.statusCode},
				Reason:   "deny",
			}

		case ActionRestrictIPs:
			permitted, why := a.permits(st.ip)
			if permitted {
				continue
			}
			if !a.enforce {
				// enforce: false means "report, do not stop": the connection
				// continues to the next rule, which is how ngrok documents it.
				st.warnOnce(a, "traffic policy %s: %s would be refused (%s) but enforce is false", a.where, st.addr, why)
				continue
			}
			st.info("restrict-ips: refusing %s: %s", st.addr, why)
			return ConnectVerdict{
				Deny:     true,
				Response: &rewriter.SyntheticResponse{StatusCode: defaultDenyStatus},
				Reason:   "restrict-ips: " + why,
			}
		}
	}
	return ConnectVerdict{}
}

// permits applies the restrict-ips CIDR matrix to an address: a source is
// permitted when it matches no denied CIDR, and -- when any allow CIDR is
// configured -- at least one allowed one. A deny always wins over an allow,
// which is what "deny wins" means for an address that matches both.
func (a *compiledAction) permits(addr string) (bool, string) {
	ip := net.ParseIP(addr)
	if ip == nil {
		// An address we cannot parse is not something to guess about: no CIDR
		// contains it, so it matches no allow list and no deny list. With an
		// allow list configured that means refused; with only a deny list it
		// means permitted, which is what the lists literally say.
		if len(a.allow) > 0 {
			return false, fmt.Sprintf("source address %q is not an IP address", addr)
		}
		return true, ""
	}
	for _, n := range a.deny {
		if n.Contains(ip) {
			return false, fmt.Sprintf("%s matches denied CIDR %s", addr, n)
		}
	}
	if len(a.allow) == 0 {
		return true, "" // a deny list alone permits everything it does not name
	}
	for _, n := range a.allow {
		if n.Contains(ip) {
			return true, ""
		}
	}
	return false, fmt.Sprintf("%s matches no allowed CIDR", addr)
}

// RequestHook returns the rewriter hook for the on_http_request phase, or nil
// when the policy has no request actions -- in which case the rewriter does no
// hook work at all, which is what keeps the no-policy path byte-identical.
//
// The hook is bound to one connection: clientAddr is the public connection's
// remote address, which is what conn.client_ip and conn.remote_addr report, and
// the vars it accumulates belong to this connection's request phase (a value
// set on one request is not visible on the next). lg receives the log action's
// output and the fail-open warnings. The hook is called from the rewriter's
// request goroutine only, so it needs no locking: nothing here is shared with
// the response side.
func (c *Compiled) RequestHook(lg log.Logger, clientAddr string) func(*http.Request) *rewriter.RequestVerdict {
	if c == nil || len(c.request) == 0 {
		return nil
	}
	if lg == nil {
		lg = defaultLog
	}
	st := newEvalState(lg, clientAddr)
	return func(req *http.Request) *rewriter.RequestVerdict {
		st.next()
		return c.evalRequest(st, req)
	}
}

// ResponseHook is RequestHook for the on_http_response phase. Its variables are
// conn.*, res.* and this connection's response-phase vars; there is no request
// to describe, which is why req.* does not compile in this phase.
func (c *Compiled) ResponseHook(lg log.Logger, clientAddr string) func(*http.Response) *rewriter.ResponseVerdict {
	if c == nil || len(c.response) == 0 {
		return nil
	}
	if lg == nil {
		lg = defaultLog
	}
	st := newEvalState(lg, clientAddr)
	return func(resp *http.Response) *rewriter.ResponseVerdict {
		st.next()
		return c.evalResponse(st, resp)
	}
}

// evalRequest runs the on_http_request rules in order and returns what the
// rewriter should do about the request: header changes, or a synthetic response
// that replaces it. It returns nil when no action changed anything, which the
// rewriter treats exactly like a policy with no hook.
func (c *Compiled) evalRequest(st *evalState, req *http.Request) *rewriter.RequestVerdict {
	act := st.requestActivation(req)
	verdict := &rewriter.RequestVerdict{}
	changed := false

	for _, a := range c.request {
		if !a.matches(act, st) {
			continue
		}
		switch a.action {
		case ActionAddHeaders:
			for _, h := range a.addHeaders {
				verdict.Add = append(verdict.Add, headerEntry(h.name, h.value.eval(act, st.evalErr)))
			}
			changed = true

		case ActionRemoveHeaders:
			verdict.Remove = append(verdict.Remove, a.removeHeaders...)
			changed = true

		case ActionDeny:
			// A terminating action: nothing after it runs, and the request
			// never reaches the upstream.
			st.info("deny: %s %s refused with status %d", req.Method, requestTarget(req), a.statusCode)
			verdict.Terminate = &rewriter.SyntheticResponse{StatusCode: a.statusCode}
			return verdict

		case ActionBasicAuth, ActionBearerAuth, ActionAPIKeyAuth, ActionJWTValidation:
			// The authentication actions are terminators that take the same
			// path deny takes, with two differences the scheme fixes and no
			// config can change: the answer is always a 401 carrying the
			// challenge their scheme prescribes (spec section 4), and a request
			// that carries acceptable credentials is admitted as a no-op --
			// the action adds nothing and the later rules proceed. The
			// decision itself lives behind a.auth, built per action type at
			// load time; this line is the only place in the executor that
			// knows the actions exist, which is what keeps adding one of them
			// a validator-plus-implementation change and not a dispatch change.
			if ch := a.auth.authenticate(req, st); ch != nil {
				st.info("%s: %s %s refused with status %d", a.action, req.Method, requestTarget(req), ch.StatusCode)
				verdict.Terminate = ch
				return verdict
			}

		case ActionCustomResponse:
			st.info("custom-response: answering %s %s with status %d",
				req.Method, requestTarget(req), a.statusCode)
			verdict.Terminate = &rewriter.SyntheticResponse{
				StatusCode: a.statusCode,
				Headers:    a.renderHeaders(act, st),
				Body:       a.body.eval(act, st.evalErr),
			}
			return verdict

		case ActionLog:
			st.logLine(a, act)

		case ActionSetVars:
			for _, as := range a.assignments {
				st.vars[as.name] = as.value.eval(act, st.evalErr)
			}
		}
	}

	if !changed {
		return nil
	}
	return verdict
}

// evalResponse is evalRequest for the on_http_response phase. No response
// action in this build terminates -- none of them can: the response already
// exists, and the ones that could replace it (custom-response) are not
// implemented in this phase.
func (c *Compiled) evalResponse(st *evalState, resp *http.Response) *rewriter.ResponseVerdict {
	act := st.responseActivation(resp)
	verdict := &rewriter.ResponseVerdict{}
	changed := false

	for _, a := range c.response {
		if !a.matches(act, st) {
			continue
		}
		switch a.action {
		case ActionAddHeaders:
			for _, h := range a.addHeaders {
				verdict.Add = append(verdict.Add, headerEntry(h.name, h.value.eval(act, st.evalErr)))
			}
			changed = true

		case ActionRemoveHeaders:
			verdict.Remove = append(verdict.Remove, a.removeHeaders...)
			changed = true

		case ActionLog:
			st.logLine(a, act)
		}
	}

	if !changed {
		return nil
	}
	return verdict
}

// matches reports whether a rule's conditions hold. All of them must (they are
// ANDed, and ngrok documents the same), and an expression that fails to
// evaluate does not hold: the rule does not apply, the connection continues,
// and the failure is logged once so that a broken expression is visible without
// being able to break traffic.
func (a *compiledAction) matches(act map[string]interface{}, st *evalState) bool {
	for _, cond := range a.when {
		ok, err := cond.evalBool(act)
		if err != nil {
			st.warnOnce(a, "traffic policy %s: %v; the rule does not apply", a.where, err)
			return false
		}
		if !ok {
			return false
		}
	}
	return true
}

// renderHeaders renders a rule's configured headers, in a stable order (the
// config is a map, and a map has no order; sorting makes what is emitted the
// same on every run).
func (a *compiledAction) renderHeaders(act map[string]interface{}, st *evalState) []string {
	out := make([]string, 0, len(a.addHeaders))
	for _, h := range a.addHeaders {
		out = append(out, headerEntry(h.name, h.value.eval(act, st.evalErr)))
	}
	return out
}

// headerEntry renders one header the way a rewriter verdict expects it:
// "Key: value". A value that interpolation filled with a CR or LF is dropped at
// the wire by the rewriter, which is the last and only place that can be sure.
func headerEntry(name, value string) string {
	return name + ": " + value
}

// requestTarget names the request in a log line: the target as sent, so that a
// log line about a refused request says which request it was.
func requestTarget(req *http.Request) string {
	if req.RequestURI != "" {
		return req.RequestURI
	}
	if req.URL != nil {
		return req.URL.RequestURI()
	}
	return "/"
}

// evalState is the runtime context of one hook: the connection facts every
// phase shares, the vars of the message being evaluated, and where the log
// action and the fail-open warnings go.
//
// It is built once per connection per direction -- the vars are the only thing
// that changes per message, and next() resets them -- which is what lets the
// warning bookkeeping below be once-per-connection. The request and the
// response direction each have their own state, and each is driven by one
// goroutine in the rewriter, so nothing here needs a lock.
type evalState struct {
	lg   log.Logger
	addr string            // the connection's remote address, "ip:port"
	ip   string            // its IP part, which is what conn.client_ip means
	vars map[string]string // the message's set-vars values

	// interpWarned and ruleWarned make the fail-open warnings
	// once-per-connection: an expression that fails fails on every message, and
	// a log that repeats it a thousand times is a log nobody reads.
	interpWarned bool
	ruleWarned   map[string]bool
}

func newEvalState(lg log.Logger, connAddr string) *evalState {
	if lg == nil {
		lg = defaultLog
	}
	ip := connAddr
	if host, _, err := net.SplitHostPort(connAddr); err == nil {
		ip = host
	}
	return &evalState{lg: lg, addr: connAddr, ip: ip, vars: map[string]string{}}
}

// next starts a new message. The phase's vars belong to one message: a value
// set-vars stored while the previous request was handled is gone, which is what
// makes ${vars.x} mean "set earlier in this message" and nothing more. The
// warning bookkeeping is deliberately not reset here.
func (st *evalState) next() {
	st.vars = map[string]string{}
}

// connectActivation is the variable set of the on_tcp_connect phase: a
// connection and nothing else.
func (st *evalState) connectActivation() map[string]interface{} {
	return st.connActivation()
}

// requestActivation is the variable set of the on_http_request phase.
func (st *evalState) requestActivation(req *http.Request) map[string]interface{} {
	path, query, raw := "", "", ""
	if req.URL != nil {
		path, query = req.URL.Path, req.URL.RawQuery
		raw = req.URL.RequestURI()
	}
	if req.RequestURI != "" {
		// The target as it arrived, which is what "raw" means: a proxy that
		// was asked for an absolute URI gets that URI, not the normalized one.
		raw = req.RequestURI
	}

	act := st.connActivation()
	act["req.method"] = req.Method
	act["req.url.path"] = path
	act["req.url.query"] = query
	act["req.url.raw"] = raw
	act["req.headers"] = headerMap(req.Header)
	act["req.cookies"] = cookieMap(req)
	act["vars"] = st.vars
	return act
}

// responseActivation is the variable set of the on_http_response phase.
func (st *evalState) responseActivation(resp *http.Response) map[string]interface{} {
	act := st.connActivation()
	act["res.status_code"] = resp.StatusCode
	act["vars"] = st.vars
	return act
}

// connActivation is what every phase has in common: the connection's own
// variables. They are *flat dotted keys*, not a nested conn object, because
// that is what the environment declares (cel.go): "conn.client_ip" is one
// variable name to CEL, so it is one key here. A nested map under "conn" is
// what this used to provide, and against the dotted declarations it would
// activate nothing -- every conn.* expression would fail to resolve at
// evaluation time and every conn.* rule would silently not apply, which is the
// failure mode the dotted declarations exist to make impossible. The two have
// to move together, so they live next to each other: the names here and the
// cel.Variable calls there are one list written twice, and a test in this
// package compares them.
func (st *evalState) connActivation() map[string]interface{} {
	return map[string]interface{}{
		"conn.client_ip":   st.ip,
		"conn.remote_addr": st.addr,
	}
}

// headerMap lower-cases the names, which is the shape the documented req.headers
// variable has, and joins repeated fields with ", " so that a header sent
// twice is still one string: this build's req.headers is map[string]string,
// while ngrok's is map[string][]string.
func headerMap(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for name, values := range h {
		out[strings.ToLower(name)] = strings.Join(values, ", ")
	}
	return out
}

// cookieMap is the req.cookies variable: cookie name to value. A name sent
// twice keeps its last value, for the same reason headerMap joins.
func cookieMap(req *http.Request) map[string]string {
	out := map[string]string{}
	for _, c := range req.Cookies() {
		out[c.Name] = c.Value
	}
	return out
}

// logLine is the log action: a structured line carrying the rule's metadata,
// with every value interpolated, at INFO. The metadata is a map in the config,
// so its keys are sorted to make the line stable.
func (st *evalState) logLine(a *compiledAction, act map[string]interface{}) {
	if st.lg == nil {
		return
	}
	fields := make([]string, 0, len(a.metadata))
	for _, m := range a.metadata {
		fields = append(fields, fmt.Sprintf("%s=%q", m.name, m.value.eval(act, st.evalErr)))
	}
	st.lg.Info("traffic policy log action %s %s", a.where, strings.Join(fields, " "))
}

// info logs a policy decision (a refusal, a synthetic answer) on the connection
// the policy was evaluated for.
func (st *evalState) info(format string, args ...interface{}) {
	st.lg.Info(format, args...)
}

// warnOnce reports a runtime failure of one rule, once per connection: the same
// expression failing on every message is one bug, and this is the fail-open
// rule made visible.
func (st *evalState) warnOnce(a *compiledAction, format string, args ...interface{}) {
	st.warnOnceAbout(a.where, format, args...)
}

// warnOnceAbout is warnOnce for a failure whose identity is a rule's where
// string rather than a compiledAction at hand (the auth actions carry their
// where as a plain field). Same bookkeeping, same once-per-connection rule.
func (st *evalState) warnOnceAbout(key, format string, args ...interface{}) {
	if st.ruleWarned == nil {
		st.ruleWarned = map[string]bool{}
	}
	if st.ruleWarned[key] {
		return
	}
	st.ruleWarned[key] = true
	st.lg.Warn(format, args...)
}

// evalErr is the callback an interpolation uses when one of its expressions
// fails: the placeholder is replaced with nothing, and the connection is
// otherwise unaffected.
func (st *evalState) evalErr(err error) {
	if st.interpWarned {
		return
	}
	st.interpWarned = true
	st.lg.Warn("traffic policy interpolation: %v; the placeholder was left empty", err)
}

// sortedKeys is the deterministic order this package renders config maps in.
func sortedKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
