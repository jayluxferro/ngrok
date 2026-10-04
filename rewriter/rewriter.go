// Package rewriter rewrites the HTTP heads that flow through an ngrok tunnel
// while leaving everything else on the wire byte-identical.
//
// Two per-direction state machines (see streamRewriter) parse just enough of
// the stream to find each message head, apply the tunnel's header Policy, and
// copy the rest -- bodies, chunk framing, trailers, websocket frames -- through
// untouched. They are read-driven: no extra goroutines, no buffering beyond
// each direction's pooled 64 KiB read buffer (see readBufPool), and no bytes
// produced before the caller asks for them, so back-pressure is exactly what
// the raw connection had.
//
// The rule that keeps this safe on a live tunnel is fail-open: anything the
// machines cannot make sense of (a head past 64 KiB, a malformed start line, a
// truncated message, a chunk-size line that is not hex) stops the parsing and
// hands that direction back to a raw byte copy, after emitting every byte that
// has already been read. A connection the old code would have carried keeps
// working; it just stops being rewritten.
//
// One transformation does touch a body. With Policy.Compress set, a response the
// client asked for gzip on -- and that is not a HEAD, a bodyless status, an
// already-encoded message, a byte-range answer or a type that does not compress
// -- is streamed through a gzip.Writer and re-framed as chunked (see the gzip
// transform section below). It is the only place this package re-frames
// anything: the input's framing is still read, not re-encoded, and every
// response the transform declines keeps the byte-identical identity path.
package rewriter

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/textproto"
	"strconv"
	"strings"
	"sync"

	"ngrok/log"
)

const (
	// readBufferSize is the size of each direction's connection-lifetime read
	// buffer, the backing array pooled in readBufPool. Every read goes through
	// it, including the raw copies, so bytes that arrive bundled with a head
	// (a head and the first body bytes usually share a TCP segment) stay in
	// order across a phase change.
	readBufferSize = 64 * 1024

	// maxHeadBytes caps a single request or response head. Past it we stop
	// trying to understand the stream and fail open.
	maxHeadBytes = 64 * 1024

	// copyChunk is how much body a state-machine step moves on the paths that
	// cannot hand the caller's buffer straight to the source. Raw and
	// content-length copies avoid it entirely (see directRead).
	copyChunk = 32 * 1024
)

// errLineTooLong reports a line that does not fit in the 64 KiB read buffer.
// No valid HTTP framing line here is that long.
var errLineTooLong = errors.New("line longer than the 64 KiB read buffer")

// Policy is the per-tunnel header policy, built from config + StartProxy
// metadata. Add/Remove entries are ordered slices; add entries are "Key: value"
// strings.
type Policy struct {
	HostHeader string // "", "rewrite", "preserve", or explicit host

	// Compress turns on the response-side gzip transform (spec 3.4). It is a
	// wish, not an instruction: whether any given response is compressed is
	// decided per response by gzipEligible, so a client that cannot take gzip
	// still gets a byte-identical response on the same connection.
	Compress bool

	RequestHeaderAdd     []string // "Key: value" pairs, append semantics
	RequestHeaderRemove  []string // header names
	ResponseHeaderAdd    []string
	ResponseHeaderRemove []string

	UpstreamHost string // hostname of tunnel.LocalAddr, for "rewrite"
	ClientAddr   string // from StartProxy.ClientAddr

	XForwardedProto string // "http" | "https"

	// RequestHook and ResponseHook are the extension points of the traffic
	// policy engine (spec cluster 4, 3.1): the policy package implements them,
	// this package only knows when to call them. Both are nil-safe -- a nil
	// hook, or a hook returning a nil verdict, leaves the head exactly as the
	// static policy left it -- and both are called with a head-only object
	// built from the parsed head bytes.
	//
	// The objects are built with http.ReadRequest / http.ReadResponse over the
	// head bytes alone, so the body fields are not meaningful: the stream is
	// still sitting in this connection's buffer and is copied, or not, after
	// the verdict is applied. For a request only Method, URL, Host, Header and
	// Proto are populated; for a response only StatusCode, Header and Proto
	// are. Anything else on the object -- Body, ContentLength, RemoteAddr,
	// RequestURI, TLS -- is the zero value that reader produced, not something
	// read from the wire.
	//
	// RequestHook may also terminate the request (see RequestVerdict): the
	// connection is answered from the edge, the request never reaches the
	// upstream, and the rest of the connection is closed rather than parsed.
	RequestHook  func(req *http.Request) *RequestVerdict
	ResponseHook func(resp *http.Response) *ResponseVerdict
}

// SyntheticResponse is a response the edge fabricates without consulting the
// upstream: what a terminating traffic policy action (deny, custom-response, a
// restrict-ips rejection) sends back to a public client.
//
// It is rendered as one complete HTTP/1.1 message -- status line, Headers,
// Content-Length, Connection: close, Body -- because the connection ends with
// it. Headers are "Key: value" entries, the same shape an add entry has; a
// Content-Length or Connection entry of the caller's is ignored, since the
// renderer writes its own. A zero StatusCode renders as 403.
type SyntheticResponse struct {
	StatusCode int
	Headers    []string // "Key: value"
	Body       string
}

// RequestVerdict is what a request hook returns: what to change about the
// request head, or that the request must not be forwarded at all.
type RequestVerdict struct {
	// Terminate, when non-nil, means the request is answered by the edge: the
	// head is not forwarded, the client gets this response instead, and the
	// connection is closed after it. Nothing else in the verdict is applied.
	Terminate *SyntheticResponse

	// Add entries ("Key: value") are appended after the static policy's own
	// adds; Remove names are dropped case-insensitively, before those adds.
	Add    []string
	Remove []string
}

// ResponseVerdict is what a response hook returns: what to change about the
// response head. Add entries are appended after the static policy's, Remove
// names are dropped case-insensitively before them.
type ResponseVerdict struct {
	Add    []string
	Remove []string
}

// Render renders a synthetic response as one complete HTTP/1.1 message. It is
// what the rewriter emits for a terminated request, and what a server writes
// for a connection its connect phase refused, so both paths produce the same
// bytes for the same verdict.
//
// HTTP/1.1 is used whatever the request's version was: every response field
// here (Content-Length, Connection: close) is defined the same way in 1.0, and
// a 1.0 client reads the message by its Content-Length regardless of the
// version we name.
//
// Entries that Validate would have rejected -- an unsplittable string, a name
// that is not a token, a value with a CR or LF in it -- are dropped rather than
// emitted: this is the last place before the wire, and a smuggled CRLF would be
// a response splitting bug, not a misconfiguration.
func (s *SyntheticResponse) Render() []byte {
	status := s.statusCode()
	out := make([]byte, 0, 128+len(s.Body))
	out = append(out, "HTTP/1.1 "...)
	out = strconv.AppendInt(out, int64(status), 10)
	out = append(out, ' ')
	out = append(out, http.StatusText(status)...)
	out = append(out, '\r', '\n')
	for _, entry := range s.Headers {
		name, value, ok := splitAddEntry(entry)
		if !ok || !ValidHeaderToken(name) || !ValidHeaderValue(value) {
			continue
		}
		if strings.EqualFold(name, "content-length") || strings.EqualFold(name, "connection") {
			continue // framing is ours to write, and only one of each is allowed
		}
		out = appendHeaderLine(out, name, value)
	}
	out = appendHeaderLine(out, "Content-Length", strconv.Itoa(len(s.Body)))
	out = appendHeaderLine(out, "Connection", "close")
	out = append(out, '\r', '\n')
	return append(out, s.Body...)
}

// statusCode is the status this response is rendered with: Render's own default
// of 403 for a zero. It is a method so that everything that describes the
// response to someone else -- Render, and the head a response hook is asked
// about (syntheticHead) -- agrees on what the client will actually receive. The
// zero is what a deny action carries when its config names no status_code.
func (s *SyntheticResponse) statusCode() int {
	if s.StatusCode == 0 {
		return http.StatusForbidden
	}
	return s.StatusCode
}

// syntheticHead builds the head-only *http.Response that a response hook is
// asked about when the response is one the edge fabricated rather than one read
// from the upstream (emitSynthetic). net/http would have canonicalized the field
// names had the message come off the wire, so the same canonicalization is
// applied here and repeated fields are kept as separate values; the framing
// headers are not part of it, because the renderer writes those itself.
func syntheticHead(s *SyntheticResponse) *http.Response {
	header := make(http.Header, len(s.Headers))
	for _, entry := range s.Headers {
		name, value, ok := splitAddEntry(entry)
		if !ok {
			continue // Render drops these too; a hook should not see them either
		}
		header.Add(textproto.CanonicalMIMEHeaderKey(name), value)
	}
	return &http.Response{
		StatusCode: s.statusCode(),
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     header,
	}
}

// Validate checks the policy for CR/LF injection, user-agent targets and
// malformed add entries. Errors name the offending entry, so a typo'd config
// fails loudly at load time instead of silently mangling traffic later.
//
// This is the one gate for a Policy, whatever built it: the client's config
// loader validates the header fields of every tunnel by building the Policy it
// would run and calling this (client/config.go, validateHeaderPolicy), so the
// rules a config has to satisfy and the rules the rewriter relies on at runtime
// are the same rules, checked by the same function. The alternative -- the
// rules spelled again in the loader -- is what let a policy the runtime
// refuses to compile load as a startup success; see the fuzzing report's R1,
// which this closes.
func (p *Policy) Validate() error {
	if err := ValidateHostHeader(p.HostHeader); err != nil {
		return err
	}

	// Header values that come from policy fields (rather than from config file
	// entries) are built by the client, but they still end up on the wire as
	// field values: reject CR/LF here too rather than trusting the caller.
	for _, f := range []struct{ name, value string }{
		{"upstream_host", p.UpstreamHost},
		{"client_addr", p.ClientAddr},
		{"x_forwarded_proto", p.XForwardedProto},
	} {
		if !ValidHeaderValue(f.value) {
			return fmt.Errorf("%s %q must not contain CR or LF", f.name, f.value)
		}
	}

	for _, entry := range p.RequestHeaderAdd {
		if err := ValidateAddEntry("request_header", entry); err != nil {
			return err
		}
	}
	for _, entry := range p.ResponseHeaderAdd {
		if err := ValidateAddEntry("response_header", entry); err != nil {
			return err
		}
	}
	for _, name := range p.RequestHeaderRemove {
		if err := ValidateRemoveName("request_header", name); err != nil {
			return err
		}
	}
	for _, name := range p.ResponseHeaderRemove {
		if err := ValidateRemoveName("response_header", name); err != nil {
			return err
		}
	}
	// Compress needs no rule here. It is a bool, and every byte the gzip
	// transform writes for it -- "Content-Encoding: gzip", "Vary:
	// Accept-Encoding", "Transfer-Encoding: chunked", the chunk framing -- is a
	// constant this package builds, never caller input, so unlike HostHeader or
	// an add entry there is no field value for a CR/LF to hide in. What it
	// changes on the wire is decided per response by the skip matrix, not by
	// configuration.
	return nil
}

// IsNoop reports whether the policy performs no transformation at all, which
// lets the client skip wrapping the connection altogether.
//
// Note that the automatic X-Forwarded injection (spec 4.3) counts as a
// transformation: a policy built for a live HTTP tunnel always carries
// ClientAddr and XForwardedProto, so it is never a no-op even when no header
// flags were set. Only a policy with nothing in it at all -- or one that says
// "preserve" and nothing else -- is a no-op.
func (p *Policy) IsNoop() bool {
	if p.RequestHook != nil || p.ResponseHook != nil {
		// A hook is a transformation whether or not this connection's verdict
		// turns out to change anything: what it will do is only known per
		// message, and the wrapping it needs -- the terminate channel, the
		// drain phase -- is not something to build on demand later.
		return false
	}
	if len(p.RequestHeaderAdd) > 0 || len(p.RequestHeaderRemove) > 0 ||
		len(p.ResponseHeaderAdd) > 0 || len(p.ResponseHeaderRemove) > 0 {
		return false
	}
	if p.ClientAddr != "" || p.XForwardedProto != "" {
		return false
	}
	if p.Compress {
		// The gzip transform is a body transformation: whether it fires depends on
		// the response and on what the request asked for, but a policy that asks
		// for it can never be skipped.
		return false
	}
	switch strings.ToLower(p.HostHeader) {
	case "", "preserve":
		return true
	}
	return false
}

// ValidateHostHeader checks a host_header configuration value: the two
// keywords, or an explicit hostname that cannot be used to inject a header
// (spec 4.1). The keywords are matched case-insensitively; any other non-empty
// value is taken as the hostname to send, so "REWRITE" is not reachable as a
// host.
//
// It is exported because the value is validated in two places that must agree:
// here, where it becomes a Host header on the wire, and in the client's config
// loader, where the user wrote it (client/config.go). A value the loader
// accepts and this rejects (or the reverse) is a tunnel that either fails to
// load for no reason or rewrites a Host no upstream will match.
func ValidateHostHeader(v string) error {
	switch strings.ToLower(v) {
	case "", "rewrite", "preserve":
		return nil
	}
	if strings.ContainsAny(v, " \t\r\n/") {
		return fmt.Errorf("invalid host_header %q: must be 'rewrite', 'preserve' or a hostname with no spaces, no '/' and no CR/LF", v)
	}
	return nil
}

// ValidateAddEntry checks one "Key: value" header entry as a user writes it: in
// a policy's add list, or in a config file's request_header/response_header
// add list. It must split at a colon, carry a field name that is an RFC 7230
// token, must not be user-agent, and must not smuggle a CR or LF onto the wire.
//
// scope names the list the entry came from ("request_header", "response_header",
// ...) so the error says which one to edit. Exported for the same reason
// ValidateHostHeader is: the config loader and this package have to agree on
// what an entry may say, and the rules used to exist as three copies -- one per
// caller -- which is how a value that loads can stop being one that runs.
func ValidateAddEntry(scope, entry string) error {
	if err := validateNoCRLF(scope, "add", entry); err != nil {
		return err
	}

	colon := strings.IndexByte(entry, ':')
	if colon < 0 {
		return fmt.Errorf("%s add entry %q must be formatted as 'key:value'", scope, entry)
	}

	name := strings.TrimSpace(entry[:colon])
	if name == "" {
		return fmt.Errorf("%s add entry %q has an empty header name", scope, entry)
	}
	if !ValidHeaderToken(name) {
		return fmt.Errorf("%s add entry %q: %q is not a valid HTTP header name", scope, entry, name)
	}
	if strings.EqualFold(name, "user-agent") {
		return fmt.Errorf("%s add entry %q: user-agent may not be added or removed (ngrok parity)", scope, entry)
	}

	// The value keeps everything after the first colon -- "X-Url: http://h" is
	// one entry -- and its own CR/LF check is the whole-entry one above.
	return nil
}

// ValidateRemoveName checks a header name a caller wants dropped, on the same
// terms as ValidateAddEntry.
func ValidateRemoveName(scope, name string) error {
	if err := validateNoCRLF(scope, "remove", name); err != nil {
		return err
	}

	if name == "" {
		return fmt.Errorf("%s remove entry %q has an empty header name", scope, name)
	}
	if !ValidHeaderToken(name) {
		return fmt.Errorf("%s remove entry %q is not a valid HTTP header name", scope, name)
	}
	if strings.EqualFold(name, "user-agent") {
		return fmt.Errorf("%s remove entry %q: user-agent may not be added or removed (ngrok parity)", scope, name)
	}

	return nil
}

// validateNoCRLF is the header-injection guard for a configured entry: nothing
// written in a list may contain a CR or an LF, wherever in the string it
// appears. verb is the list's operation ("add"/"remove"), for the message.
func validateNoCRLF(scope, verb, entry string) error {
	if !ValidHeaderValue(entry) {
		return fmt.Errorf("%s %s entry %q contains a CR or LF (header injection)", scope, verb, entry)
	}

	return nil
}

// splitAddEntry splits a "Key: value" policy entry at its first colon. The
// value keeps everything after it, so colons in values ("X-Url: http://h") are
// fine. Surrounding whitespace is trimmed; ok is false for entries that cannot
// be split at all, which Validate rejects.
func splitAddEntry(entry string) (name, value string, ok bool) {
	i := strings.IndexByte(entry, ':')
	if i <= 0 {
		return "", "", false
	}
	return strings.TrimSpace(entry[:i]), strings.TrimSpace(entry[i+1:]), true
}

// ValidHeaderValue reports whether v may be written as an HTTP field value:
// everything except CR and LF, which are the two bytes that end a field line
// and therefore the two that turn a value into a second, attacker-chosen
// header. Every check of a configured value in this repository is this rule --
// the add-list entries here, the headers map of a policy's add-headers action,
// the interpolated values the hooks produce -- so it is exported and spelled
// once.
func ValidHeaderValue(v string) bool {
	return !strings.ContainsAny(v, "\r\n")
}

// ValidHeaderToken reports whether s is a non-empty RFC 7230 token, the only
// thing a header name may be -- on the wire, in a policy's add list, in a
// config file's header lists, and as the name a policy wants removed.
//
// Exported because that last part is not this package's private business: the
// grammar is the protocol's, and a caller that accepts a name this would refuse
// (or the reverse) is a header that either never reaches the upstream or does
// so under a name nobody validated.
func ValidHeaderToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return true
}

// headerAdd is one pre-parsed add entry: the name already canonicalized for the
// wire (4.2) and the value ready to emit.
type headerAdd struct {
	name  string
	value string
}

// hookRewrite is one hook verdict merged into the static policy for the head
// being emitted: the names it drops, the entries it appends after the policy's
// own, and (requests only) a Host override. A nil *hookRewrite is the
// no-hook case and is what keeps a policy without hooks on exactly the bytes it
// emitted before this existed.
//
// It is rebuilt per message rather than cached: a verdict is a function of the
// message, which is the whole point of the hook.
type hookRewrite struct {
	// terminate is set when the request hook refused the request. It carries no
	// rewrite: the head is never emitted, so there is nothing to merge into it.
	// It is how the verdict travels from the point that asked for it (stepHead's
	// hookRewrite) to the point that can carry it out (stepHead itself, which
	// publishes it and switches to the drain phase).
	terminate *SyntheticResponse

	removes map[string]bool
	adds    []headerAdd
	host    string
}

// drops reports whether the hook removes a header, by its lowercased name.
func (h *hookRewrite) drops(lower string) bool {
	return h != nil && h.removes[lower]
}

// newHookRewrite compiles a verdict's Add/Remove entries. hostOverride says
// whether a "host" entry means "replace the Host header" (requests, as for a
// static add entry, 4.2) or is just another field to append (responses).
//
// Entries that are not usable -- no colon, a name that is not a token, a value
// carrying a CR or LF -- are dropped. The policy package is where such an entry
// is an error; by the time it reaches the wire the only safe thing to do with
// one is not to write it.
func newHookRewrite(add, remove []string, hostOverride bool) *hookRewrite {
	h := &hookRewrite{}
	if len(remove) > 0 {
		h.removes = lowerSet(remove)
	}
	for _, entry := range add {
		name, value, ok := splitAddEntry(entry)
		if !ok || !ValidHeaderToken(name) || !ValidHeaderValue(value) {
			continue
		}
		if hostOverride && strings.EqualFold(name, "host") {
			h.host = value
			continue
		}
		h.adds = append(h.adds, headerAdd{name: textproto.CanonicalMIMEHeaderKey(name), value: value})
	}
	return h
}

// compiledPolicy is the per-connection view of a Policy: entries are split,
// canonicalized and lowercased once when the connection is wrapped instead of
// once per request, and the X-Forwarded wiring is resolved into plain values.
// It is immutable afterwards and shared by both directions.
type compiledPolicy struct {
	reqRemoves  map[string]bool
	respRemoves map[string]bool
	reqAdds     []headerAdd
	respAdds    []headerAdd

	// compress is Policy.Compress, copied out of the Policy so that the gzip
	// switch is read once per connection rather than through a pointer on the
	// per-response path.
	compress bool

	// hostValue is the Host to put on requests; "" leaves Host alone (4.1).
	hostValue string

	// xffValue and xfpValue are the values to inject as X-Forwarded-For and
	// X-Forwarded-Proto; "" injects nothing (4.3).
	xffValue string
	xfpValue string

	// reqHook and respHook are Policy's extension hooks, nil when the policy
	// has none. They are copied out of the Policy so that both directions read
	// them from the one compiled value they already share.
	reqHook  func(req *http.Request) *RequestVerdict
	respHook func(resp *http.Response) *ResponseVerdict
}

// compilePolicy precomputes everything the per-request path needs. lg receives
// the one-off warnings about entries that cannot be used at all; Validate is the
// real gate, but a policy that skipped validation must not silently rewrite
// traffic either.
func compilePolicy(p *Policy, lg log.Logger) *compiledPolicy {
	cp := &compiledPolicy{
		reqRemoves:  lowerSet(p.RequestHeaderRemove),
		respRemoves: lowerSet(p.ResponseHeaderRemove),
		compress:    p.Compress,
		xffValue:    p.ClientAddr,
		xfpValue:    p.XForwardedProto,
		reqHook:     p.RequestHook,
		respHook:    p.ResponseHook,
	}

	var hostOverride string
	cp.reqAdds, hostOverride = compileAdds("request_header", p.RequestHeaderAdd, lg, true)
	cp.respAdds, _ = compileAdds("response_header", p.ResponseHeaderAdd, lg, false)

	cp.hostValue = resolveHost(p.HostHeader, p.UpstreamHost)
	if hostOverride != "" {
		cp.hostValue = hostOverride // 4.2: a host add entry overrides, never appends
	}

	// The headers we inject replace whatever the public client sent: a spoofed
	// X-Forwarded-For must not survive next to the real one (4.3).
	if cp.xffValue != "" {
		cp.reqRemoves["x-forwarded-for"] = true
	}
	if cp.xfpValue != "" {
		cp.reqRemoves["x-forwarded-proto"] = true
	}
	if cp.hostValue != "" {
		cp.reqRemoves["x-forwarded-host"] = true
	}
	return cp
}

// resolveHost turns the 4.1 host_header setting into the value to send, or ""
// to leave the request's Host alone. A "rewrite" with no UpstreamHost to rewrite
// to leaves the Host alone rather than emptying it; config validation is where
// that combination gets flagged.
func resolveHost(hostHeader, upstreamHost string) string {
	switch strings.ToLower(hostHeader) {
	case "", "preserve":
		return ""
	case "rewrite":
		return upstreamHost
	}
	return hostHeader
}

// compileAdds splits add entries and canonicalizes their names. hostOverrides
// says whether a "host" entry means "set the Host header" (requests, 4.2) or is
// just another field to append (responses, which carry no Host semantics).
func compileAdds(scope string, entries []string, lg log.Logger, hostOverrides bool) (adds []headerAdd, hostValue string) {
	for _, entry := range entries {
		name, value, ok := splitAddEntry(entry)
		if !ok || !ValidHeaderToken(name) || !ValidHeaderValue(value) {
			lg.Warn("%s add entry %q is not usable; ignoring it", scope, entry)
			continue
		}
		if hostOverrides && strings.EqualFold(name, "host") {
			hostValue = value
			continue
		}
		adds = append(adds, headerAdd{name: textproto.CanonicalMIMEHeaderKey(name), value: value})
	}
	return adds, hostValue
}

// lowerSet builds the case-insensitive match set header removal needs.
func lowerSet(names []string) map[string]bool {
	set := make(map[string]bool, len(names))
	for _, n := range names {
		set[strings.ToLower(strings.TrimSpace(n))] = true
	}
	return set
}

// side says which direction a state machine is driving. It selects the head
// syntax (request line vs status line) and the half of the policy that applies.
type side int

const (
	sideRequest side = iota
	sideResponse
)

// state is where a direction sits in the framing of the message it is copying.
type state int

const (
	stHead         state = iota // assembling a head
	stBodyCL                    // copying a Content-Length body
	stChunkSize                 // reading a chunk-size line
	stChunkData                 // copying chunk data
	stChunkDataEnd              // copying the CRLF that closes a chunk
	stChunkTrailer              // reading trailer lines up to the blank line
	stRaw                       // unparsed passthrough until EOF
	stGzipClose                 // feeding a close-delimited body to the gzip stream
	stDrain                     // request terminated: the source is read and discarded
	stDone                      // a synthetic response was this direction's last message
)

// connState is the state one connection's two directions share. The request and
// response machines run in different goroutines (conn.Join copies each direction
// on its own), so every field is mutex-guarded.
type connState struct {
	mu sync.Mutex

	// lastMethod is the request method; the response side needs it to know that
	// a HEAD response has no body. One slot covers every shape a tunnel actually
	// sees. The known limit is a client that pipelines two requests before the
	// first response comes back: the slot then holds the newer method. The
	// failure mode is a mis-framed response, not a lost byte -- and the response
	// side mis-frames into fail-open, which copies bytes rather than guessing.
	lastMethod string

	// reqAcceptsGzip, reqHasRange and reqChunkedOK are the gzip transform's
	// inputs, read off the request side for the response side: whether the
	// client's Accept-Encoding named gzip, whether it sent a Range, and whether
	// it arrived on a version that can parse the chunked framing the transform
	// emits. They are one slot, with lastMethod's limitation and its safe
	// failure mode: a client that pipelines two requests has them described by
	// the newer one, which can cost a compression opportunity (an identity
	// response nobody minds) but can never mis-frame a response -- the version
	// and bodyless-status checks that keep the framing valid are per response.
	reqAcceptsGzip bool
	reqHasRange    bool
	reqChunkedOK   bool

	// upgraded records an upgrade handshake: either a request carried
	// Connection: upgrade plus an Upgrade field (that side goes raw right after
	// emitting its head), or a 101 response was seen (the response side goes raw,
	// and the request side checks this flag before parsing its next head).
	upgraded bool

	// terminate carries a synthetic response from the direction that decided on
	// it (the request side: a hook terminated the request, or a head the policy
	// could not read was refused) to the direction that can put it on the wire
	// (the response side, which owns everything the client reads after a
	// request). terminateGen is the request generation it answers -- see reqGen
	// and respGen below -- and it is what keeps a terminate for a request that
	// is not the one the response side is answering right now from being
	// delivered in its place.
	//
	// One slot is the right size. The request side can only terminate the
	// request it is currently parsing, and after a terminate it stops parsing
	// altogether (it drains), so a second value could never be published.
	terminate    *SyntheticResponse
	terminateGen int

	// wakeResponse unblocks the response side when a terminate is published
	// while it is parked in a read of its own source. Without it the response
	// side would sit in that read until the upstream answered -- and in the
	// terminated case the upstream is never asked anything, so nothing would
	// ever arrive. NewConnPair sets it (it has the source connections);
	// NewPair leaves it nil, which is why the in-memory tests drive the request
	// side first instead of relying on the wake.
	//
	// How it unblocks the read is NewConnPair's business, but it matters that it
	// is closing the source and not setting a read deadline on it: see the wake
	// there for the mux-path hang that rules deadlines out.
	wakeResponse func()

	// respParked is true while the response side is between messages and about
	// to block in a read of the source; parkedGen is the request generation it
	// is about to answer. That is the only state in which the wake is both
	// needed (a read is in flight) and harmless (no message bytes have been read
	// yet, so interrupting it cannot truncate one).
	//
	// The pair is written by parkResponse in the same critical section that
	// looks for a pending terminate, and that atomicity is the whole point. Split
	// into "is there a terminate?" and "I am about to block", a terminate
	// published between the two answers ends up in a slot whose owner is already
	// asleep: no wake is sent, the read never returns, and the connection hangs
	// until the client gives up. Set next to a generation, the same state also
	// keeps the wake from firing for a terminate that belongs to a *later*
	// request than the one being waited for: that wake would close the source
	// mid-read and throw away a response that was on its way.
	respParked bool
	parkedGen  int

	// reqGen counts the request heads the request side has begun, this one
	// included. It is the connection's request clock. A generation is claimed by
	// beginRequest before the head is read, so a head that never becomes a
	// message (an oversized one, refused under a policy) still has one.
	reqGen int

	// respGen counts the final response heads the response side has emitted. The
	// response it is about to look for answers request respGen+1, which is
	// therefore the generation a terminate has to carry to be its answer: the
	// two counters are the same clock read from the two ends of a connection
	// where one request is answered by one final response.
	respGen int
}

// beginRequest claims the generation of the request head the request side is
// about to read. It is called once per head, before the head is assembled.
func (st *connState) beginRequest() int {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.reqGen++
	return st.reqGen
}

// nextResponseGen is the generation of the request whose answer the response
// side is about to look for.
func (st *connState) nextResponseGen() int {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.respGen + 1
}

// recordResponse counts one final response head. Interim 1xx heads are not
// responses to a request in their own right -- they are the interim answer or
// the upgrade handshake -- so they leave the clock alone.
func (st *connState) recordResponse() {
	st.mu.Lock()
	st.respGen++
	st.mu.Unlock()
}

// setTerminate publishes a synthetic response for the response side to emit,
// tagged with the request generation it answers. The first verdict wins: a
// terminate can only be published once per connection (the request side drains
// after one), and the slot is never full in practice.
//
// The wake is sent only when the response side is parked and this terminate is
// the answer to the request it is parked on. A terminate for a later request
// must not wake it: the response it is waiting for is a real one, from an
// upstream that was asked, and closing the source under that read would
// truncate it. The terminate is not lost by waiting -- the response side looks
// for it again at the start of every message, which is when its generation has
// caught up (parkResponse).
func (st *connState) setTerminate(s *SyntheticResponse, gen int) {
	st.mu.Lock()
	if st.terminate == nil {
		st.terminate, st.terminateGen = s, gen
	}
	parked, want, wake := st.respParked, st.parkedGen, st.wakeResponse
	st.mu.Unlock()

	if parked && gen == want && wake != nil {
		wake()
	}
}

// parkResponse is the response side's entry into one message: one atomic step
// that either takes the terminate published for the generation it is about to
// answer, or records that it is about to block in a read of its source. Doing
// both under one lock is what makes a terminate published *during* the step
// impossible to lose -- whichever order the two sides get the lock in, the
// response side either finds the terminate or is registered as parked before it
// is (see the respParked field comment).
//
// A terminate for a generation that has already gone by is taken too: it cannot
// be answered by a later message, and refusing it would leave the response side
// parked on an upstream that is no longer being asked anything.
func (st *connState) parkResponse(gen int) *SyntheticResponse {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.terminate != nil && st.terminateGen <= gen {
		s := st.terminate
		st.terminate, st.terminateGen = nil, 0
		return s
	}
	st.respParked, st.parkedGen = true, gen
	return nil
}

// unparkResponse leaves the parked window: the response side is committed to a
// message (or done with one) and no longer needs to be woken out of a read.
func (st *connState) unparkResponse() {
	st.mu.Lock()
	st.respParked, st.parkedGen = false, 0
	st.mu.Unlock()
}

// takeTerminate removes the pending terminate when it answers gen, and returns
// nil otherwise. This is the read-error path's version of parkResponse -- the
// wake ends the read, and this is how the response side finds what the wake was
// sent for -- so it is consulted non-blockingly on a message path that must
// never wait for a verdict that may never come.
func (st *connState) takeTerminate(gen int) *SyntheticResponse {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.terminate == nil || st.terminateGen > gen {
		return nil
	}
	s := st.terminate
	st.terminate, st.terminateGen = nil, 0
	return s
}

// recordRequest publishes everything the response side needs to know about the
// request it is answering. All four values come from one parsed head, so they are
// written under one lock: the response side must never see the new method beside
// the previous request's encoding preferences.
func (st *connState) recordRequest(method, version string, acceptsGzip, hasRange bool) {
	st.mu.Lock()
	st.lastMethod = method
	st.reqAcceptsGzip = acceptsGzip
	st.reqHasRange = hasRange
	st.reqChunkedOK = allowsChunked(version)
	st.mu.Unlock()
}

// requestTraits reads the three gzip inputs back in one go, for the same reason
// they are written in one go.
func (st *connState) requestTraits() (acceptsGzip, hasRange, chunkedOK bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.reqAcceptsGzip, st.reqHasRange, st.reqChunkedOK
}

func (st *connState) method() string {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.lastMethod
}

func (st *connState) setUpgraded() {
	st.mu.Lock()
	st.upgraded = true
	st.mu.Unlock()
}

func (st *connState) isUpgraded() bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.upgraded
}

// streamRewriter is one direction's read-driven state machine. It reads through
// a single connection-lifetime pooledReader (the pair's pooled 64 KiB read
// buffer) and queues transformed bytes in out, from where Read hands them to
// the caller.
type streamRewriter struct {
	side side
	dir  string // "request" or "response", for log messages

	// br is the direction's read buffer. It exposes exactly the two
	// bufio.Reader methods the state machine calls -- Read for the verbatim
	// body copies, ReadSlice for head-line assembly (readLine) -- which is the
	// inventory that fixed the pooledReader shape. Its backing array comes
	// from readBufPool and goes back at filteredConn.Close; see the pooling
	// block above newPairWithWake.
	br *pooledReader
	lg log.Logger
	st *connState
	cp *compiledPolicy

	// pending holds bytes read from br that have not been handed to the caller
	// yet: the head being assembled, plus any line read but not yet classified.
	// Fail-open flushes it verbatim, which is what makes "never lose bytes" hold
	// even when the stream stops making sense.
	//
	// Every line here is a copy: readLine appends the ReadSlice result, which
	// aliases br's pooled array, into this owned slice before returning. That
	// copy-out is what lets the array be recycled at Close (see readBufPool).
	//
	// Bytes that were over-read into br's buffer -- the body that shared a
	// segment with its head -- are deliberately not in here: they stay in br and
	// the next phase copies them, in order. That is the head/body splice.
	pending []byte

	out     []byte
	outOff  int
	scratch [copyChunk]byte

	phase      state
	remaining  int64 // stBodyCL: body bytes still to copy
	chunkLeft  int64 // stChunkData: chunk bytes still to copy
	chunkEnd   int   // stChunkDataEnd: framing bytes still to copy
	failedOpen bool  // already warned about giving up on this direction

	// hookWarned records that the policy hook already failed on this direction,
	// so that a hook which panics on every message gets one WARN per connection
	// rather than one per message.
	hookWarned bool

	// gen is the request generation of the head the request side is assembling,
	// as connState.beginRequest gave it out, or 0 on the response side and on a
	// connection whose policy has no request hook -- nothing can terminate
	// there, so no generation is ever read.
	gen int

	// gz is the live gzip transform of the response body being copied, or nil.
	// It is the only switch between the identity path and the transform: the
	// phases that read and frame the input are the same either way, and the sink
	// they copy into (sourceBody) is what changes.
	gz *gzipState
}

// NewPair returns the two read-driven rewriters of one connection: req for the
// public->local direction (reads requests) and resp for the local->public
// direction (reads responses). They share the connection state that ties them
// together: the last request method (a HEAD response has no body), what that
// request said about gzip and ranges, and the upgrade flag.
func NewPair(reqSrc, respSrc io.Reader, p *Policy) (req, resp io.Reader) {
	return newPair(reqSrc, respSrc, p, log.NewPrefixLogger("rewriter"), log.NewPrefixLogger("rewriter"))
}

// newPair is NewPair with an explicit logger per direction, so that the conn
// adapter can log through the connections themselves (and thus with their ids).
func newPair(reqSrc, respSrc io.Reader, p *Policy, reqLog, respLog log.Logger) (req, resp io.Reader) {
	return newPairWithWake(reqSrc, respSrc, p, reqLog, respLog, nil)
}

// The pooled 64 KiB read buffer. This is the one per-connection allocation
// that used to survive the whole connection: newPairWithWake handed each
// direction a bufio.Reader over a freshly made readBufferSize array and
// nothing ever gave the arrays back -- two connection-lifetime buffers on
// every client HTTP connection (the X-Forwarded injection makes every live
// tunnel policy non-noop, so none of them skip the wrapping) and on every
// policy-hooked server connection. The pool below recycles them; the release
// mechanics live on filteredConn.Close (conn.go), the one site a connection
// is torn down from.

// readBufPool holds the backing arrays of the pair's two per-direction
// readers. It follows conn.joinBufPool's conventions deliberately -- pool
// beside its only user, size const above, one buffer per concurrent copy --
// and for the same reason it is a pool and not one package-level slice: both
// directions of a connection read concurrently (conn.Join copies each
// direction on its own goroutine), so a shared slice would have them
// overwriting each other's in-flight bytes. One buffer per direction either
// way; the pool's only job is to let the next connection reuse the array
// instead of allocating 2x64 KiB per connection.
//
// readBuf is one pooled backing array. The pool holds *readBuf and not []byte
// for an allocation reason, not a style one: sync.Pool.Put takes an
// interface{}, and boxing a slice (three words) into one allocates on every
// Put -- on this path one allocation per direction per connection, exactly
// the kind of tax the pool exists to remove. Boxing a pointer is free, so the
// pool circulates the *readBuf cell and the reader uses rb.b as the array.
type readBuf struct {
	b [readBufferSize]byte
}

// It is a *sync.Pool rather than a sync.Pool, and nil is allowed, so that
// tests can turn pooling off and measure against it: with readBufPool nil,
// buffers are allocated and dropped exactly as the bufio.NewReaderSize code
// did, and every Put below is a no-op.
var readBufPool = &sync.Pool{New: func() interface{} { return &readBuf{} }}

func getReadBuf() *readBuf {
	if readBufPool == nil {
		return &readBuf{}
	}
	rb := readBufPool.Get().(*readBuf)
	// The Get counterpart of testPutHook: Puts alone cannot prove the
	// ownership invariant (an array may legitimately be Put, Got, and Put
	// again as it recycles between directions), so the concurrency test needs
	// to see both sides of the pool. Production leaves it nil; the cost is one
	// nil check per buffer acquisition.
	if testGetHook != nil {
		testGetHook(rb.b[:])
	}
	return rb
}

// testPutHook observes every putReadBuf. See the comment in putReadBuf.
var testPutHook func(b []byte)

// testGetHook observes every pooled getReadBuf. See testPutHook.
var testGetHook func(b []byte)

// putReadBuf returns an array the reader no longer references, in any way:
// the pool may hand it to another connection the instant this returns. The
// callers guarantee that; see pooledReader.finish and pooledReader.release
// for the two recycle points and why no view into the array can be live at
// either.
func putReadBuf(rb *readBuf) {
	if readBufPool == nil {
		return
	}
	readBufPool.Put(rb)
	// Test hook, not a production path: sync.Pool cannot be inspected, and the
	// release tests must observe that exactly one Put happened per buffer (the
	// double-release hazard). Production leaves it nil; the cost is one nil
	// check per recycled buffer.
	if testPutHook != nil {
		testPutHook(rb.b[:])
	}
}

// maxConsecutiveEmptyReads is bufio.Reader's own limit, restated here because
// bufio's is private: how many zero-byte reads fill will tolerate from a
// source before declaring it stuck.
const maxConsecutiveEmptyReads = 100

// errNegativeRead mirrors bufio's panic for a Read implementation that lies
// about its count. Like bufio's, it is a panic and not an error: a Reader
// that returns n < 0 is broken, and continuing from it would corrupt framing.
var errNegativeRead = errors.New("rewriter: source returned a negative read count")

// pooledReader is one direction's read buffer: the Read and ReadSlice of a
// bufio.Reader -- exactly the two methods the state machine calls on r.br,
// the inventory that fixed this shape -- over a backing array from
// readBufPool.
//
// bufio itself is not reused because it has no Reset and owns its array for
// the reader's whole life; here the array goes back to the pool exactly once,
// at filteredConn.Close. The semantics are mirrored from bufio.Reader method
// for method, quirks included (a fill that reads nothing makes the next Read
// return (0, nil) once before the error surfaces; ReadSlice scans forward
// across fills; an error drains the buffer with the line it cut short). That
// fidelity is load-bearing: the byte-ordering properties the package
// documents -- "the first body bytes, which usually arrived in the same read,
// stay in br for the next phase" -- are properties of those exact semantics,
// and every test in the package runs over this reader to keep them honest.
//
// Recycling is built on one observation: a buffer may go back to the pool
// only at a moment when no view into it is live and no read is in flight.
// Both recycle points are chosen for that:
//
//   - finish (read side): a read is about to return an error from the source
//     with nothing buffered. The return carries no bytes, io.Copy over this
//     reader ends on exactly such a return, and the read is completing -- so
//     this is where a Close already waiting for the buffer gets it.
//   - release (close side): filteredConn.Close, once per connection. If the
//     direction already ended, the buffer goes back here; if it is still
//     copying (the normal shutdown order has the first direction to finish
//     close the other one's legs), release only records the request and finish
//     does the Put at that direction's own termination. Either way the array
//     is never in the pool while this connection can still touch it.
//
// The bytes the state machine parses never alias the array past the read
// that produced them: readLine copies each ReadSlice line into pending (an
// owned slice) before returning, and every other path copies out of the
// buffer into the caller's slice or into out. That copy-out is what makes
// the recycle points safe, and TestReleasedBufferScribbleDoesNotCorrupt
// keeps it true.
//
// Locking: r, w and err are confined to the goroutine that reads -- conn.Join
// gives each direction exactly one reader goroutine, and nothing else reads a
// streamRewriter's source. mu guards the fields the Close path touches from
// another goroutine (buf, terminated, released, recycled) and is never
// held across a source read, so Close never waits on I/O.
type pooledReader struct {
	src io.Reader

	mu         sync.Mutex
	buf        *readBuf // the pooled buffer cell; nil while recycled
	terminated bool     // a read returned a source error with nothing buffered
	released   bool     // release ran at least once; the next terminal read recycles
	recycled   bool     // true between a Put and the next takeBuf re-lease

	// Read state, confined to the reading goroutine. The layout mirrors
	// bufio.Reader: buf[r:w] is the unconsumed span; err is the source's sticky
	// error, returned once from an empty buffer and then cleared, so a caller
	// that keeps reading after an error re-tries the source exactly as it would
	// against bufio.
	r   int
	w   int
	err error
}

func newPooledReader(src io.Reader) *pooledReader {
	return &pooledReader{src: src}
}

// takeBuf returns the backing array, (re)acquiring it after a recycle. Only
// the identity of the array is under mu: the caller uses the returned slice
// without the lock, because only the reading goroutine ever writes into it.
//
// A read after a recycle should not happen -- termination is the end of the
// copy -- but the state machine can make one more source read after a
// finish-terminated one (the fail-open flush and the gzip transform's
// close-delimited handoff both can), so a recycled direction re-acquires here
// rather than touching an array another connection may now own. The pool is a
// token system -- an array in it has no owner and every Get hands it to
// exactly one taker -- so re-acquiring can never overlap owners: either we
// get our own array back (still pooled, zero owners) or a fresh one. The new
// array is a new lease (recycled resets), so the later terminal read puts it
// back instead of leaking it out of circulation.
func (pr *pooledReader) takeBuf() []byte {
	pr.mu.Lock()
	if pr.buf == nil {
		pr.buf = getReadBuf()
		pr.r, pr.w = 0, 0
		pr.recycled = false
	}
	b := pr.buf.b[:]
	pr.mu.Unlock()
	return b
}

// stickyErr returns and clears the pending source error, as bufio's readErr
// does: served once, then the source is asked again.
func (pr *pooledReader) stickyErr() error {
	err := pr.err
	pr.err = nil
	return err
}

// finish records that a read is returning a source error with nothing
// buffered -- the shape of return io.Copy ends on, with no bytes in it. When
// Close has already asked for the buffer back (released), this is where it
// goes to the pool: no view into it is live (a (0, err) return carries no
// bytes) and no read is in flight (this is that read, returning). Should the
// state machine still make one more source read afterwards, takeBuf re-leases
// an array (ours if nobody took it, otherwise a fresh one) and the next
// terminal read recycles that one -- ownership never overlaps, nothing leaks,
// however the Close and the copy end interleave.
func (pr *pooledReader) finish() {
	pr.mu.Lock()
	pr.terminated = true
	if pr.released && !pr.recycled && pr.buf != nil {
		putReadBuf(pr.buf)
		pr.buf, pr.recycled = nil, true
	}
	pr.mu.Unlock()
}

// release is filteredConn.Close's handle on the buffer. It runs at most once
// per direction (the caller's sync.Once; the recycled flag below makes it
// idempotent regardless). If the direction has ended, the buffer goes back to
// the pool here: no read is in flight and the terminated read carried no
// bytes, so no view into the array is live. If the direction is still
// copying, release only records the request -- never touching the array the
// other goroutine is reading or holding views into -- and finish recycles at
// that direction's own termination. released stays set either way, so a
// re-lease after a release-Put (see takeBuf) still recycles on its next
// terminal read. With pooling off (readBufPool nil), both recycle points
// degrade to dropping the array for the GC, which is the behavior this pool
// replaced.
func (pr *pooledReader) release() {
	pr.mu.Lock()
	defer pr.mu.Unlock()
	pr.released = true
	if pr.recycled {
		return
	}
	if pr.terminated {
		pr.recycled = true
		if pr.buf != nil {
			putReadBuf(pr.buf)
			pr.buf = nil
		}
	}
}

// Read mirrors bufio.Reader.Read: buffered bytes are copied out first; an
// empty buffer serves one source read, directly into p when p is at least the
// buffer's size (the verbatim-copy phases, which hand io.Copy's whole
// staging buffer in, pay no bounce through the array this way -- the same
// direct path bufio has); a fill that reads nothing makes the next call
// return (0, nil) once before the error surfaces, and io.Copy's retry is
// what turns that into a clean EOF.
func (pr *pooledReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		if pr.w > pr.r {
			return 0, nil
		}
		err := pr.stickyErr()
		if err != nil {
			pr.finish()
		}
		return 0, err
	}
	if pr.r == pr.w && pr.err != nil {
		err := pr.stickyErr()
		pr.finish()
		return 0, err
	}
	b := pr.takeBuf()
	if pr.r == pr.w {
		if len(p) >= len(b) {
			// Large read, empty buffer: straight into p, no copy. The error is
			// surfaced with the bytes in the same call, as bufio does, and a
			// byte-less one ends the copy over this reader -- a recycle point.
			n, err := pr.src.Read(p)
			if n < 0 {
				panic(errNegativeRead)
			}
			pr.err = err
			if n == 0 && err != nil {
				pr.finish()
			}
			return n, pr.stickyErr()
		}
		// One read, not fill's loop: as bufio puts it, do not try to read more.
		pr.r = 0
		n, err := pr.src.Read(b)
		if n < 0 {
			panic(errNegativeRead)
		}
		pr.w = n
		if n == 0 {
			pr.err = err
			if err != nil {
				pr.finish()
			}
			return 0, err
		}
	}
	n := copy(p, b[pr.r:pr.w])
	pr.r += n
	return n, nil
}

// ReadSlice mirrors bufio.Reader.ReadSlice: scan for the delimiter, filling
// as needed and never rescanning bytes a fill brought nothing new about; an
// error drains the buffer together with the line it cut short; a buffer that
// fills without a delimiter comes back whole with ErrBufferFull (which
// readLine translates into errLineTooLong). The returned line aliases the
// array and is valid only until the next read on this reader -- bufio's own
// contract, and the reason readLine copies into pending before returning.
func (pr *pooledReader) ReadSlice(delim byte) (line []byte, err error) {
	s := 0 // scan start index: do not rescan area already scanned
	for {
		b := pr.takeBuf()
		if s > pr.w-pr.r {
			// The array was swapped under this call (a post-recycle read): the
			// old scan offset means nothing on a fresh span.
			s = pr.w - pr.r
		}
		if i := bytes.IndexByte(b[pr.r+s:pr.w], delim); i >= 0 {
			i += s
			line = b[pr.r : pr.r+i+1]
			pr.r += i + 1
			return line, nil
		}
		if pr.err != nil {
			line = b[pr.r:pr.w]
			pr.r = pr.w
			empty := len(line) == 0
			err = pr.stickyErr()
			if empty {
				// The line came back empty with the source's error: the copy
				// over this reader ends here, so this is a recycle point.
				pr.finish()
			}
			return line, err
		}
		if pr.w-pr.r >= len(b) {
			pr.r = pr.w
			return b, bufio.ErrBufferFull
		}
		s = pr.w - pr.r
		pr.fill()
	}
}

// fill mirrors bufio.Reader.fill: slide any unread span to the front of the
// array, then tolerate up to maxConsecutiveEmptyReads zero-byte reads before
// declaring the source stuck.
func (pr *pooledReader) fill() {
	b := pr.takeBuf()
	if pr.r > 0 {
		copy(b, b[pr.r:pr.w])
		pr.w -= pr.r
		pr.r = 0
	}
	if pr.w >= len(b) {
		panic("rewriter: tried to fill full buffer")
	}
	for i := maxConsecutiveEmptyReads; i > 0; i-- {
		n, err := pr.src.Read(b[pr.w:])
		if n < 0 {
			panic(errNegativeRead)
		}
		pr.w += n
		if err != nil {
			pr.err = err
			return
		}
		if n > 0 {
			return
		}
	}
	pr.err = io.ErrNoProgress
}

// releaseBuffer hands this direction's read buffer back toward the pool on
// behalf of filteredConn.Close. The mechanics and the safety argument are
// pooledReader.release's; this method exists so the adapter can reach them
// through the io.Reader it holds.
func (r *streamRewriter) releaseBuffer() {
	r.br.release()
}

// newPairWithWake is newPair plus the wake handle that unblocks the response
// side when the request side terminates: see connState.wakeResponse for why the
// response side needs to be unblocked rather than merely signalled, and why
// nil is the right value for an in-memory pair.
//
// Each direction's reader takes its backing array from readBufPool here. On
// the live path (NewConnPair) filteredConn.Close releases it; on the in-memory
// path (NewPair, the tests) nothing ever calls Close, so the array is simply
// garbage when the rewriters become unreachable -- the same lifecycle the
// bufio.NewReaderSize code had, and no worse.
func newPairWithWake(reqSrc, respSrc io.Reader, p *Policy, reqLog, respLog log.Logger, wake func()) (req, resp io.Reader) {
	cp := compilePolicy(p, reqLog)
	st := &connState{wakeResponse: wake}

	req = &streamRewriter{
		side: sideRequest, dir: "request",
		br: newPooledReader(reqSrc), lg: reqLog, st: st, cp: cp,
		phase: stHead,
	}
	resp = &streamRewriter{
		side: sideResponse, dir: "response",
		br: newPooledReader(respSrc), lg: respLog, st: st, cp: cp,
		phase: stHead,
	}
	return req, resp
}

// Read hands the caller transformed bytes, pulling from the source only when it
// has nothing left to give. The caller's buffer size shapes the copies (io.Copy
// uses 32 KiB buffers) but never the output.
func (r *streamRewriter) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		if r.outOff < len(r.out) {
			n := copy(p, r.out[r.outOff:])
			r.outOff += n
			return n, nil
		}
		r.out, r.outOff = r.out[:0], 0

		// Hot path: raw passthrough and content-length bodies are verbatim
		// copies of the source, so hand the caller's buffer straight to it
		// instead of bouncing every byte through out.
		if n, err := r.directRead(p); n > 0 || err != nil {
			return n, err
		}
		if err := r.step(); err != nil {
			return 0, err
		}
	}
}

// directRead is the verbatim-copy fast path. It returns (0, nil) when the phase
// needs the full state machine instead -- which is every phase while a gzip
// transform is live, because those body bytes have to reach the compressor rather
// than the caller's buffer.
func (r *streamRewriter) directRead(p []byte) (int, error) {
	if r.gz != nil {
		return 0, nil
	}
	switch r.phase {
	case stRaw:
		return r.br.Read(p)
	case stBodyCL:
		if r.remaining <= 0 {
			return 0, nil
		}
		if int64(len(p)) > r.remaining {
			p = p[:r.remaining]
		}
		n, err := r.br.Read(p)
		r.remaining -= int64(n)
		if r.remaining == 0 {
			r.phase = stHead
		}
		return n, err
	}
	return 0, nil
}

// step advances the state machine by at most one unit of work: one head, one
// line of framing, or one buffer of a body. Whatever it produced is queued in
// out; an error means the source is done, not that the output is done.
func (r *streamRewriter) step() error {
	switch r.phase {
	case stHead:
		return r.stepHead()
	case stBodyCL:
		return r.stepBodyCL()
	case stChunkSize:
		return r.stepChunkSize()
	case stChunkData:
		return r.stepChunkData()
	case stChunkDataEnd:
		return r.stepChunkDataEnd()
	case stChunkTrailer:
		return r.stepChunkTrailer()
	case stGzipClose:
		return r.stepGzipClose()
	case stDrain:
		return r.stepDrain()
	case stDone:
		return io.EOF
	}
	return r.stepRaw()
}

// stepDrain reads the source and throws the bytes away. It is where a
// terminated request's direction ends up: the client is still sending -- it may
// have a body to write, or a pipelined request -- and none of it can be
// forwarded, because the request that would have framed it never left. Reading
// is what keeps the client from blocking on a full socket buffer; discarding is
// what keeps a request the policy refused from reaching the upstream.
//
// The phase ends where the connection does: the response side closes both
// connections once it has emitted the synthetic response, and the read here
// then fails, which unwinds the other half of the join.
func (r *streamRewriter) stepDrain() error {
	if _, err := r.br.Read(r.scratch[:]); err != nil {
		return err
	}
	return nil
}

// stepRaw copies whatever the source has, verbatim. Read's fast path normally
// handles this phase directly; this is the fallback for a caller buffer the fast
// path declined.
func (r *streamRewriter) stepRaw() error {
	n, err := r.br.Read(r.scratch[:])
	if n > 0 {
		r.emit(r.scratch[:n])
	}
	if err != nil {
		if n > 0 {
			return nil // surface the error once the bytes are delivered
		}
		return err
	}
	return nil
}

// stepBodyCL copies exactly the number of bytes the head declared, then looks
// for the next head. If the source ends early, the truncation is the peer's:
// emit what arrived, then report EOF.
func (r *streamRewriter) stepBodyCL() error {
	if r.remaining <= 0 {
		r.endBody()
		return nil
	}
	n := int64(len(r.scratch))
	if n > r.remaining {
		n = r.remaining
	}
	read, err := r.br.Read(r.scratch[:n])
	if read > 0 {
		if !r.sourceBody(r.scratch[:read]) {
			return nil // the transform failed open; the raw copy has the rest
		}
		r.remaining -= int64(read)
		if r.remaining == 0 {
			r.endBody()
		}
	}
	if err != nil {
		if read > 0 {
			return nil
		}
		return err
	}
	return nil
}

// stepHead assembles one request or response head, rewrites it, queues it, and
// decides how the body that follows is framed.
func (r *streamRewriter) stepHead() error {
	// The request side stops parsing once the connection has been upgraded: the
	// response side sets the flag when it sees a 101, and from there on the bytes
	// belong to the upgraded protocol -- binary websocket frames, which may well
	// contain CRLFCRLF of their own.
	if r.side == sideRequest && r.st.isUpgraded() {
		r.phase = stRaw
		return nil
	}

	// gen is the request generation this call is about: on the request side the
	// generation of the head being assembled, on the response side the
	// generation of the request whose answer is being looked for. It is claimed
	// before the head is read, so that a head which never becomes a message can
	// still be tagged (see refuseHead).
	var gen int
	if r.side == sideRequest {
		// A generation is only ever read by a terminate, and only a request hook
		// can publish one: a policy without one -- every policy the client
		// builds today -- keeps this off the per-request path entirely.
		if r.cp.reqHook != nil {
			gen = r.st.beginRequest()
			r.gen = gen
		}
	} else {
		gen = r.st.nextResponseGen()
		// Test-only window into the park: the race this package has to survive
		// is a terminate published in the instant between deciding there is
		// nothing pending and registering as parked, and nothing else can open
		// that instant on purpose. See testParkGapHook.
		if testParkGapHook != nil {
			testParkGapHook(r.st)
		}
		// A terminate that is already published is emitted before the source is
		// read at all: there is no response to wait for, because the request it
		// would have answered never left this process. From here until this
		// function returns, this direction may block in a read, which is the
		// window in which a terminate published by the request side is allowed
		// to interrupt it -- and it is safe precisely here: nothing of a message
		// has been read yet, so an interrupted read cannot truncate one.
		// Between messages is also the only place the terminate is looked for,
		// which is why a terminate that arrives while a response is streaming is
		// answered after that response finishes (spec 3.1).
		//
		// Both halves happen under one lock (parkResponse): taken separately,
		// a terminate published between them is a terminate whose wake nobody
		// sends, and the connection hangs.
		if term := r.st.parkResponse(gen); term != nil {
			r.emitSynthetic(term)
			return nil
		}
		defer r.st.unparkResponse()
	}

	r.pending = r.pending[:0]
	started := false
	for {
		line, err := r.readLine()
		if err == errLineTooLong {
			if r.refuseHead("head line longer than 64 KiB", syntheticHeadTooLargeBody) {
				return nil
			}
			r.failOpen("head line longer than 64 KiB")
			return nil
		}
		if err != nil {
			if len(r.pending) == 0 {
				// A terminate is one reason this read ended: the wake
				// (connState.wakeResponse) ends a parked response side's read
				// rather than waiting for an upstream that will never be asked.
				// Whatever ended the read, the terminate is the answer the client
				// is owed, and it is checked here as well as on entry -- against
				// this message's generation, so a terminate for a later request
				// is left for that request (see connState.parkResponse).
				if r.side == sideResponse {
					if term := r.st.takeTerminate(gen); term != nil {
						r.emitSynthetic(term)
						return nil
					}
				}
				return err // clean end of stream at a message boundary
			}
			// End of stream inside a head: the connection is over either way, but
			// the peer still gets every byte it sent.
			r.failOpen("end of stream in the middle of a head")
			return nil
		}
		if len(r.pending) > maxHeadBytes {
			if r.refuseHead("head larger than 64 KiB", syntheticHeadTooLargeBody) {
				return nil
			}
			r.failOpen("head larger than 64 KiB")
			return nil
		}
		if isBlankLine(line) {
			if !started {
				// RFC 7230 3.5: tolerate -- and preserve -- empty lines before the
				// start line instead of giving up on the connection.
				continue
			}
			break
		}
		started = true
	}

	head, err := parseHead(r.pending, r.side)
	if err != nil {
		// The same rule as an oversized head, for the same reason and at a much
		// lower price to the attacker: a head this package cannot parse is a head
		// no request-phase action runs on, so failing open forwards a request the
		// policy would have refused. One obs-fold continuation line, or a header
		// line with no colon, is enough -- and it is sticky, because failOpen
		// leaves the whole connection in stRaw, so every later request on it is
		// unpoliced as well. Padding a head past 64 KiB is not the only way to
		// buy a bypass; it was only the most expensive one.
		//
		// The reason is formatted here rather than at the call so that the
		// peer-controlled text is an argument to the logger, never a format
		// string (failOpen does the same).
		if r.refuseHead(fmt.Sprintf("malformed head: %v", err), syntheticMalformedHeadBody) {
			return nil
		}
		r.failOpen("malformed head: %v", err)
		return nil
	}

	// Keep the shared state current before the other direction can look at it.
	if r.side == sideRequest {
		r.st.recordRequest(head.method, head.version,
			head.acceptsGzip(), head.hasField("range"))
		if head.isUpgrade() {
			r.st.setUpgraded()
		}
	} else if head.status >= 200 {
		// A final response is one answer to one request, so this is where the
		// response side's generation advances: the next message is the answer to
		// the next request, and that is the generation a terminate has to carry
		// to be delivered there rather than here. Interim 1xx heads (100
		// Continue) are part of the answer being read and leave the clock alone.
		r.st.recordResponse()
	}

	// The transform decision is made here, before the head is re-emitted, because
	// it decides two things at once: what the head says about the body (a
	// compressed body has no content-length to declare, and needs its framing
	// spelled out) and how the body steps feed it. Deciding them together is what
	// keeps the head and the framing from disagreeing.
	gzip := r.side == sideResponse && r.gzipEligible(head)

	next, err := r.nextPhase(head, gzip)
	if err != nil {
		r.failOpen("malformed framing: %v", err)
		return nil
	}

	hook := r.hookRewrite(head)
	if hook != nil && hook.terminate != nil {
		// The request is answered by the edge. The head is dropped -- the
		// upstream must never see the request -- and the response side is the
		// one that puts the answer on the wire: it owns everything the client
		// reads after a request, and the two directions share the connection,
		// so emitting here would interleave with a response in flight. The
		// generation this request claimed is what says which of the response
		// side's messages the answer belongs to.
		r.st.setTerminate(hook.terminate, gen)
		r.pending = r.pending[:0]
		r.phase = stDrain
		return nil
	}

	var rewritten []byte
	switch {
	case r.side == sideRequest:
		rewritten = r.cp.rewriteRequestHead(head, hook)
	case head.status < 200:
		// Interim 1xx heads (100 Continue, 101, ...) take no response policy:
		// ngrok applies response actions to the final response only, and a 101
		// belongs to the upgrade handshake. Re-emit them verbatim. (gzip is never
		// set for these: gzipEligible requires a status >= 200.)
		rewritten = head.raw
	default:
		rewritten = r.cp.rewriteResponseHead(head, gzip, hook)
	}

	if gzip {
		r.gz = newGzipState()
	}

	r.pending = r.pending[:0]
	r.emit(rewritten)
	r.phase = next
	return nil
}

// syntheticHeadTooLargeBody and syntheticMalformedHeadBody are the bodies of the
// two refusals below. They are static strings: the reason a head was refused can
// contain peer-controlled bytes, and those go to the log line, not back out onto
// the wire.
const (
	syntheticHeadTooLargeBody  = "request header fields too large: the head exceeds the limit this proxy can parse\n"
	syntheticMalformedHeadBody = "malformed request head: it is not one this proxy can parse, so the request was not forwarded\n"
)

// refuseHead is what the request side does with a head it cannot process when a
// policy is watching: instead of failing open, the head is dropped and the
// client is answered with 431. It returns true when the request was refused --
// the caller must then return, the direction is draining -- and false when the
// caller should fail open exactly as it did before policies existed.
//
// "Cannot process" has two routes into it, and they are one rule: a head past
// this package's 64 KiB read limit, and a head that parseHead refuses (an
// obs-fold continuation line, a header line with no colon, a space in a field
// name, a request line that is not one). The second is by far the cheaper
// bypass -- one malformed line versus 64 KiB of padding -- and it is stickier,
// because the fail-open path leaves the connection in stRaw for good: every
// later request on that keep-alive connection is forwarded unpoliced too.
//
// The rule is the whole point of a policy, and it is worth stating plainly.
// Every request-phase action -- deny, custom-response, add-headers,
// remove-headers, log -- runs on a parsed head, so a head that is not parsed
// skips all of them. Failing *open* there does not leave the connection
// unrewritten; it forwards the request. The audit's shape is a request the
// policy would have refused, carried in a head the proxy cannot read, and the
// only honest answers are "refuse it" and "admit the policy does not apply".
// Refusing is chosen because the alternative is a policy an attacker decides
// whether to be subject to, by choosing the shape of their head.
//
// Three things this deliberately does not do:
//
//   - It does not apply to the response side. A response head over the cap (or
//     malformed) is an upstream problem, not an attacker-controlled bypass, and
//     the edge cannot answer a request it has already forwarded with anything
//     better than the origin's own answer.
//   - It does not apply when no request hook is armed: there is nothing to
//     bypass, the connection is on the byte-identical path, and a 64 KiB head
//     from a client that simply writes long headers -- or a stream that is not
//     HTTP at all, which fails the same parse -- must keep working. That is the
//     documented fail-open rule of the package, and this function is the one
//     place where a policy changes it.
//   - It does not try to tell a hostile malformed head from a stream that was
//     never HTTP (an SSH banner, say). It cannot, and the two are the same
//     thing to a proxy that has no parsed request to police: on a connection
//     whose policy has a request hook, such a stream is refused with one 431
//     rather than forwarded unpoliced. A tunnel that carries a non-HTTP
//     protocol should not be configured with a traffic policy, and the cost of
//     being wrong is a connection that does not work rather than a rule that
//     silently does not run.
func (r *streamRewriter) refuseHead(reason, body string) bool {
	if r.side != sideRequest || r.cp.reqHook == nil {
		return false
	}
	// The warn is unconditional rather than once-per-direction: the request
	// side drains after a refusal and never parses another head, so this runs at
	// most once per connection.
	r.lg.Warn("%s: %s; a request hook is armed, so the request is refused with %d and never forwarded",
		r.dir, reason, http.StatusRequestHeaderFieldsTooLarge)
	r.st.setTerminate(&SyntheticResponse{
		StatusCode: http.StatusRequestHeaderFieldsTooLarge,
		Headers:    []string{"Content-Type: text/plain"},
		Body:       body,
	}, r.gen)
	r.pending = r.pending[:0]
	r.phase = stDrain
	return true
}

// testParkGapHook is a test-only window into the response side's park, and it
// is the only one in the package that is not on the wire path. The atomicity
// parkResponse documents is unobservable from outside -- both sides have to be
// threaded into the same instant, deterministically, for the regression test of
// the M3 race to mean anything -- so the instant is exposed here and the test
// publishes a terminate from inside it. It is nil in production, and the
// branch that reads it is one predictable load on a path that is about to
// block in a read.
var testParkGapHook func(*connState)

// hookRewrite consults the policy hook for this head, if the policy has one and
// this head is one it applies to, and returns the verdict merged for the
// rewrite -- or nil, which is the "nothing to change" answer every caller
// handles as the no-hook case.
//
// It exists so that stepHead says what it does with a verdict and this says how
// one is asked for: the request side runs its hook on every head (the request
// is a fresh one each time), the response side only on final responses (1xx
// heads are the interim answer or the upgrade handshake, not a response any
// action describes).
func (r *streamRewriter) hookRewrite(head *parsedHead) *hookRewrite {
	if r.side == sideRequest {
		if r.cp.reqHook == nil {
			return nil
		}
		verdict := r.callRequestHook(head.raw)
		if verdict == nil {
			return nil
		}
		if verdict.Terminate != nil {
			// Terminate is not a rewrite: it is carried out by stepHead, which
			// has to skip the emit and change phase.
			return &hookRewrite{terminate: verdict.Terminate}
		}
		return newHookRewrite(verdict.Add, verdict.Remove, true)
	}
	if head.status < 200 || r.cp.respHook == nil {
		return nil
	}
	verdict := r.callResponseHook(head.raw)
	if verdict == nil {
		return nil
	}
	return newHookRewrite(verdict.Add, verdict.Remove, false)
}

// callRequestHook builds the head-only request and asks the policy about it.
// The object is built from the head bytes alone -- see Policy.RequestHook for
// what is populated -- and a hook that panics or a head that net/http cannot
// read as a request is a skipped hook, never a broken connection: the request
// is forwarded exactly as the static policy left it.
func (r *streamRewriter) callRequestHook(raw []byte) (verdict *RequestVerdict) {
	defer func() {
		if rec := recover(); rec != nil {
			verdict = nil
			r.hookFailed("request hook panicked: %v", rec)
		}
	}()
	// ReadRequest is given the head alone, so the request it returns has no
	// body: the bytes behind the head are still in this direction's reader and
	// are copied, or not, according to what the verdict says.
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(raw)))
	if err != nil {
		r.hookFailed("request head is not readable by net/http (%v)", err)
		return nil
	}
	return r.cp.reqHook(req)
}

// callResponseHook is callRequestHook for the response side.
func (r *streamRewriter) callResponseHook(raw []byte) (verdict *ResponseVerdict) {
	defer func() {
		if rec := recover(); rec != nil {
			verdict = nil
			r.hookFailed("response hook panicked: %v", rec)
		}
	}()
	// The request argument is nil: it only tells ReadResponse whether the
	// response may carry a body, and this Object is never read from anyway.
	// (A response to a HEAD request is still re-emitted byte for byte by the
	// head rewrite, which is where that distinction matters.)
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(raw)), nil)
	if err != nil {
		r.hookFailed("response head is not readable by net/http (%v)", err)
		return nil
	}
	return r.callResponseHookObject(resp)
}

// callResponseHookObject is the hook call itself, for a response object that
// was not parsed from head bytes: today the synthetic response the edge
// fabricated for a terminated request (emitSynthetic). The recover is here as
// well as in callResponseHook so that both callers get the fail-open rule -- a
// hook that panics is a skipped hook, warned about once per direction, never a
// broken connection. emitSynthetic only runs on the response side, so the warn
// this can set is the response direction's -- the same flag a panic on a real
// response head would set, which is what "once per direction" should mean here.
func (r *streamRewriter) callResponseHookObject(resp *http.Response) (verdict *ResponseVerdict) {
	defer func() {
		if rec := recover(); rec != nil {
			verdict = nil
			r.hookFailed("response hook panicked: %v", rec)
		}
	}()
	return r.cp.respHook(resp)
}

// hookFailed reports a hook that could not be used, once per direction per
// connection: a hook that panics on every message is one bug, and the log
// should say so once rather than once per request. The connection is
// unaffected -- this is the fail-open rule applied to hooks.
func (r *streamRewriter) hookFailed(format string, args ...interface{}) {
	if r.hookWarned {
		return
	}
	r.hookWarned = true
	r.lg.Warn("%s hook failed (%s); the connection continues without it",
		r.dir, fmt.Sprintf(format, args...))
}

// emitSynthetic queues a fabricated response and ends this direction: the
// message is the last thing the client reads, and the next Read reports EOF so
// that Join unwinds and both connections close (spec 3.1).
//
// The response hook runs on the way out, so a response-phase action transforms
// an edge answer exactly like an upstream one (see applyResponseHook).
func (r *streamRewriter) emitSynthetic(s *SyntheticResponse) {
	r.applyResponseHook(s)
	r.emit(s.Render())
	r.phase = stDone
}

// applyResponseHook gives the response phase the same say over an answer the
// edge fabricated as over one the upstream wrote: it is what lets a
// response-phase remove-headers or add-headers action transform a deny or a
// custom-response. That is the documented ngrok behavior for the terminating
// action this build answers with most often -- the custom-response page says it
// outright, "When this policy is executed in the on_http_request phase, actions
// defined in the on_http_response phase will still be executed" -- and the deny
// page's "no further actions or rules will be executed" describes the phase the
// action terminated, since the same sentence appears on the page that does spell
// out that the response phase still runs.
//
// The hook is asked about a head-only *http.Response built from s
// (syntheticHead), whose status is the one the client will see rather than the
// zero a default-403 verdict carries, so a rule written against res.status_code
// matches what it looks like it should.
//
// A hook that panics or returns nothing usable is a skipped hook and the
// terminate still goes out: same fail-open rule as the real response path, and
// the same reason for it -- a policy must never be able to break the connection
// it is describing. What a verdict can change is headers, which is all
// ResponseVerdict carries: the status and the body of an edge answer are the
// terminating action's to decide, and there is no upstream response to replace.
func (r *streamRewriter) applyResponseHook(s *SyntheticResponse) {
	if r.cp.respHook == nil {
		return
	}
	verdict := r.callResponseHookObject(syntheticHead(s))
	if verdict == nil {
		return
	}

	// The same order rewriteResponseHead uses: the fields the hook removes are
	// dropped first, by lowercased name, and the entries it adds are appended
	// after the response's own. Both come out of newHookRewrite, so an entry
	// that is unusable -- no colon, a name that is not a token, a value carrying
	// a CR or LF -- is dropped rather than written, and add names are
	// canonicalized the way net/http would have written them.
	//
	// The result is a new slice rather than an edit of s.Headers in place: the
	// verdict belongs to the caller that produced it, and today's policy package
	// happens to hand out a fresh one per evaluation, but a hook is free to reuse
	// an object -- and the rewriter has no business writing into it either way.
	hook := newHookRewrite(verdict.Add, verdict.Remove, false)
	if len(hook.removes) == 0 && len(hook.adds) == 0 {
		return // a hook that matched but changed nothing: leave the bytes alone
	}
	headers := make([]string, 0, len(s.Headers)+len(hook.adds))
	for _, entry := range s.Headers {
		if name, _, ok := splitAddEntry(entry); ok && hook.drops(strings.ToLower(name)) {
			continue
		}
		headers = append(headers, entry)
	}
	for _, add := range hook.adds {
		headers = append(headers, add.name+": "+add.value)
	}
	s.Headers = headers
}

// readLine reads one CRLF-terminated line and appends it to pending, returning
// the line (a view into pending, valid until the next readLine). Reads consume
// exactly up to the line terminator, so nothing beyond the line is ever
// over-consumed: the first body bytes, which usually arrived in the same read,
// stay in br for the next phase to copy.
func (r *streamRewriter) readLine() ([]byte, error) {
	start := len(r.pending)
	raw, err := r.br.ReadSlice('\n')
	if len(raw) > 0 {
		r.pending = append(r.pending, raw...)
	}
	if err == bufio.ErrBufferFull {
		return r.pending[start:], errLineTooLong
	}
	return r.pending[start:], err
}

// nextPhase decides what follows a head: which body framing applies, or that the
// next head is next. gzip says the body will be compressed (and therefore
// re-framed), which only changes the close-delimited case -- the other phases
// read the input's framing exactly as they always did.
func (r *streamRewriter) nextPhase(h *parsedHead, gzip bool) (state, error) {
	if r.side == sideResponse {
		switch {
		case h.status == 101:
			// Switching protocols: from here on the bytes are the upgraded
			// protocol's own framing and are not parsed again.
			r.st.setUpgraded()
			return stRaw, nil
		case h.status >= 100 && h.status < 200:
			return stHead, nil // interim response; the final one follows
		case h.status == 204, h.status == 304:
			return stHead, nil
		case r.st.method() == "HEAD":
			return stHead, nil // a HEAD response carries headers only
		}
	}

	// Transfer-Encoding wins over Content-Length (RFC 7230 3.3.3): a message
	// that carries both has to be framed as chunked or we lose sync with it.
	if h.chunked() {
		return stChunkSize, nil
	}
	length, declared, err := h.contentLength()
	if err != nil {
		return stHead, err
	}
	if declared {
		if length == 0 {
			return stHead, nil
		}
		r.remaining = length
		return stBodyCL, nil
	}
	if r.side == sideRequest {
		return stHead, nil // a request with no body is followed by the next request
	}
	if gzip {
		// Close-delimited input, compressed output: the body runs to EOF either
		// way, but its bytes have to go through the compressor and the message
		// still needs its terminal chunk, so this is not the raw copy. (The
		// early returns above are unreachable here: gzipEligible refuses exactly
		// the statuses and methods that take them.)
		return stGzipClose, nil
	}
	return stRaw, nil // close-delimited response: copy to EOF, there is no next head
}

// stepChunkSize reads one chunk-size line. The line is copied out byte for byte,
// chunk extension included: nothing about chunked framing is re-encoded here.
// While a gzip transform is live the line is dropped instead (flushFraming),
// because the output message carries framing of its own.
func (r *streamRewriter) stepChunkSize() error {
	line, err := r.readLine()
	if err == errLineTooLong {
		r.failOpen("chunk-size line longer than 64 KiB")
		return nil
	}
	if err != nil {
		if len(r.pending) > 0 {
			r.flushPending() // truncated stream: hand over what arrived
			return nil
		}
		return err
	}

	size, ok := parseChunkSize(line)
	if !ok {
		r.failOpen("chunk size %q is not hexadecimal", strings.TrimSpace(string(line)))
		return nil
	}
	r.flushFraming()

	if size == 0 {
		r.phase = stChunkTrailer // the last chunk is followed by trailers
		return nil
	}
	r.chunkLeft = size
	r.phase = stChunkData
	return nil
}

// stepChunkData copies the bytes of one chunk.
func (r *streamRewriter) stepChunkData() error {
	n := int64(len(r.scratch))
	if n > r.chunkLeft {
		n = r.chunkLeft
	}
	read, err := r.br.Read(r.scratch[:n])
	if read > 0 {
		if !r.sourceBody(r.scratch[:read]) {
			return nil // the transform failed open; the raw copy has the rest
		}
		r.chunkLeft -= int64(read)
		if r.chunkLeft == 0 {
			r.chunkEnd = 2 // the CRLF that closes the chunk
			r.phase = stChunkDataEnd
		}
	}
	if err != nil {
		if read > 0 {
			return nil
		}
		return err
	}
	return nil
}

// stepChunkDataEnd copies the CRLF that closes a chunk. The two bytes are
// copied, not checked: a body malformed enough to matter will fail open on its
// next size line, and re-encoding framing is the one thing this package must
// never do. (Under a gzip transform they are dropped with the rest of the input's
// framing -- sourceFraming -- and the compressor's own bytes take their place.)
func (r *streamRewriter) stepChunkDataEnd() error {
	n := r.chunkEnd
	if n > len(r.scratch) {
		n = len(r.scratch)
	}
	read, err := r.br.Read(r.scratch[:n])
	if read > 0 {
		r.sourceFraming(r.scratch[:read])
		r.chunkEnd -= read
		if r.chunkEnd == 0 {
			r.phase = stChunkSize
		}
	}
	if err != nil {
		if read > 0 {
			return nil
		}
		return err
	}
	return nil
}

// stepChunkTrailer copies trailer lines up to the blank line that ends the
// message, then goes back to looking for a head.
func (r *streamRewriter) stepChunkTrailer() error {
	line, err := r.readLine()
	if err == errLineTooLong {
		r.failOpen("chunk trailer line longer than 64 KiB")
		return nil
	}
	if err != nil {
		if len(r.pending) > 0 {
			r.flushFraming()
			return nil
		}
		return err
	}
	blank := isBlankLine(line)
	r.flushFraming()
	if blank {
		// The input message is over. In gzip mode its trailers are dropped rather
		// than forwarded: they describe the body as the upstream framed it (a
		// Content-MD5 over the identity bytes, say), and the message the client is
		// reading is a different body under a different encoding.
		r.endBody()
	}
	return nil
}

// failOpen stops parsing this direction and copies the rest of it verbatim.
// Everything read but not yet emitted is flushed first, in order, so no byte is
// lost or duplicated: from here on the stream is exactly what the raw copy would
// have carried, which is what keeps fail-open from being a behavior change.
func (r *streamRewriter) failOpen(format string, args ...interface{}) {
	r.flushPending()
	if !r.failedOpen {
		r.failedOpen = true
		// Sprintf first: the reason can contain peer-controlled bytes, and it
		// must not be read as a format string by the logger.
		r.lg.Warn("%s: %s; passing the rest of the connection through unmodified",
			r.dir, fmt.Sprintf(format, args...))
	}
	r.phase = stRaw
}

// emit queues bytes for the caller.
func (r *streamRewriter) emit(b []byte) {
	r.out = append(r.out, b...)
}

// flushPending queues everything read but not yet emitted.
func (r *streamRewriter) flushPending() {
	r.emit(r.pending)
	r.pending = r.pending[:0]
}

// The gzip transform (spec 3.4).
//
// The transform is a change of sink, not of parsing. The phases that read a body
// keep tracking the input's framing exactly as they do on the identity path --
// Content-Length, chunks, close-delimited -- and hand the body bytes they copy to
// sourceBody instead of straight to the caller. What leaves the connection is
// always one chunk-framed body, built here; the input's framing bytes go to
// sourceFraming, which drops them, because they would otherwise be read by the
// client as part of the compressed body.
//
// This is the one place the package re-frames anything, and it only ever runs
// for a response that gzipEligible accepted.

// gzipState is the live state of one compressed response: the writer every body
// byte is fed to, and the buffer its compressed output lands in before it is
// framed as chunks. streamRewriter.gz is nil for every message that is not being
// compressed, and nil is the whole switch between the two paths.
type gzipState struct {
	zw  *gzip.Writer
	buf bytes.Buffer
}

// newGzipState starts one compressed message. The writer targets an in-memory
// buffer, so there is no writer to fail and no compression level to get wrong:
// NewWriter has no error to plumb through the body path.
func newGzipState() *gzipState {
	g := &gzipState{}
	g.zw = gzip.NewWriter(&g.buf)
	return g
}

// terminalChunk ends a chunked message.
var terminalChunk = []byte("0\r\n\r\n")

// sourceBody is where a body byte goes: into the compressor while a transform is
// live, and straight to the caller otherwise. It reports false when that
// transform just failed open, which tells the caller to stop framing the input --
// the rest of the connection belongs to the raw copy.
func (r *streamRewriter) sourceBody(b []byte) bool {
	if r.gz == nil {
		r.emit(b)
		return true
	}
	r.feedGzip(b)
	return r.gz != nil
}

// sourceFraming is where the input's own framing bytes go: a chunk-size line, the
// CRLF that closes a chunk, a trailer section. While a transform is live they are
// dropped rather than emitted -- the output message has its own framing, and the
// input's would land in the middle of the compressed body the client is decoding.
func (r *streamRewriter) sourceFraming(b []byte) {
	if r.gz == nil {
		r.emit(b)
	}
}

// flushFraming queues pending bytes as framing: the same as flushPending while the
// message is copied verbatim, and a drop while it is being re-framed.
func (r *streamRewriter) flushFraming() {
	if r.gz != nil {
		r.pending = r.pending[:0]
		return
	}
	r.flushPending()
}

// feedGzip hands body bytes from the source to the compressor and queues the chunk
// frames its output turns into.
//
// Each source read is flushed through the compressor before anything is queued. A
// deflate stream holds input in its window until it has enough of it to be worth
// a block, and the traffic this feature exists for -- an NDJSON token stream --
// would sit in that window until the response ended: the client would see nothing
// at all, then everything. Flushing per read costs a few bytes on bulk transfers
// and is what keeps a compressed stream a stream.
//
// The cost is worth naming, because it is not nothing: a sync flush is a few
// bytes, so it is what a read of a handful of bytes mostly compresses to. Measured
// on ~100-byte NDJSON lines, flushing per read still gives 15x at one line per
// read, 6.7x at 64 bytes, and only turns into expansion below ~32 bytes per read
// (0.86x at 7 bytes), where the alternative -- holding the data until the window
// fills -- is a streaming response that does not stream.
func (r *streamRewriter) feedGzip(src []byte) {
	g := r.gz
	if _, err := g.zw.Write(src); err != nil {
		r.gzipFail(err)
		return
	}
	if err := g.zw.Flush(); err != nil {
		r.gzipFail(err)
		return
	}
	r.emitGzipChunk()
}

// emitGzipChunk moves whatever the compressor has produced into one chunk frame.
// Nothing is emitted when it produced nothing, so a read that has not yet filled
// the compressor's window does not put an empty chunk on the wire.
func (r *streamRewriter) emitGzipChunk() {
	if r.gz.buf.Len() == 0 {
		return
	}
	r.emitChunk(r.gz.buf.Bytes())
	r.gz.buf.Reset()
}

// emitChunk frames b as one chunk of a chunked message: "<hex size>\r\n" b "\r\n".
// It appends to out directly because there is nothing to copy through emit: the
// size line is rendered in place and the payload is one append.
func (r *streamRewriter) emitChunk(b []byte) {
	r.out = strconv.AppendInt(r.out, int64(len(b)), 16)
	r.out = append(r.out, '\r', '\n')
	r.out = append(r.out, b...)
	r.out = append(r.out, '\r', '\n')
}

// finishGzip ends the compressed message: closing the writer emits the deflate
// tail and the gzip trailer, which go out as the final chunk, and the terminal
// chunk follows. It reports false when closing failed, in which case the
// transform has already handed the connection to the raw copy and the caller must
// not touch the phase.
func (r *streamRewriter) finishGzip() bool {
	if err := r.gz.zw.Close(); err != nil {
		r.gzipFail(err)
		return false
	}
	r.emitGzipChunk()
	r.gz = nil
	r.emit(terminalChunk)
	return true
}

// endBody closes out a body that just ended: a satisfied Content-Length, the
// terminal chunk and trailer section of a chunked message, or the EOF of a
// close-delimited one. In gzip mode the compressed message is finished here,
// whatever the input's framing was; either way the next thing to read is a head.
func (r *streamRewriter) endBody() {
	if r.failedOpen {
		return // this direction is a raw copy now, and it stays one
	}
	if r.gz != nil && !r.finishGzip() {
		return // the transform failed open; the phase belongs to the raw copy
	}
	r.phase = stHead
}

// gzipFail abandons the transform. Nothing on this path should be reachable -- the
// compressor writes into an in-memory buffer, so it has no writer to fail -- which
// is exactly why it is written to lose as little as possible: whatever was already
// produced is emitted as a chunk, the reason is logged once, and the rest of the
// connection is copied raw. The client sees a response that breaks, but it does
// not see a connection that hangs or truncates silently.
func (r *streamRewriter) gzipFail(err error) {
	r.emitGzipChunk()
	if !r.failedOpen {
		r.failedOpen = true
		r.lg.Warn("%s: gzip transform failed (%v); passing the rest of the connection through unmodified",
			r.dir, err)
	}
	// Pending framing bytes are dropped, not flushed: half a chunk-size line
	// would desync the client's parser worse than the failure already does.
	r.pending = r.pending[:0]
	r.gz = nil
	r.phase = stRaw
}

// stepGzipClose feeds a close-delimited response body to the compressor. The body
// ends where the stream does, so the message is finished at EOF -- and the bytes
// produced here are queued for the caller, with the EOF itself reported by the
// step after this one, because a step that returns an error must have produced
// nothing.
func (r *streamRewriter) stepGzipClose() error {
	n, err := r.br.Read(r.scratch[:])
	if n > 0 {
		r.feedGzip(r.scratch[:n])
		// These bytes go out before anything else surfaces, whether that is a read
		// error behind them or a transform that just failed open -- and in the
		// latter case the phase is already stRaw, so the next step copies raw.
		return nil
	}
	if err == nil {
		return nil
	}
	if !errors.Is(err, io.EOF) {
		return err // a broken source is not the end of a message
	}
	if r.finishGzip() {
		// Nothing follows a close-delimited body: the source is at EOF, so the
		// raw copy is the phase that reports it with nothing left to emit.
		r.phase = stRaw
	}
	return nil
}

// gzipEligible is the 3.4 skip matrix in one place. Every condition is a reason to
// copy the response byte for byte instead of compressing it, and any one of them
// is enough; the order runs from the cheapest check to the ones that parse the
// head. It is asked only for final responses (stepHead re-emits interim 1xx heads
// verbatim, before this is consulted), so 101 cannot appear here.
func (r *streamRewriter) gzipEligible(h *parsedHead) bool {
	if !r.cp.compress {
		return false
	}
	if h.status < 200 || h.status == 204 || h.status == 304 {
		return false // no body, or no body whose length may change
	}
	if r.st.method() == "HEAD" {
		return false // the response has no body at all
	}
	acceptsGzip, hasRange, chunkedOK := r.st.requestTraits()
	if !acceptsGzip {
		return false // the client never asked for gzip: it never gets gzip
	}
	if hasRange {
		return false // a range answer has to be byte-exact
	}
	if !chunkedOK {
		// The transform re-frames its output as chunked, and an HTTP/1.0 client
		// cannot parse that. It gets the identity response it would have got
		// before this feature existed.
		return false
	}
	if !allowsChunked(h.version) {
		// ...and the message's own start line has to allow it too. A head that
		// says HTTP/1.0 is read as close-delimited whatever its framing fields
		// claim -- Go's response reader ignores a transfer coding on a 1.0
		// response, so the client would read our chunk-size lines as body bytes.
		// An upstream that answers in 1.0 keeps its identity response.
		return false
	}
	if h.hasField("content-encoding") {
		return false // already encoded: a second encoding is not ours to stack on
	}
	if !compressibleType(h.firstValue("content-type")) {
		return false // not a type the transform was told to compress
	}
	// A short declared body is not worth re-framing: gzip's own header and
	// trailer are 18 bytes and the chunk framing adds more, so it would come out
	// larger. A Content-Length that does not even parse is nextPhase's problem --
	// it fails the connection open before any of this is used.
	if length, declared, _ := h.contentLength(); declared && length < minCompressBytes {
		return false
	}
	return true
}

// minCompressBytes is the smallest declared body the transform bothers with.
const minCompressBytes = 128

// compressibleTypes is the configured set of media types the gzip transform
// applies to (3.4). It is a table rather than a chain of conditions so that the
// set can be read, argued about and extended in one place: prefixes cover the
// families, exact entries name the rest.
var compressibleTypes = struct {
	prefixes []string
	exact    map[string]bool
}{
	prefixes: []string{
		"text/", // text/html, text/plain, text/css, text/event-stream, ...
	},
	exact: map[string]bool{
		"application/json":       true,
		"application/javascript": true,
		"application/xml":        true,
		"application/xhtml+xml":  true,
		"application/graphql":    true,
		"image/svg+xml":          true,
		"application/wasm":       true,
	},
}

// compressibleType reports whether a Content-Type value is in the table. The value
// is a media type plus optional parameters ("text/html; charset=utf-8") and the
// parameters do not change the type, so only the part before the first ';' is
// matched. A response that declares no Content-Type at all is not compressed:
// guessing that an unlabelled body is text is exactly the kind of guess this
// package must not make.
func compressibleType(contentType string) bool {
	if i := strings.IndexByte(contentType, ';'); i >= 0 {
		contentType = contentType[:i]
	}
	contentType = strings.ToLower(strings.TrimSpace(contentType))
	for _, prefix := range compressibleTypes.prefixes {
		if strings.HasPrefix(contentType, prefix) {
			return true
		}
	}
	return compressibleTypes.exact[contentType]
}

// allowsChunked reports whether a request's HTTP version can parse chunked
// framing. The gzip transform re-frames every body it touches as chunked and
// HTTP/1.0 clients do not know what that is, so a 1.0 client that does send
// Accept-Encoding: gzip gets an identity response rather than a response it would
// read as garbage.
func allowsChunked(version string) bool {
	// "HTTP/d.d", as parseRequestLine validated.
	if len(version) != len("HTTP/1.1") {
		return false
	}
	if version[5] > '1' {
		return true
	}
	return version[5] == '1' && version[7] >= '1'
}

// headerField is one header line of a head, kept in its original bytes so that
// untouched fields can be re-emitted byte for byte.
type headerField struct {
	raw   []byte // the line exactly as received, terminator included
	name  string // the name as written (original casing)
	lower string // the name lowercased, for case-insensitive matching
	value string // the field value, OWS trimmed
}

// parsedHead is a head split into the pieces the rewriter needs, while keeping
// the original bytes around for verbatim re-emission.
type parsedHead struct {
	raw       []byte // the whole head, for capacity hints and diagnostics
	prefix    []byte // tolerated empty lines before the start line, verbatim
	startLine []byte // request line or status line, verbatim
	fields    []headerField
	blank     []byte // the empty line that ends the head, verbatim

	method  string // request method (request side)
	version string // start-line HTTP version, either side
	status  int    // status code (response side)
}

// parseHead splits a head that readLine assembled. It is deliberately strict
// about the start line and about field names: a stream that does not look like
// HTTP must fail open and be copied verbatim rather than rewritten into
// something guessy.
func parseHead(raw []byte, sd side) (*parsedHead, error) {
	h := &parsedHead{raw: raw}

	rest := raw
	for {
		line, remainder, ok := nextLine(rest)
		if !ok {
			return nil, errors.New("head has no start line")
		}
		rest = remainder
		if isBlankLine(line) {
			h.prefix = append(h.prefix, line...)
			continue
		}
		h.startLine = line
		break
	}

	switch sd {
	case sideRequest:
		method, version, ok := parseRequestLine(h.startLine)
		if !ok {
			return nil, fmt.Errorf("malformed request line %s", quoteLine(h.startLine))
		}
		h.method, h.version = method, version
	case sideResponse:
		version, status, ok := parseStatusLine(h.startLine)
		if !ok {
			return nil, fmt.Errorf("malformed status line %s", quoteLine(h.startLine))
		}
		h.version, h.status = version, status
	}

	for len(rest) > 0 {
		line, remainder, ok := nextLine(rest)
		if !ok {
			return nil, errors.New("head has no terminating empty line")
		}
		rest = remainder
		if isBlankLine(line) {
			h.blank = line
			break
		}
		field, ok := parseHeaderField(line)
		if !ok {
			return nil, fmt.Errorf("malformed header line %s", quoteLine(line))
		}
		h.fields = append(h.fields, field)
	}
	if h.blank == nil {
		return nil, errors.New("head has no terminating empty line")
	}
	return h, nil
}

// parseRequestLine returns the method and version from
// "METHOD SP target SP HTTP/x.y".
func parseRequestLine(line []byte) (method, version string, ok bool) {
	parts := bytes.Split(trimLine(line), []byte(" "))
	if len(parts) != 3 {
		return "", "", false
	}
	method = string(parts[0])
	if !ValidHeaderToken(method) || len(parts[1]) == 0 || !isHTTPVersion(parts[2]) {
		return "", "", false
	}
	return method, string(parts[2]), true
}

// parseStatusLine returns the version and status code from
// "HTTP/x.y SP code [SP reason]".
func parseStatusLine(line []byte) (version string, status int, ok bool) {
	body := trimLine(line)
	space := bytes.IndexByte(body, ' ')
	if space < 0 || !isHTTPVersion(body[:space]) {
		return "", 0, false
	}
	code := body[space+1:]
	if next := bytes.IndexByte(code, ' '); next >= 0 {
		code = code[:next]
	}
	if !allDigits(code) || len(code) != 3 {
		return "", 0, false
	}
	n, err := strconv.Atoi(string(code))
	if err != nil {
		return "", 0, false
	}
	return string(body[:space]), n, true
}

// isHTTPVersion accepts HTTP/1.0, HTTP/1.1 and friends without pinning the
// tunnel to a particular minor version.
func isHTTPVersion(v []byte) bool {
	return len(v) == 8 && string(v[:5]) == "HTTP/" && v[6] == '.' &&
		v[5] >= '0' && v[5] <= '9' && v[7] >= '0' && v[7] <= '9'
}

// parseHeaderField splits one header line. Obsolete line folding (a continuation
// line starting with SP or HTAB) is rejected: RFC 7230 does not allow it outside
// trailers, and passing such a head through unmodified beats half-rewriting it.
func parseHeaderField(line []byte) (headerField, bool) {
	if len(line) == 0 || line[0] == ' ' || line[0] == '\t' {
		return headerField{}, false
	}
	colon := bytes.IndexByte(line, ':')
	if colon <= 0 {
		return headerField{}, false
	}
	name := string(bytes.TrimRight(line[:colon], " \t"))
	if !ValidHeaderToken(name) {
		return headerField{}, false
	}
	term := len(lineTerminator(line))
	value := line[colon+1:]
	if len(value) >= term {
		value = value[:len(value)-term]
	} else {
		value = nil
	}
	return headerField{
		raw:   line,
		name:  name,
		lower: strings.ToLower(name),
		value: strings.Trim(string(value), " \t"),
	}, true
}

// fieldValues returns every value of a header, in the order they appeared.
func (h *parsedHead) fieldValues(name string) []string {
	var values []string
	for _, f := range h.fields {
		if f.lower == name {
			values = append(values, strings.TrimSpace(f.value))
		}
	}
	return values
}

// firstValue returns the first value of a header, or "" when it is absent.
func (h *parsedHead) firstValue(name string) string {
	for _, f := range h.fields {
		if f.lower == name {
			return strings.TrimSpace(f.value)
		}
	}
	return ""
}

// hasField reports whether a head carries a field at all, whatever its value.
// Presence is what matters for "Range" and for "Content-Encoding" -- an empty
// Range header is still a client asking for a range.
func (h *parsedHead) hasField(name string) bool {
	for _, f := range h.fields {
		if f.lower == name {
			return true
		}
	}
	return false
}

// hasToken reports whether a comma-separated header carries a token, matched
// case-insensitively ("Connection: keep-alive, Upgrade").
func (h *parsedHead) hasToken(name, token string) bool {
	for _, v := range h.fieldValues(name) {
		if commaToken(v, token) {
			return true
		}
	}
	return false
}

// commaToken reports whether one comma-separated field value names a token,
// matched case-insensitively. Parameters are part of the value, not noise around
// it: "gzip;q=0" is not "gzip", which is what keeps Accept-Encoding honest -- a
// client that refuses gzip this way is simply not offered it.
func commaToken(value, token string) bool {
	for _, part := range strings.Split(value, ",") {
		if strings.EqualFold(strings.TrimSpace(part), token) {
			return true
		}
	}
	return false
}

// acceptsGzip reports whether a request asked for a gzip response. It matches the
// gzip token in Accept-Encoding exactly, so a q-valued refusal ("gzip;q=0") and
// the wildcard ("*") both decline: the transform only runs when the client named
// gzip itself.
func (h *parsedHead) acceptsGzip() bool {
	return h.hasToken("accept-encoding", "gzip")
}

// isUpgrade reports whether a request asks for a protocol upgrade: it needs both
// "Connection: upgrade" and a non-empty Upgrade field (RFC 7230 6.7).
func (h *parsedHead) isUpgrade() bool {
	return h.hasToken("connection", "upgrade") && h.firstValue("upgrade") != ""
}

// chunked reports whether the message is chunk-framed.
func (h *parsedHead) chunked() bool {
	return h.hasToken("transfer-encoding", "chunked")
}

// contentLength returns the declared body length. A message whose Content-Length
// fields conflict or do not parse has unrecoverable framing (RFC 7230 3.3.3),
// so the caller fails open instead of guessing a length and losing sync.
func (h *parsedHead) contentLength() (int64, bool, error) {
	var (
		length int64
		found  bool
	)
	for _, f := range h.fields {
		if f.lower != "content-length" {
			continue
		}
		value := strings.TrimSpace(f.value)
		if !allDigits([]byte(value)) {
			return 0, false, fmt.Errorf("Content-Length %q is not a number", f.value)
		}
		n, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return 0, false, fmt.Errorf("Content-Length %q is out of range", f.value)
		}
		if found && n != length {
			return 0, false, fmt.Errorf("Content-Length appears twice (%d and %d)", length, n)
		}
		length, found = n, true
	}
	return length, found, nil
}

// nextLine cuts one line off the front of the buffer.
func nextLine(b []byte) (line, rest []byte, ok bool) {
	i := bytes.IndexByte(b, '\n')
	if i < 0 {
		return nil, nil, false
	}
	return b[:i+1], b[i+1:], true
}

// trimLine drops the line terminator.
func trimLine(line []byte) []byte {
	return bytes.TrimRight(line, "\r\n")
}

// lineTerminator returns the line's own terminator: "\r\n", "\n", or "" for a
// line that has neither (which readLine never produces).
func lineTerminator(line []byte) string {
	if n := len(line); n >= 2 && line[n-2] == '\r' && line[n-1] == '\n' {
		return "\r\n"
	} else if n >= 1 && line[n-1] == '\n' {
		return "\n"
	}
	return ""
}

// isBlankLine reports whether a line is the empty line that ends a head.
func isBlankLine(line []byte) bool {
	switch len(line) {
	case 2:
		return line[0] == '\r' && line[1] == '\n'
	case 1:
		return line[0] == '\n'
	}
	return false
}

// quoteLine renders a line for an error message without dumping an unbounded
// amount of (possibly binary) peer data into the log.
func quoteLine(line []byte) string {
	line = trimLine(line)
	const max = 64
	if len(line) > max {
		return fmt.Sprintf("%q...", line[:max])
	}
	return fmt.Sprintf("%q", line)
}

func allDigits(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// parseChunkSize parses the hexadecimal size of one chunk. A chunk extension
// (";name=value") does not change the size but is still copied through verbatim.
func parseChunkSize(line []byte) (int64, bool) {
	body := trimLine(line)
	if i := bytes.IndexByte(body, ';'); i >= 0 {
		body = body[:i]
	}
	body = bytes.Trim(body, " \t")
	if len(body) == 0 || len(body) > 16 {
		return 0, false
	}
	for _, c := range body {
		if !isHexDigit(c) {
			return 0, false
		}
	}
	n, err := strconv.ParseInt(string(body), 16, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// rewriteRequestHead re-emits a request head with the policy applied, in the
// order 4.4 lays out: removals, then the Host (plus X-Forwarded-Host), then the
// configured additions, then X-Forwarded-For and X-Forwarded-Proto.
//
// hook is the merged request hook verdict, appended after the policy's own
// additions and merged into the same removal set; nil -- no hook, or a verdict
// that changed nothing -- emits exactly the bytes this function emitted before
// hooks existed.
//
// Untouched fields are re-emitted from their original bytes, so their order,
// casing, spacing and line endings survive exactly. Only the fields the policy
// names are re-rendered, and only their values change.
func (cp *compiledPolicy) rewriteRequestHead(h *parsedHead, hook *hookRewrite) []byte {
	out := make([]byte, 0, len(h.raw)+128)
	out = append(out, h.prefix...)
	out = append(out, h.startLine...)

	// A hook's Host entry overrides the static policy's, the same way a static
	// add entry does (4.2): "host" names one field, not one more copy of it.
	hostValue := cp.hostValue
	if hook != nil && hook.host != "" {
		hostValue = hook.host
	}

	origHost := h.firstValue("host")
	xForwardedHost := ""
	if hostValue != "" && origHost != "" {
		xForwardedHost = origHost // 4.1: the original Host is saved, not lost
	}

	// A message that carries both framings is a request-smuggling vector and
	// this package is an intermediary on it, so RFC 7230 3.3.3's "a sender MUST
	// NOT send a Content-Length header field in any message that contains a
	// Transfer-Encoding header field" applies to what is emitted here. The
	// framing this direction copies the body with is chunked whenever the token
	// is there (nextPhase), so the Content-Length is not merely redundant: it is
	// a second, disagreeing statement of where the body ends, and the next hop
	// is free to believe it. Dropping it leaves the head saying exactly one
	// thing, which is what the body bytes behind it actually are.
	//
	// The test is the token, not the field. A Transfer-Encoding without the
	// chunked token names a coding this build cannot frame with, so the body
	// behind it is copied by Content-Length and the head keeps the field that
	// describes what was copied. (RFC 7230 3.3.3 calls such a message unreliable
	// and has the next hop reject it; forwarding a length the origin cannot
	// agree with is the one outcome worse than forwarding a length it can.)
	//
	// The decision does not consult what the policy removes. A policy that
	// strips Transfer-Encoding still gets a chunk-framed body -- the removes
	// shape the head, and the framing was decided by the input (nextPhase) --
	// so keeping the Content-Length would leave the head claiming a length the
	// bytes behind it do not have. Stripping the field is the policy author's
	// choice and this package does not second-guess it; it just refuses to put a
	// second lie in the head on top of the one that removal already told.
	dropCL := h.chunked()

	hostWritten := false
	for _, f := range h.fields {
		if dropCL && f.lower == "content-length" {
			continue
		}
		if cp.reqRemoves[f.lower] || hook.drops(f.lower) {
			continue
		}
		if f.lower == "host" && hostValue != "" {
			out = appendFieldValue(out, f.raw, hostValue)
			hostWritten = true
			continue
		}
		out = append(out, f.raw...)
	}

	if hostValue != "" && !hostWritten {
		// No Host field to replace (an HTTP/1.0 request). The policy still says
		// which host the upstream should see, so add one rather than silently
		// dropping the rewrite.
		out = appendHeaderLine(out, "Host", hostValue)
	}
	if xForwardedHost != "" {
		out = appendHeaderLine(out, "X-Forwarded-Host", xForwardedHost)
	}
	// The hook's entries come after the policy's own, and in the order the hook
	// returned them: a later action that adds the same name appends rather than
	// replaces (ngrok parity), and the two loops keep the hook's slice from
	// ever being appended into the policy's -- cp is shared by every message on
	// this connection, both directions included.
	for _, add := range cp.reqAdds {
		out = appendHeaderLine(out, add.name, add.value)
	}
	if hook != nil {
		for _, add := range hook.adds {
			out = appendHeaderLine(out, add.name, add.value)
		}
	}
	// 4.4 step 4: these two go last, so an upstream that keeps the last value of
	// a repeated header sees ours rather than anything the client sent.
	if cp.xffValue != "" {
		out = appendHeaderLine(out, "X-Forwarded-For", cp.xffValue)
	}
	if cp.xfpValue != "" {
		out = appendHeaderLine(out, "X-Forwarded-Proto", cp.xfpValue)
	}
	return append(out, h.blank...)
}

// rewriteResponseHead re-emits a response head with the response half of the
// policy applied. Responses have no Host or X-Forwarded semantics: only the
// configured additions and removals (4.2). It is only ever called for final
// responses: interim 1xx heads are re-emitted verbatim by stepHead, and the
// response hook is not consulted for them either (1xx is the upgrade handshake
// and the interim answer, not the response a policy action describes).
//
// hook is the merged response hook verdict, appended after the policy's own
// additions; nil emits exactly the bytes this function emitted before hooks
// existed.
//
// gzip says the body behind this head is being compressed, which makes the head
// describe a body the upstream never sent. Three things change, and they are the
// minimum a client needs to read what follows:
//
//   - Content-Length goes: the compressed length is not known until the body
//     ends, and the declared one belongs to the bytes being replaced.
//   - ETag goes: it validates bytes that no longer exist. Handing a client an
//     ETag for a body it cannot get back -- through a conditional request that
//     would then be answered from a cache -- is worse than handing it none.
//   - Transfer-Encoding: chunked is declared if the head did not already
//     declare it, because the transform's output *is* chunk-framed. Without a
//     framing header a response is close-delimited (RFC 7230 3.3.3), which
//     would leave the client reading chunk-size lines as body bytes.
//
// Content-Encoding: gzip and Vary: Accept-Encoding are appended. Every other
// field, including one the upstream sent folded or oddly cased, keeps its bytes.
func (cp *compiledPolicy) rewriteResponseHead(h *parsedHead, gzip bool, hook *hookRewrite) []byte {
	out := make([]byte, 0, len(h.raw)+128)
	out = append(out, h.prefix...)
	out = append(out, h.startLine...)

	// The request side's rule, for the request side's reason: a response that
	// declares both framings must go out declaring one (RFC 7230 3.3.3, and see
	// rewriteRequestHead for how the token decides it, including why the removes
	// do not enter into it). It matters in this direction too -- the client is
	// the next hop and a smuggled response is as good as a smuggled request to
	// anything behind it, a cache included. gzip drops every Content-Length on
	// its own, below, so the two never disagree about the field.
	dropCL := h.chunked()

	chunkedDeclared := false
	for _, f := range h.fields {
		if dropCL && f.lower == "content-length" {
			continue
		}
		if cp.respRemoves[f.lower] || hook.drops(f.lower) {
			continue
		}
		if gzip {
			switch f.lower {
			case "content-length", "etag":
				continue
			case "transfer-encoding":
				// A chunked declaration still describes the output, so it stays as
				// it was written; any other transfer coding described the body
				// being replaced, and the framing is redeclared below.
				if !commaToken(f.value, "chunked") {
					continue
				}
				chunkedDeclared = true
			}
		}
		out = append(out, f.raw...)
	}

	for _, add := range cp.respAdds {
		out = appendHeaderLine(out, add.name, add.value)
	}
	if hook != nil {
		for _, add := range hook.adds {
			out = appendHeaderLine(out, add.name, add.value)
		}
	}
	if gzip {
		if !chunkedDeclared {
			out = appendHeaderLine(out, "Transfer-Encoding", "chunked")
		}
		out = appendHeaderLine(out, "Content-Encoding", "gzip")
		// A second Vary field is legal and caches combine them, so an upstream
		// Vary of its own is left alone rather than merged.
		out = appendHeaderLine(out, "Vary", "Accept-Encoding")
	}
	return append(out, h.blank...)
}

// appendHeaderLine appends one header field with a CRLF terminator, the
// canonical form for the fields we add ourselves (4.2).
func appendHeaderLine(dst []byte, name, value string) []byte {
	dst = append(dst, name...)
	dst = append(dst, ':', ' ')
	dst = append(dst, value...)
	return append(dst, '\r', '\n')
}

// appendFieldValue re-renders one existing field line with a new value, keeping
// the name bytes as written (casing included) and the original line terminator,
// so that only the value changes.
func appendFieldValue(dst, raw []byte, value string) []byte {
	colon := bytes.IndexByte(raw, ':')
	if colon < 0 {
		return append(dst, raw...) // not a field we understand: leave it be
	}
	dst = append(dst, raw[:colon]...)
	dst = append(dst, ':', ' ')
	dst = append(dst, value...)
	return append(dst, lineTerminator(raw)...)
}
