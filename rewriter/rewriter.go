// Package rewriter rewrites the HTTP heads that flow through an ngrok tunnel
// while leaving everything else on the wire byte-identical.
//
// Two per-direction state machines (see streamRewriter) parse just enough of
// the stream to find each message head, apply the tunnel's header Policy, and
// copy the rest -- bodies, chunk framing, trailers, websocket frames -- through
// untouched. They are read-driven: no extra goroutines, no buffering beyond
// each direction's connection-lifetime bufio.Reader, and no bytes produced
// before the caller asks for them, so back-pressure is exactly what the raw
// connection had.
//
// The rule that keeps this safe on a live tunnel is fail-open: anything the
// machines cannot make sense of (a head past 64 KiB, a malformed start line, a
// truncated message, a chunk-size line that is not hex) stops the parsing and
// hands that direction back to a raw byte copy, after emitting every byte that
// has already been read. A connection the old code would have carried keeps
// working; it just stops being rewritten.
package rewriter

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/textproto"
	"strconv"
	"strings"
	"sync"

	"ngrok/log"
)

const (
	// readBufferSize is the size of each direction's connection-lifetime
	// bufio.Reader. Every read goes through it, including the raw copies, so
	// bytes that arrive bundled with a head (a head and the first body bytes
	// usually share a TCP segment) stay in order across a phase change.
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

	RequestHeaderAdd     []string // "Key: value" pairs, append semantics
	RequestHeaderRemove  []string // header names
	ResponseHeaderAdd    []string
	ResponseHeaderRemove []string

	UpstreamHost string // hostname of tunnel.LocalAddr, for "rewrite"
	ClientAddr   string // from StartProxy.ClientAddr

	XForwardedProto string // "http" | "https"
}

// Validate checks the policy for CR/LF injection, user-agent targets and
// malformed add entries. Errors name the offending entry, so a typo'd config
// fails loudly at load time instead of silently mangling traffic later.
func (p *Policy) Validate() error {
	if err := validateHostHeader(p.HostHeader); err != nil {
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
		if strings.ContainsAny(f.value, "\r\n") {
			return fmt.Errorf("%s %q must not contain CR or LF", f.name, f.value)
		}
	}

	for _, entry := range p.RequestHeaderAdd {
		if err := validateAddEntry("request_header", entry); err != nil {
			return err
		}
	}
	for _, entry := range p.ResponseHeaderAdd {
		if err := validateAddEntry("response_header", entry); err != nil {
			return err
		}
	}
	for _, name := range p.RequestHeaderRemove {
		if err := validateRemoveName("request_header", name); err != nil {
			return err
		}
	}
	for _, name := range p.ResponseHeaderRemove {
		if err := validateRemoveName("response_header", name); err != nil {
			return err
		}
	}
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
	if len(p.RequestHeaderAdd) > 0 || len(p.RequestHeaderRemove) > 0 ||
		len(p.ResponseHeaderAdd) > 0 || len(p.ResponseHeaderRemove) > 0 {
		return false
	}
	if p.ClientAddr != "" || p.XForwardedProto != "" {
		return false
	}
	switch strings.ToLower(p.HostHeader) {
	case "", "preserve":
		return true
	}
	return false
}

// validateHostHeader accepts the two keywords and any explicit hostname that
// cannot be used to inject a header (spec 4.1). The keywords are matched
// case-insensitively; any other non-empty value is taken as the hostname to
// send, so "REWRITE" is not reachable as a host.
func validateHostHeader(v string) error {
	switch strings.ToLower(v) {
	case "", "rewrite", "preserve":
		return nil
	}
	if strings.ContainsAny(v, " \t\r\n/") {
		return fmt.Errorf("host_header %q is not a valid hostname: no spaces, '/' or CR/LF", v)
	}
	return nil
}

// validateAddEntry checks one "Key: value" entry: it must split at a colon,
// carry a valid field name, and neither name nor value may smuggle a header.
func validateAddEntry(scope, entry string) error {
	name, value, ok := splitAddEntry(entry)
	if !ok {
		return fmt.Errorf("%s add entry %q must be \"Key: value\"", scope, entry)
	}
	if !isToken(name) {
		return fmt.Errorf("%s add entry %q: %q is not a valid header name", scope, entry, name)
	}
	if strings.EqualFold(name, "user-agent") {
		return fmt.Errorf("%s add entry %q: user-agent cannot be added (ngrok parity)", scope, entry)
	}
	if strings.ContainsAny(value, "\r\n") {
		return fmt.Errorf("%s add entry %q: value must not contain CR or LF", scope, entry)
	}
	return nil
}

// validateRemoveName checks a header name that a policy wants to drop.
func validateRemoveName(scope, name string) error {
	if !isToken(name) {
		return fmt.Errorf("%s remove entry %q is not a valid header name", scope, name)
	}
	if strings.EqualFold(name, "user-agent") {
		return fmt.Errorf("%s remove entry %q: user-agent cannot be removed (ngrok parity)", scope, name)
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

// isToken reports whether s is a non-empty RFC 7230 token, the only thing a
// header name may be.
func isToken(s string) bool {
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

// compiledPolicy is the per-connection view of a Policy: entries are split,
// canonicalized and lowercased once when the connection is wrapped instead of
// once per request, and the X-Forwarded wiring is resolved into plain values.
// It is immutable afterwards and shared by both directions.
type compiledPolicy struct {
	reqRemoves  map[string]bool
	respRemoves map[string]bool
	reqAdds     []headerAdd
	respAdds    []headerAdd

	// hostValue is the Host to put on requests; "" leaves Host alone (4.1).
	hostValue string

	// xffValue and xfpValue are the values to inject as X-Forwarded-For and
	// X-Forwarded-Proto; "" injects nothing (4.3).
	xffValue string
	xfpValue string
}

// compilePolicy precomputes everything the per-request path needs. lg receives
// the one-off warnings about entries that cannot be used at all; Validate is the
// real gate, but a policy that skipped validation must not silently rewrite
// traffic either.
func compilePolicy(p *Policy, lg log.Logger) *compiledPolicy {
	cp := &compiledPolicy{
		reqRemoves:  lowerSet(p.RequestHeaderRemove),
		respRemoves: lowerSet(p.ResponseHeaderRemove),
		xffValue:    p.ClientAddr,
		xfpValue:    p.XForwardedProto,
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
		if !ok || !isToken(name) || strings.ContainsAny(value, "\r\n") {
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

	// upgraded records an upgrade handshake: either a request carried
	// Connection: upgrade plus an Upgrade field (that side goes raw right after
	// emitting its head), or a 101 response was seen (the response side goes raw,
	// and the request side checks this flag before parsing its next head).
	upgraded bool
}

func (st *connState) setMethod(method string) {
	st.mu.Lock()
	st.lastMethod = method
	st.mu.Unlock()
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
// a single connection-lifetime bufio.Reader and queues transformed bytes in out,
// from where Read hands them to the caller.
type streamRewriter struct {
	side side
	dir  string // "request" or "response", for log messages

	br *bufio.Reader
	lg log.Logger
	st *connState
	cp *compiledPolicy

	// pending holds bytes read from br that have not been handed to the caller
	// yet: the head being assembled, plus any line read but not yet classified.
	// Fail-open flushes it verbatim, which is what makes "never lose bytes" hold
	// even when the stream stops making sense.
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
}

// NewPair returns the two read-driven rewriters of one connection: req for the
// public->local direction (reads requests) and resp for the local->public
// direction (reads responses). They share the connection state that ties them
// together: the last request method (a HEAD response has no body) and the
// upgrade flag.
func NewPair(reqSrc, respSrc io.Reader, p *Policy) (req, resp io.Reader) {
	return newPair(reqSrc, respSrc, p, log.NewPrefixLogger("rewriter"), log.NewPrefixLogger("rewriter"))
}

// newPair is NewPair with an explicit logger per direction, so that the conn
// adapter can log through the connections themselves (and thus with their ids).
func newPair(reqSrc, respSrc io.Reader, p *Policy, reqLog, respLog log.Logger) (req, resp io.Reader) {
	cp := compilePolicy(p, reqLog)
	st := &connState{}

	req = &streamRewriter{
		side: sideRequest, dir: "request",
		br: bufio.NewReaderSize(reqSrc, readBufferSize), lg: reqLog, st: st, cp: cp,
		phase: stHead,
	}
	resp = &streamRewriter{
		side: sideResponse, dir: "response",
		br: bufio.NewReaderSize(respSrc, readBufferSize), lg: respLog, st: st, cp: cp,
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
// needs the full state machine instead.
func (r *streamRewriter) directRead(p []byte) (int, error) {
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
	}
	return r.stepRaw()
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
		r.phase = stHead
		return nil
	}
	n := int64(len(r.scratch))
	if n > r.remaining {
		n = r.remaining
	}
	read, err := r.br.Read(r.scratch[:n])
	if read > 0 {
		r.emit(r.scratch[:read])
		r.remaining -= int64(read)
		if r.remaining == 0 {
			r.phase = stHead
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

	r.pending = r.pending[:0]
	started := false
	for {
		line, err := r.readLine()
		if err == errLineTooLong {
			r.failOpen("head line longer than 64 KiB")
			return nil
		}
		if err != nil {
			if len(r.pending) == 0 {
				return err // clean end of stream at a message boundary
			}
			// End of stream inside a head: the connection is over either way, but
			// the peer still gets every byte it sent.
			r.failOpen("end of stream in the middle of a head")
			return nil
		}
		if len(r.pending) > maxHeadBytes {
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
		r.failOpen("malformed head: %v", err)
		return nil
	}

	// Keep the shared state current before the other direction can look at it.
	if r.side == sideRequest {
		r.st.setMethod(head.method)
		if head.isUpgrade() {
			r.st.setUpgraded()
		}
	}

	next, err := r.nextPhase(head)
	if err != nil {
		r.failOpen("malformed framing: %v", err)
		return nil
	}

	var rewritten []byte
	switch {
	case r.side == sideRequest:
		rewritten = r.cp.rewriteRequestHead(head)
	case head.status < 200:
		// Interim 1xx heads (100 Continue, 101, ...) take no response policy:
		// ngrok applies response actions to the final response only, and a 101
		// belongs to the upgrade handshake. Re-emit them verbatim.
		rewritten = head.raw
	default:
		rewritten = r.cp.rewriteResponseHead(head)
	}

	r.pending = r.pending[:0]
	r.emit(rewritten)
	r.phase = next
	return nil
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
// next head is next.
func (r *streamRewriter) nextPhase(h *parsedHead) (state, error) {
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
	return stRaw, nil // close-delimited response: copy to EOF, there is no next head
}

// stepChunkSize reads one chunk-size line. The line is copied out byte for byte,
// chunk extension included: nothing about chunked framing is re-encoded here.
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
	r.flushPending()

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
		r.emit(r.scratch[:read])
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
// never do.
func (r *streamRewriter) stepChunkDataEnd() error {
	n := r.chunkEnd
	if n > len(r.scratch) {
		n = len(r.scratch)
	}
	read, err := r.br.Read(r.scratch[:n])
	if read > 0 {
		r.emit(r.scratch[:read])
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
			r.flushPending()
			return nil
		}
		return err
	}
	blank := isBlankLine(line)
	r.flushPending()
	if blank {
		r.phase = stHead
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

	method string // request method (request side)
	status int    // status code (response side)
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
		method, ok := parseRequestLine(h.startLine)
		if !ok {
			return nil, fmt.Errorf("malformed request line %s", quoteLine(h.startLine))
		}
		h.method = method
	case sideResponse:
		status, ok := parseStatusLine(h.startLine)
		if !ok {
			return nil, fmt.Errorf("malformed status line %s", quoteLine(h.startLine))
		}
		h.status = status
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

// parseRequestLine returns the method from "METHOD SP target SP HTTP/x.y".
func parseRequestLine(line []byte) (string, bool) {
	parts := bytes.Split(trimLine(line), []byte(" "))
	if len(parts) != 3 {
		return "", false
	}
	method := string(parts[0])
	if !isToken(method) || len(parts[1]) == 0 || !isHTTPVersion(parts[2]) {
		return "", false
	}
	return method, true
}

// parseStatusLine returns the status code from "HTTP/x.y SP code [SP reason]".
func parseStatusLine(line []byte) (int, bool) {
	body := trimLine(line)
	space := bytes.IndexByte(body, ' ')
	if space < 0 || !isHTTPVersion(body[:space]) {
		return 0, false
	}
	code := body[space+1:]
	if next := bytes.IndexByte(code, ' '); next >= 0 {
		code = code[:next]
	}
	if !allDigits(code) || len(code) != 3 {
		return 0, false
	}
	n, err := strconv.Atoi(string(code))
	if err != nil {
		return 0, false
	}
	return n, true
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
	if !isToken(name) {
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

// hasToken reports whether a comma-separated header carries a token, matched
// case-insensitively ("Connection: keep-alive, Upgrade").
func (h *parsedHead) hasToken(name, token string) bool {
	for _, v := range h.fieldValues(name) {
		for _, part := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
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
// Untouched fields are re-emitted from their original bytes, so their order,
// casing, spacing and line endings survive exactly. Only the fields the policy
// names are re-rendered, and only their values change.
func (cp *compiledPolicy) rewriteRequestHead(h *parsedHead) []byte {
	out := make([]byte, 0, len(h.raw)+128)
	out = append(out, h.prefix...)
	out = append(out, h.startLine...)

	origHost := h.firstValue("host")
	xForwardedHost := ""
	if cp.hostValue != "" && origHost != "" {
		xForwardedHost = origHost // 4.1: the original Host is saved, not lost
	}

	hostWritten := false
	for _, f := range h.fields {
		if cp.reqRemoves[f.lower] {
			continue
		}
		if f.lower == "host" && cp.hostValue != "" {
			out = appendFieldValue(out, f.raw, cp.hostValue)
			hostWritten = true
			continue
		}
		out = append(out, f.raw...)
	}

	if cp.hostValue != "" && !hostWritten {
		// No Host field to replace (an HTTP/1.0 request). The policy still says
		// which host the upstream should see, so add one rather than silently
		// dropping the rewrite.
		out = appendHeaderLine(out, "Host", cp.hostValue)
	}
	if xForwardedHost != "" {
		out = appendHeaderLine(out, "X-Forwarded-Host", xForwardedHost)
	}
	for _, add := range cp.reqAdds {
		out = appendHeaderLine(out, add.name, add.value)
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
// responses: interim 1xx heads are re-emitted verbatim by stepHead.
func (cp *compiledPolicy) rewriteResponseHead(h *parsedHead) []byte {
	out := make([]byte, 0, len(h.raw)+128)
	out = append(out, h.prefix...)
	out = append(out, h.startLine...)
	for _, f := range h.fields {
		if cp.respRemoves[f.lower] {
			continue
		}
		out = append(out, f.raw...)
	}
	for _, add := range cp.respAdds {
		out = appendHeaderLine(out, add.name, add.value)
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
