package server

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"html"
	"io"
	"ngrok/conn"
	"ngrok/log"
	"ngrok/msg"
	"ngrok/policy"
	"strings"
	"sync/atomic"
	"time"
)

const (
	NotAuthorized = `HTTP/1.0 401 Not Authorized
WWW-Authenticate: Basic realm="ngrok"
Content-Length: 23

Authorization required
`

	// NotFound is the answer to a Host no tunnel is registered for. The
	// hostname is echoed back into the body, escaped (see notFoundResponse),
	// and the content type says what the body is: the field is peer-supplied
	// data, and a response that renders it raw -- or leaves the browser to
	// sniff a type for it -- turns a 404 into a reflected-content gadget.
	NotFound = `HTTP/1.0 404 Not Found
Content-Type: text/plain; charset=utf-8
X-Content-Type-Options: nosniff
Content-Length: %d

Tunnel %s not found
`

	BadRequest = `HTTP/1.0 400 Bad Request
Content-Type: text/plain; charset=utf-8
Content-Length: 12

Bad Request
`

	// MisdirectedRequest answers a request whose Host names an
	// agent-terminated endpoint on a connection this server has already
	// terminated (SPEC-CLUSTER5 5.2). 421 is the status RFC 9110 defines for
	// exactly this -- "the request was directed at a server that is unable or
	// unwilling to produce an authoritative response" -- and it matters more
	// than a plain error here: a client that reached for the agent's endpoint
	// over the wrong TLS layer must be told to re-connect naming the endpoint
	// (SNI), because no response this server could produce would ever be
	// authoritative for it. As with NotFound, the hostname is escaped and the
	// body typed, because it is peer-supplied data a browser will render.
	MisdirectedRequest = `HTTP/1.0 421 Misdirected Request
Content-Type: text/plain; charset=utf-8
X-Content-Type-Options: nosniff
Content-Length: %d

%s`

	BadGateway = `HTTP/1.0 502 Bad Gateway
Content-Type: text/plain; charset=utf-8
Content-Length: %d

%s`

	// HeadTooLarge answers a request whose head does not fit in maxHeadBytes.
	// 431 rather than 400 because the request may be perfectly well formed and
	// simply too big for this edge to route, and the reason travels in the body
	// so the client is not left guessing which limit it hit.
	HeadTooLarge = `HTTP/1.0 431 Request Header Fields Too Large
Content-Type: text/plain; charset=utf-8
Connection: close
Content-Length: %d

%s`
)

// maxHeadBytes caps the request head this listener reads before routing, and
// matches the rewriter's own limit (rewriter.maxHeadBytes): 64 KiB is far more
// than any real head needs, and it is small enough that a connection cannot
// make the server hold an unbounded amount of memory before it has been
// assigned a tunnel.
const maxHeadBytes = 64 * 1024

// Reasons a head is refused. Both are answered with HeadTooLarge; the
// distinction is only for the log and the body.
var (
	errHeadTooLarge    = fmt.Errorf("request head larger than %d bytes", maxHeadBytes)
	errHeadLineTooLong = fmt.Errorf("request head line longer than %d bytes", maxHeadBytes)
)

// respondBadGateway refuses a public connection whose forward_to chain cannot
// be resolved (SPEC 3.3): the target is offline, the chain loops, or it is
// longer than we follow. The reason travels to the client verbatim and is
// logged at the edge, so a broken chain is never a silent 404 or a dropped
// connection.
func respondBadGateway(c conn.Conn, err error) {
	c.Warn("Refusing connection: %v", err)

	body := fmt.Sprintf("Bad Gateway: %v\n", err)
	c.Write([]byte(fmt.Sprintf(BadGateway, len(body), body)))
}

// respondHeadTooLarge answers a request whose head could not be read within the
// cap. The connection is closed afterwards (the caller returns), so a client
// cannot use an oversized head to hold a connection open.
func respondHeadTooLarge(c conn.Conn, err error) {
	c.Warn("Refusing request: %v", err)

	body := fmt.Sprintf("Bad Request: %v\n", err)
	c.Write([]byte(fmt.Sprintf(HeadTooLarge, len(body), body)))
}

// notFoundResponse renders the 404 for a Host no tunnel is registered for.
//
// The hostname is escaped and the body is typed as text/plain. Both matter:
// this string is echoed from the request into a response that a browser will
// render, so an unescaped <script> in a Host header would be a reflected XSS on
// the tunnel domain itself (the Host is attacker-controlled and needs no
// authentication to send).
//
// The value substituted into NotFound is the escaped host, not a body: the
// constant already spells the sentence around it ("Tunnel %s not found"), so
// passing a body here renders the sentence twice. The length has to be measured
// against what the constant actually renders, escaping and trailing newline
// included, or Content-Length disagrees with the bytes written.
func notFoundResponse(host string) []byte {
	escaped := html.EscapeString(host)
	body := fmt.Sprintf("Tunnel %s not found\n", escaped)
	return []byte(fmt.Sprintf(NotFound, len(body), escaped))
}

// misdirectedResponse renders the 421 for a Host that names an agent-
// terminated endpoint on a connection the server already terminated. The
// hostname is escaped for the same reason notFoundResponse escapes it: it is
// attacker-controlled and the body is rendered by a browser.
func misdirectedResponse(host string) []byte {
	escaped := html.EscapeString(host)
	// Unlike NotFound, whose constant spells the sentence around its %s, the
	// MisdirectedRequest constant ends in a bare %s: the sentence below IS the
	// body, so it must be the value substituted -- passing the escaped host
	// instead would announce the sentence's length and send only the host,
	// and a conforming client would wait forever for the missing bytes.
	body := fmt.Sprintf("Tunnel %s terminates TLS in its agent; connect again naming the endpoint's hostname (SNI)\n", escaped)
	return []byte(fmt.Sprintf(MisdirectedRequest, len(body), body))
}

// admitPublicHTTPConn applies the two per-IP admission gates -- rate limit,
// then concurrent-connection cap, in that order (the order every public path
// runs: http, tcp, udp) -- to a public connection BEFORE any bytes of it are
// processed. On refusal it answers BadRequest, publishes the drop event and
// returns ok=false (the caller closes/returns); on pass it returns the ip the
// gates keyed on, which the caller OWNS: it must release the acquired slot
// on the connection's lifetime (defer connLimiter.Load().release(ip)).
//
// The https listener calls this BEFORE the SNI peek (a rate/cap verdict keys
// on the source IP and needs no SNI), and its two branches -- serveAgentTLS
// and terminateWithServerCert -> routeHTTP -- deliberately do NOT gate again:
// one connection, each gate exactly once, whichever route it takes.
func admitPublicHTTPConn(c conn.Conn) (ip string, ok bool) {
	ip = remoteIP(c.RemoteAddr())
	if !publicLimiter.Load().allow(ip) {
		atomic.AddUint64(&rateDropCount, 1)
		observe.events.publishRateLimitDrop(scopePublicHTTP, ip)
		if warnSampler.allow("public-rate:" + ip) {
			log.Warn("Rate-limited public request from %s", ip)
		}
		c.Write([]byte(BadRequest))
		return ip, false
	}
	if !connLimiter.Load().acquire(ip) {
		observe.events.publishConnectionCapDrop(scopePublicHTTP, ip)
		if warnSampler.allow("public-cap:" + ip) {
			log.Warn("Connection cap reached for %s", ip)
		}
		c.Write([]byte(BadRequest))
		return ip, false
	}
	return ip, true
}

// Listens for new http(s) connections from the public internet
func startHttpListener(addr string, tlsCfg *tls.Config) (listener *conn.Listener) {
	// The listener accepts raw connections on both variants: the plain-http
	// listener always did (its TLS config is nil), and the https listener
	// used to have conn.Listen wrap every accepted conn in tls.Server before
	// anything could look at it. It must not any more (SPEC-CLUSTER5 5.2):
	// whether this connection terminates here or passes through to an agent
	// is decided per connection, from the ClientHello, and the wrap is part
	// of that decision.
	var err error
	if listener, err = conn.Listen(addr, "pub", nil); err != nil {
		panic(err)
	}

	// The protocol name is both the log line's and the key a tunnel is looked
	// up under ("<proto>://<host>", below), so it comes from package msg with
	// the rest of the wire vocabulary rather than being spelled again here.
	proto := msg.ProtoHTTP
	if tlsCfg != nil {
		proto = msg.ProtoHTTPS
	}

	log.Info("Listening for public %s connections on %v", proto, listener.Addr.String())
	go func() {
		for c := range listener.Conns {
			if tlsCfg == nil {
				go httpHandler(c, proto)
				continue
			}
			go httpsConnHandler(c, tlsCfg)
		}
	}()

	return
}

// httpsConnHandler demultiplexes one connection accepted on the https
// listener (SPEC-CLUSTER5 5.2). The ClientHello is peeked first -- bounded,
// with the same read budget and deadline every public connection gets -- and
// the endpoint it names decides the connection's fate:
//
//   - SNI names an agent-terminated endpoint: the connection is joined to the
//     endpoint's agent AS RAW BYTES. The server never terminates this TLS and
//     never sees the plaintext; the peeked bytes are replayed so the agent's
//     own TLS terminator sees the hello byte for byte.
//   - everything else -- SNI absent, SNI unmatched, SNI matched to an edge
//     endpoint, or a stream that is not a ClientHello at all -- terminates
//     with the server certificate, and httpHandler routes by Host exactly as
//     it always has. A failed peek is treated as SNI-absent on purpose: the
//     TLS terminator, not this parser, answers a bad stream, and it does so
//     with a real TLS alert because it sees the real bytes.
func httpsConnHandler(c conn.Conn, tlsCfg *tls.Config) {
	defer c.Close()
	defer func() {
		// recover from failures, as httpHandler does
		if r := recover(); r != nil {
			c.Warn("httpsConnHandler failed with error %v", r)
		}
	}()

	// The read deadline bounds whatever this connection does next (peek, or
	// nothing, if the gates below refuse it); the admission gates run BEFORE
	// the peek: the rate/cap keys are the source IP and need no SNI, so a
	// refused connection is turned away without the server reading one byte
	// of its ClientHello -- an attacker cannot spend peek work (or log SNI
	// lines) once its IP is over budget. Both branches below (serveAgentTLS
	// and terminateWithServerCert -> routeHTTP) deliberately skip the gates:
	// this is the one pass per connection. The slot lives for the whole
	// handler -- the conn's lifetime.
	c.SetDeadline(time.Now().Add(connReadTimeout))
	ip, admitted := admitPublicHTTPConn(c)
	if !admitted {
		return
	}
	defer connLimiter.Load().release(ip)
	incPublicConns()
	defer decPublicConns()

	sni, peeked, err := readClientHelloSNI(c, maxHeadBytes)

	switch {
	case err == nil:
		c.Debug("ClientHello read in %d bytes", len(peeked))
	case errors.Is(err, ErrSNIAbsent):
		// A client that names no endpoint is normal (IP literals, some
		// legacy stacks): terminate, and let the Host header speak.
		c.Info("%v; terminating with the server certificate", err)
	default:
		c.Info("SNI peek failed (%v); treating the connection as SNI-absent", err)
	}

	if sni != "" {
		// Registry keys are lower-cased (hostFromHead's rule); SNI hostnames
		// are binary-safe octets on the wire, and the lowercase of the name
		// is the name the tunnel was registered under. The %q spellings
		// below are deliberate: the name is peer-controlled bytes (it can
		// carry \n, control chars, ANSI escapes) and %q escapes them, so no
		// log line can be forged by a crafted ClientHello.
		host := strings.ToLower(sni)
		c.Debug("Found SNI %q in ClientHello", host)

		tunnel := tunnelRegistry.Get(fmt.Sprintf("%s://%s", msg.ProtoHTTPS, host))
		switch {
		case tunnel == nil:
			c.Info("No tunnel found for SNI %q; terminating with the server certificate", host)
		case tunnel.agentTLS():
			c.Info("SNI %q routes to agent-terminated endpoint %s; passing the connection through as raw TLS bytes", host, tunnel.Id())
			serveAgentTLS(c, tunnel, peeked)
			return
		default:
			c.Info("SNI %q routes to edge-terminated endpoint %s; terminating with the server certificate", host, tunnel.Id())
		}
	}

	terminateWithServerCert(c, peeked, tlsCfg)
}

// serveAgentTLS passes one public connection through to an agent-terminated
// endpoint's proxy connection without the server ever inspecting a byte of
// its payload. Everything the server is still entitled to see -- the source
// address, the endpoint's on_tcp_connect policy, the forward_to chain --
// is decided here, on the outside of the TLS; inside there is only ciphertext
// this server has no key for.
//
// The admission gates are NOT here: they ran once in httpsConnHandler, before
// the peek (this function is only reachable from there, and a connection
// must pass each gate exactly once whichever branch takes it).
func serveAgentTLS(c conn.Conn, tunnel *Tunnel, peeked []byte) {
	// The forward_to chain decides which endpoint actually serves this
	// connection, exactly as it does on the Host path: an agent-terminated
	// entry endpoint with a forward_to terminates at the internal endpoint
	// the chain names, and the entry's agent never sees the traffic.
	target, err := tunnelRegistry.ResolveForward(tunnel)
	if err != nil {
		respondBadGateway(c, err)
		return
	}

	// on_tcp_connect stays server-side (SPEC-CLUSTER5 5.3): it runs before a
	// proxy connection exists, on the only facts the server has -- the source
	// address and the policy of the endpoint the chain terminates at. The
	// synthetic response the verdict may carry is written onto the raw
	// stream, where a TLS-speaking visitor cannot read it; the enforcement
	// is the point, not the answer. The connection is closed either way: a
	// refused connection must not reach an agent.
	pol := tunnel.policyFor(target)
	if v := connectVerdict(pol, c); v.Deny {
		respondPolicyDeny(c, v)
		return
	}

	// From here on the connection is ciphertext end to end. Give the peeked
	// bytes back -- the ClientHello reaches the agent's TLS terminator as the
	// stream's first bytes, which is what makes the pass-through transparent
	// to it -- and clear the peek deadline: the join owns the connection now.
	//
	// The conn is also marked as a passthrough: if the forward_to chain below
	// terminates at an endpoint that is NOT itself agent-terminated, that
	// endpoint's join must still treat this stream as the opaque ciphertext it
	// is -- this server holds no key for it, and the terminus's rewriter hooks
	// must not be pointed at TLS records. The marker makes the entry
	// endpoint's zero-knowledge property travel with the connection.
	publicConn := &passthroughConn{newReplayConn(c, peeked, c)}
	publicConn.SetDeadline(time.Time{})

	target.HandlePublicConnection(publicConn, pol)
}

// terminateWithServerCert hands a peeked connection to the server's TLS
// terminator and the Host router: the bytes the SNI peek consumed are put back
// on the front of the stream, so the handshake sees the ClientHello exactly as
// the client sent it, and the routing half of the http handler takes over as
// if it had accepted the connection itself. This is the pre-SNI behavior,
// preserved byte for byte for every connection the SNI does not claim for an
// agent. The gates already ran in httpsConnHandler (pre-peek), so the
// routing half is entered directly -- no second count.
func terminateWithServerCert(c conn.Conn, peeked []byte, tlsCfg *tls.Config) {
	tlsConn := tls.Server(newReplayConn(c, peeked, c), tlsCfg)
	tc := &terminatedConn{Conn: c, tlsConn: tlsConn}
	// routeHTTP does not close ("the caller owns Close"), and the caller of
	// THIS function -- httpsConnHandler -- holds only the raw conn, whose
	// Close cannot speak TLS: closing the raw socket after the last response
	// ends the session without close_notify, which well-behaved TLS clients
	// (openssl s_client among them) report as an unexpected EOF. Before the
	// gates/handler split this path entered httpHandler, which owned and
	// closed the terminated conn; the split moved ownership here without
	// moving the close. This defer is that close: terminatedConn.Close
	// delegates to tlsConn.Close, which sends the close_notify the raw conn's
	// own deferred Close (httpsConnHandler) then merely double-reports.
	defer tc.Close()
	routeHTTP(tc, msg.ProtoHTTPS)
}

// terminatedConn is a public connection whose payload flows through a TLS
// layer the server built after peeking at it, while the connection's identity
// -- id, log prefixes, Close, deadlines, addresses -- stays the accepted
// connection's. It mirrors replayConn's embedding for the same reason: the
// conn the listener accepted is the one whose life is being logged, and a
// second identity would split that story in two.
//
// Read and Write go to the TLS layer; everything else goes to the accepted
// conn underneath it, which is where those operations acted before the SNI
// peek existed (conn.Listen used to swap the TLS layer in under the same
// loggedConn, so deadlines and addresses always reached the raw socket).
type terminatedConn struct {
	conn.Conn
	tlsConn *tls.Conn
}

func (c *terminatedConn) Read(p []byte) (int, error) {
	return c.tlsConn.Read(p)
}

func (c *terminatedConn) Write(p []byte) (int, error) {
	return c.tlsConn.Write(p)
}

// Close closes the TLS layer, which sends close_notify and closes the
// underlying socket -- the same thing closing the pre-SNI wrapped conn did.
func (c *terminatedConn) Close() error {
	return c.tlsConn.Close()
}

// replayConn is a connection whose reads serve the request head that was taken
// off it before routing, and then whatever the connection itself delivers.
//
// It exists because routing needs the head (the Host field) and the rest of the
// connection needs the head back: the request must reach the tunnel's agent
// byte for byte, starting with the line the router read. The head is served out
// of a buffer, and the bytes after it come from the buffered reader the head
// was read through -- which is also where any body bytes that arrived in the
// same read are sitting, so nothing is consumed twice and nothing is lost.
//
// Embedding conn.Conn (rather than wrapping it in a new loggedConn) keeps the
// connection's identity: its id, its type and its log prefixes are the ones the
// listener gave it, and Close/SetDeadline/RemoteAddr still go straight to the
// real connection. Only Read is different.
type replayConn struct {
	conn.Conn
	r io.Reader
}

func (c *replayConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

// newReplayConn rebinds a connection to the bytes already read from it.
func newReplayConn(c conn.Conn, head []byte, rest io.Reader) conn.Conn {
	return &replayConn{
		Conn: c,
		r:    io.MultiReader(bytes.NewReader(head), rest),
	}
}

// passthroughConn marks a public connection that arrived over an
// agent-terminated endpoint's SNI route: its payload is TLS ciphertext the
// server has no key for, and it must be joined to its agent as raw bytes no
// matter which tunnel in a forward_to chain ends up serving it -- the entry
// endpoint's zero-knowledge property travels with the connection, because
// rewriter hooks pointed at this stream would be parsing TLS records.
// Tunnel.join reads the marker; nothing else about the connection changes.
type passthroughConn struct {
	conn.Conn
}

// readRequestHead reads exactly one request head off a public connection and
// returns it with the reader it was read through.
//
// This replaces the go-vhost library's head parse on this path, and the point
// of replacing it is bounds. vhost reads a request with http.ReadRequest over
// an unbounded reader: a head, or a header line, is limited only by whatever
// memory the process has, and the library's request object also parses and
// buffers the body. This reader stops at the first blank line, refuses to grow
// past maxHeadBytes, and never reads a byte it does not return: what it
// over-read -- the first body bytes, usually -- stays in the returned *bufio.Reader
// and is replayed, so no body is buffered beyond the head that arrived with it
// and none is dropped.
//
// The head syntax is the rewriter's, deliberately: lines are CRLF-terminated
// (or bare-LF terminated, which the rewriter tolerates too), a head ends at the
// first blank line, and a single line longer than the cap is an error rather
// than a partial read. Two parsers of the same wire format that disagree is
// exactly how a request gets routed by one and rewritten by the other.
func readRequestHead(c conn.Conn) (head []byte, rest *bufio.Reader, err error) {
	// The buffer is the cap: ReadSlice returns ErrBufferFull rather than
	// allocating, so neither a huge head nor one unbounded line can make this
	// read more than maxHeadBytes at a time.
	rest = bufio.NewReaderSize(c, maxHeadBytes)
	head = make([]byte, 0, 512)

	for {
		line, readErr := rest.ReadSlice('\n')
		if len(line) > 0 {
			head = append(head, line...)
		}

		switch {
		case readErr == bufio.ErrBufferFull:
			return nil, nil, errHeadLineTooLong
		case readErr != nil:
			// end of stream (or timeout) before the head ended: the caller
			// answers with a 400, and the connection goes away with it
			return nil, nil, readErr
		}

		if len(head) > maxHeadBytes {
			return nil, nil, errHeadTooLarge
		}

		// the blank line that ends the head (isBlankLine's rule: "\r\n" or
		// "\n" alone)
		if isHeadTerminator(line) {
			return head, rest, nil
		}
	}
}

// isHeadTerminator reports whether a line ends a head: the empty line, with
// either terminator. It is the rewriter's isBlankLine, spelled for a single
// line instead of a running buffer.
func isHeadTerminator(line []byte) bool {
	switch len(line) {
	case 2:
		return line[0] == '\r' && line[1] == '\n'
	case 1:
		return line[0] == '\n'
	}
	return false
}

// headField returns the value of the first field of the given name in a request
// head, or "". Names are matched case-insensitively and must be followed by a
// colon, which is the rule http.Header.Get applies -- first occurrence wins,
// the value is trimmed of the spaces around it, and the line terminator is not
// part of it.
//
// Only the first occurrence is returned, on purpose: a request that carries the
// same field twice must be routed by the same value the agent (and every proxy
// in between) will see as the request's Host, and the first occurrence is that
// value.
//
// A field continued onto a second line (obs-fold, which RFC 7230 tells servers
// to reject) is read as its first line alone: joining it would mean the value
// we routed by was assembled here and not by the agent, which is the mismatch
// the whole extraction is trying to avoid.
func headField(head []byte, name string) string {
	for _, line := range bytes.Split(head, []byte("\n")) {
		colon := bytes.IndexByte(line, ':')
		if colon <= 0 {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(string(line[:colon])), name) {
			continue
		}
		return strings.TrimSpace(string(bytes.TrimRight(line[colon+1:], "\r")))
	}
	return ""
}

// hostFromHead extracts the Host of a request head the way the vhost library
// did: the first Host field, case-insensitively found, lowercased (the registry
// keys tunnel urls in lower case), with the port kept if one was sent. An empty
// result is a request with no Host at all.
//
// Only the Host field is read, deliberately, and that is the one place this is
// narrower than what it replaced. vhost.HTTP parses the request with
// net/http's ReadRequest, which takes the host from an absolute-form request
// target ("GET http://svc.test/ HTTP/1.1") in preference to the Host field, as
// RFC 7230 says a server should. Here the request line is not parsed at all: an
// absolute-form target with no Host field -- a rare shape, sent by proxies --
// now 404s instead of routing. Reading the field the agent's own proxy will
// route on, and reading no more of the request than the head we already have to
// read, is the trade: the divergence is a request nobody sends us, against
// routing a request by a name the agent will not agree with.
func hostFromHead(head []byte) string {
	return strings.ToLower(headField(head, "Host"))
}

// Handles a new http connection from the public internet: the admission
// gates and the connection's lifetime, then the routing half below.
//
// This entry point is the PLAIN listener's (startHttpListener). Connections
// arriving through the https listener do NOT come through here -- their gates
// ran once in httpsConnHandler before the SNI peek, and after the peek they
// enter routeHTTP directly (serveAgentTLS or terminateWithServerCert) so each
// connection passes each gate exactly once.
func httpHandler(c conn.Conn, proto string) {
	defer c.Close()
	defer func() {
		// recover from failures (covers the gates; routeHTTP recovers its
		// own body first, so this fires only for a panic above it)
		if r := recover(); r != nil {
			c.Warn("httpHandler failed with error %v", r)
		}
	}()

	// Make sure we detect dead connections while we decide how to multiplex
	c.SetDeadline(time.Now().Add(connReadTimeout))
	ip, admitted := admitPublicHTTPConn(c)
	if !admitted {
		return
	}
	defer connLimiter.Load().release(ip)
	incPublicConns()
	defer decPublicConns()

	routeHTTP(c, proto)
}

// routeHTTP is the routing half of the http handler: everything after
// admission, from the head read to the tunnel handoff. It runs on the plain
// listener's connections (via httpHandler) and on the https listener's
// terminated connections (via terminateWithServerCert, already admitted).
func routeHTTP(c conn.Conn, proto string) {
	defer func() {
		// recover from failures (the caller owns Close)
		if r := recover(); r != nil {
			c.Warn("httpHandler failed with error %v", r)
		}
	}()

	// Multiplex by the Host field of the head, which is read here with a
	// bounded parser (readRequestHead) rather than the go-vhost library's
	// unbounded one.
	head, rest, err := readRequestHead(c)
	if err != nil {
		if errors.Is(err, errHeadTooLarge) || errors.Is(err, errHeadLineTooLong) {
			respondHeadTooLarge(c, err)
			return
		}
		c.Warn("Failed to read valid %s request: %v", proto, err)
		c.Write([]byte(BadRequest))
		return
	}

	// read out the Host and auth from the request
	host := hostFromHead(head)
	auth := headField(head, "Authorization")

	// We need to read from the replay conn from here on, since the head has
	// already been taken off the stream and has to reach the agent with the
	// rest of the request.
	c = newReplayConn(c, head, rest)

	// multiplex to find the right backend host
	c.Debug("Found hostname %s in request", host)
	tunnel := tunnelRegistry.Get(fmt.Sprintf("%s://%s", proto, host))
	if tunnel == nil {
		if strings.HasSuffix(host, msg.InternalSuffix) {
			// Internal endpoints live under an owner-namespaced key, so a
			// public lookup of one is a miss by construction (SPEC 3.2)
			c.Info("No public tunnel for internal hostname %s; internal endpoints are only reachable through forward_to", host)
		} else {
			c.Info("No tunnel found for hostname %s", host)
		}
		c.Write(notFoundResponse(host))
		return
	}

	// The Host names an agent-terminated endpoint, but this connection was
	// already terminated -- by construction: every conn that reaches this
	// function had its TLS removed by this server (the plain listener's
	// conns carry no TLS at all, and agent-terminated tunnels can only be
	// registered under https urls, which only the terminated path looks up).
	// Piping the plaintext into the agent's tunnel would feed it bytes the
	// agent's TLS terminator cannot read, so the request is refused with 421
	// (SPEC-CLUSTER5 5.2): the one status that tells the client it reached
	// the right name over the wrong connection.
	if tunnel.agentTLS() {
		c.Info("Host %s names agent-terminated endpoint %s but this connection was terminated by the server; refusing with 421", host, tunnel.Id())
		c.Write(misdirectedResponse(host))
		return
	}

	// If the client specified http auth and it doesn't match this request's auth
	// then fail the request with 401 Not Authorized and request the client reissue the
	// request with basic authdeny the request
	if tunnel.req.HttpAuth != "" && auth != tunnel.req.HttpAuth {
		c.Info("Authentication failed")
		c.Write([]byte(NotAuthorized))
		return
	}

	// dead connections will now be handled by tunnel heartbeating and the client
	c.SetDeadline(time.Time{})

	// Follow the forward_to chain, if this endpoint has one, and serve the
	// connection through whichever tunnel terminates the chain. The public
	// client's address rides along untouched, so X-Forwarded-For stays
	// truthful, and the forwarding endpoint's own agent never sees this
	// connection (SPEC 3.3). Only HTTP is wired: internal TCP endpoints do
	// not exist in this cluster, so a TCP chain could never resolve.
	target, err := tunnelRegistry.ResolveForward(tunnel)
	if err != nil {
		respondBadGateway(c, err)
		return
	}

	// The endpoint's on_tcp_connect phase runs before an agent is asked for a
	// proxy connection. The connection is nominally past "connect" by now --
	// the head was read to find the tunnel -- but the phase's only input is the
	// source address, which has not changed, so the verdict is the one an
	// operator would get at accept time (SPEC 3.3).
	//
	// The policy is the one the hooks below will run: entry.policyFor(target),
	// which is the entry endpoint's own policy when it has one and the target's
	// otherwise. It is deliberately the same value and not the entry tunnel's
	// own policy: evaluating the connect phase against a policy other than the
	// one that governs the connection meant a restrict-ips on the endpoint the
	// traffic actually terminates at never ran (a forward_to entry with no
	// policy of its own skipped it entirely).
	pol := tunnel.policyFor(target)
	if v := connectVerdict(pol, c); v.Deny {
		respondPolicyDeny(c, v)
		return
	}

	// let the tunnel handle the connection now
	target.HandlePublicConnection(c, pol)
}

// respondPolicyDeny answers a connection the traffic policy refused. An HTTP
// client gets the synthetic response the verdict carries (the policy's 403 by
// default); the connection is closed either way, because a denied request must
// not reach an agent.
func respondPolicyDeny(c conn.Conn, v policy.ConnectVerdict) {
	c.Info("Traffic policy refused the request: %s", v.Reason)
	if v.Response != nil {
		c.Write(v.Response.Render())
	}
}
