package client

// Scaffolding shared by the two parsed local legs (SPEC-CLUSTER17's h1<->h2c
// transcoder, client/upstreamh2.go, and SPEC-CLUSTER25's h1 pool bridge,
// client/upstreamh1.go). Both features put the same shape in place of the
// plain TCP dial of serveProxyConnection: a net.Pipe whose relay-facing end
// behaves as the local leg, and a one-connection http.Server on the other end
// that hands every parsed request to the feature's own handler. Extracted
// verbatim from upstreamh2.go when the second leg arrived -- a mechanical
// move, not a redesign; cluster-17's tests staying green is the proof the
// move changed nothing.
//
// What is deliberately NOT shared is anything the two features decide
// differently: the handler (transcode vs pool), the transports (h2 connection
// pool vs h1 keep-alive pool) and the failure vocabulary each one owes its
// spec. Sharing code is for things that cannot be allowed to drift; these
// below are exactly those -- the listener, the pipe, the server lifecycle and
// the teardown order.

import (
	"net"
	"net/http"
	"sync"

	"ngrok/conn"
)

// oneConnListener is the classic single-connection listener adapter: it
// yields exactly the connection it was built with and then behaves as a closed
// listener. http.Server.Serve needs a listener; this is the smallest thing
// that is one.
type oneConnListener struct {
	ch   chan net.Conn
	done chan struct{}
	once sync.Once
}

func newOneConnListener(c net.Conn) *oneConnListener {
	l := &oneConnListener{
		ch:   make(chan net.Conn, 1),
		done: make(chan struct{}),
	}
	l.ch <- c
	return l
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *oneConnListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

// Addr has no real value: the server asks for it only to attach addresses to
// log lines, and a pipe connection has none. The loopback address is an honest
// label for where this leg goes -- every local leg this file builds goes to a
// service on or near this machine, whichever feature is driving it.
func (l *oneConnListener) Addr() net.Addr {
	return &oneConnListenerAddr
}

var oneConnListenerAddr = net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}

// startPipeBridge is the whole h1 half both features share: one pipe, one
// one-connection server, one connection. The end given to the server reads
// what the relay writes and the relay reads what the server writes -- net.Pipe's
// two ends are the two sides of the local leg -- and net/http does every byte
// of h1 parsing and framing on both crossings. This codebase does not
// hand-roll framing on data paths, which is also why the server side is a
// server and not a client: a client would need a fresh upstream connection per
// request or a request queue, both of which re-implement what a server already
// does.
func startPipeBridge(handler http.Handler) *pipeBridgeConn {
	pipeLocal, pipeServer := net.Pipe()
	ln := newOneConnListener(pipeServer)

	srv := &http.Server{Handler: handler}
	go srv.Serve(ln)

	return &pipeBridgeConn{
		Conn: conn.Wrap(pipeLocal, "prv"),
		ln:   ln,
	}
}

// pipeBridgeConn is the local leg the relay sees. Its Close tears down both
// halves of the bridge: the pipe end's close fails the server-side connection
// (which cancels the in-flight request context, which cancels whatever the
// handler's upstream crossing is doing), and the listener's close ends
// srv.Serve.
type pipeBridgeConn struct {
	conn.Conn
	ln *oneConnListener
}

func (c *pipeBridgeConn) Close() error {
	errLn := c.ln.Close()
	errConn := c.Conn.Close()
	// The pipe end's close is the one that matters (it is what unblocks the
	// server); the listener's is bookkeeping. Report the pipe error first.
	if errConn != nil {
		return errConn
	}
	return errLn
}
