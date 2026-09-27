package rewriter

import (
	"io"

	"ngrok/conn"
)

// filteredConn is the conn.Conn adapter for one direction: Read returns
// rewriter-transformed bytes, while everything else -- Write, Close, the
// deadlines, CloseRead, Id, SetType and the log.Logger methods -- is the
// embedded connection's own behavior. Delegating rather than reimplementing
// keeps the wrapper invisible to conn.Join and to the rest of the plumbing that
// writes to and logs through these connections.
type filteredConn struct {
	conn.Conn
	r io.Reader
}

func (c *filteredConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

// NewConnPair is NewPair for the live path: it wraps the two readers in
// conn.Conn adapters that keep delegating writes and deadlines to the same
// sockets. reqSrc is the public->local stream (the tunnel connection, whose
// bytes are requests) and respSrc is the local->public one (the upstream
// connection, whose bytes are responses).
//
// In the client's proxy loop this is used as
//
//	toUpstream, fromUpstream := rewriter.NewConnPair(remoteConn, localConn, policy)
//	bytesIn, bytesOut := conn.Join(fromUpstream, toUpstream)
//
// which keeps each rewriter on the source side of the direction it rewrites:
// requests flow remoteConn -> localConn through the request rewriter, responses
// flow localConn -> remoteConn through the response rewriter.
func NewConnPair(reqSrc, respSrc conn.Conn, p *Policy) (toUpstream, fromUpstream conn.Conn) {
	// Log through the source connections themselves: each already carries the
	// connection id prefix, which is what a fail-open warning should name.
	req, resp := newPair(reqSrc, respSrc, p, reqSrc, respSrc)
	return &filteredConn{Conn: reqSrc, r: req}, &filteredConn{Conn: respSrc, r: resp}
}
