package rewriter

import (
	"io"
	"sync"

	"ngrok/conn"
)

// bufferReleaser is the release handle the pair's readers carry: it lets
// filteredConn.Close return the direction's pooled 64 KiB read buffer to
// readBufPool without knowing anything about the state machine behind the
// reader. See readBufPool in rewriter.go for the pool, and
// pooledReader.release for the recycling mechanics.
type bufferReleaser interface {
	releaseBuffer()
}

// filteredConn is the conn.Conn adapter for one direction: Read returns
// rewriter-transformed bytes, while everything else -- Write, the deadlines,
// CloseRead, Id, SetType and the log.Logger methods -- is the embedded
// connection's own behavior. Delegating rather than reimplementing
// keeps the wrapper invisible to conn.Join and to the rest of the plumbing that
// writes to and logs through these connections.
type filteredConn struct {
	conn.Conn
	r io.Reader

	// releaseOnce guards the one buffer release this adapter is responsible
	// for. It is per-adapter, and conn.Join closes each leg from both pipe
	// goroutines, so Close here runs twice per direction in every join; the
	// Once keeps that from ever turning into a double Put of the same array
	// (two connections would hold one buffer -- the corruption class
	// TestJoinStagingBufferIsNotShared pins for joinBufPool). Idempotent again
	// inside pooledReader.release, which is also where the "safe when pooling
	// is off" behavior lives.
	releaseOnce sync.Once
}

func (c *filteredConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

// Close closes the wrapped connection first and then releases the direction's
// read buffer, once. The order matters: closing the underlying connection is
// what ends a read the other join goroutine still has parked in this
// direction's rewriter (a read is never woken by the release below), and the
// release itself never waits -- it recycles the buffer if this direction's
// copy has ended, or marks it for recycling at that copy's own termination
// (pooledReader.release). This is the ONE release site for the pair's
// buffers: conn.Join defers Close on both legs of both directions
// (conn/conn.go), so the client relay and the server join need no changes,
// and every path out of a joined pair goes through here exactly once per
// direction.
func (c *filteredConn) Close() error {
	err := c.Conn.Close()
	c.releaseOnce.Do(func() {
		if rl, ok := c.r.(bufferReleaser); ok {
			rl.releaseBuffer()
		}
	})
	return err
}

// NewConnPair is NewPair for the live path: it wraps the two readers in
// conn.Conn adapters that keep delegating writes and deadlines to the same
// sockets. reqSrc is the public->local stream (the tunnel connection, whose
// bytes are requests) and respSrc is the local->public one (the upstream
// connection, whose bytes are responses).
//
// On the server the pair is used as
//
//	toUpstream, fromUpstream := rewriter.NewConnPair(publicConn, proxyConn, policy)
//	bytesIn, bytesOut := conn.Join(fromUpstream, toUpstream)
//
// and on the client as
//
//	toUpstream, fromUpstream := rewriter.NewConnPair(remoteConn, localConn, policy)
//	bytesIn, bytesOut := conn.Join(fromUpstream, toUpstream)
//
// which in both cases keeps each rewriter on the source side of the direction
// it rewrites: requests flow the first connection to the second through the
// request rewriter, responses flow back through the response rewriter.
func NewConnPair(reqSrc, respSrc conn.Conn, p *Policy) (toUpstream, fromUpstream conn.Conn) {
	// Log through the source connections themselves: each already carries the
	// connection id prefix, which is what a fail-open warning should name.
	req, resp := newPairWithWake(reqSrc, respSrc, p, reqSrc, respSrc, func() {
		// The request side terminated while the response side was parked in a
		// read of its own source. Nothing will ever arrive on that source -- the
		// request that would have provoked a response was never forwarded -- so
		// the read is ended by closing it.
		//
		// Closing, and not a read deadline, is deliberate: it is the fix for a
		// hang the mux path had. A read deadline only works if the connection
		// implementation re-checks it while a read is in flight. A TCP socket
		// does -- the kernel wakes the parked read -- but an smux stream does
		// not: Stream.SetReadDeadline only stores the value, and Stream.Read
		// samples that value once, on entry, so a read already parked further
		// down never learns a deadline was set. The response side stayed parked,
		// the request side kept draining a public connection that never EOFs,
		// and conn.Join waited on both legs forever.
		//
		// Close has no such per-implementation rule to get wrong: it is how every
		// conn.Conn in this program ends, and it ends the read whatever the read
		// is parked in. It is safe here because a terminate makes the source
		// disposable -- the synthetic response is the last message of the
		// connection, nothing is read from this source again, and conn.Join's own
		// pipe closes both legs as soon as either copy returns, so it would be
		// closed moments later anyway. The woken side finds the published
		// terminate on its read-error path and emits it (see stepHead).
		//
		// The error Close may cause on the write side of a mux stream is the same
		// error the leg's own close would produce, and the leg ignores it: what
		// the client reads is the synthetic response, written to the other
		// connection.
		respSrc.Close()
	})
	return &filteredConn{Conn: reqSrc, r: req}, &filteredConn{Conn: respSrc, r: resp}
}
