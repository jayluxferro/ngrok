package conn

import (
	"io"
	"net"
)

// Zero-copy legs (SPEC cluster 3, 3.2).
//
// Every leg of a proxied connection is a loggedConn, so until these two methods
// existed io.Copy between two legs could only take its userspace path: the
// wrapper has no ReadFrom/WriterTo of its own, and embedding the net.Conn
// *interface* promotes net.Conn's method set, not the concrete conn's extras.
// Declaring them hands the copy back to the net package, which is where the
// kernel-assisted copies live -- on Linux (*net.TCPConn).ReadFrom reaches
// splice(2), and (*net.TCPConn).WriteTo is its mirror image.
//
// What that buys, stated honestly (checked against go1.23.1, net/splice_linux.go
// and net/net.go):
//
//   - Splice only fires when BOTH legs are plain *net.TCPConn underneath the
//     wrappers, on Linux. The net package chooses the splice path by concrete
//     type switch, so it cannot see through loggedConn, a tls.Conn, an
//     smux.Stream or the tee: with any of those on either side the copy is the
//     userspace copy it always was.
//   - For a TCP-to-TCP copy the splice is arranged by the *ReadFrom* side (in
//     this toolchain spliceTo accepts only a stream-oriented *UnixConn as the
//     writer), and it happens because net's own genericWriteTo hands the
//     fallback a tcpConnWithoutWriteTo wrapper, which spliceFrom recognises as
//     a socket it can pull from. That is why delegating in BOTH directions
//     matters: a WriteTo that fell back to a plain userspace loop would lose
//     the splice for the ReadFrom on the far side of the copy.
//   - TLS legs (client.Dial with a tls.Config replaces c.Conn with a *tls.Conn)
//     and smux streams (SPEC 3.1 -- wrapConn's default case) stay on the
//     generic path. That is expected rather than a miss: there is no kernel
//     copy between two encrypted or multiplexed endpoints. The larger staging
//     buffer (joinBufPool) is what helps on those legs, here in the two
//     fallbacks and in Join itself.
//   - macOS has no splice(2) at all. There, delegation is a differently shaped
//     userspace copy and nothing more; the win on Darwin is the buffer.
//   - The tee (conn/tee.go) cannot splice: its writes fan out to two
//     destinations, which is not something splice(2) can express. Its own
//     ReadFrom is left alone.
//
// The conn whose type decides is the *current* one, c.Conn -- never the tcp
// field loggedConn records next to it. On a TLS leg that recorded tcp is the
// raw socket, and copying plaintext straight into it would bypass the TLS
// wrapper entirely.

// writeOnly exposes only the Write method of the conn it wraps.
//
// io.Copy asks its destination for io.ReaderFrom before it stages anything, so
// the fallback in ReadFrom below -- io.Copy(writeOnly{c}, r) -- would find
// loggedConn.ReadFrom again through c and recurse until the stack ran out.
// Hiding the method behind a one-method interface is the same trick the net
// package plays on itself (net/tcpConnWithoutReadFrom).
type writeOnly struct {
	io.Writer
}

// readOnly is writeOnly's mirror for the WriteTo fallback: io.Copy(w,
// readOnly{c}) still reaches w's ReadFrom, but cannot find loggedConn.WriteTo
// through it and call back into it.
type readOnly struct {
	io.Reader
}

// ReadFrom implements io.ReaderFrom: read from r, write to c.
//
// The delegation is the whole point: for a plain TCP leg the net package then
// gets to choose between splice(2) (Linux, and only when r is a socket too),
// sendfile, and a userspace copy. For any other underlying conn -- TLS, an
// smux stream, the tee -- there is no such choice to make and io.Copy through
// a userspace buffer is the honest answer.
func (c *loggedConn) ReadFrom(r io.Reader) (int64, error) {
	if tcp, ok := c.Conn.(*net.TCPConn); ok {
		return tcp.ReadFrom(r)
	}
	buf := joinBufPool.Get().([]byte)
	defer joinBufPool.Put(buf)
	return io.CopyBuffer(writeOnly{c}, r, buf)
}

// WriteTo implements io.WriterTo: write c into w.
//
// Mirror of ReadFrom, caveats included: on Linux the splice for a TCP-to-TCP
// copy is set up on the ReadFrom side, so delegation here mostly means "let
// the net package choose" rather than "splice happens here".
//
// The delegation is spelled as io.Copy rather than tcp.WriteTo(w) on purpose.
// (*net.TCPConn).WriteTo is a go1.22 addition (api/go1.22.txt, issue 58808) and
// this module still declares go 1.21, so naming the method fails vet's
// stdversion check -- and on a go1.21 toolchain it would not exist to name at
// all. io.Copy's first act is to ask its source for io.WriterTo, so this
// reaches the same method wherever it exists and degrades to the same
// userspace loop where it does not.
func (c *loggedConn) WriteTo(w io.Writer) (int64, error) {
	if _, ok := c.Conn.(*net.TCPConn); ok {
		return io.Copy(w, c.Conn)
	}
	buf := joinBufPool.Get().([]byte)
	defer joinBufPool.Put(buf)
	return io.CopyBuffer(w, readOnly{c}, buf)
}
