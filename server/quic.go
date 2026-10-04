package server

// QUIC carrier for the multiplexed proxy transport (SPEC cluster 7).
//
// One QUIC session -- a UDP connection -- plays the role the smux-over-TCP
// connection plays in server/mux.go: the client's first stream carries RegMux
// to name and authenticate the control session it belongs to, every later
// stream carries the RegProxy it always did, and every stream goes through the
// same registerProxyStream into the control's proxy pool, so nothing behind
// the pool changes. What QUIC buys is per-stream independence on the wire: a
// lost packet stalls only the stream it belonged to, where a lost packet on
// the TCP carrier stalls every stream multiplexed onto it -- head-of-line
// blocking, the thing this transport exists to remove.
//
// The listener is opt-in. -quicAddr / quic_addr selects the UDP address to
// serve; the default -- empty -- keeps the server's footprint at one TCP port
// and keeps msg.QuicCapability out of AuthResp, so no client ever dials QUIC.
// That is also the failure story: the control channel stays on TCP, a failed
// QUIC dial is the client's cue to fall back to smux, and a server that stops
// advertising the cap stops receiving QUIC sessions without any operator
// action.

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"ngrok/conn"
	"ngrok/log"
	"ngrok/msg"

	"github.com/quic-go/quic-go"
)

const (
	// quicALPN is the wire-vocabulary constant (msg.QuicALPN), aliased so the
	// listener code reads without the package qualifier everywhere. The TLS
	// handshake is what refuses cross-protocol misdirection -- a client that
	// dials this UDP port expecting some other QUIC service, or a plain TLS
	// client, fails the handshake instead of being handed to the mux protocol
	// by mistake.
	quicALPN = msg.QuicALPN

	// The session's transport settings. KeepAlivePeriod and MaxIdleTimeout
	// mirror smux's 10s/30s keepalive pair (client/model.go's muxConfig),
	// which is load-bearing there for the same reason it is here: they are
	// what turn a server that vanished silently into a dead session -- and
	// therefore into a reconnected one -- without waiting for a stream to be
	// attempted and to hang. 512 bidirectional streams is the per-session
	// proxy-connection budget: smux does not bound it, QUIC needs a number,
	// and this is a limit the client runs into at OpenStream long before the
	// process feels it.
	quicKeepAlivePeriod    = 10 * time.Second
	quicMaxIdleTimeout     = 30 * time.Second
	quicMaxIncomingStreams = 512

	// quicSessionError is the application error code the server closes a QUIC
	// session with. 0 is QUIC's "no error": closing is the ordinary end of a
	// session (unknown client, bad secret, idle timeout, replacement,
	// shutdown) and the reason string -- which is what the client logs -- says
	// which, where a non-zero error code would ask the client to distinguish
	// recoveries it treats identically anyway.
	quicSessionError quic.ApplicationErrorCode = 0
)

// quicServing records that the QUIC proxy listener is up. It is what the
// AuthResp capability list consults (NewControl), so it is set only after
// quic.ListenAddr has succeeded, and never cleared again: the listener lives
// as long as the process does. Tests set and restore it.
var quicServing atomic.Bool

// quicConfig is the QUIC configuration for the server side of a session.
func quicConfig() *quic.Config {
	return &quic.Config{
		KeepAlivePeriod: quicKeepAlivePeriod,
		MaxIdleTimeout:  quicMaxIdleTimeout,
		// MaxIncomingStreams is the negotiated cap on the proxy streams a
		// client may keep open on one session (see the const above).
		MaxIncomingStreams: quicMaxIncomingStreams,
		// The server never opens unidirectional streams and does not accept
		// any. Note the value: quic-go reads 0 as "unset" and would apply its
		// default of 100, so actually disallowing them -- the point of the
		// setting -- takes the negative value. A client that opens one gets
		// refused at OpenUniStream, which is a bug report, not a hung session.
		MaxIncomingUniStreams: -1,
	}
}

// quicTLSConfig derives the QUIC listener's TLS configuration from the tunnel
// listener's: the same certificate pair, so the QUIC endpoint presents exactly
// the identity the TCP one does, plus the ALPN protocol the handshake
// requires. The clone matters -- the config is shared with the TCP listener,
// whose handshakes must keep advertising no application protocol at all.
func quicTLSConfig(tlsConfig *tls.Config) *tls.Config {
	tlsCfg := tlsConfig.Clone()
	tlsCfg.NextProtos = []string{quicALPN}
	return tlsCfg
}

// startQuicListener brings up the QUIC proxy listener on a UDP address and
// returns once it is accepting; sessions are handled on their own goroutines.
func startQuicListener(addr string, tlsConfig *tls.Config) (*quic.Listener, error) {
	ql, err := quic.ListenAddr(addr, quicTLSConfig(tlsConfig), quicConfig())
	if err != nil {
		return nil, err
	}

	go quicAcceptLoop(ql)
	return ql, nil
}

// quicAcceptLoop accepts QUIC sessions until the listener closes. The TLS
// handshake -- including the ALPN check -- has already completed for
// everything Accept returns, so nothing that reaches handleQuicSession speaks
// anything but this protocol.
func quicAcceptLoop(ql *quic.Listener) {
	for {
		qconn, err := ql.Accept(context.Background())
		if err != nil {
			// the listener was closed for shutdown
			return
		}
		go handleQuicSession(qconn)
	}
}

// quicBindTimeout bounds the wait for the RegMux that must be the first
// message on a session's first stream -- the wait for the stream to be opened
// and the read of the message on it alike. The tunnel listener applies the
// same bound (connReadTimeout) to the first message on a fresh TCP conn: a
// session that completes the handshake and then says nothing is broken or a
// probe, and it must not hold a goroutine and a stream slot forever.
const quicBindTimeout = connReadTimeout

// handleQuicSession runs the bind half of the mux handshake over one QUIC
// session -- the QUIC counterpart of NewMux, with the same three outcomes. The
// first stream must carry RegMux naming the control session this one belongs
// to: a session naming an unknown client is closed (there is nothing to attach
// it to, and the client's watchdog will try again), one that cannot prove the
// id with the session secret is closed (the id is public -- it is logged, and
// it is in every admin snapshot -- so the secret is what makes this
// authentication rather than naming), and a valid one is attached to its
// control with the replace-and-close-prior semantics of Control.SetMuxSession.
// Everything after the first stream is the per-stream path that
// registerProxyStream shares with smux, byte for byte.
func handleQuicSession(qconn quic.Connection) {
	defer func() {
		if r := recover(); r != nil {
			log.Error("QUIC session bind failed with error: %v", r)
			qconn.CloseWithError(quicSessionError, "internal error")
		}
	}()

	// Until the RegMux names a client id there is nothing better to prefix
	// the log with than the peer's address.
	logger := log.NewPrefixLogger("quic", qconn.RemoteAddr().String())
	logger.Info("New QUIC session")

	ctx, cancel := context.WithTimeout(context.Background(), quicBindTimeout)
	defer cancel()

	stream, err := qconn.AcceptStream(ctx)
	if err != nil {
		logger.Warn("QUIC session ended before RegMux: %v", err)
		qconn.CloseWithError(quicSessionError, "no RegMux")
		return
	}

	// The bind stream travels through the same conn.Conn stack -- framing,
	// logging, deadlines -- a mux conn does, over the net.Conn adapter.
	bindConn := conn.Wrap(newQuicStreamConn(qconn, stream), "quic")

	bindConn.SetReadDeadline(time.Now().Add(quicBindTimeout))
	var regMux msg.RegMux
	if err := msg.ReadMsgInto(bindConn, &regMux); err != nil {
		bindConn.Warn("Failed to read RegMux from QUIC stream: %v", err)
		qconn.CloseWithError(quicSessionError, "invalid RegMux")
		return
	}
	// The deadline is not cleared, on purpose: this stream has no future
	// past this message -- either the session binds and the stream is
	// retired below, or the session is closed.

	logger.Info("Registering new QUIC mux session for %s", regMux.ClientId)
	ctl := controlRegistry.Get(regMux.ClientId)

	if ctl == nil {
		logger.Warn("No client found for identifier: %s", regMux.ClientId)
		qconn.CloseWithError(quicSessionError, "unknown client id")
		return
	}

	if !secretMatches(ctl.secret, regMux.Secret) {
		// The id is logged (it is public); the secret never is, and neither
		// is the value that was presented.
		logger.Warn("Rejecting QUIC session for %s: invalid session secret", regMux.ClientId)
		qconn.CloseWithError(quicSessionError, "invalid session secret")
		return
	}

	// The bind stream did its only job -- naming and authenticating the
	// session -- and is retired so it does not count against the
	// MaxIncomingStreams budget for the session's life: CancelRead reclaims
	// the receive side at once, Close sends the FIN for the send side (a
	// well-behaved client has half-closed its end after RegMux anyway).
	stream.CancelRead(0)
	stream.Close()

	ctl.SetMuxSession(newQuicSession(qconn, ctl, regMux.ClientId))
}

// QuicSession is the server's end of one client's QUIC proxy session: the
// streamSession the control holds for a client that chose the QUIC carrier.
// It is the QUIC counterpart of MuxSession (server/mux.go) and shares its
// shape, its per-stream path (registerProxyStream) and its failure story: the
// session is a shared failure domain, its death takes every stream with it,
// and the joins on those streams unwind exactly as they would for a dropped
// smux session.
type QuicSession struct {
	// the client id the session registered as. It is kept here rather than
	// read back from the control, whose id is cleared when it is replaced.
	id string

	// the control connection this session belongs to
	ctl *Control

	// the QUIC connection carrying the streams
	conn quic.Connection

	log.Logger

	closeOnce sync.Once
}

// newQuicSession wraps an authenticated QUIC connection and starts accepting
// proxy streams on it.
func newQuicSession(qconn quic.Connection, ctl *Control, clientId string) *QuicSession {
	q := &QuicSession{
		id:     clientId,
		ctl:    ctl,
		conn:   qconn,
		Logger: log.NewPrefixLogger("mux", clientId),
	}

	q.Info("QUIC mux session established")
	go q.acceptLoop()
	return q
}

// AcceptStream implements streamSession. A QUIC stream carries every net.Conn
// method except the two address accessors -- a stream has no addresses of its
// own -- so quicStreamConn supplies the session's, and the stream then travels
// through conn.Wrap like any other proxy conn.
func (q *QuicSession) AcceptStream() (net.Conn, error) {
	stream, err := q.conn.AcceptStream(context.Background())
	if err != nil {
		return nil, err
	}
	return newQuicStreamConn(q.conn, stream), nil
}

// acceptLoop turns every stream the client opens into a proxy connection, and
// doubles as the session's death watch. It is the loop mux.go runs over smux,
// reading through the streamSession interface: when the QUIC connection goes
// away -- the client closed it, the transport broke, the idle timeout fired --
// AcceptStream returns an error, the loop ends, and the streams that were
// already pooled are dead by then, their joins unwinding as usual.
func (q *QuicSession) acceptLoop() {
	defer func() {
		if r := recover(); r != nil {
			q.Error("Mux accept loop failed with error %v", r)
		}
	}()

	for {
		stream, err := q.AcceptStream()
		if err != nil {
			q.Info("Mux session ended: %v", err)
			q.Close()
			return
		}

		go registerProxyStream(q.id, q.ctl, stream)
	}
}

// Close tears the session down: the QUIC connection (and with it every stream)
// plus the control's reference to the session. It is the idempotent
// three-way close MuxSession.Close documents -- the accept loop when it ends,
// the control when it shuts down or replaces the session, the bind handler
// when the session could not be registered -- so the Once is load-bearing
// here too. The connection closes with quicSessionError and a reason string
// rather than a transport error: closing is the ordinary end of a session,
// not a protocol violation for the peer to report.
func (q *QuicSession) Close() error {
	var err error
	q.closeOnce.Do(func() {
		err = q.conn.CloseWithError(quicSessionError, "mux session closed")
		q.ctl.clearMuxSession(q)
	})
	return err
}

// Id returns the client id this session was registered for.
func (q *QuicSession) Id() string {
	return q.id
}

// quicStreamConn adapts a quic.Stream to net.Conn.
//
// quic.Stream (v0.45.0) carries every net.Conn method -- Read, Write, Close,
// and deadlines that actually bound the calls, which is what
// registerProxyStream's read timeout and conn.Join's shutdown lean on --
// except LocalAddr and RemoteAddr: a stream has no addresses of its own. The
// session's are the right answer for the logging and diagnostics that read
// them, so the adapter records them once, at accept time.
type quicStreamConn struct {
	quic.Stream
	local  net.Addr
	remote net.Addr
}

// newQuicStreamConn adapts one accepted stream of qconn to a net.Conn.
func newQuicStreamConn(qconn quic.Connection, stream quic.Stream) *quicStreamConn {
	return &quicStreamConn{
		Stream: stream,
		local:  qconn.LocalAddr(),
		remote: qconn.RemoteAddr(),
	}
}

func (c *quicStreamConn) LocalAddr() net.Addr  { return c.local }
func (c *quicStreamConn) RemoteAddr() net.Addr { return c.remote }

// Close sends the FIN for the write side and cancels the receive side.
//
// The cancel is deliberate half-close economics, not an abbreviation: a QUIC
// stream's state is reclaimed only once both directions are finished, and on
// this path "closed" always means "the join is over and nobody will ever read
// this stream again" -- conn.Join closes both legs when either direction
// ends -- so waiting for an app-level EOF that has no reader would keep every
// finished stream allocated until the session died. smux has no such state to
// reclaim -- its Close tears down the whole stream -- which is the one
// behavioral wrinkle of the QUIC carrier.
func (c *quicStreamConn) Close() error {
	c.CancelRead(0)
	return c.Stream.Close()
}
