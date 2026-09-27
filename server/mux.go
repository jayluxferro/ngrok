package server

// This file implements the server end of the multiplexed proxy transport (SPEC
// cluster 3, section 3.1): one long-lived smux connection per client, carrying
// every proxy connection that client serves as a stream instead of as a fresh
// TCP+TLS dial.
//
// The design goal is how little of the server changes. A stream is wrapped into
// a conn.Conn, reads the same RegProxy message a dialed proxy conn sends, and
// enters the control's proxy pool through the same RegisterProxy call, so
// everything behind the pool -- StartProxy, the public listeners, conn.Join,
// the tee, the rewriter -- is untouched. The win is the handshake and the setup
// round trip per proxied connection that no longer happen, not a new data path.

import (
	"sync"
	"time"

	"ngrok/conn"
	"ngrok/log"
	"ngrok/msg"

	"github.com/xtaci/smux/v2"
)

const (
	// muxCapability is the AuthResp capability that tells a client it may
	// multiplex (SPEC 3.1). It gates nothing on this side -- a client that opens
	// a mux conn states what it wants with RegMux and gets it -- but a client
	// that never sees the cap keeps dialing one conn per proxy connection, which
	// is exactly what a mixed-version deployment needs.
	muxCapability = "proxy-mux"

	// muxStreamReadTimeout bounds the wait for the RegProxy that must be the
	// first message on every stream. A stream that says nothing is broken or a
	// probe, and it must not hold an accept goroutine forever. The tunnel
	// listener applies the same bound (connReadTimeout) to the first message on
	// a fresh connection.
	muxStreamReadTimeout = 10 * time.Second
)

// muxConfig is the smux configuration for the server side of a mux session.
//
// The library defaults are kept -- 10s keepalive, 30s keepalive timeout, 4 MiB
// receive window, 64 KiB per-stream buffer -- because they are the settings
// smux recommends, and the bench harness (SPEC 3.3) is what should move them if
// per-stream buffering shows up as contention under load.
func muxConfig() *smux.Config {
	return smux.DefaultConfig()
}

// NewMux takes over a client's multiplexed proxy connection (SPEC 3.1).
//
// The tunnel listener cannot tell a mux conn from a control or a proxy conn
// until it has read the first message, so RegMux names the client session the
// conn belongs to, and the control that owns that id takes the session. A
// RegMux naming an unknown client is logged and dropped with its conn: there is
// nothing to attach it to, and the client's watchdog (or its next control
// session) will try again.
func NewMux(muxConn conn.Conn, regMux *msg.RegMux) {
	// fail gracefully if the mux connection cannot be registered, the same way
	// NewProxy does
	defer func() {
		if r := recover(); r != nil {
			muxConn.Warn("Failed with error: %v", r)
			muxConn.Close()
		}
	}()

	// set logging prefix
	muxConn.SetType("mux")

	muxConn.Info("Registering new mux session for %s", regMux.ClientId)
	ctl := controlRegistry.Get(regMux.ClientId)

	if ctl == nil {
		muxConn.Warn("No client found for identifier: %s", regMux.ClientId)
		muxConn.Close()
		return
	}

	sess, err := smux.Server(muxConn, muxConfig())
	if err != nil {
		muxConn.Warn("Failed to start mux session: %v", err)
		muxConn.Close()
		return
	}

	ctl.SetMuxSession(newMuxSession(muxConn, sess, ctl, regMux.ClientId))
}

// MuxSession is the server's end of one client's multiplexed proxy connection.
//
// Every proxy connection that client opens arrives as a stream on this session
// instead of as a fresh dial, and each stream goes through the same
// registration a dialed proxy conn goes through: it is wrapped, its first
// message must be RegProxy, the client id in it is validated against the
// session, and it is put in the control's proxy pool.
//
// The session is a shared failure domain: its death takes every stream with it,
// and the public connections joined to those streams unwind through conn.Join
// exactly as they would if a dialed proxy conn had been dropped. Streams do not
// outlive it, which is why the control replaces and closes the whole session
// when the client reconnects.
type MuxSession struct {
	// the client id the session registered as. It is kept here rather than read
	// back from the control, whose id is cleared when it is replaced.
	id string

	// the control connection this session belongs to
	ctl *Control

	// the connection carrying the smux frames
	conn conn.Conn

	sess *smux.Session

	log.Logger

	closeOnce sync.Once
}

// newMuxSession wraps an established smux session and starts accepting proxy
// streams on it.
func newMuxSession(muxConn conn.Conn, sess *smux.Session, ctl *Control, clientId string) *MuxSession {
	m := &MuxSession{
		id:     clientId,
		ctl:    ctl,
		conn:   muxConn,
		sess:   sess,
		Logger: log.NewPrefixLogger("mux", clientId),
	}

	m.Info("Mux session established")
	go m.acceptLoop()
	return m
}

// acceptLoop turns every stream the client opens into a proxy connection, and
// doubles as the session's death watch.
//
// When the mux conn goes away -- the client closed it, the transport broke, or
// smux's keepalive gave up on a silent peer -- AcceptStream returns an error
// and the loop ends. The streams that were already pooled are dead by then
// (their reads and writes fail) and the joins on them unwind as usual.
func (m *MuxSession) acceptLoop() {
	defer func() {
		if r := recover(); r != nil {
			m.Error("Mux accept loop failed with error %v", r)
		}
	}()

	for {
		stream, err := m.sess.AcceptStream()
		if err != nil {
			m.Info("Mux session ended: %v", err)
			m.Close()
			return
		}

		go m.handleStream(stream)
	}
}

// handleStream registers one mux stream as a proxy connection.
//
// The steps mirror NewProxy's -- read RegProxy, find the control it names,
// register -- with one check that only a stream can make: the client id must be
// the one this session registered as, because the stream is not authenticated
// on its own. A stream that names another client, or one whose control has been
// replaced in the meantime, is closed and never pooled: it is either a bug or
// an attempt to borrow somebody else's tunnels.
func (m *MuxSession) handleStream(stream *smux.Stream) {
	// A control that shuts down while a stream is registering closes the pool
	// channel under it. NewProxy guards its registration the same way: the panic
	// must take down this stream (the deferred close) and not the process.
	defer func() {
		if r := recover(); r != nil {
			stream.Close()
		}
	}()

	pxyConn := conn.Wrap(stream, "pxy")
	if pxyConn == nil {
		// conn.Wrap has a default case, so this cannot happen; failing closed is
		// still better than a nil pointer in the accept loop.
		stream.Close()
		return
	}

	pxyConn.SetReadDeadline(time.Now().Add(muxStreamReadTimeout))
	var regPxy msg.RegProxy
	if err := msg.ReadMsgInto(pxyConn, &regPxy); err != nil {
		pxyConn.Warn("Failed to read RegProxy from mux stream: %v", err)
		pxyConn.Close()
		return
	}

	if regPxy.ClientId != m.id || controlRegistry.Get(regPxy.ClientId) != m.ctl {
		pxyConn.Warn("Rejecting mux stream for %s: session belongs to %s", regPxy.ClientId, m.id)
		pxyConn.Close()
		return
	}

	m.ctl.RegisterProxy(pxyConn)
}

// Close tears the session down: the smux session (and with it every stream) and
// the conn underneath. The control drops its reference to a session that closes
// on its own, so that a dead session is not kept around as if it were live.
//
// Closing is idempotent (smux's Close returns io.ErrClosedPipe the second
// time), which matters because the session is closed from three places: the
// accept loop when it ends, the control when it shuts down or replaces the
// session, and NewMux's caller when the conn could not be registered.
func (m *MuxSession) Close() error {
	var err error
	m.closeOnce.Do(func() {
		err = m.sess.Close()
		m.ctl.clearMuxSession(m)
	})
	return err
}

// Id returns the client id this session was registered for.
func (m *MuxSession) Id() string {
	return m.id
}
