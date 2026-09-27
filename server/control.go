package server

import (
	"fmt"
	"io"
	"ngrok/conn"
	"ngrok/msg"
	"ngrok/util"
	"ngrok/version"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	pingTimeoutInterval = 30 * time.Second
	connReapInterval    = 10 * time.Second
	controlWriteTimeout = 10 * time.Second
	proxyStaleDuration  = 60 * time.Second
	proxyMaxPoolSize    = 10
)

type Control struct {
	// auth message
	auth *msg.Auth

	// actual connection
	conn conn.Conn

	// put a message in this channel to send it over
	// conn to the client
	out chan (msg.Message)

	// read from this channel to get the next message sent
	// to us over conn by the client
	in chan (msg.Message)

	// the last time we received a ping from the client - for heartbeats
	lastPing time.Time

	// all of the tunnels this control connection handles
	tunnels []*Tunnel

	// proxy connections
	proxies chan conn.Conn

	// mux session (SPEC 3.1): the client's multiplexed proxy connection, if it
	// opened one. Its streams are this control's proxy connections, so it is
	// attached when the client registers it, replaced when the client
	// reconnects, and closed when this control shuts down. muxMu guards the
	// slot: the tunnel listener attaches sessions while the stopper (and the
	// session's own accept loop) clear them.
	muxMu sync.Mutex
	mux   *MuxSession

	// identifier: the client id this session was registered under. It is
	// immutable from the moment NewControl has decided it -- the affinity
	// cache, the metrics and the admin snapshots all read it from other
	// goroutines -- and the one thing that changes about a control's identity
	// over its life, being replaced by a newer connection for the same id, is
	// recorded in the replaced flag below instead of by mutating this field.
	id string

	// secret is the session secret that goes with id: the proof a later
	// connection claiming this id has to present (Auth.Secret, RegProxy.Secret,
	// RegMux.Secret). Like id it is set once, before the session is announced
	// anywhere, and never mutated. It is a credential and is never logged.
	secret string

	// replaced is set when a newer connection takes this control's id over.
	// The replaced control keeps its id -- so it keeps logging and reporting as
	// itself, which is what it still is -- and consults this flag where the old
	// code relied on the id having been cleared: stopper() must not evict its
	// replacement from the control registry (see ControlRegistry.Del, which
	// also re-checks the identity under the registry lock).
	replaced int32

	// synchronizer for controlled shutdown of writer()
	writerShutdown *util.Shutdown

	// synchronizer for controlled shutdown of reader()
	readerShutdown *util.Shutdown

	// synchronizer for controlled shutdown of manager()
	managerShutdown *util.Shutdown

	// synchronizer for controller shutdown of entire Control
	shutdown *util.Shutdown
}

// ownerOf returns the account identity of a control connection, which is what
// namespaces internal endpoints and scopes forward_to resolution (SPEC 3.1).
//
// This fork has no account objects: when the server is started with
// -authToken, the validated auth token IS the identity. Without tokens
// configured every client shares the "default" namespace, which is a
// documented limitation rather than a security boundary.
func ownerOf(ctl *Control) string {
	if ctl == nil || ctl.auth == nil {
		return defaultOwner
	}
	if len(opts.authTokens) == 0 {
		return defaultOwner
	}
	owner := strings.TrimSpace(ctl.auth.User)
	if owner == "" {
		return defaultOwner
	}
	return owner
}

func NewControl(ctlConn conn.Conn, authMsg *msg.Auth) {
	var err error
	atomic.AddInt64(&controlConnCount, 1)

	// create the object
	c := &Control{
		auth:            authMsg,
		conn:            ctlConn,
		out:             make(chan msg.Message),
		in:              make(chan msg.Message),
		proxies:         make(chan conn.Conn, 10),
		lastPing:        time.Now(),
		writerShutdown:  util.NewShutdown(),
		readerShutdown:  util.NewShutdown(),
		managerShutdown: util.NewShutdown(),
		shutdown:        util.NewShutdown(),
	}

	failAuth := func(e error) {
		_ = msg.WriteMsg(ctlConn, &msg.AuthResp{Error: e.Error()})
		ctlConn.Close()
		atomic.AddUint64(&authRejectCount, 1)
		atomic.AddInt64(&controlConnCount, -1)
	}

	// Validate the auth token before anything else the caller could learn
	// from: version negotiation in particular tells an unauthenticated caller
	// what software the server runs (and, through the error text, invites it to
	// download a different one), so a wrong token has to be answered with the
	// auth error and nothing else. Token validation is also the cheapest check,
	// which is a happy accident rather than the reason.
	if len(opts.authTokens) > 0 {
		clientToken := authMsg.User
		validToken := false
		for _, validTokenStr := range opts.authTokens {
			if tokenMatches(validTokenStr, clientToken) {
				validToken = true
				break
			}
		}
		if !validToken {
			if warnSampler.allow("auth-invalid") {
				ctlConn.Warn("Authentication failed: invalid token")
			}
			observe.events.publishAuthReject(reasonInvalidToken)
			failAuth(fmt.Errorf("Invalid authentication token"))
			return
		}
		ctlConn.Info("Authenticated with valid token")
	}

	// Establish the session identity (SPEC cluster 3 hardening): a client that
	// names a client id is resuming that session, and resuming one is a claim
	// on its tunnels, its proxy pool and its mux session. The claim is only
	// honoured with the secret the server minted for that id, compared in
	// constant time.
	//
	// The three outcomes are deliberately different:
	//
	//   - no id: a new session. A fresh id and a fresh secret are minted; an
	//     old client that sends no id keeps working exactly as it always did.
	//   - an id this server still has a live control for: the secret decides.
	//     A missing or wrong secret is refused, without touching the live
	//     control, which is what makes id guessing useless (the id is public:
	//     it is logged and cached in the clear).
	//   - an id with no live control (the server restarted, or the session
	//     ended): a new id and secret are minted. The requested id is not
	//     reused, so this cannot be used to take over an id either -- it is the
	//     same "stale id" case the old code handled by assigning a fresh one.
	//
	// The secret is not rotated on resume: the session keeps one credential for
	// its whole life, which is what makes the replacement window below sane
	// (both the old and the new control of one session accept the same proof
	// while the old one drains).
	c.id = authMsg.ClientId
	if c.id != "" {
		if existing := controlRegistry.Get(c.id); existing != nil {
			if !secretMatches(existing.secret, authMsg.Secret) {
				if warnSampler.allow("auth-secret") {
					ctlConn.Warn("Authentication failed: session %s presented no valid session secret", c.id)
				}
				observe.events.publishAuthReject(reasonInvalidSessionSecret)
				failAuth(fmt.Errorf("Session %s cannot be resumed: a valid session secret is required", c.id))
				return
			}
			// the resumed session keeps the secret it already had
			c.secret = existing.secret
		} else {
			ctlConn.Debug("No live session for client id, assigning a new one")
			c.id = ""
		}
	}

	if c.secret == "" {
		// a new session: mint both halves of its identity
		if c.id == "" {
			if c.id, err = util.SecureRandId(16); err != nil {
				failAuth(err)
				return
			}
		}
		if c.secret, err = newSessionSecret(); err != nil {
			failAuth(err)
			return
		}
	}

	// set logging prefix (the id, never the secret)
	ctlConn.SetType("ctl")
	ctlConn.AddLogPrefix(c.id)

	// Version negotiation comes last of the checks: everything above is
	// authentication, and an unauthenticated caller does not get to learn the
	// server version.
	if authMsg.Version != version.Proto {
		failAuth(fmt.Errorf("Incompatible versions. Server %s, client %s. Download a new version at http://ngrok.com", version.MajorMinor(), authMsg.Version))
		return
	}

	// register the control
	if replaced := controlRegistry.Add(c.id, c); replaced != nil {
		replaced.shutdown.WaitComplete()
	}

	// start the writer first so that the following messages get sent
	go c.writer()

	// Respond to authentication
	//
	// The advertised capabilities are additive: a client that does not know one
	// ignores it (this client included, until msg.MuxCapability arrived), and a
	// client that knows none of them keeps using the transports it always did.
	//
	// Secret is the session secret the client must present to resume this id
	// and to register proxy connections and mux sessions for it. It is written
	// to the control channel and nowhere else.
	c.out <- &msg.AuthResp{
		Version:   version.Proto,
		MmVersion: version.MajorMinor(),
		ClientId:  c.id,
		Secret:    c.secret,
		Caps:      []string{"sha256_tokens", "rate_limits", msg.MuxCapability},
	}

	// As a performance optimization, ask for a proxy connection up front
	c.out <- &msg.ReqProxy{}

	// manage the connection
	go c.manager()
	go c.reader()
	go c.stopper()
}

// Register a new tunnel on this control connection
func (c *Control) registerTunnel(rawTunnelReq *msg.ReqTunnel) {
	for _, proto := range strings.Split(rawTunnelReq.Protocol, "+") {
		tunnelReq := *rawTunnelReq
		tunnelReq.Protocol = proto

		c.conn.Debug("Registering new tunnel")
		t, err := NewTunnel(&tunnelReq, c)
		if err != nil {
			// A registration failure is answered with the request it belongs
			// to. The client matches NewTunnel against the ReqTunnel it sent by
			// ReqId; without one it cannot tell which of its requests this
			// answer is for, and a rejected tunnel looks like a tunnel that
			// never got an answer at all. The error text names the endpoint
			// (hostname or port) as well, because the client may be
			// multiplexing several requests and the id is its only handle on
			// them.
			c.out <- &msg.NewTunnel{
				ReqId:    rawTunnelReq.ReqId,
				Protocol: proto,
				Error:    err.Error(),
			}
			if len(c.tunnels) == 0 {
				c.shutdown.Begin()
			}

			// we're done
			return
		}

		// add it to the list of tunnels
		c.tunnels = append(c.tunnels, t)

		// acknowledge success
		c.out <- &msg.NewTunnel{
			Url:      t.url,
			Protocol: proto,
			ReqId:    rawTunnelReq.ReqId,
		}

		rawTunnelReq.Hostname = strings.Replace(t.url, proto+"://", "", 1)
	}
}

func (c *Control) manager() {
	// don't crash on panics
	defer func() {
		if err := recover(); err != nil {
			c.conn.Info("Control::manager failed with error %v: %s", err, debug.Stack())
		}
	}()

	// kill everything if the control manager stops
	defer c.shutdown.Begin()

	// notify that manager() has shutdown
	defer c.managerShutdown.Complete()

	// reaping timer for detecting heartbeat failure
	reap := time.NewTicker(connReapInterval)
	defer reap.Stop()

	for {
		select {
		case <-reap.C:
			if time.Since(c.lastPing) > pingTimeoutInterval {
				c.conn.Info("Lost heartbeat")
				c.shutdown.Begin()
			}

		case mRaw, ok := <-c.in:
			// c.in closes to indicate shutdown
			if !ok {
				return
			}

			switch m := mRaw.(type) {
			case *msg.ReqTunnel:
				c.registerTunnel(m)

			case *msg.Ping:
				c.lastPing = time.Now()
				c.out <- &msg.Pong{}
			}
		}
	}
}

func (c *Control) writer() {
	defer func() {
		if err := recover(); err != nil {
			c.conn.Info("Control::writer failed with error %v: %s", err, debug.Stack())
		}
	}()

	// kill everything if the writer() stops
	defer c.shutdown.Begin()

	// notify that we've flushed all messages
	defer c.writerShutdown.Complete()

	// write messages to the control channel
	for m := range c.out {
		c.conn.SetWriteDeadline(time.Now().Add(controlWriteTimeout))
		if err := msg.WriteMsg(c.conn, m); err != nil {
			panic(err)
		}
	}
}

func (c *Control) reader() {
	defer func() {
		if err := recover(); err != nil {
			c.conn.Warn("Control::reader failed with error %v: %s", err, debug.Stack())
		}
	}()

	// kill everything if the reader stops
	defer c.shutdown.Begin()

	// notify that we're done
	defer c.readerShutdown.Complete()

	// read messages from the control channel
	for {
		if msg, err := msg.ReadMsg(c.conn); err != nil {
			if err == io.EOF {
				c.conn.Info("EOF")
				return
			} else {
				panic(err)
			}
		} else {
			// this can also panic during shutdown
			c.in <- msg
		}
	}
}

func (c *Control) stopper() {
	defer func() {
		if r := recover(); r != nil {
			c.conn.Error("Failed to shut down control: %v", r)
		}
	}()

	// wait until we're instructed to shutdown
	c.shutdown.WaitBegin()

	// remove ourself from the control registry. A control that was replaced
	// (the client reconnected before this connection noticed) must leave the
	// replacement in place; Del decides that under the registry lock, and the
	// replaced flag is the local shortcut for the common case.
	if c.wasReplaced() {
		c.conn.Debug("Replaced by a newer control; not removing the control registry entry")
	} else if err := controlRegistry.Del(c.id, c); err != nil {
		c.conn.Debug("Control registry entry not removed: %v", err)
	}

	// shutdown manager() so that we have no more work to do
	close(c.in)
	c.managerShutdown.WaitComplete()

	// shutdown writer()
	close(c.out)
	c.writerShutdown.WaitComplete()

	// close connection fully
	c.conn.Close()

	// shutdown all of the tunnels
	for _, t := range c.tunnels {
		t.Shutdown()
	}

	// tear down the mux session: its streams are this control's proxy
	// connections (SPEC 3.1) and none of them may outlive it. Closing the
	// session fails every stream, so the joins on them unwind before the pool
	// below is drained.
	if m := c.takeMuxSession(); m != nil {
		m.Close()
	}

	// shutdown all of the proxy connections
	close(c.proxies)
	for p := range c.proxies {
		p.Close()
	}

	c.shutdown.Complete()
	c.conn.Info("Shutdown complete")
	atomic.AddInt64(&controlConnCount, -1)
}

// SetMuxSession attaches a client's multiplexed proxy connection to this
// control (SPEC 3.1), replacing -- and closing -- whatever session the client
// had before.
//
// A second mux session for one control is what a client that reconnected looks
// like: the previous one is dead or dying by definition, and its streams must
// never be handed to a public connection again, so the old session is closed
// rather than left to be discovered as stale.
func (c *Control) SetMuxSession(m *MuxSession) {
	c.muxMu.Lock()
	old := c.mux
	c.mux = m
	c.muxMu.Unlock()

	if old != nil {
		old.Close()
	}
}

// MuxSession returns this control's mux session, or nil when the client has not
// registered one (a pre-mux agent, or the window before it does).
func (c *Control) MuxSession() *MuxSession {
	c.muxMu.Lock()
	defer c.muxMu.Unlock()
	return c.mux
}

// takeMuxSession detaches and returns the control's mux session, if any, so the
// caller can close it without holding the lock.
func (c *Control) takeMuxSession() *MuxSession {
	c.muxMu.Lock()
	defer c.muxMu.Unlock()

	m := c.mux
	c.mux = nil
	return m
}

// clearMuxSession drops the control's reference to a session that is closing on
// its own (its accept loop ended), so that a dead session is not reported as a
// live one.
func (c *Control) clearMuxSession(m *MuxSession) {
	c.muxMu.Lock()
	if c.mux == m {
		c.mux = nil
	}
	c.muxMu.Unlock()
}

// RegisterProxy puts a proxy connection into this control's pool.
//
// No staleness deadline is stamped here. The conn is not used while it waits in
// the pool, so a deadline starting now would measure the wrong thing: a conn
// that waited 59 of its 60 seconds would be handed out with a second of budget
// left, and the StartProxy write -- the first thing that happens to it --
// would fail on a conn that is perfectly healthy. The deadline is stamped at
// handout instead (GetProxy), where the clock starts when the conn is asked to
// do something.
func (c *Control) RegisterProxy(conn conn.Conn) {
	conn.AddLogPrefix(c.id)

	select {
	case c.proxies <- conn:
		conn.Info("Registered")
	default:
		conn.Info("Proxies buffer is full, discarding.")
		conn.Close()
	}
}

// Remove a proxy connection from the pool and return it
// If not proxy connections are in the pool, request one
// and wait until it is available
// Returns an error if we couldn't get a proxy because it took too long
// or the tunnel is closing
//
// Every conn this hands out carries a fresh proxyStaleDuration deadline, which
// is the budget for the StartProxy handshake that follows. It is deliberately
// not a lease on the whole connection: HandlePublicConnection clears the
// deadline once the handshake is done, because a proxied connection has no
// business timing out while the rewriter policies are running over it (a
// long-lived stream, an idle websocket). What bounds a conn that died while
// nobody was looking is the fresh deadline here -- the write below it fails
// against a peer that is gone -- rather than the dwell time it accumulated.
func (c *Control) GetProxy() (proxyConn conn.Conn, err error) {
	var ok bool

	// get a proxy connection from the pool
	select {
	case proxyConn, ok = <-c.proxies:
		if !ok {
			err = fmt.Errorf("No proxy connections available, control is closing")
			return
		}
	default:
		// no proxy available in the pool, ask for one over the control channel
		c.conn.Debug("No proxy in pool, requesting proxy from control . . .")
		if err = util.PanicToError(func() { c.out <- &msg.ReqProxy{} }); err != nil {
			return
		}

		select {
		case proxyConn, ok = <-c.proxies:
			if !ok {
				err = fmt.Errorf("No proxy connections available, control is closing")
				return
			}

		case <-time.After(pingTimeoutInterval):
			err = fmt.Errorf("Timeout trying to get proxy connection")
			return
		}
	}

	// stamped here, not at registration: this is the moment the conn stops
	// waiting and starts working
	proxyConn.SetDeadline(time.Now().Add(proxyStaleDuration))
	return
}

// Called when this control is replaced by another control
// this can happen if the network drops out and the client reconnects
// before the old tunnel has lost its heartbeat
//
// The id is NOT cleared. It used to be, so that the stopper's
// registry.Del(c.id) would miss the replacement -- but c.id is read
// concurrently by the affinity cache, the metrics and every admin snapshot, so
// writing to it here was a data race (and made a replaced control report itself
// as the empty id in all of those places). The replacement signal is the
// replaced flag now, and ControlRegistry.Del re-checks the identity under the
// registry lock, which closes the window between this call and the stopper
// running even if the flag is somehow missed.
func (c *Control) Replaced(replacement *Control) {
	c.conn.Info("Replaced by control: %s", replacement.conn.Id())

	atomic.StoreInt32(&c.replaced, 1)

	// tell the old one to shutdown
	c.shutdown.Begin()
}

// wasReplaced reports whether this control lost its id to a newer connection.
func (c *Control) wasReplaced() bool {
	return atomic.LoadInt32(&c.replaced) == 1
}
