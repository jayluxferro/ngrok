package client

import (
	"crypto/tls"
	"fmt"
	metrics "github.com/rcrowley/go-metrics"
	"github.com/xtaci/smux/v2"
	"io"
	"math"
	"net"
	"ngrok/client/mvc"
	"ngrok/conn"
	"ngrok/log"
	"ngrok/msg"
	"ngrok/proto"
	"ngrok/rewriter"
	"ngrok/util"
	"ngrok/version"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultServerAddr   = "ngrokd.ngrok.com:443"
	defaultInspectAddr  = "127.0.0.1:4040"
	pingInterval        = 20 * time.Second
	maxPongLatency      = 15 * time.Second
	updateCheckInterval = 6 * time.Hour

	// The capability that switches this client to the multiplexed transport
	// (SPEC cluster 3, 3.1) is msg.MuxCapability: it is the server's string, so
	// it lives with the wire vocabulary rather than being spelled again here.
	// Without it -- a pre-mux server -- the client dials one conn per proxy
	// connection, which is what it has always done.

	// muxMaxAttempts bounds the mux watchdog's consecutive failures: a session
	// that could not be dialed, or that died before it carried anything. Once
	// it is reached the mux transport is abandoned for the rest of the control
	// session and proxy connections are dialed one by one, which is always
	// correct -- only slower.
	muxMaxAttempts = 8

	// muxRetryBaseDelay is the first reconnect delay; it doubles per consecutive
	// failure up to muxMaxRetryDelay.
	muxRetryBaseDelay = 1 * time.Second
	muxMaxRetryDelay  = 30 * time.Second

	// muxMinSessionLifetime is how long a mux session must survive to count as
	// "the transport worked, it just dropped": only a session shorter than this
	// consumes one of the bounded attempts. Without it, a server that rejects
	// every mux conn would be redialed in a hot loop forever.
	muxMinSessionLifetime = 5 * time.Second
	BadGateway            = `<html>
<body style="background-color: #97a8b9">
    <div style="margin:auto; width:400px;padding: 20px 60px; background-color: #D3D3D3; border: 5px solid maroon;">
        <h2>Tunnel %s unavailable</h2>
        <p>Unable to initiate connection to <strong>%s</strong>. A web server must be running on port <strong>%s</strong> to complete the tunnel.</p>
`
)

type ClientModel struct {
	log.Logger

	id            string
	tunnels       map[string]mvc.Tunnel
	tunnelsMu     sync.RWMutex
	serverVersion string
	serverCaps    map[string]struct{}
	metrics       *ClientMetrics
	updateStatus  mvc.UpdateStatus
	connStatus    mvc.ConnStatus
	protoMap      map[string]proto.Protocol
	protocols     []proto.Protocol
	ctl           mvc.Controller
	serverAddr    string
	proxyUrl      string
	authToken     string
	tlsConfig     *tls.Config
	tunnelConfig  map[string]*TunnelConfiguration
	configPath    string
	proxyWorkers  chan struct{}

	// sessionSecret is the secret that goes with c.id: handed out by the server
	// in AuthResp, presented in Auth when this client reconnects with that id,
	// and in every RegProxy and RegMux. It is the proof that a connection
	// naming this client is this client, which is what the server checks before
	// it hands over a session's traffic.
	//
	// In memory only, for the life of the session: it is not written to the
	// config file or anywhere else, so a client restart simply starts a new
	// session with a new id and a new secret. That costs one round trip and
	// saves the alternative -- a credential at rest, in a file whose
	// permissions the client would then own -- and it is why the server can
	// treat an unknown id as "make a new one" instead of having to support
	// recovery.
	//
	// Guarded by its own lock, unlike c.id: the control loop writes it once per
	// control session while proxy goroutines and the mux watchdog read it.
	sessionSecretMu sync.RWMutex
	sessionSecret   string

	// mux session (SPEC 3.1): the single conn every proxy stream travels on,
	// when the server advertised muxCapability. muxMu guards the slot because
	// the watchdog replaces it while ReqProxy handlers read it.
	muxMu sync.Mutex
	mux   *muxSession
}

// sessionSecretValue returns the session secret the server handed out, or ""
// when there is none (no control session yet, or a server that predates it).
func (c *ClientModel) sessionSecretValue() string {
	c.sessionSecretMu.RLock()
	defer c.sessionSecretMu.RUnlock()
	return c.sessionSecret
}

// setSessionSecret records the secret that goes with the current client id.
func (c *ClientModel) setSessionSecret(secret string) {
	c.sessionSecretMu.Lock()
	c.sessionSecret = secret
	c.sessionSecretMu.Unlock()
}

// resumeCredentials returns what to put in Auth's ClientId and Secret fields.
//
// Resuming an id is only possible with the secret that proves it, so a client
// that holds an id but no secret sends neither and asks for a fresh session
// instead: it cannot prove the id, the server would refuse the claim, and the
// session it needs is a new one anyway. The only way to be in that state is to
// have spoken to a server that predates the field (or to have lost the secret
// with the process), which is exactly the case this keeps working.
func (c *ClientModel) resumeCredentials() (clientId, secret string) {
	secret = c.sessionSecretValue()
	if c.id == "" || secret == "" {
		return "", ""
	}
	return c.id, secret
}

func newClientModel(config *Configuration, ctl mvc.Controller) *ClientModel {
	// The protocol names are package msg's (they are what the wire carries and
	// what the server matches on), and the http/https aliasing is deliberate:
	// one *proto.Http serves both, because the difference between them is which
	// public listener the server accepted the connection on, not anything this
	// client does -- the private leg it dials is plain HTTP either way.
	protoMap := make(map[string]proto.Protocol)
	protoMap[msg.ProtoHTTP] = proto.NewHttp()
	protoMap[msg.ProtoHTTPS] = protoMap[msg.ProtoHTTP]
	protoMap[msg.ProtoTCP] = proto.NewTcp()
	protocols := []proto.Protocol{protoMap[msg.ProtoHTTP], protoMap[msg.ProtoTCP]}

	m := &ClientModel{
		Logger: log.NewPrefixLogger("client"),

		// server address
		serverAddr: config.ServerAddr,

		// proxy address
		proxyUrl: config.HttpProxy,

		// auth token
		authToken: config.AuthToken,

		// connection status
		connStatus: mvc.ConnConnecting,

		// update status
		updateStatus: mvc.UpdateNone,

		// metrics
		metrics: NewClientMetrics(),

		// protocols
		protoMap: protoMap,

		// protocol list
		protocols: protocols,

		// open tunnels
		tunnels: make(map[string]mvc.Tunnel),

		// controller
		ctl: ctl,

		// tunnel configuration
		tunnelConfig: config.Tunnels,

		// config path
		configPath: config.Path,

		// bounded proxy setup workers
		proxyWorkers: make(chan struct{}, config.ProxyMaxConcurrent),
	}

	// configure TLS
	if config.TrustHostRootCerts {
		m.Info("Trusting host's root certificates")
		m.tlsConfig = &tls.Config{}
	} else {
		m.Info("Loading root CAs from: %v", rootCrtPaths)
		var err error
		m.tlsConfig, err = LoadTLSConfig(rootCrtPaths)
		if err != nil {
			// This should not happen with the new implementation,
			// but handle it gracefully just in case
			m.Warn("Failed to load TLS config, using system root CAs: %v", err)
			m.tlsConfig = &tls.Config{}
		} else if m.tlsConfig.RootCAs == nil {
			// No embedded certificates were loaded, using system root CAs
			m.Info("No embedded certificates found, using system root CAs")
		} else {
			m.Info("Using embedded root certificates")
		}
	}

	// configure TLS SNI
	m.tlsConfig.ServerName = serverName(m.serverAddr)
	m.tlsConfig.InsecureSkipVerify = useInsecureSkipVerify()
	if m.tlsConfig.InsecureSkipVerify {
		m.Warn("TLS certificate verification is disabled (NGROK_INSECURE_SKIP_VERIFY=1)")
	}

	return m
}

// server name in release builds is the host part of the server address
func serverName(addr string) string {
	host, _, err := net.SplitHostPort(addr)

	// should never panic because the config parser calls SplitHostPort first
	if err != nil {
		panic(err)
	}

	return host
}

// mvc.State interface
func (c *ClientModel) GetProtocols() []proto.Protocol { return c.protocols }
func (c *ClientModel) GetClientVersion() string       { return version.MajorMinor() }
func (c *ClientModel) GetServerVersion() string       { return c.serverVersion }
func (c *ClientModel) GetTunnels() []mvc.Tunnel {
	c.tunnelsMu.RLock()
	defer c.tunnelsMu.RUnlock()

	tunnels := make([]mvc.Tunnel, 0)
	for _, t := range c.tunnels {
		tunnels = append(tunnels, t)
	}
	return tunnels
}
func (c *ClientModel) GetConnStatus() mvc.ConnStatus     { return c.connStatus }
func (c *ClientModel) GetUpdateStatus() mvc.UpdateStatus { return c.updateStatus }

func (c *ClientModel) GetConnectionMetrics() (metrics.Meter, metrics.Timer) {
	return c.metrics.connMeter, c.metrics.connTimer
}

func (c *ClientModel) GetBytesInMetrics() (metrics.Counter, metrics.Histogram) {
	return c.metrics.bytesInCount, c.metrics.bytesIn
}

func (c *ClientModel) GetBytesOutMetrics() (metrics.Counter, metrics.Histogram) {
	return c.metrics.bytesOutCount, c.metrics.bytesOut
}
func (c *ClientModel) SetUpdateStatus(updateStatus mvc.UpdateStatus) {
	c.updateStatus = updateStatus
	c.update()
}

// mvc.Model interface
func (c *ClientModel) PlayRequest(tunnel mvc.Tunnel, payload []byte) {
	var localConn conn.Conn
	localConn, err := conn.Dial(tunnel.LocalAddr, "prv", nil)
	if err != nil {
		c.Warn("Failed to open private leg to %s: %v", tunnel.LocalAddr, err)
		return
	}

	defer localConn.Close()
	localConn = tunnel.Protocol.WrapConn(localConn, mvc.ConnectionContext{Tunnel: tunnel, ClientAddr: "127.0.0.1"})
	localConn.Write(payload)
	io.ReadAll(localConn)
}

func (c *ClientModel) Shutdown() {
}

func (c *ClientModel) update() {
	c.ctl.Update(c)
}

func (c *ClientModel) Run() {
	// how long we should wait before we reconnect
	maxWait := 30 * time.Second
	wait := 1 * time.Second

	for {
		// run the control channel
		c.control()

		// control only returns when a failure has occurred, so we're going to try to reconnect
		if c.connStatus == mvc.ConnOnline {
			wait = 1 * time.Second
		}

		log.Info("Waiting %d seconds before reconnecting", int(wait.Seconds()))
		time.Sleep(wait)
		// exponentially increase wait time
		wait = 2 * wait
		wait = time.Duration(math.Min(float64(wait), float64(maxWait)))
		c.connStatus = mvc.ConnReconnecting
		c.update()
	}
}

// Establishes and manages a tunnel control connection with the server
func (c *ClientModel) control() {
	defer func() {
		if r := recover(); r != nil {
			log.Error("control recovering from failure %v", r)
		}
	}()

	// establish control channel
	var (
		ctlConn conn.Conn
		err     error
	)
	if c.proxyUrl == "" {
		// simple non-proxied case, just connect to the server
		ctlConn, err = conn.Dial(c.serverAddr, "ctl", c.tlsConfig)
	} else {
		ctlConn, err = conn.DialHttpProxy(c.proxyUrl, c.serverAddr, "ctl", c.tlsConfig)
	}
	if err != nil {
		panic(err)
	}
	defer ctlConn.Close()

	// authenticate with the server. A reconnect resumes this client's previous
	// session -- the same ClientId, which is what keeps its tunnel urls and its
	// affinity -- by presenting the secret that came with that id. Without a
	// secret there is nothing to resume: an empty ClientId asks for a new
	// session (see resumeCredentials).
	resumeId, resumeSecret := c.resumeCredentials()
	auth := &msg.Auth{
		ClientId:  resumeId,
		Secret:    resumeSecret,
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		Version:   version.Proto,
		MmVersion: version.MajorMinor(),
		User:      c.authToken,
		Caps:      []string{"inspect_body_truncation", "inspect_auth"},
	}

	if err = msg.WriteMsg(ctlConn, auth); err != nil {
		panic(err)
	}

	// wait for the server to authenticate us
	var authResp msg.AuthResp
	if err = msg.ReadMsgInto(ctlConn, &authResp); err != nil {
		panic(err)
	}

	if authResp.Error != "" {
		emsg := fmt.Sprintf("Failed to authenticate to server: %s", authResp.Error)
		c.ctl.Shutdown(emsg)
		return
	}

	c.id = authResp.ClientId
	// The server mints a secret with every id it assigns, and the client stores
	// it for the life of the session: it is the proof that a later connection
	// naming this id is this client, so the client presents it when it
	// reconnects and on every proxy connection (SPEC cluster 3 hardening).
	c.setSessionSecret(authResp.Secret)
	c.serverVersion = authResp.MmVersion
	c.serverCaps = make(map[string]struct{}, len(authResp.Caps))
	for _, capName := range authResp.Caps {
		c.serverCaps[capName] = struct{}{}
	}
	c.Info("Authenticated with server, client id: %v", c.id)
	c.update()
	if err = SaveAuthToken(c.configPath, c.authToken); err != nil {
		c.Error("Failed to save auth token: %v", err)
	}

	// SPEC 3.1: when the server offers the multiplexed transport, bring up the
	// mux conn for this control session -- it belongs to the control session and
	// goes away with it (the watchdog closes it when muxStop closes).
	//
	// The first dial happens in the watchdog rather than here on purpose: it is
	// a second connection to the server, and a server that stalls it must not be
	// able to hold up the control channel. The cost of that choice is bounded
	// and small -- the ReqProxy the server sends right after AuthResp is
	// answered with a dialed proxy conn when it beats the session, and every
	// later one with a stream.
	if _, ok := c.serverCaps[msg.MuxCapability]; ok {
		c.Info("Server offers %s; using one multiplexed proxy connection", msg.MuxCapability)
		muxStop := make(chan struct{})
		defer close(muxStop)
		go c.muxWatchdog(muxStop, nil)
	}

	// request tunnels
	reqIdToTunnelConfig := make(map[string]*TunnelConfiguration)
	for _, config := range c.tunnelConfig {
		reqTunnel := reqTunnelFromConfig(util.RandId(8), config)

		// send the tunnel request
		if err = msg.WriteMsg(ctlConn, reqTunnel); err != nil {
			panic(err)
		}

		// save request id association so we know which local address
		// to proxy to later
		reqIdToTunnelConfig[reqTunnel.ReqId] = config
	}

	// start the heartbeat
	lastPong := time.Now().UnixNano()
	c.ctl.Go(func() { c.heartbeat(&lastPong, ctlConn) })

	// main control loop
	for {
		var rawMsg msg.Message
		if rawMsg, err = msg.ReadMsg(ctlConn); err != nil {
			panic(err)
		}

		switch m := rawMsg.(type) {
		case *msg.ReqProxy:
			c.ctl.Go(c.proxyBounded)

		case *msg.Pong:
			atomic.StoreInt64(&lastPong, time.Now().UnixNano())

		case *msg.NewTunnel:
			if m.Error != "" {
				emsg := fmt.Sprintf("Server failed to allocate tunnel: %s", m.Error)
				c.Error(emsg)
				c.ctl.Shutdown(emsg)
				continue
			}

			// The tunnel carries its config from here on: this is the last
			// point at which the config that requested the tunnel is still
			// reachable, and by the time a proxied connection arrives proxy()
			// has nothing but the tunnel itself (found by public URL).
			tunnelCfg := reqIdToTunnelConfig[m.ReqId]
			tunnel := tunnelFromConfig(m.Url, m.Protocol, c.protoMap[m.Protocol], tunnelCfg)

			c.tunnelsMu.Lock()
			c.tunnels[tunnel.PublicUrl] = tunnel
			c.tunnelsMu.Unlock()
			c.connStatus = mvc.ConnOnline
			c.Info("Tunnel established at %v", tunnel.PublicUrl)
			c.update()

		default:
			ctlConn.Warn("Ignoring unknown control message %v ", m)
		}
	}
}

// reqTunnelFromConfig builds the ReqTunnel that asks the server for one
// configured tunnel (SPEC 3.5), carrying the endpoint settings added by
// cluster 2 -- binding, pooling and forward_to -- along with the fields the
// client has always sent, and the traffic policy (SPEC 3.4), which is the one
// of them the client never evaluates: it validates the policy at load time and
// passes it on, and the server compiles it once at registration and enforces it
// on every connection. It is split out of control() so that the request,
// which is otherwise only observable over a live control connection, can be
// asserted on directly.
//
// The protocol list is sorted rather than left in map order: a config tunnel
// with an http and an https leg used to ask for "http+https" or "https+http"
// at random, which made the request (and any test of it) unreproducible for no
// reason. The set of protocols is unchanged, and the set is all the server
// looks at -- it splits the field on "+" (server/control.go).
func reqTunnelFromConfig(reqId string, config *TunnelConfiguration) *msg.ReqTunnel {
	protocols := make([]string, 0, len(config.Protocols))
	for proto := range config.Protocols {
		protocols = append(protocols, proto)
	}
	sort.Strings(protocols)

	return &msg.ReqTunnel{
		ReqId:      reqId,
		Protocol:   strings.Join(protocols, "+"),
		Hostname:   config.Hostname,
		Subdomain:  config.Subdomain,
		HttpAuth:   config.HttpAuth,
		RemotePort: config.RemotePort,

		Binding:   config.Binding,
		Pooling:   config.Pooling,
		ForwardTo: config.ForwardTo,

		// Nil when the tunnel has no policy, which is the common case and the
		// value every pre-cluster-4 client sends: the field is additive, and
		// the server's no-policy path is the one it always took.
		TrafficPolicy: config.TrafficPolicy,
	}
}

// tunnelFromConfig builds the mvc.Tunnel the client works with for a tunnel the
// server just established. Like reqTunnelFromConfig it is split out of
// control() so the mapping from configuration to tunnel -- which header
// settings get flattened, which endpoint settings get carried, and the fact
// that Compress is the resolved value of a key that defaults to on -- can be
// tested without a control channel.
//
// publicUrl and protocolName are what the server reported (msg.NewTunnel.Url
// and .Protocol). The proto.Protocol is passed in already resolved, because the
// map from a protocol name to a proto.Protocol belongs to the ClientModel and
// not to the tunnel.
func tunnelFromConfig(publicUrl, protocolName string, protocol proto.Protocol, config *TunnelConfiguration) mvc.Tunnel {
	requestHeaderAdd, requestHeaderRemove := flattenHeaderConfig(config.RequestHeader)
	responseHeaderAdd, responseHeaderRemove := flattenHeaderConfig(config.ResponseHeader)

	return mvc.Tunnel{
		PublicUrl: publicUrl,
		LocalAddr: config.Protocols[protocolName],
		Protocol:  protocol,

		HostHeader: config.HostHeader,

		RequestHeaderAdd:     requestHeaderAdd,
		RequestHeaderRemove:  requestHeaderRemove,
		ResponseHeaderAdd:    responseHeaderAdd,
		ResponseHeaderRemove: responseHeaderRemove,

		Binding:   config.Binding,
		Pooling:   config.Pooling,
		ForwardTo: config.ForwardTo,
		Compress:  config.Compress(),
	}
}

func (c *ClientModel) proxyBounded() {
	c.proxyWorkers <- struct{}{}
	defer func() { <-c.proxyWorkers }()
	c.proxy()
}

// Establishes and manages a tunnel proxy connection with the server: one stream
// on the mux session when there is a live one (SPEC 3.1), a conn of its own
// otherwise.
func (c *ClientModel) proxy() {
	if sess := c.muxSession(); sess != nil {
		if err := c.proxyStream(sess); err == nil {
			return
		} else {
			c.Warn("Mux proxy stream failed (%v), dialing a proxy connection instead", err)
		}
	}

	c.proxyDial()
}

// proxyDial is the original per-connection path: dial the server, register, and
// relay what the server sends. It is what a server without the mux capability
// gets, and what serves the window before the mux session is up, while it is
// being re-established, and after the watchdog gave up.
func (c *ClientModel) proxyDial() {
	var (
		remoteConn conn.Conn
		err        error
	)

	if c.proxyUrl == "" {
		remoteConn, err = conn.Dial(c.serverAddr, "pxy", c.tlsConfig)
	} else {
		remoteConn, err = conn.DialHttpProxy(c.proxyUrl, c.serverAddr, "pxy", c.tlsConfig)
	}

	if err != nil {
		log.Error("Failed to establish proxy connection: %v", err)
		return
	}
	defer remoteConn.Close()

	err = msg.WriteMsg(remoteConn, &msg.RegProxy{ClientId: c.id, Secret: c.sessionSecretValue()})
	if err != nil {
		remoteConn.Error("Failed to write RegProxy: %v", err)
		return
	}

	// wait for the server to ack our register
	var startPxy msg.StartProxy
	if err = msg.ReadMsgInto(remoteConn, &startPxy); err != nil {
		remoteConn.Error("Server failed to write StartProxy: %v", err)
		return
	}

	c.serveProxyConnection(remoteConn, &startPxy)
}

// proxyStream answers one ReqProxy with a stream on the mux session: the same
// RegProxy/StartProxy handshake a dialed proxy conn performs, on a conn that
// costs no handshake, followed by the very same relay.
//
// The error return covers the handshake only. Once the handshake is done and
// serveProxyConnection has the stream, the connection's lifetime belongs to the
// server (StartProxy) and the relay: a dead session ends it exactly the way a
// dropped dialed conn is ended, and it is not retried here. A handshake failure
// means this stream never carried anything, so the caller is free to dial
// instead.
func (c *ClientModel) proxyStream(sess *muxSession) error {
	stream, err := sess.sess.OpenStream()
	if err != nil {
		return fmt.Errorf("failed to open a proxy stream: %v", err)
	}

	// conn.Wrap's default case is what makes a stream a conn.Conn; after this
	// line the msg framing, the deadlines and the join are the code the dialed
	// path runs, unmodified.
	remoteConn := conn.Wrap(stream, "pxy")
	if remoteConn == nil {
		stream.Close()
		return fmt.Errorf("failed to wrap the proxy stream")
	}
	defer remoteConn.Close()

	if err = msg.WriteMsg(remoteConn, &msg.RegProxy{ClientId: c.id, Secret: c.sessionSecretValue()}); err != nil {
		return fmt.Errorf("failed to write RegProxy: %v", err)
	}

	// wait for the server to ack our register
	var startPxy msg.StartProxy
	if err = msg.ReadMsgInto(remoteConn, &startPxy); err != nil {
		return fmt.Errorf("server failed to write StartProxy: %v", err)
	}

	c.serveProxyConnection(remoteConn, &startPxy)
	return nil
}

// serveProxyConnection is the part of serving a proxy connection that runs once
// the server has sent StartProxy: find the tunnel it is for, dial the private
// leg, and relay until both directions stop. It is shared verbatim by the
// dialed and the mux paths (SPEC 3.1) so that the two transports cannot drift
// apart: the metrics, the 502 for a dead upstream, the tee/rewriter stack
// inside relay() and the byte accounting are common to both.
//
// The remainder of what used to be proxy()'s body follows, unchanged.
func (c *ClientModel) serveProxyConnection(remoteConn conn.Conn, startPxy *msg.StartProxy) {
	c.tunnelsMu.RLock()
	tunnel, ok := c.tunnels[startPxy.Url]
	c.tunnelsMu.RUnlock()
	if !ok {
		remoteConn.Error("Couldn't find tunnel for proxy: %s", startPxy.Url)
		return
	}

	// start up the private connection
	start := time.Now()
	localConn, err := conn.Dial(tunnel.LocalAddr, "prv", nil)
	if err != nil {
		remoteConn.Warn("Failed to open private leg %s: %v", tunnel.LocalAddr, err)

		if msg.IsHTTP(tunnel.Protocol.GetName()) {
			// try to be helpful when you're in HTTP mode and a human might see the output
			badGatewayBody := fmt.Sprintf(BadGateway, tunnel.PublicUrl, tunnel.LocalAddr, tunnel.LocalAddr)
			remoteConn.Write([]byte(fmt.Sprintf(`HTTP/1.0 502 Bad Gateway
Content-Type: text/html
Content-Length: %d

%s`, len(badGatewayBody), badGatewayBody)))
		}
		return
	}
	defer localConn.Close()

	m := c.metrics
	m.proxySetupTimer.Update(time.Since(start))
	m.connMeter.Mark(1)
	c.update()
	m.connTimer.Time(func() {
		localConn := tunnel.Protocol.WrapConn(localConn, mvc.ConnectionContext{Tunnel: tunnel, ClientAddr: startPxy.ClientAddr})
		bytesIn, bytesOut := c.relay(localConn, remoteConn, tunnel, startPxy.ClientAddr)
		m.bytesIn.Update(bytesIn)
		m.bytesOut.Update(bytesOut)
		m.bytesInCount.Inc(bytesIn)
		m.bytesOutCount.Inc(bytesOut)
	})
	c.update()
}

// relay shuttles bytes between the two legs of a proxied connection until both
// directions have stopped -- which conn.Join makes happen as soon as either
// side closes -- and reports how much flowed in each direction. bytesIn counts
// the public -> local leg and bytesOut the local -> public one, which is what
// the raw join has always reported and what the byte metrics mean.
//
// This is where header rewriting enters the data path (SPEC 5.3), split out of
// proxy() so that the join can be exercised without a server to register with,
// a tunnel to look up or a control channel to speak.
//
// The direction wiring is the one thing here that is easy to get backwards.
// Requests flow remoteConn -> localConn and responses flow localConn ->
// remoteConn, and each rewriter wraps the *source* end of the direction it
// rewrites: the request rewriter reads remoteConn (the public bytes) and the
// response rewriter reads localConn (the upstream bytes). Wrapping the source
// rather than the destination is what keeps back-pressure intact -- the
// rewriter only ever pulls from the side that is being read anyway.
//
// conn.Join's first return value is always the bytes it copied into its first
// argument from its second, so Join(fromUpstream, toUpstream) reports requests
// first and responses second: the same order the unwrapped Join(localConn,
// remoteConn) reports, which is why bytesIn keeps its meaning. The two
// filtered conns only filter reads; writes, closes and deadlines still go to
// the connections underneath (rewriter/conn.go), so each leg is closed exactly
// as the raw join closed it.
func (c *ClientModel) relay(localConn, remoteConn conn.Conn, tunnel mvc.Tunnel, clientAddr string) (bytesIn, bytesOut int64) {
	if !msg.IsHTTP(tunnel.Protocol.GetName()) {
		// Nothing with a header syntax: TCP tunnels, and any protocol this
		// client version does not know, keep the byte pipe they always had.
		return conn.Join(localConn, remoteConn)
	}

	policy := policyFromTunnel(tunnel, clientAddr)
	if policy == nil || policy.IsNoop() {
		// A no-op policy would only copy the bytes the long way round. A live
		// HTTP tunnel cannot currently produce one -- SPEC 4.3's X-Forwarded
		// injection is always on, and that alone makes the policy do work --
		// but the escape hatch stays wired so the decision is stated here
		// rather than implied by the absence of a check.
		c.Debug("Tunnel %s: no header rewriting for this connection", tunnel.PublicUrl)
		return conn.Join(localConn, remoteConn)
	}

	c.Debug("Tunnel %s: rewriting HTTP headers (host_header=%q)", tunnel.PublicUrl, policy.HostHeader)
	toUpstream, fromUpstream := rewriter.NewConnPair(remoteConn, localConn, policy)
	return conn.Join(fromUpstream, toUpstream)
}

// muxSession is the client's end of one multiplexed proxy connection (SPEC
// cluster 3, 3.1): a single TCP+TLS conn to the server carrying every proxy
// stream, instead of one conn per proxy connection.
//
// The session is a shared failure domain -- if it dies, every stream on it dies
// with it -- so nothing but proxy streams travels over it, and the watchdog
// below is what makes that acceptable: streams that die mid-flight fail closed,
// unwinding their joins exactly as a dropped dialed conn does, and a new
// session is brought up behind them.
type muxSession struct {
	log.Logger

	// the conn carrying smux frames, and the session on it
	conn conn.Conn
	sess *smux.Session

	// when the session was established, which is what tells a flaky transport
	// (it lived, then died) from one that never worked (it died at once)
	established time.Time

	// done is closed once the session is known to be dead; the watchdog waits
	// on it to know when to reconnect
	done      chan struct{}
	closeOnce sync.Once
}

// newMuxSession wraps an established smux session and starts the goroutine that
// turns its death into a closed done channel.
func newMuxSession(muxConn conn.Conn, sess *smux.Session) *muxSession {
	m := &muxSession{
		Logger:      log.NewPrefixLogger("mux"),
		conn:        muxConn,
		sess:        sess,
		established: time.Now(),
		done:        make(chan struct{}),
	}

	go m.watch()
	return m
}

// watch blocks until the session dies and reports it by closing done.
//
// This side opens every proxy stream (the server only ever accepts them), so
// the accept half of the session exists for exactly this: AcceptStream returns
// when either end closes the session, when the transport dies, or when smux's
// keepalive gives up on a peer that stopped answering. Nothing else here would
// notice any of those before the next stream is attempted.
func (m *muxSession) watch() {
	defer close(m.done)

	for {
		stream, err := m.sess.AcceptStream()
		if err != nil {
			m.Info("Mux session closed: %v", err)
			break
		}

		// Nothing on the server opens streams to us, so a stream here is a
		// protocol surprise: close it and keep watching.
		m.Warn("Closing unexpected stream on the mux session")
		stream.Close()
	}

	// Closing the smux session is what fails the streams and closes the conn
	// underneath; errors from it are noise, because the session is already on
	// its way out when AcceptStream returns.
	m.Close()
}

// Close tears the session down: every stream on it fails and the conn goes
// away, which is also what unblocks watch() and closes done.
func (m *muxSession) Close() {
	m.closeOnce.Do(func() {
		_ = m.sess.Close()
		_ = m.conn.Close()
	})
}

// muxConfig is the smux configuration for the client side of a mux session.
//
// The library defaults are kept -- 10s keepalive, 30s keepalive timeout, 4 MiB
// receive window, 64 KiB per-stream buffer -- so that both ends run what smux
// recommends. The keepalive is load-bearing here: it is what turns a server
// that vanished silently into a dead session, and therefore into a reconnected
// one, without waiting for a stream to be attempted.
func muxConfig() *smux.Config {
	return smux.DefaultConfig()
}

// dialMuxSession establishes one mux conn to the server: dial it (through the
// configured http proxy, like every other conn this client opens), declare it
// with RegMux, and wrap it in an smux client session.
//
// RegMux names this client's control session, which is how the server tells the
// conn apart from a control or a proxy conn; a server that does not know the
// client id closes the conn, and that shows up here as a session that dies at
// once, handled like any other mux failure.
func (c *ClientModel) dialMuxSession() (*muxSession, error) {
	var (
		muxConn conn.Conn
		err     error
	)

	if c.proxyUrl == "" {
		muxConn, err = conn.Dial(c.serverAddr, "mux", c.tlsConfig)
	} else {
		muxConn, err = conn.DialHttpProxy(c.proxyUrl, c.serverAddr, "mux", c.tlsConfig)
	}
	if err != nil {
		return nil, err
	}

	// RegMux carries the session's credentials like RegProxy does: attaching a
	// mux session to a client id means every stream on it is a proxy
	// connection for that client's tunnels, so it is authenticated with the
	// same secret the id was handed out with.
	if err = msg.WriteMsg(muxConn, &msg.RegMux{ClientId: c.id, Secret: c.sessionSecretValue()}); err != nil {
		muxConn.Close()
		return nil, err
	}

	sess, err := smux.Client(muxConn, muxConfig())
	if err != nil {
		muxConn.Close()
		return nil, err
	}

	return newMuxSession(muxConn, sess), nil
}

// muxWatchdog owns the mux transport for one control session (SPEC 3.1): it
// keeps c.mux pointing at a live session, re-establishes it when it dies, and
// closes it when the control session ends (stop).
//
// When it gives up -- muxMaxAttempts consecutive failures, each one a dial that
// failed or a session that died before carrying anything -- it leaves the slot
// empty and returns. Every ReqProxy is answered by dialing after that, which is
// what a pre-mux server gets anyway, so a mux outage costs throughput and never
// correctness. The next control session starts a fresh watchdog.
func (c *ClientModel) muxWatchdog(stop <-chan struct{}, sess *muxSession) {
	attempts := 0

	for {
		if sess != nil {
			select {
			case <-stop:
				c.Info("Control session ended, closing the mux session")
				sess.Close()
				c.clearMuxSession(sess)
				return
			case <-sess.done:
			}

			c.clearMuxSession(sess)
			lifetime := time.Since(sess.established)
			if lifetime < muxMinSessionLifetime {
				// It died before it carried anything, so it counts as a failed
				// attempt rather than as a working transport that dropped.
				attempts++
			} else {
				attempts = 0
			}
			c.Warn("Mux session lost after %s (attempt %d/%d)", lifetime.Round(time.Millisecond), attempts, muxMaxAttempts)
			sess = nil
		}

		if attempts >= muxMaxAttempts {
			c.Error("Giving up on the mux transport after %d failed attempts; proxy connections will be dialed one at a time", attempts)
			return
		}

		if attempts > 0 {
			delay := muxRetryDelay(attempts)
			c.Info("Waiting %s before reconnecting the mux session", delay)
			select {
			case <-time.After(delay):
			case <-stop:
				return
			}
		}

		newSess, err := c.dialMuxSession()
		if err != nil {
			attempts++
			c.Warn("Failed to establish mux session (attempt %d/%d): %v", attempts, muxMaxAttempts, err)
			continue
		}

		// A session established after the control session ended belongs to
		// nobody (c.id is about to change or the client is about to reconnect):
		// close it rather than publish it.
		select {
		case <-stop:
			newSess.Close()
			return
		default:
		}

		sess = newSess
		c.setMuxSession(sess)
		c.Info("Mux session established with %v", c.serverAddr)
	}
}

// muxRetryDelay is how long to wait before the next reconnect attempt:
// muxRetryBaseDelay doubled per consecutive failure, capped at
// muxMaxRetryDelay.
func muxRetryDelay(attempts int) time.Duration {
	delay := muxRetryBaseDelay
	for i := 1; i < attempts; i++ {
		delay *= 2
		if delay >= muxMaxRetryDelay {
			return muxMaxRetryDelay
		}
	}
	return delay
}

// setMuxSession publishes a freshly established session to the ReqProxy path.
func (c *ClientModel) setMuxSession(s *muxSession) {
	c.muxMu.Lock()
	c.mux = s
	c.muxMu.Unlock()
}

// clearMuxSession drops a session that has been closed, but only if it is still
// the one in the slot: a reconnect may already have published its replacement.
func (c *ClientModel) clearMuxSession(s *muxSession) {
	c.muxMu.Lock()
	if c.mux == s {
		c.mux = nil
	}
	c.muxMu.Unlock()
}

// muxSession returns the session a proxy stream should be opened on, or nil
// when there is none: no capability, the window before the first session is up,
// between reconnects, or after the watchdog gave up. A session that is already
// closed is reported as absent so that the caller dials instead of opening a
// stream that cannot work.
func (c *ClientModel) muxSession() *muxSession {
	c.muxMu.Lock()
	defer c.muxMu.Unlock()

	if c.mux == nil || c.mux.sess.IsClosed() {
		return nil
	}
	return c.mux
}

// Hearbeating to ensure our connection ngrokd is still live
func (c *ClientModel) heartbeat(lastPongAddr *int64, conn conn.Conn) {
	lastPing := time.Unix(atomic.LoadInt64(lastPongAddr)-1, 0)
	ping := time.NewTicker(pingInterval)
	pongCheck := time.NewTicker(time.Second)

	defer func() {
		conn.Close()
		ping.Stop()
		pongCheck.Stop()
	}()

	for {
		select {
		case <-pongCheck.C:
			lastPong := time.Unix(0, atomic.LoadInt64(lastPongAddr))
			needPong := lastPong.Sub(lastPing) < 0
			pongLatency := time.Since(lastPing)

			if needPong && pongLatency > maxPongLatency {
				c.Info("Last ping: %v, Last pong: %v", lastPing, lastPong)
				c.Info("Connection stale, haven't gotten PongMsg in %d seconds", int(pongLatency.Seconds()))
				return
			}

		case <-ping.C:
			err := msg.WriteMsg(conn, &msg.Ping{})
			if err != nil {
				conn.Debug("Got error %v when writing PingMsg", err)
				return
			}
			lastPing = time.Now()
		}
	}
}
