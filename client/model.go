package client

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/quic-go/quic-go"
	metrics "github.com/rcrowley/go-metrics"
	"github.com/xtaci/smux/v2"
	"io"
	"math"
	"net"
	"ngrok/client/mvc"
	"ngrok/conn"
	"ngrok/log"
	"ngrok/msg"
	"ngrok/policy"
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

	// carrierKeepAlivePeriod and carrierMaxIdleTimeout are the session-keeping
	// values every mux carrier runs (SPEC-CLUSTER7 5). They were smux's library
	// defaults before there was a second carrier; with QUIC beside it they are
	// pinned here and both adapters read them, so the two transports provably
	// keep a session alive on the same clock instead of similar ones. The
	// keepalive is load-bearing: it is what turns a server that vanished
	// silently into a dead session -- and therefore into a reconnected one --
	// without waiting for the next proxy stream to be attempted.
	//
	// Both are spellings of the shared timing vocabulary (msg.CarrierKeepAlive,
	// msg.CarrierIdleTimeout), not local policy: the server side keeps its half
	// of the agreement on the same clock. The values are pinned against that
	// vocabulary by TestCarrierTimeoutsUseSharedVocabulary.
	carrierKeepAlivePeriod = msg.CarrierKeepAlive
	carrierMaxIdleTimeout  = msg.CarrierIdleTimeout

	// The names the two carriers go by in logs and tests. They are not wire
	// values -- the server sees which transport dialed it, never this string.
	carrierSmux = "smux"
	carrierQuic = "quic"

	// quicALPN is the wire-vocabulary constant (msg.QuicALPN), aliased so the
	// dialer reads without the package qualifier. A mismatch fails the TLS
	// handshake -- the cross-protocol refusal -- which is the carrier
	// fallback's cue.
	quicALPN = msg.QuicALPN

	// quicMaxIncomingStreams mirrors the server's cap on concurrent proxy
	// streams (server/quic.go, SPEC-CLUSTER7 4). The client never accepts
	// streams -- the server only ever opens them into us in protocol
	// violations -- so this states the symmetric budget rather than a working
	// limit.
	quicMaxIncomingStreams = 512

	// agentTLSHandshakeTimeout bounds the public TLS handshake of an
	// agent-terminated tunnel (SPEC-CLUSTER5 5.3). It is the server's
	// connReadTimeout (server/main.go) on purpose: the server bounds how long
	// it will wait to see what a connection is, and the agent's answer to that
	// wait -- the handshake -- should not be the step that outlives the
	// patience on the other end. Like the server's, it is a deadline set before
	// the handshake and cleared after, so a live connection is never throttled
	// by it.
	agentTLSHandshakeTimeout = 10 * time.Second
	BadGateway               = `<html>
<body style="background-color: #97a8b9">
    <div style="margin:auto; width:400px;padding: 20px 60px; background-color: #D3D3D3; border: 5px solid maroon;">
        <h2>Tunnel %s unavailable</h2>
        <p>Unable to initiate connection to <strong>%s</strong>. A web server must be running on port <strong>%s</strong> to complete the tunnel.</p>
`
)

// quicHandshakeTimeout bounds the QUIC handshake of a carrier dial: the QUIC
// equivalent of the TCP dial timeout, and the thing that keeps "the UDP path
// is a black hole" from being discovered at leisure. It is a var rather than a
// const only so the tests can shrink it -- a dead QUIC path must fail fast in
// a test that then proves the smux fall-through.
var quicHandshakeTimeout = 5 * time.Second

// udpIdleTimeout is how long a udp flow may sit with no traffic in either
// direction before this end closes it (SPEC-CLUSTER8 3.2). It mirrors the
// server's per-flow expiry so both ends agree that a silent flow has ended --
// either side's expiry tears down its half, and the proxy conn close
// propagates the same way a dropped tcp tunnel's does. Like
// quicHandshakeTimeout it is a var only so the tests can shrink it; the
// default it starts from is the shared value (msg.UdpIdleTimeout), not this
// package's own idea of one.
var udpIdleTimeout = msg.UdpIdleTimeout

// proxyTransport is the resolved form of the config's proxy_transport key
// (client/config.go owns the string vocabulary and its validation): which
// carrier the mux transport prefers, after the configuration has met the one
// fact that can override it at construction time -- the http_proxy setting.
// The capability gate is separate (quicPeerCap), because it is per control
// session, not per process.
type proxyTransport int

const (
	// proxyTransportAuto prefers QUIC per attempt and falls back to the smux
	// path inside the same attempt when the QUIC dial fails. This is the
	// default.
	proxyTransportAuto proxyTransport = iota

	// proxyTransportQuic is the explicit "quic" setting; it changes nothing
	// about the capability gate, so it degrades to the smux path against a
	// server that has not turned QUIC on.
	proxyTransportQuic

	// proxyTransportTCP pins the smux path (TCP+TLS under the smux frames),
	// which is what the transport ran before SPEC-CLUSTER7.
	proxyTransportTCP
)

// proxyTransportForConfig maps a validated proxy_transport value onto the
// enum. The empty string is the value of a config (and a flag) that said
// nothing: auto.
func proxyTransportForConfig(value string) proxyTransport {
	switch value {
	case ProxyTransportQuic:
		return proxyTransportQuic
	case ProxyTransportTCP:
		return proxyTransportTCP
	default:
		return proxyTransportAuto
	}
}

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

	// proxyTransport is the carrier preference the configuration resolved to
	// at construction (SPEC-CLUSTER7 5): auto, quic, or tcp -- with any
	// http_proxy override already applied (there is no QUIC through an HTTP
	// CONNECT proxy, so http_proxy set resolves auto and quic to tcp). Read
	// only after construction: the watchdog and the dialer consult it from
	// other goroutines.
	proxyTransport proxyTransport

	// quicPeerCap records whether the current control session's AuthResp
	// advertised msg.QuicCapability. Atomic on purpose: it is written once per
	// control session, but a watchdog from the *previous* control session can
	// still be inside a dial when the next one rewrites it (control() returns
	// while the watchdog is mid-dial; only the selects between dials watch the
	// stop channel). The overlap then reads a stale-but-valid decision -- the
	// previous session's answer about the same server -- instead of racing on
	// the serverCaps map. The zero value is "not advertised", which is also
	// what a model that has never run a control session must report.
	quicPeerCap atomic.Bool

	// Per-tunnel runtime for agent-terminated tunnels (SPEC-CLUSTER5 5.3),
	// both keyed by public URL and both built when the tunnel is established
	// (NewTunnel), i.e. once per tunnel session:
	//
	//   - agentTLS is the tls.Config that terminates the tunnel's public side.
	//     Built per session on purpose: the ephemeral cert model is one
	//     certificate per session, and re-reading the configured files per
	//     session picks up a certificate rotated on disk.
	//   - tunnelPolicies is the tunnel's traffic policy, compiled client-side
	//     with the same policy package call the server's Tunnel.join uses. On
	//     an agent-terminated tunnel the http phases run HERE, where plaintext
	//     is visible; the server skips them for these tunnels.
	//
	// The mutexes are separate because the two maps are written and read at
	// different times (TLS at establishment, hooks per connection) and are
	// unrelated to each other.
	agentTLSMu       sync.Mutex
	agentTLS         map[string]*tls.Config
	tunnelPoliciesMu sync.Mutex
	tunnelPolicies   map[string]*policy.Compiled
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
	// udp (SPEC-CLUSTER8 3.2) is registered in the map the control loop
	// resolves NewTunnel.Protocol through, but deliberately not in protocols:
	// that slice is the list of protocols the controller builds inspector
	// views for, and udp has none (SPEC-CLUSTER8 2 -- no inspector for udp).
	// tcp sits in it as a harmless default-case entry; udp simply never
	// reaches a view at all.
	protoMap[msg.ProtoUDP] = proto.NewUdp()
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

		// per-tunnel agent TLS and traffic-policy runtime (SPEC-CLUSTER5 5.3),
		// populated per tunnel session by establishTunnelRuntime
		agentTLS:       make(map[string]*tls.Config),
		tunnelPolicies: make(map[string]*policy.Compiled),
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

	// Resolve the proxy transport (SPEC-CLUSTER7 5). The configured value was
	// validated at load; the one override that can still happen here is
	// http_proxy: QUIC is UDP end-to-end, and an HTTP CONNECT proxy cannot
	// carry it, so a proxy URL forces the TCP path whatever was configured.
	// The override is logged rather than applied in silence -- an operator who
	// asked for quic (or accepted auto's preference for it) and silently never
	// got it would be debugging a transport choice nobody admitted to making.
	// It is stated once per process, here, because the resolution happens once
	// per process.
	m.proxyTransport = proxyTransportForConfig(config.ProxyTransport)
	if m.proxyTransport != proxyTransportTCP && config.HttpProxy != "" {
		m.proxyTransport = proxyTransportTCP
		m.Info("http_proxy is set; using TCP for the proxy transport: QUIC needs UDP end-to-end, which an HTTP CONNECT proxy cannot carry")
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

		// SPEC-CLUSTER7 5: whether the proxy transport may prefer QUIC for
		// this control session. QUIC rides the same watchdog and the same
		// give-up arithmetic as the smux carrier, so it exists only when the
		// mux transport does -- no mux capability means no second carrier
		// either. The snapshot (not a live read of the map) is what the
		// watchdog's dialer consults; see quicPeerCap for why it must be
		// atomic.
		_, quicCap := c.serverCaps[msg.QuicCapability]
		c.quicPeerCap.Store(quicCap)
		if quicCap && c.proxyTransport != proxyTransportTCP {
			c.Info("Server offers %s; QUIC will be preferred for the proxy transport", msg.QuicCapability)
		}

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
				c.Error("%s", emsg)
				c.ctl.Shutdown(emsg)
				continue
			}

			// The tunnel carries its config from here on: this is the last
			// point at which the config that requested the tunnel is still
			// reachable, and by the time a proxied connection arrives proxy()
			// has nothing but the tunnel itself (found by public URL).
			tunnelCfg := reqIdToTunnelConfig[m.ReqId]
			tunnel := tunnelFromConfig(m.Url, m.Protocol, c.protoMap[m.Protocol], tunnelCfg)

			// The ack must echo the termination mode this client asked for.
			// A server from before agent TLS termination accepts the
			// registration and drops the field in silence -- the endpoint
			// comes up edge-terminated while this agent arms its own TLS
			// terminator, and every connection then fails twice over. The
			// echo turns that into a refusal here, at establishment, with an
			// error that says what to do about it.
			if err := terminationEchoError(m.Url, tunnelCfg, m); err != nil {
				emsg := err.Error()
				c.Error("%s", emsg)
				c.ctl.Shutdown(emsg)
				continue
			}

			// Build the per-session runtime of agent-terminated tunnels: the
			// tls.Config that will terminate the public side, and the traffic
			// policy compiled client-side (its http phases run here, not on the
			// server, for these tunnels). A failure is fatal to the session:
			// the material was already validated at load, so this only fires
			// when a certificate file changed or vanished under us, and
			// silently serving the tunnel without TLS would be the one failure
			// mode worse than stopping.
			if err = c.establishTunnelRuntime(m.Url, tunnelCfg); err != nil {
				emsg := fmt.Sprintf("Tunnel %s: %v", m.Url, err)
				c.Error("%s", emsg)
				c.ctl.Shutdown(emsg)
				continue
			}

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

		// SPEC-CLUSTER5 5.1: "" (the zero value every pre-cluster-5 client
		// sends) is edge termination -- the server decrypts, today's default --
		// and TLSTerminationAgent asks for passthrough: the server routes the
		// tunnel's https traffic by SNI and never sees plaintext.
		TLSTermination: tlsTerminationForWire(config),

		// Nil when the tunnel has no policy, which is the common case and the
		// value every pre-cluster-4 client sends: the field is additive, and
		// the server's no-policy path is the one it always took.
		TrafficPolicy: config.TrafficPolicy,
	}
}

// tlsTerminationForWire maps the config's agent_tls_termination switch onto the
// ReqTunnel.TLSTermination wire vocabulary (SPEC-CLUSTER5 5.1, single source of
// truth in package msg): false is the empty string the wire has always carried
// (edge termination), true is msg.TLSTerminationAgent.
func tlsTerminationForWire(config *TunnelConfiguration) string {
	if config.AgentTLSTermination {
		return msg.TLSTerminationAgent
	}
	return msg.TLSTerminationEdge
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

		// SPEC-CLUSTER5 5.3: the flag the proxy path checks to decide whether
		// THIS connection's public side terminates here, and what a view may
		// display. It rides on every leg of the tunnel; only the https leg's
		// public URL actually gets termination (serveProxyConnection checks the
		// scheme too).
		AgentTLS: config.AgentTLSTermination,
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
// Since SPEC-CLUSTER5 5.3 it also serves agent-terminated tunnels: when the
// tunnel's public TLS terminates here, the proxy stream arrives carrying the
// visitor's TLS records (the server relays them unread), and the steps below
// terminate that TLS before anything else happens. The order of the steps is
// the spec's, and the dial-first order is the one this function has always had.
func (c *ClientModel) serveProxyConnection(remoteConn conn.Conn, startPxy *msg.StartProxy) {
	c.tunnelsMu.RLock()
	tunnel, ok := c.tunnels[startPxy.Url]
	c.tunnelsMu.RUnlock()
	if !ok {
		remoteConn.Error("Couldn't find tunnel for proxy: %s", startPxy.Url)
		return
	}

	// A udp tunnel's flow shares none of the steps below (SPEC-CLUSTER8 3.2):
	// its local leg is a connected UDP socket, not conn.Dial's TCP conn; its
	// proxy leg carries length-framed datagrams, not a byte stream, so relay's
	// raw join would be wrong in both directions; there is no TLS to terminate
	// (agent termination is an https-leg feature) and no 502 to write -- udp
	// is not IsHTTP and stays so, and a public UDP caller whose local service
	// is dead gets silence, the same thing an unreachable UDP port gives
	// everywhere else.
	if tunnel.Protocol.GetName() == msg.ProtoUDP {
		c.serveUdpFlow(remoteConn, tunnel, startPxy.ClientAddr)
		return
	}

	// Step 1: dial the local upstream FIRST, before any TLS work, exactly as
	// this path always has. The order is load-bearing for the dead-upstream
	// case: on an agent-terminated tunnel the 502 has to go out over a
	// completed TLS handshake (step 3), and knowing the dial's outcome before
	// the handshake is what makes that one message instead of an
	// alert-after-request.
	start := time.Now()
	localConn, localErr := conn.Dial(tunnel.LocalAddr, "prv", nil)
	if localErr != nil {
		remoteConn.Warn("Failed to open private leg %s: %v", tunnel.LocalAddr, localErr)
	}

	if c.agentTerminated(tunnel) {
		// Step 2: terminate the public TLS. The remote conn -- the proxy/mux
		// stream the server is relaying raw -- becomes the plaintext leg the
		// rest of the path works on.
		plain, ok := c.terminatePublicTLS(remoteConn, tunnel, startPxy.ClientAddr)
		if !ok {
			return
		}
		defer plain.Close()

		// Step 3: dead upstream, answered with the existing 502 over the
		// terminated connection. The handshake is already complete, so the
		// visitor gets a real HTTP 502 instead of a TLS decode error.
		if localErr != nil {
			c.writeBadGateway(plain, tunnel)
			return
		}

		// Steps 4 and 5 happen in the relay below: the tee and the
		// header/compression/traffic-policy rewriter all work on the plaintext
		// legs, and the terminated conn takes the remote seat.
		remoteConn = plain
	} else if localErr != nil {
		// The edge path's dead-upstream answer, unchanged: plaintext 502 when
		// this tunnel speaks HTTP (and a human might see it), a bare close
		// otherwise.
		if msg.IsHTTP(tunnel.Protocol.GetName()) {
			c.writeBadGateway(remoteConn, tunnel)
		}
		return
	}
	defer localConn.Close()

	m := c.metrics
	m.proxySetupTimer.Update(time.Since(start))
	m.connMeter.Mark(1)
	c.update()
	m.connTimer.Time(func() {
		// The inspector tee stays on the local leg, agent-terminated or not
		// (SPEC-CLUSTER5 5.3 step 4). Both legs are plaintext at this point,
		// but the tee's buffer roles are fixed by proto/http.go -- its
		// WriteBuffer carries what is written INTO the conn (requests, on the
		// local leg) and its ReadBuffer what is read FROM it (responses). Tee'd
		// on the plain leg the roles would come out exactly reversed and the
		// analyzer would parse responses as requests, which would take changes
		// to proto/http.go that the spec rules out. On the local leg the
		// analyzer sees the same plaintext it always has, with zero changes,
		// which is the step's invariant ("analyzer sees plaintext, local-leg
		// plumbing reused") kept by the one honest placement of the tee.
		localConn := tunnel.Protocol.WrapConn(localConn, mvc.ConnectionContext{Tunnel: tunnel, ClientAddr: startPxy.ClientAddr})
		bytesIn, bytesOut := c.relay(localConn, remoteConn, tunnel, startPxy.ClientAddr)
		m.bytesIn.Update(bytesIn)
		m.bytesOut.Update(bytesOut)
		m.bytesInCount.Inc(bytesIn)
		m.bytesOutCount.Inc(bytesOut)
	})
	c.update()
}

// serveUdpFlow is the udp tunnel's counterpart of the dial+relay pair the
// byte-stream protocols run (SPEC-CLUSTER8 3.2). The server established one
// flow for one public client address and hands it to us as one proxy
// connection; from here on that connection carries framed datagrams
// (proto.ReadDatagramFrame / proto.WriteDatagramFrame) in both directions,
// and the local leg is a CONNECTED UDP socket toward the configured local
// service.
//
// Connectedness is the quiet half of the design: replies from the local
// service need no per-packet routing decision, and -- the security-relevant
// direction -- the socket only ever delivers datagrams from the service the
// tunnel points at, so a public client can never use the agent as a reflector
// toward a third host. The server runs the mirror-image socket toward its
// public client (SPEC-CLUSTER8 3.1) for the same reason in the other
// direction.
func (c *ClientModel) serveUdpFlow(remoteConn conn.Conn, tunnel mvc.Tunnel, clientAddr string) {
	start := time.Now()

	raddr, err := net.ResolveUDPAddr("udp", tunnel.LocalAddr)
	if err != nil {
		remoteConn.Warn("Failed to resolve private UDP leg %s: %v", tunnel.LocalAddr, err)
		remoteConn.Close()
		return
	}

	// The dial itself cannot fail because the service is down -- UDP has no
	// handshake -- so unlike the tcp path, the outcome of this call says
	// nothing about the local service, only about the local address. A dead
	// service surfaces later, as a write error (ICMP port-unreachable on the
	// connected socket), and is answered there the udp way: a quiet close.
	localConn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		remoteConn.Warn("Failed to open private UDP leg %s for client %s: %v", tunnel.LocalAddr, clientAddr, err)
		remoteConn.Close()
		return
	}

	f := &udpFlow{
		Logger:   log.NewPrefixLogger("udp"),
		remote:   remoteConn,
		local:    localConn,
		activity: make(chan struct{}, 1),
		done:     make(chan struct{}),
	}
	// One owner of the teardown, reached from every path out (either pump's
	// first error, the idle watcher, or this defer): idempotent by Once.
	defer f.teardown()

	// The same connection metrics the tcp relay feeds: the server gates and
	// counts a udp flow per connection (SPEC-CLUSTER8 3.1), so the client's
	// accounting should read the same way. Unlike the relay's byte counts --
	// which are raw copy counts, framing included -- these are datagram
	// payloads only: the framing is transport plumbing, and a metrics graph
	// that moved when the framing constant changed would be lying about the
	// tunnel's traffic.
	m := c.metrics
	m.proxySetupTimer.Update(time.Since(start))
	m.connMeter.Mark(1)
	c.update()

	// One buffer per direction, one reader per buffer, for the life of the
	// flow -- the joinBufPool rule (conn/conn.go) without the pool: a udp flow
	// is short-lived by construction (the idle expiry below), so the buffers
	// die with it instead of recycling through a pool sized for steady-state
	// copying. 128 KiB per live flow is the honest price of 64 KiB datagrams
	// in both directions.
	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		defer f.teardown()
		f.pumpProxyToLocal(make([]byte, proto.MaxDatagramSize))
	}()
	go func() {
		defer wg.Done()
		defer f.teardown()
		f.pumpLocalToProxy(make([]byte, proto.MaxDatagramSize))
	}()
	go func() {
		defer wg.Done()
		f.watchIdle()
	}()

	m.connTimer.Time(func() {
		// Both pumps must be out before this returns: the callers close
		// remoteConn on return, and a pump still parked in a read of it must
		// not outlive the close's owner. The pumps' defers run teardown before
		// wg.Done (LIFO), so by the time Wait returns, f.done is closed and
		// the watcher -- counted in the same WaitGroup -- is out too.
		wg.Wait()
	})
	bytesIn, bytesOut := f.bytesIn.Load(), f.bytesOut.Load()
	m.bytesIn.Update(bytesIn)
	m.bytesOut.Update(bytesOut)
	m.bytesInCount.Inc(bytesIn)
	m.bytesOutCount.Inc(bytesOut)
	c.update()
}

// udpFlow is one live udp flow: the server-side twin of a public client's
// address, seen from the agent as one proxy connection plus one connected
// local socket. Everything about its lifetime is Close-based -- see teardown.
type udpFlow struct {
	log.Logger

	remote conn.Conn    // the proxy leg: a stream on whatever mux carrier is up
	local  *net.UDPConn // the connected local leg

	// activity carries idle-refresh pings from the pumps to the watcher. One
	// slot, sent non-blocking, coalescing on purpose: a refresh is idempotent,
	// and a pump must never block on telling the watcher about traffic -- the
	// datagram itself is the proof of life, the ping is just the report.
	activity chan struct{}

	// done is closed by teardown; the watcher waits on it so that a flow the
	// pumps ended stops resetting a timer that no longer matters.
	done      chan struct{}
	closeOnce sync.Once

	// Payload byte counts, written by the pumps and read by serveUdpFlow after
	// wg.Wait. Atomic rather than plain because the codebase's cross-goroutine
	// counters are (model.go's lastPong), and because nothing here enforces
	// that every future reader waits first.
	bytesIn  atomic.Int64 // datagram payload, proxy -> local
	bytesOut atomic.Int64 // datagram payload, local -> proxy
}

// teardown ends the flow: both legs closed, done closed, exactly once.
//
// Close, not a read deadline, is what ends a parked pump: the proxy leg is a
// stream on an smux session or a QUIC one, and Stream.Read does not re-check
// deadlines while parked -- it samples the deadline once on entry (the
// rationale rewriter/conn.go records for the client relay, and
// terminatePublicTLS backs up with a timer that closes). A closed conn is the
// one ending every read in this program obeys, so one teardown unblocks both
// pumps whatever each is parked in.
func (f *udpFlow) teardown() {
	f.closeOnce.Do(func() {
		f.remote.Close()
		f.local.Close()
		close(f.done)
	})
}

// ping reports one datum of activity to the idle watcher. Coalesced by
// design; see udpFlow.activity.
func (f *udpFlow) ping() {
	select {
	case f.activity <- struct{}{}:
	default:
	}
}

// pumpProxyToLocal moves datagrams from the proxy leg into the local service:
// one framed datagram off the stream, one whole datagram into the socket.
// There is no reassembly and no coalescing -- the frame boundary IS the
// datagram boundary, which is the property the framing test pins
// (SPEC-CLUSTER8 6.3).
func (f *udpFlow) pumpProxyToLocal(buf []byte) {
	defer f.teardown()
	for {
		n, err := proto.ReadDatagramFrame(f.remote, buf)
		if err != nil {
			if errors.Is(err, proto.ErrDatagramTooLarge) {
				// The peer sent a frame no conforming sender produces. The
				// flow is over either way; the WARN is what tells a human the
				// close was the peer's desynchronization, not a dropped
				// session.
				f.remote.Warn("udp flow protocol error from the proxy leg, closing: %v", err)
				return
			}
			f.remote.Debug("udp flow proxy read ended: %v", err)
			return
		}
		f.ping()
		if _, err := f.local.Write(buf[:n]); err != nil {
			// The local service is gone (on a connected socket an ICMP
			// port-unreachable from an earlier datagram surfaces right here)
			// or its socket buffer is full. First failure closes the flow
			// quietly: udp is not IsHTTP and stays so -- there is no 502 page
			// a UDP caller could read, and inventing one would be the only
			// option worse than silence (SPEC-CLUSTER8 3.2).
			f.Debug("udp flow local write failed, closing: %v", err)
			return
		}
		f.bytesIn.Add(int64(n))
		f.ping()
	}
}

// pumpLocalToProxy moves datagrams from the local service into the proxy leg:
// one datagram off the connected socket, one framed datagram onto the stream.
func (f *udpFlow) pumpLocalToProxy(buf []byte) {
	defer f.teardown()
	for {
		// Read, not ReadFromUDP: the socket is connected, so the kernel
		// delivers only the local service's datagrams -- no address is
		// reported because no routing decision is left to make.
		n, err := f.local.Read(buf)
		if err != nil {
			f.Debug("udp flow local read ended: %v", err)
			return
		}
		f.ping()
		if err := proto.WriteDatagramFrame(f.remote, buf[:n]); err != nil {
			f.remote.Debug("udp flow proxy write failed, closing: %v", err)
			return
		}
		f.bytesOut.Add(int64(n))
		f.ping()
	}
}

// watchIdle closes the flow after udpIdleTimeout with no traffic in either
// direction (SPEC-CLUSTER8 3.2: the client mirrors the server's per-flow
// expiry, so both ends agree a silent flow has ended and neither half waits
// on the other to notice).
//
// The timer is owned by this goroutine alone -- Timer.Reset is only sound
// from the goroutine that drains the timer's channel -- so the pumps report
// activity on the one-slot channel instead of touching it. Both branches that
// Reset do the documented dance: Stop, and when Stop reports a fire already
// queued, drain it before Reset, so a fire is never lost (which would strand
// a live flow until the pumps end it) and never doubled (which would cut a
// live flow one window early).
func (f *udpFlow) watchIdle() {
	timer := time.NewTimer(udpIdleTimeout)
	defer timer.Stop()

	for {
		select {
		case <-f.activity:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(udpIdleTimeout)

		case <-timer.C:
			// The window closed. A ping can be sitting in the channel from
			// just before the fire -- activity that arrived inside the
			// expiring window, reported to a watcher that was not scheduled
			// in time to Reset. It counts: grant a fresh window.
			select {
			case <-f.activity:
				// The fire was consumed by this branch, so Reset is safe.
				timer.Reset(udpIdleTimeout)
			default:
				f.Debug("udp flow idle for %v, closing", udpIdleTimeout)
				f.teardown()
				return
			}

		case <-f.done:
			// The pumps ended the flow (an error, or the server closed the
			// proxy leg); teardown already ran, so there is nothing left to
			// guard.
			return
		}
	}
}

// agentTerminated reports whether THIS proxy connection's public side
// terminates in the agent (SPEC-CLUSTER5 5.3). Both conditions are needed: the
// tunnel flag rides on every leg of a mixed http+https tunnel, but only the
// https leg's connections arrive carrying TLS bytes to terminate -- the http
// leg stays edge-served exactly as before.
func (c *ClientModel) agentTerminated(tunnel mvc.Tunnel) bool {
	return tunnel.AgentTLS && strings.HasPrefix(tunnel.PublicUrl, msg.ProtoHTTPS+"://")
}

// terminatePublicTLS is step 2: wrap the proxy stream -- which the server is
// relaying as raw TLS bytes -- in tls.Server with the tunnel's per-session cert
// config, and run the handshake under the handshake deadline.
//
// The deadline follows the established convention (the server's connReadTimeout
// shape, server/http.go): set before the TLS work, cleared right after, so a
// healthy handshake is bounded and a healthy connection is not throttled by the
// deadline it survived.
//
// ok is false when the handshake failed: the connection is closed and the
// failure logged at WARN. The visitor sees a TLS alert and nothing else --
// whatever it sent, none of it reached the local upstream, which is the
// zero-knowledge property holding at the least friendly edge of the path.
// clientAddr is the visitor's address from StartProxy: the remote addr of the
// proxy stream itself is this agent's link to the server, not the client the
// handshake failed with, so the WARN names the visitor.
func (c *ClientModel) terminatePublicTLS(remoteConn conn.Conn, tunnel mvc.Tunnel, clientAddr string) (plain conn.Conn, ok bool) {
	cfg := c.agentTLSConfigFor(tunnel.PublicUrl)
	if cfg == nil {
		// Only reachable if the tunnel was established without its per-session
		// runtime (establishTunnelRuntime): a wiring bug, which is why this is
		// an Error and a close rather than an answer the visitor could read.
		remoteConn.Error("No agent TLS configuration for tunnel %s", tunnel.PublicUrl)
		remoteConn.Close()
		return nil, false
	}

	tlsConn := tls.Server(remoteConn, cfg)
	plain = conn.Wrap(tlsConn, "tls")

	// The deadline bounds the handshake, and the timer below backs it up:
	// on a TCP leg SetDeadline alone is enough (the kernel wakes a parked
	// read), but on a mux stream SetReadDeadline only stores its value -- see
	// the wake rationale in rewriter/conn.go -- so a peer that stalls
	// mid-ClientHello would park the handshake forever. Closing the conn is
	// the one ending every conn.Conn implementation obeys.
	plain.SetDeadline(time.Now().Add(agentTLSHandshakeTimeout))
	timer := time.AfterFunc(agentTLSHandshakeTimeout, func() { tlsConn.Close() })
	err := tlsConn.Handshake()
	timer.Stop()
	plain.SetDeadline(time.Time{})
	if err != nil {
		plain.Warn("TLS handshake with public client %s failed: %v", clientAddr, err)
		plain.Close()
		return nil, false
	}

	return plain, true
}

// terminationEchoError checks a NewTunnel ack against the termination mode its
// tunnel asked for (the ack's TLSTermination echo, set by the server from what
// it actually registered). nil means the ack is consistent; an error means the
// endpoint must not be served -- most importantly the old-server pairing,
// where the registration succeeded, the field was dropped in silence, and the
// only honest outcome is a refusal naming the version gap.
func terminationEchoError(publicUrl string, tunnelCfg *TunnelConfiguration, m *msg.NewTunnel) error {
	if tunnelCfg == nil || !tunnelCfg.AgentTLSTermination {
		return nil
	}
	if m.TLSTermination == msg.TLSTerminationAgent {
		return nil
	}
	return fmt.Errorf("Tunnel %s: the server did not confirm agent TLS termination "+
		"(it echoed %q; this client asked for %q). The server predates zero-knowledge TLS -- "+
		"upgrade ngrokd to 1.0.7 or later, or remove agent_tls_termination from this tunnel",
		publicUrl, m.TLSTermination, msg.TLSTerminationAgent)
}

// writeBadGateway writes the HTTP/1.0 502 page for a dead upstream. It is the
// inline spelling the edge path has always used, extracted so that the
// agent-terminated path (SPEC-CLUSTER5 5.3 step 3) sends byte-for-byte the same
// answer over its terminated connection -- the destination differs, the page
// does not.
func (c *ClientModel) writeBadGateway(dst conn.Conn, tunnel mvc.Tunnel) {
	// try to be helpful when you're in HTTP mode and a human might see the output
	badGatewayBody := fmt.Sprintf(BadGateway, tunnel.PublicUrl, tunnel.LocalAddr, tunnel.LocalAddr)
	dst.Write([]byte(fmt.Sprintf(`HTTP/1.0 502 Bad Gateway
Content-Type: text/html
Content-Length: %d

%s`, len(badGatewayBody), badGatewayBody)))
}

// establishTunnelRuntime builds the per-session state serving a tunnel needs
// beyond its mvc.Tunnel, when the tunnel is established (msg.NewTunnel):
//
//   - for an agent-terminated tunnel, the tls.Config that will terminate its
//     public side (tlsagent.go). Built per session on purpose: the ephemeral
//     cert model is one certificate per session, and re-reading the configured
//     files here means a certificate rotated on disk is picked up at the next
//     reconnect without restarting the client. Everything that can be wrong
//     with the files was already refused at load time (validateAgentTLS), so an
//     error here is a file that changed under us.
//   - for a tunnel with a traffic policy, the policy compiled client-side with
//     the same policy package call the server's Tunnel.join uses. On an
//     edge-terminated tunnel the map entry sits unused -- the server runs those
//     phases, and attachPolicyHooks only consults the map for agent-terminated
//     tunnels. (on_tcp_connect is NOT in this story: it stays server-side for
//     every tunnel -- it runs at accept time, before any proxy conn exists, so
//     an agent could not evaluate it at all. That is the phase split of
//     SPEC-CLUSTER5 5.3 step 6.)
func (c *ClientModel) establishTunnelRuntime(publicUrl string, tunnelCfg *TunnelConfiguration) error {
	if tunnelCfg == nil {
		return nil
	}

	if tunnelCfg.AgentTLSTermination {
		// Only the https leg terminates here. A mixed tunnel registers one
		// leg per protocol, both carrying the flag; building (and, for the
		// ephemeral model, minting and warning about) a session config for the
		// http leg would be runtime nothing can ever reach, because
		// agentTerminated requires the https scheme too.
		if strings.HasPrefix(publicUrl, msg.ProtoHTTPS+"://") {
			cfg, err := agentTLSConfig(tunnelCfg)
			if err != nil {
				return err
			}
			c.setAgentTLSConfig(publicUrl, cfg)
		}
	}

	if tunnelCfg.TrafficPolicy != nil {
		compiled, err := tunnelCfg.TrafficPolicy.Compile()
		if err != nil {
			// The policy was validated at load and compiled by the server at
			// registration (it answered NewTunnel, not an error), so this is
			// "the same document stopped compiling here": report it with the
			// URL, loudly, rather than serve an unpoliced tunnel.
			return fmt.Errorf("traffic policy failed to compile: %v", err)
		}
		c.setCompiledPolicy(publicUrl, compiled)
	}

	return nil
}

// Per-URL accessors for the runtime maps. The setters lazy-init so that a
// zero-value ClientModel (the tests build several) stores without a panic; the
// getters read a nil map as "not set", which every caller already handles.

func (c *ClientModel) setAgentTLSConfig(publicUrl string, cfg *tls.Config) {
	c.agentTLSMu.Lock()
	defer c.agentTLSMu.Unlock()
	if c.agentTLS == nil {
		c.agentTLS = make(map[string]*tls.Config)
	}
	c.agentTLS[publicUrl] = cfg
}

func (c *ClientModel) agentTLSConfigFor(publicUrl string) *tls.Config {
	c.agentTLSMu.Lock()
	defer c.agentTLSMu.Unlock()
	return c.agentTLS[publicUrl]
}

func (c *ClientModel) setCompiledPolicy(publicUrl string, compiled *policy.Compiled) {
	c.tunnelPoliciesMu.Lock()
	defer c.tunnelPoliciesMu.Unlock()
	if c.tunnelPolicies == nil {
		c.tunnelPolicies = make(map[string]*policy.Compiled)
	}
	c.tunnelPolicies[publicUrl] = compiled
}

func (c *ClientModel) compiledPolicyFor(publicUrl string) *policy.Compiled {
	c.tunnelPoliciesMu.Lock()
	defer c.tunnelPoliciesMu.Unlock()
	return c.tunnelPolicies[publicUrl]
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

	// SPEC-CLUSTER5 5.3 step 5: on an agent-terminated tunnel this client,
	// not the server, runs the endpoint's traffic policy http phases -- the
	// server has only ciphertext at its end of these tunnels. The hooks are
	// merged into the same rewriter.Policy that carries the header and
	// compression semantics, so a policy with phases and a tunnel with header
	// settings act on one stream, in the rewriter's own order (hooks first,
	// then the fixed headers -- see package rewriter). Tunnels without an
	// https-agent flag keep the server-side split and get nothing here.
	c.attachPolicyHooks(tunnel, clientAddr, policy)

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

// attachPolicyHooks merges a tunnel's compiled traffic policy http phases into
// the connection's rewrite policy -- on an agent-terminated tunnel only.
//
// The split is the one SPEC-CLUSTER5 5.3 step 6 fixes in place: on_tcp_connect
// stays server-side for every tunnel (it evaluates at accept time, before any
// proxy conn exists, so the agent never sees a connection the phase would have
// refused), while on_http_request / on_http_response move to the agent for
// agent-terminated tunnels, because the server never has plaintext to run them
// on. The hooks are built per connection -- they hold that connection's policy
// vars -- with the same policy package API the server uses in Tunnel.join
// (Compiled.RequestHook / Compiled.ResponseHook), and they are merged with, not
// instead of, the tunnel's header and compression policy: the rewriter applies
// a verdict's headers and the fixed headers to the same head.
//
// On an edge-terminated tunnel this does nothing on purpose: the server runs
// the phases there, and running them here too would apply every action twice.
// With no compiled policy, or a policy with no http phases, both hooks come
// back nil and the rewriter behaves exactly as today.
func (c *ClientModel) attachPolicyHooks(tunnel mvc.Tunnel, clientAddr string, p *rewriter.Policy) {
	if p == nil || !c.agentTerminated(tunnel) {
		return
	}

	compiled := c.compiledPolicyFor(tunnel.PublicUrl)
	if compiled == nil {
		return
	}

	// c carries the log.Logger the policy's log actions and fail-open warnings
	// are written through, and clientAddr is what conn.client_ip /
	// conn.remote_addr report -- the same value the server passes on this
	// path's edge twin (the public connection's remote address).
	p.RequestHook = compiled.RequestHook(c, clientAddr)
	p.ResponseHook = compiled.ResponseHook(c, clientAddr)
	// The agent-side twin of the server's join wiring (SPEC 10 §3): a policy
	// whose request phase consumes the body gets the rewriter's deferred
	// verdict + bounded buffering here too, so agent-terminated tunnels
	// enforce webhook verification identically to edge-terminated ones.
	p.BodyBufferCap = compiled.RequestBodyCap()
}

// streamCarrier is the transport a mux session runs on (SPEC-CLUSTER7 5): the
// one long-lived connection every proxy stream travels on. Before QUIC there
// was exactly one -- an smux session on a TCP+TLS conn -- and the machinery
// around it (the watchdog, the backoff, the publish/replace protocol) never
// needed to know that. This interface is that ignorance made explicit: the
// carrier opens and accepts net.Conn streams, closes as a whole, and can be
// asked whether it is already dead. Everything else about a carrier -- how
// frames travel, how keepalives are kept, how a dead peer is noticed -- is the
// adapter's business, below.
//
// The failure semantics are the part the callers lean on, so they are the
// contract, not implementation detail: when the carrier dies (peer gone,
// transport timeout, keepalive given up), AcceptStream returns an error and
// IsClosed turns true -- and every stream the carrier handed out fails, the
// way a dropped TCP conn fails, which is what unwinds the relays built on
// them.
type streamCarrier interface {
	// OpenStream opens one stream of the session. This side of the protocol
	// opens every proxy stream; the server only ever accepts them.
	OpenStream() (net.Conn, error)

	// AcceptStream blocks until the peer opens a stream (a protocol surprise:
	// nothing in this protocol has the server opening streams) or the session
	// dies, in which case it returns the error. It is the death watch of the
	// session -- the earliest signal either end has that the transport is
	// gone.
	AcceptStream() (net.Conn, error)

	// Close tears the carrier down: every stream on it fails and the
	// underlying transport goes away, which also unblocks AcceptStream. It
	// must be safe to call more than once (the watchdog and the dying session
	// itself both get there).
	Close() error

	// IsClosed reports whether the session is already dead. The muxSession()
	// accessor reads it so that a ReqProxy answered in the window between a
	// session dying and the watchdog noticing dials a conn instead of opening
	// a stream that cannot work.
	IsClosed() bool
}

// smuxCarrier is the original carrier (SPEC cluster 3, 3.1): an smux session
// client on a TCP+TLS conn. Its behavior is the one streamCarrier's contract
// was written down from -- Close the session and the conn under it, in that
// order, which is the order muxSession.Close has always used.
type smuxCarrier struct {
	// conn is the TCP+TLS conn the smux frames travel on. The smux session
	// closes it when it closes, but explicitly closing it here as well is the
	// belt the watchdog has always worn: smux's close path has never been the
	// thing the client's correctness leans on.
	conn conn.Conn
	sess *smux.Session
}

func (c *smuxCarrier) OpenStream() (net.Conn, error) {
	// *smux.Stream is a net.Conn (it completes the addresses from the conn the
	// session runs on), so it goes up the stack as-is.
	return c.sess.OpenStream()
}

func (c *smuxCarrier) AcceptStream() (net.Conn, error) {
	return c.sess.AcceptStream()
}

// Close closes the session first -- that is what fails every stream and
// unblocks the accept half -- and then the conn underneath. Both errors are
// dropped on purpose: this runs on the death path, where the session is
// already on its way out, and every caller of streamCarrier.Close treats the
// errors as noise.
func (c *smuxCarrier) Close() error {
	_ = c.sess.Close()
	_ = c.conn.Close()
	return nil
}

func (c *smuxCarrier) IsClosed() bool {
	return c.sess.IsClosed()
}

// quicCarrier is the QUIC carrier (SPEC-CLUSTER7 5): one QUIC connection over
// UDP, every proxy stream a QUIC bidirectional stream on it. The point of the
// carrier is what QUIC does under the streams: packet loss on one stream no
// longer head-of-line blocks the others, which on the smux carrier is exactly
// what one lost TCP segment does to every multiplexed proxy connection at
// once.
type quicCarrier struct {
	conn *quic.Conn
}

func (c *quicCarrier) OpenStream() (net.Conn, error) {
	stream, err := c.conn.OpenStream()
	if err != nil {
		return nil, err
	}
	return newQuicStreamConn(stream, c.conn), nil
}

// AcceptStream is the carrier's death watch, and the context it runs under is
// the connection's own: quic.Conn.Context is cancelled when the
// connection dies (idle timeout, keepalive given up, peer closed, transport
// error), so a dead session unblocks the accept by itself -- the same "AcceptStream
// returns when the session dies" behavior the smux carrier gets from its
// library -- without this adapter owning a goroutine or a timer of its own.
func (c *quicCarrier) AcceptStream() (net.Conn, error) {
	stream, err := c.conn.AcceptStream(c.conn.Context())
	if err != nil {
		return nil, err
	}
	return newQuicStreamConn(stream, c.conn), nil
}

// CloseWithError is QUIC's only whole-connection close, and it is the right
// shape: one call ends every stream at once, which is the fan-out closing an
// smux session has. The application error code is ours to choose -- both ends
// run this protocol -- and the reason string is for the peer's log.
func (c *quicCarrier) Close() error {
	return c.conn.CloseWithError(quicSessionCloseCode, "closing mux session")
}

func (c *quicCarrier) IsClosed() bool {
	select {
	case <-c.conn.Context().Done():
		return true
	default:
		return false
	}
}

// QUIC error codes. The stream code ends a single stream's receive side, the
// session code closes a whole carrier; both are private to this protocol, so
// zero (with the reason strings doing the explaining) is as good as any
// registry entry either end could have disagreed about.
const (
	quicStreamResetCode  quic.StreamErrorCode      = 0
	quicSessionCloseCode quic.ApplicationErrorCode = 0
)

// quicStreamConn adapts a quic.Stream to net.Conn.
//
// Two differences between the two types are the reason this exists:
//
//   - a quic.Stream has no LocalAddr/RemoteAddr -- those live on the
//     connection -- and net.Conn requires them. The adapter carries the
//     connection's addresses so that conn.Wrap (and every log line that
//     renders a conn) works on a stream exactly as it does on an smux stream,
//     which fills the addresses in from the conn its session runs on.
//   - quic.Stream.Close only finishes the SEND side (a FIN); the receive side
//     stays open until the peer closes its end. "Closed" has to mean more than
//     that here: conn.Join closes a conn to unwind the relay, and a receive
//     side that outlives the close would leave a read parked on a conn the
//     rest of the program believes is dead -- smux's Close kills the whole
//     stream, and the unwinding depends on it. So Close also cancels the
//     receive side, which is what makes the peer's writes to this stream fail
//     immediately. Neither half is an error to repeat (the library no-ops
//     them), so Close stays idempotent the way conn.Conn users expect.
type quicStreamConn struct {
	*quic.Stream
	local  net.Addr
	remote net.Addr
}

func newQuicStreamConn(stream *quic.Stream, qconn *quic.Conn) *quicStreamConn {
	return &quicStreamConn{
		Stream: stream,
		local:  qconn.LocalAddr(),
		remote: qconn.RemoteAddr(),
	}
}

func (c *quicStreamConn) LocalAddr() net.Addr  { return c.local }
func (c *quicStreamConn) RemoteAddr() net.Addr { return c.remote }

func (c *quicStreamConn) Close() error {
	c.Stream.CancelRead(quicStreamResetCode)
	return c.Stream.Close()
}

// muxSession is the client's end of one multiplexed proxy connection (SPEC
// cluster 3, 3.1): a single carrier conn to the server carrying every proxy
// stream, instead of one conn per proxy connection.
//
// The session is a shared failure domain -- if it dies, every stream on it dies
// with it -- so nothing but proxy streams travels over it, and the watchdog
// below is what makes that acceptable: streams that die mid-flight fail closed,
// unwinding their joins exactly as a dropped dialed conn does, and a new
// session is brought up behind them. Since SPEC-CLUSTER7 the carrier may be
// QUIC (streamCarrier): the watchdog, the backoff and the publish protocol
// below are the same code for both, because they never looked at the
// transport in the first place.
type muxSession struct {
	log.Logger

	// sess is the carrier the session runs on. The field keeps the name it had
	// when the only carrier was smux: watch(), Close() and the muxSession()
	// accessor read it, and after the generalization they are the same three
	// lines they always were -- only the type got wider.
	sess streamCarrier

	// transport names the carrier for logs and tests ("smux" or "quic"); it is
	// what tells a reader of the log (and the e2e) which transport actually
	// carried the session.
	transport string

	// when the session was established, which is what tells a flaky transport
	// (it lived, then died) from one that never worked (it died at once)
	established time.Time

	// done is closed once the session is known to be dead; the watchdog waits
	// on it to know when to reconnect
	done      chan struct{}
	closeOnce sync.Once
}

// newMuxSession wraps an established carrier and starts the goroutine that
// turns its death into a closed done channel.
func newMuxSession(carrier streamCarrier, transport string) *muxSession {
	m := &muxSession{
		Logger:      log.NewPrefixLogger("mux"),
		sess:        carrier,
		transport:   transport,
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
// when either end closes the session, when the transport dies, or when the
// carrier's keepalive gives up on a peer that stopped answering. Nothing else
// here would notice any of those before the next stream is attempted.
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

	// Closing the carrier is what fails the streams and closes the transport
	// underneath; errors from it are noise, because the session is already on
	// its way out when AcceptStream returns.
	m.Close()
}

// Close tears the session down: every stream on it fails and the transport
// goes away, which is also what unblocks watch() and closes done.
func (m *muxSession) Close() {
	m.closeOnce.Do(func() {
		// The carrier owns everything the session used to close piecewise --
		// for smux the session and the TCP conn under it, for QUIC the
		// connection and every stream with it -- so one call is the whole
		// teardown.
		_ = m.sess.Close()
	})
}

// muxConfig is the smux configuration for the client side of a mux session.
//
// The library defaults are kept -- 4 MiB receive window, 64 KiB per-stream
// buffer -- except the two session-keeping values, which are pinned from the
// carrier-wide consts (carrierKeepAlivePeriod, carrierMaxIdleTimeout) instead
// of left as the library defaults they happen to equal: that is what makes
// "both carriers keep a session alive on the same clock" a property of one
// source of truth rather than a coincidence of two defaults (SPEC-CLUSTER7 5).
// The keepalive is load-bearing here: it is what turns a server that vanished
// silently into a dead session, and therefore into a reconnected one, without
// waiting for a stream to be attempted.
func muxConfig() *smux.Config {
	cfg := smux.DefaultConfig()
	cfg.KeepAliveInterval = carrierKeepAlivePeriod
	cfg.KeepAliveTimeout = carrierMaxIdleTimeout
	return cfg
}

// quicConfig is the QUIC transport configuration for the client side of a
// carrier session (SPEC-CLUSTER7 5). There are deliberately no configuration
// knobs behind it: the keepalives are the shared carrier consts, and the
// stream budgets mirror the server's listener. What each field is for:
//
//   - KeepAlivePeriod/MaxIdleTimeout are the QUIC counterparts of smux's
//     keepalive ping and its give-up timeout (see muxConfig for why they are
//     load-bearing).
//   - MaxIncomingStreams mirrors the server's cap; the server opens no
//     streams, so this states the symmetric budget rather than a working
//     limit.
//   - MaxIncomingUniStreams refuses unidirectional streams outright: the
//     protocol opens none, and the negative value is the only spelling
//     quic-go reads as "none" (zero means the library default, 100).
//   - HandshakeIdleTimeout bounds the dial (see quicHandshakeTimeout).
func quicConfig() *quic.Config {
	return &quic.Config{
		KeepAlivePeriod:       carrierKeepAlivePeriod,
		MaxIdleTimeout:        carrierMaxIdleTimeout,
		MaxIncomingStreams:    quicMaxIncomingStreams,
		MaxIncomingUniStreams: -1,
		HandshakeIdleTimeout:  quicHandshakeTimeout,
	}
}

// quicTransportAllowed reports whether the current attempt may try the QUIC
// carrier: the configuration must not have resolved to TCP (proxy_transport
// tcp, or the http_proxy override that newClientModel applied), and the
// current control session's AuthResp must have advertised
// msg.QuicCapability. The capability half is the compatibility rule of
// SPEC-CLUSTER7 3: a server whose QUIC listener is down -- or that predates
// the feature entirely -- is never dialed over UDP, whatever the config asks
// for, and "quic" degrades to the smux path for exactly that reason.
func (c *ClientModel) quicTransportAllowed() bool {
	if c.proxyTransport == proxyTransportTCP {
		return false
	}
	return c.quicPeerCap.Load()
}

// dialSession establishes one mux session on the best carrier available for
// this attempt (SPEC-CLUSTER7 5): QUIC when the configuration allows it and
// the server advertised the capability, the smux path otherwise -- including
// immediately after a failed QUIC dial, which falls through to the smux dial
// inside the same watchdog attempt cycle rather than spending an attempt of
// its own. A QUIC dial failure is a fallback signal, not a condition to
// retry: an ALPN mismatch is an old server on that port, an unreachable UDP
// path is a middlebox or a firewall, and neither improves by being dialed
// twice in a row. The next attempt prefers QUIC again, and the give-up
// arithmetic (which counts failed attempts, not carriers) never sees the QUIC
// leg on its own.
func (c *ClientModel) dialSession() (*muxSession, error) {
	if c.quicTransportAllowed() {
		sess, err := c.dialQuicSession()
		if err == nil {
			return sess, nil
		}
		c.Info("QUIC session dial failed (%v); using the TCP mux path for this attempt", err)
	}
	return c.dialMuxSession()
}

// dialQuicSession establishes one QUIC carrier to the server: dial it with the
// model's TLS configuration (the same TrustHostRootCerts / embedded CA /
// NGROK_INSECURE_SKIP_VERIFY decision the control channel made -- only the
// ALPN is added, cloned rather than mutated so the control conn's config is
// untouched), declare the session by carrying RegMux on the first stream, and
// hand the connection to the mux machinery as the carrier.
//
// The address is the server address, UDP side: the QUIC listener is expected
// on the same host and port the TCP server runs on (a port number is two
// independent bindings, one per protocol). There is no advertisement channel
// for a different address -- AuthResp carries a capability, not an endpoint --
// so an operator running QUIC elsewhere has nothing to point this client at,
// and the honest state is that the capability then stays off.
//
// RegMux over the first stream is the same session bind the smux path makes on
// the raw conn before smux takes over: same message, same credentials, same
// server-side refusal (an unknown client or a wrong secret gets the conn
// closed, which shows up here as a session that dies at once, handled like any
// other mux failure). The registration stream is closed once the message is
// away -- the server retires its end right after reading it, and a stream
// retired on both ends does not sit on the session's stream budget for the
// session's life.
func (c *ClientModel) dialQuicSession() (*muxSession, error) {
	// http_proxy cannot reach this line (the constructor resolves it to TCP),
	// which is load-bearing: quic.DialAddr opens UDP directly and would skip a
	// configured CONNECT proxy in silence, sending traffic somewhere the
	// operator explicitly routed away from.
	//
	// A nil tls.Config means what it means on the TCP path (conn.Dial skips
	// StartTLS for one): library defaults. QUIC has no un-TLS'd mode, so the
	// nil is substituted, never skipped -- and defaults verify the server
	// certificate, which is exactly the fallback signal against a server this
	// client does not trust.
	tlsCfg := &tls.Config{}
	if c.tlsConfig != nil {
		tlsCfg = c.tlsConfig.Clone()
	}
	tlsCfg.NextProtos = []string{quicALPN}

	qconn, err := quic.DialAddr(context.Background(), c.serverAddr, tlsCfg, quicConfig())
	if err != nil {
		return nil, fmt.Errorf("QUIC dial to %s failed: %v", c.serverAddr, err)
	}

	// RegMux carries the session's credentials like RegProxy does (see
	// dialMuxSession): attaching a mux session to a client id means every
	// stream on it is a proxy connection for that client's tunnels.
	stream, err := qconn.OpenStream()
	if err != nil {
		qconn.CloseWithError(quicSessionCloseCode, "failed to open the registration stream")
		return nil, fmt.Errorf("failed to open the QUIC registration stream: %v", err)
	}
	regConn := conn.Wrap(newQuicStreamConn(stream, qconn), "mux")
	if err = msg.WriteMsg(regConn, &msg.RegMux{ClientId: c.id, Secret: c.sessionSecretValue()}); err != nil {
		regConn.Close()
		qconn.CloseWithError(quicSessionCloseCode, "failed to register the session")
		return nil, fmt.Errorf("failed to write RegMux on the QUIC session: %v", err)
	}
	// The bind stream's only job is done: retire it (both directions) so it
	// stops counting against the session's stream budget. Nothing in the
	// protocol reads or writes it again.
	regConn.Close()

	return newMuxSession(&quicCarrier{conn: qconn}, carrierQuic), nil
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

	return newMuxSession(&smuxCarrier{conn: muxConn, sess: sess}, carrierSmux), nil
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

		// dialSession picks the carrier for this attempt (QUIC first when
		// allowed, the smux path otherwise or after a failed QUIC dial) -- the
		// watchdog's counting, backoff and give-up below are the same for both,
		// because a failed attempt is a failed attempt whatever it failed on.
		newSess, err := c.dialSession()
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
		c.Info("Mux session established with %v (%s carrier)", c.serverAddr, sess.transport)
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
