package server

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"ngrok/conn"
	log "ngrok/log"
	"ngrok/msg"
	"ngrok/policy"
	"ngrok/util"
	"os"
	"os/signal"
	"runtime/debug"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"
)

const (
	registryCacheSize uint64        = 1024 * 1024 // 1 MB
	connReadTimeout   time.Duration = 10 * time.Second
)

// GLOBALS
var (
	tunnelRegistry  *TunnelRegistry
	controlRegistry *ControlRegistry

	// XXX: kill these global variables - they're only used in tunnel.go for constructing forwarding URLs
	opts      *Options
	listeners map[string]*conn.Listener
	adminSrv  *http.Server

	authLimiter   *ipRateLimiter
	publicLimiter atomic.Pointer[ipRateLimiter]
	connLimiter   atomic.Pointer[ipConnLimiter]
	warnSampler   *logSampler
)

// NewProxy attaches a dialed proxy connection to the control session it names.
//
// A proxy connection is the transport that carries a public connection's bytes
// to an agent, so attaching one to a session means handing that session's
// traffic to whoever opened the conn. The RegProxy names the session with a
// client id -- a public value -- and proves it with the session secret minted
// in AuthResp, which is the actual authentication of this path.
//
// Deliberately, a conn that fails the check is closed rather than kept: an old
// client that does not send a secret is refused here exactly like an impostor,
// because from this side the two are indistinguishable and only one of them is
// safe to serve. That is the upgrade requirement stated in msg.Auth.Secret.
func NewProxy(pxyConn conn.Conn, regPxy *msg.RegProxy) {
	// fail gracefully if the proxy connection fails to register
	defer func() {
		if r := recover(); r != nil {
			pxyConn.Warn("Failed with error: %v", r)
			pxyConn.Close()
		}
	}()

	// set logging prefix
	pxyConn.SetType("pxy")

	// look up the control connection for this proxy
	pxyConn.Info("Registering new proxy for %s", regPxy.ClientId)
	ctl := controlRegistry.Get(regPxy.ClientId)

	if ctl == nil {
		pxyConn.Warn("No client found for identifier: %s", regPxy.ClientId)
		pxyConn.Close()
		return
	}

	if !secretMatches(ctl.secret, regPxy.Secret) {
		pxyConn.Warn("Rejecting proxy connection for %s: invalid session secret", regPxy.ClientId)
		pxyConn.Close()
		return
	}

	ctl.RegisterProxy(pxyConn)
}

// Listen for incoming control and proxy connections
// We listen for incoming control and proxy connections on the same port
// for ease of deployment. The hope is that by running on port 443, using
// TLS and running all connections over the same port, we can bust through
// restrictive firewalls.
func tunnelListener(addr string, tlsConfig *tls.Config) *conn.Listener {
	// listen for incoming connections
	listener, err := conn.Listen(addr, "tun", tlsConfig)
	if err != nil {
		panic(err)
	}

	log.Info("Listening for control and proxy connections on %s", listener.Addr.String())
	go func() {
		for c := range listener.Conns {
			go func(tunnelConn conn.Conn) {
				// don't crash on panics
				defer func() {
					if r := recover(); r != nil {
						tunnelConn.Info("tunnelListener failed with error %v: %s", r, debug.Stack())
					}
				}()

				tunnelConn.SetReadDeadline(time.Now().Add(connReadTimeout))
				var rawMsg msg.Message
				if rawMsg, err = msg.ReadMsg(tunnelConn); err != nil {
					tunnelConn.Warn("Failed to read message: %v", err)
					tunnelConn.Close()
					return
				}

				// don't timeout after the initial read, tunnel heartbeating will kill
				// dead connections
				tunnelConn.SetReadDeadline(time.Time{})

				switch m := rawMsg.(type) {
				case *msg.Auth:
					ip := remoteIP(tunnelConn.RemoteAddr())
					if !authLimiter.allow(ip) {
						atomic.AddUint64(&rateDropCount, 1)
						observe.events.publishRateLimitDrop(scopeAuth, ip)
						if warnSampler.allow("auth-rate:" + ip) {
							tunnelConn.Warn("Rate-limited auth attempt from %s", ip)
						}
						tunnelConn.Close()
						return
					}
					NewControl(tunnelConn, m)

				case *msg.RegProxy:
					NewProxy(tunnelConn, m)

				case *msg.RegMux:
					// A client that multiplexes its proxy connections (SPEC
					// 3.1) announces that on a fresh conn, exactly like a
					// control or a proxy conn would; from here on the conn
					// carries smux frames instead of messages.
					NewMux(tunnelConn, m)

				default:
					tunnelConn.Close()
				}
			}(c)
		}
	}()

	return listener
}

// installOIDCSessionKey installs the configured oidc_session_key, if the
// operator set one (SPEC-CLUSTER18 4). An empty value is "not configured"
// and is a no-op: the policy package then generates a random key at first
// use and logs that itself, which is the zero-config default (sessions die
// with the process). A configured key shorter than the package's floor is a
// startup error naming the minimum -- a weak signing key is not something to
// default into serving.
func installOIDCSessionKey(key string) error {
	if key == "" {
		return nil
	}
	return policy.SetOIDCSessionKey([]byte(key))
}

func Main() {
	// parse options
	opts = parseArgs()
	if err := validateOptions(opts); err != nil {
		panic(err)
	}
	msg.SetMaxMessageSize(opts.maxMsgBytes)

	// init logging
	log.LogTo(opts.logto, opts.loglevel, opts.logformat)

	// The oidc session key installs before any listener (and so before any
	// tunnel registration): a key installed later would invalidate every
	// flow and session cookie an endpoint had already minted under the
	// generated one.
	if err := installOIDCSessionKey(opts.oidcSessionKey); err != nil {
		panic(err)
	}

	// seed random number generator
	seed, err := util.RandomSeed()
	if err != nil {
		panic(err)
	}
	util.InitGlobalRand(seed)

	// init tunnel/control registry
	registryCacheFile := os.Getenv("REGISTRY_CACHE_FILE")
	tunnelRegistry = NewTunnelRegistry(registryCacheSize, registryCacheFile)
	controlRegistry = NewControlRegistry()
	authLimiter = newIPRateLimiter(opts.authRate, time.Minute)
	publicLimiter.Store(newIPRateLimiter(opts.publicRate, time.Second))
	connLimiter.Store(newIPConnLimiter(opts.maxConnPerIP))
	warnSampler = newLogSampler(30 * time.Second)

	// Event export (SPEC-CLUSTER9 §4): start the configured destinations
	// before any listener, so the first tunnel_open already has somewhere to
	// go. With no event_destinations in the config this is a no-op and the
	// event stream behaves exactly as before.
	startEventExport(opts.eventDestinations)

	// start listeners
	listeners = make(map[string]*conn.Listener)

	// load tls configuration
	tlsConfig, err := LoadTLSConfig(opts.tlsCrt, opts.tlsKey)
	if err != nil {
		panic(err)
	}
	if opts.tlsCrt == "" || opts.tlsKey == "" {
		log.Warn("Using embedded development TLS certificate/key; do not use this configuration in production")
	}

	// listen for http
	if opts.httpAddr != "" {
		listeners[msg.ProtoHTTP] = startHttpListener(opts.httpAddr, nil)
	}

	// listen for https
	if opts.httpsAddr != "" {
		listeners[msg.ProtoHTTPS] = startHttpListener(opts.httpsAddr, tlsConfig)
	}

	// ngrok clients
	listeners["tunnel"] = tunnelListener(opts.tunnelAddr, tlsConfig)

	// QUIC proxy sessions (SPEC cluster 7): opt-in, via -quicAddr / quic_addr.
	// The default -- empty -- leaves the default footprint (one TCP port)
	// unchanged and keeps msg.QuicCapability out of AuthResp, so clients keep
	// the smux transport. The flag is what the capability advertisement
	// reads, so it is set only once the listener is really accepting.
	var quicLn *quic.Listener
	if opts.quicAddr != "" {
		var err error
		if quicLn, err = startQuicListener(opts.quicAddr, tlsConfig); err != nil {
			panic(err)
		}
		quicServing.Store(true)
		log.Info("Listening for QUIC proxy sessions on %s", quicLn.Addr())
	}

	if opts.adminAddr != "" {
		log.Info("Starting admin server on %s", opts.adminAddr)
		adminSrv = startAdminServer(opts.adminAddr, opts.enablePprof, parseAdminAuth(opts.adminAuth, opts.adminToken), opts.adminRate)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh
	log.Info("Shutdown signal received")

	for _, l := range listeners {
		_ = l.Close()
	}
	// Closing the QUIC listener unblocks its accept loop and closes every
	// session it accepted; the process is exiting either way, but the accept
	// goroutine should not outlive the shutdown that closed everything else.
	if quicLn != nil {
		_ = quicLn.Close()
	}
	if adminSrv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := adminSrv.Shutdown(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Warn("Failed to close admin server: %v", err)
		}
	}
}
