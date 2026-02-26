package server

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"ngrok/conn"
	log "ngrok/log"
	"ngrok/msg"
	"ngrok/util"
	"os"
	"os/signal"
	"runtime/debug"
	"sync/atomic"
	"syscall"
	"time"
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
	publicLimiter *ipRateLimiter
	connLimiter   *ipConnLimiter
	warnSampler   *logSampler
)

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
		panic("No client found for identifier: " + regPxy.ClientId)
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
						observe.events.publish(map[string]interface{}{"type": "rate_limit_drop", "scope": "auth", "ip": ip, "at": time.Now().UTC()})
						if warnSampler.allow("auth-rate:" + ip) {
							tunnelConn.Warn("Rate-limited auth attempt from %s", ip)
						}
						tunnelConn.Close()
						return
					}
					NewControl(tunnelConn, m)

				case *msg.RegProxy:
					NewProxy(tunnelConn, m)

				default:
					tunnelConn.Close()
				}
			}(c)
		}
	}()

	return listener
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
	publicLimiter = newIPRateLimiter(opts.publicRate, time.Second)
	connLimiter = newIPConnLimiter(opts.maxConnPerIP)
	warnSampler = newLogSampler(30 * time.Second)

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
		listeners["http"] = startHttpListener(opts.httpAddr, nil)
	}

	// listen for https
	if opts.httpsAddr != "" {
		listeners["https"] = startHttpListener(opts.httpsAddr, tlsConfig)
	}

	// ngrok clients
	listeners["tunnel"] = tunnelListener(opts.tunnelAddr, tlsConfig)

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
	if adminSrv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := adminSrv.Shutdown(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Warn("Failed to close admin server: %v", err)
		}
	}
}
