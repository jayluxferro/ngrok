package server

import (
	"crypto/tls"
	"fmt"
	vhost "github.com/inconshreveable/go-vhost"
	//"net"
	"ngrok/conn"
	"ngrok/log"
	"strings"
	"sync/atomic"
	"time"
)

const (
	NotAuthorized = `HTTP/1.0 401 Not Authorized
WWW-Authenticate: Basic realm="ngrok"
Content-Length: 23

Authorization required
`

	NotFound = `HTTP/1.0 404 Not Found
Content-Length: %d

Tunnel %s not found
`

	BadRequest = `HTTP/1.0 400 Bad Request
Content-Length: 12

Bad Request
`

	BadGateway = `HTTP/1.0 502 Bad Gateway
Content-Length: %d

%s`
)

// respondBadGateway refuses a public connection whose forward_to chain cannot
// be resolved (SPEC 3.3): the target is offline, the chain loops, or it is
// longer than we follow. The reason travels to the client verbatim and is
// logged at the edge, so a broken chain is never a silent 404 or a dropped
// connection.
func respondBadGateway(c conn.Conn, err error) {
	c.Warn("Refusing connection: %v", err)

	body := fmt.Sprintf("Bad Gateway: %v\n", err)
	c.Write([]byte(fmt.Sprintf(BadGateway, len(body), body)))
}

// Listens for new http(s) connections from the public internet
func startHttpListener(addr string, tlsCfg *tls.Config) (listener *conn.Listener) {
	// bind/listen for incoming connections
	var err error
	if listener, err = conn.Listen(addr, "pub", tlsCfg); err != nil {
		panic(err)
	}

	proto := "http"
	if tlsCfg != nil {
		proto = "https"
	}

	log.Info("Listening for public %s connections on %v", proto, listener.Addr.String())
	go func() {
		for conn := range listener.Conns {
			go httpHandler(conn, proto)
		}
	}()

	return
}

// Handles a new http connection from the public internet
func httpHandler(c conn.Conn, proto string) {
	defer c.Close()
	defer func() {
		// recover from failures
		if r := recover(); r != nil {
			c.Warn("httpHandler failed with error %v", r)
		}
	}()

	// Make sure we detect dead connections while we decide how to multiplex
	c.SetDeadline(time.Now().Add(connReadTimeout))
	ip := remoteIP(c.RemoteAddr())
	if !publicLimiter.allow(ip) {
		atomic.AddUint64(&rateDropCount, 1)
		observe.events.publish(map[string]interface{}{"type": "rate_limit_drop", "scope": "public_http", "ip": ip, "at": time.Now().UTC()})
		if warnSampler.allow("public-rate:" + ip) {
			log.Warn("Rate-limited public request from %s", ip)
		}
		c.Write([]byte(BadRequest))
		return
	}
	if !connLimiter.acquire(ip) {
		observe.events.publish(map[string]interface{}{"type": "connection_cap_drop", "scope": "public_http", "ip": ip, "at": time.Now().UTC()})
		if warnSampler.allow("public-cap:" + ip) {
			log.Warn("Connection cap reached for %s", ip)
		}
		c.Write([]byte(BadRequest))
		return
	}
	defer connLimiter.release(ip)
	incPublicConns()
	defer decPublicConns()

	// multiplex by extracting the Host header, the vhost library
	vhostConn, err := vhost.HTTP(c)
	if err != nil {
		c.Warn("Failed to read valid %s request: %v", proto, err)
		c.Write([]byte(BadRequest))
		return
	}

	// read out the Host header and auth from the request
	host := strings.ToLower(vhostConn.Host())
	auth := vhostConn.Request.Header.Get("Authorization")

	// done reading mux data, free up the request memory
	vhostConn.Free()

	// We need to read from the vhost conn now since it mucked around reading the stream
	c = conn.Wrap(vhostConn, "pub")

	// multiplex to find the right backend host
	c.Debug("Found hostname %s in request", host)
	tunnel := tunnelRegistry.Get(fmt.Sprintf("%s://%s", proto, host))
	if tunnel == nil {
		if strings.HasSuffix(host, internalSuffix) {
			// Internal endpoints live under an owner-namespaced key, so a
			// public lookup of one is a miss by construction (SPEC 3.2)
			c.Info("No public tunnel for internal hostname %s; internal endpoints are only reachable through forward_to", host)
		} else {
			c.Info("No tunnel found for hostname %s", host)
		}
		c.Write([]byte(fmt.Sprintf(NotFound, len(host)+18, host)))
		return
	}

	// If the client specified http auth and it doesn't match this request's auth
	// then fail the request with 401 Not Authorized and request the client reissue the
	// request with basic authdeny the request
	if tunnel.req.HttpAuth != "" && auth != tunnel.req.HttpAuth {
		c.Info("Authentication failed")
		c.Write([]byte(NotAuthorized))
		return
	}

	// dead connections will now be handled by tunnel heartbeating and the client
	c.SetDeadline(time.Time{})

	// Follow the forward_to chain, if this endpoint has one, and serve the
	// connection through whichever tunnel terminates the chain. The public
	// client's address rides along untouched, so X-Forwarded-For stays
	// truthful, and the forwarding endpoint's own agent never sees this
	// connection (SPEC 3.3). Only HTTP is wired: internal TCP endpoints do
	// not exist in this cluster, so a TCP chain could never resolve.
	target, err := tunnelRegistry.ResolveForward(tunnel)
	if err != nil {
		respondBadGateway(c, err)
		return
	}

	// let the tunnel handle the connection now
	target.HandlePublicConnection(c)
}
