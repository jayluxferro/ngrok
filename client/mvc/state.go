package mvc

import (
	metrics "github.com/rcrowley/go-metrics"
	"ngrok/proto"
)

type UpdateStatus int

const (
	UpdateNone = -1 * iota
	UpdateInstalling
	UpdateReady
	UpdateAvailable
)

type ConnStatus int

const (
	ConnConnecting = iota
	ConnReconnecting
	ConnOnline
)

type Tunnel struct {
	PublicUrl string
	Protocol  proto.Protocol
	LocalAddr string

	// Per-tunnel HTTP header policy, carried from the tunnel's configuration
	// (client/config.go) to whoever builds the rewrite policy. Nothing in this
	// package interprets these fields; they are pure data.
	HostHeader           string
	RequestHeaderAdd     []string
	RequestHeaderRemove  []string
	ResponseHeaderAdd    []string
	ResponseHeaderRemove []string

	// Endpoint settings, carried the same way and for the same reason: they
	// come from the tunnel's configuration and are consumed by the rewrite
	// policy (Compress) or reported to the user (the other three).
	Binding   string // "" public, "internal"
	Pooling   bool
	ForwardTo string
	Compress  bool

	// AgentTLS reports that this tunnel's public TLS terminates in the agent
	// (SPEC-CLUSTER5 5.3) instead of at the edge: the server relays the TLS
	// bytes unread and this client decrypts. The proxy path reads it to decide
	// whether to terminate, and a view may show it; nothing else in this
	// package interprets it. Only meaningful for https public URLs -- a tunnel
	// with both legs carries the flag, but its http leg is still edge-served.
	AgentTLS bool

	// UpstreamProtocol is what the agent speaks to this tunnel's local service
	// (SPEC-CLUSTER17): "http1" -- the plain TCP dial -- or "http2", the local
	// leg's h1<->h2c transcoder. Resolved at the config->tunnel boundary (the
	// empty config value becomes "http1" here), so the proxy path tests one
	// definite value. Carried the same way as the header policy above: pure
	// data from the configuration; nothing in this package interprets it.
	UpstreamProtocol string

	// UpstreamPool reports that this tunnel's local leg opted into connection
	// pooling (SPEC-CLUSTER25): the plain dial's place is taken by the h1 pool
	// bridge (client/upstreamh1.go), an httputil.ReverseProxy behind a shared
	// per-address keep-alive transport. A bool needs no resolving -- the zero
	// value IS the default -- so unlike UpstreamProtocol it is carried as
	// written. Pure data from the configuration; nothing in this package
	// interprets it.
	UpstreamPool bool
}

type ConnectionContext struct {
	Tunnel     Tunnel
	ClientAddr string
}

type State interface {
	GetClientVersion() string
	GetServerVersion() string
	GetTunnels() []Tunnel
	GetProtocols() []proto.Protocol
	GetUpdateStatus() UpdateStatus
	GetConnStatus() ConnStatus
	GetConnectionMetrics() (metrics.Meter, metrics.Timer)
	GetBytesInMetrics() (metrics.Counter, metrics.Histogram)
	GetBytesOutMetrics() (metrics.Counter, metrics.Histogram)
	SetUpdateStatus(UpdateStatus)
}
