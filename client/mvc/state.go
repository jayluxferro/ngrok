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
