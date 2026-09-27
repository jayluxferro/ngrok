package client

import (
	"net"
	"ngrok/client/mvc"
	"ngrok/msg"
	"ngrok/rewriter"
	"strings"
)

// policyFromTunnel turns one tunnel's configuration into the header policy the
// rewriter applies to every connection proxied through it (SPEC 5.3).
//
// The tunnel is the only carrier available at this point: by the time a proxied
// connection arrives, proxy() has the public URL and nothing else, so the
// per-tunnel header settings were copied onto mvc.Tunnel when it was
// established. This function is a field copy plus the two values the rewriter
// cannot derive from the config alone.
//
// clientAddr is msg.StartProxy.ClientAddr -- the address of the public client
// whose connection is being proxied -- and becomes X-Forwarded-For with the
// socket's port stripped: upstreams expect a bare IP (SPEC 4.3).
//
// The result is always non-nil; it is the caller's job to decide whether this
// tunnel has headers worth rewriting (a TCP tunnel does not) and to skip the
// rewriter when the policy turns out to be a no-op.
func policyFromTunnel(tunnel mvc.Tunnel, clientAddr string) *rewriter.Policy {
	// "rewrite" sends the host of the local leg (SPEC 4.1), so the port has to
	// go: the port of the private connection is an implementation detail the
	// upstream never sees, and Ollama's loopback check -- the reason this
	// feature exists -- compares against a bare host.
	//
	// LocalAddr is normalized to host:port by the config loader. If it somehow
	// is not, the raw value is still the best host we have.
	upstreamHost := tunnel.LocalAddr
	if host, _, err := net.SplitHostPort(tunnel.LocalAddr); err == nil {
		upstreamHost = host
	}
	// RFC 7230 5.4: an IPv6 literal in a Host value must be bracketed, and
	// SplitHostPort returns it bare ("::1"), so put the brackets back.
	if strings.Contains(upstreamHost, ":") {
		upstreamHost = "[" + upstreamHost + "]"
	}

	// The public scheme is what an upstream should believe the client spoke.
	// The local leg is always plain HTTP -- the client terminates TLS, the
	// upstream never speaks it -- so the value comes from the public URL and
	// not from LocalAddr.
	xForwardedProto := msg.ProtoHTTP
	if strings.HasPrefix(tunnel.PublicUrl, msg.ProtoHTTPS+"://") {
		xForwardedProto = msg.ProtoHTTPS
	}

	// X-Forwarded-For carries the bare client IP: the server sends
	// RemoteAddr().String() ("ip:port"), upstreams expect the IP alone, and an
	// "ip:port" value breaks XFF consumers. An address SplitHostPort cannot
	// split (which the server never sends) goes through verbatim.
	clientIP := clientAddr
	if host, _, err := net.SplitHostPort(clientAddr); err == nil {
		clientIP = host
	}

	return &rewriter.Policy{
		HostHeader: tunnel.HostHeader,
		// Compression is a per-tunnel wish, not a per-connection decision: the
		// rewriter's skip matrix (SPEC 3.4) decides for each response whether
		// this tunnel may gzip it, and it needs the flag even for a response
		// that ends up not being compressed.
		Compress: tunnel.Compress,

		RequestHeaderAdd:     tunnel.RequestHeaderAdd,
		RequestHeaderRemove:  tunnel.RequestHeaderRemove,
		ResponseHeaderAdd:    tunnel.ResponseHeaderAdd,
		ResponseHeaderRemove: tunnel.ResponseHeaderRemove,

		UpstreamHost:    upstreamHost,
		ClientAddr:      clientIP,
		XForwardedProto: xForwardedProto,
	}
}

// flattenHeaderConfig turns one config-file header section into the flat
// add/remove lists mvc.Tunnel carries. A tunnel whose config has no
// request_header (or response_header) block has a nil *HeaderConfig, and that
// flattens to nil -- an empty list, which is exactly how the rewriter reads it
// (every add/remove path is a range or a len check), so the nil never has to be
// handled again downstream.
func flattenHeaderConfig(hc *HeaderConfig) (add, remove []string) {
	if hc == nil {
		return nil, nil
	}

	return hc.Add, hc.Remove
}
