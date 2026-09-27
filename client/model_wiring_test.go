package client

import (
	"reflect"
	"testing"

	"ngrok/client/mvc"
	"ngrok/msg"
	"ngrok/proto"
)

// Tests for the two model.go helpers that carry per-tunnel configuration to the
// places that use it: reqTunnelFromConfig (the control-plane request) and
// tunnelFromConfig (the mvc.Tunnel the proxy path and the rewrite policy work
// with). They are split out of control() exactly so that this mapping -- which
// a control connection would otherwise be needed to reach -- can be asserted
// on, the same way relay() and policyFromTunnel are.

// boolPtr is how the tests spell an explicit compression value, mirroring the
// config loader: the YAML key is a *bool so that "absent" (on) and "false"
// (off) are different values.
func boolPtr(b bool) *bool { return &b }

func TestReqTunnelFromConfig(t *testing.T) {
	tests := []struct {
		name   string
		config *TunnelConfiguration
		want   *msg.ReqTunnel
	}{
		{
			name: "http tunnel with no endpoint settings",
			config: &TunnelConfiguration{
				Hostname:  "web.example.com",
				HttpAuth:  "user:pass",
				Protocols: map[string]string{"http": "127.0.0.1:8080"},
			},
			want: &msg.ReqTunnel{
				ReqId:    "reqid",
				Protocol: "http",
				Hostname: "web.example.com",
				HttpAuth: "user:pass",
			},
		},
		{
			name: "internal endpoint",
			config: &TunnelConfiguration{
				Hostname:  "svc.internal",
				Binding:   "internal",
				Protocols: map[string]string{"https": "127.0.0.1:11434"},
			},
			want: &msg.ReqTunnel{
				ReqId:    "reqid",
				Protocol: "https",
				Hostname: "svc.internal",
				Binding:  "internal",
			},
		},
		{
			// The pooling flag is what lets a second agent join the URL instead
			// of being refused it, so it has to reach the wire with the request
			// and not only the local config.
			name: "pooled public endpoint",
			config: &TunnelConfiguration{
				Subdomain: "pool",
				Pooling:   true,
				Protocols: map[string]string{"http": "127.0.0.1:8080"},
			},
			want: &msg.ReqTunnel{
				ReqId:     "reqid",
				Protocol:  "http",
				Subdomain: "pool",
				Pooling:   true,
			},
		},
		{
			name: "forwarding endpoint",
			config: &TunnelConfiguration{
				Hostname:  "web.example.com",
				ForwardTo: "https://svc.internal",
				Protocols: map[string]string{"http": "127.0.0.1:8080"},
			},
			want: &msg.ReqTunnel{
				ReqId:     "reqid",
				Protocol:  "http",
				Hostname:  "web.example.com",
				ForwardTo: "https://svc.internal",
			},
		},
		{
			// Two protocols are joined with "+" for the server to split, and the
			// join is sorted so that the same config always produces the same
			// request (map order used to decide it).
			name: "http and https legs",
			config: &TunnelConfiguration{
				Hostname:  "web.example.com",
				Protocols: map[string]string{"https": "127.0.0.1:8080", "http": "127.0.0.1:8080"},
			},
			want: &msg.ReqTunnel{
				ReqId:    "reqid",
				Protocol: "http+https",
				Hostname: "web.example.com",
			},
		},
		{
			name: "tcp tunnel with a remote port",
			config: &TunnelConfiguration{
				RemotePort: 12345,
				Protocols:  map[string]string{"tcp": "127.0.0.1:22"},
			},
			want: &msg.ReqTunnel{
				ReqId:      "reqid",
				Protocol:   "tcp",
				RemotePort: 12345,
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := reqTunnelFromConfig("reqid", tc.config)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("reqTunnelFromConfig = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// TestTunnelFromConfig pins the config-to-tunnel mapping: the local address
// comes from the protocol the server established, the header policy is
// flattened, the endpoint settings are carried, and compression is the
// *resolved* value of a key that defaults to on.
func TestTunnelFromConfig(t *testing.T) {
	httpProto := proto.NewHttp()

	config := &TunnelConfiguration{
		Hostname:       "svc.internal",
		Protocols:      map[string]string{"https": "127.0.0.1:11434"},
		HostHeader:     "rewrite",
		RequestHeader:  &HeaderConfig{Add: []string{"X-One: 1"}, Remove: []string{"X-Two"}},
		ResponseHeader: &HeaderConfig{Remove: []string{"Server"}},
		Binding:        "internal",
		Pooling:        true,
		ForwardTo:      "https://other.internal",
		Compression:    boolPtr(false),
	}

	got := tunnelFromConfig("https://svc.internal", "https", httpProto, config)

	want := mvc.Tunnel{
		PublicUrl: "https://svc.internal",
		LocalAddr: "127.0.0.1:11434",
		Protocol:  httpProto,

		HostHeader: "rewrite",

		RequestHeaderAdd:     []string{"X-One: 1"},
		RequestHeaderRemove:  []string{"X-Two"},
		ResponseHeaderRemove: []string{"Server"},

		Binding:   "internal",
		Pooling:   true,
		ForwardTo: "https://other.internal",
		Compress:  false,
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("tunnelFromConfig = %+v, want %+v", got, want)
	}
}

// TestTunnelFromConfigCompressionDefault is the other half of the compression
// mapping: a config with no compression key (the common case, and every tunnel
// started before cluster 2) must produce a compressing tunnel.
func TestTunnelFromConfigCompressionDefault(t *testing.T) {
	config := &TunnelConfiguration{
		Hostname:  "web.example.com",
		Protocols: map[string]string{"http": "127.0.0.1:8080"},
	}

	got := tunnelFromConfig("http://web.example.com", "http", proto.NewHttp(), config)
	if !got.Compress {
		t.Fatal("a tunnel with no compression key must compress (SPEC 3.4 default)")
	}

	config.Compression = boolPtr(true)
	if got := tunnelFromConfig("http://web.example.com", "http", proto.NewHttp(), config); !got.Compress {
		t.Fatal("an explicit compression: true must compress")
	}
}

// TestEndpointSettingsReachTheWire walks the whole client-side path a
// config-file tunnel takes: LoadConfiguration (keys read, binding normalized,
// compression resolved), reqTunnelFromConfig (what goes to the server) and
// tunnelFromConfig (what the proxy path and the rewrite policy see). It is the
// test that would catch a field that is parsed but never forwarded.
func TestEndpointSettingsReachTheWire(t *testing.T) {
	configPath := writeConfig(t, `
tunnels:
  svc:
    hostname: svc.internal
    binding: internal
    proto:
      https: 127.0.0.1:11434
  web:
    hostname: web.example.com
    proto:
      http: 127.0.0.1:8080
    binding: public
    pooling: true
    forward_to: https://svc.internal
    compression: false
`)

	config, err := LoadConfiguration(&Options{config: configPath, command: "start-all"})
	if err != nil {
		t.Fatalf("expected the config to load, got: %v", err)
	}

	svcCfg := config.Tunnels["svc"]
	svcReq := reqTunnelFromConfig("svc-req", svcCfg)
	if svcReq.Binding != "internal" || svcReq.Protocol != "https" || svcReq.Hostname != "svc.internal" {
		t.Fatalf("internal endpoint request = %+v", svcReq)
	}
	if svcReq.Pooling || svcReq.ForwardTo != "" {
		t.Fatalf("the internal endpoint picked up settings it was not given: %+v", svcReq)
	}

	svcTunnel := tunnelFromConfig("https://svc.internal", "https", proto.NewHttp(), svcCfg)
	if !svcTunnel.Compress {
		t.Fatal("the internal endpoint's absent compression key did not resolve to on")
	}

	webCfg := config.Tunnels["web"]
	webReq := reqTunnelFromConfig("web-req", webCfg)
	// "binding: public" is the public endpoint spelled out, and the wire only
	// knows the empty string for it.
	if webReq.Binding != "" {
		t.Fatalf("binding public was not normalized for the wire: %q", webReq.Binding)
	}
	if !webReq.Pooling || webReq.ForwardTo != "https://svc.internal" {
		t.Fatalf("forwarding endpoint request = %+v", webReq)
	}

	webTunnel := tunnelFromConfig("http://web.example.com", "http", proto.NewHttp(), webCfg)
	if webTunnel.Compress {
		t.Fatal("compression: false did not reach the proxy path")
	}
	if webTunnel.ForwardTo != "https://svc.internal" {
		t.Fatalf("forward_to did not reach the tunnel: %q", webTunnel.ForwardTo)
	}
	if webTunnel.LocalAddr != "127.0.0.1:8080" {
		t.Fatalf("local address = %q, want the http leg's address", webTunnel.LocalAddr)
	}
}
