package client

// Tests for the agent_tls_termination / tls / remote_port configuration
// surface (SPEC-CLUSTER5 5.1, 4.1): that the YAML keys and the flags arrive
// intact, that the fixed remote port and the TLS material reach the wire
// request, and that every malformation is refused at load time naming the
// tunnel, key or file it came from. What the termination does to a live
// connection is agenttls_proxy_test.go's subject; what the cert models build is
// tlsagent_test.go's.

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ngrok/msg"
	"ngrok/proto"
)

// agentTLSTunnelYAML builds a one-tunnel config with extra (indented) lines
// spliced inside the tunnel, on top of an https leg -- the protocol agent
// termination needs.
func agentTLSTunnelYAML(extraLines ...string) string {
	lines := []string{
		"tunnels:",
		"  web:",
		"    proto:",
		"      https: 127.0.0.1:8443",
	}
	lines = append(lines, extraLines...)

	return strings.Join(lines, "\n") + "\n"
}

// mustTestCAFiles writes a real CA pair for the happy-path loads.
func mustTestCAFiles(t *testing.T) (caCrtPath, caKeyPath string) {
	t.Helper()

	caPEM, caKeyPEM := agentTestCA(t)
	return writeAgentTLSFile(t, "ca.crt", caPEM), writeAgentTLSFile(t, "ca.key", caKeyPEM)
}

// mustTestLeafFiles writes a leaf/key pair signed by the given CA.
func mustTestLeafFiles(t *testing.T, caCrtPath, caKeyPath string) (crtPath, keyPath string) {
	t.Helper()

	caPEM, err := os.ReadFile(caCrtPath)
	if err != nil {
		t.Fatalf("failed to read test CA: %v", err)
	}
	caKeyPEM, err := os.ReadFile(caKeyPath)
	if err != nil {
		t.Fatalf("failed to read test CA key: %v", err)
	}
	caBlock, _ := pem.Decode(caPEM)
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		t.Fatalf("test CA does not parse: %v", err)
	}
	keyBlock, _ := pem.Decode(caKeyPEM)
	caKey, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatalf("test CA key does not parse: %v", err)
	}

	crtPEM, keyPEM := agentTestLeafPEM(t, caCert, caKey, "web.example.com")
	return writeAgentTLSFile(t, "leaf.crt", crtPEM), writeAgentTLSFile(t, "leaf.key", keyPEM)
}

// TestAgentTLSConfigValidation drives the rejections through LoadConfiguration,
// so it also proves the validation is wired in for config-file tunnels and not
// merely available as an unused helper.
func TestAgentTLSConfigValidation(t *testing.T) {
	caCrt, caKey := mustTestCAFiles(t)
	goodCrt, goodKey := mustTestLeafFiles(t, caCrt, caKey)
	missing := filepath.Join(t.TempDir(), "not-there.crt")

	cases := []struct {
		name  string
		lines []string
		// yaml overrides the whole config for cases the https base YAML cannot
		// express (an http-only tunnel, say).
		yaml string
		want []string // substrings the load error must contain
	}{
		{
			name: "requires an https leg",
			yaml: "tunnels:\n  web:\n    proto:\n      http: 127.0.0.1:8080\n    agent_tls_termination: true\n",
			want: []string{"agent_tls_termination", "https"},
		},
		{
			name: "crt without key names the missing key",
			lines: []string{
				"    agent_tls_termination: true",
				fmt.Sprintf("    tls:\n      crt: %s", goodCrt),
			},
			want: []string{"tls.key"},
		},
		{
			name: "key without crt names the missing certificate",
			lines: []string{
				"    agent_tls_termination: true",
				fmt.Sprintf("    tls:\n      key: %s", goodKey),
			},
			want: []string{"tls.crt"},
		},
		{
			name: "ca_crt without ca_key names the missing key",
			lines: []string{
				"    agent_tls_termination: true",
				fmt.Sprintf("    tls:\n      ca_crt: %s", caCrt),
			},
			want: []string{"tls.ca_key"},
		},
		{
			name: "both models at once is refused",
			lines: []string{
				"    agent_tls_termination: true",
				fmt.Sprintf("    tls:\n      crt: %s\n      key: %s\n      ca_crt: %s\n      ca_key: %s", goodCrt, goodKey, caCrt, caKey),
			},
			want: []string{"not both", "tls.crt"},
		},
		{
			name: "a missing file is a load error naming the path",
			lines: []string{
				"    agent_tls_termination: true",
				fmt.Sprintf("    tls:\n      crt: %s\n      key: %s", missing, goodKey),
			},
			want: []string{"not-there.crt"},
		},
		{
			name: "a non-CA named as CA is refused at load",
			lines: []string{
				"    agent_tls_termination: true",
				fmt.Sprintf("    tls:\n      ca_crt: %s\n      ca_key: %s", goodCrt, goodKey),
			},
			want: []string{"not a certificate authority", "leaf.crt"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			configYAML := tc.yaml
			if configYAML == "" {
				configYAML = agentTLSTunnelYAML(tc.lines...)
			}
			configPath := writeConfig(t, configYAML)
			_, err := LoadConfiguration(&Options{config: configPath, command: "start", args: []string{"web"}})
			if err == nil {
				t.Fatal("expected the configuration to be refused")
			}
			for _, want := range tc.want {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("error should mention %q, got: %v", want, err)
				}
			}
			if !strings.Contains(err.Error(), "Tunnel web") {
				t.Fatalf("error should name the offending tunnel, got: %v", err)
			}
		})
	}
}

// TestAgentTLSConfigAcceptedShapes covers what must LOAD: the ephemeral model
// with the switch alone, and each explicit model with a real pair -- and in
// every case the switch reaches the wire request as TLSTerminationAgent.
func TestAgentTLSConfigAcceptedShapes(t *testing.T) {
	caCrt, caKey := mustTestCAFiles(t)
	goodCrt, goodKey := mustTestLeafFiles(t, caCrt, caKey)

	cases := []struct {
		name  string
		lines []string
	}{
		{
			name:  "the switch alone means the ephemeral model",
			lines: []string{"    agent_tls_termination: true"},
		},
		{
			name: "an explicit leaf and key load",
			lines: []string{
				"    agent_tls_termination: true",
				fmt.Sprintf("    tls:\n      crt: %s\n      key: %s", goodCrt, goodKey),
			},
		},
		{
			name: "a CA pair loads",
			lines: []string{
				"    agent_tls_termination: true",
				fmt.Sprintf("    tls:\n      ca_crt: %s\n      ca_key: %s", caCrt, caKey),
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			configPath := writeConfig(t, agentTLSTunnelYAML(tc.lines...))
			config, err := LoadConfiguration(&Options{config: configPath, command: "start", args: []string{"web"}})
			if err != nil {
				t.Fatalf("expected the configuration to load, got: %v", err)
			}
			if !config.Tunnels["web"].AgentTLSTermination {
				t.Fatal("agent_tls_termination did not survive the load")
			}
			if req := reqTunnelFromConfig("web-req", config.Tunnels["web"]); req.TLSTermination != msg.TLSTerminationAgent {
				t.Fatalf("ReqTunnel.TLSTermination = %q, want %q", req.TLSTermination, msg.TLSTerminationAgent)
			}
		})
	}
}

// TestAgentTLSOffMeansEdgeTermination is the default pinned at the wire: a
// tunnel that says nothing about termination asks for exactly what every
// pre-cluster-5 client asked for, the empty string.
func TestAgentTLSOffMeansEdgeTermination(t *testing.T) {
	configPath := writeConfig(t, agentTLSTunnelYAML())
	config, err := LoadConfiguration(&Options{config: configPath, command: "start", args: []string{"web"}})
	if err != nil {
		t.Fatalf("expected the configuration to load, got: %v", err)
	}
	if req := reqTunnelFromConfig("web-req", config.Tunnels["web"]); req.TLSTermination != msg.TLSTerminationEdge {
		t.Fatalf("ReqTunnel.TLSTermination = %q, want the edge value %q", req.TLSTermination, msg.TLSTerminationEdge)
	}
}

// TestAgentTLSKeysWithoutTheSwitchAreRefused pins the control the other way: a
// tls block on a tunnel that never asked for termination would sit in the file
// doing nothing, which is a control the operator believes in and that is not
// there.
func TestAgentTLSKeysWithoutTheSwitchAreRefused(t *testing.T) {
	caCrt, _ := mustTestCAFiles(t)

	configPath := writeConfig(t, agentTLSTunnelYAML(fmt.Sprintf("    tls:\n      crt: %s", caCrt)))
	_, err := LoadConfiguration(&Options{config: configPath, command: "start", args: []string{"web"}})
	if err == nil {
		t.Fatal("a tls block without agent_tls_termination must be refused")
	}
	for _, want := range []string{"Tunnel web", "agent_tls_termination", "tls.crt"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error should mention %q, got: %v", want, err)
		}
	}
}

// TestAgentTLSInternalBindingRefused pins the 5.4 invariant a misconfiguration
// would break: forwarding delivers plaintext http into the target, and an
// agent-terminated target waits for a ClientHello instead.
func TestAgentTLSInternalBindingRefused(t *testing.T) {
	configPath := writeConfig(t, `
tunnels:
  svc:
    hostname: svc.internal
    binding: internal
    agent_tls_termination: true
    proto:
      https: 127.0.0.1:8443
`)
	_, err := LoadConfiguration(&Options{config: configPath, command: "start", args: []string{"svc"}})
	if err == nil {
		t.Fatal("binding internal with agent_tls_termination must be refused")
	}
	for _, want := range []string{"Tunnel svc", "binding internal", "plaintext"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error should mention %q, got: %v", want, err)
		}
	}
}

// TestAgentTLSDefaultTunnelFlags walks the flag spelling: the flags feed the
// synthesized "default" tunnel, which is validated like a config-file tunnel
// and carries the same keys.
func TestAgentTLSDefaultTunnelFlags(t *testing.T) {
	caCrt, caKey := mustTestCAFiles(t)

	opts, _ := parseArgs(t, []string{
		"ngrok", "-proto=https", "-agent-tls-termination",
		"-tls-ca-crt=" + caCrt, "-tls-ca-key=" + caKey,
		"-hostname=app.example.com", "8443",
	})
	if !opts.agentTLSTermination || opts.tlsCaCrt != caCrt || opts.tlsCaKey != caKey {
		t.Fatalf("the agent TLS flags did not arrive in the options: %+v", opts)
	}

	configPath := writeConfig(t, "")
	config, err := LoadConfiguration(&Options{
		config: configPath, command: opts.command, args: opts.args,
		protocol:            opts.protocol,
		hostname:            opts.hostname,
		agentTLSTermination: opts.agentTLSTermination,
		tlsCaCrt:            opts.tlsCaCrt, tlsCaKey: opts.tlsCaKey,
	})
	if err != nil {
		t.Fatalf("expected the synthesized tunnel to load, got: %v", err)
	}
	def := config.Tunnels["default"]
	if !def.AgentTLSTermination {
		t.Fatal("the -agent-tls-termination flag did not reach the default tunnel")
	}
	if def.TLS == nil || def.TLS.CaCrt != caCrt || def.TLS.CaKey != caKey {
		t.Fatalf("the -tls-ca-* flags did not reach the default tunnel: %+v", def.TLS)
	}
	if req := reqTunnelFromConfig("default-req", def); req.TLSTermination != msg.TLSTerminationAgent {
		t.Fatalf("the default tunnel's request does not ask for agent termination: %+v", req)
	}
}

// TestRemotePortFlags pins the CLI half of the fixed remote port (4.1): the
// flag arrives, feeds the default tunnel and its wire request, and is policed
// by the same rules a config-file remote_port is.
func TestRemotePortFlags(t *testing.T) {
	opts, _ := parseArgs(t, []string{"ngrok", "-proto=tcp", "-remote-port=2222", "22"})
	if opts.remotePort != 2222 {
		t.Fatalf("-remote-port arrived as %d, want 2222", opts.remotePort)
	}

	configPath := writeConfig(t, "")
	config, err := LoadConfiguration(&Options{
		config: configPath, command: opts.command, args: opts.args,
		protocol: opts.protocol, remotePort: opts.remotePort,
	})
	if err != nil {
		t.Fatalf("expected the synthesized tunnel to load, got: %v", err)
	}
	if got := config.Tunnels["default"].RemotePort; got != 2222 {
		t.Fatalf("default tunnel remote_port = %d, want 2222", got)
	}
	if req := reqTunnelFromConfig("default-req", config.Tunnels["default"]); req.RemotePort != 2222 {
		t.Fatalf("the fixed remote port did not reach the wire request: %+v", req)
	}

	for _, tc := range []struct {
		name string
		argv []string
		want []string
	}{
		{
			name: "a port below 1024 explains the privilege requirement",
			argv: []string{"ngrok", "-proto=tcp", "-remote-port=443", "22"},
			// The message uses the config key's spelling: one helper polices
			// both surfaces, so both get the same words.
			want: []string{"remote_port", "443", "1024"},
		},
		{
			name: "a port past uint16 is refused with the flag named",
			argv: []string{"ngrok", "-proto=tcp", "-remote-port=70000", "22"},
			want: []string{"remote-port", "65535"},
		},
		{
			name: "a remote port on an http tunnel is refused",
			argv: []string{"ngrok", "-remote-port=2222", "8080"},
			want: []string{"remote_port", "tcp"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts, _ := parseArgs(t, tc.argv)
			_, err := LoadConfiguration(&Options{
				config: configPath, command: opts.command, args: opts.args,
				protocol: opts.protocol, remotePort: opts.remotePort,
			})
			if err == nil {
				t.Fatal("expected the configuration to be refused")
			}
			for _, want := range tc.want {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("error should mention %q, got: %v", want, err)
				}
			}
		})
	}
}

// TestRemotePortValidationSharedWithConfigFiles pins that the config-file
// spelling is policed by the same helper the flags go through: same rules, same
// words, for both surfaces. (A valid remote_port on a config-file tcp tunnel is
// covered by TestTrafficPolicyOnTcpTunnel, which loads exactly that.)
func TestRemotePortValidationSharedWithConfigFiles(t *testing.T) {
	cases := []struct {
		name  string
		lines []string
		want  string
	}{
		{
			name:  "privileged port",
			lines: []string{"    proto:\n      tcp: 22", "    remote_port: 443"},
			want:  "1024",
		},
		{
			name:  "two protocols with a remote port",
			lines: []string{"    proto:\n      http: 8080", "      https: 8443", "    remote_port: 2222"},
			want:  "exactly one protocol",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			configPath := writeConfig(t, strings.Join(append([]string{"tunnels:", "  db:"}, tc.lines...), "\n")+"\n")
			_, err := LoadConfiguration(&Options{config: configPath, command: "start", args: []string{"db"}})
			if err == nil {
				t.Fatal("expected the configuration to be refused")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error should mention %q, got: %v", tc.want, err)
			}
		})
	}
}

// TestTunnelFromConfigCarriesAgentTLS completes the mapping tests in
// model_wiring_test.go for the new flag: config -> mvc.Tunnel.
func TestTunnelFromConfigCarriesAgentTLS(t *testing.T) {
	config := &TunnelConfiguration{
		Hostname:            "web.example.com",
		Protocols:           map[string]string{"https": "127.0.0.1:8443"},
		AgentTLSTermination: true,
	}

	got := tunnelFromConfig("https://web.example.com", "https", proto.NewHttp(), config)
	if !got.AgentTLS {
		t.Fatal("agent_tls_termination did not reach the tunnel")
	}

	config.AgentTLSTermination = false
	if got := tunnelFromConfig("https://web.example.com", "https", proto.NewHttp(), config); got.AgentTLS {
		t.Fatal("a tunnel without the switch must not carry the flag")
	}
}

// TestTerminationEchoError pins the establishment-time version guard: a client
// that asked for agent TLS termination accepts only an ack that echoes it. The
// old-server pairing -- registration succeeds, the field is dropped in
// silence, the endpoint serves edge-terminated while this agent arms its own
// terminator -- must fail here, loudly, naming the fix.
func TestTerminationEchoError(t *testing.T) {
	cases := []struct {
		name      string
		agentAsk  bool
		echo      string
		wantErr   bool
		wantParts []string
	}{
		{
			name:     "agent ask, agent echo",
			agentAsk: true,
			echo:     msg.TLSTerminationAgent,
		},
		{
			name:      "agent ask, old server (no echo)",
			agentAsk:  true,
			echo:      "",
			wantErr:   true,
			wantParts: []string{"did not confirm agent TLS termination", "1.0.7", "agent_tls_termination"},
		},
		{
			name:     "agent ask, edge echo (server refused to honor it)",
			agentAsk: true,
			echo:     "edge",
			wantErr:  true,
		},
		{
			name:     "edge tunnel, no echo",
			agentAsk: false,
			echo:     "",
		},
		{
			name:     "nil config (no tunnel configuration)",
			agentAsk: false,
			echo:     "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var cfg *TunnelConfiguration
			if tc.agentAsk || tc.name != "nil config (no tunnel configuration)" {
				cfg = &TunnelConfiguration{AgentTLSTermination: tc.agentAsk}
			}
			err := terminationEchoError("https://x.test", cfg, &msg.NewTunnel{TLSTermination: tc.echo})
			if tc.wantErr && err == nil {
				t.Fatal("the mismatch must be refused")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("a consistent ack must pass, got: %v", err)
			}
			for _, part := range tc.wantParts {
				if err != nil && !strings.Contains(err.Error(), part) {
					t.Fatalf("the error must mention %q, got: %v", part, err)
				}
			}
		})
	}
}
