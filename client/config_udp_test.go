package client

// Tests for the udp tunnel's configuration surface (SPEC-CLUSTER8 3.2,
// workstream B): the protocol joins the enum, remote_port becomes valid for
// tcp or udp, and hostname/subdomain are refused for udp exactly as for tcp
// (a port-routed protocol is addressed by its port, not by a name).
//
// These are new-file additions on purpose: the surrounding validation tests
// live in config_test.go, and its tables predate udp, so the udp cases sit
// beside them in their own table rather than spliced into tables whose cases
// were written to pin non-udp behavior.

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// udpTunnelYAML builds a one-tunnel config whose proto section is udp, with
// extraLines spliced in as (already indented) tunnel-level keys -- the
// tunnelYAML shape from config_test.go, pointed at a udp tunnel so the
// "offending tunnel is named" assertions below have the same subject.
func udpTunnelYAML(extraLines ...string) string {
	lines := []string{
		"tunnels:",
		"  dns:",
		"    proto:",
		"      udp: 127.0.0.1:53",
	}
	lines = append(lines, extraLines...)

	return strings.Join(lines, "\n") + "\n"
}

func loadTunnelConfig(t *testing.T, contents, tunnel string) (*Configuration, error) {
	t.Helper()
	return LoadConfiguration(&Options{config: writeConfig(t, contents), command: "start", args: []string{tunnel}})
}

// TestLoadConfigurationUDPTunnel is the positive case: a udp config tunnel
// loads, its local address is normalized like any other protocol's, and the
// name-derived subdomain assignment still applies.
//
// That last assertion is load-bearing, not incidental: the loader assigns the
// tunnel name as subdomain after the per-protocol validation loop, so the
// assignment deliberately escapes the hostname/subdomain refusal for
// port-routed protocols -- for tcp that has always been true, and udp (which
// the spec defines as "port-routed, like tcp") now behaves the same. If the
// server ever starts refusing named udp registrations, this is the assertion
// that will catch the resulting breakage of every default-named udp tunnel.
func TestLoadConfigurationUDPTunnel(t *testing.T) {
	config, err := loadTunnelConfig(t, udpTunnelYAML(), "dns")
	if err != nil {
		t.Fatalf("expected the udp tunnel to load, got: %v", err)
	}

	tunnel, ok := config.Tunnels["dns"]
	if !ok {
		t.Fatalf("expected a tunnel named dns, got %d tunnels", len(config.Tunnels))
	}
	if got := tunnel.Protocols["udp"]; got != "127.0.0.1:53" {
		t.Fatalf("udp local address = %q, want %q", got, "127.0.0.1:53")
	}
	// Pinned after the loader fix: a port-routed tunnel's name must NOT
	// become its subdomain -- the server refuses names on udp endpoints, so
	// the assignment made every config-file udp tunnel unregistrable.
	if tunnel.Subdomain != "" || tunnel.Hostname != "" {
		t.Fatalf("subdomain=%q hostname=%q: a port-routed tunnel gets no name assignment", tunnel.Subdomain, tunnel.Hostname)
	}
}

// TestLoadConfigurationUDPValidation is the refusal table: every control that
// could never mean anything on a udp tunnel is a startup error naming the
// tunnel, and the neighboring tcp refusals are re-pinned so extending the
// checks cannot quietly narrow them.
func TestLoadConfigurationUDPValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		wantErr string
	}{
		{
			name:    "udp with an explicit hostname",
			config:  udpTunnelYAML("    hostname: dns.example.com"),
			wantErr: "hostname/subdomain are only valid for http/https",
		},
		{
			name:    "udp with an explicit subdomain",
			config:  udpTunnelYAML("    subdomain: mydns"),
			wantErr: "hostname/subdomain are only valid for http/https",
		},
		{
			// The tcp refusal predates udp; pinning it here means the
			// udp extension of the check is provably additive.
			name:    "tcp with an explicit hostname is still refused",
			config:  strings.Replace(udpTunnelYAML("    hostname: ssh.example.com"), "udp: 127.0.0.1:53", "tcp: 127.0.0.1:22", 1),
			wantErr: "hostname/subdomain are only valid for http/https",
		},
		{
			name:    "udp with a remote_port below the privileged range",
			config:  udpTunnelYAML("    remote_port: 53"),
			wantErr: "below 1024",
		},
		{
			name:    "remote_port over http is still refused",
			config:  strings.Replace(udpTunnelYAML("    remote_port: 5353"), "udp: 127.0.0.1:53", "http: 127.0.0.1:8080", 1),
			wantErr: "remote_port is only valid for tcp or udp",
		},
		{
			// Two protocols and a remote_port: the claim has exactly one
			// port to attach to, whichever pair of protocols it is.
			name: "remote_port over two protocols is still refused",
			config: strings.Replace(udpTunnelYAML("    remote_port: 5353"),
				"udp: 127.0.0.1:53", "udp: 127.0.0.1:53\n      tcp: 127.0.0.1:22", 1),
			wantErr: "remote_port requires exactly one protocol",
		},
		{
			name:    "a protocol outside the enum is still refused",
			config:  strings.Replace(udpTunnelYAML(), "udp", "quic", 1),
			wantErr: "Invalid protocol",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := loadTunnelConfig(t, tt.config, "dns")
			if err == nil {
				t.Fatalf("expected an error containing %q, got none", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error should mention %q, got: %v", tt.wantErr, err)
			}
			if !strings.Contains(err.Error(), "dns") {
				t.Fatalf("error should name the offending tunnel, got: %v", err)
			}
		})
	}
}

// TestLoadConfigurationUDPRemotePortAccepted is the positive half of the
// remote_port extension (SPEC-CLUSTER8 3.2): tcp keeps the claim it always
// had, udp gains the same one, and the boundary rule (one protocol, port at
// or above 1024) is the same rule for both.
func TestLoadConfigurationUDPRemotePortAccepted(t *testing.T) {
	tests := []struct {
		name       string
		proto      string
		localAddr  string
		remotePort int
	}{
		{
			name:       "tcp keeps its claim",
			proto:      "tcp",
			localAddr:  "127.0.0.1:22",
			remotePort: 2222,
		},
		{
			name:       "udp gains the claim",
			proto:      "udp",
			localAddr:  "127.0.0.1:5353",
			remotePort: 5353,
		},
		{
			// 1024 itself is legal: the refusal is for ports BELOW 1024.
			name:       "udp at the 1024 boundary",
			proto:      "udp",
			localAddr:  "127.0.0.1:1024",
			remotePort: 1024,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := strings.Replace(udpTunnelYAML("    remote_port: 5353"),
				"udp: 127.0.0.1:53", tt.proto+": "+tt.localAddr, 1)
			config = strings.Replace(config,
				"remote_port: 5353", "remote_port: "+strconv.Itoa(tt.remotePort), 1)

			got, err := loadTunnelConfig(t, config, "dns")
			if err != nil {
				t.Fatalf("expected the %s tunnel with remote_port %d to load, got: %v", tt.proto, tt.remotePort, err)
			}
			if got.Tunnels["dns"].RemotePort != uint16(tt.remotePort) {
				t.Fatalf("remote_port = %d, want %d", got.Tunnels["dns"].RemotePort, tt.remotePort)
			}
		})
	}
}

// TestDefaultTunnelUDPFlags covers the CLI surface: -proto=udp with a
// -remote-port synthesizes the same tunnel a config file would have, through
// the same validators.
func TestDefaultTunnelUDPFlags(t *testing.T) {
	configPath := writeConfig(t, "server_addr: \"tunnel.example.com:443\"\n")

	config, err := LoadConfiguration(&Options{
		config:     configPath,
		command:    "default",
		args:       []string{"53"},
		protocol:   "udp",
		remotePort: 5353,
	})
	if err != nil {
		t.Fatalf("expected the synthesized udp tunnel to load, got: %v", err)
	}

	tunnel := config.Tunnels["default"]
	if got := tunnel.Protocols["udp"]; got != "127.0.0.1:53" {
		t.Fatalf("udp local address = %q, want %q", got, "127.0.0.1:53")
	}
	if tunnel.RemotePort != 5353 {
		t.Fatalf("remote_port = %d, want 5353", tunnel.RemotePort)
	}
}

// TestUDPProtoFlagIsListed pins the help text contract: -proto=udp must be
// accepted by the flag parser (it is only validated at load, so the parser
// accepting it is what lets LoadConfiguration produce the error that names
// the tunnel for a typo, and the help must not list a value it would refuse).
func TestUDPProtoFlagIsListed(t *testing.T) {
	opts, usage := parseArgs(t, []string{"ngrok", "-proto=udp", "53"})
	if opts.protocol != "udp" {
		t.Fatalf("-proto=udp parsed as %q", opts.protocol)
	}
	if !strings.Contains(usage, "'http', 'https', 'tcp' or 'udp'") {
		t.Fatal("the -proto help text no longer lists udp")
	}
}

// TestPortRoutedTunnelsGetNoAutoSubdomain pins the loader fix for the udp
// registration collision: a tunnel whose every protocol is port-routed must
// NOT have its name auto-assigned as subdomain/hostname, because the server
// refuses names on port-routed endpoints -- while an http tunnel still gets
// the assignment and a mixed http+tcp tunnel keeps it (its http leg uses it).
func TestPortRoutedTunnelsGetNoAutoSubdomain(t *testing.T) {
	dir := t.TempDir()
	write := func(content string) string {
		p := filepath.Join(dir, "cfg.yml")
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatalf("failed to write config: %v", err)
		}
		return p
	}

	cases := []struct {
		name    string
		protos  map[string]string
		tunnel  string
		wantSub bool
	}{
		{"udp only", map[string]string{"udp": "127.0.0.1:15353"}, "dnstunnel", false},
		{"tcp only", map[string]string{"tcp": "127.0.0.1:12222"}, "sshtunnel", false},
		{"http only", map[string]string{"http": "127.0.0.1:18080"}, "webapp", true},
		{"mixed http tcp", map[string]string{"http": "127.0.0.1:18081", "tcp": "127.0.0.1:12223"}, "mixed", true},
		// "http+https" is a single map key, not two: the name-routing check
		// must split it (the exact-match version missed it and silently
		// skipped the assignment for this exact config shape).
		{"combined http+https key", map[string]string{"http+https": "127.0.0.1:18082"}, "combo", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := "server_addr: 127.0.0.1:14443\nauth_token: alpha\ntunnels:\n  " + tc.tunnel + ":\n    proto:\n"
			for k, addr := range tc.protos {
				doc += "      " + k + ": " + addr + "\n"
			}
			cfg, err := LoadConfiguration(&Options{config: write(doc), command: "start", args: []string{tc.tunnel}})
			if err != nil {
				t.Fatalf("the config must load, got: %v", err)
			}
			tun := cfg.Tunnels[tc.tunnel]
			if tc.wantSub {
				if tun.Subdomain == "" && tun.Hostname == "" {
					t.Fatal("a name-routed tunnel must still get the name assignment")
				}
			} else {
				if tun.Subdomain != "" || tun.Hostname != "" {
					t.Fatalf("a port-routed tunnel must not get a name assignment, got subdomain=%q hostname=%q", tun.Subdomain, tun.Hostname)
				}
			}
		})
	}
}
