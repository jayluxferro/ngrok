package client

// Tests from the wire/API consistency audit:
//
//   - M1: a combined proto key ("http+https") is ONE map key, so the
//     name-routing check must split it the way the server splits
//     ReqTunnel.Protocol before answering. An exact match used to miss it and
//     silently skip the name assignment every loader behavior since 1.0.7
//     performed for the same config.
//   - M2: hostname/subdomain versus port-routed protocols is refused by
//     validateEndpointPolicy, so the CLI path ("-proto=tcp -hostname=foo 22")
//     refuses exactly what the config-file path refuses, instead of silently
//     discarding the name.
//   - Shared timing vocabulary: client/model.go's carrier and udp values are
//     spellings of msg's constants, not local literals (msg/shared_timeouts_test.go
//     pins the values and names the still-literal server sites).

import (
	"strings"
	"testing"

	"ngrok/msg"
)

// TestTunnelHasNameRoutedProtoSplitsCombinedKeys is the unit-level pin for
// M1, over every protocol key shape validateProtocol accepts.
func TestTunnelHasNameRoutedProtoSplitsCombinedKeys(t *testing.T) {
	cases := []struct {
		name   string
		protos map[string]string
		want   bool
	}{
		{"single http", map[string]string{"http": "127.0.0.1:80"}, true},
		{"single https", map[string]string{"https": "127.0.0.1:443"}, true},
		{"combined http+https is one key, both legs name-routed", map[string]string{"http+https": "127.0.0.1:80"}, true},
		{"single tcp", map[string]string{"tcp": "127.0.0.1:22"}, false},
		{"single udp", map[string]string{"udp": "127.0.0.1:53"}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tunnelHasNameRoutedProto(&TunnelConfiguration{Protocols: tc.protos}); got != tc.want {
				t.Fatalf("tunnelHasNameRoutedProto(%v) = %v, want %v", tc.protos, got, tc.want)
			}
		})
	}
}

// TestCombinedProtoKeyGetsNameAssignment is M1 end to end through the loader:
// a named tunnel whose proto section carries the combined key gets the same
// name assignment a plain http tunnel gets. This is the exact shape the
// exact-match bug skipped ("http+https" != "http", so no assignment, so the
// tunnel silently registered nameless where 1.0.7 assigned it a name).
func TestCombinedProtoKeyGetsNameAssignment(t *testing.T) {
	doc := "server_addr: 127.0.0.1:14443\nauth_token: alpha\ntunnels:\n" +
		"  webapp:\n" +
		"    proto:\n" +
		"      http+https: 127.0.0.1:18082\n"

	cfg, err := LoadConfiguration(&Options{config: writeConfig(t, doc), command: "start", args: []string{"webapp"}})
	if err != nil {
		t.Fatalf("expected the combined-key tunnel to load, got: %v", err)
	}

	tunnel := cfg.Tunnels["webapp"]
	if tunnel.Subdomain == "" && tunnel.Hostname == "" {
		t.Fatal("a combined http+https key is name-routed: the loader must assign the tunnel name to it")
	}
}

// TestFlagsPathRefusesNameOnPortRoutedProto is M2's new half, through the
// exact CLI shape from the audit: "ngrok -proto=tcp -hostname=foo 22" used to
// synthesize the tunnel, drop the hostname on the floor, and start a tunnel
// under a random url. The synthesized tunnel goes through the same
// validateEndpointPolicy a config-file tunnel does, so the refusal is the
// same words by either road.
func TestFlagsPathRefusesNameOnPortRoutedProto(t *testing.T) {
	configPath := writeConfig(t, "")

	cases := []struct {
		name      string
		argv      []string
		wantErr   string
		wantProto string
	}{
		{
			name:      "tcp with -hostname",
			argv:      []string{"ngrok", "-config=" + configPath, "-proto=tcp", "-hostname=foo", "22"},
			wantErr:   "hostname/subdomain are only valid for http/https",
			wantProto: "tcp",
		},
		{
			name:      "udp with -subdomain",
			argv:      []string{"ngrok", "-config=" + configPath, "-proto=udp", "-subdomain=dns", "53"},
			wantErr:   "hostname/subdomain are only valid for http/https",
			wantProto: "udp",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// parseArgs fails the test itself if the argv does not parse; the
			// second return is the usage text, which these cases do not use.
			opts, _ := parseArgs(t, tc.argv)

			_, err := LoadConfiguration(opts)
			if err == nil {
				t.Fatalf("expected a refusal containing %q, got a loaded config", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error should mention %q, got: %v", tc.wantErr, err)
			}
			// The refusal names the tunnel (the synthesized "default") and the
			// port-routed protocols the name was paired with.
			if !strings.Contains(err.Error(), "default") {
				t.Fatalf("error should name the synthesized tunnel, got: %v", err)
			}
			if !strings.Contains(err.Error(), tc.wantProto) {
				t.Fatalf("error should name the port-routed protocol %q, got: %v", tc.wantProto, err)
			}
		})
	}
}

// TestMixedNameRoutedAndPortRoutedKeepsName pins the rule's edge on both
// paths: a tunnel with an http leg AND a port-routed leg keeps its name. The
// http leg is name-routed and uses it; the port-routed leg ignores it, as it
// always has.
func TestMixedNameRoutedAndPortRoutedKeepsName(t *testing.T) {
	t.Run("config file path", func(t *testing.T) {
		doc := "server_addr: 127.0.0.1:14443\nauth_token: alpha\ntunnels:\n" +
			"  mixed:\n" +
			"    hostname: mixed.example.com\n" +
			"    proto:\n" +
			"      http: 127.0.0.1:18081\n" +
			"      tcp: 127.0.0.1:12223\n"

		cfg, err := loadTunnelConfig(t, doc, "mixed")
		if err != nil {
			t.Fatalf("expected the mixed tunnel to load, got: %v", err)
		}
		if cfg.Tunnels["mixed"].Hostname != "mixed.example.com" {
			t.Fatalf("hostname = %q, want it kept (the http leg uses it)", cfg.Tunnels["mixed"].Hostname)
		}
	})

	t.Run("flags path", func(t *testing.T) {
		configPath := writeConfig(t, "server_addr: \"tunnel.example.com:443\"\n")
		opts, _ := parseArgs(t, []string{"ngrok", "-config=" + configPath, "-proto=http+tcp", "-hostname=foo", "8080"})

		cfg, err := LoadConfiguration(opts)
		if err != nil {
			t.Fatalf("expected the mixed flags tunnel to load, got: %v", err)
		}
		tunnel := cfg.Tunnels["default"]
		if tunnel.Hostname != "foo" {
			t.Fatalf("hostname = %q, want foo kept (the http leg uses it)", tunnel.Hostname)
		}
		if len(tunnel.Protocols) != 2 || tunnel.Protocols["http"] == "" || tunnel.Protocols["tcp"] == "" {
			t.Fatalf("protocols = %v, want both legs registered", tunnel.Protocols)
		}
	})
}

// TestConfigPathNameOnPortRoutedStillRefused keeps the config-file refusal
// pinned next to the new flags-path one: the check moved into
// validateEndpointPolicy, so the file path's behavior is asserted one more
// time here rather than trusted to the move being neutral.
func TestConfigPathNameOnPortRoutedStillRefused(t *testing.T) {
	doc := "server_addr: 127.0.0.1:14443\nauth_token: alpha\ntunnels:\n" +
		"  ssh:\n" +
		"    hostname: ssh.example.com\n" +
		"    proto:\n" +
		"      tcp: 127.0.0.1:22\n"

	_, err := loadTunnelConfig(t, doc, "ssh")
	if err == nil {
		t.Fatal("expected the config-file tcp+hostname refusal to survive the move into validateEndpointPolicy")
	}
	if !strings.Contains(err.Error(), "hostname/subdomain are only valid for http/https") {
		t.Fatalf("error should be the hostname/subdomain refusal, got: %v", err)
	}
	if !strings.Contains(err.Error(), "tcp") {
		t.Fatalf("error should name the port-routed protocol, got: %v", err)
	}
}

// TestCarrierTimeoutsUseSharedVocabulary re-pins, from the client side, that
// the carrier and udp values derive from msg's timing constants rather than
// local literals: someone editing a literal back into client/model.go fails
// here. (The values themselves -- and the still-literal server sites -- are
// documented and pinned in msg/shared_timeouts_test.go.)
func TestCarrierTimeoutsUseSharedVocabulary(t *testing.T) {
	if udpIdleTimeout != msg.UdpIdleTimeout {
		t.Fatalf("udpIdleTimeout = %v, want the shared msg.UdpIdleTimeout (%v)", udpIdleTimeout, msg.UdpIdleTimeout)
	}
	if carrierKeepAlivePeriod != msg.CarrierKeepAlive {
		t.Fatalf("carrierKeepAlivePeriod = %v, want the shared msg.CarrierKeepAlive (%v)", carrierKeepAlivePeriod, msg.CarrierKeepAlive)
	}
	if carrierMaxIdleTimeout != msg.CarrierIdleTimeout {
		t.Fatalf("carrierMaxIdleTimeout = %v, want the shared msg.CarrierIdleTimeout (%v)", carrierMaxIdleTimeout, msg.CarrierIdleTimeout)
	}
}
