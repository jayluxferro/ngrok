package client

// Tests for the proxy_transport configuration (SPEC-CLUSTER7 5): the enum
// validation at load (config file and -proxy-transport flag, one choke point),
// and the resolution newClientModel applies on top of the validated value --
// the http_proxy override, which is the one setting that can silently change
// which carrier a client runs, and therefore the one that must be loud.

import (
	"strings"
	"testing"
)

// transportConfigYAML builds a config file with a top-level proxy_transport
// key. Top-level on purpose: proxy_transport is a client-level setting, and a
// test that put it inside the tunnel block would be validating a key that
// does not exist (and, with this decoder, silently means nothing).
func transportConfigYAML(value string) string {
	if value == "" {
		return tunnelYAML()
	}
	return "proxy_transport: " + value + "\n" + tunnelYAML()
}

// loadTransportConfig runs LoadConfiguration the way the start command does,
// with the environment's http_proxy neutralized: the loader falls back to it
// when the config file says nothing, and the test box must not be able to
// turn "auto, no proxy" into "forced tcp" by leaking a variable in. An argv
// means the flags come from the real ParseArgs; otherwise the options are
// built directly.
func loadTransportConfig(t *testing.T, configPath string, argv ...string) (*Configuration, error) {
	t.Helper()
	t.Setenv("http_proxy", "")

	opts := &Options{config: configPath, command: "start", args: []string{"web"}}
	if len(argv) > 0 {
		// parseArgs t.Fatals on a parse failure of its own; its second
		// return is the usage text, which these tests have no use for.
		opts, _ = parseArgs(t, argv)
	}
	return LoadConfiguration(opts)
}

// TestProxyTransportConfigValidation is the enum table (SPEC-CLUSTER7 8-B):
// every value the loader must accept, the normalization it applies, and the
// loud refusal a typo gets. The error cases are the point of the feature's
// configuration: a transport setting that silently means something else would
// only ever be noticed as traffic on the wrong carrier.
func TestProxyTransportConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    string
		wantErr string
	}{
		{name: "absent key means auto", value: "", want: ProxyTransportAuto},
		{name: "auto", value: "auto", want: ProxyTransportAuto},
		{name: "quic", value: "quic", want: ProxyTransportQuic},
		{name: "tcp", value: "tcp", want: ProxyTransportTCP},
		{name: "case and space normalized", value: "  QUIC ", want: ProxyTransportQuic},
		{
			name:    "typo refused",
			value:   "grpc",
			wantErr: "proxy_transport must be one of 'auto', 'quic' or 'tcp'",
		},
		{
			name:    "compound value refused",
			value:   "auto,tcp",
			wantErr: "proxy_transport must be one of",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			configPath := writeConfig(t, transportConfigYAML(tc.value))

			config, err := loadTransportConfig(t, configPath)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("proxy_transport %q loaded; want refusal naming the enum", tc.value)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error %q does not name the accepted values (%q)", err.Error(), tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("proxy_transport %q refused: %v", tc.value, err)
			}

			if config.ProxyTransport != tc.want {
				t.Fatalf("proxy_transport %q resolved to %q, want %q", tc.value, config.ProxyTransport, tc.want)
			}
		})
	}
}

// TestProxyTransportFlagOverridesConfigFile pins the precedence (SPEC-CLUSTER7
// 5): the flag wins when given, the file stands when the flag is at its empty
// default, and a typo'd flag value is the same startup error a typo'd file
// value gets -- the validation runs after the override, so there is exactly
// one road to a bad transport and it is named either way. The flag is parsed
// through the real ParseArgs, because its empty default (rather than "auto")
// is what makes "flag not given" distinguishable from "flag said auto".
func TestProxyTransportFlagOverridesConfigFile(t *testing.T) {
	t.Run("flag wins over file", func(t *testing.T) {
		configPath := writeConfig(t, transportConfigYAML("tcp"))
		config, err := loadTransportConfig(t, configPath,
			"ngrok", "-config", configPath, "-proxy-transport=quic", "8080")
		if err != nil {
			t.Fatalf("-proxy-transport=quic refused: %v", err)
		}
		if got := config.ProxyTransport; got != ProxyTransportQuic {
			t.Fatalf("the flag was overridden by the file: got %q, want %q", got, ProxyTransportQuic)
		}
	})

	t.Run("file stands when flag absent", func(t *testing.T) {
		configPath := writeConfig(t, transportConfigYAML("tcp"))
		config, err := loadTransportConfig(t, configPath,
			"ngrok", "-config", configPath, "8080")
		if err != nil {
			t.Fatalf("config file value refused: %v", err)
		}
		if got := config.ProxyTransport; got != ProxyTransportTCP {
			t.Fatalf("the file value lost: got %q, want %q", got, ProxyTransportTCP)
		}
	})

	t.Run("neither means auto", func(t *testing.T) {
		configPath := writeConfig(t, transportConfigYAML(""))
		config, err := loadTransportConfig(t, configPath,
			"ngrok", "-config", configPath, "8080")
		if err != nil {
			t.Fatalf("the default refused: %v", err)
		}
		if got := config.ProxyTransport; got != ProxyTransportAuto {
			t.Fatalf("the default is %q, want %q", got, ProxyTransportAuto)
		}
	})

	t.Run("typo'd flag refused with the enum", func(t *testing.T) {
		configPath := writeConfig(t, transportConfigYAML(""))
		_, err := loadTransportConfig(t, configPath,
			"ngrok", "-config", configPath, "-proxy-transport=grpc", "8080")
		if err == nil {
			t.Fatal("a typo'd flag value loaded; want the startup error")
		}
		if !strings.Contains(err.Error(), "proxy_transport must be one of") {
			t.Fatalf("error %q does not name the flag's enum", err.Error())
		}
	})
}

// TestNewClientModelResolvesProxyTransport covers the construction-time
// resolution: the validated string becomes the model's enum, and http_proxy
// forces TCP with the override logged -- for auto (whose QUIC preference the
// proxy silently defeats) and for an explicit quic (which the operator asked
// for by name) alike, but not for tcp, which is already what the operator
// asked for and would only be noise. This is the unit half of the selection
// matrix's "http_proxy -> tcp" row: by the time quicTransportAllowed runs,
// the override has already happened here.
func TestNewClientModelResolvesProxyTransport(t *testing.T) {
	tests := []struct {
		name      string
		transport string
		httpProxy string
		want      proxyTransport
	}{
		{name: "auto", transport: ProxyTransportAuto, want: proxyTransportAuto},
		{name: "quic", transport: ProxyTransportQuic, want: proxyTransportQuic},
		{name: "tcp", transport: ProxyTransportTCP, want: proxyTransportTCP},
		{name: "absent means auto", transport: "", want: proxyTransportAuto},
		{
			name:      "http_proxy overrides auto",
			httpProxy: "http://corp-proxy.test:3128",
			want:      proxyTransportTCP,
		},
		{
			name:      "http_proxy overrides explicit quic",
			transport: ProxyTransportQuic,
			httpProxy: "http://corp-proxy.test:3128",
			want:      proxyTransportTCP,
		},
		{
			name:      "http_proxy with tcp stays tcp",
			transport: ProxyTransportTCP,
			httpProxy: "http://corp-proxy.test:3128",
			want:      proxyTransportTCP,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("http_proxy", "")
			config := &Configuration{
				ServerAddr:     "ngrokd.test:443",
				ProxyTransport: tc.transport,
				HttpProxy:      tc.httpProxy,
			}

			model := newClientModel(config, nil)
			if model.proxyTransport != tc.want {
				t.Fatalf("resolved transport %v, want %v", model.proxyTransport, tc.want)
			}

			// The capability half of the decision composes with whatever the
			// resolution produced: without the capability recorded (the zero
			// value, what a model that never ran a control session holds)
			// QUIC is never allowed, and with it recorded the resolved
			// transport alone decides.
			if model.quicTransportAllowed() {
				t.Fatal("QUIC allowed with no capability recorded")
			}
			model.quicPeerCap.Store(true)
			if got := model.quicTransportAllowed(); got != (tc.want != proxyTransportTCP) {
				t.Fatalf("quicTransportAllowed() with capability recorded = %v (resolved transport %v)", got, tc.want)
			}
		})
	}
}

// TestProxyTransportFlagWithoutConfigFile still loads: the transport setting
// is optional by design, and the flag-only invocation -- no config file at
// all -- must reach the model. HOME is pointed at an empty temp dir, because
// that is where the loader looks when -config is not given: a missing
// $HOME/.ngrok is the "no config file" state, and the loader treats it as
// defaults (it only becomes fatal when -config names a missing file
// explicitly, which is a different test that this one is careful not to
// become).
func TestProxyTransportFlagWithoutConfigFile(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("http_proxy", "")

	opts, _ := parseArgs(t, []string{"ngrok", "-proxy-transport=tcp", "8080"})
	config, err := LoadConfiguration(opts)
	if err != nil {
		t.Fatalf("the flag-only invocation refused: %v", err)
	}
	if got := config.ProxyTransport; got != ProxyTransportTCP {
		t.Fatalf("flag-only transport = %q, want %q", got, ProxyTransportTCP)
	}
}
