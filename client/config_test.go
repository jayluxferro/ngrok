package client

import (
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v1"
)

// Tests for the config-file and command-line surface of the header-manipulation
// feature (SPEC section 8, workstream B). What the header policy does to bytes on
// the wire is package rewriter's business; these tests only prove that the YAML
// keys and the repeatable flags arrive intact, that the CLI "default" tunnel gets
// them, and that bad input fails loudly at load time instead of on the wire.

// headerTunnelYAML exercises every new key at once.
const headerTunnelYAML = `
tunnels:
  web:
    proto:
      http: 127.0.0.1:8080
    host_header: rewrite
    request_header:
      add:
        - "X-Custom: value"
        - "X-Colon: a:b:c"
      remove:
        - "X-Secret"
    response_header:
      add:
        - "X-Served-By: ngrok"
      remove:
        - "Server"
`

// tunnelYAML builds a one-tunnel config file with extraLines spliced in as
// (already indented) lines inside the tunnel. tunnelYAML() with no lines is the
// same config as before this feature existed.
func tunnelYAML(extraLines ...string) string {
	lines := []string{
		"tunnels:",
		"  web:",
		"    proto:",
		"      http: 127.0.0.1:8080",
	}
	lines = append(lines, extraLines...)

	return strings.Join(lines, "\n") + "\n"
}

func writeConfig(t *testing.T, contents string) string {
	t.Helper()

	configPath := filepath.Join(t.TempDir(), "ngrok.yml")
	if err := os.WriteFile(configPath, []byte(contents), 0600); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	return configPath
}

// parseArgs runs ParseArgs against a private FlagSet, so the test binary's own
// flags (and anything a previous test registered) cannot leak into the parse.
// ParseArgs works on the flag package's global state, so CommandLine and os.Args
// are swapped for the duration of the call and restored afterwards. The usage
// text that PrintDefaults would produce is returned alongside the options.
func parseArgs(t *testing.T, argv []string) (*Options, string) {
	t.Helper()

	prevCommandLine, prevArgs := flag.CommandLine, os.Args
	flag.CommandLine = flag.NewFlagSet(argv[0], flag.ContinueOnError)
	os.Args = argv
	var usage strings.Builder
	flag.CommandLine.SetOutput(&usage)
	defer func() {
		flag.CommandLine, os.Args = prevCommandLine, prevArgs
	}()

	opts, err := ParseArgs()
	if err != nil {
		t.Fatalf("ParseArgs(%v) failed: %v", argv[1:], err)
	}

	flag.CommandLine.PrintDefaults()

	return opts, usage.String()
}

func TestHeaderConfigYAMLRoundTrip(t *testing.T) {
	config := new(Configuration)
	if err := yaml.Unmarshal([]byte(headerTunnelYAML), config); err != nil {
		t.Fatalf("failed to unmarshal header config: %v", err)
	}

	tunnel, ok := config.Tunnels["web"]
	if !ok {
		t.Fatalf("expected a tunnel named web, got %d tunnels", len(config.Tunnels))
	}

	if tunnel.HostHeader != "rewrite" {
		t.Fatalf("host_header: expected rewrite, got %q", tunnel.HostHeader)
	}
	if tunnel.RequestHeader == nil || tunnel.ResponseHeader == nil {
		t.Fatalf("expected both header sections to be present, got %+v", tunnel)
	}
	if want := []string{"X-Custom: value", "X-Colon: a:b:c"}; !reflect.DeepEqual(tunnel.RequestHeader.Add, want) {
		t.Fatalf("request_header.add: expected %v, got %v", want, tunnel.RequestHeader.Add)
	}
	if want := []string{"X-Secret"}; !reflect.DeepEqual(tunnel.RequestHeader.Remove, want) {
		t.Fatalf("request_header.remove: expected %v, got %v", want, tunnel.RequestHeader.Remove)
	}
	if want := []string{"X-Served-By: ngrok"}; !reflect.DeepEqual(tunnel.ResponseHeader.Add, want) {
		t.Fatalf("response_header.add: expected %v, got %v", want, tunnel.ResponseHeader.Add)
	}
	if want := []string{"Server"}; !reflect.DeepEqual(tunnel.ResponseHeader.Remove, want) {
		t.Fatalf("response_header.remove: expected %v, got %v", want, tunnel.ResponseHeader.Remove)
	}

	// The policy also has to survive a marshal/unmarshal cycle: SaveAuthToken
	// rewrites the config file through yaml.Marshal, and users edit configs with
	// tools that re-emit them.
	marshaled, err := yaml.Marshal(config)
	if err != nil {
		t.Fatalf("failed to marshal config: %v", err)
	}
	for _, key := range []string{"host_header: rewrite", "request_header:", "response_header:", "add:", "remove:"} {
		if !strings.Contains(string(marshaled), key) {
			t.Fatalf("marshaled config is missing %q:\n%s", key, marshaled)
		}
	}

	reloaded := new(Configuration)
	if err := yaml.Unmarshal(marshaled, reloaded); err != nil {
		t.Fatalf("failed to re-unmarshal marshaled config: %v", err)
	}
	if again := reloaded.Tunnels["web"]; !reflect.DeepEqual(tunnel, again) {
		t.Fatalf("round trip changed the tunnel:\n before: %+v\nafter: %+v", tunnel, again)
	}
}

// TestYAMLWithoutHeaderKeysRoundTrip is the other half of the round trip: a
// config that says nothing about headers must not grow header keys when it is
// re-marshaled (the new fields are omitempty).
func TestYAMLWithoutHeaderKeysRoundTrip(t *testing.T) {
	config := new(Configuration)
	if err := yaml.Unmarshal([]byte(tunnelYAML()), config); err != nil {
		t.Fatalf("failed to unmarshal config: %v", err)
	}

	marshaled, err := yaml.Marshal(config)
	if err != nil {
		t.Fatalf("failed to marshal config: %v", err)
	}
	if strings.Contains(string(marshaled), "header") {
		t.Fatalf("no header keys should be emitted when none were configured:\n%s", marshaled)
	}

	reloaded := new(Configuration)
	if err := yaml.Unmarshal(marshaled, reloaded); err != nil {
		t.Fatalf("failed to re-unmarshal marshaled config: %v", err)
	}
	tunnel := reloaded.Tunnels["web"]
	if tunnel.HostHeader != "" || tunnel.RequestHeader != nil || tunnel.ResponseHeader != nil {
		t.Fatalf("expected an empty header policy, got %+v", tunnel)
	}
}

// TestLoadConfigurationHeaderValidation drives the rejections through the real
// entry point, so it also proves the validation is wired into LoadConfiguration
// and not just available as an unused helper.
func TestLoadConfigurationHeaderValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		wantErr string
	}{
		{
			name:   "no header configuration at all",
			config: tunnelYAML(),
		},
		{
			name:   "host_header rewrite",
			config: tunnelYAML("    host_header: rewrite"),
		},
		{
			name:   "host_header preserve",
			config: tunnelYAML("    host_header: preserve"),
		},
		{
			name:   "host_header explicit hostname",
			config: tunnelYAML("    host_header: ollama.internal"),
		},
		{
			name: "valid add/remove entries",
			config: tunnelYAML(
				"    host_header: rewrite",
				"    request_header:",
				"      add:",
				"        - \"X-Custom: value\"",
				"        - \"X-Url: http://example.com/path\"",
				"      remove:",
				"        - \"X-Secret\"",
				"    response_header:",
				"      add:",
				"        - \"X-Served-By: ngrok\"",
				"      remove:",
				"        - \"Server\"",
			),
		},
		{
			name:    "host_header with a space",
			config:  tunnelYAML("    host_header: \"two words\""),
			wantErr: "invalid host_header",
		},
		{
			name:    "host_header with a slash",
			config:  tunnelYAML("    host_header: \"evil.com/path\""),
			wantErr: "invalid host_header",
		},
		{
			name:    "host_header with CR LF",
			config:  tunnelYAML("    host_header: \"evil.com\\r\\nX-Injected: 1\""),
			wantErr: "invalid host_header",
		},
		{
			name: "add entry without a colon",
			config: tunnelYAML(
				"    request_header:",
				"      add:",
				"        - \"X-Custom\"",
			),
			wantErr: "must be formatted as 'key:value'",
		},
		{
			name: "add entry with an empty key",
			config: tunnelYAML(
				"    request_header:",
				"      add:",
				"        - \": value\"",
			),
			wantErr: "empty header name",
		},
		{
			name: "add entry whose key is not an RFC 7230 token",
			config: tunnelYAML(
				"    request_header:",
				"      add:",
				"        - \"X Custom: value\"",
			),
			wantErr: "is not a valid HTTP header name",
		},
		{
			name: "remove entry whose key is not an RFC 7230 token",
			config: tunnelYAML(
				"    response_header:",
				"      remove:",
				"        - \"Bad Key\"",
			),
			wantErr: "is not a valid HTTP header name",
		},
		{
			name: "add value containing CR LF",
			config: tunnelYAML(
				"    request_header:",
				"      add:",
				"        - \"X-Custom: value\\r\\nX-Injected: 1\"",
			),
			wantErr: "contains a CR or LF",
		},
		{
			name: "remove entry containing CR LF",
			config: tunnelYAML(
				"    response_header:",
				"      remove:",
				"        - \"X-Secret\\r\\nX-Injected\"",
			),
			wantErr: "contains a CR or LF",
		},
		{
			name: "user-agent may not be added",
			config: tunnelYAML(
				"    request_header:",
				"      add:",
				"        - \"User-Agent: not-a-real-client\"",
			),
			wantErr: "user-agent may not be added or removed",
		},
		{
			name: "user-agent may not be removed, whatever the case",
			config: tunnelYAML(
				"    response_header:",
				"      remove:",
				"        - \"user-agent\"",
			),
			wantErr: "user-agent may not be added or removed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configPath := writeConfig(t, tt.config)
			_, err := LoadConfiguration(&Options{config: configPath, command: "start", args: []string{"web"}})

			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("expected the config to load, got: %v", err)
				}
				return
			}

			if err == nil {
				t.Fatalf("expected an error containing %q, got none", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error should mention %q, got: %v", tt.wantErr, err)
			}
			// Failing loudly also means saying which tunnel is at fault.
			if !strings.Contains(err.Error(), "web") {
				t.Fatalf("error should name the offending tunnel, got: %v", err)
			}
		})
	}
}

func TestHeaderValidationNamesOffendingTunnel(t *testing.T) {
	configPath := writeConfig(t, `
tunnels:
  good:
    proto:
      http: 127.0.0.1:8080
    host_header: preserve
  bad:
    proto:
      http: 127.0.0.1:8081
    request_header:
      add:
        - "X-Missing-Colon"
`)

	_, err := LoadConfiguration(&Options{config: configPath, command: "start", args: []string{"good", "bad"}})
	if err == nil {
		t.Fatalf("expected the bad tunnel to be rejected")
	}
	if !strings.Contains(err.Error(), "bad") {
		t.Fatalf("error should name the offending tunnel, got: %v", err)
	}
	if strings.Contains(err.Error(), "Tunnel good") {
		t.Fatalf("error should not blame the good tunnel, got: %v", err)
	}
}

func TestLoadConfigurationHeaderTunnel(t *testing.T) {
	configPath := writeConfig(t, headerTunnelYAML)

	config, err := LoadConfiguration(&Options{config: configPath, command: "start", args: []string{"web"}})
	if err != nil {
		t.Fatalf("expected the config to load, got: %v", err)
	}

	tunnel, ok := config.Tunnels["web"]
	if !ok {
		t.Fatalf("expected a tunnel named web, got %d tunnels", len(config.Tunnels))
	}

	if tunnel.HostHeader != "rewrite" {
		t.Fatalf("host_header did not survive loading: %q", tunnel.HostHeader)
	}
	if want := []string{"X-Custom: value", "X-Colon: a:b:c"}; !reflect.DeepEqual(tunnel.RequestHeader.Add, want) {
		t.Fatalf("request_header.add: expected %v, got %v", want, tunnel.RequestHeader.Add)
	}
	if want := []string{"Server"}; !reflect.DeepEqual(tunnel.ResponseHeader.Remove, want) {
		t.Fatalf("response_header.remove: expected %v, got %v", want, tunnel.ResponseHeader.Remove)
	}
}

// TestDefaultTunnelHeaderSynthesis covers the config.go wiring: the flags are
// copied onto the tunnel that LoadConfiguration synthesizes for the simple
// "ngrok <port>" invocation.
func TestDefaultTunnelHeaderSynthesis(t *testing.T) {
	configPath := writeConfig(t, "server_addr: \"tunnel.example.com:443\"\n")

	config, err := LoadConfiguration(&Options{
		config:               configPath,
		command:              "default",
		args:                 []string{"8080"},
		protocol:             "http",
		hostHeader:           "rewrite",
		requestHeaderAdd:     stringList{"X-One: 1", "X-One: 2"},
		requestHeaderRemove:  stringList{"X-Secret"},
		responseHeaderAdd:    stringList{"X-Served-By: ngrok"},
		responseHeaderRemove: stringList{"Server"},
	})
	if err != nil {
		t.Fatalf("expected the default tunnel to load, got: %v", err)
	}

	tunnel, ok := config.Tunnels["default"]
	if !ok {
		t.Fatalf("expected a synthesized default tunnel, got %d tunnels", len(config.Tunnels))
	}
	if tunnel.Protocols["http"] != "127.0.0.1:8080" {
		t.Fatalf("unexpected local address: %v", tunnel.Protocols)
	}
	if tunnel.HostHeader != "rewrite" {
		t.Fatalf("host_header: expected rewrite, got %q", tunnel.HostHeader)
	}
	if want := []string{"X-One: 1", "X-One: 2"}; !reflect.DeepEqual(tunnel.RequestHeader.Add, want) {
		t.Fatalf("request_header.add: expected %v, got %v", want, tunnel.RequestHeader.Add)
	}
	if want := []string{"X-Secret"}; !reflect.DeepEqual(tunnel.RequestHeader.Remove, want) {
		t.Fatalf("request_header.remove: expected %v, got %v", want, tunnel.RequestHeader.Remove)
	}
	if want := []string{"X-Served-By: ngrok"}; !reflect.DeepEqual(tunnel.ResponseHeader.Add, want) {
		t.Fatalf("response_header.add: expected %v, got %v", want, tunnel.ResponseHeader.Add)
	}
	if want := []string{"Server"}; !reflect.DeepEqual(tunnel.ResponseHeader.Remove, want) {
		t.Fatalf("response_header.remove: expected %v, got %v", want, tunnel.ResponseHeader.Remove)
	}
}

func TestDefaultTunnelHeaderSynthesisRejectsBadValues(t *testing.T) {
	configPath := writeConfig(t, "server_addr: \"tunnel.example.com:443\"\n")

	_, err := LoadConfiguration(&Options{
		config:     configPath,
		command:    "default",
		args:       []string{"8080"},
		protocol:   "http",
		hostHeader: "two words",
	})
	if err == nil {
		t.Fatalf("expected an invalid -host-header to be rejected")
	}
	if !strings.Contains(err.Error(), "invalid host_header") || !strings.Contains(err.Error(), "default") {
		t.Fatalf("error should name the default tunnel and the bad value, got: %v", err)
	}
}

// A user who sets no header flags must get exactly the tunnel they got before
// this feature existed: nil header sections, not empty ones.
func TestDefaultTunnelWithoutHeaderFlags(t *testing.T) {
	configPath := writeConfig(t, "server_addr: \"tunnel.example.com:443\"\n")

	config, err := LoadConfiguration(&Options{
		config:   configPath,
		command:  "default",
		args:     []string{"8080"},
		protocol: "http",
	})
	if err != nil {
		t.Fatalf("expected the default tunnel to load, got: %v", err)
	}

	tunnel := config.Tunnels["default"]
	if tunnel == nil {
		t.Fatalf("expected a synthesized default tunnel")
	}
	if tunnel.HostHeader != "" || tunnel.RequestHeader != nil || tunnel.ResponseHeader != nil {
		t.Fatalf("no header flags should leave the tunnel untouched, got %+v", tunnel)
	}
}

// TestRepeatableHeaderFlagParsing is the core flag test: the add/remove flags
// must accumulate every occurrence, in order, and mixed -flag=value / -flag value
// spellings must behave identically.
func TestRepeatableHeaderFlagParsing(t *testing.T) {
	opts, _ := parseArgs(t, []string{
		"ngrok",
		"-host-header", "rewrite",
		"-request-header-add", "X-One: 1",
		"-request-header-add=X-Two: 2",
		"-request-header-remove", "X-Secret",
		"-response-header-add", "X-Served-By: ngrok",
		"-response-header-remove", "Server",
		"8080",
	})

	if opts.hostHeader != "rewrite" {
		t.Fatalf("host_header: expected rewrite, got %q", opts.hostHeader)
	}
	if want := (stringList{"X-One: 1", "X-Two: 2"}); !reflect.DeepEqual(opts.requestHeaderAdd, want) {
		t.Fatalf("request-header-add: expected %v, got %v", want, opts.requestHeaderAdd)
	}
	if want := (stringList{"X-Secret"}); !reflect.DeepEqual(opts.requestHeaderRemove, want) {
		t.Fatalf("request-header-remove: expected %v, got %v", want, opts.requestHeaderRemove)
	}
	if want := (stringList{"X-Served-By: ngrok"}); !reflect.DeepEqual(opts.responseHeaderAdd, want) {
		t.Fatalf("response-header-add: expected %v, got %v", want, opts.responseHeaderAdd)
	}
	if want := (stringList{"Server"}); !reflect.DeepEqual(opts.responseHeaderRemove, want) {
		t.Fatalf("response-header-remove: expected %v, got %v", want, opts.responseHeaderRemove)
	}

	// The positional argument handling is unchanged by the new flags.
	if opts.command != "default" {
		t.Fatalf("command: expected default, got %q", opts.command)
	}
	if len(opts.args) != 1 || opts.args[0] != "8080" {
		t.Fatalf("args: expected [8080], got %v", opts.args)
	}
}

// TestHeaderFlagParsingDefaults guards the other direction: without the flags,
// nothing accumulates and the old behavior is preserved.
func TestHeaderFlagParsingDefaults(t *testing.T) {
	opts, _ := parseArgs(t, []string{"ngrok", "8080"})

	if opts.hostHeader != "" {
		t.Fatalf("host_header should default to empty, got %q", opts.hostHeader)
	}
	for name, list := range map[string]stringList{
		"request-header-add":     opts.requestHeaderAdd,
		"request-header-remove":  opts.requestHeaderRemove,
		"response-header-add":    opts.responseHeaderAdd,
		"response-header-remove": opts.responseHeaderRemove,
	} {
		if len(list) != 0 {
			t.Fatalf("-%s should default to empty, got %v", name, list)
		}
	}
}

// TestHeaderFlagsAreRegistered checks the flags exist and carry help text: a flag
// nobody can discover in the usage output is as good as missing.
func TestHeaderFlagsAreRegistered(t *testing.T) {
	_, usage := parseArgs(t, []string{"ngrok", "8080"})

	for _, name := range []string{
		"host-header",
		"request-header-add",
		"request-header-remove",
		"response-header-add",
		"response-header-remove",
	} {
		if !strings.Contains(usage, "-"+name) {
			t.Fatalf("flag -%s is missing from the usage output:\n%s", name, usage)
		}
	}

	if !strings.Contains(usage, "key:value") {
		t.Fatalf("usage output should explain the key:value format:\n%s", usage)
	}
}

func TestStringListFlagValue(t *testing.T) {
	var l stringList
	var _ flag.Value = &l

	if got := l.String(); got != "" {
		t.Fatalf("an empty stringList should print as the empty string, got %q", got)
	}

	for _, value := range []string{"X-One: 1", "X-Two: 2"} {
		if err := l.Set(value); err != nil {
			t.Fatalf("Set(%q) returned an error: %v", value, err)
		}
	}

	if want := []string{"X-One: 1", "X-Two: 2"}; !reflect.DeepEqual([]string(l), want) {
		t.Fatalf("expected %v, got %v", want, l)
	}
	if want := "X-One: 1,X-Two: 2"; l.String() != want {
		t.Fatalf("String(): expected %q, got %q", want, l.String())
	}
}
