package client

import (
	"flag"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"ngrok/rewriter"
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

// TestHeaderValidationIsTheWriters is the differential test for the one-gate
// property this package gained when its header rules were deleted in favour of
// package rewriter's: what the loader accepts and what rewriter.Policy.Validate
// accepts have to be the same set, value for value.
//
// It is written as a comparison against rewriter's own validators rather than
// as a table of messages on purpose. A table only pins the cases someone
// thought of, and the old failure mode was not a wrong message: it was two
// copies of the rules that agreed on every case anyone had written down and
// were free to disagree on the rest -- so a tunnel could load and then be
// written to the wire by a code path whose own rules would have refused it
// (the fuzzing report's R1). Comparing the two gates directly is what makes a
// freshly reintroduced second copy fail this test.
func TestHeaderValidationIsTheWriters(t *testing.T) {
	hostHeaders := []string{
		"",
		"rewrite",
		"preserve",
		"REWRITE", // the keywords are case-insensitive at write time
		"host.example",
		"host.example:8080",
		"bad host",
		"evil.example/path",
		"evil.example\r\nX-Injected: 1",
		"\t",
	}

	for _, hostHeader := range hostHeaders {
		t.Run("host_header "+strconv.Quote(hostHeader), func(t *testing.T) {
			configPath := writeConfig(t, tunnelYAML("    host_header: "+strconv.Quote(hostHeader)))
			_, err := LoadConfiguration(&Options{config: configPath, command: "start", args: []string{"web"}})

			wantErr := rewriter.ValidateHostHeader(hostHeader) != nil
			if wantErr != (err != nil) {
				t.Fatalf("load of host_header %q returned %v; rewriter.ValidateHostHeader says it %s valid",
					hostHeader, err, map[bool]string{true: "is not", false: "is"}[wantErr])
			}
		})
	}

	entries := []string{
		"X-A: b",
		"X-Url: http://localhost:8080/x",
		"X-Colon: a:b:c",
		"X-A",
		": value",
		"   : value",
		"X Bad: v",
		"X-A: b\r\nX-Injected: 1",
		"User-Agent: not-a-real-client",
		"user-agent",
		"",
	}

	for _, entry := range entries {
		t.Run("add "+strconv.Quote(entry), func(t *testing.T) {
			configPath := writeConfig(t, tunnelYAML("    request_header:", "      add:", "        - "+strconv.Quote(entry)))
			_, err := LoadConfiguration(&Options{config: configPath, command: "start", args: []string{"web"}})

			wantErr := rewriter.ValidateAddEntry("request_header", entry) != nil
			if wantErr != (err != nil) {
				t.Fatalf("load of add entry %q returned %v; rewriter.ValidateAddEntry says it %s usable",
					entry, err, map[bool]string{true: "is not", false: "is"}[wantErr])
			}
		})

		t.Run("remove "+strconv.Quote(entry), func(t *testing.T) {
			configPath := writeConfig(t, tunnelYAML("    response_header:", "      remove:", "        - "+strconv.Quote(entry)))
			_, err := LoadConfiguration(&Options{config: configPath, command: "start", args: []string{"web"}})

			wantErr := rewriter.ValidateRemoveName("response_header", entry) != nil
			if wantErr != (err != nil) {
				t.Fatalf("load of remove entry %q returned %v; rewriter.ValidateRemoveName says it %s usable",
					entry, err, map[bool]string{true: "is not", false: "is"}[wantErr])
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

// Tests for the cluster-2 endpoint surface (SPEC 4-C): the -binding, -pooling,
// -forward-to and -compression flags, the equivalent per-tunnel config keys,
// and the validation that keeps a misconfigured endpoint from failing silently
// at request time instead of at startup.

// endpointTunnelYAML builds a one-tunnel ("web") config file with the given
// proto lines spliced in under "proto:" and extraLines spliced in as (already
// indented) tunnel lines.
func endpointTunnelYAML(protoLines []string, extraLines ...string) string {
	lines := []string{
		"tunnels:",
		"  web:",
		"    proto:",
	}
	lines = append(lines, protoLines...)
	lines = append(lines, extraLines...)

	return strings.Join(lines, "\n") + "\n"
}

// The two proto sections the endpoint cases use. The http one is what
// tunnelYAML() bakes in; the tcp one exists because the tcp cases need a tunnel
// the endpoint settings are not valid for.
var (
	httpProtoLines = []string{"      http: 127.0.0.1:8080"}
	tcpProtoLines  = []string{"      tcp: 127.0.0.1:8080"}
)

// cluster2TunnelYAML exercises every new key at once, on the two kinds of
// tunnel that use them: an internal endpoint, and a public endpoint that
// forwards to it.
const cluster2TunnelYAML = `
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
    forward_to: https://svc.internal
    pooling: true
    compression: false
`

// TestNegativeLimitKeysAreLoadErrors covers the two numeric keys that carry a
// default: a negative value used to be clamped to the default in silence, so a
// file that asked for a negative limit loaded as if it had asked for the
// default and nothing was said. Both keys are limits -- how much body the
// inspector keeps, how many proxied connections run at once -- and a limit the
// operator did not choose is exactly the kind of thing that is noticed only
// under load.
func TestNegativeLimitKeysAreLoadErrors(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		value   string
		wantErr string
	}{
		{"negative inspect_max_body_bytes", "inspect_max_body_bytes", "-1", "inspect_max_body_bytes must not be negative"},
		{"negative proxy_max_concurrency", "proxy_max_concurrency", "-1", "proxy_max_concurrency must not be negative"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configPath := writeConfig(t, "server_addr: \"tunnel.example.com:443\"\n"+tt.key+": "+tt.value+"\n")

			_, err := LoadConfiguration(&Options{
				config:   configPath,
				command:  "default",
				args:     []string{"8080"},
				protocol: "http",
			})
			if err == nil {
				t.Fatalf("expected %s: %s to be a load error", tt.key, tt.value)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected the error to mention %q, got: %v", tt.wantErr, err)
			}
			// The message has to tell the operator the way out, since the
			// value they wrote is what they get told about.
			if !strings.Contains(err.Error(), tt.value) || !strings.Contains(err.Error(), "omit the key") {
				t.Fatalf("expected the error to quote the value and say what to do instead, got: %v", err)
			}
		})
	}
}

// TestLimitKeysDefaultAndExplicitValues is the other half: absent, explicitly
// zero and explicitly set all have to behave, because 0 is not a
// distinguishable "unset" for either key -- it means "the default" here, and
// the load errors above are what keeps a real 0 from being confused with a
// mistake.
func TestLimitKeysDefaultAndExplicitValues(t *testing.T) {
	tests := []struct {
		name         string
		lines        string
		wantBodySize int64
		wantWorkers  int
	}{
		{"absent", "", 1024 * 1024, 64},
		{"explicit zero", "inspect_max_body_bytes: 0\nproxy_max_concurrency: 0\n", 1024 * 1024, 64},
		{"explicit values", "inspect_max_body_bytes: 4096\nproxy_max_concurrency: 8\n", 4096, 8},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configPath := writeConfig(t, "server_addr: \"tunnel.example.com:443\"\n"+tt.lines)

			config, err := LoadConfiguration(&Options{
				config:   configPath,
				command:  "default",
				args:     []string{"8080"},
				protocol: "http",
			})
			if err != nil {
				t.Fatalf("expected the config to load, got: %v", err)
			}
			if config.InspectMaxBodySize != tt.wantBodySize {
				t.Errorf("InspectMaxBodySize: expected %d, got %d", tt.wantBodySize, config.InspectMaxBodySize)
			}
			if config.ProxyMaxConcurrent != tt.wantWorkers {
				t.Errorf("ProxyMaxConcurrent: expected %d, got %d", tt.wantWorkers, config.ProxyMaxConcurrent)
			}
		})
	}
}

func TestEndpointConfigYAMLRoundTrip(t *testing.T) {
	config := new(Configuration)
	if err := yaml.Unmarshal([]byte(cluster2TunnelYAML), config); err != nil {
		t.Fatalf("failed to unmarshal endpoint config: %v", err)
	}

	svc := config.Tunnels["svc"]
	if svc == nil {
		t.Fatalf("expected a tunnel named svc, got %d tunnels", len(config.Tunnels))
	}
	if svc.Binding != "internal" {
		t.Fatalf("binding: expected internal, got %q", svc.Binding)
	}
	if svc.Pooling {
		t.Fatalf("pooling should default to off, got %v", svc.Pooling)
	}
	if svc.ForwardTo != "" {
		t.Fatalf("forward_to should default to empty, got %q", svc.ForwardTo)
	}
	// The compression key is absent here and the default is on (SPEC 3.4), so
	// this is the case that has to distinguish "not configured" from "false".
	if svc.Compression != nil {
		t.Fatalf("an absent compression key should stay nil, got %v", *svc.Compression)
	}
	if !svc.Compress() {
		t.Fatal("compression should default to on")
	}

	web := config.Tunnels["web"]
	if web.Binding != "" {
		t.Fatalf("an absent binding should stay empty, got %q", web.Binding)
	}
	if !web.Pooling {
		t.Fatal("pooling: true did not survive unmarshaling")
	}
	if web.ForwardTo != "https://svc.internal" {
		t.Fatalf("forward_to: expected https://svc.internal, got %q", web.ForwardTo)
	}
	if web.Compression == nil || *web.Compression {
		t.Fatalf("compression: false did not survive unmarshaling: %v", web.Compression)
	}
	if web.Compress() {
		t.Fatal("an explicit compression: false must resolve to off")
	}

	// The keys also have to survive a marshal/unmarshal cycle: SaveAuthToken
	// rewrites the config file through yaml.Marshal.
	marshaled, err := yaml.Marshal(config)
	if err != nil {
		t.Fatalf("failed to marshal config: %v", err)
	}
	for _, key := range []string{"binding: internal", "forward_to: https://svc.internal", "pooling: true", "compression: false"} {
		if !strings.Contains(string(marshaled), key) {
			t.Fatalf("marshaled config is missing %q:\n%s", key, marshaled)
		}
	}

	reloaded := new(Configuration)
	if err := yaml.Unmarshal(marshaled, reloaded); err != nil {
		t.Fatalf("failed to re-unmarshal marshaled config: %v", err)
	}
	if again := reloaded.Tunnels["svc"]; !reflect.DeepEqual(svc, again) {
		t.Fatalf("round trip changed the internal tunnel:\n before: %+v\nafter: %+v", svc, again)
	}
	if again := reloaded.Tunnels["web"]; !reflect.DeepEqual(web, again) {
		t.Fatalf("round trip changed the forwarding tunnel:\n before: %+v\nafter: %+v", web, again)
	}
}

// TestYAMLWithoutEndpointKeysRoundTrip is the other half: a config that says
// nothing about endpoints must not grow any of the new keys when it is
// re-marshaled (they are all omitempty), and must still read as
// compression-on.
func TestYAMLWithoutEndpointKeysRoundTrip(t *testing.T) {
	config := new(Configuration)
	if err := yaml.Unmarshal([]byte(tunnelYAML()), config); err != nil {
		t.Fatalf("failed to unmarshal config: %v", err)
	}

	marshaled, err := yaml.Marshal(config)
	if err != nil {
		t.Fatalf("failed to marshal config: %v", err)
	}
	for _, key := range []string{"binding", "pooling", "forward_to", "compression"} {
		if strings.Contains(string(marshaled), key) {
			t.Fatalf("no endpoint keys should be emitted when none were configured (%q appeared):\n%s", key, marshaled)
		}
	}

	reloaded := new(Configuration)
	if err := yaml.Unmarshal(marshaled, reloaded); err != nil {
		t.Fatalf("failed to re-unmarshal marshaled config: %v", err)
	}
	tunnel := reloaded.Tunnels["web"]
	if tunnel.Binding != "" || tunnel.Pooling || tunnel.ForwardTo != "" {
		t.Fatalf("expected no endpoint settings, got %+v", tunnel)
	}
	if !tunnel.Compress() {
		t.Fatal("a config with no compression key must load with compression on")
	}
}

// TestLoadConfigurationEndpointValidation drives the endpoint rejections
// through the real entry point, so it also proves the validation is wired into
// LoadConfiguration for config-file tunnels and not just available as an
// unused helper.
func TestLoadConfigurationEndpointValidation(t *testing.T) {
	tests := []struct {
		name    string
		proto   []string
		lines   []string
		wantErr string
	}{
		{
			name:  "no endpoint configuration at all",
			proto: httpProtoLines,
		},
		{
			name:  "binding public is the default spelled out",
			proto: httpProtoLines,
			lines: []string{"    binding: public"},
		},
		{
			name:  "binding internal with a hostname",
			proto: httpProtoLines,
			lines: []string{"    hostname: svc.internal", "    binding: internal"},
		},
		{
			name:  "internal endpoint over https",
			proto: []string{"      https: 127.0.0.1:8080"},
			lines: []string{"    hostname: svc.internal", "    binding: internal"},
		},
		{
			name:  "pooling",
			proto: httpProtoLines,
			lines: []string{"    pooling: true"},
		},
		{
			name:  "compression off",
			proto: httpProtoLines,
			lines: []string{"    compression: false"},
		},
		{
			name:  "forward_to to an internal endpoint",
			proto: httpProtoLines,
			lines: []string{"    forward_to: https://svc.internal"},
		},
		{
			name:  "forward_to with a trailing slash is accepted (the server strips it)",
			proto: httpProtoLines,
			lines: []string{"    forward_to: https://svc.internal/"},
		},
		{
			name:    "binding that is not public or internal",
			proto:   httpProtoLines,
			lines:   []string{"    binding: loopback"},
			wantErr: "invalid binding",
		},
		{
			name:    "internal without a hostname",
			proto:   httpProtoLines,
			lines:   []string{"    binding: internal"},
			wantErr: "requires a hostname",
		},
		{
			name:    "internal hostname outside the .internal namespace",
			proto:   httpProtoLines,
			lines:   []string{"    hostname: svc.example.com", "    binding: internal"},
			wantErr: "must end in .internal",
		},
		{
			name:    "internal hostname with uppercase letters",
			proto:   httpProtoLines,
			lines:   []string{"    hostname: Svc.Internal", "    binding: internal"},
			wantErr: "must be lowercase",
		},
		{
			name:    "internal with a subdomain",
			proto:   httpProtoLines,
			lines:   []string{"    subdomain: svc", "    hostname: svc.internal", "    binding: internal"},
			wantErr: "does not support subdomain",
		},
		{
			name:    "internal over tcp",
			proto:   tcpProtoLines,
			lines:   []string{"    hostname: svc.internal", "    binding: internal"},
			wantErr: "only supported for http and https",
		},
		{
			name:    "forward_to without a scheme",
			proto:   httpProtoLines,
			lines:   []string{"    forward_to: svc.internal"},
			wantErr: "forward_to",
		},
		{
			name:    "forward_to with a path",
			proto:   httpProtoLines,
			lines:   []string{"    forward_to: https://svc.internal/foo"},
			wantErr: "forward_to",
		},
		{
			name:    "forward_to with a port",
			proto:   httpProtoLines,
			lines:   []string{"    forward_to: https://svc.internal:443"},
			wantErr: "forward_to",
		},
		{
			name:    "forward_to to a host outside the .internal namespace",
			proto:   httpProtoLines,
			lines:   []string{"    forward_to: https://example.com"},
			wantErr: "forward_to",
		},
		{
			name:    "forward_to on a tcp tunnel",
			proto:   tcpProtoLines,
			lines:   []string{"    forward_to: https://svc.internal"},
			wantErr: "forward_to is only supported for http and https",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configPath := writeConfig(t, endpointTunnelYAML(tt.proto, tt.lines...))
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

// TestEndpointBindingNormalization pins the one value the loader rewrites: a
// tunnel configured with "binding: public" must go on the wire with the empty
// binding the protocol uses for public endpoints, not with "public" (which the
// server would refuse as an unknown binding).
func TestEndpointBindingNormalization(t *testing.T) {
	configPath := writeConfig(t, endpointTunnelYAML(httpProtoLines, "    binding: public"))

	config, err := LoadConfiguration(&Options{config: configPath, command: "start", args: []string{"web"}})
	if err != nil {
		t.Fatalf("expected the config to load, got: %v", err)
	}
	if got := config.Tunnels["web"].Binding; got != "" {
		t.Fatalf("binding: public should be normalized to the empty binding, got %q", got)
	}
}

func TestLoadConfigurationEndpointTunnel(t *testing.T) {
	configPath := writeConfig(t, cluster2TunnelYAML)

	config, err := LoadConfiguration(&Options{config: configPath, command: "start", args: []string{"svc", "web"}})
	if err != nil {
		t.Fatalf("expected the config to load, got: %v", err)
	}

	svc := config.Tunnels["svc"]
	if svc.Binding != "internal" || svc.Hostname != "svc.internal" {
		t.Fatalf("internal tunnel did not survive loading: %+v", svc)
	}
	if !svc.Compress() {
		t.Fatal("the internal tunnel's absent compression key should still mean on")
	}

	web := config.Tunnels["web"]
	if web.ForwardTo != "https://svc.internal" || !web.Pooling {
		t.Fatalf("forwarding tunnel did not survive loading: %+v", web)
	}
	if web.Compress() {
		t.Fatal("compression: false did not survive loading")
	}
}

// TestDefaultTunnelEndpointSynthesis covers the config.go wiring: the flags are
// copied onto the tunnel that LoadConfiguration synthesizes for the simple
// "ngrok <port>" invocation, including the compression default.
func TestDefaultTunnelEndpointSynthesis(t *testing.T) {
	configPath := writeConfig(t, "server_addr: \"tunnel.example.com:443\"\n")

	t.Run("internal endpoint", func(t *testing.T) {
		config, err := LoadConfiguration(&Options{
			config:      configPath,
			command:     "default",
			args:        []string{"8080"},
			protocol:    "http",
			binding:     "internal",
			hostname:    "svc.internal",
			pooling:     true,
			compression: false,
		})
		if err != nil {
			t.Fatalf("expected the default tunnel to load, got: %v", err)
		}

		tunnel := config.Tunnels["default"]
		if tunnel == nil {
			t.Fatal("expected a synthesized default tunnel")
		}
		if tunnel.Binding != "internal" {
			t.Fatalf("binding: expected internal, got %q", tunnel.Binding)
		}
		if tunnel.Hostname != "svc.internal" {
			t.Fatalf("hostname: expected svc.internal, got %q", tunnel.Hostname)
		}
		if !tunnel.Pooling {
			t.Fatal("-pooling did not reach the synthesized tunnel")
		}
		if tunnel.Compress() {
			t.Fatal("-compression=false did not reach the synthesized tunnel")
		}
		if tunnel.Compression == nil {
			t.Fatal("the flag should always set an explicit compression value")
		}
	})

	t.Run("forwarding endpoint", func(t *testing.T) {
		config, err := LoadConfiguration(&Options{
			config:    configPath,
			command:   "default",
			args:      []string{"8080"},
			protocol:  "http",
			forwardTo: "https://svc.internal",
			// Options has no default of its own for this one: ParseArgs fills
			// it from the flag, whose default is on (SPEC 3.4), which is what
			// an invocation that passes no -compression gets.
			compression: true,
		})
		if err != nil {
			t.Fatalf("expected the default tunnel to load, got: %v", err)
		}

		tunnel := config.Tunnels["default"]
		if tunnel.ForwardTo != "https://svc.internal" {
			t.Fatalf("forward_to: expected https://svc.internal, got %q", tunnel.ForwardTo)
		}
		if tunnel.Binding != "" {
			t.Fatalf("a forwarding tunnel is public by default, got binding %q", tunnel.Binding)
		}
		// No -compression=false was passed: on is what a user gets.
		if !tunnel.Compress() {
			t.Fatal("compression should be on for a tunnel started without -compression=false")
		}
	})
}

func TestDefaultTunnelEndpointSynthesisRejectsBadValues(t *testing.T) {
	configPath := writeConfig(t, "server_addr: \"tunnel.example.com:443\"\n")

	tests := []struct {
		name    string
		opts    Options
		wantErr string
	}{
		{
			name:    "binding internal without a hostname",
			opts:    Options{config: configPath, command: "default", args: []string{"8080"}, protocol: "http", binding: "internal"},
			wantErr: "-hostname=myapp.internal",
		},
		{
			name:    "binding internal with a hostname outside the namespace",
			opts:    Options{config: configPath, command: "default", args: []string{"8080"}, protocol: "http", binding: "internal", hostname: "svc"},
			wantErr: "must end in .internal",
		},
		{
			name:    "binding internal over tcp",
			opts:    Options{config: configPath, command: "default", args: []string{"22"}, protocol: "tcp", binding: "internal", hostname: "svc.internal"},
			wantErr: "only supported for http and https",
		},
		{
			name:    "unknown binding",
			opts:    Options{config: configPath, command: "default", args: []string{"8080"}, protocol: "http", binding: "loopback"},
			wantErr: "invalid binding",
		},
		{
			name:    "malformed forward_to",
			opts:    Options{config: configPath, command: "default", args: []string{"8080"}, protocol: "http", forwardTo: "svc.internal"},
			wantErr: "forward_to",
		},
		{
			name:    "forward_to over tcp",
			opts:    Options{config: configPath, command: "default", args: []string{"22"}, protocol: "tcp", forwardTo: "https://svc.internal"},
			wantErr: "forward_to is only supported for http and https",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := tt.opts
			_, err := LoadConfiguration(&opts)
			if err == nil {
				t.Fatalf("expected an error containing %q, got none", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error should mention %q, got: %v", tt.wantErr, err)
			}
			if !strings.Contains(err.Error(), "default") {
				t.Fatalf("error should name the default tunnel, got: %v", err)
			}
		})
	}
}

// TestEndpointFlagParsing is the core flag test: the new flags reach Options,
// including the compression default and the -flag=value / -flag value
// spellings.
func TestEndpointFlagParsing(t *testing.T) {
	opts, _ := parseArgs(t, []string{
		"ngrok",
		"-binding", "internal",
		"-hostname=svc.internal",
		"-pooling",
		"-forward-to=https://other.internal",
		"-compression=false",
		"8080",
	})

	if opts.binding != "internal" {
		t.Fatalf("binding: expected internal, got %q", opts.binding)
	}
	if opts.hostname != "svc.internal" {
		t.Fatalf("hostname: expected svc.internal, got %q", opts.hostname)
	}
	if !opts.pooling {
		t.Fatal("-pooling did not reach the options")
	}
	if opts.forwardTo != "https://other.internal" {
		t.Fatalf("forward_to: expected https://other.internal, got %q", opts.forwardTo)
	}
	if opts.compression {
		t.Fatal("-compression=false did not reach the options")
	}
	if opts.command != "default" || len(opts.args) != 1 || opts.args[0] != "8080" {
		t.Fatalf("positional argument handling changed: command=%q args=%v", opts.command, opts.args)
	}
}

// TestEndpointFlagParsingDefaults guards the other direction: without the
// flags, pooling is off and compression is on.
func TestEndpointFlagParsingDefaults(t *testing.T) {
	opts, _ := parseArgs(t, []string{"ngrok", "8080"})

	if opts.binding != "" {
		t.Fatalf("binding should default to empty, got %q", opts.binding)
	}
	if opts.pooling {
		t.Fatal("pooling should default to off")
	}
	if opts.forwardTo != "" {
		t.Fatalf("forward_to should default to empty, got %q", opts.forwardTo)
	}
	if !opts.compression {
		t.Fatal("compression should default to on (SPEC 3.4)")
	}
}

// TestEndpointFlagsAreRegistered checks the flags exist and carry help text: a
// flag nobody can discover in the usage output is as good as missing.
func TestEndpointFlagsAreRegistered(t *testing.T) {
	_, usage := parseArgs(t, []string{"ngrok", "8080"})

	for _, name := range []string{"binding", "pooling", "forward-to", "compression"} {
		if !strings.Contains(usage, "-"+name) {
			t.Fatalf("flag -%s is missing from the usage output:\n%s", name, usage)
		}
	}

	if !strings.Contains(usage, "internal") || !strings.Contains(usage, ".internal") {
		t.Fatalf("usage output should explain internal endpoints:\n%s", usage)
	}
	if !strings.Contains(usage, "round-robin") {
		t.Fatalf("usage output should explain pooling:\n%s", usage)
	}
}

// Tests for the alpn tunnel key (SPEC-CLUSTER16 1). The terminator half -- what
// the configured list does to the TLS handshake -- is tlsagent_test.go's; these
// are the load-time contract: what a config may offer, what may accompany an
// h2 offer, and the exact refusal an operator sees when the two disagree. The
// messages are user-facing contracts, so the refusals are asserted verbatim:
// LoadConfiguration returns validateAlpn's error unwrapped, which is what makes
// the equality possible.

// alpnTunnelYAML builds a one-tunnel config that is a VALID h2-offering
// agent-terminated https tunnel: the base every matrix case starts from, so
// that what a case changes is the thing being tested. The terminator needs no
// cert material -- validateAgentTLS leaves the ephemeral model to the session
// -- which keeps every case down to its one interesting key.
func alpnTunnelYAML(extraLines ...string) string {
	lines := []string{
		"tunnels:",
		"  web:",
		"    proto:",
		"      https: 127.0.0.1:7000",
		"    agent_tls_termination: true",
		"    alpn:",
		"      - h2",
		"      - http/1.1",
		"    compression: false",
	}
	lines = append(lines, extraLines...)

	return strings.Join(lines, "\n") + "\n"
}

func TestLoadConfigurationAlpnValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		wantErr string // the full refusal, verbatim
	}{
		{
			name:   "the valid base loads",
			config: alpnTunnelYAML(),
		},
		{
			name:   "host_header preserve is not a control h2 could dodge",
			config: alpnTunnelYAML("    host_header: preserve"),
		},
		{
			// The rewriter matches its keywords case-insensitively, so
			// "Preserve" IS preserve -- the h2 guard has to judge the value
			// the same way its writer does, or this valid spelling would be
			// refused only on the h2 road.
			name:   "host_header preserve in another case is still preserve",
			config: alpnTunnelYAML("    host_header: Preserve"),
		},
		{
			name: "an on_tcp_connect-only policy is fine: it runs server-side, before any TLS",
			config: alpnTunnelYAML(
				"    traffic_policy:",
				"      on_tcp_connect:",
				"        - name: restrict-ips",
				"          config:",
				"            allow:",
				"              - 127.0.0.0/8",
			),
		},
		{
			name:    "alpn without agent_tls_termination",
			config:  strings.Replace(alpnTunnelYAML(), "    agent_tls_termination: true\n", "", 1),
			wantErr: `Tunnel web: alpn requires agent_tls_termination: the advertised protocols belong to the TLS handshake this agent terminates, and without it the https leg is terminated on the server, which offers no ALPN`,
		},
		{
			// An http-only tunnel answers to validateAgentTLS first, whose
			// refusal for the same shape fires earlier in the chain -- this
			// pins that ordering so a future reordering cannot strand the
			// operator with the less specific message.
			name: "agent_tls_termination without an https leg is the earlier validator's refusal",
			config: `
tunnels:
  web:
    proto:
      http: 127.0.0.1:8080
    agent_tls_termination: true
    alpn:
      - h2
    compression: false
`,
			wantErr: `Tunnel web: agent_tls_termination requires the tunnel's protocols to include https, got http`,
		},
		{
			name:    "a token outside the set",
			config:  strings.Replace(alpnTunnelYAML(), "      - http/1.1", "      - spdy", 1),
			wantErr: `Tunnel web: alpn value "spdy" is not supported: the accepted values are "h2" and "http/1.1"`,
		},
		{
			// The tokens are wire tokens: "H2" is not the identifier RFC 7540
			// registers, and advertising it verbatim would be an offer no
			// visitor could answer. Case-folding it here would put bytes on
			// the wire the operator did not write.
			name:    "a near-miss spelling is refused, not corrected",
			config:  strings.Replace(alpnTunnelYAML(), "      - h2", "      - H2", 1),
			wantErr: `Tunnel web: alpn value "H2" is not supported: the accepted values are "h2" and "http/1.1"`,
		},
		{
			name:    "a duplicated protocol",
			config:  strings.Replace(alpnTunnelYAML(), "      - http/1.1", "      - h2", 1),
			wantErr: `Tunnel web: alpn lists "h2" more than once: advertise each protocol at most once`,
		},
		{
			// An explicitly written empty list is a control that says nothing:
			// refused, with the two ways out of it named.
			name:    "an explicitly empty list",
			config:  strings.Replace(alpnTunnelYAML(), "    alpn:\n      - h2\n      - http/1.1", "    alpn: []", 1),
			wantErr: `Tunnel web: alpn is empty: omit the key to offer no ALPN, or list "h2" and/or "http/1.1"`,
		},
		{
			name: "h2 with an on_http_request policy",
			config: alpnTunnelYAML(
				"    traffic_policy:",
				"      on_http_request:",
				"        - name: deny",
				"          expressions:",
				"            - 'req.url.path == \"/blocked\"'",
			),
			wantErr: `Tunnel web: alpn offers h2 but the traffic policy has on_http_request/on_http_response rules: h2 connections are raw passthrough, and a visitor must not be able to dodge them by negotiating h2 (on_tcp_connect is fine -- it runs server-side on the raw accept; drop the h2 alpn value or the http rules)`,
		},
		{
			name: "h2 with an on_http_response policy",
			config: alpnTunnelYAML(
				"    traffic_policy:",
				"      on_http_response:",
				"        - name: remove-headers",
				"          config:",
				"            headers:",
				"              - Server",
			),
			wantErr: `Tunnel web: alpn offers h2 but the traffic policy has on_http_request/on_http_response rules: h2 connections are raw passthrough, and a visitor must not be able to dodge them by negotiating h2 (on_tcp_connect is fine -- it runs server-side on the raw accept; drop the h2 alpn value or the http rules)`,
		},
		{
			name:    "h2 with a rewritten host_header",
			config:  alpnTunnelYAML("    host_header: rewrite"),
			wantErr: `Tunnel web: alpn offers h2 but host_header is set to "rewrite": rewriting the Host header is rewriter-driven, and a visitor must not be able to dodge it by negotiating h2 (drop host_header, set it to preserve, or drop the h2 alpn value)`,
		},
		{
			name:    "h2 with an explicit-host host_header",
			config:  alpnTunnelYAML("    host_header: app.internal"),
			wantErr: `Tunnel web: alpn offers h2 but host_header is set to "app.internal": rewriting the Host header is rewriter-driven, and a visitor must not be able to dodge it by negotiating h2 (drop host_header, set it to preserve, or drop the h2 alpn value)`,
		},
		{
			name: "h2 with request_header manipulation",
			config: alpnTunnelYAML(
				"    request_header:",
				"      add:",
				"        - \"X-Custom: value\"",
			),
			wantErr: `Tunnel web: alpn offers h2 but request_header adds or removes headers: header manipulation is rewriter-driven, and a visitor must not be able to dodge it by negotiating h2 (drop the h2 alpn value or the request_header entries)`,
		},
		{
			name: "h2 with response_header manipulation",
			config: alpnTunnelYAML(
				"    response_header:",
				"      remove:",
				"        - Server",
			),
			wantErr: `Tunnel web: alpn offers h2 but response_header adds or removes headers: header manipulation is rewriter-driven, and a visitor must not be able to dodge it by negotiating h2 (drop the h2 alpn value or the response_header entries)`,
		},
		{
			// The key is simply absent: compression defaults ON, and the
			// refusal has to say what to write, not just that it is wrong.
			name:    "h2 with compression left at its default",
			config:  strings.Replace(alpnTunnelYAML(), "    compression: false\n", "", 1),
			wantErr: `Tunnel web: alpn offers h2 but compression is not explicitly false: compression defaults on and is rewriter-driven, which an h2 visitor bypasses -- set compression: false alongside the h2 alpn value`,
		},
		{
			// Explicitly on is the same refusal: the operator stated it, and
			// what they stated is what an h2 visitor would bypass.
			name:    "h2 with compression explicitly on",
			config:  strings.Replace(alpnTunnelYAML(), "    compression: false", "    compression: true", 1),
			wantErr: `Tunnel web: alpn offers h2 but compression is not explicitly false: compression defaults on and is rewriter-driven, which an h2 visitor bypasses -- set compression: false alongside the h2 alpn value`,
		},
		{
			// The asymmetry, the whole point of gating rule 3 on the h2 value:
			// pinning h1 changes nothing servicewise, so a tunnel may offer
			// http/1.1 under every rewriter-driven control it likes.
			name: "http/1.1 alone needs none of the h2 conditions",
			config: `
tunnels:
  web:
    proto:
      https: 127.0.0.1:7000
    agent_tls_termination: true
    alpn:
      - http/1.1
    host_header: rewrite
    request_header:
      add:
        - "X-Custom: value"
`,
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
				t.Fatalf("expected the verbatim refusal\n\t%s\ngot none", tt.wantErr)
			}
			if err.Error() != tt.wantErr {
				t.Fatalf("refusal does not match the contract:\n got: %s\nwant: %s", err.Error(), tt.wantErr)
			}
		})
	}
}

// TestLoadConfigurationAlpnTunnel pins that a loaded alpn list survives into
// the tunnel the loader hands back -- the list tlsagent.go will advertise.
func TestLoadConfigurationAlpnTunnel(t *testing.T) {
	configPath := writeConfig(t, alpnTunnelYAML())

	config, err := LoadConfiguration(&Options{config: configPath, command: "start", args: []string{"web"}})
	if err != nil {
		t.Fatalf("expected the config to load, got: %v", err)
	}

	tunnel := config.Tunnels["web"]
	if tunnel == nil {
		t.Fatalf("expected a tunnel named web, got %d tunnels", len(config.Tunnels))
	}
	if want := []string{"h2", "http/1.1"}; !reflect.DeepEqual(tunnel.Alpn, want) {
		t.Fatalf("alpn: expected %v (order preserved, h2 preferred), got %v", want, tunnel.Alpn)
	}
}

// TestAlpnConfigYAMLRoundTrip runs the alpn key through the marshal/unmarshal
// cycle SaveAuthToken puts every config through, and checks the other
// direction too: a config that says nothing about alpn must not grow the key
// when re-marshaled (the field is omitempty).
func TestAlpnConfigYAMLRoundTrip(t *testing.T) {
	config := new(Configuration)
	if err := yaml.Unmarshal([]byte(alpnTunnelYAML()), config); err != nil {
		t.Fatalf("failed to unmarshal config: %v", err)
	}

	marshaled, err := yaml.Marshal(config)
	if err != nil {
		t.Fatalf("failed to marshal config: %v", err)
	}
	for _, key := range []string{"alpn:", "- h2", "- http/1.1"} {
		if !strings.Contains(string(marshaled), key) {
			t.Fatalf("marshaled config is missing %q:\n%s", key, marshaled)
		}
	}

	reloaded := new(Configuration)
	if err := yaml.Unmarshal(marshaled, reloaded); err != nil {
		t.Fatalf("failed to re-unmarshal marshaled config: %v", err)
	}
	if again := reloaded.Tunnels["web"]; !reflect.DeepEqual(config.Tunnels["web"], again) {
		t.Fatalf("round trip changed the tunnel:\n before: %+v\nafter: %+v", config.Tunnels["web"], again)
	}

	without := new(Configuration)
	if err := yaml.Unmarshal([]byte(tunnelYAML()), without); err != nil {
		t.Fatalf("failed to unmarshal the alpn-less config: %v", err)
	}
	withoutMarshaled, err := yaml.Marshal(without)
	if err != nil {
		t.Fatalf("failed to marshal the alpn-less config: %v", err)
	}
	if strings.Contains(string(withoutMarshaled), "alpn") {
		t.Fatalf("no alpn key should be emitted when none was configured:\n%s", withoutMarshaled)
	}
}

// TestValidateAlpnHTTPSRefusalReachableDirectly pins the https-leg half of
// rule 1, which the loader cannot reach -- validateAgentTLS, earlier in the
// chain, refuses the same tunnel shape first (the table above pins that
// ordering). The check is kept in validateAlpn so that the function is a total
// judge of an alpn list against a tunnel, callable for any tunnel, and so the
// refusal exists with its own words if the chain is ever reordered.
func TestValidateAlpnHTTPSRefusalReachableDirectly(t *testing.T) {
	err := validateAlpn("web", &TunnelConfiguration{
		Protocols:           map[string]string{"http": "127.0.0.1:8080"},
		AgentTLSTermination: true,
		Alpn:                []string{alpnH2},
	})
	if err == nil {
		t.Fatal("expected alpn on an https-less tunnel to be refused")
	}
	want := `Tunnel web: alpn requires the tunnel's protocols to include https, got http`
	if err.Error() != want {
		t.Fatalf("refusal does not match the contract:\n got: %s\nwant: %s", err.Error(), want)
	}
}

// TestAlpnFlagParsing is the core flag test: -alpn carries its raw
// comma-separated value, and the flag's default is the empty string the
// loader reads as "not given".
func TestAlpnFlagParsing(t *testing.T) {
	opts, _ := parseArgs(t, []string{"ngrok", "-alpn", "h2, http/1.1", "8080"})

	if want := "h2, http/1.1"; opts.alpn != want {
		t.Fatalf("-alpn arrived as %q, want the raw value %q (splitting happens at load)", opts.alpn, want)
	}
	if opts.command != "default" || len(opts.args) != 1 || opts.args[0] != "8080" {
		t.Fatalf("positional argument handling changed: command=%q args=%v", opts.command, opts.args)
	}
}

// TestAlpnFlagParsingDefaults guards the other direction: without the flag,
// nothing is offered.
func TestAlpnFlagParsingDefaults(t *testing.T) {
	opts, _ := parseArgs(t, []string{"ngrok", "8080"})

	if opts.alpn != "" {
		t.Fatalf("alpn should default to empty, got %q", opts.alpn)
	}
}

// TestAlpnFlagsAreRegistered checks the flag exists and carries help text: a
// flag nobody can discover in the usage output is as good as missing.
func TestAlpnFlagsAreRegistered(t *testing.T) {
	_, usage := parseArgs(t, []string{"ngrok", "8080"})

	if !strings.Contains(usage, "-alpn") {
		t.Fatalf("flag -alpn is missing from the usage output:\n%s", usage)
	}
	if !strings.Contains(usage, "agent-tls-termination") || !strings.Contains(usage, "h2") {
		t.Fatalf("usage output should explain what -alpn requires and offers:\n%s", usage)
	}
}

// TestDefaultTunnelAlpnSynthesis covers the config.go wiring: the flag feeds
// the synthesized "default" tunnel, split and trimmed, and the same validator
// that police a config-file alpn key police what the flag produced.
func TestDefaultTunnelAlpnSynthesis(t *testing.T) {
	configPath := writeConfig(t, "server_addr: \"tunnel.example.com:443\"\n")

	config, err := LoadConfiguration(&Options{
		config:              configPath,
		command:             "default",
		args:                []string{"7000"},
		protocol:            "https",
		agentTLSTermination: true,
		compression:         false,
		alpn:                "h2, http/1.1",
	})
	if err != nil {
		t.Fatalf("expected the synthesized tunnel to load, got: %v", err)
	}

	tunnel := config.Tunnels["default"]
	if tunnel == nil {
		t.Fatalf("expected a synthesized default tunnel")
	}
	if want := []string{"h2", "http/1.1"}; !reflect.DeepEqual(tunnel.Alpn, want) {
		t.Fatalf("alpn: expected %v (comma split, spaces trimmed), got %v", want, tunnel.Alpn)
	}
}

// TestDefaultTunnelWithoutAlpnFlag: a user who sets no -alpn flag must get
// exactly the tunnel they got before the flag existed -- nil list, nothing
// advertised.
func TestDefaultTunnelWithoutAlpnFlag(t *testing.T) {
	configPath := writeConfig(t, "server_addr: \"tunnel.example.com:443\"\n")

	config, err := LoadConfiguration(&Options{
		config:   configPath,
		command:  "default",
		args:     []string{"7000"},
		protocol: "https",
	})
	if err != nil {
		t.Fatalf("expected the default tunnel to load, got: %v", err)
	}
	if tunnel := config.Tunnels["default"]; tunnel.Alpn != nil {
		t.Fatalf("no -alpn flag should leave the list nil, got %v", tunnel.Alpn)
	}
}

// TestDefaultTunnelAlpnSynthesisRejectsBadValues drives the flag road through
// the same refusals the config-file road uses: same rules, same words, with
// the synthesized tunnel named.
func TestDefaultTunnelAlpnSynthesisRejectsBadValues(t *testing.T) {
	configPath := writeConfig(t, "server_addr: \"tunnel.example.com:443\"\n")

	tests := []struct {
		name    string
		alpn    string
		wantErr string
	}{
		{
			name:    "an unknown token",
			alpn:    "h2,spdy",
			wantErr: `Tunnel default: alpn value "spdy" is not supported: the accepted values are "h2" and "http/1.1"`,
		},
		{
			// An empty piece is not a value: the split left it behind, and
			// advertising "" would be an offer nobody answers.
			name:    "a trailing comma",
			alpn:    "h2,",
			wantErr: `Tunnel default: alpn value "" is not supported: the accepted values are "h2" and "http/1.1"`,
		},
		{
			name:    "a duplicate across the comma",
			alpn:    "h2,h2",
			wantErr: `Tunnel default: alpn lists "h2" more than once: advertise each protocol at most once`,
		},
		{
			// Without the switch, the terminator whose ALPN this is does not
			// exist -- the flag road is refused by the same rule 1 the config
			// road is.
			name:    "alpn without -agent-tls-termination",
			alpn:    "h2",
			wantErr: `Tunnel default: alpn requires agent_tls_termination: the advertised protocols belong to the TLS handshake this agent terminates, and without it the https leg is terminated on the server, which offers no ALPN`,
		},
		{
			// The h2 conditions bind the flag road too: the flag turned
			// compression off here, but the header flags turned a control on.
			name:    "h2 with -request-header-add",
			alpn:    "h2",
			wantErr: `Tunnel default: alpn offers h2 but request_header adds or removes headers: header manipulation is rewriter-driven, and a visitor must not be able to dodge it by negotiating h2 (drop the h2 alpn value or the request_header entries)`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &Options{
				config:              configPath,
				command:             "default",
				args:                []string{"7000"},
				protocol:            "https",
				agentTLSTermination: true,
				compression:         false,
				alpn:                tt.alpn,
			}
			if tt.name == "alpn without -agent-tls-termination" {
				opts.agentTLSTermination = false
			}
			if tt.name == "h2 with -request-header-add" {
				opts.requestHeaderAdd = stringList{"X-Custom: value"}
			}

			_, err := LoadConfiguration(opts)
			if err == nil {
				t.Fatalf("expected the verbatim refusal\n\t%s\ngot none", tt.wantErr)
			}
			if err.Error() != tt.wantErr {
				t.Fatalf("refusal does not match the contract:\n got: %s\nwant: %s", err.Error(), tt.wantErr)
			}
		})
	}
}
