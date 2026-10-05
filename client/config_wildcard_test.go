package client

// Tests for the wildcard-hostname grammar (SPEC 11 §2-3, workstream B): the
// client accepts exactly the shape `*.<labels>` -- one leading "*." label,
// nothing else wild, no '*' mid-name -- for public http/https tunnels, refuses
// every other wildcard-bearing spelling with the accepted shape named, and
// carries the "*.base" spelling through to the registration request
// untouched, because the server's url for the tunnel is derived from exactly
// this field.
//
// These are new-file additions on purpose, like config_udp_test.go: the
// validation tables in config_test.go predate wildcards, and the grammar is
// one coherent table -- splicing its cases into tables pinning older rules
// would bury both.

import (
	"strings"
	"testing"
)

// wildcardTunnelYAML builds a one-tunnel config whose proto section is http,
// with extraLines spliced in as (already indented) tunnel-level keys -- the
// tunnelYAML shape from config_test.go, pointed at an http tunnel so the
// wildcard keys below attach to a name-routed protocol.
func wildcardTunnelYAML(extraLines ...string) string {
	lines := []string{
		"tunnels:",
		"  web:",
		"    proto:",
		"      http: 127.0.0.1:8080",
	}
	lines = append(lines, extraLines...)

	return strings.Join(lines, "\n") + "\n"
}

// TestLoadConfigurationWildcardGrammar is the grammar table. Every refusal is
// a load-time error naming the tunnel and the accepted shape; the valid cases
// load with the hostname carried through unchanged.
//
// The second valid case is deliberate: the client's grammar is `*.<labels>` --
// the base may itself be multi-label, because label depth is a MATCHING
// question (one label deep, server-side) and the client cannot know the
// server's domain, only that the spelling is well-formed.
func TestLoadConfigurationWildcardGrammar(t *testing.T) {
	tests := []struct {
		name     string
		hostname string
		wantErr  string
	}{
		// valid: the one wildcard form, and a multi-label base of the same form
		{name: "one leading wildcard label", hostname: `*.example.com`},
		{name: "multi-label base", hostname: `*.a.example.com`},

		// refused: every other wildcard-bearing spelling
		{name: "bare star", hostname: `*`, wantErr: `not a valid wildcard`},
		{name: "second wildcard mid-name", hostname: `*.a.*`, wantErr: `more than one '*'`},
		{name: "wildcard between labels", hostname: `a.*.b`, wantErr: `not a valid wildcard`},
		{name: "star glued to the name", hostname: `*example.com`, wantErr: `not a valid wildcard`},
		{name: "trailing star", hostname: `a.example.*`, wantErr: `not a valid wildcard`},
		{name: "star dot with no domain", hostname: `*.`, wantErr: `no domain after "*."`},
		{name: "empty label behind the star", hostname: `*..com`, wantErr: `cannot be empty`},
		{name: "port suffix is not a domain label", hostname: `*.example.com:80`, wantErr: `not a hostname label`},
		{name: "space in a base label", hostname: `*.exa mple.com`, wantErr: `not a hostname label`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := wildcardTunnelYAML("    hostname: \"" + tt.hostname + "\"")
			got, err := loadTunnelConfig(t, config, "web")

			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("expected %q to load, got: %v", tt.hostname, err)
				}
				if hostname := got.Tunnels["web"].Hostname; hostname != tt.hostname {
					t.Fatalf("hostname = %q, want the written %q", hostname, tt.hostname)
				}
				return
			}

			if err == nil {
				t.Fatalf("expected %q to be refused with %q, got none", tt.hostname, tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error should mention %q, got: %v", tt.wantErr, err)
			}
			if !strings.Contains(err.Error(), "web") {
				t.Fatalf("error should name the offending tunnel, got: %v", err)
			}
			// The accepted shape is part of every grammar refusal (SPEC 11
			// gate 5): the error must show the spelling that would have loaded.
			if !strings.Contains(err.Error(), "*.example.com") {
				t.Fatalf("error should name the accepted shape, got: %v", err)
			}
		})
	}
}

// TestLoadConfigurationWildcardUppercaseNormalized pins the canonicalization:
// a hostname is case-insensitive, so "*.EXAMPLE.com" is the same wildcard as
// its lowercase spelling, and it is stored -- and later registered -- in the
// lowercase form the server canonicalizes every public hostname to. The
// "*.base" spelling itself survives: only case and surrounding space are
// normalized, never the wildcard.
func TestLoadConfigurationWildcardUppercaseNormalized(t *testing.T) {
	config := wildcardTunnelYAML(`    hostname: " *.EXAMPLE.com "`)

	got, err := loadTunnelConfig(t, config, "web")
	if err != nil {
		t.Fatalf("expected the uppercase wildcard to load, got: %v", err)
	}
	if hostname := got.Tunnels["web"].Hostname; hostname != "*.example.com" {
		t.Fatalf("hostname = %q, want the canonicalized %q", hostname, "*.example.com")
	}
}

// TestLoadConfigurationWildcardSubdomainRefused pins the field rule: the
// wildcard is canonicalized to the hostname field only. The server has no
// branch for a star in subdomain -- it would register the star as a literal
// subdomain label -- so every spelling is refused at load with the hostname
// spelling named, including the grammatically valid one.
func TestLoadConfigurationWildcardSubdomainRefused(t *testing.T) {
	for _, subdomain := range []string{`*`, `a.*.b`, `*.example.com`} {
		config := wildcardTunnelYAML("    subdomain: \"" + subdomain + "\"")

		_, err := loadTunnelConfig(t, config, "web")
		if err == nil {
			t.Fatalf("subdomain %q: expected a refusal, got none", subdomain)
		}
		if !strings.Contains(err.Error(), "must not contain '*'") {
			t.Fatalf("subdomain %q: error should name the rule, got: %v", subdomain, err)
		}
		if !strings.Contains(err.Error(), "hostname") {
			t.Fatalf("subdomain %q: error should point at the hostname spelling, got: %v", subdomain, err)
		}
	}
}

// TestLoadConfigurationWildcardInternalRefused pins the binding rule: a
// wildcard on binding internal is refused because internal endpoints are
// exact names -- that is HOW other tunnels address them in forward_to. The
// contrast case pins the composition with the older public-binding check: the
// same wildcard pointed at the reserved namespace under the PUBLIC binding is
// refused by THAT rule (the public listener never routes .internal), not by
// the grammar.
func TestLoadConfigurationWildcardInternalRefused(t *testing.T) {
	internal := wildcardTunnelYAML("    binding: internal", `    hostname: "*.svc.internal"`)
	_, err := loadTunnelConfig(t, internal, "web")
	if err == nil {
		t.Fatal("expected a wildcard on binding internal to be refused, got none")
	}
	if !strings.Contains(err.Error(), "wildcards are a public-binding feature") {
		t.Fatalf("error should name the binding rule, got: %v", err)
	}
	if !strings.Contains(err.Error(), "web") {
		t.Fatalf("error should name the offending tunnel, got: %v", err)
	}

	public := wildcardTunnelYAML(`    hostname: "*.svc.internal"`)
	_, err = loadTunnelConfig(t, public, "web")
	if err == nil {
		t.Fatal("expected a wildcard over .internal under the public binding to be refused, got none")
	}
	if !strings.Contains(err.Error(), "requires binding internal") {
		t.Fatalf("expected the existing .internal-on-public refusal, got: %v", err)
	}
}

// TestLoadConfigurationWildcardTCPRemainsNameRefused pins the composition with
// the port-routed name refusal (the SPEC-CLUSTER8 fix): a wildcard on a
// tcp/udp tunnel is refused by THAT rule, in its words -- the grammar never
// preempts it, not even for an ill-formed star. The tunnel shape is refused
// before the spelling is judged, which is the whole reason the wildcard checks
// sit after the port-routed refusal in validateEndpointPolicy.
func TestLoadConfigurationWildcardTCPRemainsNameRefused(t *testing.T) {
	tests := []struct {
		name     string
		proto    string
		hostname string
	}{
		{name: "tcp with a valid wildcard", proto: "tcp", hostname: `*.example.com`},
		{name: "tcp with an ill-formed star", proto: "tcp", hostname: `*.a.*`},
		{name: "udp with a valid wildcard", proto: "udp", hostname: `*.example.com`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := strings.Replace(wildcardTunnelYAML("    hostname: \""+tt.hostname+"\""),
				"http: 127.0.0.1:8080", tt.proto+": 127.0.0.1:22", 1)

			_, err := loadTunnelConfig(t, config, "web")
			if err == nil {
				t.Fatalf("expected the %s tunnel to be refused, got none", tt.proto)
			}
			if !strings.Contains(err.Error(), "hostname/subdomain are only valid for http/https") {
				t.Fatalf("expected the existing port-routed name refusal, got: %v", err)
			}
		})
	}
}

// TestLoadConfigurationWildcardPublicURLIsLiteral is the end-to-end half: an
// http tunnel with hostname "*.example.com" loads through LoadConfiguration,
// and the wildcard reaches the registration request (reqTunnelFromConfig) and
// the reported public url (tunnelFromConfig) with the literal "*.base"
// spelling -- no expansion, no quoting, no port play. The server derives the
// url from exactly this field, so any transformation here would be a url the
// operator never configured.
func TestLoadConfigurationWildcardPublicURLIsLiteral(t *testing.T) {
	config, err := loadTunnelConfig(t, wildcardTunnelYAML(`    hostname: "*.example.com"`), "web")
	if err != nil {
		t.Fatalf("expected the wildcard tunnel to load, got: %v", err)
	}

	tunnel := config.Tunnels["web"]
	if tunnel.Hostname != "*.example.com" {
		t.Fatalf("hostname = %q, want the literal %q", tunnel.Hostname, "*.example.com")
	}

	req := reqTunnelFromConfig("req-id", tunnel)
	if req.Hostname != "*.example.com" {
		t.Fatalf("ReqTunnel.Hostname = %q, want the literal %q", req.Hostname, "*.example.com")
	}
	if req.Subdomain != "" {
		t.Fatalf("ReqTunnel.Subdomain = %q, want empty: the wildcard lives in the hostname field", req.Subdomain)
	}

	// The public url is what the server reported, carried through as-is; the
	// passthrough must not touch the wildcard spelling.
	view := tunnelFromConfig("https://*.example.com", "http", nil, tunnel)
	if view.PublicUrl != "https://*.example.com" {
		t.Fatalf("PublicUrl = %q, want the literal %q", view.PublicUrl, "https://*.example.com")
	}
}

// TestDefaultTunnelWildcardFlag covers the CLI surface: -hostname='*.example.com'
// synthesizes the same tunnel a config file would have, through the same
// validateEndpointPolicy call the endpoint rules have always shared.
func TestDefaultTunnelWildcardFlag(t *testing.T) {
	configPath := writeConfig(t, "server_addr: \"tunnel.example.com:443\"\n")

	config, err := LoadConfiguration(&Options{
		config:   configPath,
		command:  "default",
		args:     []string{"8080"},
		protocol: "http",
		hostname: "*.example.com",
	})
	if err != nil {
		t.Fatalf("expected the synthesized wildcard tunnel to load, got: %v", err)
	}
	if hostname := config.Tunnels["default"].Hostname; hostname != "*.example.com" {
		t.Fatalf("hostname = %q, want the literal %q", hostname, "*.example.com")
	}

	// The CLI road is policed by the same grammar: an ill-formed star on the
	// flag is the same startup error it is in the config file.
	configPath = writeConfig(t, "server_addr: \"tunnel.example.com:443\"\n")
	_, err = LoadConfiguration(&Options{
		config:   configPath,
		command:  "default",
		args:     []string{"8080"},
		protocol: "http",
		hostname: "*",
	})
	if err == nil {
		t.Fatal("expected -hostname=* to be refused, got none")
	}
	if !strings.Contains(err.Error(), "not a valid wildcard") {
		t.Fatalf("error should name the grammar, got: %v", err)
	}
}
