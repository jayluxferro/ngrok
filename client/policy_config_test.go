package client

// Tests for the traffic-policy surface of the config file and the command line
// (SPEC 3.4, workstream B). What a policy does to a connection is package
// policy's and the server's business; these tests prove that the traffic_policy
// key and the -traffic-policy-file flag arrive intact, that the CLI "default"
// tunnel gets the policy, that what the client sends carries it, and that a
// policy that could not mean what its author thinks fails at load time naming
// the tunnel (or the file) instead of at the edge.
//
// The rule shape under test is this build's flat one: one action per rule, with
// name, expressions and config at the top level of the rule. ngrok nests a list
// of actions ({"name": "my rule", "actions": [{"type": ..., "config": ...}]})
// inside each rule, which yaml.v1 cannot decode into a typed policy -- the
// deviation, its reasoning and the one shape of it that does not fail loudly
// are in docs/CHANGELOG.md.

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v1"

	"ngrok/conn"
	"ngrok/msg"
	"ngrok/policy"
)

// guardedTunnelYAML is one guarded endpoint with a policy in every phase: the
// set of actions and config fields the cluster implements, in the shape a
// config file has to use.
//
// Two details are worth reading twice, because the YAML that reads best is not
// the YAML that works:
//
//   - "proto: {http: 127.0.0.1:8080}" -- the flow spelling -- does not parse at
//     all under yaml.v1: a plain scalar inside a flow mapping may not contain a
//     colon ("found unexpected ':'"), so the port has to be written in block
//     style. Every config in this repo does.
//   - a header value is an object entry ("X-Policy: checked"), not a quoted
//     "X-Policy: checked" string: the quoted spelling is a YAML set entry whose
//     value is null, and the policy package (rightly) refuses it as a header
//     name rather than guessing. Same config shape as ngrok's headers object.
const guardedTunnelYAML = `
tunnels:
  guarded:
    hostname: guarded
    proto:
      http: 127.0.0.1:8080
    traffic_policy:
      on_tcp_connect:
        - name: restrict-ips
          config:
            allow:
              - 127.0.0.0/8
              - "::1/128"
      on_http_request:
        - name: deny
          expressions:
            - 'req.url.path == "/blocked"'
        - name: set-vars
          config:
            vars:
              - who: policy
        - name: add-headers
          config:
            headers:
              X-Policy: checked
              X-Who: "${vars.who}"
        - name: custom-response
          expressions:
            - 'req.url.path == "/teapot"'
          config:
            status_code: 418
            body: short and stout
            headers:
              X-Flavour: tea
        - name: log
          config:
            metadata:
              hit: "${vars.who}"
      on_http_response:
        - name: remove-headers
          config:
            headers:
              - Server
        - name: add-headers
          config:
            headers:
              X-Edge: ngrokd
`

// writeFile writes a file into dir for a test that needs one.
func writeFile(t *testing.T, dir, name, contents string) string {
	t.Helper()

	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatalf("failed to write %s: %v", name, err)
	}

	return path
}

// TestTrafficPolicyYAMLRoundTrip pins the config-file spelling: every phase,
// every action the cluster implements, the config field names ngrok documents,
// and the ${vars...} interpolation in a header value -- and it survives a
// marshal/unmarshal cycle, because SaveAuthToken rewrites the config file with
// yaml.Marshal and users edit configs with tools that re-emit them.
func TestTrafficPolicyYAMLRoundTrip(t *testing.T) {
	config := new(Configuration)
	if err := yaml.Unmarshal([]byte(guardedTunnelYAML), config); err != nil {
		t.Fatalf("failed to unmarshal the traffic policy config: %v", err)
	}

	tunnel, ok := config.Tunnels["guarded"]
	if !ok {
		t.Fatalf("expected a tunnel named guarded, got %d tunnels", len(config.Tunnels))
	}

	tp := tunnel.TrafficPolicy
	if tp == nil {
		t.Fatalf("traffic_policy did not reach the tunnel: %+v", tunnel)
	}

	if got := len(tp.OnTCPConnect); got != 1 {
		t.Fatalf("on_tcp_connect: expected 1 rule, got %d", got)
	}
	if tp.OnTCPConnect[0].Name != policy.ActionRestrictIPs {
		t.Fatalf("on_tcp_connect[0]: expected %s, got %q", policy.ActionRestrictIPs, tp.OnTCPConnect[0].Name)
	}

	reqNames := make([]string, 0, len(tp.OnHTTPRequest))
	for _, r := range tp.OnHTTPRequest {
		reqNames = append(reqNames, r.Name)
	}
	if want := []string{"deny", "set-vars", "add-headers", "custom-response", "log"}; !reflect.DeepEqual(reqNames, want) {
		t.Fatalf("on_http_request: expected %v, got %v", want, reqNames)
	}

	respNames := make([]string, 0, len(tp.OnHTTPResponse))
	for _, r := range tp.OnHTTPResponse {
		respNames = append(respNames, r.Name)
	}
	if want := []string{"remove-headers", "add-headers"}; !reflect.DeepEqual(respNames, want) {
		t.Fatalf("on_http_response: expected %v, got %v", want, respNames)
	}

	// The expressions and config values have to arrive as written: the order of
	// the actions is the order they run in, and a config field that got lost in
	// decoding is a control that does nothing.
	if got := tp.OnHTTPRequest[0].Expressions; !reflect.DeepEqual(got, []string{`req.url.path == "/blocked"`}) {
		t.Fatalf("deny expressions: got %v", got)
	}
	if got := tp.OnHTTPRequest[3].Config["status_code"]; got != 418 {
		t.Fatalf("custom-response status_code: expected 418, got %#v", got)
	}
	if got := tp.OnHTTPResponse[0].Config["headers"]; !reflect.DeepEqual(got, []interface{}{"Server"}) {
		t.Fatalf("remove-headers headers: got %#v", got)
	}

	// The whole point of validating at load time: a policy that got here has to
	// compile, or the tunnel would come up carrying a policy the server refuses.
	if _, err := tp.Compile(); err != nil {
		t.Fatalf("the parsed policy does not compile: %v", err)
	}

	marshaled, err := yaml.Marshal(config)
	if err != nil {
		t.Fatalf("failed to marshal the config: %v", err)
	}
	for _, key := range []string{"traffic_policy:", "on_tcp_connect:", "on_http_request:", "on_http_response:", "name: deny", "expressions:"} {
		if !strings.Contains(string(marshaled), key) {
			t.Fatalf("marshaled config is missing %q:\n%s", key, marshaled)
		}
	}

	reloaded := new(Configuration)
	if err := yaml.Unmarshal(marshaled, reloaded); err != nil {
		t.Fatalf("failed to re-unmarshal the marshaled config: %v", err)
	}

	again := reloaded.Tunnels["guarded"]
	if again == nil {
		t.Fatal("the tunnel did not survive the round trip")
	}
	if again.Hostname != tunnel.Hostname || !reflect.DeepEqual(again.Protocols, tunnel.Protocols) {
		t.Fatalf("round trip changed the endpoint:\n before: %+v\nafter:  %+v", tunnel, again)
	}
	if want, got := policyRules(tp), policyRules(again.TrafficPolicy); !reflect.DeepEqual(want, got) {
		t.Fatalf("round trip changed the policy:\n before: %+v\nafter:  %+v", want, got)
	}
}

// policyRule is one rule of a policy in a form that two decodes of the same
// document can be compared in. The difference it exists to normalize away: a
// rule with no config key comes back from a marshal/unmarshal cycle with an
// empty config map rather than a nil one (yaml.v1 emits `config: {}` and reads
// it back as an empty map). That is a difference in representation, not in
// meaning -- the policy package reads both as "this action has no config" -- but
// reflect.DeepEqual sees it, so the round trip is asserted on this view.
type policyRule struct {
	phase       string
	name        string
	expressions []string
	config      map[string]interface{}
}

func policyRules(tp *policy.TrafficPolicy) []policyRule {
	if tp == nil {
		return nil
	}

	var out []policyRule
	for _, phase := range []struct {
		name  string
		rules []*policy.Action
	}{
		{"on_tcp_connect", tp.OnTCPConnect},
		{"on_http_request", tp.OnHTTPRequest},
		{"on_http_response", tp.OnHTTPResponse},
	} {
		for i, r := range phase.rules {
			config := r.Config
			if config == nil {
				config = map[string]interface{}{}
			}
			out = append(out, policyRule{
				phase:       fmt.Sprintf("%s[%d]", phase.name, i),
				name:        r.Name,
				expressions: r.Expressions,
				config:      config,
			})
		}
	}

	return out
}

// TestLoadConfigurationTrafficPolicyTunnel is the config-file happy path: a
// valid policy loads, is attached to its tunnel, and is the very object the
// tunnel registration sends.
func TestLoadConfigurationTrafficPolicyTunnel(t *testing.T) {
	configPath := writeConfig(t, guardedTunnelYAML)

	config, err := LoadConfiguration(&Options{config: configPath, command: "start", args: []string{"guarded"}})
	if err != nil {
		t.Fatalf("expected the config to load, got: %v", err)
	}

	tp := config.Tunnels["guarded"].TrafficPolicy
	if tp == nil {
		t.Fatal("the loaded tunnel has no traffic policy")
	}
	if len(tp.OnHTTPRequest) != 5 {
		t.Fatalf("expected 5 on_http_request rules, got %d", len(tp.OnHTTPRequest))
	}

	// The policy has to be marshallable as well as valid. The tunnel
	// registration is a JSON envelope, and a policy read from a config file holds
	// yaml.v1's map[interface{}]interface{} shape until the loader normalizes it
	// -- a policy that loads but cannot be sent leaves the client retrying its
	// control connection forever.
	if _, err := json.Marshal(tp); err != nil {
		t.Fatalf("the loaded policy cannot go over the control channel: %v", err)
	}

	req := reqTunnelFromConfig("reqid", config.Tunnels["guarded"])
	if req.TrafficPolicy != tp {
		t.Fatalf("reqTunnelFromConfig sent a different policy than the tunnel holds")
	}
}

// TestLoadConfigurationTrafficPolicyValidation is the loud half: every way a
// policy can fail to mean what its author thinks is a load-time error that
// names the tunnel and the rule, with no silent fallback.
func TestLoadConfigurationTrafficPolicyValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		wantErr []string
	}{
		{
			name: "unknown action name",
			config: tunnelYAML(
				"    traffic_policy:",
				"      on_http_request:",
				"        - name: rate-limit",
			),
			wantErr: []string{"invalid traffic policy", "on_http_request[0] (rate-limit)", "unknown action"},
		},
		{
			name: "action in a phase it is not implemented in",
			config: tunnelYAML(
				"    traffic_policy:",
				"      on_http_response:",
				"        - name: custom-response",
				"          config:",
				"            status_code: 418",
			),
			wantErr: []string{"invalid traffic policy", "on_http_response[0] (custom-response)", "not implemented in the on_http_response phase"},
		},
		{
			name: "action with no name",
			config: tunnelYAML(
				"    traffic_policy:",
				"      on_http_request:",
				"        - expressions:",
				"            - 'req.url.path == \"/\"'",
			),
			wantErr: []string{"invalid traffic policy", "on_http_request[0]: action has no name"},
		},
		{
			name: "CEL that does not compile",
			config: tunnelYAML(
				"    traffic_policy:",
				"      on_http_request:",
				"        - name: deny",
				"          expressions:",
				"            - 'req.url.path =='",
			),
			wantErr: []string{"invalid traffic policy", "on_http_request[0] (deny)", "condition 0"},
		},
		{
			name: "CEL that only exists in the other phase",
			config: tunnelYAML(
				"    traffic_policy:",
				"      on_http_request:",
				"        - name: deny",
				"          expressions:",
				"            - 'res.status_code == 200'",
			),
			wantErr: []string{"invalid traffic policy", "on_http_request[0] (deny)", "condition 0"},
		},
		{
			name: "restrict-ips with a CIDR it cannot parse",
			config: tunnelYAML(
				"    traffic_policy:",
				"      on_tcp_connect:",
				"        - name: restrict-ips",
				"          config:",
				"            allow:",
				"              - not-an-address",
			),
			wantErr: []string{"invalid traffic policy", "on_tcp_connect[0] (restrict-ips)", "\"allow\" entry 0", "is not a CIDR"},
		},
		{
			name: "restrict-ips with nothing to enforce",
			config: tunnelYAML(
				"    traffic_policy:",
				"      on_tcp_connect:",
				"        - name: restrict-ips",
				"          config:",
				"            enforce: true",
			),
			wantErr: []string{"invalid traffic policy", "restrict-ips needs at least one CIDR"},
		},
		{
			name: "restrict-ips ip_policies, which needs the ngrok API",
			config: tunnelYAML(
				"    traffic_policy:",
				"      on_tcp_connect:",
				"        - name: restrict-ips",
				"          config:",
				"            ip_policies:",
				"              - pol_123",
			),
			wantErr: []string{"invalid traffic policy", "ip_policies\" is not implemented in this build", "allow/deny CIDRs"},
		},
		{
			name: "an unknown config field",
			config: tunnelYAML(
				"    traffic_policy:",
				"      on_http_request:",
				"        - name: deny",
				"          config:",
				"            body: nope",
			),
			wantErr: []string{"invalid traffic policy", "on_http_request[0] (deny)", "unknown config field \"body\""},
		},
		{
			name: "set-vars with a config shape that is not ngrok's",
			config: tunnelYAML(
				"    traffic_policy:",
				"      on_http_request:",
				"        - name: set-vars",
				"          config:",
				"            vars:",
				"              who: policy",
			),
			wantErr: []string{"invalid traffic policy", "on_http_request[0] (set-vars)", "must be a list of one-entry maps"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configPath := writeConfig(t, tt.config)
			_, err := LoadConfiguration(&Options{config: configPath, command: "start", args: []string{"web"}})

			if err == nil {
				t.Fatalf("expected an error mentioning %v, got none", tt.wantErr)
			}
			for _, want := range tt.wantErr {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("error should mention %q, got: %v", want, err)
				}
			}
			// Failing loudly also means saying which tunnel is at fault.
			if !strings.Contains(err.Error(), "Tunnel web") {
				t.Fatalf("error should name the offending tunnel, got: %v", err)
			}
		})
	}
}

// TestTrafficPolicyOnTcpTunnel covers the rule that a policy's HTTP phases need
// a tunnel that speaks HTTP: on a tcp tunnel they would never run, which is a
// control the operator believes in and that is not there. The on_tcp_connect
// phase is real on tcp (the server evaluates it at accept time), so a
// connect-only policy on a tcp tunnel is allowed -- and it is the one policy a
// tcp tunnel can carry.
func TestTrafficPolicyOnTcpTunnel(t *testing.T) {
	t.Run("http phases on a tcp tunnel are refused", func(t *testing.T) {
		configPath := writeConfig(t, `
tunnels:
  db:
    proto:
      tcp: 22
    remote_port: 2022
    traffic_policy:
      on_http_request:
        - name: deny
`)

		_, err := LoadConfiguration(&Options{config: configPath, command: "start", args: []string{"db"}})
		if err == nil {
			t.Fatal("expected an http-phase policy on a tcp tunnel to be refused")
		}
		for _, want := range []string{"Tunnel db", "on_http_request/on_http_response"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("error should mention %q, got: %v", want, err)
			}
		}
	})

	t.Run("a connect-only policy on a tcp tunnel loads", func(t *testing.T) {
		configPath := writeConfig(t, `
tunnels:
  db:
    proto:
      tcp: 22
    remote_port: 2022
    traffic_policy:
      on_tcp_connect:
        - name: restrict-ips
          config:
            allow:
              - 127.0.0.0/8
        - name: log
          config:
            metadata:
              conn: "${conn.client_ip}"
`)

		config, err := LoadConfiguration(&Options{config: configPath, command: "start", args: []string{"db"}})
		if err != nil {
			t.Fatalf("expected the tcp policy to load, got: %v", err)
		}
		if tp := config.Tunnels["db"].TrafficPolicy; tp == nil || len(tp.OnTCPConnect) != 2 {
			t.Fatalf("expected the tcp tunnel to carry its connect-phase policy, got %+v", tp)
		}
	})
}

// TestEmptyTrafficPolicyIsNormalizedToNil pins the one normalization the client
// does: an empty policy document is the absence of a policy, not a policy that
// does nothing, so it must not change what the tunnel registration sends.
func TestEmptyTrafficPolicyIsNormalizedToNil(t *testing.T) {
	tests := []struct {
		name   string
		config string
	}{
		{"an empty document", tunnelYAML("    traffic_policy:")},
		{"empty phases", tunnelYAML("    traffic_policy:", "      on_http_request: []", "      on_http_response: []")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configPath := writeConfig(t, tt.config)

			config, err := LoadConfiguration(&Options{config: configPath, command: "start", args: []string{"web"}})
			if err != nil {
				t.Fatalf("expected the config to load, got: %v", err)
			}
			if tp := config.Tunnels["web"].TrafficPolicy; tp != nil {
				t.Fatalf("an empty policy should normalize to nil, got %+v", tp)
			}
		})
	}
}

// TestNestedNgrokRuleShapeIsRejected pins what happens to ngrok's own rule
// shape, which this build does not implement: a rule whose actions are nested
// has no action name of its own, and yaml.v1 silently drops the key it does not
// know. The load failure is the point -- the shape must not load as something
// that enforces less than its author read into it.
//
// It is only a partial guard, and the limitation is worth stating where the test
// is: yaml.v1 has no strict mode, so a nested rule that happens to *be* named
// after a real action ("- name: deny" with "actions:" under it) decodes as
// that action with no conditions. That shape is not caught here; see the
// changelog's parity notes.
func TestNestedNgrokRuleShapeIsRejected(t *testing.T) {
	configPath := writeConfig(t, tunnelYAML(
		"    traffic_policy:",
		"      on_http_request:",
		"        - actions:",
		"            - type: deny",
	))

	_, err := LoadConfiguration(&Options{config: configPath, command: "start", args: []string{"web"}})
	if err == nil {
		t.Fatal("expected a nested-actions rule to be refused")
	}
	if !strings.Contains(err.Error(), "action has no name") {
		t.Fatalf("expected the unnamed rule to be named in the error, got: %v", err)
	}
}

// --- the flag --------------------------------------------------------------

// TestTrafficPolicyFlagParsing is the flag half: the path reaches Options in
// both spellings, and nothing else about the parse changes.
func TestTrafficPolicyFlagParsing(t *testing.T) {
	opts, _ := parseArgs(t, []string{
		"ngrok",
		"-traffic-policy-file", "/tmp/policy.yml",
		"-proto=http",
		"-hostname=guarded",
		"8080",
	})

	if opts.trafficPolicyFile != "/tmp/policy.yml" {
		t.Fatalf("traffic_policy_file: expected /tmp/policy.yml, got %q", opts.trafficPolicyFile)
	}
	if opts.command != "default" || len(opts.args) != 1 || opts.args[0] != "8080" {
		t.Fatalf("positional argument handling changed: command=%q args=%v", opts.command, opts.args)
	}

	opts, _ = parseArgs(t, []string{"ngrok", "-traffic-policy-file=/tmp/other.yml", "8080"})
	if opts.trafficPolicyFile != "/tmp/other.yml" {
		t.Fatalf("traffic_policy_file: expected /tmp/other.yml, got %q", opts.trafficPolicyFile)
	}
}

// TestTrafficPolicyFlagIsRegistered checks the flag exists and carries help
// text: a flag nobody can discover in the usage output is as good as missing.
func TestTrafficPolicyFlagIsRegistered(t *testing.T) {
	opts, usage := parseArgs(t, []string{"ngrok", "8080"})

	if opts.trafficPolicyFile != "" {
		t.Fatalf("traffic_policy_file should default to empty, got %q", opts.trafficPolicyFile)
	}
	if !strings.Contains(usage, "-traffic-policy-file") {
		t.Fatalf("flag -traffic-policy-file is missing from the usage output:\n%s", usage)
	}
	if !strings.Contains(usage, "HTTP only") {
		t.Fatalf("the flag's help should say it is HTTP only:\n%s", usage)
	}
}

// TestDefaultTunnelTrafficPolicyFromFile is the flag end to end on the client
// side: a policy file is read, validated and attached to the synthesized
// "default" tunnel, and every way of getting it wrong names the file.
func TestDefaultTunnelTrafficPolicyFromFile(t *testing.T) {
	configPath := writeConfig(t, "server_addr: \"tunnel.example.com:443\"\n")
	dir := t.TempDir()

	good := writeFile(t, dir, "good.yml", `
on_http_request:
  - name: deny
    expressions:
      - 'req.url.path == "/blocked"'
  - name: add-headers
    config:
      headers:
        X-Policy-File: from-file
`)
	// The same policy in JSON: a policy document is data, and JSON is a subset
	// of YAML, so the flag takes it. (Only worth a test because it is a promise
	// the loader makes.)
	goodJSON := writeFile(t, dir, "good.json", `{
  "on_http_request": [
    {"name": "deny", "expressions": ["req.url.path == \"/blocked\""]}
  ]
}`)
	empty := writeFile(t, dir, "empty.yml", "# nothing but a comment\n")
	badYAML := writeFile(t, dir, "bad-yaml.yml", "on_http_request: [ this is not: valid\n")
	badPolicy := writeFile(t, dir, "bad-policy.yml", `
on_http_request:
  - name: rate-limit
`)
	missing := filepath.Join(dir, "not-here.yml")

	tests := []struct {
		name     string
		path     string
		protocol string
		wantErr  []string
		wantNil  bool
	}{
		{
			name: "missing file",
			path: missing, protocol: "http",
			wantErr: []string{"Failed to read traffic policy file", missing},
		},
		{
			name: "invalid YAML",
			path: badYAML, protocol: "http",
			wantErr: []string{"Error parsing traffic policy file", badYAML},
		},
		{
			name: "invalid policy names the file and the rule",
			path: badPolicy, protocol: "http",
			wantErr: []string{"Traffic policy file " + badPolicy, "on_http_request[0] (rate-limit)", "unknown action"},
		},
		{
			name: "tcp is refused (the flag is http only)",
			path: good, protocol: "tcp",
			wantErr: []string{"-traffic-policy-file", "only supported for http and https tunnels", "tcp"},
		},
		{
			name: "yaml policy file",
			path: good, protocol: "http",
		},
		{
			name: "json policy file",
			path: goodJSON, protocol: "http",
		},
		{
			name: "empty policy file",
			path: empty, protocol: "http", wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := Options{
				config:            configPath,
				command:           "default",
				args:              []string{"8080"},
				protocol:          tt.protocol,
				trafficPolicyFile: tt.path,
			}

			config, err := LoadConfiguration(&opts)
			if len(tt.wantErr) > 0 {
				if err == nil {
					t.Fatalf("expected an error mentioning %v, got none", tt.wantErr)
				}
				for _, want := range tt.wantErr {
					if !strings.Contains(err.Error(), want) {
						t.Fatalf("error should mention %q, got: %v", want, err)
					}
				}
				return
			}

			if err != nil {
				t.Fatalf("expected the config to load, got: %v", err)
			}
			tp := config.Tunnels["default"].TrafficPolicy
			if tt.wantNil {
				if tp != nil {
					t.Fatalf("an empty policy file should attach no policy, got %+v", tp)
				}
				return
			}
			if tp == nil {
				t.Fatal("the policy file did not reach the default tunnel")
			}
			if _, err := tp.Compile(); err != nil {
				t.Fatalf("the attached policy does not compile: %v", err)
			}
		})
	}
}

// TestDefaultTunnelTrafficPolicyWithNoFlag guards the other direction: without
// the flag the synthesized tunnel carries no policy at all, which is what every
// pre-cluster-4 client sends.
func TestDefaultTunnelTrafficPolicyWithNoFlag(t *testing.T) {
	configPath := writeConfig(t, "server_addr: \"tunnel.example.com:443\"\n")

	config, err := LoadConfiguration(&Options{config: configPath, command: "default", args: []string{"8080"}, protocol: "http"})
	if err != nil {
		t.Fatalf("expected the config to load, got: %v", err)
	}
	if tp := config.Tunnels["default"].TrafficPolicy; tp != nil {
		t.Fatalf("expected no policy without -traffic-policy-file, got %+v", tp)
	}
}

// wireTunnelYAML is what the wire test loads: the same action set as
// guardedTunnelYAML, with no numeric config values, so that the policy the JSON
// envelope carries back is comparable to the one that went in (JSON has one
// number type, and a comparison that hides that would also hide a lost field).
const wireTunnelYAML = `
tunnels:
  guarded:
    hostname: guarded
    proto:
      http: 127.0.0.1:19001
    traffic_policy:
      on_tcp_connect:
        - name: restrict-ips
          config:
            allow:
              - 127.0.0.0/8
      on_http_request:
        - name: deny
          expressions:
            - 'req.url.path == "/blocked"'
        - name: set-vars
          config:
            vars:
              - who: policy
        - name: add-headers
          config:
            headers:
              X-Policy: checked
              X-Who: "${vars.who}"
      on_http_response:
        - name: remove-headers
          config:
            headers:
              - Server
`

// TestReqTunnelCarriesTrafficPolicyOverTheWire pins the one thing the client
// does with a policy besides validating it: it sends it. The registration is a
// JSON envelope on the control connection, so the policy's json tags are part of
// the feature -- a field that does not survive the round trip is a policy the
// server never sees, which looks exactly like a policy that does nothing.
//
// The policy is loaded from a config file rather than built here, and that is
// the substance of the test, not a convenience: yaml.v1 decodes a nested map
// into map[interface{}]interface{}, which encoding/json cannot marshal at all,
// so a struct built in Go would test a path no user takes. The e2e run is what
// found the difference; this is the unit-level guard for it.
func TestReqTunnelCarriesTrafficPolicyOverTheWire(t *testing.T) {
	configPath := writeConfig(t, wireTunnelYAML)

	config, err := LoadConfiguration(&Options{config: configPath, command: "start", args: []string{"guarded"}})
	if err != nil {
		t.Fatalf("expected the config to load, got: %v", err)
	}

	tunnel := config.Tunnels["guarded"]
	if tunnel.TrafficPolicy == nil {
		t.Fatal("the loaded tunnel has no traffic policy")
	}

	req := reqTunnelFromConfig("reqid", tunnel)

	// net.Pipe is unbuffered, so the write has to happen on its own goroutine.
	clientSide, serverSide := net.Pipe()
	errCh := make(chan error, 1)
	go func() { errCh <- msg.WriteMsg(conn.Wrap(clientSide, "test"), req) }()

	raw, err := msg.ReadMsg(conn.Wrap(serverSide, "test"))
	if err != nil {
		t.Fatalf("failed to read the ReqTunnel back: %v", err)
	}
	if err = <-errCh; err != nil {
		t.Fatalf("failed to write the ReqTunnel: %v", err)
	}

	got, ok := raw.(*msg.ReqTunnel)
	if !ok {
		t.Fatalf("expected a *msg.ReqTunnel, got %T", raw)
	}
	if got.TrafficPolicy == nil {
		t.Fatal("the policy did not survive the control-channel envelope")
	}

	if want, have := policyRules(tunnel.TrafficPolicy), policyRules(got.TrafficPolicy); !reflect.DeepEqual(want, have) {
		t.Fatalf("the policy changed on the wire:\n sent: %+v\n got:  %+v", want, have)
	}
	// The server compiles what it receives at registration: a policy that only
	// survives the trip is not enough.
	if _, err := got.TrafficPolicy.Compile(); err != nil {
		t.Fatalf("the policy the server receives does not compile: %v", err)
	}
}
