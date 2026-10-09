package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"gopkg.in/yaml.v3"
	"net"
	"net/url"
	"ngrok/log"
	"ngrok/msg"
	"ngrok/policy"
	"ngrok/rewriter"
	"os"
	"os/user"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type Configuration struct {
	HttpProxy          string `yaml:"http_proxy,omitempty"`
	ServerAddr         string `yaml:"server_addr,omitempty"`
	InspectAddr        string `yaml:"inspect_addr,omitempty"`
	InspectAuth        string `yaml:"inspect_auth,omitempty"`
	InspectToken       string `yaml:"inspect_token,omitempty"`
	InspectMaxBodySize int64  `yaml:"inspect_max_body_bytes,omitempty"`
	ProxyMaxConcurrent int    `yaml:"proxy_max_concurrency,omitempty"`

	// ProxyTransport selects the carrier the multiplexed proxy connection
	// (SPEC cluster 3, 3.1) travels on (SPEC-CLUSTER7 5): "auto" prefers QUIC
	// when the server offers it and falls back to TCP per attempt, "quic" and
	// "tcp" pin one carrier (pinning quic still respects the capability gate:
	// a server without msg.QuicCapability is never dialed over UDP). The
	// value is validated against the enum at load -- a typo is a startup
	// error, not a silently different transport -- and resolved against
	// http_proxy in newClientModel, which is where the override is logged:
	// QUIC is UDP end-to-end, and an HTTP CONNECT proxy cannot carry it, so a
	// proxy URL always resolves to TCP.
	ProxyTransport     string                          `yaml:"proxy_transport,omitempty"`
	TrustHostRootCerts bool                            `yaml:"trust_host_root_certs,omitempty"`
	AuthToken          string                          `yaml:"auth_token,omitempty"`
	Tunnels            map[string]*TunnelConfiguration `yaml:"tunnels,omitempty"`

	// Vaults names the secret vaults (SPEC-CLUSTER9 3) that credential values
	// in traffic policies may reference as secret("vault/key") instead of
	// carrying inline. The block is loaded and installed into package policy
	// here, at configuration load, BEFORE any tunnel is validated -- policy
	// validation resolves references through the installed set, so a policy
	// that references a vault must have it available by then. Each side of the
	// protocol loads its own vaults; the same document plus the same vaults
	// resolves identically on both (the server's half is loadServerVaults).
	Vaults map[string]policy.VaultSource `yaml:"vaults,omitempty"`

	LogTo string `yaml:"-"`
	Path  string `yaml:"-"`
}

// HeaderConfig is the "key:value" add list / header-name remove list pair used
// by both request_header and response_header (ngrok v2 config-file shape).
type HeaderConfig struct {
	Add    []string `yaml:"add,omitempty"`
	Remove []string `yaml:"remove,omitempty"`
}

// TLSConfig is a tunnel's `tls:` block (SPEC-CLUSTER5 5.1): the certificate
// material the agent terminates the public https TLS with when
// agent_tls_termination is set. The two pairs are alternative cert models, not
// layers -- an explicit leaf, or a CA the agent mints per-hostname leaves from
// -- and naming both is refused at load (validateAgentTLS), because which one
// would run is otherwise a coin flip decided by code order.
type TLSConfig struct {
	Crt   string `yaml:"crt,omitempty"`
	Key   string `yaml:"key,omitempty"`
	CaCrt string `yaml:"ca_crt,omitempty"`
	CaKey string `yaml:"ca_key,omitempty"`
}

type TunnelConfiguration struct {
	Subdomain  string            `yaml:"subdomain,omitempty"`
	Hostname   string            `yaml:"hostname,omitempty"`
	Protocols  map[string]string `yaml:"proto,omitempty"`
	HttpAuth   string            `yaml:"auth,omitempty"`
	RemotePort uint16            `yaml:"remote_port,omitempty"`

	// AgentTLSTermination switches the tunnel's https leg from edge termination
	// (the server decrypts, today's default) to agent termination (SPEC-CLUSTER5
	// 5.3): the server routes by SNI and relays the TLS bytes unread, and this
	// client terminates and speaks plaintext to the local address. The wire
	// carries it as ReqTunnel.TLSTermination; see reqTunnelFromConfig.
	AgentTLSTermination bool `yaml:"agent_tls_termination,omitempty"`

	// TLS is the certificate material for agent termination. Nil is the common
	// case (ephemeral self-signed, or edge termination entirely). Validated and
	// loaded by validateAgentTLS at configuration load; the files are re-read
	// when the tunnel is established, so a cert rotated on disk between load and
	// registration is picked up at the next reconnect.
	TLS *TLSConfig `yaml:"tls,omitempty"`

	// Alpn lists the application protocols this tunnel's public TLS handshake
	// advertises (SPEC-CLUSTER16 1), in preference order: ["h2", "http/1.1"]
	// offers both and prefers h2. Nil -- the default -- advertises nothing at
	// all, byte-identical handshakes to before the key existed, because
	// advertising h2 unconditionally would flip every h2-capable visitor onto
	// h2 toward local services that only speak HTTP/1.1. Opt-in is the only
	// safe default. The list is agent-local -- it belongs to the terminator,
	// tlsagent.go -- so it never travels the wire; what may accompany an h2
	// offer is validateAlpn's business, and that is checked at load.
	Alpn []string `yaml:"alpn,omitempty"`

	// HTTP header manipulation. Validated for every tunnel regardless of
	// protocol, but only applied to http tunnels.
	HostHeader     string        `yaml:"host_header,omitempty"`
	RequestHeader  *HeaderConfig `yaml:"request_header,omitempty"`
	ResponseHeader *HeaderConfig `yaml:"response_header,omitempty"`

	// UpstreamProtocol selects what this agent speaks to the tunnel's local
	// service (SPEC-CLUSTER17 1): "http1" -- the default, today's plain TCP
	// dial -- or "http2", which puts the h1<->h2c transcoder (client/
	// upstreamh2.go) in the dial's place: the proxy leg stays h1, where the
	// rewriter, policy hooks, tee and XFF injection live, and the local
	// service receives real h2c. The value is a config enum, not a wire
	// advertisement (the server never learns it), so it is matched exactly,
	// no case folding -- but a misspelling fails loudly at load. Empty is the
	// default, and the default is deliberately not written back into the
	// field: LoadConfiguration leaving it empty is what keeps a config
	// round-trip (SaveAuthToken) from growing the key into every tunnel that
	// did not have it. validateUpstreamProtocol owns the rules.
	UpstreamProtocol string `yaml:"upstream_protocol,omitempty"`

	// UpstreamPool opts the tunnel's local leg into connection pooling
	// (SPEC-CLUSTER25): N requests over k pooled keep-alive conns to the local
	// service instead of one fresh dial per proxy connection. The default leg
	// is deliberately raw -- a pooled raw socket cannot be reused soundly (the
	// client cannot know where an h1 message ended), so the pooled leg parses,
	// via httputil.ReverseProxy over the shared pipe scaffolding, and is
	// therefore opt-in: upstream_pool: true means "my local service speaks
	// plain h1 and may be reached with Go-serialized requests". Like
	// UpstreamProtocol and CarrierDedup, the default is never written back into
	// the field: the bool's zero value IS the default and omitempty keeps it
	// out of every config SaveAuthToken re-marshals, so a document without the
	// key round-trips without growing one. What may not keep the key company
	// is validateUpstreamPool's business, judged at load, tunnel named.
	//
	// Upgrade behavior on a pooled tunnel is WebSocket PASSTHROUGH:
	// ReverseProxy relays the 101 handshake and then splices raw bytes both
	// ways, which is what the default raw pipe already does for the same
	// traffic -- refusing upgrades here would regress tunnels that work today.
	// e2e pins the passthrough (scripts/e2e.sh, the pool group).
	UpstreamPool bool `yaml:"upstream_pool,omitempty"`

	// CarrierDedup opts the tunnel's agent<->server carrier into the
	// experimental content-defined chunk dedup (SPEC-CLUSTER21): repeated
	// chunks -- a re-sent 32 KiB LLM system prompt is the shape of the win --
	// cross the carrier as 10-byte references instead of as themselves. Like
	// UpstreamProtocol, the default is never written back into the field: the
	// bool's zero value IS the default and omitempty keeps it out of every
	// config SaveAuthToken re-marshals, so a document without the key
	// round-trips without growing one. What may not keep the key company is
	// validateCarrierDedup's business, judged at load, tunnel named.
	CarrierDedup bool `yaml:"carrier_dedup,omitempty"`

	// Endpoint settings (SPEC 3.2/3.3/3.4). Binding is normalized at load time
	// ("public" becomes the empty string the wire protocol uses) and, together
	// with ForwardTo, validated by validateEndpointPolicy; Pooling is carried
	// through as written.
	Binding   string `yaml:"binding,omitempty"`
	Pooling   bool   `yaml:"pooling,omitempty"`
	ForwardTo string `yaml:"forward_to,omitempty"`

	// Compression is a pointer because the default is on: "no compression key
	// at all" and "compression: false" have to be distinguishable, and a plain
	// bool cannot tell them apart. Compress reports the resolved value.
	Compression *bool `yaml:"compression,omitempty"`

	// TrafficPolicy is this endpoint's traffic policy (SPEC 3.4): the client
	// reads and validates it here, and the server compiles and enforces it --
	// the policy travels in the tunnel registration, so nothing on this side
	// evaluates it. Nil is the case every pre-cluster-4 config has; an empty
	// policy document is normalized to nil so that it takes exactly the same
	// path (validateTrafficPolicy).
	//
	// The rule shape is this build's flat one -- one action per rule, each with
	// name, expressions and config -- not ngrok's list of actions inside a named
	// rule. The parser swap did not move this: the struct above has no field for
	// a nested actions list, and neither yaml.v1 nor yaml.v3 turns an unknown key
	// into anything (both drop it by default, having no strict mode in use here),
	// so the nested spelling is refused by validation -- "action has no name" --
	// and is not a shape this struct can carry. docs/CHANGELOG.md has the
	// deviation and the one nested spelling it does not catch.
	TrafficPolicy *policy.TrafficPolicy `yaml:"traffic_policy,omitempty"`

	// TrafficPolicyFile is traffic_policy_file, the config-file twin of
	// -traffic-policy-file: the policy lives in the named file instead of
	// inline under traffic_policy. It is resolved once at load -- the file is
	// read and its document takes TrafficPolicy's place -- so validation and
	// the wire see one policy however it was sourced. Naming both a file and
	// an inline policy is refused, exactly like naming both cert models in
	// the tls block.
	TrafficPolicyFile string `yaml:"traffic_policy_file,omitempty"`
}

// Compress reports whether responses on this tunnel may be gzip-compressed
// (SPEC 3.4). Compression defaults to on -- the ngrok v2 default -- so the key
// only turns it off when the config says so explicitly; a nil tunnel (a lookup
// miss) reads as the default too.
func (t *TunnelConfiguration) Compress() bool {
	if t == nil || t.Compression == nil {
		return true
	}

	return *t.Compression
}

const (
	// bindingPublicAlias is the one user-facing spelling this package keeps for
	// itself: users write binding: public in a config file and -binding=public
	// on the command line, so the word has to be recognized here. It is not a
	// wire value -- msg.BindingPublic (the empty string) is what the protocol
	// carries, and validateEndpointPolicy normalizes the alias to it, so the
	// server sees exactly one spelling per binding and never sees this one.
	bindingPublicAlias = "public"

	// The upstream_protocol vocabulary (SPEC-CLUSTER17 1). This is client-side
	// configuration, not wire vocabulary -- the server never sees the value --
	// so the consts live here rather than in package msg, next to the
	// validation that enforces them. The tokens are spelled out ("http1", not
	// "h1"; "http2", not "h2") so that the default reads honestly in a config
	// file, and they are matched exactly: the token names a behavior of this
	// agent, so "HTTP2" or the ALPN token "h2" would be a near-miss someone
	// half-remembered from another key, and it is refused rather than guessed
	// at.
	UpstreamProtocolHTTP1 = "http1"

	// UpstreamProtocolHTTP2 selects the h1<->h2c transcoder for the tunnel's
	// local leg (client/upstreamh2.go).
	UpstreamProtocolHTTP2 = "http2"

	// msg.BindingInternal and the .internal namespace are the server's values: both
	// live in package msg with the rest of the wire vocabulary
	// (msg.BindingInternal, msg.InternalSuffix). The client checks them so that
	// a config that could never be reachable fails at load instead of at
	// registration; the server is what enforces them.
)

// The proxy_transport vocabulary (SPEC-CLUSTER7 5). This is client-side
// configuration, not wire vocabulary, so the consts live here rather than in
// package msg: the server never sees the value -- it sees which carrier the
// client dialed, and says whether QUIC exists at all with its AuthResp
// capability.
const (
	// ProxyTransportAuto prefers QUIC per watchdog attempt when the server
	// advertises msg.QuicCapability, falling back to the TCP path within the
	// same attempt on a failed QUIC dial. The default.
	ProxyTransportAuto = "auto"

	// ProxyTransportQuic pins the QUIC carrier, subject to the same
	// capability gate and the same http_proxy override as auto.
	ProxyTransportQuic = "quic"

	// ProxyTransportTCP pins the TCP+smux carrier, which is what the
	// transport ran before SPEC-CLUSTER7.
	ProxyTransportTCP = "tcp"
)

func LoadConfiguration(opts *Options) (config *Configuration, err error) {
	configPath := opts.config
	if configPath == "" {
		configPath = defaultPath()
	}

	log.Info("Reading configuration file %s", configPath)
	configBuf, err := os.ReadFile(configPath)
	if err != nil {
		// failure to read a configuration file is only a fatal error if
		// the user specified one explicitly
		if opts.config != "" {
			err = fmt.Errorf("Failed to read configuration file %s: %v", configPath, err)
			return
		}
	}

	// deserialize/parse the config
	config = new(Configuration)
	if err = yaml.Unmarshal(configBuf, &config); err != nil {
		err = fmt.Errorf("Error parsing configuration file %s: %v", configPath, err)
		return
	}

	// try to parse the old .ngrok format for backwards compatibility
	matched := false
	content := strings.TrimSpace(string(configBuf))
	if matched, err = regexp.MatchString("^[0-9a-zA-Z_\\-!]+$", content); err != nil {
		return
	} else if matched {
		config = &Configuration{AuthToken: content}
	}

	// The http_proxy environment fallback runs before applyDefaultsAndValidate,
	// out of the extracted body. This is order-invisible: no default touches
	// HttpProxy and the fallback only fills the value when empty, so the
	// extracted traversal observes the same document either way.
	if config.HttpProxy == "" {
		config.HttpProxy = os.Getenv("http_proxy")
	}

	// -proxy-transport (SPEC-CLUSTER7 5) rides the same pattern: the flag's
	// empty default leaves the config file's value standing, an explicit
	// value overrides it, and the proxy_transport switch inside the
	// extracted body then validates whichever won -- a flag typo is the same
	// startup error as a file typo, and the workbench road (which has no
	// flags) checks the key with the same switch (SPEC-CLUSTER19 5).
	if opts.proxyTransport != "" {
		config.ProxyTransport = opts.proxyTransport
	}

	if err = config.applyDefaultsAndValidate(true, true); err != nil {
		return
	}

	// override configuration with command-line options
	config.LogTo = opts.logto
	config.Path = configPath
	if opts.authtoken != "" {
		config.AuthToken = opts.authtoken
	}

	// -remote-port is a uint64 flag feeding a uint16 wire field: reject an
	// out-of-range value here, with the flag named, rather than let the
	// conversion wrap a big number into a small port.
	if opts.remotePort > 65535 {
		err = fmt.Errorf("-remote-port must be between 1 and 65535, got %d", opts.remotePort)
		return
	}

	switch opts.command {
	// start a single tunnel, the default, simple ngrok behavior
	case "default":
		// The flag's policy file is read before the tunnel is synthesized, so
		// that a missing or malformed file names the file the user passed
		// rather than the tunnel it would have been attached to.
		var filePolicy *policy.TrafficPolicy
		if filePolicy, err = loadTrafficPolicyFile(opts.trafficPolicyFile); err != nil {
			return
		}

		config.Tunnels = make(map[string]*TunnelConfiguration)
		config.Tunnels["default"] = &TunnelConfiguration{
			Subdomain:      opts.subdomain,
			Hostname:       opts.hostname,
			HttpAuth:       opts.httpauth,
			Protocols:      make(map[string]string),
			HostHeader:     opts.hostHeader,
			RequestHeader:  newHeaderConfig(opts.requestHeaderAdd, opts.requestHeaderRemove),
			ResponseHeader: newHeaderConfig(opts.responseHeaderAdd, opts.responseHeaderRemove),
			Binding:        opts.binding,
			Pooling:        opts.pooling,
			ForwardTo:      opts.forwardTo,
			// The flag defaults to true, so the pointer always has the value
			// the user asked for -- there is no "unset" for a flag.
			Compression:   &opts.compression,
			TrafficPolicy: filePolicy,

			// Fixed remote port and agent TLS termination (SPEC-CLUSTER5),
			// the tunnel's alpn list (SPEC-CLUSTER16 1), and the upstream
			// protocol (SPEC-CLUSTER17 1), wired exactly like the proto
			// options above: the flags feed the synthesized tunnel, and the
			// same validators that police a config-file tunnel police what
			// the flags produced.
			RemotePort:          uint16(opts.remotePort),
			AgentTLSTermination: opts.agentTLSTermination,
			TLS:                 newTLSConfig(opts.tlsCrt, opts.tlsKey, opts.tlsCaCrt, opts.tlsCaKey),
			Alpn:                parseAlpnFlag(opts.alpn),
			UpstreamProtocol:    opts.upstreamProtocol,
		}

		for _, proto := range strings.Split(opts.protocol, "+") {
			if err = validateProtocol(proto, "default"); err != nil {
				return
			}

			if config.Tunnels["default"].Protocols[proto], err = normalizeAddress(opts.args[0], ""); err != nil {
				return
			}
		}

		// the synthesized tunnel never went through the config-file validation
		// loop above, so validate what the endpoint and header flags produced
		// here
		if err = validateEndpointPolicy("default", config.Tunnels["default"]); err != nil {
			return
		}
		if err = validateRemotePort("default", config.Tunnels["default"]); err != nil {
			return
		}
		if err = validateAgentTLS("default", config.Tunnels["default"]); err != nil {
			return
		}
		if err = validateHeaderPolicy("default", config.Tunnels["default"]); err != nil {
			return
		}

		// -traffic-policy-file is documented HTTP-only, like -hostname: a tcp
		// tunnel carries no requests or responses for the policy's HTTP phases
		// to act on. A config-file tunnel may still carry an on_tcp_connect-only
		// policy (the accept path evaluates that phase for tcp as well), but the
		// flag refuses tcp outright rather than meaning two things depending on
		// where the policy was written.
		if filePolicy != nil {
			for proto := range config.Tunnels["default"].Protocols {
				if !isHttpProtocol(proto) {
					err = fmt.Errorf("-traffic-policy-file is only supported for http and https tunnels, not %s (put the policy in a config file tunnel if you want an on_tcp_connect-only policy)", proto)
					return
				}
			}
		}

		if err = validateTrafficPolicy("default", config.Tunnels["default"]); err != nil {
			return
		}

		// Same position as in the config-file loop: after the flag-built
		// policy has been resolved, so the h2 refusals judge the policy that
		// will actually run.
		if err = validateAlpn("default", config.Tunnels["default"]); err != nil {
			return
		}

		// Same position as in the config-file loop: after alpn, so the
		// combined refusal judges a list alpn itself has accepted.
		if err = validateUpstreamProtocol("default", config.Tunnels["default"]); err != nil {
			return
		}

	// list tunnels
	case "list":
		for name, _ := range config.Tunnels {
			fmt.Println(name)
		}
		os.Exit(0)

	// start tunnels
	case "start":
		if len(opts.args) == 0 {
			err = fmt.Errorf("You must specify at least one tunnel to start")
			return
		}

		requestedTunnels := make(map[string]bool)
		for _, arg := range opts.args {
			requestedTunnels[arg] = true

			if _, ok := config.Tunnels[arg]; !ok {
				err = fmt.Errorf("Requested to start tunnel %s which is not defined in the config file.", arg)
				return
			}
		}

		for name, _ := range config.Tunnels {
			if !requestedTunnels[name] {
				delete(config.Tunnels, name)
			}
		}

	case "start-all":
		return

	default:
		err = fmt.Errorf("Unknown command: %s", opts.command)
		return
	}

	return
}

// applyDefaultsAndValidate is LoadConfiguration's post-parse body: the
// defaults and the whole validation traversal, in the order and with the
// error strings LoadConfiguration has always used. It exists so that
// ValidateConfigurationDoc can run the exact same traversal over a document
// that arrived without a file behind it (SPEC-CLUSTER19 5) -- extraction, not
// duplication, because a second copy of the rules is a second set of rules
// free to disagree; the parity corpus in config_test.go is what keeps the
// extraction honest.
//
// loadVaults gates installing the vaults block into package policy's
// process-global set, and loadFileRefs gates reading operator-named files
// (traffic_policy_file). LoadConfiguration passes (true, true); the workbench
// path passes (false, false) and reads no file and touches no process-global
// state.
func (config *Configuration) applyDefaultsAndValidate(loadVaults, loadFileRefs bool) (err error) {
	// set configuration defaults
	if config.ServerAddr == "" {
		config.ServerAddr = defaultServerAddr
	}

	if config.InspectAddr == "" {
		config.InspectAddr = defaultInspectAddr
	}

	// Zero means "the key is absent", which is what a missing YAML key decodes
	// to, and keeps the default. A negative value is a mistake in the file: it
	// used to be clamped to the default in silence, so a typo (or a number past
	// MaxInt64 that the decoder produced a negative for) configured something
	// the operator never asked for and nothing ever said so. Both of these are
	// limits -- one on how much body the inspector captures, one on how many
	// proxied connections run at once -- and a limit that is not what the file
	// says is exactly the kind of thing that is only noticed under load.
	if config.InspectMaxBodySize < 0 {
		return fmt.Errorf("inspect_max_body_bytes must not be negative, got %d (omit the key to keep the default)", config.InspectMaxBodySize)
	}
	if config.InspectMaxBodySize == 0 {
		config.InspectMaxBodySize = 1 * 1024 * 1024
	}
	if config.ProxyMaxConcurrent < 0 {
		return fmt.Errorf("proxy_max_concurrency must not be negative, got %d (omit the key to keep the default)", config.ProxyMaxConcurrent)
	}
	if config.ProxyMaxConcurrent == 0 {
		config.ProxyMaxConcurrent = 64
	}

	// The vaults block is loaded before any tunnel is validated, so that
	// policy validation -- which resolves secret("vault/key") references
	// through the installed set -- sees exactly this configuration's vaults.
	// The call is unconditional: a config without vaults installs the empty
	// set, which both resets whatever a previous load in this process
	// installed and makes an unresolvable reference the loud load error it
	// must be rather than a stale hit.
	//
	// Gated on loadVaults: the workbench path (loadVaults=false, i.e.
	// ValidateConfigurationDoc) never touches process-global vault state
	// (SPEC-CLUSTER19 3). Mutating the process's installed set to answer a UI
	// question would feed garbage to real tunnel registrations, and validating
	// against it would answer a question about the agent's vaults with the
	// server's set. Documents naming vaults are refused before this point
	// (ValidateConfigurationDoc's raw scan); the gate is what keeps every other
	// caller honest too.
	if loadVaults {
		if err = config.loadVaults(); err != nil {
			return
		}
	}

	// validate and normalize configuration
	if config.InspectAddr != "disabled" {
		if config.InspectAddr, err = normalizeAddress(config.InspectAddr, "inspect_addr"); err != nil {
			return
		}
	}

	if config.ServerAddr, err = normalizeAddress(config.ServerAddr, "server_addr"); err != nil {
		return
	}

	if config.HttpProxy != "" {
		var proxyUrl *url.URL
		if proxyUrl, err = url.Parse(config.HttpProxy); err != nil {
			return
		} else {
			if proxyUrl.Scheme != msg.ProtoHTTP && proxyUrl.Scheme != msg.ProtoHTTPS {
				err = fmt.Errorf("Proxy url scheme must be 'http' or 'https', got %v", proxyUrl.Scheme)
				return
			}
		}
	}

	if config.InspectAuth != "" && !strings.Contains(config.InspectAuth, ":") {
		return fmt.Errorf("inspect_auth must be formatted as username:password")
	}
	if config.InspectMaxBodySize > 64*1024*1024 {
		return fmt.Errorf("inspect_max_body_bytes too large (max 67108864)")
	}

	for name, t := range config.Tunnels {
		if t == nil || t.Protocols == nil || len(t.Protocols) == 0 {
			err = fmt.Errorf("Tunnel %s does not specify any protocols to tunnel.", name)
			return
		}
		// Before the protocol loop, and for the CLI-synthesized tunnel further
		// down: the endpoint rules -- binding, the internal namespace, forward_to,
		// and hostname/subdomain versus port-routed protocols -- live in exactly
		// one function, validateEndpointPolicy, so a config key and a command-line
		// flag are refused for the same reasons in the same words.
		if err = validateEndpointPolicy(name, t); err != nil {
			return
		}

		for k, addr := range t.Protocols {
			tunnelName := fmt.Sprintf("for tunnel %s[%s]", name, k)
			if t.Protocols[k], err = normalizeAddress(addr, tunnelName); err != nil {
				return
			}

			if err = validateProtocol(k, tunnelName); err != nil {
				return
			}
		}

		if err = validateRemotePort(name, t); err != nil {
			return
		}

		if err = validateAgentTLS(name, t); err != nil {
			return
		}

		if err = validateHeaderPolicy(name, t); err != nil {
			return
		}

		// traffic_policy_file is resolved here, before validateTrafficPolicy,
		// so the validation below polices one policy however it was sourced:
		// a malformed document in the file produces the same loud load-time
		// error an inline one does, naming the tunnel and the file.
		//
		// Gated on loadFileRefs: the workbench never reads operator-named
		// paths (SPEC-CLUSTER19 5), so a document naming the key is refused,
		// with the way out named, exactly where the file would have been
		// opened. The mutual-exclusion check below is skipped with it -- the
		// refusal is the whole behavior on this road.
		if t.TrafficPolicyFile != "" {
			if !loadFileRefs {
				err = fmt.Errorf("Tunnel %s: traffic_policy_file cannot be resolved here -- inline the policy (traffic_policy) to validate it in the workbench", name)
				return
			}
			if t.TrafficPolicy != nil {
				err = fmt.Errorf("Tunnel %s: traffic_policy and traffic_policy_file are alternatives -- choose one, not both", name)
				return
			}
			if t.TrafficPolicy, err = loadTrafficPolicyFile(t.TrafficPolicyFile); err != nil {
				err = fmt.Errorf("Tunnel %s: %v", name, err)
				return
			}
		}

		if err = validateTrafficPolicy(name, t); err != nil {
			return
		}

		// alpn is judged last on purpose: its h2 rules read the policy and the
		// header settings the validators above have already normalized (see
		// validateAlpn).
		if err = validateAlpn(name, t); err != nil {
			return
		}

		// upstream_protocol is judged after alpn on purpose: its one
		// cross-key rule is the alpn combination, and judging second means the
		// refusal fires only against an alpn list that is otherwise valid --
		// an invalid list is alpn's refusal to give, about alpn.
		if err = validateUpstreamProtocol(name, t); err != nil {
			return
		}

		// upstream_pool is judged after upstream_protocol (its sibling -- both
		// own the local leg), so its http2-combination refusal fires against a
		// tunnel whose upstream_protocol value the validator above has already
		// judged, and after alpn for the same reason upstream_protocol is.
		if err = validateUpstreamPool(name, t); err != nil {
			return
		}

		// carrier_dedup is judged last (SPEC-CLUSTER21): its two cross-key
		// rules read the protocol set validateProtocol has already judged and
		// the agent_tls_termination switch validateAgentTLS has already had
		// its say on, so a tunnel with several problems hears about the others
		// in their own words first. It lives inside the extracted traversal on
		// purpose -- the fb697c3 lesson -- so BOTH roads (the loader and the
		// workbench's ValidateConfigurationDoc) refuse the combination with
		// the same error; the parity corpus in config_test.go pins that.
		if err = validateCarrierDedup(name, t); err != nil {
			return
		}

		// use the name of the tunnel as the subdomain if none is specified.
		// Port-routed protocols (tcp, udp) never take a name -- the server
		// refuses hostname/subdomain on them because their url is the bound
		// port -- so a tunnel whose every protocol is port-routed must not
		// have its name turned into a subdomain it cannot register with.
		// (tcp endpoints used to tolerate the ignored subdomain; udp's
		// refusal is the honest spelling of the same rule, and skipping the
		// assignment changes nothing a tcp tunnel ever saw. Mixed
		// http+nameless-port tunnels keep the assignment: their http leg uses
		// it and the tcp leg always ignored it.)
		if t.Hostname == "" && t.Subdomain == "" && tunnelHasNameRoutedProto(t) {
			// XXX: a crude heuristic, really we should be checking if the last part
			// is a TLD
			if len(strings.Split(name, ".")) > 1 {
				t.Hostname = name
			} else {
				t.Subdomain = name
			}
		}
	}

	// proxy_transport, validated last -- the position it has always held
	// relative to the rest of the traversal (the loader ran this switch in
	// its opts merge, after this whole body; a doc with a bad tunnel AND a
	// bad carrier word has always heard about the tunnel first, and the
	// parity corpus pins that it still does). It lives inside the extracted
	// body so the workbench road refuses a bogus carrier word with the same
	// error instead of waving it through (SPEC-CLUSTER19 5). Case and
	// surrounding space are normalized first, the way binding is: "QUIC"
	// means "quic", not a startup error about a value the operator clearly
	// meant.
	config.ProxyTransport = strings.ToLower(strings.TrimSpace(config.ProxyTransport))
	switch config.ProxyTransport {
	case "":
		config.ProxyTransport = ProxyTransportAuto
	case ProxyTransportAuto, ProxyTransportQuic, ProxyTransportTCP:
	default:
		return fmt.Errorf("proxy_transport must be one of '%s', '%s' or '%s', got '%s' (in the config file or via -proxy-transport)",
			ProxyTransportAuto, ProxyTransportQuic, ProxyTransportTCP, config.ProxyTransport)
	}

	return nil
}

// ErrVaultRefused is the sentinel ValidateConfigurationDoc refuses a
// vault-bearing document with. Vault resolution is process-global state
// (policy.SetVaults): each process -- the agent, ngrokd -- installs and
// resolves against its own configured set, and a validation that runs without
// a process's set has none and will not guess. The sentinel lives here rather
// than in any HTTP layer, so every caller inherits the refusal and can match
// it with errors.Is to give it its own answer (the workbench's 422).
var ErrVaultRefused = errors.New("vault references cannot be resolved here: vaults resolve against each process's own configured set, and this validation has none and will not guess -- remove the vaults block and secret() references to validate the rest of the document")

// ValidateConfigurationDoc parses and validates a client configuration
// document exactly as LoadConfiguration would, without reading files,
// consulting the environment, or touching process-global vault state. It is
// the workbench's validator (SPEC-CLUSTER19 5): the same traversal -- the very
// applyDefaultsAndValidate LoadConfiguration runs -- over a document that
// arrived as bytes, with the two things a file-backed load may do that a
// workbench must not (loading vaults, resolving traffic_policy_file) gated
// off.
//
// A document naming a top-level vaults: block or any secret("vault/key")
// reference is refused with ErrVaultRefused before parsing. The scan runs over
// the raw text on purpose: vault references can sit anywhere a policy can, and
// a structural scan would have to re-implement the YAML grammar to be sure it
// had seen every placement -- crude and fail-closed beats clever and
// occasionally wrong (SPEC-CLUSTER19 3). A header value that merely contains
// "secret(" is refused too, with the explanation.
func ValidateConfigurationDoc(buf []byte) error {
	// The raw scan runs before any parsing, so the refusal cannot be outrun by
	// placement or nesting.
	s := string(buf)
	if strings.Contains(s, "secret(") {
		return fmt.Errorf(`%w: the document contains a secret("vault/key") reference`, ErrVaultRefused)
	}
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(strings.TrimLeft(line, " \t"), "vaults:") {
			return fmt.Errorf("%w: the document contains a top-level vaults: block", ErrVaultRefused)
		}
	}

	// deserialize/parse the document. The wording mirrors LoadConfiguration's
	// parse step; there is no file to name.
	config := new(Configuration)
	if err := yaml.Unmarshal(buf, &config); err != nil {
		return fmt.Errorf("Error parsing configuration document: %v", err)
	}

	// try to parse the old .ngrok format for backwards compatibility, exactly
	// as LoadConfiguration does (same regexp, same place behind the parse).
	content := strings.TrimSpace(s)
	matched, err := regexp.MatchString("^[0-9a-zA-Z_\\-!]+$", content)
	if err != nil {
		return err
	} else if matched {
		config = &Configuration{AuthToken: content}
	}

	return config.applyDefaultsAndValidate(false, false)
}

func defaultPath() string {
	user, err := user.Current()

	// user.Current() does not work on linux when cross compiling because
	// it requires CGO; use os.Getenv("HOME") hack until we compile natively
	homeDir := os.Getenv("HOME")
	if err != nil {
		log.Warn("Failed to get user's home directory: %s. Using $HOME: %s", err.Error(), homeDir)
	} else {
		homeDir = user.HomeDir
	}

	return path.Join(homeDir, ".ngrok")
}

func normalizeAddress(addr string, propName string) (string, error) {
	// normalize port to address
	if _, err := strconv.Atoi(addr); err == nil {
		addr = ":" + addr
	}

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("Invalid address %s '%s': %s", propName, addr, err.Error())
	}

	if host == "" {
		host = "127.0.0.1"
	}

	return fmt.Sprintf("%s:%s", host, port), nil
}

func validateProtocol(proto, propName string) (err error) {
	switch proto {
	case msg.ProtoHTTP, msg.ProtoHTTPS, msg.ProtoHTTPPlusHTTPS, msg.ProtoTCP, msg.ProtoUDP:
	default:
		err = fmt.Errorf("Invalid protocol for %s: %s", propName, proto)
	}

	return
}

const (
	hostHeaderRewrite  = "rewrite"
	hostHeaderPreserve = "preserve"
)

// The alpn vocabulary (SPEC-CLUSTER16 1). Both spellings are the exact ALPN
// wire tokens -- "h2" is the identifier RFC 7540 registers for HTTP/2 and
// "http/1.1" the one HTTP/1.1 negotiates with -- and they are matched exactly
// rather than case-folded: whatever is configured is advertised verbatim in
// the handshake, and a near-miss spelling ("H2", "HTTP/2") is an offer no
// visitor can answer, so it is refused instead of sent.
const (
	alpnH2     = "h2"
	alpnHTTP11 = "http/1.1"
)

// newHeaderConfig turns the repeatable flag values into a HeaderConfig. It
// returns nil when both lists are empty so that users who set no header flags
// keep the exact config they had before (no empty request_header block, and no
// change to how their config re-marshals).
func newHeaderConfig(add, remove []string) *HeaderConfig {
	if len(add) == 0 && len(remove) == 0 {
		return nil
	}

	return &HeaderConfig{Add: add, Remove: remove}
}

// newTLSConfig turns the -tls-* flags into a tunnel's tls block, mirroring
// newHeaderConfig: an all-empty set of flags produces a nil block, so the
// synthesized "default" tunnel of an invocation that said nothing about TLS is
// byte-for-byte the tunnel it used to be.
func newTLSConfig(crt, key, caCrt, caKey string) *TLSConfig {
	if crt == "" && key == "" && caCrt == "" && caKey == "" {
		return nil
	}

	return &TLSConfig{Crt: crt, Key: key, CaCrt: caCrt, CaKey: caKey}
}

// parseAlpnFlag splits -alpn's comma-separated value into a tunnel's alpn
// list (SPEC-CLUSTER16 1), tolerating spaces around the values: "-alpn=h2,
// http/1.1" and "-alpn h2, http/1.1" are one list. The flag's empty default
// stays nil, which is exactly the list a config-file tunnel without the key
// gets. Nothing else is decided here -- an empty piece, an unknown token, a
// duplicate are all left for validateAlpn -- so a flag and a config key are
// refused for the same reasons in the same words.
func parseAlpnFlag(raw string) []string {
	if raw == "" {
		return nil
	}

	parts := strings.Split(raw, ",")
	alpn := make([]string, 0, len(parts))
	for _, part := range parts {
		alpn = append(alpn, strings.TrimSpace(part))
	}

	return alpn
}

// validateHeaderPolicy validates the header settings of one tunnel. It is
// called both for tunnels read from the config file and for the CLI-synthesized
// "default" tunnel. Everything it rejects is a startup error naming the tunnel
// and the offending entry: there is deliberately no silent fallback.
//
// The rules themselves are package rewriter's, and they are applied by building
// the *rewriter.Policy this tunnel would run and calling its Validate: the
// grammar of a header name, the user-agent ban, the CR/LF guards and the
// host_header shapes are one function each, in the package that will put the
// bytes on the wire, rather than a second copy here. That copy is what let a
// tunnel whose host_header could not be written load cleanly (rewriter's
// fuzzing report, R1): the loader accepted values the writer refuses, and the
// only sign of it was traffic that came out wrong.
//
// The form of the policy is the same one client/headers.go builds per
// connection (policyFromTunnel), so what loads is what runs.
func validateHeaderPolicy(tunnelName string, t *TunnelConfiguration) error {
	requestAdd, requestRemove := flattenHeaderConfig(t.RequestHeader)
	responseAdd, responseRemove := flattenHeaderConfig(t.ResponseHeader)

	policy := &rewriter.Policy{
		HostHeader:           t.HostHeader,
		RequestHeaderAdd:     requestAdd,
		RequestHeaderRemove:  requestRemove,
		ResponseHeaderAdd:    responseAdd,
		ResponseHeaderRemove: responseRemove,
	}

	if err := policy.Validate(); err != nil {
		return fmt.Errorf("Tunnel %s: %v", tunnelName, err)
	}

	return nil
}

// validateEndpointPolicy validates the cluster-2 endpoint settings of one
// tunnel: the binding, the internal-namespace rules, forward_to, and
// hostname/subdomain versus port-routed protocols. Like validateHeaderPolicy
// it is called for config-file tunnels and for the CLI-synthesized "default"
// tunnel, so the rules live in exactly one place.
//
// It also normalizes: a binding of "public" (the spelling users will reach for,
// since that is what the flag documents) becomes the empty string that
// msg.ReqTunnel.Binding actually carries, so the server sees exactly one
// spelling per binding. Everything else it rejects is a startup error naming
// the tunnel and the offending value: the failure modes here (a private
// endpoint that silently ends up public, a forward_to that could never resolve)
// are all invisible until traffic arrives, so they are refused up front.
func validateEndpointPolicy(tunnelName string, t *TunnelConfiguration) error {
	binding := strings.ToLower(strings.TrimSpace(t.Binding))
	if binding == bindingPublicAlias {
		binding = ""
	}
	t.Binding = binding

	switch binding {
	case "":
		// A .internal hostname registered with the public binding is a tunnel
		// the public listener will never route to (server/http.go treats
		// .internal hosts as misses): refuse it here rather than letting it
		// come online and 404 by construction.
		if strings.HasSuffix(strings.ToLower(t.Hostname), msg.InternalSuffix) {
			return fmt.Errorf("Tunnel %s: hostname %q ends in %s, which requires binding internal (the public listener never routes %s hosts)", tunnelName, t.Hostname, msg.InternalSuffix, msg.InternalSuffix)
		}
	case msg.BindingInternal:
		if err := validateInternalEndpoint(tunnelName, t); err != nil {
			return err
		}
	default:
		return fmt.Errorf("Tunnel %s: invalid binding %q: must be 'public' or 'internal'", tunnelName, t.Binding)
	}

	// An internal endpoint is served by an agent, not by a public listener, so
	// it can only be the target of an http/https forward chain. The server
	// refuses internal TCP as well (it would have no way to reach it); this
	// mirror of that rule turns a remote registration error into a local one
	// that names the tunnel.
	if binding == msg.BindingInternal {
		for proto := range t.Protocols {
			if !isHttpProtocol(proto) {
				return fmt.Errorf("Tunnel %s: binding internal is only supported for http and https tunnels, not %s", tunnelName, proto)
			}
		}
	}

	// hostname/subdomain name a name-routed endpoint (http, https). The
	// port-routed protocols -- tcp, and udp since SPEC-CLUSTER8 -- are
	// addressed by their public port, so a name on a tunnel whose every
	// protocol is port-routed is a control that could never mean anything:
	// refuse it here rather than silently discard it and register a tunnel
	// under a url nobody asked for. The check lives here, not beside the
	// config-file protocol loop it used to sit in, precisely so that the
	// CLI-synthesized tunnel below is policed by the same rule: "-proto=tcp
	// -hostname=foo" used to drop the hostname without a word.
	//
	// A mixed tunnel keeps its name: an http+tcp tunnel's http leg is
	// name-routed and uses it (the tcp leg ignores it, as it always has), so
	// only the every-leg-port-routed shape is refused.
	if (t.Hostname != "" || t.Subdomain != "") && tunnelAllPortRouted(t) {
		return fmt.Errorf("Tunnel %s: hostname/subdomain are only valid for http/https protocols, got %s", tunnelName, protoNames(t.Protocols))
	}

	// Wildcard hostnames (SPEC 11). The checks sit after the port-routed
	// refusal on purpose: a wildcard on a tcp/udp tunnel is refused by THAT
	// rule, in its words -- a name on a port-routed endpoint is a control that
	// could never mean anything, wildcard or not -- so the grammar below only
	// ever judges names a name-routed endpoint could actually carry.
	//
	// The wildcard lives in the hostname field only: a '*' in subdomain is a
	// spelling the server has no branch for (it would register the star as a
	// literal subdomain label), so it is refused here with the hostname
	// spelling named. And the client's check is grammar-only, deliberately:
	// which domains may carry a wildcard is the server's own-domain rule, and
	// the client cannot know the server's domain -- the server refuses a
	// wildcard over anything else with that domain named (the mirror
	// discipline: same grammar both sides, the domain rule server-side only).
	if strings.Contains(t.Subdomain, "*") {
		return fmt.Errorf("Tunnel %s: subdomain %q must not contain '*': write the wildcard in the hostname instead (for example hostname: \"*.example.com\")",
			tunnelName, t.Subdomain)
	}
	if strings.Contains(t.Hostname, "*") {
		if err := validateWildcardHostname(tunnelName, t); err != nil {
			return err
		}
	}

	return validateForwardTo(tunnelName, t)
}

// validateWildcardHostname polices the registration grammar of SPEC 11 §2 for
// a hostname that contains '*': exactly one leading "*." label, nothing else
// wild, no '*' mid-name -- the shape `*.<domain>`. It is called from
// validateEndpointPolicy for config-file tunnels and the CLI-synthesized
// "default" tunnel alike, and it validates GRAMMAR only: the server serves a
// wildcard over its own configured domain and refuses every other base with
// that domain named, which is a rule this side cannot restate (it does not
// know the domain). What the client can do is refuse, at load, every
// wildcard-bearing spelling that is not a wildcard at all -- "*", "a.*.b",
// "*." with nothing behind it -- so the operator's typo is a startup error
// naming the accepted shape instead of a registration error (or, worse, a
// literal-star name registered and never routed) from the server.
//
// It also canonicalizes: the hostname is lowercased and trimmed before the
// grammar runs and written back, so the grammar judges -- and the wire
// carries -- the exact name the server will register. That is the same
// canonicalization the server applies to every public hostname it registers
// (lowercase, surrounding space stripped), so "*.EXAMPLE.com" and
// " *.example.com" are one hostname here the way they are one hostname there;
// the "*.base" spelling itself survives untouched, and the tunnel's url keeps
// the literal wildcard.
//
// On binding internal the refusal is categorical and comes first: an internal
// endpoint is an exact name in the .internal namespace -- it is how other
// tunnels address it in forward_to -- and a wildcard there would be an
// endpoint with no single name to address.
func validateWildcardHostname(tunnelName string, t *TunnelConfiguration) error {
	if t.Binding == msg.BindingInternal {
		return fmt.Errorf("Tunnel %s: hostname %q must not contain '*': wildcards are a public-binding feature, and internal endpoints are exact names in the %s namespace (the owner namespace must stay exact)",
			tunnelName, t.Hostname, msg.InternalSuffix)
	}

	hostname := strings.ToLower(strings.TrimSpace(t.Hostname))

	rest, ok := strings.CutPrefix(hostname, "*.")
	if !ok {
		return fmt.Errorf("Tunnel %s: hostname %q is not a valid wildcard: the only wildcard form is one leading \"*.\" followed by an exact domain, with no other '*' anywhere (for example \"*.example.com\")",
			tunnelName, t.Hostname)
	}
	if rest == "" {
		return fmt.Errorf("Tunnel %s: hostname %q has no domain after \"*.\" (for example \"*.example.com\")",
			tunnelName, t.Hostname)
	}
	if strings.Contains(rest, "*") {
		return fmt.Errorf("Tunnel %s: hostname %q has more than one '*': exactly one leading \"*.\" is allowed (for example \"*.example.com\")",
			tunnelName, t.Hostname)
	}
	for _, label := range strings.Split(rest, ".") {
		if label == "" {
			return fmt.Errorf("Tunnel %s: hostname %q is not a domain: labels between dots cannot be empty (for example \"*.example.com\")",
				tunnelName, t.Hostname)
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return fmt.Errorf("Tunnel %s: hostname %q is not a domain: %q is not a hostname label -- letters, digits and '-' only (for example \"*.example.com\")",
					tunnelName, t.Hostname, label)
			}
		}
	}

	t.Hostname = hostname
	return nil
}

// validateInternalEndpoint checks the .internal namespace rules of SPEC 3.2:
// internal endpoints are named, never assigned, so a hostname is required and
// nothing may be derived from a subdomain or a port.
func validateInternalEndpoint(tunnelName string, t *TunnelConfiguration) error {
	if t.Subdomain != "" {
		return fmt.Errorf("Tunnel %s: binding internal does not support subdomain: internal endpoints are addressed by hostname in the %s namespace",
			tunnelName, msg.InternalSuffix)
	}
	if t.RemotePort != 0 {
		return fmt.Errorf("Tunnel %s: binding internal does not support remote_port: internal endpoints are http/https only", tunnelName)
	}

	hostname := t.Hostname
	if hostname == "" {
		return fmt.Errorf("Tunnel %s: binding internal requires a hostname ending in %s (pass -hostname=myapp%s, or set hostname: myapp%s in the config file)",
			tunnelName, msg.InternalSuffix, msg.InternalSuffix, msg.InternalSuffix)
	}

	// The hostname is the name other tunnels forward to, so it is checked in
	// the exact spelling it will be registered under: the server lowercases it,
	// and a user who wrote "Svc.Internal" would then have a forward_to that
	// does not look like what they configured.
	if hostname != strings.ToLower(hostname) {
		return fmt.Errorf("Tunnel %s: internal hostname %q must be lowercase (use %q)", tunnelName, hostname, strings.ToLower(hostname))
	}
	if !strings.HasSuffix(hostname, msg.InternalSuffix) {
		return fmt.Errorf("Tunnel %s: internal hostname %q must end in %s (for example \"myapp%s\")", tunnelName, hostname, msg.InternalSuffix, msg.InternalSuffix)
	}
	if len(hostname) == len(msg.InternalSuffix) {
		return fmt.Errorf("Tunnel %s: internal hostname %q needs a name in front of %s (for example \"myapp%s\")", tunnelName, hostname, msg.InternalSuffix, msg.InternalSuffix)
	}
	if strings.ContainsAny(hostname, " \t\r\n/") {
		return fmt.Errorf("Tunnel %s: internal hostname %q must not contain spaces or '/'", tunnelName, hostname)
	}

	return nil
}

// validateForwardTo checks a forward_to target. It has to parse as an http or
// https URL whose host is in the .internal namespace: the server resolves
// forward_to against the internal registry key, which is exactly
// "<scheme>://<hostname>" (server/tunnel.go registerInternal), so anything more
// -- a path, a query, a port, credentials -- could never resolve and would only
// turn into a 502 at request time.
//
// The scheme is not a style choice: an internal endpoint registered with
// -proto=https is keyed "https://svc.internal" and can only be forwarded to
// with that spelling, so a typo here is a 502, not a redirect.
func validateForwardTo(tunnelName string, t *TunnelConfiguration) error {
	forwardTo := t.ForwardTo
	if forwardTo == "" {
		return nil
	}

	u, err := url.Parse(forwardTo)
	if err != nil {
		return fmt.Errorf("Tunnel %s: invalid forward_to %q: %v", tunnelName, forwardTo, err)
	}

	if u.Scheme != msg.ProtoHTTP && u.Scheme != msg.ProtoHTTPS {
		return fmt.Errorf("Tunnel %s: forward_to %q must be an http:// or https:// url pointing at an internal endpoint (for example \"https://myapp%s\")",
			tunnelName, forwardTo, msg.InternalSuffix)
	}
	if u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return fmt.Errorf("Tunnel %s: forward_to %q must be only the internal endpoint url, with no path, query or fragment (for example \"https://myapp%s\")",
			tunnelName, forwardTo, msg.InternalSuffix)
	}
	if u.Port() != "" {
		return fmt.Errorf("Tunnel %s: forward_to %q must not carry a port: internal endpoints are addressed by name (for example \"https://myapp%s\")",
			tunnelName, forwardTo, msg.InternalSuffix)
	}

	hostname := u.Hostname()
	if !strings.HasSuffix(hostname, msg.InternalSuffix) || len(hostname) == len(msg.InternalSuffix) {
		return fmt.Errorf("Tunnel %s: forward_to %q must point at an internal endpoint whose hostname ends in %s (for example \"https://myapp%s\")",
			tunnelName, forwardTo, msg.InternalSuffix, msg.InternalSuffix)
	}

	// A forward chain out of a TCP tunnel could never resolve: internal
	// endpoints are http/https only. The server refuses this too.
	for proto := range t.Protocols {
		if !isHttpProtocol(proto) {
			return fmt.Errorf("Tunnel %s: forward_to is only supported for http and https tunnels, not %s", tunnelName, proto)
		}
	}

	return nil
}

// validateRemotePort checks a tunnel's remote_port claim (SPEC-CLUSTER5 4.1).
// It is the single home of the client-side rules -- the two the loader has
// always applied (exactly one protocol; the protocol must be one a public port
// is meaningful for) plus the privileged-port note -- and it runs for
// config-file tunnels and for the CLI-synthesized "default" tunnel alike, so a
// flag and a config key are refused for the same reasons in the same words.
//
// Since SPEC-CLUSTER8 the protocol rule accepts tcp and udp: a remote_port
// claims a public port, and a udp tunnel's public side is a port exactly the
// way a tcp one is. The two port spaces are independent on the wire (the
// server's claim registry is keyed by (proto, port)), but from the client this
// is one rule about one field.
//
// Ownership of a claimed port is the server's business (its port-claim
// registry); what the client can know without a server is the shape of a claim
// that could never work.
func validateRemotePort(tunnelName string, t *TunnelConfiguration) error {
	if t.RemotePort == 0 {
		return nil
	}

	if len(t.Protocols) != 1 {
		return fmt.Errorf("Tunnel %s remote_port requires exactly one protocol (tcp or udp)", tunnelName)
	}
	for proto := range t.Protocols {
		if proto != msg.ProtoTCP && proto != msg.ProtoUDP {
			return fmt.Errorf("Tunnel %s remote_port is only valid for tcp or udp protocol", tunnelName)
		}
	}

	// Ports below 1024 are the kernel's privileged range: ngrokd can only bind
	// one if its own process is privileged. Without this note a claim that
	// always fails at registration ("bind: permission denied") looks like a
	// server bug rather than a property of the port the config asked for.
	if t.RemotePort < 1024 {
		return fmt.Errorf("Tunnel %s remote_port %d is below 1024: the ngrok server process must run with the privileges to bind privileged ports for such a claim to work (use a port >= 1024 unless you control the server's privileges)", tunnelName, t.RemotePort)
	}

	return nil
}

// validateAgentTLS checks a tunnel's agent TLS termination settings
// (SPEC-CLUSTER5 5.1). Like the validators around it, it runs for config-file
// tunnels and for the CLI-synthesized "default" tunnel, and everything it
// rejects is a startup error naming the tunnel and the offending key or file:
// a TLS setting that does not mean what its author thinks shows up at best as a
// handshake failure in a browser far away, and at worst as plaintext the
// operator believed was encrypted.
//
// When the settings are well-shaped, it also loads and parses the certificate
// files once here, so that a path that does not exist or a PEM that does not
// parse fails at load with the file named, not when the first visitor connects.
func validateAgentTLS(tunnelName string, t *TunnelConfiguration) error {
	// A tls block without the switch is a control that would do nothing at all:
	// refuse it rather than let it sit in the file looking like it terminates
	// something.
	if !t.AgentTLSTermination {
		if t.TLS != nil {
			for _, pair := range []struct{ key, value string }{
				{"tls.crt", t.TLS.Crt},
				{"tls.key", t.TLS.Key},
				{"tls.ca_crt", t.TLS.CaCrt},
				{"tls.ca_key", t.TLS.CaKey},
			} {
				if pair.value != "" {
					return fmt.Errorf("Tunnel %s sets %s but not agent_tls_termination: the tls block only applies to agent-terminated tunnels", tunnelName, pair.key)
				}
			}
		}
		return nil
	}

	// The feature is the https leg's: the http leg of the same tunnel keeps edge
	// termination. A tunnel without an https leg has nothing to terminate, so
	// the switch would be a no-op on tcp (and on http, where there is no TLS to
	// hand over in the first place).
	hasHTTPS := false
	for proto := range t.Protocols {
		if proto == msg.ProtoHTTPS {
			hasHTTPS = true
		}
	}
	if !hasHTTPS {
		return fmt.Errorf("Tunnel %s: agent_tls_termination requires the tunnel's protocols to include https, got %v", tunnelName, protoNames(t.Protocols))
	}

	// Forwarding delivers plaintext http into the target tunnel's agent, and an
	// agent-terminated target would be waiting for a TLS ClientHello instead:
	// the two settings on one endpoint are a standstill, so say so at load
	// (SPEC-CLUSTER5 5.4: forward targets stay plaintext http legs).
	if t.Binding == msg.BindingInternal {
		return fmt.Errorf("Tunnel %s: binding internal cannot be combined with agent_tls_termination: a forwarding target receives plaintext http, which an agent-terminated endpoint does not speak", tunnelName)
	}

	if t.TLS == nil {
		// The ephemeral model: no files to check. The loud WARN about the
		// temporary self-signed certificate happens when the tunnel is
		// established (tlsagent.go), once per session.
		return nil
	}

	// Shape: each pair is all-or-nothing, and the two models are alternatives.
	// These are checked before any file is read so that a half-named pair
	// reports the missing key instead of a confusing open error about the one
	// that was named.
	explicit, ca := t.TLS.Crt != "" || t.TLS.Key != "", t.TLS.CaCrt != "" || t.TLS.CaKey != ""
	if explicit && ca {
		return fmt.Errorf("Tunnel %s: choose explicit cert or CA, not both: tls.crt/tls.key and tls.ca_crt/tls.ca_key name two different certificate models", tunnelName)
	}
	if (t.TLS.Crt == "") != (t.TLS.Key == "") {
		if t.TLS.Crt == "" {
			return fmt.Errorf("Tunnel %s: tls.key requires tls.crt: the certificate and its private key are one pair", tunnelName)
		}
		return fmt.Errorf("Tunnel %s: tls.crt requires tls.key: the certificate and its private key are one pair", tunnelName)
	}
	if (t.TLS.CaCrt == "") != (t.TLS.CaKey == "") {
		if t.TLS.CaCrt == "" {
			return fmt.Errorf("Tunnel %s: tls.ca_key requires tls.ca_crt: the CA certificate and its private key are one pair", tunnelName)
		}
		return fmt.Errorf("Tunnel %s: tls.ca_crt requires tls.ca_key: the CA certificate and its private key are one pair", tunnelName)
	}

	// The files must load and parse now. The built *tls.Config is not kept:
	// building the session config is tlsagent.go's job (and a cert rotated on
	// disk is picked up when the tunnel is established). If this passes, the
	// same call at registration time can only fail if a file changed under us,
	// which the client then reports the same way.
	if _, err := agentTLSConfig(t); err != nil {
		return fmt.Errorf("Tunnel %s: %v", tunnelName, err)
	}

	return nil
}

// validateAlpn checks a tunnel's alpn list (SPEC-CLUSTER16 1): the application
// protocols its agent-terminated terminator offers on the public TLS
// handshake. Like the validators around it, it runs for config-file tunnels
// and for the CLI-synthesized "default" tunnel, and everything it rejects is a
// startup error naming the tunnel and the rule.
//
// It is deliberately the last validator in the chain, because the h2 rules are
// about what ELSE the tunnel configures: they read the traffic policy the
// loaders above have already resolved from traffic_policy_file and stripped of
// empty documents, so an empty policy block cannot masquerade as armed hooks.
//
// The matrix has a deliberate asymmetry worth stating: only an h2 offer
// triggers the passthrough rules. ["http/1.1"] alone pins the leg to h1, which
// the rewriter-driven path already serves, so it changes nothing servicewise
// and demands nothing. With h2 in the list, the connection is raw passthrough
// -- nothing rewriter-driven runs on it -- so every rewriter-driven control
// the tunnel configures would be a control h2 visitors could dodge by
// negotiating h2, and each refusal below names the conflicting key and says
// which side to give up.
func validateAlpn(tunnelName string, t *TunnelConfiguration) error {
	if t.Alpn == nil {
		return nil
	}
	if len(t.Alpn) == 0 {
		return fmt.Errorf("Tunnel %s: alpn is empty: omit the key to offer no ALPN, or list %q and/or %q", tunnelName, alpnH2, alpnHTTP11)
	}

	// Rule 1: the advertised protocols belong to the handshake THIS agent
	// terminates. Without agent_tls_termination the https leg's TLS ends on
	// the server, which advertises no ALPN -- the list would be a promise the
	// handshake never makes. (The https-leg half of the rule mirrors
	// validateAgentTLS's own check, so this function is a total judge of an
	// alpn list; through the loader the earlier validator answers that shape
	// first.)
	if !t.AgentTLSTermination {
		return fmt.Errorf("Tunnel %s: alpn requires agent_tls_termination: the advertised protocols belong to the TLS handshake this agent terminates, and without it the https leg is terminated on the server, which offers no ALPN", tunnelName)
	}
	hasHTTPS := false
	for proto := range t.Protocols {
		if proto == msg.ProtoHTTPS {
			hasHTTPS = true
		}
	}
	if !hasHTTPS {
		return fmt.Errorf("Tunnel %s: alpn requires the tunnel's protocols to include https, got %v", tunnelName, protoNames(t.Protocols))
	}

	// Rule 2: the vocabulary. Matched exactly against the two wire tokens, no
	// duplicates -- a protocol advertised twice is a malformed offer, and a
	// token outside the set is one no visitor could ever negotiate.
	seen := make(map[string]bool, len(t.Alpn))
	for _, proto := range t.Alpn {
		switch proto {
		case alpnH2, alpnHTTP11:
		default:
			return fmt.Errorf("Tunnel %s: alpn value %q is not supported: the accepted values are %q and %q", tunnelName, proto, alpnH2, alpnHTTP11)
		}
		if seen[proto] {
			return fmt.Errorf("Tunnel %s: alpn lists %q more than once: advertise each protocol at most once", tunnelName, proto)
		}
		seen[proto] = true
	}

	// Rule 3, h2 only: the tunnel must be servable for h2 visitors, which by
	// the passthrough semantics means nothing rewriter-driven may be
	// configured. on_tcp_connect is deliberately absent from this list -- it
	// runs server-side on the raw accept, before any TLS exists, so an h2
	// connection cannot dodge it.
	if !seen[alpnH2] {
		return nil
	}

	if t.TrafficPolicy != nil && (len(t.TrafficPolicy.OnHTTPRequest) > 0 || len(t.TrafficPolicy.OnHTTPResponse) > 0) {
		return fmt.Errorf("Tunnel %s: alpn offers h2 but the traffic policy has on_http_request/on_http_response rules: h2 connections are raw passthrough, and a visitor must not be able to dodge them by negotiating h2 (on_tcp_connect is fine -- it runs server-side on the raw accept; drop the h2 alpn value or the http rules)", tunnelName)
	}

	// host_header is judged the way the rewriter judges it, case-insensitively
	// on the keyword: "Preserve" resolves to preserve just as "PRESERVE" does,
	// and neither is a control an h2 visitor could dodge.
	if t.HostHeader != "" && !strings.EqualFold(t.HostHeader, hostHeaderPreserve) {
		return fmt.Errorf("Tunnel %s: alpn offers h2 but host_header is set to %q: rewriting the Host header is rewriter-driven, and a visitor must not be able to dodge it by negotiating h2 (drop host_header, set it to preserve, or drop the h2 alpn value)", tunnelName, t.HostHeader)
	}

	for _, headers := range []struct {
		key string
		cfg *HeaderConfig
	}{
		{"request_header", t.RequestHeader},
		{"response_header", t.ResponseHeader},
	} {
		if headers.cfg == nil || (len(headers.cfg.Add) == 0 && len(headers.cfg.Remove) == 0) {
			continue
		}
		return fmt.Errorf("Tunnel %s: alpn offers h2 but %s adds or removes headers: header manipulation is rewriter-driven, and a visitor must not be able to dodge it by negotiating h2 (drop the h2 alpn value or the %s entries)", tunnelName, headers.key, headers.key)
	}

	// Compression defaults ON, and the rewriter cannot frame h2 bodies -- so an
	// operator must state the off, and a config that merely failed to turn it
	// off is refused the same way one that turned it on is.
	if t.Compress() {
		return fmt.Errorf("Tunnel %s: alpn offers h2 but compression is not explicitly false: compression defaults on and is rewriter-driven, which an h2 visitor bypasses -- set compression: false alongside the h2 alpn value", tunnelName)
	}

	return nil
}

// validateUpstreamProtocol checks a tunnel's upstream_protocol key
// (SPEC-CLUSTER17 1): what this agent speaks to the tunnel's local service.
// Like the validators around it, it runs for config-file tunnels and for the
// CLI-synthesized "default" tunnel, and everything it rejects is a startup
// error naming the tunnel and the rule.
//
// What it deliberately does NOT refuse is the company the key keeps on the h1
// side: binding internal (an internal terminus is dialed like any local
// service), traffic policies, header settings and compression all compose,
// because they all run on the visitor leg -- the leg the transcoder keeps
// unchanged. That contrast with the alpn matrix is the point.
func validateUpstreamProtocol(tunnelName string, t *TunnelConfiguration) error {
	switch t.UpstreamProtocol {
	case "":
		// The key's absence is the default. It is deliberately not normalized
		// to the default here: see TunnelConfiguration.UpstreamProtocol.
		return nil
	case UpstreamProtocolHTTP1, UpstreamProtocolHTTP2:
	default:
		return fmt.Errorf("Tunnel %s: upstream_protocol value %q is not supported: the accepted values are %q and %q",
			tunnelName, t.UpstreamProtocol, UpstreamProtocolHTTP1, UpstreamProtocolHTTP2)
	}

	// The feature is the h1 proxy leg's: a transcoder needs an h1 request to
	// transcode, and the two port-routed protocols are raw byte pipes with no
	// h1 leg at all. Same family of refusal as remote_port's, for the same
	// reason: the key names a control on a protocol that has nothing for it to
	// control.
	for proto := range t.Protocols {
		if !isHttpProtocol(proto) {
			return fmt.Errorf("Tunnel %s: upstream_protocol is only supported for http and https tunnels, not %s", tunnelName, proto)
		}
	}

	// A forwarding endpoint's traffic is handed to another internal endpoint
	// upstream of this agent entirely: this client never dials a local port
	// for it, so there is no local leg for a transcoder to own. The dial the
	// key would change does not happen.
	if t.ForwardTo != "" {
		return fmt.Errorf("Tunnel %s: upstream_protocol cannot be combined with forward_to: a forwarding endpoint's traffic never reaches this agent's local dial, so there is nothing to transcode",
			tunnelName)
	}

	// The two h2 stories own the local leg incompatibly (SPEC-CLUSTER16 vs
	// SPEC-CLUSTER17): alpn's h2 visitors are raw passthrough -- their bytes
	// must reach an h2c listener unmodified -- while upstream_protocol's local
	// leg expects to parse h1 and transcode it. One tunnel, one local-leg
	// shape. An alpn list of ["http/1.1"] alone composes freely: every visitor
	// is h1, and the transcoder serves them all.
	for _, offered := range t.Alpn {
		if offered == alpnH2 {
			return fmt.Errorf("Tunnel %s: upstream_protocol cannot be combined with an alpn list containing %q: the two h2 features own the local leg incompatibly -- alpn passes h2 visitors through raw, so the local service must speak h2c itself, while upstream_protocol keeps the visitor leg h1 and transcodes it to h2c. Use alpn for h2 visitors, upstream_protocol for h1 visitors, never both on one tunnel",
				tunnelName, alpnH2)
		}
	}

	return nil
}

// validateUpstreamPool checks a tunnel's upstream_pool key (SPEC-CLUSTER25):
// the opt-in pooled local leg for HTTP tunnels. Like the validators around it,
// it runs for every tunnel applyDefaultsAndValidate walks, so the loader and
// the workbench road refuse the same document with the same error.
//
// There is deliberately no command-line flag for the key (the spec offers only
// the config-file spelling), so the CLI-synthesized "default" tunnel can never
// carry it and LoadConfiguration's flag branch needs no call here -- the same
// shape validateCarrierDedup documents for itself.
//
// The refusals are the spec's non-goals made loud:
//
//   - any non-HTTP proto leg, tcp/udp including "+"-mixed: the bridge parses
//     h1, and the port-routed protocols are raw byte pipes with no h1 leg at
//     all. The mixed case is refused with the rest because the key is the
//     tunnel's and the proxy path cannot exempt one leg -- the same reasoning
//     validateCarrierDedup gives for refusing its own mixed case.
//   - forward_to: a forwarding endpoint's traffic never reaches this agent's
//     local dial, so there is no local leg to pool.
//   - upstream_protocol: http2: that leg already pools (its transport is the
//     per-address h2 pool of SPEC-CLUSTER17); both keys owning the local dial
//     at once has no meaning.
//   - alpn containing "h2": alpn-h2 visitors are relayed RAW to the local leg
//     (the client never branches on NegotiatedProtocol -- verified absence in
//     client/), so the bridge would parse h2 bytes as h1. An alpn list of
//     ["http/1.1"] composes: every visitor is h1, and the bridge serves them.
//
// What composes, and is deliberately left alone: upstream_protocol: http1 (the
// feature's exact shape), agent_tls_termination (it transforms the remote leg;
// the local dial precedes it), carrier_dedup (carrier leg), compression and the
// header keys (proxy leg), binding internal (an internal terminus is dialed
// like any local service).
func validateUpstreamPool(tunnelName string, t *TunnelConfiguration) error {
	if !t.UpstreamPool {
		return nil
	}

	// isHttpProtocol splits "+"-joined keys the way the server does, so a
	// mixed tunnel ("http+tcp") is refused by the same test that refuses the
	// pure ones -- the key would be silently half-honored on the raw leg.
	for proto := range t.Protocols {
		if !isHttpProtocol(proto) {
			return fmt.Errorf("Tunnel %s: upstream_pool is only supported for http and https tunnels, not %s", tunnelName, proto)
		}
	}

	if t.ForwardTo != "" {
		return fmt.Errorf("Tunnel %s: upstream_pool cannot be combined with forward_to: a forwarding endpoint's traffic never reaches this agent's local dial, so there is nothing to pool",
			tunnelName)
	}

	if t.UpstreamProtocol == UpstreamProtocolHTTP2 {
		return fmt.Errorf("Tunnel %s: upstream_pool cannot be combined with upstream_protocol: http2: the h2 leg already pools its local connections (its per-address h2 transport), and both keys owning the local dial at once has no meaning. Use upstream_pool for an h1 local service, upstream_protocol: http2 for an h2c one",
			tunnelName)
	}

	for _, offered := range t.Alpn {
		if offered == alpnH2 {
			return fmt.Errorf("Tunnel %s: upstream_pool cannot be combined with an alpn list containing %q: alpn passes h2 visitors through to the local leg raw, and the pooled bridge would parse h2 bytes as h1. Use alpn for h2 visitors without pooling, upstream_pool for h1 visitors",
				tunnelName, alpnH2)
		}
	}

	return nil
}

// validateCarrierDedup checks a tunnel's carrier_dedup key (SPEC-CLUSTER21):
// the experimental content-defined chunk dedup on the agent<->server carrier.
// Like the validators around it, it runs for every tunnel applyDefaultsAndValidate
// walks, so the loader and the workbench road refuse the same document with the
// same error.
//
// There is deliberately no command-line flag for the key (the spec offers only
// the config-file spelling), so the CLI-synthesized "default" tunnel can never
// carry it and LoadConfiguration's flag branch needs no call here.
//
// The refusals are the spec's non-goals made loud. A tunnel with ANY udp
// protocol is refused -- mixed tunnels included -- for two honest reasons.
// First, the key would be silently half-honored: the udp flow path's
// StartProxy carries no DedupAck (server/udp.go), so that leg's codec never
// engages and never could -- "the http legs dedup, the udp legs don't" is not
// a distinction the negotiation can express, because the proposal is per
// client and the config key is the tunnel's, and an operator reading
// carrier_dedup: true on a mixed tunnel would be right to expect it means the
// tunnel. Second, a length-framed datagram stream is not the shape the
// feature exists for -- payloads are small (often below the codec's own
// 512-byte minimum chunk) and rarely repeated in bulk. agent_tls_termination
// is the zero-value case: the carrier holds TLS ciphertext, whose fresh AEAD
// nonces mean zero repeats, so the codec would be pure overhead plus a second
// framing layer over encrypted bytes.
func validateCarrierDedup(tunnelName string, t *TunnelConfiguration) error {
	if !t.CarrierDedup {
		return nil
	}

	// The keys are split the way tunnelAllPortRouted splits them: a proto key
	// may be a "+"-joined combination, and a udp leg must not hide behind one
	// (validateProtocol accepts only the enumerated spellings today, so the
	// only udp-bearing key is "udp" -- the split keeps that true by
	// construction rather than by current enum).
	for k := range t.Protocols {
		for _, leg := range strings.Split(k, "+") {
			if leg == msg.ProtoUDP {
				return fmt.Errorf("Tunnel %s: carrier_dedup cannot be combined with a udp protocol (got %s): a udp leg's proxy conn is never acked, so the key would be silently un-honored on that leg, and a length-framed datagram stream is not the repeated-payload shape the feature exists for -- the refusal covers mixed tunnels too, because carrier_dedup is the tunnel's and the negotiation cannot exempt one leg",
					tunnelName, protoNames(t.Protocols))
			}
		}
	}

	if t.AgentTLSTermination {
		return fmt.Errorf("Tunnel %s: carrier_dedup cannot be combined with agent_tls_termination: an agent-terminated tunnel's carrier holds TLS ciphertext, whose fresh AEAD nonces never repeat, so the codec would be pure overhead",
			tunnelName)
	}

	return nil
}

// protoNames renders a protocol map's keys sorted, for error messages: a
// config's proto section is a map, so iterating it directly would make the
// same tunnel describe itself differently run to run.
func protoNames(protocols map[string]string) string {
	names := make([]string, 0, len(protocols))
	for proto := range protocols {
		names = append(names, proto)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// isHttpProtocol reports whether a protocol key (as written in the config's
// proto section, so possibly a "+"-joined combination) is one this client
// serves over HTTP. The rule is the wire vocabulary's, in package msg, because
// the server asks the same question of the same field (SPEC 3.2/3.4).
func isHttpProtocol(proto string) bool {
	return msg.IsHTTPOnly(proto)
}

// hasHTTPProtocol reports whether a tunnel serves at least one http or https
// leg, which is the question that decides whether a policy's HTTP phases can
// ever run on it.
func hasHTTPProtocol(t *TunnelConfiguration) bool {
	for proto := range t.Protocols {
		if isHttpProtocol(proto) {
			return true
		}
	}

	return false
}

// validateTrafficPolicy validates one tunnel's traffic policy (SPEC 3.4). Like
// validateHeaderPolicy it is called for tunnels read from the config file and
// for the CLI-synthesized "default" tunnel, so a policy is checked by exactly
// one code path no matter what wrote it.
//
// What a policy may say -- the action names, the phase each action may appear
// in, the CEL expressions, every per-action config field -- belongs to package
// policy, which fails loudly and names the rule. This wrapper adds the two
// things that package cannot know: which tunnel the operator wrote the policy
// under, and whether the tunnel can run the phases it asks for. Everything
// rejected here is a startup error: a policy that does not mean what its author
// thinks must not reach the edge, where its only symptom would be traffic the
// operator believes is policed and is not.
func validateTrafficPolicy(tunnelName string, t *TunnelConfiguration) error {
	if t.TrafficPolicy == nil {
		return nil
	}

	// An empty policy document ("traffic_policy:" with nothing under it, or
	// only empty phases) has no rules to enforce and no hooks to build, so it is
	// normalized away: the tunnel then takes exactly the path it takes without
	// the key, wire included.
	if t.TrafficPolicy.IsZero() {
		t.TrafficPolicy = nil
		return nil
	}

	// Normalize before validating, so that what is checked is what will be
	// sent. See normalizeTrafficPolicy for what there is to normalize.
	normalizeTrafficPolicy(t.TrafficPolicy)

	if err := t.TrafficPolicy.Validate(); err != nil {
		return fmt.Errorf("Tunnel %s: invalid traffic policy: %v", tunnelName, err)
	}

	// The HTTP phases act on requests and responses, so they only fire on a
	// connection that carries HTTP. A policy that has them on a tunnel with no
	// http or https leg is a control that can never run: refuse it rather than
	// let it sit in a config file looking like it is enforcing something. The
	// on_tcp_connect phase is real on both kinds of tunnel (the server evaluates
	// it at accept time, and again in the HTTP handler), so a connect-only
	// policy is allowed on tcp.
	if !hasHTTPProtocol(t) && (len(t.TrafficPolicy.OnHTTPRequest) > 0 || len(t.TrafficPolicy.OnHTTPResponse) > 0) {
		return fmt.Errorf("Tunnel %s: traffic policy has on_http_request/on_http_response rules, which only run on http and https tunnels, and this tunnel has neither", tunnelName)
	}

	return nil
}

// normalizeTrafficPolicy rewrites a policy's config values into the map shapes
// the control channel can carry. The YAML decoder can produce
// map[interface{}]interface{} at any depth, which has no key type and which
// encoding/json therefore refuses to marshal at all -- and the tunnel
// registration is a JSON envelope. A policy straight out of a YAML file would
// otherwise fail at the first ReqTunnel and take the whole control connection
// down with it, retrying forever: the e2e found this, and the unit tests could
// not, because they built their policies in Go, where the maps are already
// map[string]interface{}.
//
// What the yaml.v3 migration changed here, and why the pass stayed anyway: v1
// gave *every* nested map the interface-keyed shape, so this rewrote every
// config value of every policy loaded from a file; v3 uses
// map[string]interface{} when all the keys are strings and falls back to the
// interface-keyed shape only when one is not (an int, a bool, a null). So for a
// policy that validates this is now usually a no-op -- asMap refuses a non-string
// key wherever it reads one, so no valid policy has one -- and it is kept because
// the loader cannot know that before validation has run, and the cost of being
// wrong is a client that never registers.
//
// The one thing it still does to such a document is rewrite the key itself: a
// non-string key becomes its %v rendering *before* Validate sees it, so it is
// judged as a config field name (which will not match any field an action
// documents) rather than refused as a key. That is what v1 did with every map,
// and it is left exactly as it was found: changing it would change which
// documents are refused, which is not what a parser swap is for.
func normalizeTrafficPolicy(tp *policy.TrafficPolicy) {
	if tp == nil {
		return
	}

	for _, rules := range [][]*policy.Action{tp.OnTCPConnect, tp.OnHTTPRequest, tp.OnHTTPResponse} {
		for _, r := range rules {
			if r == nil || r.Config == nil {
				continue
			}
			r.Config = normalizePolicyMap(r.Config)
		}
	}
}

// normalizePolicyMap rebuilds one map with every nested value normalized.
func normalizePolicyMap(m map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		out[k] = normalizePolicyValue(v)
	}

	return out
}

// normalizePolicyValue is normalizePolicyMap's recursion: it converts the YAML
// map shape and leaves every other value as it is, including the numbers YAML
// and JSON decode differently (configStatus reads both).
func normalizePolicyValue(v interface{}) interface{} {
	switch t := v.(type) {
	case map[interface{}]interface{}:
		out := make(map[string]interface{}, len(t))
		for k, val := range t {
			key, ok := k.(string)
			if !ok {
				key = fmt.Sprintf("%v", k)
			}
			out[key] = normalizePolicyValue(val)
		}
		return out

	case map[string]interface{}:
		return normalizePolicyMap(t)

	case []interface{}:
		out := make([]interface{}, len(t))
		for i, val := range t {
			out[i] = normalizePolicyValue(val)
		}
		return out
	}

	return v
}

// loadTrafficPolicyFile reads the file named by -traffic-policy-file. YAML is
// the documented format and is what the config file's traffic_policy key is
// written in; a JSON policy document is tolerated, because JSON is a subset of
// YAML and the decoder parses it as one (there is a test for the spelling).
//
// The policy is validated here, not later: the point of validating at load time
// is that a control which does not mean what its author thinks never reaches a
// tunnel. The errors name the file the user passed, and -- through package
// policy -- the rule inside it.
//
// An empty path (the flag was not given) and an empty document both load to a
// nil policy, which is what the tunnel registration sends when there is no
// policy at all.
func loadTrafficPolicyFile(path string) (*policy.TrafficPolicy, error) {
	if path == "" {
		return nil, nil
	}

	log.Info("Reading traffic policy file %s", path)

	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("Failed to read traffic policy file %s: %v", path, err)
	}

	tp := new(policy.TrafficPolicy)
	if err = yaml.Unmarshal(buf, tp); err != nil {
		// A document that looks like JSON but did not parse as YAML gets a
		// second attempt through encoding/json, whose error names the offset:
		// the YAML parser's complaint about flow syntax is not much help to
		// someone who wrote a JSON file.
		if tp = parseJSONPolicy(buf); tp == nil {
			return nil, fmt.Errorf("Error parsing traffic policy file %s: %v", path, err)
		}
	}

	normalizeTrafficPolicy(tp)

	if err = tp.Validate(); err != nil {
		return nil, fmt.Errorf("Traffic policy file %s: %v", path, err)
	}

	if tp.IsZero() {
		return nil, nil
	}

	return tp, nil
}

// parseJSONPolicy is the second attempt described above. It returns nil for a
// document that does not look like JSON, or that JSON cannot parse, so that the
// caller reports the YAML parser's error rather than two guesses.
func parseJSONPolicy(buf []byte) *policy.TrafficPolicy {
	trimmed := strings.TrimSpace(string(buf))
	if trimmed == "" || (trimmed[0] != '{' && trimmed[0] != '[') {
		return nil
	}

	tp := new(policy.TrafficPolicy)
	if err := json.Unmarshal([]byte(trimmed), tp); err != nil {
		return nil
	}

	return tp
}

// loadVaults resolves the configuration's vaults: block into package policy's
// process-wide vault set (SPEC-CLUSTER9 3.1). The source loading itself --
// the vault file reads, the environment scan, the per-entry validation -- is
// policy.LoadVaults, the same loader the server runs over its own config, so
// one file shape and one set of load errors serve both sides.
//
// It is called unconditionally from LoadConfiguration: a configuration with no
// vaults installs the empty set. That is what makes an secret("vault/key")
// reference in a vault-less config a load error ("no vaults are configured")
// instead of either a crash on stale state or -- worse -- the reference text
// silently becoming a credential that matches nothing.
func (c *Configuration) loadVaults() error {
	vaults, err := policy.LoadVaults(c.Vaults)
	if err != nil {
		return err
	}
	policy.SetVaults(vaults)
	return nil
}

func SaveAuthToken(configPath, authtoken string) (err error) {
	// empty configuration by default for the case that we can't read it
	c := new(Configuration)

	// read the configuration
	oldConfigBytes, err := os.ReadFile(configPath)
	if err == nil {
		// unmarshal if we successfully read the configuration file
		if err = yaml.Unmarshal(oldConfigBytes, c); err != nil {
			return
		}
	}

	// no need to save, the authtoken is already the correct value
	if c.AuthToken == authtoken {
		return
	}

	// update auth token
	c.AuthToken = authtoken

	// rewrite configuration
	newConfigBytes, err := yaml.Marshal(c)
	if err != nil {
		return
	}

	err = os.WriteFile(configPath, newConfigBytes, 0600)
	return
}

// nameRoutedLegs reports whether any leg of one protocol key is routed by name
// (http, https). A proto section key may be the "+"-joined combination the
// client spells for one endpoint with several legs ("http+https") -- a single
// map key, so an exact match against "http" or "https" misses it -- and it is
// split the same way the server splits ReqTunnel.Protocol (see
// msg.IsHTTPOnly) before asking each leg.
func nameRoutedLegs(k string) bool {
	for _, leg := range strings.Split(k, "+") {
		if msg.IsHTTP(leg) {
			return true
		}
	}

	return false
}

// tunnelHasNameRoutedProto reports whether any of the tunnel's protocols is
// routed by name (http, https) rather than by a bound port (tcp, udp). The
// auto-subdomain step consults it: a name a port-routed endpoint cannot
// register with must not be assigned to one. A combined key takes part with
// its legs, so "http+https" counts as name-routed (its legs are), while a key
// made only of port-routed legs never could.
func tunnelHasNameRoutedProto(t *TunnelConfiguration) bool {
	for k := range t.Protocols {
		if nameRoutedLegs(k) {
			return true
		}
	}
	return false
}

// tunnelAllPortRouted is tunnelHasNameRoutedProto's complement over the whole
// tunnel: every leg of every protocol key is port-routed (tcp, udp), so there
// is no leg a hostname or subdomain could attach to. validateEndpointPolicy
// refuses that shape when the tunnel also carries a name.
func tunnelAllPortRouted(t *TunnelConfiguration) bool {
	if len(t.Protocols) == 0 {
		return false
	}
	for k := range t.Protocols {
		for _, leg := range strings.Split(k, "+") {
			if leg != msg.ProtoTCP && leg != msg.ProtoUDP {
				return false
			}
		}
	}

	return true
}
