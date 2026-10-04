package client

import (
	"encoding/json"
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
	HttpProxy          string                          `yaml:"http_proxy,omitempty"`
	ServerAddr         string                          `yaml:"server_addr,omitempty"`
	InspectAddr        string                          `yaml:"inspect_addr,omitempty"`
	InspectAuth        string                          `yaml:"inspect_auth,omitempty"`
	InspectToken       string                          `yaml:"inspect_token,omitempty"`
	InspectMaxBodySize int64                           `yaml:"inspect_max_body_bytes,omitempty"`
	ProxyMaxConcurrent int                             `yaml:"proxy_max_concurrency,omitempty"`
	TrustHostRootCerts bool                            `yaml:"trust_host_root_certs,omitempty"`
	AuthToken          string                          `yaml:"auth_token,omitempty"`
	Tunnels            map[string]*TunnelConfiguration `yaml:"tunnels,omitempty"`
	LogTo              string                          `yaml:"-"`
	Path               string                          `yaml:"-"`
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

	// HTTP header manipulation. Validated for every tunnel regardless of
	// protocol, but only applied to http tunnels.
	HostHeader     string        `yaml:"host_header,omitempty"`
	RequestHeader  *HeaderConfig `yaml:"request_header,omitempty"`
	ResponseHeader *HeaderConfig `yaml:"response_header,omitempty"`

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

	// msg.BindingInternal and the .internal namespace are the server's values: both
	// live in package msg with the rest of the wire vocabulary
	// (msg.BindingInternal, msg.InternalSuffix). The client checks them so that
	// a config that could never be reachable fails at load instead of at
	// registration; the server is what enforces them.
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
		return nil, fmt.Errorf("inspect_max_body_bytes must not be negative, got %d (omit the key to keep the default)", config.InspectMaxBodySize)
	}
	if config.InspectMaxBodySize == 0 {
		config.InspectMaxBodySize = 1 * 1024 * 1024
	}
	if config.ProxyMaxConcurrent < 0 {
		return nil, fmt.Errorf("proxy_max_concurrency must not be negative, got %d (omit the key to keep the default)", config.ProxyMaxConcurrent)
	}
	if config.ProxyMaxConcurrent == 0 {
		config.ProxyMaxConcurrent = 64
	}

	if config.HttpProxy == "" {
		config.HttpProxy = os.Getenv("http_proxy")
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
		return nil, fmt.Errorf("inspect_auth must be formatted as username:password")
	}
	if config.InspectMaxBodySize > 64*1024*1024 {
		return nil, fmt.Errorf("inspect_max_body_bytes too large (max 67108864)")
	}

	for name, t := range config.Tunnels {
		if t == nil || t.Protocols == nil || len(t.Protocols) == 0 {
			err = fmt.Errorf("Tunnel %s does not specify any protocols to tunnel.", name)
			return
		}
		// Before the protocol loop: the endpoint rules are more specific than
		// "hostname/subdomain are only valid for http/https", so a bad
		// internal-plus-tcp combination should say that instead.
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

			if (t.Hostname != "" || t.Subdomain != "") && k == msg.ProtoTCP {
				err = fmt.Errorf("Tunnel %s hostname/subdomain are only valid for http/https protocols", name)
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

		if err = validateTrafficPolicy(name, t); err != nil {
			return
		}

		// use the name of the tunnel as the subdomain if none is specified
		if t.Hostname == "" && t.Subdomain == "" {
			// XXX: a crude heuristic, really we should be checking if the last part
			// is a TLD
			if len(strings.Split(name, ".")) > 1 {
				t.Hostname = name
			} else {
				t.Subdomain = name
			}
		}
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
			// wired exactly like the proto options above: the flags feed the
			// synthesized tunnel, and the same validators that police a
			// config-file tunnel police what the flags produced.
			RemotePort:          uint16(opts.remotePort),
			AgentTLSTermination: opts.agentTLSTermination,
			TLS:                 newTLSConfig(opts.tlsCrt, opts.tlsKey, opts.tlsCaCrt, opts.tlsCaKey),
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
	case msg.ProtoHTTP, msg.ProtoHTTPS, msg.ProtoHTTPPlusHTTPS, msg.ProtoTCP:
	default:
		err = fmt.Errorf("Invalid protocol for %s: %s", propName, proto)
	}

	return
}

const (
	hostHeaderRewrite  = "rewrite"
	hostHeaderPreserve = "preserve"
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
// tunnel: the binding, the internal-namespace rules, and forward_to. Like
// validateHeaderPolicy it is called for config-file tunnels and for the
// CLI-synthesized "default" tunnel, so the rules live in exactly one place.
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

	return validateForwardTo(tunnelName, t)
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
// always applied (tcp only, exactly one protocol) plus the two this feature
// adds -- and it runs for config-file tunnels and for the CLI-synthesized
// "default" tunnel alike, so a flag and a config key are refused for the same
// reasons in the same words.
//
// Ownership of a claimed port is the server's business (its port-claim
// registry); what the client can know without a server is the shape of a claim
// that could never work.
func validateRemotePort(tunnelName string, t *TunnelConfiguration) error {
	if t.RemotePort == 0 {
		return nil
	}

	if len(t.Protocols) != 1 {
		return fmt.Errorf("Tunnel %s remote_port requires exactly one protocol (tcp)", tunnelName)
	}
	for proto := range t.Protocols {
		if proto != msg.ProtoTCP {
			return fmt.Errorf("Tunnel %s remote_port is only valid for tcp protocol", tunnelName)
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
