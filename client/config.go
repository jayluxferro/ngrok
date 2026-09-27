package client

import (
	"fmt"
	"gopkg.in/yaml.v1"
	"net"
	"net/url"
	"ngrok/log"
	"os"
	"os/user"
	"path"
	"regexp"
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

type TunnelConfiguration struct {
	Subdomain  string            `yaml:"subdomain,omitempty"`
	Hostname   string            `yaml:"hostname,omitempty"`
	Protocols  map[string]string `yaml:"proto,omitempty"`
	HttpAuth   string            `yaml:"auth,omitempty"`
	RemotePort uint16            `yaml:"remote_port,omitempty"`

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
	// bindingPublic and bindingInternal are the accepted values of the binding
	// configuration key, and of msg.ReqTunnel.Binding. The empty string is what
	// the wire protocol uses for a public endpoint, so "public" is normalized
	// to "" when the configuration is loaded.
	bindingPublic   = "public"
	bindingInternal = "internal"

	// internalSuffix is the reserved namespace for internal endpoints. It
	// mirrors server/tunnel.go's internalSuffix, which is what actually
	// enforces it: nothing outside it can be registered as internal.
	internalSuffix = ".internal"
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
	if config.InspectMaxBodySize <= 0 {
		config.InspectMaxBodySize = 1 * 1024 * 1024
	}
	if config.ProxyMaxConcurrent <= 0 {
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
			if proxyUrl.Scheme != "http" && proxyUrl.Scheme != "https" {
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
		if t.RemotePort != 0 && len(t.Protocols) != 1 {
			err = fmt.Errorf("Tunnel %s remote_port requires exactly one protocol (tcp)", name)
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

			if t.RemotePort != 0 && k != "tcp" {
				err = fmt.Errorf("Tunnel %s remote_port is only valid for tcp protocol", name)
				return
			}
			if (t.Hostname != "" || t.Subdomain != "") && k == "tcp" {
				err = fmt.Errorf("Tunnel %s hostname/subdomain are only valid for http/https protocols", name)
				return
			}
		}

		if err = validateHeaderPolicy(name, t); err != nil {
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

	switch opts.command {
	// start a single tunnel, the default, simple ngrok behavior
	case "default":
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
			Compression: &opts.compression,
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
		if err = validateHeaderPolicy("default", config.Tunnels["default"]); err != nil {
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
	case "http", "https", "http+https", "tcp":
	default:
		err = fmt.Errorf("Invalid protocol for %s: %s", propName, proto)
	}

	return
}

const (
	hostHeaderRewrite  = "rewrite"
	hostHeaderPreserve = "preserve"
)

// headerTokenRegexp is the RFC 7230 token grammar for header field names. Any
// value that fails it (CR/LF, spaces, ':', control bytes, ...) is rejected here,
// before it can ever reach a header writer.
var headerTokenRegexp = regexp.MustCompile("^[!#$%&'*+\\-.^_`|~0-9A-Za-z]+$")

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

// validateHeaderPolicy validates the header policy of one tunnel. It is called
// both for tunnels read from the config file and for the CLI-synthesized
// "default" tunnel. Everything it rejects is a startup error naming the tunnel
// and the offending entry: there is deliberately no silent fallback.
func validateHeaderPolicy(tunnelName string, t *TunnelConfiguration) error {
	if err := validateHostHeader(tunnelName, t.HostHeader); err != nil {
		return err
	}

	if t.RequestHeader != nil {
		if err := validateHeaderConfig(tunnelName, "request_header", t.RequestHeader); err != nil {
			return err
		}
	}

	if t.ResponseHeader != nil {
		if err := validateHeaderConfig(tunnelName, "response_header", t.ResponseHeader); err != nil {
			return err
		}
	}

	return nil
}

// validateHostHeader accepts the empty value (which means "preserve", the
// historical behavior), the two keywords, or a plain hostname.
func validateHostHeader(tunnelName, hostHeader string) error {
	switch hostHeader {
	case "", hostHeaderRewrite, hostHeaderPreserve:
		return nil
	}

	if strings.ContainsAny(hostHeader, " \t\r\n/") {
		return fmt.Errorf("Tunnel %s: invalid host_header %q: must be 'rewrite', 'preserve' or a hostname with no spaces, no '/' and no CR/LF",
			tunnelName, hostHeader)
	}

	return nil
}

func validateHeaderConfig(tunnelName, section string, hc *HeaderConfig) error {
	for _, entry := range hc.Add {
		if err := validateNoCRLF(tunnelName, section, entry); err != nil {
			return err
		}

		// Split on the first colon only, so that values may contain colons
		// (e.g. "X-Origin: http://example.com").
		colon := strings.Index(entry, ":")
		if colon < 0 {
			return fmt.Errorf("Tunnel %s: %s add entry %q must be formatted as 'key:value'",
				tunnelName, section, entry)
		}

		if err := validateHeaderEntry(tunnelName, section, entry, entry[:colon]); err != nil {
			return err
		}
	}

	for _, key := range hc.Remove {
		if err := validateHeaderEntry(tunnelName, section, key, key); err != nil {
			return err
		}
	}

	return nil
}

// validateHeaderEntry checks a single configured header name. entry is the
// whole configured string, and key the name parsed out of it (equal to entry for
// removals), so that errors can quote what the user actually wrote.
func validateHeaderEntry(tunnelName, section, entry, key string) error {
	if err := validateNoCRLF(tunnelName, section, entry); err != nil {
		return err
	}

	if key == "" {
		return fmt.Errorf("Tunnel %s: %s entry %q has an empty header name", tunnelName, section, entry)
	}

	if !headerTokenRegexp.MatchString(key) {
		return fmt.Errorf("Tunnel %s: %s entry %q: %q is not a valid HTTP header name",
			tunnelName, section, entry, key)
	}

	// ngrok parity: user-agent is not user-settable in either direction.
	if strings.EqualFold(key, "user-agent") {
		return fmt.Errorf("Tunnel %s: %s entry %q: user-agent may not be added or removed",
			tunnelName, section, entry)
	}

	return nil
}

// validateNoCRLF is the header-injection guard: nothing configured here may
// contain CR or LF, wherever it appears in the string.
func validateNoCRLF(tunnelName, section, entry string) error {
	if strings.ContainsAny(entry, "\r\n") {
		return fmt.Errorf("Tunnel %s: %s entry %q contains a CR or LF (header injection)",
			tunnelName, section, entry)
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
	if binding == bindingPublic {
		binding = ""
	}
	t.Binding = binding

	switch binding {
	case "":
		// A .internal hostname registered with the public binding is a tunnel
		// the public listener will never route to (server/http.go treats
		// .internal hosts as misses): refuse it here rather than letting it
		// come online and 404 by construction.
		if strings.HasSuffix(strings.ToLower(t.Hostname), internalSuffix) {
			return fmt.Errorf("Tunnel %s: hostname %q ends in %s, which requires binding internal (the public listener never routes %s hosts)", tunnelName, t.Hostname, internalSuffix, internalSuffix)
		}
	case bindingInternal:
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
	if binding == bindingInternal {
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
			tunnelName, internalSuffix)
	}
	if t.RemotePort != 0 {
		return fmt.Errorf("Tunnel %s: binding internal does not support remote_port: internal endpoints are http/https only", tunnelName)
	}

	hostname := t.Hostname
	if hostname == "" {
		return fmt.Errorf("Tunnel %s: binding internal requires a hostname ending in %s (pass -hostname=myapp%s, or set hostname: myapp%s in the config file)",
			tunnelName, internalSuffix, internalSuffix, internalSuffix)
	}

	// The hostname is the name other tunnels forward to, so it is checked in
	// the exact spelling it will be registered under: the server lowercases it,
	// and a user who wrote "Svc.Internal" would then have a forward_to that
	// does not look like what they configured.
	if hostname != strings.ToLower(hostname) {
		return fmt.Errorf("Tunnel %s: internal hostname %q must be lowercase (use %q)", tunnelName, hostname, strings.ToLower(hostname))
	}
	if !strings.HasSuffix(hostname, internalSuffix) {
		return fmt.Errorf("Tunnel %s: internal hostname %q must end in %s (for example \"myapp%s\")", tunnelName, hostname, internalSuffix, internalSuffix)
	}
	if len(hostname) == len(internalSuffix) {
		return fmt.Errorf("Tunnel %s: internal hostname %q needs a name in front of %s (for example \"myapp%s\")", tunnelName, hostname, internalSuffix, internalSuffix)
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

	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("Tunnel %s: forward_to %q must be an http:// or https:// url pointing at an internal endpoint (for example \"https://myapp%s\")",
			tunnelName, forwardTo, internalSuffix)
	}
	if u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return fmt.Errorf("Tunnel %s: forward_to %q must be only the internal endpoint url, with no path, query or fragment (for example \"https://myapp%s\")",
			tunnelName, forwardTo, internalSuffix)
	}
	if u.Port() != "" {
		return fmt.Errorf("Tunnel %s: forward_to %q must not carry a port: internal endpoints are addressed by name (for example \"https://myapp%s\")",
			tunnelName, forwardTo, internalSuffix)
	}

	hostname := u.Hostname()
	if !strings.HasSuffix(hostname, internalSuffix) || len(hostname) == len(internalSuffix) {
		return fmt.Errorf("Tunnel %s: forward_to %q must point at an internal endpoint whose hostname ends in %s (for example \"https://myapp%s\")",
			tunnelName, forwardTo, internalSuffix, internalSuffix)
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

// isHttpProtocol reports whether a protocol key (as written in the config's
// proto section, so possibly a "+"-joined combination) is one this client
// serves over HTTP.
func isHttpProtocol(proto string) bool {
	for _, p := range strings.Split(proto, "+") {
		if p != "http" && p != "https" {
			return false
		}
	}

	return true
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
