package server

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"ngrok/policy"
)

// serverConfig is the YAML config file as it appears on disk.
//
// The four rate limits are pointers so that "key absent" is distinguishable
// from "key set to 0": 0 means "disable this limit" to the server, while absent
// means "leave the flag default alone". With plain ints the two collapse into
// the same value, and the CLI could not tell whether the file had asked for
// anything -- see overrides.num in cli.go for what that cost.
type serverConfig struct {
	HttpAddr     string   `yaml:"http_addr"`
	HTTPSAddr    string   `yaml:"https_addr"`
	TunnelAddr   string   `yaml:"tunnel_addr"`
	QuicAddr     string   `yaml:"quic_addr"`
	AdminAddr    string   `yaml:"admin_addr"`
	AdminAuth    string   `yaml:"admin_auth"`
	AdminToken   string   `yaml:"admin_token"`
	AdminRate    *int     `yaml:"admin_rate"`
	Domain       string   `yaml:"domain"`
	TLSCrt       string   `yaml:"tls_crt"`
	TLSKey       string   `yaml:"tls_key"`
	LogTo        string   `yaml:"log"`
	LogLevel     string   `yaml:"log_level"`
	LogFormat    string   `yaml:"log_format"`
	AuthTokens   []string `yaml:"auth_tokens"`
	MaxMsgBytes  int64    `yaml:"max_msg_bytes"`
	AuthRate     *int     `yaml:"auth_rate"`
	PublicRate   *int     `yaml:"public_rate"`
	MaxConnPerIP *int     `yaml:"max_conn_per_ip"`
	EnablePprof  bool     `yaml:"pprof"`

	EventDestinations []eventDestinationConfig `yaml:"event_destinations"`

	// Vaults is the server's secret vaults block (SPEC-CLUSTER9 3), the twin
	// of the client's: key material that traffic policies reference with
	// secret("name/key") and event-destination auth headers with the same
	// spelling. policy.VaultSource is deliberately the one shared type, so
	// strict decode polices its keys on this side exactly as it does on the
	// client's.
	Vaults map[string]policy.VaultSource `yaml:"vaults"`
}

// eventDestinationConfig is one entry of event_destinations: a place the
// server's event stream (SPEC-CLUSTER9 §4) is shipped to. The struct holds the
// file's raw values; the defaults (batch_size 100, flush_interval 5s) are
// applied by the destination constructors in events_export.go, so the config
// layer stays a faithful image of what the operator wrote and the validation
// errors below can quote it.
type eventDestinationConfig struct {
	Type          string `yaml:"type"`
	URL           string `yaml:"url"`
	AuthHeader    string `yaml:"auth_header"`
	BatchSize     int    `yaml:"batch_size"`
	FlushInterval string `yaml:"flush_interval"`
	Path          string `yaml:"path"`
}

func loadServerConfig(path string) (*serverConfig, error) {
	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := new(serverConfig)
	// Strict decoding: a typo'd key (auth_tokens misspelled, a rate limit
	// nested one level too deep) silently leaves the server unprotected when
	// it is discarded -- the security-relevant fields here must either load
	// or fail the load.
	dec := yaml.NewDecoder(bytes.NewReader(buf))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		return nil, err
	}
	if err := cfg.validateEventDestinations(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// validateEventDestinations is the semantic half of strict decoding for the
// event_destinations list. KnownFields(true) already refuses a key the struct
// does not have (a misspelled flush_interval fails the load); what it cannot
// see is a *value* that makes no sense, so every one of those is refused here,
// loudly, with the entry's index -- because an operator with five destinations
// needs to know which one killed the boot.
func (cfg *serverConfig) validateEventDestinations() error {
	for i, d := range cfg.EventDestinations {
		prefix := fmt.Sprintf("event_destinations[%d]", i)
		switch d.Type {
		case "http":
			if d.URL == "" {
				return fmt.Errorf("%s: type http requires url", prefix)
			}
			if d.Path != "" {
				return fmt.Errorf("%s: type http does not take path", prefix)
			}
			if err := validateAuthHeader(d.AuthHeader); err != nil {
				return fmt.Errorf("%s: %v", prefix, err)
			}
			if d.BatchSize < 0 {
				return fmt.Errorf("%s: batch_size must be positive, got %d", prefix, d.BatchSize)
			}
			if err := validateFlushInterval(d.FlushInterval); err != nil {
				return fmt.Errorf("%s: %v", prefix, err)
			}
		case "jsonl":
			if d.Path == "" {
				return fmt.Errorf("%s: type jsonl requires path", prefix)
			}
			// The http-only keys are refused rather than ignored on a jsonl
			// destination for the same reason the top level decodes strictly:
			// a url: sitting under a jsonl entry is almost certainly a
			// misremembered type or a copy-paste from the entry above, and
			// silently dropping it would ship the operator's events somewhere
			// they never asked for.
			if d.URL != "" || d.AuthHeader != "" || d.BatchSize != 0 || d.FlushInterval != "" {
				return fmt.Errorf("%s: type jsonl takes only path (got url/auth_header/batch_size/flush_interval)", prefix)
			}
		default:
			return fmt.Errorf("%s: unknown type %q (want \"http\" or \"jsonl\")", prefix, d.Type)
		}
	}
	return nil
}

// validateAuthHeader checks the "Name: value" shape auth_header must have. The
// name has to be a valid header field name and the value free of CR/LF: both
// reach net/http's header write path unchanged, and a crafted value there is a
// response-splitting primitive, not a typo.
//
// COMPOSITION POINT (SPEC-CLUSTER9 §4.2): auth_header is a literal value in
// this cluster. The vaults work resolves secret("vault/key") to plaintext at
// config load -- before this validation runs on the resolved string -- so no
// vault handling lives here by design.
func validateAuthHeader(header string) error {
	if header == "" {
		return nil
	}
	name, value, ok := strings.Cut(header, ":")
	if !ok || strings.TrimSpace(name) == "" {
		return fmt.Errorf("auth_header must be \"Name: value\", got %q", header)
	}
	if !validHeaderFieldName(name) {
		return fmt.Errorf("auth_header: %q is not a valid header name", name)
	}
	if strings.ContainsAny(value, "\r\n") {
		return fmt.Errorf("auth_header value must not contain CR or LF")
	}
	return nil
}

// validHeaderFieldName reports whether s is an RFC 7230 token: the tchar set,
// no separators, no whitespace. net/http would silently drop anything else
// when writing the header, which would turn a config typo into a destination
// that receives unauthenticated POSTs.
func validHeaderFieldName(name string) bool {
	for _, c := range name {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.ContainsRune("!#$%&'*+-.^_`|~", c):
		default:
			return false
		}
	}
	return true
}

// validateFlushInterval checks the optional duration string. An unset value is
// the destination's default; a set value must parse and be positive, because a
// zero interval at a ticker is a busy loop disguised as configuration.
func validateFlushInterval(raw string) error {
	if raw == "" {
		return nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return fmt.Errorf("flush_interval: %v", err)
	}
	if d <= 0 {
		return fmt.Errorf("flush_interval must be positive, got %s", raw)
	}
	return nil
}
