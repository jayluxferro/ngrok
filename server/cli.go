package server

import (
	"flag"
	"fmt"
	"os"
	"strings"
)

type Options struct {
	httpAddr     string
	httpsAddr    string
	tunnelAddr   string
	quicAddr     string
	adminAddr    string
	adminAuth    string
	adminToken   string
	adminRate    int
	statusURL    string
	statusAuth   string
	statusToken  string
	domain       string
	tlsCrt       string
	tlsKey       string
	logto        string
	loglevel     string
	logformat    string
	authTokens   []string // Valid auth tokens (empty means no validation required)
	maxMsgBytes  int64
	authRate     int
	publicRate   int
	maxConnPerIP int
	enablePprof  bool
	// eventDestinations is the server-side event export list
	// (SPEC-CLUSTER9 §4). Deliberately config-only, with no flag: each entry
	// is a small struct (type/url/auth_header/batch_size/flush_interval/path)
	// and the two destination types want disjoint keys, so a flag would need
	// a bespoke lossy mini-grammar -- exactly what the YAML config file
	// already expresses. parseArgs copies the list through untouched; all
	// validation happened at load.
	eventDestinations []eventDestinationConfig
}

func parseArgs() *Options {
	configPath := flag.String("config", "", "Path to ngrokd YAML config file")
	httpAddr := flag.String("httpAddr", ":80", "Public address for HTTP connections, empty string to disable")
	httpsAddr := flag.String("httpsAddr", ":443", "Public address listening for HTTPS connections, emptry string to disable")
	tunnelAddr := flag.String("tunnelAddr", ":4443", "Public address listening for ngrok client")
	quicAddr := flag.String("quicAddr", "", "Public address listening for QUIC proxy sessions (UDP), empty string to disable")
	adminAddr := flag.String("adminAddr", "", "Address for admin endpoints (/healthz, /metrics), empty to disable")
	adminAuth := flag.String("adminAuth", "", "Admin basic auth in user:password format")
	adminToken := flag.String("adminToken", "", "Admin token required via X-Ngrok-Admin-Token")
	adminRate := flag.Int("adminRate", 120, "Max admin requests per minute per IP (0 disables)")
	statusURL := flag.String("statusURL", "", "Query an admin endpoint URL and print status, then exit")
	statusAuth := flag.String("statusAuth", "", "Basic auth for -statusURL in user:password format")
	statusToken := flag.String("statusToken", "", "Token for -statusURL via X-Ngrok-Admin-Token")
	domain := flag.String("domain", "ngrok.com", "Domain where the tunnels are hosted")
	tlsCrt := flag.String("tlsCrt", "", "Path to a TLS certificate file")
	tlsKey := flag.String("tlsKey", "", "Path to a TLS key file")
	logto := flag.String("log", "stdout", "Write log messages to this file. 'stdout' and 'none' have special meanings")
	loglevel := flag.String("log-level", "DEBUG", "The level of messages to log. One of: DEBUG, INFO, WARNING, ERROR")
	logformat := flag.String("log-format", "text", "Log format: text or json")
	authTokensFlag := flag.String("authToken", "", "Comma-separated list of valid auth tokens (optional, if not set, no authentication required)")
	hashToken := flag.String("hashToken", "", "Print sha256 token hash in format 'sha256:<hex>' and exit")
	maxMsgBytes := flag.Int64("maxMsgBytes", 4*1024*1024, "Maximum control/proxy protocol message size in bytes")
	authRate := flag.Int("authRate", 60, "Max auth attempts per minute per IP (0 disables)")
	publicRate := flag.Int("publicRate", 0, "Max new public connections per second per IP (0 disables)")
	maxConnPerIP := flag.Int("maxConnPerIP", 0, "Max concurrent public connections per IP (0 disables)")
	enablePprof := flag.Bool("pprof", false, "Enable pprof handlers on admin server (requires -adminAddr)")
	flag.Parse()

	if *hashToken != "" {
		fmt.Printf("sha256:%s\n", tokenDigest(*hashToken))
		os.Exit(0)
	}
	if *statusURL != "" {
		if err := runStatus(*statusURL, *statusAuth, *statusToken); err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}
		os.Exit(0)
	}

	seen := explicitFlags()

	// event_destinations has no flag to compete with, so it is collected here
	// and applied in the return below.
	var eventDestinations []eventDestinationConfig

	if *configPath != "" {
		cfg, err := loadServerConfig(*configPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Failed to read config:", err.Error())
			os.Exit(1)
		}
		// The vaults install before anything else reads them: tunnel
		// registrations compile agent policies against this set, and the
		// event destinations' auth_header values resolve against it below.
		if err := loadServerVaults(cfg.Vaults); err != nil {
			fmt.Fprintln(os.Stderr, "Failed to load vaults:", err.Error())
			os.Exit(1)
		}
		// Precedence: an explicit command-line flag beats the config file
		// (the flag is the more recent, more specific statement of intent),
		// and a config file beats the flag's built-in default. The helpers
		// below are what keep that rule in one place; before them this was 20
		// hand-written `if !seen[...] && ...` branches, which is how the rate
		// limits came to be silently disabled (see overrides.num).
		seen.str(httpAddr, cfg.HttpAddr, "httpAddr")
		seen.str(httpsAddr, cfg.HTTPSAddr, "httpsAddr")
		seen.str(tunnelAddr, cfg.TunnelAddr, "tunnelAddr")
		seen.str(quicAddr, cfg.QuicAddr, "quicAddr")
		seen.str(adminAddr, cfg.AdminAddr, "adminAddr")
		seen.str(adminAuth, cfg.AdminAuth, "adminAuth")
		seen.str(adminToken, cfg.AdminToken, "adminToken")
		seen.num(adminRate, cfg.AdminRate, "adminRate")
		seen.str(domain, cfg.Domain, "domain")
		seen.str(tlsCrt, cfg.TLSCrt, "tlsCrt")
		seen.str(tlsKey, cfg.TLSKey, "tlsKey")
		seen.str(logto, cfg.LogTo, "log")
		seen.str(loglevel, cfg.LogLevel, "log-level")
		seen.str(logformat, cfg.LogFormat, "log-format")
		seen.positive(maxMsgBytes, cfg.MaxMsgBytes, "maxMsgBytes")
		seen.num(authRate, cfg.AuthRate, "authRate")
		seen.num(publicRate, cfg.PublicRate, "publicRate")
		seen.num(maxConnPerIP, cfg.MaxConnPerIP, "maxConnPerIP")
		seen.yes(enablePprof, cfg.EnablePprof, "pprof")
		if len(cfg.AuthTokens) > 0 && !seen["authToken"] {
			*authTokensFlag = strings.Join(cfg.AuthTokens, ",")
		}
		// No flag competes with event_destinations (see Options), so the list
		// is applied unconditionally: an empty list is "no export", which is
		// also what an absent config file means.
		eventDestinations = cfg.EventDestinations
	}

	// Parse auth tokens from comma-separated string
	var authTokens []string
	if *authTokensFlag != "" {
		tokens := strings.Split(*authTokensFlag, ",")
		for _, token := range tokens {
			token = strings.TrimSpace(token)
			if token != "" {
				authTokens = append(authTokens, token)
			}
		}
	}

	return &Options{
		httpAddr:          *httpAddr,
		httpsAddr:         *httpsAddr,
		tunnelAddr:        *tunnelAddr,
		quicAddr:          *quicAddr,
		adminAddr:         *adminAddr,
		adminAuth:         *adminAuth,
		adminToken:        *adminToken,
		adminRate:         *adminRate,
		statusURL:         *statusURL,
		statusAuth:        *statusAuth,
		statusToken:       *statusToken,
		domain:            *domain,
		tlsCrt:            *tlsCrt,
		tlsKey:            *tlsKey,
		logto:             *logto,
		loglevel:          *loglevel,
		logformat:         *logformat,
		authTokens:        authTokens,
		maxMsgBytes:       *maxMsgBytes,
		authRate:          *authRate,
		publicRate:        *publicRate,
		maxConnPerIP:      *maxConnPerIP,
		enablePprof:       *enablePprof,
		eventDestinations: eventDestinations,
	}
}

// overrides is the set of flag names the operator actually typed on the
// command line. Everything else in a flag's value comes from either the config
// file or the flag's built-in default, in that order.
type overrides map[string]bool

func explicitFlags() overrides {
	o := overrides{}
	flag.Visit(func(f *flag.Flag) {
		o[f.Name] = true
	})

	return o
}

// str applies a config-file string. An empty value means "the file did not set
// this key", so it never clears a flag default -- which is why httpsAddr can be
// set in the config file but not unset there (pass -httpsAddr= to disable).
func (o overrides) str(dst *string, val, flagName string) {
	if !o[flagName] && val != "" {
		*dst = val
	}
}

// num applies a config-file integer. val is a *int because the zero value is a
// meaningful setting for every rate limit here (0 disables the limit), so the
// config loader has to report "unset" out of band.
//
// This is where the old hand-written chain went wrong: the check used to read
// `cfg.AdminRate >= 0` against a plain int, which is true even when the key is
// absent, so *any* -config file silently reset -adminRate to 0 and -authRate to
// 0. Both defaults are the single-IP rate limits; loading a config file
// therefore turned the admin- and auth-brute-force throttles off, and nothing
// said so.
func (o overrides) num(dst *int, val *int, flagName string) {
	if !o[flagName] && val != nil {
		*dst = *val
	}
}

// positive applies a config-file count where 0 means "unset" rather than
// "disabled" (a zero-byte message cap is not a setting anyone wants).
func (o overrides) positive(dst *int64, val int64, flagName string) {
	if !o[flagName] && val > 0 {
		*dst = val
	}
}

// yes applies a config-file bool. There is no way to turn a flag off from the
// config file, only on; that matches the bool defaults here, which are all off.
func (o overrides) yes(dst *bool, val bool, flagName string) {
	if !o[flagName] && val {
		*dst = true
	}
}
