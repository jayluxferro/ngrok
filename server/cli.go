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
}

func parseArgs() *Options {
	httpAddr := flag.String("httpAddr", ":80", "Public address for HTTP connections, empty string to disable")
	httpsAddr := flag.String("httpsAddr", ":443", "Public address listening for HTTPS connections, emptry string to disable")
	tunnelAddr := flag.String("tunnelAddr", ":4443", "Public address listening for ngrok client")
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
		httpAddr:     *httpAddr,
		httpsAddr:    *httpsAddr,
		tunnelAddr:   *tunnelAddr,
		adminAddr:    *adminAddr,
		adminAuth:    *adminAuth,
		adminToken:   *adminToken,
		adminRate:    *adminRate,
		statusURL:    *statusURL,
		statusAuth:   *statusAuth,
		statusToken:  *statusToken,
		domain:       *domain,
		tlsCrt:       *tlsCrt,
		tlsKey:       *tlsKey,
		logto:        *logto,
		loglevel:     *loglevel,
		logformat:    *logformat,
		authTokens:   authTokens,
		maxMsgBytes:  *maxMsgBytes,
		authRate:     *authRate,
		publicRate:   *publicRate,
		maxConnPerIP: *maxConnPerIP,
		enablePprof:  *enablePprof,
	}
}
