package client

import (
	"flag"
	"fmt"
	"ngrok/msg"
	"ngrok/version"
	"os"
	"strings"
)

const usage1 string = `Usage: %s [OPTIONS] <local port or address>
Options:
`

const usage2 string = `
Examples:
	ngrok 80
	ngrok -subdomain=example 8080
	ngrok -proto=tcp 22
	ngrok -hostname="example.com" -httpauth="user:password" 10.0.0.1
	ngrok -binding=internal -hostname=svc.internal 8080
	ngrok -forward-to=https://svc.internal 80
	ngrok -traffic-policy-file=policy.yml -hostname=guarded 8080
	ngrok -proto=tcp -remote-port=2222 22
	ngrok -agent-tls-termination -tls-ca-crt=ca.pem -tls-ca-key=ca.key -hostname=app.example.com 8080


Advanced usage: ngrok [OPTIONS] <command> [command args] [...]
Commands:
	ngrok start [tunnel] [...]    Start tunnels by name from config file
	ngork start-all               Start all tunnels defined in config file
	ngrok list                    List tunnel names from config file
	ngrok help                    Print help
	ngrok version                 Print ngrok version

Examples:
	ngrok start www api blog pubsub
	ngrok -log=stdout -config=ngrok.yml start ssh
	ngrok start-all
	ngrok version

`

type Options struct {
	config    string
	logto     string
	loglevel  string
	logformat string
	authtoken string
	httpauth  string
	hostname  string
	protocol  string
	subdomain string
	command   string
	args      []string

	// HTTP header manipulation. The add/remove flags are repeatable, so they
	// accumulate into stringLists rather than single values.
	hostHeader           string
	requestHeaderAdd     stringList
	requestHeaderRemove  stringList
	responseHeaderAdd    stringList
	responseHeaderRemove stringList

	// Endpoint settings (SPEC 3.2/3.3/3.4). Like the header flags above, these
	// only feed the "default" tunnel synthesized for the simple
	// "ngrok <port>" invocation; config-file tunnels set the equivalent keys
	// per tunnel. compression defaults to true, so the zero value of this
	// struct is deliberately NOT the default for it.
	binding     string
	pooling     bool
	forwardTo   string
	compression bool

	// trafficPolicyFile is the path given by -traffic-policy-file. Like the
	// flags above it only feeds the synthesized "default" tunnel; config-file
	// tunnels name their own traffic_policy. Only the path is kept here: the
	// file is read and validated in LoadConfiguration, so that a policy is
	// checked by exactly one code path whether it came from a flag or from a
	// config file.
	trafficPolicyFile string

	// Fixed remote port and agent TLS termination (SPEC-CLUSTER5). Like the
	// endpoint flags above, these only feed the synthesized "default" tunnel;
	// config-file tunnels set the equivalent keys (remote_port,
	// agent_tls_termination, tls) per tunnel. remotePort stays a uint64 here so
	// that a flag value past uint16 reaches LoadConfiguration and is rejected
	// with a message naming the flag, instead of wrapping around silently.
	remotePort          uint64
	agentTLSTermination bool
	tlsCrt              string
	tlsKey              string
	tlsCaCrt            string
	tlsCaKey            string

	// proxyTransport is the value of -proxy-transport (SPEC-CLUSTER7 5): a
	// client-level setting like -authtoken, not a per-tunnel one, so it
	// overrides the config file's proxy_transport key whenever it is not
	// empty. The empty default is what makes "flag not given" observable, and
	// LoadConfiguration validates whichever value won.
	proxyTransport string
}

// stringList is a flag.Value that accumulates each occurrence of a repeatable
// flag; the Go flag package has no repeatable-flag support of its own.
//
// Note that Set appends the raw value: splitting "key:value" on the first colon
// and validating the pieces happens in LoadConfiguration, not here, so that
// values coming from the command line and from the config file are checked by
// exactly one code path.
type stringList []string

func (l *stringList) String() string {
	return strings.Join(*l, ",")
}

func (l *stringList) Set(value string) error {
	*l = append(*l, value)
	return nil
}

func ParseArgs() (opts *Options, err error) {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, usage1, os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, usage2)
	}

	config := flag.String(
		"config",
		"",
		"Path to ngrok configuration file. (default: $HOME/.ngrok)")

	logto := flag.String(
		"log",
		"none",
		"Write log messages to this file. 'stdout' and 'none' have special meanings")

	loglevel := flag.String(
		"log-level",
		"DEBUG",
		"The level of messages to log. One of: DEBUG, INFO, WARNING, ERROR")

	logformat := flag.String(
		"log-format",
		"text",
		"Log format: text or json")

	authtoken := flag.String(
		"authtoken",
		"",
		"Authentication token for identifying an ngrok.com account")

	proxyTransport := flag.String(
		"proxy-transport",
		"",
		"Transport carrying the multiplexed proxy connection to the server: 'auto' (default: QUIC when the server offers it, falling back to TCP), 'quic' or 'tcp'. Setting http_proxy forces TCP regardless: QUIC needs UDP end-to-end, which an HTTP CONNECT proxy cannot carry.")

	httpauth := flag.String(
		"httpauth",
		"",
		"username:password HTTP basic auth creds protecting the public tunnel endpoint")

	subdomain := flag.String(
		"subdomain",
		"",
		"Request a custom subdomain from the ngrok server. (HTTP only)")

	hostname := flag.String(
		"hostname",
		"",
		"Request a custom hostname from the ngrok server. (HTTP only) (requires CNAME of your DNS)")

	// The help text used to list {'http', 'https', 'tcp'} while the default was
	// 'http+https' -- a value the list did not contain, so the one spelling a
	// user was most likely to type was the one the help said was invalid. It is
	// not: the field is '+'-joined, and a tunnel may carry several protocols at
	// once (each is registered and served separately).
	protocol := flag.String(
		"proto",
		msg.ProtoHTTPPlusHTTPS,
		"The protocol of the traffic over the tunnel: 'http', 'https' or 'tcp', or several of them joined with '+' to serve the same tunnel over each (default: 'http+https', which is an http and an https endpoint)")

	hostHeader := flag.String(
		"host-header",
		"",
		"Rewrite the Host header of requests sent to your local server. 'rewrite' rewrites it to the local address's hostname, 'preserve' leaves it unchanged (default), or specify an explicit hostname. (HTTP only)")

	requestHeaderAdd := new(stringList)
	flag.Var(requestHeaderAdd,
		"request-header-add",
		"Header 'key:value' to add to requests sent to your local server. May be given multiple times to add multiple headers. (HTTP only)")

	requestHeaderRemove := new(stringList)
	flag.Var(requestHeaderRemove,
		"request-header-remove",
		"Header key to remove from requests sent to your local server. May be given multiple times to remove multiple headers. (HTTP only)")

	responseHeaderAdd := new(stringList)
	flag.Var(responseHeaderAdd,
		"response-header-add",
		"Header 'key:value' to add to responses returned to the public client. May be given multiple times to add multiple headers. (HTTP only)")

	responseHeaderRemove := new(stringList)
	flag.Var(responseHeaderRemove,
		"response-header-remove",
		"Header key to remove from responses returned to the public client. May be given multiple times to remove multiple headers. (HTTP only)")

	binding := flag.String(
		"binding",
		"",
		"Whether the tunnel is reachable from the public internet: 'public' (default) or 'internal'. An internal endpoint lives in the .internal namespace of your account and is only reachable from another tunnel of yours via -forward-to. (HTTP only)")

	pooling := flag.Bool(
		"pooling",
		false,
		"Allow several agents to register the same tunnel URL and share the traffic between them, round-robin per connection (default: false)")

	forwardTo := flag.String(
		"forward-to",
		"",
		"Forward this endpoint's traffic to an internal endpoint ('https://svc.internal') instead of to the local address. (HTTP only)")

	compression := flag.Bool(
		"compression",
		true,
		"Gzip-compress compressible responses sent to clients that accept gzip. Set -compression=false to send responses exactly as your local server wrote them. (HTTP only)")

	trafficPolicyFile := flag.String(
		"traffic-policy-file",
		"",
		"Path to a YAML traffic policy file to enforce on the server for this endpoint. The policy is validated at startup: a rule the server cannot enforce is a startup error, not a control that silently does nothing. (HTTP only)")

	remotePort := flag.Uint64(
		"remote-port",
		0,
		"Claim this specific public port for a tcp tunnel instead of a random one (0 lets the server choose). A port the server's own listeners use, one another auth token has already claimed, or one below 1024 (which the server process needs privileges to bind) is refused at registration. (TCP only)")

	agentTLSTermination := flag.Bool(
		"agent-tls-termination",
		false,
		"Terminate TLS for https connections in this agent instead of on the ngrok server: the server routes by SNI and relays the TLS bytes unread (it never sees plaintext), and this process decrypts and speaks plain HTTP to the local address. The certificate comes from -tls-crt/-tls-key, from -tls-ca-crt/-tls-ca-key, or -- with neither -- is a temporary self-signed one. (HTTPS only)")

	tlsCrt := flag.String(
		"tls-crt",
		"",
		"Path to a PEM certificate the agent presents on https connections when terminating TLS itself. Requires -tls-key. (with -agent-tls-termination)")

	tlsKey := flag.String(
		"tls-key",
		"",
		"Path to the PEM private key of -tls-crt. Requires -tls-crt. (with -agent-tls-termination)")

	tlsCaCrt := flag.String(
		"tls-ca-crt",
		"",
		"Path to a PEM certificate authority the agent uses to mint a certificate per requested hostname on the fly, instead of presenting one fixed certificate. Requires -tls-ca-key. (with -agent-tls-termination)")

	tlsCaKey := flag.String(
		"tls-ca-key",
		"",
		"Path to the PEM private key of -tls-ca-crt. It never leaves this machine. Requires -tls-ca-crt. (with -agent-tls-termination)")

	flag.Parse()

	opts = &Options{
		config:               *config,
		logto:                *logto,
		loglevel:             *loglevel,
		logformat:            *logformat,
		httpauth:             *httpauth,
		subdomain:            *subdomain,
		protocol:             *protocol,
		authtoken:            *authtoken,
		proxyTransport:       *proxyTransport,
		hostname:             *hostname,
		hostHeader:           *hostHeader,
		requestHeaderAdd:     *requestHeaderAdd,
		requestHeaderRemove:  *requestHeaderRemove,
		responseHeaderAdd:    *responseHeaderAdd,
		responseHeaderRemove: *responseHeaderRemove,
		binding:              *binding,
		pooling:              *pooling,
		forwardTo:            *forwardTo,
		compression:          *compression,
		trafficPolicyFile:    *trafficPolicyFile,
		remotePort:           *remotePort,
		agentTLSTermination:  *agentTLSTermination,
		tlsCrt:               *tlsCrt,
		tlsKey:               *tlsKey,
		tlsCaCrt:             *tlsCaCrt,
		tlsCaKey:             *tlsCaKey,
		command:              flag.Arg(0),
	}

	switch opts.command {
	case "list":
		opts.args = flag.Args()[1:]
	case "start":
		opts.args = flag.Args()[1:]
	case "start-all":
		opts.args = flag.Args()[1:]
	case "version":
		fmt.Println(version.MajorMinorPatch())
		os.Exit(0)
	case "help":
		flag.Usage()
		os.Exit(0)
	case "":
		err = fmt.Errorf("Error: Specify a local port to tunnel to, or " +
			"an ngrok command.\n\nExample: To expose port 80, run " +
			"'ngrok 80'")
		return

	default:
		if len(flag.Args()) > 1 {
			err = fmt.Errorf("You may only specify one port to tunnel to on the command line, got %d: %v",
				len(flag.Args()),
				flag.Args())
			return
		}

		opts.command = "default"
		opts.args = flag.Args()
	}

	return
}
