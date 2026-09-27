package client

import (
	"flag"
	"fmt"
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

	protocol := flag.String(
		"proto",
		"http+https",
		"The protocol of the traffic over the tunnel {'http', 'https', 'tcp'} (default: 'http+https')")

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
		hostname:             *hostname,
		hostHeader:           *hostHeader,
		requestHeaderAdd:     *requestHeaderAdd,
		requestHeaderRemove:  *requestHeaderRemove,
		responseHeaderAdd:    *responseHeaderAdd,
		responseHeaderRemove: *responseHeaderRemove,
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
