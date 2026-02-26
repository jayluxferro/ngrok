//go:build !release
// +build !release

package client

import "os"

var (
	rootCrtPaths = []string{"assets/client/tls/ngrokroot.crt", "assets/client/tls/snakeoilca.crt"}
)

func useInsecureSkipVerify() bool {
	return os.Getenv("NGROK_INSECURE_SKIP_VERIFY") == "1"
}
