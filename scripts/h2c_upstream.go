//go:build ignore

// scripts/h2c_upstream.go — the local service of the e2e h2-passthrough
// group (SPEC-CLUSTER16): a plaintext HTTP/2 server (h2c, prior-knowledge)
// that also answers HTTP/1.1, so ONE upstream serves both columns of the
// group's dual-protocol table.
//
// It exists because no stdlib serves h2c: net/http speaks h2 only over TLS
// via ALPN, and the h2-passthrough path hands the terminator's PLAINTEXT to
// the local leg — an h2 visitor arrives here as h2c frames regardless of the
// TLS the visitor and the agent spoke. x/net's h2c handler sniffs the
// connection preface and serves either protocol on the one port, which is
// exactly what the tunnel does after the agent's terminator.
//
// The response body is the assertion surface. It reports the protocol the
// request ACTUALLY arrived as (r.Proto — "HTTP/2.0" for h2, "HTTP/1.1" for
// h1) and whether X-Forwarded-For was injected, because the two facts
// together are the whole feature: an h2 visitor must be served over h2 with
// NOTHING injected (raw passthrough — the guard's byte-exactness, asserted
// end to end), and an h1 visitor on the SAME tunnel must still get the
// injected XFF the rewriter has always added. The pre-guard code spliced
// XFF into the 24-byte h2 preface and broke the framing; the h2 row here is
// that bug's regression test.
//
// Build-ignored on purpose: it is test tooling, not module code, and the
// ignore tag keeps it out of ./... builds and go.mod's direct requirements
// (x/net rides quic-go's indirect require). The e2e harness runs it with
//   go run scripts/h2c_upstream.go 127.0.0.1:<port>
// which names the file explicitly and is therefore not excluded by the tag.
package main

import (
	"fmt"
	"net/http"
	"os"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: go run scripts/h2c_upstream.go <listen-addr>")
		os.Exit(2)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		xff := "absent"
		if r.Header.Get("X-Forwarded-For") != "" {
			xff = "present"
		}
		// Nothing else: every byte of this body is an asserted fact, so a
		// failure message quotes the whole truth of what arrived.
		fmt.Fprintf(w, "h2served proto=%s xff=%s", r.Proto, xff)
	})

	srv := &http.Server{
		Addr:    os.Args[1],
		Handler: h2c.NewHandler(mux, &http2.Server{}),
	}
	if err := srv.ListenAndServe(); err != nil {
		fmt.Fprintln(os.Stderr, "h2c upstream:", err)
		os.Exit(1)
	}
}
