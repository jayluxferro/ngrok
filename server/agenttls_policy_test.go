package server

// Tests for the enforcement and naming rules of the agent-TLS passthrough
// path (SPEC-CLUSTER5 5.2/5.3), and for the SNI parser's handshake-length
// arithmetic.
//
// serveAgentTLS is the one branch of httpsConnHandler where the server holds a
// connection it cannot read: everything it is still entitled to decide -- the
// on_tcp_connect verdict, which endpoint the connection belongs to -- must be
// decided BEFORE the proxy connection exists, on the outside of the TLS. The
// tests here pin exactly that seam: a verdict-deny must be visible as an armed
// proxy conn that never receives anything and a public socket that closes,
// never as a byte the agent sees. The fixtures come from sni_test.go (the
// ClientHello capture, the hand-built hello, the https-listener harness),
// registry_v2_test.go (registry and control) and policy_test.go (the
// StartProxy and no-bytes assertions), because "the agent never saw it" is an
// assertion about bytes on a socket, not about calls into a mock.

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"ngrok/msg"
	"ngrok/policy"
)

// readUntilClosed drains a public conn until the server closes it, failing if
// the connection is still open when the ordinary deadline passes. Whatever the
// server wrote on the way out is discarded on purpose: on the passthrough path
// a refusal's synthetic response is written onto a raw TLS stream, where no
// TLS-speaking visitor can read it -- the enforcement is the point, not the
// answer (serveAgentTLS) -- so the assertions a test makes here are about the
// connection's end, not about bytes.
func readUntilClosed(t *testing.T, c net.Conn, what string) {
	t.Helper()

	if err := c.SetReadDeadline(time.Now().Add(publicTimeout)); err != nil {
		t.Fatalf("failed to set a read deadline: %v", err)
	}
	drained := 0
	buf := make([]byte, 512)
	for {
		n, err := c.Read(buf)
		drained += n
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				t.Fatalf("%s was never closed (read %d byte(s) first)", what, drained)
			}
			return
		}
	}
}

// TestAgentTLSPassthroughConnectDenyNeverReachesAgent pins the connect gate on
// the passthrough path (SPEC-CLUSTER5 5.3): an agent-terminated endpoint whose
// on_tcp_connect policy refuses the flow's client IP must be refused BEFORE a
// proxy connection exists -- the armed agent never receives a StartProxy and
// never sees a byte -- and the public connection closes. The control subtest
// proves the route itself is alive: the same endpoint, with a policy that does
// not refuse this client, hands the hello to its agent verbatim. Without the
// control, a broken route (a hello that never reaches serveAgentTLS at all)
// would pass the deny assertions for the wrong reason.
func TestAgentTLSPassthroughConnectDenyNeverReachesAgent(t *testing.T) {
	cases := []struct {
		name   string
		config map[string]interface{}
		denied bool
	}{
		{
			name:   "the connect verdict refuses the client's IP",
			config: map[string]interface{}{"deny": []interface{}{"127.0.0.1/32"}},
			denied: true,
		},
		{
			name:   "a policy that does not refuse this client lets the flow through",
			config: map[string]interface{}{"deny": []interface{}{"203.0.113.0/24"}},
			denied: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setupTestRegistry(t)
			ctl := testControl(t, "")
			agentConn := armHTTPAgent(t, ctl)
			tun := registerTestTunnel(t, ctl, msg.ReqTunnel{
				Protocol:       msg.ProtoHTTPS,
				Hostname:       "agent.test",
				TLSTermination: msg.TLSTerminationAgent,
				TrafficPolicy: &policy.TrafficPolicy{
					OnTCPConnect: []*policy.Action{policyActionConfig("restrict-ips", tc.config)},
				},
			})
			if tun.policy == nil {
				t.Fatal("the test tunnel must carry a compiled policy for this assertion to mean anything")
			}

			hello := captureClientHello(t, tlsClientConfig("agent.test"))
			publicClient := startHTTPSHandler(t, testTLSConfig(t))
			if _, err := publicClient.Write(hello); err != nil {
				t.Fatalf("failed to write the ClientHello: %v", err)
			}

			if tc.denied {
				// The refusal is decided in serveAgentTLS, before
				// HandlePublicConnection: no proxy conn is ever taken. Read the
				// public side to the ground first -- the handler closes it after
				// writing the verdict's synthetic response onto the raw stream --
				// and only then assert the agent's silence, so a guilty ordering
				// (a dispatch written microseconds behind the close) cannot slip
				// past a too-early read.
				readUntilClosed(t, publicClient, "the denied public connection")
				expectNoBytes(t, agentConn, "the armed agent")
				return
			}

			startProxy := readStartProxy(t, agentConn, "the agent-terminated tunnel")
			if startProxy.Url != tun.url {
				t.Fatalf("StartProxy names %q, want the agent-terminated endpoint %q", startProxy.Url, tun.url)
			}

			if err := agentConn.SetReadDeadline(time.Now().Add(publicTimeout)); err != nil {
				t.Fatalf("failed to set a read deadline: %v", err)
			}
			got := make([]byte, len(hello))
			if _, err := io.ReadFull(agentConn, got); err != nil {
				t.Fatalf("the ClientHello never reached the agent: %v", err)
			}
			if !bytes.Equal(got, hello) {
				t.Fatal("the bytes reaching the agent differ from the visitor's ClientHello")
			}
		})
	}
}

// TestSNIRouteIsCaseInsensitive pins the case rules of the SNI route: the
// endpoint is registered as "Case.Test", which the registry stores lower-cased
// (registerVhost's rule), and a visitor naming it "case.test" in its
// ClientHello must get the passthrough route. The second hello puts mixed case
// ON the wire -- RFC 6066 makes the server_name a DNS name, and DNS matching
// is case-insensitive -- so the server must lowercase the wire name BEFORE it
// looks: a client stack that sends "Case.Test" is not a different endpoint.
func TestSNIRouteIsCaseInsensitive(t *testing.T) {
	setupTestRegistry(t)
	ctl := testControl(t, "")
	tun := registerTestTunnel(t, ctl, msg.ReqTunnel{
		Protocol:       msg.ProtoHTTPS,
		Hostname:       "Case.Test",
		TLSTermination: msg.TLSTerminationAgent,
	})
	if tun.url != "https://case.test" {
		t.Fatalf("the endpoint registered as %q, want the lower-cased https://case.test", tun.url)
	}

	hellos := map[string][]byte{
		// A real Go client's hello naming the endpoint lower-cased.
		"lower-cased SNI": captureClientHello(t, tlsClientConfig("case.test")),
		// A hand-built hello carrying the mixed case on the wire: the server
		// lowercases what the wire says, so this is the same endpoint.
		"mixed-case SNI bytes": buildClientHello(t, "Case.Test", 0, nil),
	}
	for name, hello := range hellos {
		t.Run(name, func(t *testing.T) {
			agentConn := armHTTPAgent(t, ctl)

			publicClient := startHTTPSHandler(t, testTLSConfig(t))
			if _, err := publicClient.Write(hello); err != nil {
				t.Fatalf("failed to write the ClientHello: %v", err)
			}

			startProxy := readStartProxy(t, agentConn, "the agent-terminated tunnel")
			if startProxy.Url != tun.url {
				t.Fatalf("the hello routed to %q, want the agent-terminated endpoint %q", startProxy.Url, tun.url)
			}

			if err := agentConn.SetReadDeadline(time.Now().Add(publicTimeout)); err != nil {
				t.Fatalf("failed to set a read deadline: %v", err)
			}
			got := make([]byte, len(hello))
			if _, err := io.ReadFull(agentConn, got); err != nil {
				t.Fatalf("the ClientHello never reached the agent: %v", err)
			}
			if !bytes.Equal(got, hello) {
				t.Fatal("the bytes reaching the agent differ from the visitor's ClientHello")
			}
		})
	}
}

// TestSNIHandshakeLengthLowByteBit2 pins the arithmetic handshakeLen exists to
// get right (see its comment): the `+ tlsHandshakeHeaderSize` must be an
// ADDITION to the 3-byte length, never an OR term. Written as
// `4 + hs[1]<<16 | hs[2]<<8 | hs[3]`, Go's precedence makes the 4 part of the
// first OR term, and a length whose low byte has bit 2 set absorbs it -- the
// header's 4 bytes vanish, the parse runs 4 bytes short, and every offset
// after the handshake header misreads. 300 = 0x012C is the smallest length
// that shows it: low byte 0x2C has bit 2 set.
func TestSNIHandshakeLengthLowByteBit2(t *testing.T) {
	// The unit pin on the function itself.
	if got := handshakeLen([]byte{tlsHandshakeClientHello, 0x00, 0x01, 0x2C}); got != 4+300 {
		t.Fatalf("handshakeLen = %d, want %d: the header size must be added, not OR-ed into the length", got, 4+300)
	}

	// And end to end: a real hello whose declared handshake length is exactly
	// 300 must parse. The hello is assembled like buildClientHello's, padded
	// to the target length through one extra extension -- extensions are
	// skipped by their declared length, so the padding is the part of the
	// hello a truncated length would cut first.
	const declared = 300
	base := buildClientHello(t, "bit2.test", 0, nil)
	baseDeclared := int(base[6])<<16 | int(base[7])<<8 | int(base[8])
	pad := declared - baseDeclared - 4 // the extra extension costs 4 bytes of framing
	if pad < 0 {
		t.Fatalf("the base hello's declared length %d leaves nothing to pad to %d", baseDeclared, declared)
	}
	hello := buildClientHello(t, "bit2.test", 0x0015, bytes.Repeat([]byte{0x00}, pad)) // 0x0015: padding

	gotDeclared := int(hello[6])<<16 | int(hello[7])<<8 | int(hello[8])
	if gotDeclared != declared {
		t.Fatalf("the fixture's declared handshake length is %d, want %d -- the padding arithmetic broke", gotDeclared, declared)
	}
	if hello[8]&0x04 == 0 {
		t.Fatalf("the fixture's low length byte 0x%02x has bit 2 clear; this vector is only a regression pin while it is set", hello[8])
	}

	sni, _, err := readClientHelloSNI(bytes.NewReader(hello), maxHeadBytes)
	if err != nil {
		t.Fatalf("a hello whose low length byte has bit 2 set must parse, got: %v", err)
	}
	if sni != "bit2.test" {
		t.Fatalf("parsed SNI %q, want %q -- the length came back short and the parse misread the extensions", sni, "bit2.test")
	}
}

// TestTerminatedPathSendsCloseNotify pins the ownership fix in
// terminateWithServerCert: a connection this server terminates must end with
// a TLS close_notify, not a raw-socket close. Without it, well-behaved TLS
// clients (openssl s_client among them) report an unexpected EOF after the
// final response -- the e2e's no-SNI scenario dies on exactly that exit code
// -- and the regression is invisible to every response assertion, because
// the response bytes arrive whole either way.
func TestTerminatedPathSendsCloseNotify(t *testing.T) {
	setupTestRegistry(t)
	ctl := testControl(t, "")
	registerTestTunnel(t, ctl, msg.ReqTunnel{
		Protocol:       msg.ProtoHTTPS,
		Hostname:       "close.test",
		TLSTermination: msg.TLSTerminationAgent,
	})

	publicClient := startHTTPSHandler(t, testTLSConfig(t))

	client := tls.Client(publicClient, &tls.Config{
		InsecureSkipVerify: true,
		MaxVersion:         tls.VersionTLS12,
		// No ServerName: the connection terminates at the server's cert and
		// routes by Host, the exact path whose close lost its notify once.
	})
	if err := client.SetDeadline(time.Now().Add(publicTimeout)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	if _, err := client.Write([]byte("GET / HTTP/1.1\r\nHost: close.test\r\nConnection: close\r\n\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(client), nil)
	if err != nil {
		t.Fatalf("no response: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("status %d, want 421 (the Host names an agent-terminated endpoint on a terminated conn)", resp.StatusCode)
	}

	// The assertion: after the response, the next read must be a CLEAN EOF.
	// A raw-socket close under TLS surfaces here as an error (Go reports the
	// missing close_notify); close_notify surfaces as io.EOF.
	if _, err := client.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("the terminated connection did not end with close_notify (got %v, want io.EOF): a raw close under TLS reads as an unexpected EOF to every careful client", err)
	}
}
