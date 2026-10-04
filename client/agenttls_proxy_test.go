package client

// Integration tests for the agent TLS termination data path (SPEC-CLUSTER5
// 5.3):
//
//	TLS visitor <-> tls.Conn <-> net.Pipe <-> serveProxyConnection() <-> plain
//	plaintext legs <-> rewriter (headers + traffic policy) <-> localConn <->
//	httptest upstream
//
// serveProxyConnection() is the part of the proxy path that terminates the
// public TLS when the tunnel says agent_tls_termination, so these tests need
// neither an ngrokd (the server side of the tunnel is one end of a net.Pipe,
// and the visitor is a real tls.Client) nor a control channel. Everything a
// visitor and an upstream can observe is asserted on the real objects: the
// chain the visitor verified, the head the upstream received, the status it
// was answered with.
//
// What is *not* covered here: the certificate models themselves
// (tlsagent_test.go), the config validation (agenttls_config_test.go), and the
// server's SNI routing half of the story.

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ngrok/client/mvc"
	"ngrok/log"
	"ngrok/msg"
	"ngrok/policy"
	"ngrok/proto"
	"ngrok/util"
)

// agentTLSStubController is the mvc.Controller stand-in for proxy-path tests:
// serveProxyConnection reports state through it, and a no-op Update is exactly
// what the assertions here want.
type agentTLSStubController struct {
	log.Logger
}

func (c *agentTLSStubController) Update(mvc.State)               {}
func (c *agentTLSStubController) Shutdown(string)                {}
func (c *agentTLSStubController) PlayRequest(mvc.Tunnel, []byte) {}
func (c *agentTLSStubController) Updates() *util.Broadcast       { return util.NewBroadcast() }
func (c *agentTLSStubController) State() mvc.State               { return nil }
func (c *agentTLSStubController) Go(fn func())                   { go fn() }
func (c *agentTLSStubController) GetWebInspectAddr() string      { return "disabled" }

// agentTLSProxy is one in-flight proxied connection through an agent-terminated
// tunnel, as the test drives it: the pipe's public end stands in for the
// server-side proxy conn, and whatever is written there is the TLS the server
// relayed unread.
type agentTLSProxy struct {
	// public is the raw (TLS-carrying) end the visitor dials into.
	public net.Conn

	model    *ClientModel
	finished chan struct{}
}

// startAgentTLSProxy registers the tunnel on a fresh model and starts
// serveProxyConnection, exactly as the proxy path would run it: the tunnel's
// per-session runtime is established first (establishTunnelRuntime, the call
// control() makes on NewTunnel), then the connection is served once StartProxy
// arrived.
func startAgentTLSProxy(t *testing.T, tunnel mvc.Tunnel, tunnelCfg *TunnelConfiguration, compiled *policy.Compiled) *agentTLSProxy {
	t.Helper()

	model := &ClientModel{
		Logger:  log.NewPrefixLogger("test"),
		metrics: NewClientMetrics(),
		ctl:     &agentTLSStubController{Logger: log.NewPrefixLogger("ctl")},
		tunnels: map[string]mvc.Tunnel{tunnel.PublicUrl: tunnel},
	}
	if tunnelCfg != nil {
		if err := model.establishTunnelRuntime(tunnel.PublicUrl, tunnelCfg); err != nil {
			t.Fatalf("establishTunnelRuntime: %v", err)
		}
	}
	if compiled != nil {
		model.setCompiledPolicy(tunnel.PublicUrl, compiled)
	}

	publicEnd, serverEnd := net.Pipe()
	remoteConn := &proxyTestConn{Conn: serverEnd, Logger: log.NewPrefixLogger("pxy"), id: "pxy"}
	// Every read the test does is bounded: a wiring bug must fail the test,
	// not hang it.
	publicEnd.SetDeadline(time.Now().Add(30 * time.Second))

	h := &agentTLSProxy{
		public:   publicEnd,
		model:    model,
		finished: make(chan struct{}),
	}
	go func() {
		defer close(h.finished)
		model.serveProxyConnection(remoteConn, &msg.StartProxy{Url: tunnel.PublicUrl, ClientAddr: testClientAddr})
	}()

	t.Cleanup(func() {
		publicEnd.Close()
		select {
		case <-h.finished:
		case <-time.After(10 * time.Second):
			t.Errorf("serveProxyConnection did not return after the public connection was closed")
		}
	})

	return h
}

// dialVisitor is the public client: a real tls.Client over the relayed bytes,
// whose handshake the agent terminates. It fails the test when the handshake
// does, which is the assertion for "the agent presented a certificate the
// visitor accepts".
func (h *agentTLSProxy) dialVisitor(t *testing.T, clientCfg *tls.Config) *tls.Conn {
	t.Helper()

	visitor := tls.Client(h.public, clientCfg)
	handshook := make(chan error, 1)
	go func() { handshook <- visitor.Handshake() }()
	select {
	case err := <-handshook:
		if err != nil {
			t.Fatalf("visitor handshake failed: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("visitor handshake did not complete")
	}
	return visitor
}

// send writes a raw request into the visitor's TLS connection.
func (h *agentTLSProxy) sendVisitor(t *testing.T, visitor *tls.Conn, raw string) {
	t.Helper()

	if _, err := io.WriteString(visitor, raw); err != nil {
		t.Fatalf("failed to write the request over TLS: %v", err)
	}
}

// agentTLSHttpsTunnel is the https tunnel every case here proxies through:
// agent termination on, its public URL an https one (the two together are what
// make serveProxyConnection terminate), and the headers a case wants.
func agentTLSHttpsTunnel(publicUrl, localAddr string) mvc.Tunnel {
	tunnel := httpTunnel(publicUrl, localAddr)
	tunnel.AgentTLS = true
	return tunnel
}

// explicitCertTunnelConfig is a tunnel configuration using the explicit cert
// model, with a leaf named for the given DNS name: exactly what a
// `tls: {crt: ..., key: ...}` block parses to.
func explicitCertTunnelConfig(t *testing.T, dnsName string) *TunnelConfiguration {
	t.Helper()

	caPEM, caKeyPEM := agentTestCA(t)
	caBlock, _ := pem.Decode(caPEM)
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		t.Fatalf("test CA does not parse: %v", err)
	}
	keyBlock, _ := pem.Decode(caKeyPEM)
	caKey, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatalf("test CA key does not parse: %v", err)
	}
	crtPEM, keyPEM := agentTestLeafPEM(t, caCert, caKey, dnsName)

	return &TunnelConfiguration{
		AgentTLSTermination: true,
		TLS: &TLSConfig{
			Crt: writeAgentTLSFile(t, "leaf.crt", crtPEM),
			Key: writeAgentTLSFile(t, "leaf.key", keyPEM),
		},
	}
}

// TestServeProxyConnectionAgentTLSIsThePlainLeg is the end-to-end spine of the
// feature: the visitor's TLS ends at the agent, the upstream sees the rewritten
// plaintext request (Host rewritten per the tunnel, X-Forwarded-For injected,
// X-Forwarded-Proto https), and the response comes back through the same TLS.
// The inspector sees the connection too -- the tee parses the rewritten
// plaintext, because the analyzer's plumbing is unchanged (5.3 step 4).
func TestServeProxyConnectionAgentTLSIsThePlainLeg(t *testing.T) {
	srv, seen := upstreamServer(t)
	upstreamAddr := srv.Listener.Addr().String()

	httpProto := proto.NewHttp()

	// The inspector subscription goes in BEFORE the request flows: the txn
	// broadcast is what the web view would render.
	transactions := httpProto.Txns.Reg()
	t.Cleanup(func() { httpProto.Txns.UnReg(transactions) })

	tunnel := agentTLSHttpsTunnel("https://tunnel.example.com", upstreamAddr)
	tunnel.HostHeader = "rewrite"
	tunnel.Protocol = httpProto

	p := startAgentTLSProxy(t, tunnel, explicitCertTunnelConfig(t, "tunnel.example.com"), nil)
	visitor := p.dialVisitor(t, &tls.Config{
		// The explicit model's certificate is from a CA the visitor was not
		// told about: this test is about the plaintext legs, not chain
		// verification (TestServeProxyConnectionAgentTLSCAModel does that).
		InsecureSkipVerify: true,
		ServerName:         "tunnel.example.com",
	})
	p.sendVisitor(t, visitor, getRequest("tunnel.example.com", "X-Connection: first"))

	// The upstream receives plaintext, rewritten: the Host from its own
	// address ("rewrite"), the public client's IP, and the scheme the public
	// URL promises.
	got := upstreamObserved(t, seen)
	if want := hostOf(t, upstreamAddr); got.host != want {
		t.Fatalf("upstream saw Host %q, want the rewritten %q", got.host, want)
	}
	if xff := got.header.Get("X-Forwarded-For"); xff != testClientIP {
		t.Fatalf("upstream saw X-Forwarded-For %q, want %q", xff, testClientIP)
	}
	if xfp := got.header.Get("X-Forwarded-Proto"); xfp != "https" {
		t.Fatalf("upstream saw X-Forwarded-Proto %q, want https (from the public URL)", xfp)
	}
	if xconn := got.header.Get("X-Connection"); xconn != "first" {
		t.Fatalf("upstream saw X-Connection %q, want first", xconn)
	}

	// And the visitor reads the upstream's response through the same TLS.
	resp, body := readResponse(t, bufio.NewReader(visitor))
	if resp.StatusCode != http.StatusOK || string(body) != testUpstreamBody {
		t.Fatalf("visitor read status %d body %q, want 200 %q", resp.StatusCode, body, testUpstreamBody)
	}

	// The inspector: the transaction the tee parsed carries the REWRITTEN
	// request (the tee sits after the rewriter on the local leg), so the
	// analyzer sees exactly what the upstream sees.
	select {
	case t0 := <-transactions:
		txn, ok := t0.(*proto.HttpTxn)
		if !ok || txn == nil || txn.Req == nil {
			t.Fatalf("the inspector broadcast a malformed transaction: %+v", t0)
		}
		if want := hostOf(t, upstreamAddr); txn.Req.Host != want {
			t.Fatalf("the inspector saw Host %q, want the rewritten %q", txn.Req.Host, want)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the inspector never saw the request over the agent-terminated tunnel")
	}
}

// TestServeProxyConnectionAgentTLSCAModel walks the CA model end to end: the
// visitor trusts ONLY the configured CA, names the tunnel's hostname, and the
// handshake must succeed on the per-hostname leaf the agent minted -- the
// property an operator buys by pointing tls.ca_crt at a CA they control.
func TestServeProxyConnectionAgentTLSCAModel(t *testing.T) {
	srv, seen := upstreamServer(t)
	upstreamAddr := srv.Listener.Addr().String()

	caPEM, caKeyPEM := agentTestCA(t)
	caPath := writeAgentTLSFile(t, "ca.crt", caPEM)
	caKeyPath := writeAgentTLSFile(t, "ca.key", caKeyPEM)

	caBlock, _ := pem.Decode(caPEM)
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		t.Fatalf("test CA does not parse: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	tunnel := agentTLSHttpsTunnel("https://minted.example.com", upstreamAddr)

	p := startAgentTLSProxy(t, tunnel, &TunnelConfiguration{
		AgentTLSTermination: true,
		TLS:                 &TLSConfig{CaCrt: caPath, CaKey: caKeyPath},
	}, nil)
	// RootCAs alone: the chain the agent presents must verify for the named
	// host, or this handshake goes nowhere.
	visitor := p.dialVisitor(t, &tls.Config{RootCAs: pool, ServerName: "minted.example.com"})
	p.sendVisitor(t, visitor, getRequest("minted.example.com"))

	if _, body := readResponse(t, bufio.NewReader(visitor)); string(body) != testUpstreamBody {
		t.Fatalf("response body = %q, want %q", body, testUpstreamBody)
	}
	if got := upstreamObserved(t, seen); got.host != "minted.example.com" {
		t.Fatalf("upstream saw Host %q, want the preserved minted.example.com", got.host)
	}
}

// TestServeProxyConnectionAgentTLSDialFail502 is 5.3 step 3: dead upstream, and
// the visitor gets the existing 502 page as REAL HTTP -- the handshake
// completes first, so a browser sees a status code instead of a TLS error.
func TestServeProxyConnectionAgentTLSDialFail502(t *testing.T) {
	// A port nothing is listening on: bind one, note the address, close it.
	dead, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find a dead port: %v", err)
	}
	deadAddr := dead.Addr().String()
	dead.Close()

	tunnel := agentTLSHttpsTunnel("https://tunnel.example.com", deadAddr)
	p := startAgentTLSProxy(t, tunnel, &TunnelConfiguration{AgentTLSTermination: true}, nil)

	visitor := p.dialVisitor(t, &tls.Config{InsecureSkipVerify: true, ServerName: "tunnel.example.com"})

	// No request is sent on purpose: the dial-first order means the agent
	// knows the upstream is dead before the visitor says anything, and a real
	// visitor sees the 502 (then the close) whatever it does next.
	resp, err := http.ReadResponse(bufio.NewReader(visitor), nil)
	if err != nil {
		t.Fatalf("failed to read the 502 over TLS: %v", err)
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("visitor read status %d, want 502 as real HTTP over the completed handshake", resp.StatusCode)
	}
	if _, err := io.ReadAll(resp.Body); err != nil {
		t.Fatalf("failed to read the 502 body: %v", err)
	}
}

// TestServeProxyConnectionAgentTLSPolicyDeny proves the http phases run
// agent-side (5.3 step 6): the tunnel's traffic policy denies the request where
// plaintext is visible -- here, inside the client -- and the visitor gets the
// synthetic answer without the upstream ever being consulted. On an
// edge-terminated tunnel this same policy would have run on the server; on
// this tunnel the server has only ciphertext.
func TestServeProxyConnectionAgentTLSPolicyDeny(t *testing.T) {
	srv, seen := upstreamServer(t)
	upstreamAddr := srv.Listener.Addr().String()

	compiled := compileTestPolicy(t, `{
		"on_http_request": [
			{
				"name": "custom-response",
				"expressions": ["req.url.path == '/blocked'"],
				"config": {"status_code": 403, "body": "not for you"}
			}
		]
	}`)

	tunnel := agentTLSHttpsTunnel("https://tunnel.example.com", upstreamAddr)
	p := startAgentTLSProxy(t, tunnel, &TunnelConfiguration{AgentTLSTermination: true}, compiled)

	visitor := p.dialVisitor(t, &tls.Config{InsecureSkipVerify: true, ServerName: "tunnel.example.com"})
	// The path the policy matches on.
	p.sendVisitor(t, visitor, "GET /blocked HTTP/1.1\r\nHost: tunnel.example.com\r\n\r\n")

	resp, body := readResponse(t, bufio.NewReader(visitor))
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("visitor read status %d, want the policy's 403", resp.StatusCode)
	}
	if string(body) != "not for you" {
		t.Fatalf("visitor read body %q, want the policy's body", body)
	}

	// And the request really went nowhere: the upstream saw nothing.
	select {
	case req := <-seen:
		t.Fatalf("a denied request reached the upstream anyway (Host %q)", req.host)
	case <-time.After(500 * time.Millisecond):
	}
}

// TestServeProxyConnectionAgentTLSCompressionStillApplied is the "everything
// that must keep working over agent-terminated tunnels" list, compression item:
// the tunnel's Compress flag still compresses responses on the plaintext leg.
func TestServeProxyConnectionAgentTLSCompressionStillApplied(t *testing.T) {
	// The transform skips bodies smaller than minCompressBytes, and plain-text
	// types: give it a body worth compressing.
	longBody := strings.Repeat("ngrok agent-tls body line\n", 100)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, longBody)
	}))
	t.Cleanup(srv.Close)

	tunnel := agentTLSHttpsTunnel("https://tunnel.example.com", srv.Listener.Addr().String())
	tunnel.Compress = true
	p := startAgentTLSProxy(t, tunnel, &TunnelConfiguration{AgentTLSTermination: true}, nil)

	visitor := p.dialVisitor(t, &tls.Config{InsecureSkipVerify: true, ServerName: "tunnel.example.com"})
	p.sendVisitor(t, visitor, getRequest("tunnel.example.com", "Accept-Encoding: gzip"))

	resp, err := http.ReadResponse(bufio.NewReader(visitor), nil)
	if err != nil {
		t.Fatalf("failed to read the response over TLS: %v", err)
	}
	if resp.Header.Get("Content-Encoding") != "gzip" {
		t.Fatalf("response Content-Encoding = %q, want gzip on the agent-terminated tunnel", resp.Header.Get("Content-Encoding"))
	}

	zr, err := gzip.NewReader(resp.Body)
	if err != nil {
		t.Fatalf("response is not readable gzip: %v", err)
	}
	decompressed, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("failed to decompress the response body: %v", err)
	}
	if !bytes.Equal(decompressed, []byte(longBody)) {
		t.Fatal("the decompressed body is not the upstream's body")
	}
}

// TestServeProxyConnectionAgentTLSHandshakeFailureClosed is the fail-closed
// half of step 2: a visitor that never speaks TLS gets its connection closed,
// a WARN in the client's log, and nothing at all on the local upstream.
func TestServeProxyConnectionAgentTLSHandshakeFailureClosed(t *testing.T) {
	logFile := filepath.Join(t.TempDir(), "client.log")
	log.LogTo(logFile, "DEBUG", "text")

	srv, seen := upstreamServer(t)

	tunnel := agentTLSHttpsTunnel("https://tunnel.example.com", srv.Listener.Addr().String())
	p := startAgentTLSProxy(t, tunnel, &TunnelConfiguration{AgentTLSTermination: true}, nil)

	// Not a TLS record: the handshake must refuse it.
	if _, err := io.WriteString(p.public, "GET / HTTP/1.1\r\nHost: tunnel.example.com\r\n\r\n"); err != nil {
		t.Fatalf("failed to write the impostor bytes: %v", err)
	}

	// The connection is closed on us: a read ends, soon, with an error.
	done := make(chan error, 1)
	go func() {
		_, err := io.ReadAll(p.public)
		done <- err
	}()
	select {
	// A clean close reads back as EOF (a nil error); either way, the read
	// ENDED, which is what "closed" means here. The failure is the timeout.
	case err := <-done:
		_ = err
	case <-time.After(10 * time.Second):
		t.Fatal("the failed handshake did not close the connection")
	}

	// Nothing reached the upstream: whatever the visitor sent, none of it was
	// forwarded.
	select {
	case req := <-seen:
		t.Fatalf("the failed handshake's bytes reached the upstream anyway (Host %q)", req.host)
	case <-time.After(500 * time.Millisecond):
	}

	// And the failure is in the log, at WARN, naming the remote address.
	const marker = "agent-tls-handshake-log-scan-marker"
	log.Info(marker)
	content := waitForLogMarker(t, logFile, marker)
	if !strings.Contains(content, "TLS handshake") {
		t.Fatalf("the log does not record the failed handshake:\n%s", content)
	}
}

// TestServeProxyConnectionAgentTLSOnlyOnHTTPSLeg pins the mixed-tunnel gate: a
// tunnel with agent_tls_termination registers an http leg too, and THAT leg is
// still edge-served plaintext end to end -- terminating it would double-encrypt
// nothing and break every http visitor.
func TestServeProxyConnectionAgentTLSOnlyOnHTTPSLeg(t *testing.T) {
	srv, seen := upstreamServer(t)
	upstreamAddr := srv.Listener.Addr().String()

	tunnel := httpTunnel("http://tunnel.example.com", upstreamAddr)
	tunnel.AgentTLS = true // carries the flag, but this leg's URL is http://

	p := startAgentTLSProxy(t, tunnel, &TunnelConfiguration{AgentTLSTermination: true}, nil)

	// Plain HTTP in: no ClientHello, no termination.
	if _, err := io.WriteString(p.public, getRequest("tunnel.example.com")); err != nil {
		t.Fatalf("failed to write the plain request: %v", err)
	}

	resp, body := readResponse(t, bufio.NewReader(p.public))
	if resp.StatusCode != http.StatusOK || string(body) != testUpstreamBody {
		t.Fatalf("http leg read status %d body %q, want the usual plaintext answer", resp.StatusCode, body)
	}
	if got := upstreamObserved(t, seen); got.host != "tunnel.example.com" {
		t.Fatalf("upstream saw Host %q, want the preserved tunnel.example.com", got.host)
	}
}

// parseTestPolicy parses a policy document, and compileTestPolicy builds the
// compiled form of one -- the same call establishTunnelRuntime makes for a
// tunnel's traffic policy before it stores the compiled result.
func parseTestPolicy(t *testing.T, doc string) *policy.TrafficPolicy {
	t.Helper()

	tp := new(policy.TrafficPolicy)
	if err := json.Unmarshal([]byte(doc), tp); err != nil {
		t.Fatalf("test policy does not parse: %v", err)
	}
	return tp
}

func compileTestPolicy(t *testing.T, doc string) *policy.Compiled {
	t.Helper()

	compiled, err := parseTestPolicy(t, doc).Compile()
	if err != nil {
		t.Fatalf("test policy does not compile: %v", err)
	}
	return compiled
}

// TestEstablishTunnelRuntime pins the per-session runtime wiring at the one
// place a control connection would otherwise be needed to reach: the cert
// config and the compiled policy land keyed by the public URL the proxy
// connections arrive with, and a broken cert file fails the call instead of
// silently serving the tunnel without TLS.
func TestEstablishTunnelRuntime(t *testing.T) {
	caPEM, caKeyPEM := agentTestCA(t)
	model := &ClientModel{Logger: log.NewPrefixLogger("test")}

	// Nothing configured: nothing stored, no error.
	if err := model.establishTunnelRuntime("http://plain.example.com", &TunnelConfiguration{}); err != nil {
		t.Fatalf("plain tunnel failed to establish: %v", err)
	}
	if model.agentTLSConfigFor("http://plain.example.com") != nil {
		t.Fatal("a plain tunnel must not get an agent TLS config")
	}

	// Agent TLS + policy: both stored under the URL.
	cfg := &TunnelConfiguration{
		AgentTLSTermination: true,
		TLS: &TLSConfig{
			CaCrt: writeAgentTLSFile(t, "ca.crt", caPEM),
			CaKey: writeAgentTLSFile(t, "ca.key", caKeyPEM),
		},
		TrafficPolicy: parseTestPolicy(t, `{"on_http_request": [{"name": "log", "config": {"metadata": {"seen": "yes"}}}]}`),
	}
	url := "https://tunnel.example.com"
	if err := model.establishTunnelRuntime(url, cfg); err != nil {
		t.Fatalf("agent-terminated tunnel failed to establish: %v", err)
	}
	if model.agentTLSConfigFor(url) == nil {
		t.Fatal("the per-session TLS config did not land under the public URL")
	}
	if model.compiledPolicyFor(url) == nil {
		t.Fatal("the compiled policy did not land under the public URL")
	}
	if model.agentTLSConfigFor(url).GetCertificate == nil {
		t.Fatal("expected the CA model's per-hostname minting")
	}

	// A cert file that vanished between load and establishment: the tunnel is
	// not established.
	cfg.TLS.CaCrt = filepath.Join(t.TempDir(), "gone.crt")
	if err := model.establishTunnelRuntime("https://other.example.com", cfg); err == nil {
		t.Fatal("a vanished certificate file must fail the establishment")
	}
}
