package server

// Tests for the server's edge enforcement of traffic policies (SPEC 3.3).
//
// Two of the three phases are reachable from the server and each has its own
// entry point, so both are driven end to end over real loopback TCP:
// on_tcp_connect runs in the http handler's routing half (routeHTTP, behind
// httpHandler) and in listenTcp, before the endpoint is handed a proxy
// connection at all, and on_http_request / on_http_response run inside the
// rewriter pair Tunnel.join installs. The agent's end of every connection is
// a TCP pair the test drives itself, so "the request never reached the
// agent" is an assertion about bytes rather than about a mock call.
//
// The fixtures (setupTestRegistry, testControl, registerTestTunnel, tcpPair,
// armProxyPool, dispatch) come from registry_v2_test.go: real loopback
// connections, for the reason documented there (conn.Wrap only understands
// *net.TCPConn).

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"ngrok/conn"
	"ngrok/msg"
	"ngrok/policy"
	"strings"
	"testing"
	"time"

	"github.com/xtaci/smux/v2"
)

// ---------------------------------------------------------------------------
// fixtures

// policyAction builds one rule of a traffic policy.
func policyAction(name string, expr ...string) *policy.Action {
	return &policy.Action{Name: name, Expressions: expr}
}

// policyActionConfig is policyAction with a config block.
func policyActionConfig(name string, cfg map[string]interface{}, expr ...string) *policy.Action {
	return &policy.Action{Name: name, Expressions: expr, Config: cfg}
}

// publicTimeout is how long a test waits for anything on the wire. Long
// enough that a loaded machine does not fail the test, short enough that a
// connection that is never answered fails it rather than hanging it.
const publicTimeout = 5 * time.Second

// requestHead is the request a test's public client writes.
func requestHead(host, path string) string {
	return "GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\n\r\n"
}

// armHTTPAgent arms the proxy connection an endpoint's agent would have
// opened and returns the agent's end of it. Nothing is registered here: the
// pool the server draws from is a plain channel and this fills it.
func armHTTPAgent(t *testing.T, ctl *Control) conn.Conn {
	t.Helper()

	proxyClient, proxyServer := tcpPair(t)
	ctl.proxies <- conn.Wrap(proxyServer, "pxy")
	return conn.Wrap(proxyClient, "pxy")
}

// armMuxAgent is armHTTPAgent with the agent side arriving the way a
// multiplexed client arrives: an smux stream over an in-memory pipe, wrapped
// with conn.Wrap exactly as server/mux.go's handleStream wraps one.
//
// The transport is the point of the fixture, not a detail. This connection
// becomes NewConnPair's respSrc -- the source the response rewriter parks a read
// in while it waits for the agent's response -- and an smux stream is the one
// connection type that will not wake from a read deadline set while the read is
// already waiting.
func armMuxAgent(t *testing.T, ctl *Control) conn.Conn {
	t.Helper()

	clientEnd, serverEnd := net.Pipe()
	sess, err := smux.Server(serverEnd, smux.DefaultConfig())
	if err != nil {
		t.Fatalf("smux.Server: %v", err)
	}
	t.Cleanup(func() { sess.Close() })

	clientSess, err := smux.Client(clientEnd, smux.DefaultConfig())
	if err != nil {
		t.Fatalf("smux.Client: %v", err)
	}
	t.Cleanup(func() { clientSess.Close() })

	agentEnd, err := clientSess.OpenStream()
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	t.Cleanup(func() { agentEnd.Close() })

	// AcceptStream has no deadline of its own, so bound it here rather than
	// letting a session that never comes up hang the suite.
	accepted := make(chan *smux.Stream, 1)
	acceptErr := make(chan error, 1)
	go func() {
		stream, err := sess.AcceptStream()
		if err != nil {
			acceptErr <- err
			return
		}
		accepted <- stream
	}()

	select {
	case stream := <-accepted:
		ctl.proxies <- conn.Wrap(stream, "pxy")
	case err := <-acceptErr:
		t.Fatalf("AcceptStream: %v", err)
	case <-time.After(publicTimeout):
		t.Fatal("the mux session never accepted the stream")
	}
	return conn.Wrap(agentEnd, "agt")
}

// publicResult is what startPublicRequest's reader goroutine delivers.
type publicResult struct {
	resp *http.Response
	body string
	err  error
}

// startPublicRequest serves one request through the real public HTTP path on a
// fresh connection and returns a channel carrying the response. It does not
// wait: a test can watch the agent's side of the connection while the request
// is in flight.
func startPublicRequest(t *testing.T, host, path string) <-chan publicResult {
	t.Helper()

	client, server := tcpPair(t)
	go httpHandler(conn.Wrap(server, "pub"), "http")

	if _, err := client.Write([]byte(requestHead(host, path))); err != nil {
		t.Fatalf("failed to write the request: %v", err)
	}

	res := make(chan publicResult, 1)
	go func() {
		// The reader runs in its own goroutine, so it reports failures through
		// the channel: t.Fatalf must not be called off the test goroutine.
		_ = client.SetReadDeadline(time.Now().Add(publicTimeout))
		resp, err := http.ReadResponse(bufio.NewReader(client), nil)
		if err != nil {
			res <- publicResult{err: err}
			return
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		res <- publicResult{resp: resp, body: string(body), err: err}
	}()
	return res
}

// waitPublic waits for startPublicRequest's reader and fails the test when the
// public path never answered.
func waitPublic(t *testing.T, res <-chan publicResult) (*http.Response, string) {
	t.Helper()

	select {
	case r := <-res:
		if r.err != nil {
			t.Fatalf("no HTTP response from the public path: %v", r.err)
		}
		return r.resp, r.body
	case <-time.After(publicTimeout):
		t.Fatal("the public path never answered")
		return nil, ""
	}
}

// policyRoundTrip is the synchronous form of startPublicRequest/waitPublic.
func policyRoundTrip(t *testing.T, host, path string) (*http.Response, string) {
	t.Helper()
	return waitPublic(t, startPublicRequest(t, host, path))
}

// readHead reads one complete request head from the agent's side of a
// connection. One byte at a time is fine on loopback, and it keeps the helper
// free of assumptions about how the server splits its writes.
func readHead(t *testing.T, c conn.Conn, what string) string {
	t.Helper()

	if err := c.SetReadDeadline(time.Now().Add(publicTimeout)); err != nil {
		t.Fatalf("failed to set a read deadline: %v", err)
	}

	var head bytes.Buffer
	one := make([]byte, 1)
	for {
		if _, err := io.ReadFull(c, one); err != nil {
			t.Fatalf("%s: no request head (read %q so far): %v", what, head.String(), err)
		}
		head.WriteByte(one[0])
		if bytes.HasSuffix(head.Bytes(), []byte("\r\n\r\n")) {
			return head.String()
		}
		if head.Len() > 64*1024 {
			t.Fatalf("%s: no head terminator in %d bytes", what, head.Len())
		}
	}
}

// expectNoBytes asserts that a connection delivers nothing to the agent, which
// is what "the policy stopped it at the edge" has to mean over a socket: the
// read either times out with an empty buffer or ends with the connection
// closed, and either way no bytes came out of it.
//
// Both outcomes are accepted on purpose, because they are two different
// endings of the same story. A refusal that happens before the endpoint is
// handed a proxy connection leaves the connection open and silent; a
// termination answers the request and then the connection is torn down (the
// server closes both ends when the join returns), so the agent's next read is
// EOF. Asserting "still open" would pin which of the two happened, which is
// not what this test is about.
func expectNoBytes(t *testing.T, c conn.Conn, what string) {
	t.Helper()

	if err := c.SetReadDeadline(time.Now().Add(250 * time.Millisecond)); err != nil {
		t.Fatalf("failed to set a read deadline: %v", err)
	}
	buf := make([]byte, 64)
	n, err := c.Read(buf)
	if err == nil {
		t.Fatalf("%s received %d byte(s) the policy should have stopped: %q", what, n, buf[:n])
	}
	if n != 0 {
		t.Fatalf("%s received %d byte(s) before the read failed: %q", what, n, buf[:n])
	}
}

// expectClosed asserts that a connection was closed without delivering
// anything, which is how the TCP path refuses a connection: there is no
// protocol there to answer in.
func expectClosed(t *testing.T, c net.Conn, what string) {
	t.Helper()

	if err := c.SetReadDeadline(time.Now().Add(publicTimeout)); err != nil {
		t.Fatalf("failed to set a read deadline: %v", err)
	}
	buf := make([]byte, 1)
	n, err := c.Read(buf)
	if err == nil {
		t.Fatalf("%s: the connection is still open and delivered %d byte(s): %q", what, n, buf[:n])
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatalf("%s: the connection was not closed", what)
	}
}

// dialTcpTunnel dials a tunnel's TCP listener on 127.0.0.1.
//
// The listener is created for 0.0.0.0, which Go serves as a dual-stack socket
// (its reported address is [::] with v6only off), so dialing the address it
// reports connects over ::1 and the server sees an IPv6 client address. Naming
// the IPv4 loopback keeps the address the client actually arrives with -- and
// therefore the CIDRs these tests write -- the obvious ones.
func dialTcpTunnel(t *testing.T, tun *Tunnel) *net.TCPConn {
	t.Helper()

	if tun.listener == nil {
		t.Fatal("a TCP tunnel must bind a listener")
	}
	port := tun.listener.Addr().(*net.TCPAddr).Port
	publicClient, err := net.DialTCP("tcp", nil, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Fatalf("failed to dial the public port of %s: %v", tun.url, err)
	}
	t.Cleanup(func() { publicClient.Close() })
	return publicClient
}

// hasField reports whether a head carries a field, comparing the name the way
// HTTP does (case-insensitively) and the value exactly. The rewriter emits
// field names in canonical form, so a policy that configures "x-added" puts
// "X-Added" on the wire: asserting the configured spelling would pin a detail
// that is not part of the contract.
func hasField(head, name, value string) bool {
	for _, line := range strings.Split(head, "\r\n") {
		n, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(n), name) && strings.TrimSpace(v) == value {
			return true
		}
	}
	return false
}

// readStartProxy consumes the StartProxy message every proxied connection
// begins with, and returns it.
func readStartProxy(t *testing.T, agent conn.Conn, what string) msg.StartProxy {
	t.Helper()

	if err := agent.SetReadDeadline(time.Now().Add(publicTimeout)); err != nil {
		t.Fatalf("failed to set a read deadline: %v", err)
	}
	var startProxy msg.StartProxy
	if err := msg.ReadMsgInto(agent, &startProxy); err != nil {
		t.Fatalf("%s was never asked for the connection: %v", what, err)
	}
	return startProxy
}

// ---------------------------------------------------------------------------
// on_tcp_connect, HTTP path

// TestPolicyConnectPhaseRefusesBeforeAnAgentIsAsked covers the connect phase
// on the HTTP path. The verdict is reached in httpHandler, before the target
// is handed a proxy connection, so the client is answered with the synthetic
// response the verdict carries and the agent's connection stays silent.
func TestPolicyConnectPhaseRefusesBeforeAnAgentIsAsked(t *testing.T) {
	const host = "guarded.ngrok.test"

	cases := []struct {
		name   string
		action *policy.Action
	}{
		{"deny", policyAction("deny")},
		{
			// The public client is on 127.0.0.1, so an allow list that only
			// names 10.0.0.0/8 refuses it. The client's address is the only
			// input this phase has, and it is the real one (the connection is
			// a loopback TCP pair, not a synthetic address).
			"restrict-ips",
			policyActionConfig("restrict-ips", map[string]interface{}{
				"allow": []interface{}{"10.0.0.0/8"},
			}),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setupTestRegistry(t)
			ctl := testControl(t, "")
			agent := armHTTPAgent(t, ctl)
			registerTestTunnel(t, ctl, msg.ReqTunnel{
				Protocol:      "http",
				Hostname:      host,
				TrafficPolicy: &policy.TrafficPolicy{OnTCPConnect: []*policy.Action{tc.action}},
			})

			resp, body := policyRoundTrip(t, host, "/")
			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("status = %d, want 403", resp.StatusCode)
			}
			if body != "" {
				t.Fatalf("body = %q, want an empty body", body)
			}
			if resp.ContentLength != 0 {
				t.Fatalf("Content-Length = %d, want 0", resp.ContentLength)
			}

			// The connection never became a proxy connection: the agent sees
			// neither a StartProxy nor a byte of the request.
			expectNoBytes(t, agent, "the agent")
		})
	}
}

// TestPolicyConnectPhaseLetsAPermittedClientThrough is the other side of the
// same phase: a restrict-ips rule that permits the client changes nothing
// about the connection, which is served as it always was.
func TestPolicyConnectPhaseLetsAPermittedClientThrough(t *testing.T) {
	const host = "guarded.ngrok.test"

	setupTestRegistry(t)
	ctl := testControl(t, "")
	agent := armHTTPAgent(t, ctl)
	registerTestTunnel(t, ctl, msg.ReqTunnel{
		Protocol: "http",
		Hostname: host,
		TrafficPolicy: &policy.TrafficPolicy{OnTCPConnect: []*policy.Action{
			policyActionConfig("restrict-ips", map[string]interface{}{
				"allow": []interface{}{"127.0.0.1/32"},
			}),
		}},
	})

	res := startPublicRequest(t, host, "/hello")

	startProxy := readStartProxy(t, agent, "the agent")
	if startProxy.Url != "http://"+host {
		t.Fatalf("StartProxy Url = %q, want http://%s", startProxy.Url, host)
	}
	if head := readHead(t, agent, "the agent"); !strings.HasPrefix(head, "GET /hello HTTP/1.1\r\n") {
		t.Fatalf("the agent got %q, want the request", head)
	}

	upstream := "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
	if _, err := agent.Write([]byte(upstream)); err != nil {
		t.Fatalf("failed to write the upstream response: %v", err)
	}

	resp, body := waitPublic(t, res)
	if resp.StatusCode != http.StatusOK || body != "hello" {
		t.Fatalf("the public client got %d %q, want 200 \"hello\"", resp.StatusCode, body)
	}
}

// ---------------------------------------------------------------------------
// on_tcp_connect, TCP path

// TestPolicyConnectPhaseOnTcpPath covers the connect phase where the
// connection arrives at the endpoint's own TCP listener. A refusal there is
// the connection closing, because a TCP client has no request to be answered,
// and a permitted connection is dispatched to the agent as usual.
func TestPolicyConnectPhaseOnTcpPath(t *testing.T) {
	t.Run("a refused connection is closed without reaching an agent", func(t *testing.T) {
		setupTestRegistry(t)
		ctl := testControl(t, "")

		// Arm the agent's connection before the tunnel exists, i.e. before
		// its listener's accept goroutine can wrap anything (see armProxyPool).
		agent := armProxyPool(t, ctl)
		tun := registerTestTunnel(t, ctl, msg.ReqTunnel{
			Protocol: "tcp",
			TrafficPolicy: &policy.TrafficPolicy{OnTCPConnect: []*policy.Action{
				policyActionConfig("restrict-ips", map[string]interface{}{
					"deny": []interface{}{"127.0.0.1/32"},
				}),
			}},
		})

		publicClient := dialTcpTunnel(t, tun)

		expectClosed(t, publicClient, "the public client")
		expectNoBytes(t, agent, "the agent")
	})

	t.Run("a permitted connection is dispatched", func(t *testing.T) {
		setupTestRegistry(t)
		ctl := testControl(t, "")
		agent := armProxyPool(t, ctl)
		tun := registerTestTunnel(t, ctl, msg.ReqTunnel{
			Protocol: "tcp",
			TrafficPolicy: &policy.TrafficPolicy{OnTCPConnect: []*policy.Action{
				policyActionConfig("restrict-ips", map[string]interface{}{
					"allow": []interface{}{"127.0.0.1/32"},
				}),
			}},
		})

		dialTcpTunnel(t, tun)
		if got := readStartProxy(t, agent, "the agent"); got.Url != tun.url {
			t.Fatalf("the connection was proxied for %s, want %s", got.Url, tun.url)
		}
	})
}

// ---------------------------------------------------------------------------
// on_http_request

// TestPolicyRequestPhaseAnswersAtTheEdge covers the terminating request
// actions end to end: the head is read, the hook answers it, and the answer
// reaches the public client while the request itself never reaches the agent.
// The second half of the test sends a request the rule does not match, which
// must be proxied untouched.
func TestPolicyRequestPhaseAnswersAtTheEdge(t *testing.T) {
	const host = "guarded.ngrok.test"

	setupTestRegistry(t)
	ctl := testControl(t, "")
	// Two public connections are served, in order, by these two connections: a
	// pool is a FIFO.
	denied := armHTTPAgent(t, ctl)
	allowed := armHTTPAgent(t, ctl)

	registerTestTunnel(t, ctl, msg.ReqTunnel{
		Protocol: "http",
		Hostname: host,
		TrafficPolicy: &policy.TrafficPolicy{OnHTTPRequest: []*policy.Action{
			policyActionConfig("custom-response", map[string]interface{}{
				"status_code": 418,
				"body":        "teapot ${req.url.path}",
			}, "req.url.path == '/admin'"),
		}},
	})

	// A request the rule matches is answered by the edge.
	res := startPublicRequest(t, host, "/admin")
	readStartProxy(t, denied, "the agent")
	expectNoBytes(t, denied, "the agent")

	resp, body := waitPublic(t, res)
	if resp.StatusCode != http.StatusTeapot {
		t.Fatalf("status = %d, want 418", resp.StatusCode)
	}
	if body != "teapot /admin" {
		t.Fatalf("body = %q, want %q", body, "teapot /admin")
	}
	// The content type is sniffed from the configured body when the config
	// does not give one, the way ngrok documents.
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("Content-Type = %q, want text/plain", ct)
	}

	// A request the rule does not match is proxied, so the condition -- not
	// just the action -- is doing its work.
	res = startPublicRequest(t, host, "/public")
	readStartProxy(t, allowed, "the agent")
	if head := readHead(t, allowed, "the agent"); !strings.HasPrefix(head, "GET /public HTTP/1.1\r\n") {
		t.Fatalf("the agent got %q, want the request", head)
	}
	if _, err := allowed.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")); err != nil {
		t.Fatalf("failed to write the upstream response: %v", err)
	}

	resp, body = waitPublic(t, res)
	if resp.StatusCode != http.StatusOK || body != "ok" {
		t.Fatalf("the public client got %d %q, want 200 \"ok\"", resp.StatusCode, body)
	}
}

// TestPolicyTerminateOverAMuxStream is the server-level version of the case
// workstream B's e2e hung on: a terminating request-phase action on a connection
// whose agent side is a mux stream rather than a TCP socket.
//
// Nothing about the policy differs from TestPolicyRequestPhaseAnswersAtTheEdge
// above -- same action, same phases, same public path. The difference is the
// connection under it: the response side parks in a read of the proxy conn for a
// response that will never come, and this is the transport where a read deadline
// cannot end that read. With a deadline for a wake this test fails at
// waitPublic's timeout (the client is never answered, the request side drains a
// public connection that never EOFs, and Join never unwinds); with the wake
// closing the source the terminated client is answered like any other.
func TestPolicyTerminateOverAMuxStream(t *testing.T) {
	const host = "muxed.ngrok.test"

	setupTestRegistry(t)
	ctl := testControl(t, "")
	agent := armMuxAgent(t, ctl)
	registerTestTunnel(t, ctl, msg.ReqTunnel{
		Protocol: "http",
		Hostname: host,
		TrafficPolicy: &policy.TrafficPolicy{OnHTTPRequest: []*policy.Action{
			policyActionConfig("custom-response", map[string]interface{}{
				"status_code": 451,
				"body":        "not here",
			}),
		}},
	})

	res := startPublicRequest(t, host, "/anything")
	// The agent is told a proxy connection started -- that is written before the
	// policy runs -- and is then sent nothing: the request is answered at the
	// edge, so it never reaches the proxy connection at all.
	readStartProxy(t, agent, "the agent")
	expectNoBytes(t, agent, "the agent")

	resp, body := waitPublic(t, res)
	if resp.StatusCode != 451 || body != "not here" {
		t.Fatalf("the public client got %d %q, want 451 %q", resp.StatusCode, body, "not here")
	}
	if !resp.Close {
		t.Fatalf("a terminated connection closes after its synthetic response")
	}
}

// TestPolicyRequestPhaseRewritesWhatTheAgentSees covers the non-terminating
// request action: the head the agent reads carries the policy's headers, with
// their ${...} placeholders resolved against the request that arrived.
func TestPolicyRequestPhaseRewritesWhatTheAgentSees(t *testing.T) {
	const host = "guarded.ngrok.test"

	setupTestRegistry(t)
	ctl := testControl(t, "")
	agent := armHTTPAgent(t, ctl)
	registerTestTunnel(t, ctl, msg.ReqTunnel{
		Protocol: "http",
		Hostname: host,
		TrafficPolicy: &policy.TrafficPolicy{OnHTTPRequest: []*policy.Action{
			policyActionConfig("add-headers", map[string]interface{}{
				"headers": map[string]interface{}{
					"X-Added":  "yes",
					"X-Path":   "${req.url.path}",
					"X-Client": "${conn.client_ip}",
				},
			}),
		}},
	})

	res := startPublicRequest(t, host, "/hello")
	readStartProxy(t, agent, "the agent")

	head := readHead(t, agent, "the agent")
	for _, want := range [][2]string{
		{"x-added", "yes"},
		{"x-path", "/hello"},
		{"x-client", "127.0.0.1"},
	} {
		if !hasField(head, want[0], want[1]) {
			t.Fatalf("the agent's head %q does not carry %s: %s", head, want[0], want[1])
		}
	}

	if _, err := agent.Write([]byte("HTTP/1.1 204 No Content\r\n\r\n")); err != nil {
		t.Fatalf("failed to write the upstream response: %v", err)
	}
	if resp, _ := waitPublic(t, res); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// on_http_response

// TestPolicyResponsePhaseStripsHeaders covers the response phase: the head the
// agent wrote on its way back to the public client is rewritten, and only the
// names the policy names are touched.
func TestPolicyResponsePhaseStripsHeaders(t *testing.T) {
	const host = "guarded.ngrok.test"

	setupTestRegistry(t)
	ctl := testControl(t, "")
	agent := armHTTPAgent(t, ctl)
	registerTestTunnel(t, ctl, msg.ReqTunnel{
		Protocol: "http",
		Hostname: host,
		TrafficPolicy: &policy.TrafficPolicy{OnHTTPResponse: []*policy.Action{
			policyActionConfig("remove-headers", map[string]interface{}{
				"headers": []interface{}{"X-Internal", "server"},
			}),
		}},
	})

	res := startPublicRequest(t, host, "/hello")
	readStartProxy(t, agent, "the agent")
	readHead(t, agent, "the agent")

	upstream := "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nX-Internal: leak\r\nServer: nginx\r\nX-Keep: yes\r\n\r\nhello"
	if _, err := agent.Write([]byte(upstream)); err != nil {
		t.Fatalf("failed to write the upstream response: %v", err)
	}

	resp, body := waitPublic(t, res)
	if resp.StatusCode != http.StatusOK || body != "hello" {
		t.Fatalf("the public client got %d %q, want 200 \"hello\"", resp.StatusCode, body)
	}
	if got := resp.Header.Get("X-Internal"); got != "" {
		t.Fatalf("X-Internal = %q, want the header the policy removes", got)
	}
	if got := resp.Header.Get("Server"); got != "" {
		t.Fatalf("Server = %q, want the header the policy removes", got)
	}
	if got := resp.Header.Get("X-Keep"); got != "yes" {
		t.Fatalf("X-Keep = %q, want the header the policy does not name", got)
	}
}

// ---------------------------------------------------------------------------
// the no-policy path

// TestPolicyAbsentOrEmptyTakesTheRawPath is the parity gate for the server: an
// endpoint with no policy, and one whose policy carries no actions at all,
// must move bytes exactly as this server moved them before policies existed.
//
// The upstream response is deliberately non-canonical (a lower-case field
// name, an unusual casing) so that any head rewrite on the way through would
// show up as a difference, and the request is compared byte for byte on the
// agent's side for the same reason.
func TestPolicyAbsentOrEmptyTakesTheRawPath(t *testing.T) {
	const host = "plain.ngrok.test"

	cases := []struct {
		name   string
		policy *policy.TrafficPolicy
	}{
		{"no policy", nil},
		{"a policy with no actions", &policy.TrafficPolicy{}},
	}

	upstream := "HTTP/1.1 200 OK\r\ncontent-length: 5\r\nX-MiXeD-Case: v\r\n\r\nhello"

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setupTestRegistry(t)
			ctl := testControl(t, "")
			agent := armHTTPAgent(t, ctl)
			registerTestTunnel(t, ctl, msg.ReqTunnel{
				Protocol:      "http",
				Hostname:      host,
				TrafficPolicy: tc.policy,
			})

			client, server := tcpPair(t)
			go httpHandler(conn.Wrap(server, "pub"), "http")

			request := requestHead(host, "/hello")
			if _, err := client.Write([]byte(request)); err != nil {
				t.Fatalf("failed to write the request: %v", err)
			}

			readStartProxy(t, agent, "the agent")
			if head := readHead(t, agent, "the agent"); head != request {
				t.Fatalf("the agent read %q, want the request verbatim %q", head, request)
			}

			if _, err := agent.Write([]byte(upstream)); err != nil {
				t.Fatalf("failed to write the upstream response: %v", err)
			}

			got := make([]byte, len(upstream))
			if err := client.SetReadDeadline(time.Now().Add(publicTimeout)); err != nil {
				t.Fatalf("failed to set a read deadline: %v", err)
			}
			if _, err := io.ReadFull(client, got); err != nil {
				t.Fatalf("failed to read the upstream response: %v", err)
			}
			if string(got) != upstream {
				t.Fatalf("the public client read\n%q\nwant\n%q", got, upstream)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// registration

// TestNewTunnelRefusesAPolicyItCannotEnforce is the loud half of the design: a
// policy the server cannot enforce fails the registration, and the endpoint's
// url is not claimed, so an endpoint can never look protected while running
// unprotected (SPEC 3.3).
func TestNewTunnelRefusesAPolicyItCannotEnforce(t *testing.T) {
	const host = "bad.ngrok.test"

	cases := []struct {
		name   string
		policy *policy.TrafficPolicy
		want   []string
	}{
		{
			"an unknown action",
			&policy.TrafficPolicy{OnHTTPRequest: []*policy.Action{policyAction("kill-connection")}},
			[]string{"on_http_request[0]", "kill-connection"},
		},
		{
			"a status code that is not an HTTP status",
			&policy.TrafficPolicy{OnHTTPRequest: []*policy.Action{
				policyActionConfig("deny", map[string]interface{}{"status_code": 999}),
			}},
			[]string{"on_http_request[0] (deny)", "status_code"},
		},
		{
			"an action in a phase that does not implement it",
			&policy.TrafficPolicy{OnHTTPResponse: []*policy.Action{policyAction("custom-response")}},
			[]string{"on_http_response[0] (custom-response)", "on_http_response"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setupTestRegistry(t)
			ctl := testControl(t, "")

			req := msg.ReqTunnel{Protocol: "http", Hostname: host, TrafficPolicy: tc.policy}
			tun, err := NewTunnel(&req, ctl)
			if err == nil {
				tun.Shutdown()
				t.Fatal("a policy the server cannot enforce must fail the registration")
			}
			if !strings.Contains(err.Error(), "invalid traffic policy") {
				t.Errorf("the error %q does not name the policy as the cause", err)
			}
			for _, want := range tc.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("the error %q does not mention %q", err, want)
				}
			}

			if tunnelRegistry.Get("http://"+host) != nil {
				t.Fatal("the refused registration claimed the url anyway")
			}

			// The url is still available to a tunnel whose policy compiles.
			if got := registerTestTunnel(t, ctl, msg.ReqTunnel{Protocol: "http", Hostname: host}); got.url != "http://"+host {
				t.Fatalf("the url after a refused registration is %q, want http://%s", got.url, host)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// policy across a forward_to chain

// TestPolicyAcrossForwardToEndpoint covers which endpoint's policy governs a
// connection that arrives at a public entry point and terminates at an
// internal one. The entry point's own policy wins when it has one -- the spec
// says "the target's", which for a chain would silently drop the policy an
// operator attached to the public endpoint -- and the target's policy applies
// when the entry point has none.
func TestPolicyAcrossForwardToEndpoint(t *testing.T) {
	const host = "entry.ngrok.test"

	t.Run("the entry point's policy wins", func(t *testing.T) {
		setupTestRegistry(t)
		ctl := testControl(t, "")
		armHTTPAgent(t, ctl)

		internal := registerTestTunnel(t, ctl, msg.ReqTunnel{
			Protocol: "http", Binding: msg.BindingInternal, Hostname: "svc.internal",
			TrafficPolicy: &policy.TrafficPolicy{OnHTTPRequest: []*policy.Action{
				policyActionConfig("add-headers", map[string]interface{}{
					"headers": map[string]interface{}{"X-Internal": "added"},
				}),
			}},
		})
		registerTestTunnel(t, ctl, msg.ReqTunnel{
			Protocol: "http", Hostname: host, ForwardTo: internal.url,
			TrafficPolicy: &policy.TrafficPolicy{OnHTTPRequest: []*policy.Action{policyAction("deny")}},
		})

		resp, _ := policyRoundTrip(t, host, "/")
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status = %d, want 403: the entry point's own policy did not run", resp.StatusCode)
		}
	})

	t.Run("the target's policy applies when the entry point has none", func(t *testing.T) {
		setupTestRegistry(t)
		ctl := testControl(t, "")
		agent := armHTTPAgent(t, ctl)

		internal := registerTestTunnel(t, ctl, msg.ReqTunnel{
			Protocol: "http", Binding: msg.BindingInternal, Hostname: "svc.internal",
			TrafficPolicy: &policy.TrafficPolicy{OnHTTPRequest: []*policy.Action{policyAction("deny")}},
		})
		registerTestTunnel(t, ctl, msg.ReqTunnel{
			Protocol: "http", Hostname: host, ForwardTo: internal.url,
		})

		res := startPublicRequest(t, host, "/")

		// The chain landed on the internal endpoint (StartProxy names it),
		// and its policy answered the request there.
		if got := readStartProxy(t, agent, "the internal endpoint's agent"); got.Url != internal.url {
			t.Fatalf("StartProxy Url = %q, want %q", got.Url, internal.url)
		}
		expectNoBytes(t, agent, "the internal endpoint's agent")

		resp, _ := waitPublic(t, res)
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status = %d, want 403: the target's policy did not run", resp.StatusCode)
		}
	})
}
