package server

// Tests for the TLSTermination wire field and its registration semantics
// (SPEC-CLUSTER5 5.1): the additive-decode rule (an old-style message without
// the field decodes to "" = edge), the fail-loudly value check, the https-only
// reach of agent termination, and the registry/routing observable that
// separates edge from agent tunnels.

import (
	"encoding/json"
	"strings"
	"testing"

	"ngrok/msg"
)

// TestOldStyleReqTunnelDecodesEdgeTermination pins the additive-field rule:
// a client (or a captured wire message) that predates TLSTermination must
// decode to "" -- edge termination -- so old tunnels keep every behavior.
func TestOldStyleReqTunnelDecodesEdgeTermination(t *testing.T) {
	// A ReqTunnel payload spelled exactly as a pre-agent-TLS client sends it:
	// no TLSTermination key at all.
	wire, err := json.Marshal(struct {
		Type    string
		Payload map[string]interface{}
	}{
		Type: "ReqTunnel",
		Payload: map[string]interface{}{
			"ReqId":    "1",
			"Protocol": "https",
			"Hostname": "old.test",
		},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	unpacked, err := msg.Unpack(wire)
	if err != nil {
		t.Fatalf("unpack: %v", err)
	}
	req, ok := unpacked.(*msg.ReqTunnel)
	if !ok {
		t.Fatalf("unpacked %T, want *msg.ReqTunnel", unpacked)
	}
	if req.TLSTermination != msg.TLSTerminationEdge {
		t.Fatalf("absent TLSTermination must decode to %q, got %q", msg.TLSTerminationEdge, req.TLSTermination)
	}
}

func TestNewTunnelRefusesUnknownTLSTermination(t *testing.T) {
	setupTestRegistry(t)
	ctl := testControl(t, "")

	// A typo must be refused, never read as the edge default: the silent
	// fallback would register an endpoint where the server holds the
	// certificate the operator believes the agent holds.
	_, err := NewTunnel(&msg.ReqTunnel{
		Protocol:       msg.ProtoHTTPS,
		Hostname:       "typo.test",
		TLSTermination: "agents",
	}, ctl)
	if err == nil {
		t.Fatal("an unknown TLSTermination value must refuse registration")
	}
	if !strings.Contains(err.Error(), "TLSTermination") {
		t.Fatalf("the error must name the offending field, got: %v", err)
	}
}

func TestAgentTerminationOnlyReachableOnHTTPSLeg(t *testing.T) {
	setupTestRegistry(t)
	ctl := testControl(t, "")

	// The https leg carries it: this is the one tunnel the SNI router sends
	// raw bytes to.
	httpsTun := registerTestTunnel(t, ctl, msg.ReqTunnel{
		Protocol:       msg.ProtoHTTPS,
		Hostname:       "agent.test",
		TLSTermination: msg.TLSTerminationAgent,
	})
	if !httpsTun.agentTLS() {
		t.Fatal("the https leg with agent termination must report agentTLS")
	}

	// The http leg of the same multi-leg request arrives with the field set
	// (it rides on the request, the server splits the legs) and must be
	// inert: no TLS on that leg, so nothing to terminate anywhere. It must
	// register normally and stay edge.
	httpTun := registerTestTunnel(t, ctl, msg.ReqTunnel{
		Protocol:       msg.ProtoHTTP,
		Hostname:       "agent.test",
		TLSTermination: msg.TLSTerminationAgent,
	})
	if httpTun.agentTLS() {
		t.Fatal("an http leg must never report agentTLS")
	}

	// Same for a tcp leg.
	tcpTun := registerTestTunnel(t, ctl, msg.ReqTunnel{
		Protocol:       msg.ProtoTCP,
		TLSTermination: msg.TLSTerminationAgent,
	})
	if tcpTun.agentTLS() {
		t.Fatal("a tcp leg must never report agentTLS")
	}
	tcpTun.Shutdown()
}

// TestNewTunnelAckEchoesTLSTermination pins the ack's termination echo: the
// success acknowledgement carries the mode the server actually registered
// (normalized), and an edge registration echoes edge. The echo is the
// client's establishment-time proof it got what it asked for -- an old server
// decodes nothing into the field, and the client refuses the tunnel instead
// of discovering the mismatch one broken connection at a time.
func TestNewTunnelAckEchoesTLSTermination(t *testing.T) {
	setupTestRegistry(t)
	ctl := testControl(t, "")

	// The mixed casing is deliberate: validateRequest normalizes before the
	// echo is built, so the ack must carry the canonical spelling.
	ctl.registerTunnel(&msg.ReqTunnel{ReqId: "req-agent", Protocol: msg.ProtoHTTPS, Hostname: "echo-agent.test", TLSTermination: "Agent"})
	ctl.registerTunnel(&msg.ReqTunnel{ReqId: "req-edge", Protocol: msg.ProtoHTTPS, Hostname: "echo-edge.test"})

	for _, want := range []struct {
		reqId string
		echo  string
	}{
		{"req-agent", msg.TLSTerminationAgent},
		{"req-edge", msg.TLSTerminationEdge},
	} {
		reply, ok := nextControlMessage(t, ctl).(*msg.NewTunnel)
		if !ok {
			t.Fatalf("%s: the control was not sent a NewTunnel", want.reqId)
		}
		if reply.Error != "" {
			t.Fatalf("%s: the registration must succeed, got %q", want.reqId, reply.Error)
		}
		if reply.TLSTermination != want.echo {
			t.Fatalf("%s: the ack echoed %q, want %q", want.reqId, reply.TLSTermination, want.echo)
		}
	}
}
