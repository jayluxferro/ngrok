package server

// Tests for the fixed-TCP-port ownership registry (SPEC-CLUSTER5 4.1/4.2).
//
// Two layers: the registry's own claim/refuse/reclaim/release semantics, and
// the registration path that feeds it (registerTcp through NewTunnel, real
// loopback binds). The ownership question is the url-bucket question applied
// to numbers, so the refusals are asserted on their wording too -- an error
// that doesn't name the port is a support ticket, not a message.

import (
	"net"
	"strconv"
	"strings"
	"testing"

	"ngrok/conn"
	"ngrok/msg"
)

// setupPortClaims installs a fresh port registry and restores the old one.
func setupPortClaims(t *testing.T) *portClaimRegistry {
	t.Helper()

	prev := portClaims
	t.Cleanup(func() { portClaims = prev })
	portClaims = newPortClaimRegistry()
	return portClaims
}

// freePort returns a loopback port that is free right now. Racy by nature
// (the port could be taken between close and the next bind), but good enough
// to find an unused number for a test.
func freePort(t *testing.T) int {
	t.Helper()

	l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("failed to find a free port: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return port
}

func TestPortClaimRefusesAnotherOwner(t *testing.T) {
	reg := setupPortClaims(t)
	port := freePort(t)

	if err := reg.Claim(msg.ProtoTCP, port, "alice"); err != nil {
		t.Fatalf("first claim must succeed: %v", err)
	}
	err := reg.Claim(msg.ProtoTCP, port, "bob")
	if err == nil {
		t.Fatal("a second owner must not claim a held port")
	}
	if !strings.Contains(err.Error(), "already claimed by another auth token") {
		t.Fatalf("refusal must name the hijack attempt, got: %v", err)
	}
	if !strings.Contains(err.Error(), strconv.Itoa(port)) {
		t.Fatalf("refusal must name the port, got: %v", err)
	}
	if got := reg.HeldBy(msg.ProtoTCP, port); got != "alice" {
		t.Fatalf("the refused claim must not disturb the holder, got %q", got)
	}
}

func TestPortClaimSameOwnerReclaimsAtomically(t *testing.T) {
	reg := setupPortClaims(t)
	port := freePort(t)

	if err := reg.Claim(msg.ProtoTCP, port, "alice"); err != nil {
		t.Fatalf("first claim: %v", err)
	}
	// The reconnect race: the new tunnel registers before the old one's
	// teardown releases. Same owner must sail through -- the port never
	// looks free, so a third party cannot slip in between.
	if err := reg.Claim(msg.ProtoTCP, port, "alice"); err != nil {
		t.Fatalf("same-owner reclaim must succeed: %v", err)
	}
	if got := reg.HeldBy(msg.ProtoTCP, port); got != "alice" {
		t.Fatalf("holder changed after reclaim: %q", got)
	}

	// Third party still locked out while both holds live.
	if err := reg.Claim(msg.ProtoTCP, port, "bob"); err == nil {
		t.Fatal("another owner must be refused while the reclaim holds")
	}
}

func TestPortClaimReleaseFreesForNextOwner(t *testing.T) {
	reg := setupPortClaims(t)
	port := freePort(t)

	if err := reg.Claim(msg.ProtoTCP, port, "alice"); err != nil {
		t.Fatalf("claim: %v", err)
	}
	// A foreign release is ignored, not obeyed: teardown paths are
	// best-effort and must not drop someone else's claim.
	reg.Release(msg.ProtoTCP, port, "bob")
	if got := reg.HeldBy(msg.ProtoTCP, port); got != "alice" {
		t.Fatalf("a foreign release must not drop the claim, holder %q", got)
	}

	reg.Release(msg.ProtoTCP, port, "alice")
	if got := reg.HeldBy(msg.ProtoTCP, port); got != "" {
		t.Fatalf("the port must be free after the holder releases, got %q", got)
	}
	if err := reg.Claim(msg.ProtoTCP, port, "bob"); err != nil {
		t.Fatalf("the next owner must claim the released port: %v", err)
	}
}

func TestPortClaimRefcountSurvivesPartialTeardown(t *testing.T) {
	reg := setupPortClaims(t)
	port := freePort(t)

	// Two tunnels of one account on one port (pooling members): the port
	// stays claimed until the LAST goes.
	if err := reg.Claim(msg.ProtoTCP, port, "alice"); err != nil {
		t.Fatalf("first claim: %v", err)
	}
	if err := reg.Claim(msg.ProtoTCP, port, "alice"); err != nil {
		t.Fatalf("second claim: %v", err)
	}
	reg.Release(msg.ProtoTCP, port, "alice")
	if got := reg.HeldBy(msg.ProtoTCP, port); got != "alice" {
		t.Fatalf("one release must not free a twice-claimed port, got %q", got)
	}
	reg.Release(msg.ProtoTCP, port, "alice")
	if got := reg.HeldBy(msg.ProtoTCP, port); got != "" {
		t.Fatalf("the last release must free the port, got %q", got)
	}
}

func TestPortClaimRefusesOwnListeners(t *testing.T) {
	setupTestRegistry(t) // installs http:80 / https:443 / tunnel-less listeners
	setupPortClaims(t)

	err := portClaims.Claim(msg.ProtoTCP, 443, "alice")
	if err == nil {
		t.Fatal("claiming the server's own https listener port must be refused")
	}
	if !strings.Contains(err.Error(), "public https listener") {
		t.Fatalf("refusal must name the listener, got: %v", err)
	}

	err = portClaims.Claim(msg.ProtoTCP, 80, "alice")
	if err == nil || !strings.Contains(err.Error(), "public http listener") {
		t.Fatalf("claiming the http listener port must name it, got: %v", err)
	}

	// The control/proxy listener and the admin server are named too, from
	// their configured addresses. The tunnel listener is a bare struct with
	// only its bound address set, exactly as setupTestRegistry builds the
	// http/https stubs: the collision check reads the address, not a socket.
	prevTunnel := listeners["tunnel"]
	listeners["tunnel"] = &conn.Listener{Addr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4443}}
	defer func() { listeners["tunnel"] = prevTunnel }()
	if err := portClaims.Claim(msg.ProtoTCP, 4443, "alice"); err == nil || !strings.Contains(err.Error(), "control/proxy (tunnel) listener") {
		t.Fatalf("claiming the tunnel listener port must name it, got: %v", err)
	}

	prevAdmin := opts.adminAddr
	opts.adminAddr = "127.0.0.1:7788"
	defer func() { opts.adminAddr = prevAdmin }()
	if err := portClaims.Claim(msg.ProtoTCP, 7788, "alice"); err == nil || !strings.Contains(err.Error(), "admin server listener") {
		t.Fatalf("claiming the admin port must name it, got: %v", err)
	}
}

func TestRegisterTcpClaimsRefusesAndReclaims(t *testing.T) {
	setupTestRegistry(t)
	setupPortClaims(t)
	opts.authTokens = []string{"tok-a"} // owners come from auth.User when tokens exist

	alice := testControl(t, "alice")
	bob := testControl(t, "bob")
	port := freePort(t)

	// Alice claims and binds.
	tunA := registerTestTunnel(t, alice, msg.ReqTunnel{Protocol: msg.ProtoTCP, RemotePort: uint16(port)})
	if tunA.listener == nil {
		t.Fatal("the fixed-port tunnel must bind its listener")
	}
	if got := portClaims.HeldBy(msg.ProtoTCP, port); got != "alice" {
		t.Fatalf("the bind must carry a claim, holder %q", got)
	}

	// Bob reaches for the same number: refused by the registry, before the
	// kernel gets to say "address already in use".
	_, err := NewTunnel(&msg.ReqTunnel{Protocol: msg.ProtoTCP, RemotePort: uint16(port)}, bob)
	if err == nil {
		t.Fatal("a second account must not take a claimed remote port")
	}
	if !strings.Contains(err.Error(), "already claimed by another auth token") || !strings.Contains(err.Error(), strconv.Itoa(port)) {
		t.Fatalf("refusal must name port and hijack, got: %v", err)
	}

	// Alice's teardown releases; Bob can have the number now.
	tunA.Shutdown()
	if got := portClaims.HeldBy(msg.ProtoTCP, port); got != "" {
		t.Fatalf("shutdown must release the claim, holder %q", got)
	}
	tunB := registerTestTunnel(t, bob, msg.ReqTunnel{Protocol: msg.ProtoTCP, RemotePort: uint16(port)})
	if got := portClaims.HeldBy(msg.ProtoTCP, port); got != "bob" {
		t.Fatalf("the released port must be claimable by the next owner, holder %q", got)
	}
	tunB.Shutdown()
}

func TestRegisterTcpReclaimAfterRestart(t *testing.T) {
	setupTestRegistry(t)
	setupPortClaims(t)
	opts.authTokens = []string{"tok-a"}

	alice := testControl(t, "alice")
	port := freePort(t)

	tunA := registerTestTunnel(t, alice, msg.ReqTunnel{Protocol: msg.ProtoTCP, RemotePort: uint16(port)})
	tunA.Shutdown()

	// The spec's e2e shape: the same account's client restarts and asks for
	// its old port -- it must get it back, not find it poisoned.
	tunA2 := registerTestTunnel(t, alice, msg.ReqTunnel{Protocol: msg.ProtoTCP, RemotePort: uint16(port)})
	if tunA2.listener == nil {
		t.Fatal("the restarting owner must rebind its own port")
	}
	tunA2.Shutdown()
}

func TestRegisterTcpBindFailureReleasesClaim(t *testing.T) {
	setupTestRegistry(t)
	setupPortClaims(t)
	opts.authTokens = []string{"tok-a"}

	alice := testControl(t, "alice")
	port := freePort(t)

	// A process outside this registry holds the number: the claim is taken,
	// the bind fails, and the claim must NOT survive -- a port this server
	// cannot bind must not stay locked against the account that asked.
	// The blocker binds the same wildcard address registerTcp binds (a
	// loopback-specific bind does not conflict with a wildcard one on
	// macOS, where this suite runs).
	blocker, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("0.0.0.0"), Port: port})
	if err != nil {
		t.Fatalf("failed to occupy the test port: %v", err)
	}
	t.Cleanup(func() { blocker.Close() })

	_, err = NewTunnel(&msg.ReqTunnel{Protocol: msg.ProtoTCP, RemotePort: uint16(port)}, alice)
	if err == nil {
		t.Fatal("binding an occupied port must fail")
	}
	if got := portClaims.HeldBy(msg.ProtoTCP, port); got != "" {
		t.Fatalf("a failed bind must release the claim, holder %q", got)
	}
}

// ---------------------------------------------------------------------------
// SPEC-CLUSTER8 3.1: the protocol dimension

// TestPortClaimProtocolSpacesAreIndependent pins the claim key's protocol
// dimension: tcp:5000 and udp:5000 are different ports to every part of the
// IP stack that matters here, so the registry must keep their claims apart --
// different owners may hold the same number in the two spaces, and within one
// space the old rules hold unchanged.
func TestPortClaimProtocolSpacesAreIndependent(t *testing.T) {
	reg := setupPortClaims(t)
	port := freePort(t)

	// Alice holds tcp:port; Bob may hold udp:port -- the spaces are
	// independent, which is the whole point of the dimension.
	if err := reg.Claim(msg.ProtoTCP, port, "alice"); err != nil {
		t.Fatalf("tcp claim: %v", err)
	}
	if err := reg.Claim(msg.ProtoUDP, port, "bob"); err != nil {
		t.Fatalf("a udp claim must not fight a tcp claim on the same number: %v", err)
	}

	// Within one space, the cross-owner refusal holds, and names the space:
	// "remote udp port N" rather than a bare port number, because a number
	// alone no longer identifies what was refused.
	err := reg.Claim(msg.ProtoUDP, port, "alice")
	if err == nil {
		t.Fatal("a second owner must not claim a held udp port")
	}
	if !strings.Contains(err.Error(), "already claimed by another auth token") ||
		!strings.Contains(err.Error(), strconv.Itoa(port)) || !strings.Contains(err.Error(), "udp") {
		t.Fatalf("refusal must name the space and the port, got: %v", err)
	}
	if got := reg.HeldBy(msg.ProtoUDP, port); got != "bob" {
		t.Fatalf("the refused claim must not disturb the udp holder, got %q", got)
	}

	// Refcounting stays per space too: releasing the tcp claim must not
	// disturb the udp one.
	reg.Release(msg.ProtoTCP, port, "alice")
	if got := reg.HeldBy(msg.ProtoTCP, port); got != "" {
		t.Fatalf("the tcp claim must be released, got %q", got)
	}
	if got := reg.HeldBy(msg.ProtoUDP, port); got != "bob" {
		t.Fatalf("releasing the tcp claim must not disturb the udp claim, got %q", got)
	}
}

// TestPortClaimRefusesQuicListener covers the udp space's own listener: the
// QUIC proxy listener (SPEC cluster 7) is the one UDP socket the server
// holds, so a udp tunnel reaching for its port number is refused by name --
// while the same number stays claimable in the tcp space, where nothing of
// ours listens on it.
func TestPortClaimRefusesQuicListener(t *testing.T) {
	setupPortClaims(t)

	// The global records the real listener startQuicListener bound; save and
	// restore it so a test that started one never leaks its port into
	// another test's collision checks.
	prev := quicListener.Load()
	t.Cleanup(func() { quicListener.Store(prev) })

	ql := quicTestListener(t)
	port := ql.Addr().(*net.UDPAddr).Port

	err := portClaims.Claim(msg.ProtoUDP, port, "alice")
	if err == nil {
		t.Fatal("claiming the QUIC listener's port for a udp tunnel must be refused")
	}
	if !strings.Contains(err.Error(), "QUIC proxy listener") {
		t.Fatalf("refusal must name the QUIC listener, got: %v", err)
	}

	// The listener is a UDP socket; the tcp space does not see it.
	if err := portClaims.Claim(msg.ProtoTCP, port, "alice"); err != nil {
		t.Fatalf("the QUIC listener's port number must stay free in the tcp space: %v", err)
	}
}
