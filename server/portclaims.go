package server

// Ownership registry for fixed public ports, per protocol (SPEC-CLUSTER5 4.1;
// the protocol dimension is SPEC-CLUSTER8 §3.1).
//
// A tcp tunnel that asks for a specific remote port used to rely on the
// kernel's EADDRINUSE to keep the port to itself. That protects the *listener*
// while it exists, and nothing else: between one owner's tunnel closing and
// rebinding, the port is free for whoever asks first, and the second binder --
// not the account that had the port -- wins it. This registry closes that
// window by making the claim independent of the bind: a port is owned by an
// account from the moment its tunnel registers until that tunnel tears down,
// the same ownership rule the URL buckets in server/registry.go enforce for
// names, applied to numbers.
//
// PROTOCOL DIMENSION (SPEC-CLUSTER8 §3.1). TCP and UDP port spaces are
// independent: the kernel itself keeps them apart -- a TCP listener on 5000
// and a UDP socket on 5000 are different sockets with no namespace in
// common -- so the registry keys its claims on (proto, port) and udp:5000
// never fights tcp:5000. Within one protocol space the old rules are
// unchanged, byte for byte: one owner, refcounted holds, cross-owner refusal.
//
// The ownership question is the same one Register answers for urls: who may
// hold this public name, and what happens when someone else reaches for it.
// The refusal style is mirrored from there too -- the error names the port and
// the fact of the other owner, and says nothing about the other owner beyond
// that.

import (
	"fmt"
	"net"
	"ngrok/log"
	"ngrok/msg"
	"strconv"
	"strings"
	"sync"
)

// portClaimKey is one claim's coordinates: the protocol space and the port
// within it. The protocol is the wire vocabulary spelling (msg.ProtoTCP,
// msg.ProtoUDP), which is what the claim paths pass.
type portClaimKey struct {
	proto string
	port  int
}

// portClaim is one port's current holder: the account that claimed it and how
// many of that account's live tunnels hold it. The refcount exists because a
// single account can legitimately have several tunnels on one port -- pooling
// members all name the same remote port -- and the port must stay claimed
// until the LAST of them goes, not the first.
type portClaim struct {
	owner string
	refs  int
}

// portClaimRegistry maps a (protocol, port) pair to its claim. One mutex
// guards the whole map: the operations are single map lookups (claim,
// release), so a per-port lock would buy nothing and the registry lock keeps
// claim-release-claim sequences visibly atomic.
type portClaimRegistry struct {
	sync.Mutex
	claims map[portClaimKey]*portClaim
}

// portClaims is the process-wide registry. Like tunnelRegistry it is installed
// by Main and replaced by tests (setupTestRegistry).
var portClaims = newPortClaimRegistry()

func newPortClaimRegistry() *portClaimRegistry {
	return &portClaimRegistry{claims: make(map[portClaimKey]*portClaim)}
}

// Claim records owner's hold on the given protocol's port, or refuses it.
//
// The outcomes, in the order they are decided:
//
//   - the port carries one of the server's own listeners in this protocol's
//     space (public http/https and control/proxy for tcp; the QUIC proxy
//     listener for udp) -> refused, with the listener named: a tunnel binding
//     where ngrokd itself listens would hijack or starve a fixed service, and
//     the raw bind error the kernel would eventually produce ("address
//     already in use") does not say who holds the port.
//   - unclaimed -> claimed (refs = 1).
//   - claimed by the same owner -> reclaimed: refs go up, the claim survives
//     the reconnect race where the new tunnel registers before the old one's
//     teardown releases, and the port never becomes free in between.
//   - claimed by another owner -> refused, with the port named. As with the
//     url buckets, the error says the port is taken and by "another auth
//     token", and nothing else about that token.
//
// Port 0 is never claimed: it is not a remote port any tunnel asked for, it is
// what the kernel hands back for a random bind.
func (p *portClaimRegistry) Claim(proto string, port int, owner string) error {
	if port == 0 {
		return nil
	}

	if what := p.ownListenerAt(proto, port); what != "" {
		return fmt.Errorf("remote %s port %d cannot be claimed: it is the server's own %s", proto, port, what)
	}

	p.Lock()
	defer p.Unlock()

	key := portClaimKey{proto: proto, port: port}
	if held := p.claims[key]; held != nil {
		if held.owner != owner {
			return fmt.Errorf("remote %s port %d already claimed by another auth token", proto, port)
		}
		// Same owner, again: a reconnect, a re-registration, or another
		// pooling member of the same port. The claim deepens; it is never
		// dropped and re-created, so there is no instant at which the port
		// looks free.
		held.refs++
		return nil
	}

	p.claims[key] = &portClaim{owner: owner, refs: 1}
	return nil
}

// Release drops one of owner's holds on the given protocol's port. When the
// last hold goes, the claim does too, and the port is free for the next
// account that asks.
//
// A release by an account that does not hold the port is ignored rather than
// an error: teardown paths run best-effort, and refusing to act on a foreign
// release is what keeps a misbehaving shutdown from dropping someone else's
// claim. The registry logs it loudly instead (the caller's logger is not
// available here; the tunnel's own Shutdown logs context around its release).
func (p *portClaimRegistry) Release(proto string, port int, owner string) {
	if port == 0 {
		return
	}

	p.Lock()
	defer p.Unlock()

	key := portClaimKey{proto: proto, port: port}
	held := p.claims[key]
	if held == nil {
		return
	}
	if held.owner != owner {
		log.Error("Refusing release of remote %s port %d by owner %s: claimed by %s", proto, port, owner, held.owner)
		return
	}

	held.refs--
	if held.refs <= 0 {
		delete(p.claims, key)
	}
}

// HeldBy reports the owner currently holding the given protocol's port, or
// "". It exists for tests and the admin surface; the claim path never
// consults it (it reads the map under its own lock).
func (p *portClaimRegistry) HeldBy(proto string, port int) string {
	p.Lock()
	defer p.Unlock()

	if held := p.claims[portClaimKey{proto: proto, port: port}]; held != nil {
		return held.owner
	}
	return ""
}

// ownListenerAt names the server's own listener bound to the given protocol's
// port, or "" when the port carries none in that protocol space.
//
// The listener set is read live from the process globals rather than
// snapshotted: listeners are installed by Main before any tunnel can register,
// so the answer cannot change underneath a registration, and tests install
// their own. Only the spaces that actually have server-owned sockets are
// consulted: tcp sees the listeners map (public http/https, the control/proxy
// listener) and the admin server; udp sees the QUIC proxy listener, the one
// UDP socket ngrokd itself can hold (SPEC cluster 7). The two spaces are
// deliberately independent -- the QUIC listener's port is free to a udp
// tunnel claim exactly as much as a tcp tunnel claim may take the http
// listener's port's number in the udp space, where nothing of ours listens.
//
// A port the server configured but could not bind is not here -- the maps key
// off the listeners that actually exist, which is the truth that matters: the
// collision this refuses is with a socket that is listening.
func (p *portClaimRegistry) ownListenerAt(proto string, port int) string {
	switch proto {
	case msg.ProtoTCP:
		for name, l := range listeners {
			if l == nil || l.Addr == nil {
				continue
			}
			if tcpAddr, ok := l.Addr.(*net.TCPAddr); ok && tcpAddr.Port == port {
				return listenerDisplayName(name)
			}
		}

		if opts != nil && opts.adminAddr != "" {
			if _, portStr, err := net.SplitHostPort(opts.adminAddr); err == nil {
				if adminPort, err := strconv.Atoi(portStr); err == nil && adminPort == port {
					return "admin server listener"
				}
			}
		}

	case msg.ProtoUDP:
		if addr := quicListenerAddr(); addr != nil && addr.Port == port {
			return "QUIC proxy listener"
		}
	}

	return ""
}

// listenerDisplayName turns a listeners-map key into the name an error shows
// an operator: the map's keys ("http", "https", "tunnel") are code spelling,
// the display names say what the listener serves.
func listenerDisplayName(key string) string {
	names := map[string]string{
		msg.ProtoHTTP:  "public http listener",
		msg.ProtoHTTPS: "public https listener",
		"tunnel":       "control/proxy (tunnel) listener",
	}
	if name, ok := names[key]; ok {
		return name
	}
	return strings.TrimSpace(key) + " listener"
}
