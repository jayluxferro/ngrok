package msg

// The shared timing vocabulary (UdpIdleTimeout, CarrierKeepAlive,
// CarrierIdleTimeout) is agreement between the two binaries, and this test is
// where the agreement is written down: the values are pinned here, and the
// usage sites -- the per-end constants that derive from them -- are named so
// that the next reader can finish the unification rather than re-spell a
// duration.
//
// State of the unification:
//
//   - client/model.go derives all three of its values from these constants
//     (udpIdleTimeout's default, carrierKeepAlivePeriod, carrierMaxIdleTimeout).
//     client/wire_consistency_test.go re-pins that derivation, so a literal
//     creeping back in fails there.
//   - server/udp.go and server/quic.go still hold literals (the files belong
//     to another workstream; the constants were added from the client side).
//     When that workstream unifies them, update the references below (line
//     numbers as of this writing; the symbols, not the lines, are the anchor):
//
//	server/udp.go:105  defaultUdpIdleTimeout = 30 * time.Second  -> msg.UdpIdleTimeout
//	server/quic.go:56  quicKeepAlivePeriod   = 10 * time.Second  -> msg.CarrierKeepAlive
//	server/quic.go:57  quicMaxIdleTimeout    = 30 * time.Second  -> msg.CarrierIdleTimeout
//
// A value change is therefore a two-file change minimum -- here and the
// deriving site(s) -- and never a silent one-end drift.

import (
	"testing"
	"time"
)

func TestSharedTimeoutValues(t *testing.T) {
	// UdpIdleTimeout (SPEC-CLUSTER8 3.2): how long a udp flow may sit silent
	// before either end closes it. Both ends expiring on the same clock is
	// what makes a dead flow's teardown symmetric.
	if UdpIdleTimeout != 30*time.Second {
		t.Fatalf("UdpIdleTimeout = %v, want 30s (server/udp.go defaultUdpIdleTimeout and client/model.go udpIdleTimeout must move with it)", UdpIdleTimeout)
	}

	// CarrierKeepAlive (SPEC-CLUSTER7 5): the session-keeping ping interval
	// both mux carriers run. It is the load-bearing half: it converts a
	// silently vanished peer into a dead session.
	if CarrierKeepAlive != 10*time.Second {
		t.Fatalf("CarrierKeepAlive = %v, want 10s (server/quic.go quicKeepAlivePeriod and client/model.go carrierKeepAlivePeriod must move with it)", CarrierKeepAlive)
	}

	// CarrierIdleTimeout (SPEC-CLUSTER7 5): how much total silence -- the
	// keepalives included -- ends a carrier session. It must stay longer than
	// CarrierKeepAlive or every keepalive would arrive at a dead session.
	if CarrierIdleTimeout != 30*time.Second {
		t.Fatalf("CarrierIdleTimeout = %v, want 30s (server/quic.go quicMaxIdleTimeout and client/model.go carrierMaxIdleTimeout must move with it)", CarrierIdleTimeout)
	}

	if CarrierIdleTimeout <= CarrierKeepAlive {
		t.Fatalf("CarrierIdleTimeout (%v) must exceed CarrierKeepAlive (%v): the keepalive must be answerable within the idle window", CarrierIdleTimeout, CarrierKeepAlive)
	}
}
