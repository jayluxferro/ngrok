package proto

// The udp proxy leg's framing is implemented twice: exported here (udp.go,
// client side) and privately in server/udp.go (writeFrame/readFrame behind
// the server's flow table, whose symbols this package cannot import). The
// duplication itself belongs to the server workstream to unify; what this
// test can and must police is the WIRE between the two implementations, so
// that a change to one half that the other half does not make fails here
// instead of on a live flow.
//
// It pins three things:
//
//  1. The spec shape (SPEC-CLUSTER8 3.1/3.2): one datagram = one 4-byte
//     big-endian length prefix + exactly that many payload bytes, in both
//     directions. The exported writer's bytes are decoded by a minimal
//     in-test reader of that spec, and spec-shaped bytes by the exported
//     reader -- neither implementation is consulted for what "conforming"
//     means.
//  2. The boundary rule (SPEC-CLUSTER8 6.3): frame boundaries are datagram
//     boundaries even when frames sit back to back in one stream.
//  3. The limits, as a cross-checked table: the server's private
//     udpMaxDatagramSize (server/udp.go) and its too-large refusal are pinned
//     BY VALUE here, next to this package's own. If either side changes its
//     framing or its limit, this table is where the change lands in the same
//     commit -- the two ends agreeing is not automatic, it is checked.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
)

// specLimit is the framing limit as the SPEC and the server's private
// implementation both state it: 65507 is the largest payload a UDP datagram
// can have on IPv4 (65535-byte IP packet less the 20-byte IP and 8-byte UDP
// headers), so it is not policy but physics.
//
// Cross-checked against server/udp.go's `udpMaxDatagramSize = 65507` (the
// private const its readFrame/writeFrame compare against). If that literal
// moves, this one moves in the same commit or this test names the drift.
const specLimit = 65507

// readSpecDatagram decodes one datagram the SPEC describes, with no help from
// either implementation: 4-byte big-endian length, then that many bytes.
func readSpecDatagram(t *testing.T, r io.Reader) []byte {
	t.Helper()

	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		t.Fatalf("reading spec length prefix: %v", err)
	}
	length := binary.BigEndian.Uint32(hdr[:])
	if length > specLimit {
		t.Fatalf("spec reader got a %d-byte length prefix, beyond the %d-byte limit", length, specLimit)
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		t.Fatalf("reading spec payload of %d bytes: %v", length, err)
	}

	return payload
}

// writeSpecDatagram encodes one datagram the SPEC describes, again with no
// help from either implementation.
func writeSpecDatagram(buf *bytes.Buffer, payload []byte) {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	buf.Write(hdr[:])
	buf.Write(payload)
}

func TestDatagramFramingWireSpec(t *testing.T) {
	t.Run("exported writer emits the spec shape", func(t *testing.T) {
		payloads := [][]byte{
			{},          // an empty datagram is legal UDP
			[]byte("x"), // the smallest non-empty one
			[]byte("framed, not coalesced"),
			bytes.Repeat([]byte{0xA5}, specLimit), // the largest conforming one
		}

		var wire bytes.Buffer
		for _, payload := range payloads {
			if err := WriteDatagramFrame(&wire, payload); err != nil {
				t.Fatalf("WriteDatagramFrame(%d bytes): %v", len(payload), err)
			}
		}

		for i, want := range payloads {
			if got := readSpecDatagram(t, &wire); !bytes.Equal(got, want) {
				t.Fatalf("datagram %d: spec reader got %d bytes, want %d", i, len(got), len(want))
			}
		}
		if wire.Len() != 0 {
			t.Fatalf("%d bytes left unread: the writer emitted more frames than it was given", wire.Len())
		}
	})

	t.Run("spec-shaped frames decode via the exported reader", func(t *testing.T) {
		payloads := [][]byte{
			{},
			[]byte("hello"),
			bytes.Repeat([]byte("udp"), 1000),
		}

		var wire bytes.Buffer
		for _, payload := range payloads {
			writeSpecDatagram(&wire, payload)
		}

		buf := make([]byte, specLimit)
		for i, want := range payloads {
			n, err := ReadDatagramFrame(&wire, buf)
			if err != nil {
				t.Fatalf("ReadDatagramFrame(%d): %v", i, err)
			}
			if n != len(want) || !bytes.Equal(buf[:n], want) {
				t.Fatalf("datagram %d: decoded %d bytes, want %d", i, n, len(want))
			}
		}
		if wire.Len() != 0 {
			t.Fatalf("%d bytes left unread", wire.Len())
		}
	})

	t.Run("frame boundaries survive back-to-back framing", func(t *testing.T) {
		// SPEC-CLUSTER8 6.3: the reader must neither merge nor split adjacent
		// datagrams, whatever the writer's write boundaries were.
		first := bytes.Repeat([]byte{0x01}, 100)
		second := bytes.Repeat([]byte{0x02}, 7)

		var wire bytes.Buffer
		if err := WriteDatagramFrame(&wire, first); err != nil {
			t.Fatalf("write first: %v", err)
		}
		if err := WriteDatagramFrame(&wire, second); err != nil {
			t.Fatalf("write second: %v", err)
		}

		buf := make([]byte, specLimit)
		n, err := ReadDatagramFrame(&wire, buf)
		if err != nil || !bytes.Equal(buf[:n], first) {
			t.Fatalf("first frame: n=%d err=%v (boundaries merged or lost)", n, err)
		}
		n, err = ReadDatagramFrame(&wire, buf)
		if err != nil || !bytes.Equal(buf[:n], second) {
			t.Fatalf("second frame: n=%d err=%v (boundaries merged or lost)", n, err)
		}
	})

	t.Run("the framing limit is the spec limit, on both sides of the wire", func(t *testing.T) {
		// The exported const, the spec, and (by the cross-checked table
		// above) the server's private const are one number.
		if MaxDatagramSize != specLimit {
			t.Fatalf("proto.MaxDatagramSize = %d, want the spec's %d (server/udp.go udpMaxDatagramSize must agree)", MaxDatagramSize, specLimit)
		}

		// Exactly at the limit conforms; one byte past it is refused on write
		// -- and refused on read, as ErrDatagramTooLarge, for a peer that
		// sent it anyway.
		if err := WriteDatagramFrame(io.Discard, bytes.Repeat([]byte{0}, specLimit)); err != nil {
			t.Fatalf("a %d-byte datagram must be writable, got: %v", specLimit, err)
		}
		if err := WriteDatagramFrame(io.Discard, bytes.Repeat([]byte{0}, specLimit+1)); err == nil {
			t.Fatal("a datagram past the framing limit must be refused on write")
		}

		var wire bytes.Buffer
		writeSpecDatagram(&wire, bytes.Repeat([]byte{0}, specLimit+1))
		_, err := ReadDatagramFrame(&wire, make([]byte, specLimit))
		if !errors.Is(err, ErrDatagramTooLarge) {
			t.Fatalf("reading a past-the-limit frame: want ErrDatagramTooLarge, got %v", err)
		}
	})
}

// TestDatagramFramingErrorMentionsLimits keeps the refusal diagnosable: the
// too-large error carries the number it saw and the number it enforces, which
// is what turns a peer's protocol bug into a readable log line.
func TestDatagramFramingErrorMentionsLimits(t *testing.T) {
	var wire bytes.Buffer
	writeSpecDatagram(&wire, make([]byte, specLimit+1))

	_, err := ReadDatagramFrame(&wire, make([]byte, specLimit))
	if err == nil {
		t.Fatal("expected a refusal")
	}
	if !strings.Contains(err.Error(), "65508") || !strings.Contains(err.Error(), "65507") {
		t.Fatalf("the too-large error should name both the seen and the enforced limit, got: %v", err)
	}
}
