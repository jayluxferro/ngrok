package proto

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"ngrok/conn"
)

// Udp is the udp tunnel protocol (SPEC-CLUSTER8 3.2): the identity protocol
// tcp is, for the same reason and with one difference in what identity means.
// A tcp tunnel's bytes are the payload; a udp tunnel's proxy leg carries
// length-framed datagrams (the framing below), so the *payload* this protocol
// promises to leave untouched is the datagram stream inside the frames -- the
// frames themselves are transport, added and removed on the way through, the
// way msg framing is on the control channel. WrapConn therefore still returns
// the conn unchanged: the framing is applied by the pumps that read and write
// the conn, not by a wrapper around it, because a wrapper that re-frames on
// arbitrary write boundaries is exactly the coalescing/splitting behavior the
// framing exists to prevent (SPEC-CLUSTER8 6.3).
type Udp struct{}

func NewUdp() *Udp {
	return new(Udp)
}

func (h *Udp) GetName() string { return "udp" }

func (h *Udp) WrapConn(c conn.Conn, ctx interface{}) conn.Conn {
	return c
}

// MaxDatagramSize is the largest single datagram the proxy leg will carry:
// 65507 is the largest payload a UDP datagram can have on IPv4 (65535 bytes
// of IP packet, less the 20-byte IP and 8-byte UDP headers), so the limit is
// not a policy of this protocol -- it is the largest datagram any sender could
// have produced. A length field beyond it cannot be a datagram anyone sent;
// it is a desynchronization or a broken peer, and the reader refuses it as a
// protocol error rather than trying to reframe the stream.
const MaxDatagramSize = 65507

// ErrDatagramTooLarge is returned by ReadDatagramFrame when the length field
// it read exceeds MaxDatagramSize. Callers close the flow on it -- there is no
// way to resynchronize a stream that has lost its frame boundary -- but it is
// a distinct value so the log can say "the peer is wrong" rather than "the
// connection ended".
var ErrDatagramTooLarge = errors.New("datagram length field exceeds the framing limit")

// The wire format (SPEC-CLUSTER8 3.1/3.2) is one the server and the client
// each implement against this shape: every datagram travels the stream-backed
// proxy leg as a 4-byte big-endian length prefix followed by exactly that many
// payload bytes, in both directions. Two Writes per frame rather than one
// concatenated buffer: it saves an allocation of up to 64 KiB per datagram,
// and a stream does not care where the write boundaries fall -- only the
// reader's counting does, and the reader below counts bytes, not writes.
func writeDatagramHeader(w io.Writer, length int) error {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(length))
	_, err := w.Write(hdr[:])
	return err
}

// WriteDatagramFrame writes one framed datagram. A payload larger than
// MaxDatagramSize is refused here rather than at the far end's reader: the
// writer knows the frame it is about to produce is one no conforming reader
// will ever accept, and saying so at the write site names the local caller
// instead of a peer that would only see a protocol error.
func WriteDatagramFrame(w io.Writer, payload []byte) error {
	if len(payload) > MaxDatagramSize {
		return fmt.Errorf("%d-byte datagram exceeds the %d-byte framing limit", len(payload), MaxDatagramSize)
	}
	if err := writeDatagramHeader(w, len(payload)); err != nil {
		return err
	}
	if len(payload) == 0 {
		// An empty datagram is legal UDP; writing the zero-length payload
		// after its header would be a no-op call on some writers and a
		// spurious one on others, so it is skipped rather than trusted.
		return nil
	}
	_, err := w.Write(payload)
	return err
}

// ReadDatagramFrame reads one framed datagram into buf and returns its
// payload length. The frame boundary is the datagram boundary: whatever else
// follows in the stream is left for the next call, which is what makes this
// codec's tests able to pin boundary preservation (SPEC-CLUSTER8 6.3).
//
// buf must be at least MaxDatagramSize for the reader to be able to accept
// every frame a conforming peer can write; a well-formed frame that does not
// fit the buffer given is reported as an error (and closes the caller's flow,
// like every other read error) rather than being silently truncated -- a
// truncated datagram delivered as a short one would corrupt the datagram
// semantics the tunnel exists to preserve.
func ReadDatagramFrame(r io.Reader, buf []byte) (int, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, err
	}

	length := binary.BigEndian.Uint32(hdr[:])
	if length > MaxDatagramSize {
		// Not a datagram anyone could have sent: refuse the stream. io is not
		// consulted further -- the flow is over -- so nothing is drained here.
		return 0, fmt.Errorf("%w: %d bytes, limit is %d", ErrDatagramTooLarge, length, MaxDatagramSize)
	}
	if int(length) > len(buf) {
		return 0, fmt.Errorf("%d-byte datagram does not fit the %d-byte read buffer", length, len(buf))
	}
	if _, err := io.ReadFull(r, buf[:length]); err != nil {
		return 0, err
	}

	return int(length), nil
}
