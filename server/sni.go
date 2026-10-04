package server

// SNI peek for the https listener (SPEC-CLUSTER5 5.2).
//
// Zero-knowledge TLS starts with a routing decision the server can only make
// before it terminates anything: on a connection that may belong to an
// agent-terminated endpoint, the one place the endpoint's name appears in the
// clear is the server_name extension of the TLS ClientHello. This file reads
// exactly that hello and nothing more, so the connection can then go two ways:
// replayed into the server's TLS terminator (edge-terminated endpoints,
// today's behavior), or joined to an agent as raw bytes the server never
// parses again (agent-terminated endpoints, where the plaintext does not exist
// on this side at all).
//
// The parser is bounded and total: every byte it accepts from the socket is
// returned to the caller, every loop has a hard bound, and every failure is an
// error rather than a guess. A parser that consumed bytes it did not return
// would silently eat the connection's first bytes; one that guessed at
// structure it did not verify would route on a name the real TLS handshake
// would not agree with.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Wire constants of the TLS record and handshake layers this parser walks.
// Only what a ClientHello needs is spelled; everything else is refused or
// skipped by length, never interpreted.
const (
	tlsRecordHeaderSize    = 5
	tlsHandshakeHeaderSize = 4

	// contentType 0x16: handshake. A ClientHello always arrives in handshake
	// records; any other content type before the hello is over means the
	// stream is not the opening of a TLS handshake.
	tlsRecordHandshake = 0x16

	// handshake type 0x01: ClientHello.
	tlsHandshakeClientHello = 0x01

	// extension type 0x0000: server_name (RFC 6066).
	tlsExtensionServerName = 0x0000

	// name_type 0 inside the server_name extension: a DNS hostname. This
	// parser reads only this type, as RFC 6066 reserves the list for a single
	// host_name entry today.
	tlsServerNameHostName = 0
)

var (
	// ErrSNIAbsent is returned when the ClientHello parsed cleanly but
	// carried no server_name extension. It is how the caller tells "this
	// client named no endpoint" (a normal event: IP-literal and some
	// legacy clients send no SNI) apart from "this stream is not something
	// we can route", which comes back as any other error. Both end in the
	// server-cert terminator; only the log line differs.
	ErrSNIAbsent = errors.New("client hello carries no server_name extension")

	// errNotTLS marks a stream whose opening bytes are not a TLS handshake
	// record at all -- plaintext sent to the TLS port, or a protocol this
	// server does not speak there.
	errNotTLS = errors.New("stream does not open with a TLS handshake record")

	// errSNIOversized marks a hello that will not fit in the peek budget.
	errSNIOversized = errors.New("client hello exceeds the SNI peek budget")
)

// clientHelloVectors lists the length-prefixed vectors a ClientHello carries
// in front of its extension block, in wire order, with the width of each
// vector's length prefix. Skipping them is table-driven on purpose (SPEC-CLUSTER5
// 8.5): the shapes a parser must survive are data, and a new TLS version that
// inserts a vector is an entry here rather than a new branch in the walk.
var clientHelloVectors = []struct {
	name   string
	prefix int // width of the length prefix, in bytes
}{
	{"session_id", 1},
	{"cipher_suites", 2},
	{"compression_methods", 1},
}

// readClientHelloSNI reads one ClientHello off r and returns the hostname its
// server_name extension carries, together with EVERY byte consumed from r --
// record headers and any trailing bytes that arrived in the same records
// included -- so the caller can put the connection back exactly as it found
// it. peeked is returned on error paths too: a caller that falls back to
// terminating the connection itself replays whatever was read, so the TLS
// terminator sees the stream the client actually sent and answers it with a
// real alert, rather than waiting for a hello that has already been eaten.
//
// The hello may arrive fragmented across any number of continuation records;
// the walk reassembles it from the 5-byte record framing. Malformed input --
// not a handshake record, not a ClientHello, truncated, or a hello longer than
// max bytes -- is an error, never a partial guess; a hello that parses but
// carries no server_name extension is ErrSNIAbsent, which is a success of the
// parser and a routing decision for the caller.
//
// max bounds the total number of bytes consumed from r. It is the same budget
// the http head parser uses (maxHeadBytes) for the same reason: the peek
// happens before the connection has been assigned a tunnel, so it must not be
// able to hold an unbounded amount of memory per connection.
func readClientHelloSNI(r io.Reader, max int) (sni string, peeked []byte, err error) {
	// Two views of the same bytes: peeked holds everything consumed from r,
	// headers included, for the replay; hs holds the concatenation of the
	// record bodies alone, which is the handshake message. They are not the
	// same stream -- each record carries its own 5-byte header, so once a
	// hello is fragmented across records the handshake is interleaved with
	// framing that must travel back to the TLS terminator but must not reach
	// the hello parser.
	var hs []byte
	var assembled bool
	for !assembled {
		var header [tlsRecordHeaderSize]byte
		if _, err = io.ReadFull(r, header[:]); err != nil {
			return "", peeked, fmt.Errorf("reading TLS record header: %w", err)
		}

		recType := header[0]
		recLen := int(binary.BigEndian.Uint16(header[3:5]))

		if recType != tlsRecordHandshake {
			return "", peeked, fmt.Errorf("%w: content type 0x%02x", errNotTLS, recType)
		}

		if len(peeked)+tlsRecordHeaderSize+recLen > max {
			return "", peeked, fmt.Errorf("%w: over %d bytes", errSNIOversized, max)
		}

		peeked = append(peeked, header[:]...)
		peeked = append(peeked, make([]byte, recLen)...)
		body := peeked[len(peeked)-recLen:]
		if _, err = io.ReadFull(r, body); err != nil {
			return "", peeked, fmt.Errorf("reading TLS record body: %w", err)
		}

		// Once the handshake header's 3-byte length is visible, the hello is
		// assembled when that many body bytes have arrived -- across as many
		// records as the peer needed.
		hs = append(hs, body...)
		if len(hs) < tlsHandshakeHeaderSize {
			continue
		}
		hsLen := handshakeLen(hs)
		assembled = len(hs) >= hsLen
	}

	hsLen := handshakeLen(hs)
	if hsLen > len(hs) {
		// Unreachable (the loop above only exits when this holds), but the
		// parse below slices by it and must not be told otherwise.
		return "", peeked, fmt.Errorf("client hello shorter (%d) than its header claims (%d)", len(hs), hsLen)
	}

	sni, err = parseClientHelloSNI(hs[:hsLen])
	return sni, peeked, err
}

// handshakeLen reads a handshake message's 4-byte header (type + 3-byte
// length) and returns the total message length, header included.
//
// The length field's three bytes are composed with shifts and ORs, and the
// parenthesization here is load-bearing, which a first draft of this parser
// got wrong: written as `4 + hs[1]<<16 | hs[2]<<8 | hs[3]`, Go's precedence
// makes the `+ 4` part of the first OR term -- `4 | hs[1]<<16` -- so a
// handshake whose low length byte has bit 2 clear came back four bytes
// short, and the parse then misread every offset after the truncation.
func handshakeLen(hs []byte) int {
	return tlsHandshakeHeaderSize + (int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3]))
}

// parseClientHelloSNI extracts the server_name from one assembled handshake
// message, which must be a ClientHello. It reads nothing it was not given.
func parseClientHelloSNI(hs []byte) (string, error) {
	if hs[0] != tlsHandshakeClientHello {
		return "", fmt.Errorf("first handshake message is type 0x%02x, not a ClientHello (0x%02x)", hs[0], tlsHandshakeClientHello)
	}

	c := &sniCursor{b: hs[tlsHandshakeHeaderSize:]}

	// legacy_version, then the fixed random, then the three vectors whose
	// shapes the table above carries.
	if _, err := c.take(2, "legacy_version"); err != nil {
		return "", err
	}
	if _, err := c.take(32, "random"); err != nil {
		return "", err
	}
	for _, v := range clientHelloVectors {
		n, err := c.take(v.prefix, v.name+" length")
		if err != nil {
			return "", err
		}
		if _, err := c.take(vectorLen(n, v.name), v.name); err != nil {
			return "", err
		}
	}

	// The extension block is optional; a hello without one has no SNI by
	// construction.
	if len(c.b) == 0 {
		return "", ErrSNIAbsent
	}
	extLen, err := c.u16("extension block length")
	if err != nil {
		return "", err
	}
	if extLen > len(c.b) {
		return "", fmt.Errorf("client hello extension block claims %d bytes, %d follow", extLen, len(c.b))
	}
	exts := c.b[:extLen]

	// Each extension: 2-byte type, 2-byte length, data. Everything that is
	// not the server_name extension is skipped by its own declared length --
	// TLS 1.3 hellos carry key_share, supported_versions, signature_algorithms
	// and friends here, and all of them must be stepped over, not parsed.
	for len(exts) > 0 {
		e := &sniCursor{b: exts}
		extType, err := e.u16("extension type")
		if err != nil {
			return "", err
		}
		dataLen, err := e.u16("extension length")
		if err != nil {
			return "", err
		}
		data, err := e.take(dataLen, "extension data")
		if err != nil {
			return "", err
		}
		exts = e.b

		if extType != tlsExtensionServerName {
			continue
		}
		return parseServerName(data)
	}

	return "", ErrSNIAbsent
}

// parseServerName reads the server_name extension's payload: a
// server_name_list whose entries are one name_type byte, a 2-byte length and
// the name. Only a non-empty host_name entry is an SNI; the extension is
// malformed when its list does not hold one, which RFC 6066 agrees with --
// the list is required to carry exactly this entry.
func parseServerName(data []byte) (string, error) {
	if len(data) < 2 {
		return "", fmt.Errorf("server_name extension is %d bytes, too short for a list length", len(data))
	}
	listLen := int(binary.BigEndian.Uint16(data))
	if 2+listLen > len(data) {
		return "", fmt.Errorf("server_name_list claims %d bytes, %d follow its length", listLen, len(data)-2)
	}
	list := data[2 : 2+listLen]

	for len(list) > 0 {
		nameType := list[0]
		list = list[1:]
		if len(list) < 2 {
			return "", fmt.Errorf("server_name_list entry truncated in its length field")
		}
		nameLen := int(binary.BigEndian.Uint16(list))
		list = list[2:]
		if nameLen > len(list) {
			return "", fmt.Errorf("server_name_list entry claims %d bytes, %d follow", nameLen, len(list))
		}
		name := list[:nameLen]
		list = list[nameLen:]

		if nameType != tlsServerNameHostName {
			continue
		}
		if nameLen == 0 {
			return "", fmt.Errorf("server_name_list carries an empty host_name")
		}
		return string(name), nil
	}

	return "", fmt.Errorf("server_name_list carries no host_name entry")
}

// vectorLen reads a vector's length prefix. Prefixes are unsigned and
// big-endian; 1 and 2 bytes are the only widths the wire uses, and anything
// else is a bug in the table above, so it panics rather than misparse.
func vectorLen(prefix []byte, what string) int {
	switch len(prefix) {
	case 1:
		return int(prefix[0])
	case 2:
		return int(binary.BigEndian.Uint16(prefix))
	}
	panic(fmt.Sprintf("client hello vector %s has a %d-byte length prefix; the wire only defines 1 and 2", what, len(prefix)))
}

// sniCursor is a bounds-checked reader over an assembled byte vector: every
// take either returns exactly n bytes or fails with an error naming what was
// being read. It is how the hello parse above stays total -- no slice
// expression in it can go out of range, because every one goes through here.
type sniCursor struct {
	b []byte
}

func (c *sniCursor) take(n int, what string) ([]byte, error) {
	if len(c.b) < n {
		return nil, fmt.Errorf("client hello truncated reading %s: need %d bytes, %d remain", what, n, len(c.b))
	}
	out := c.b[:n]
	c.b = c.b[n:]
	return out, nil
}

func (c *sniCursor) u16(what string) (int, error) {
	b, err := c.take(2, what)
	if err != nil {
		return 0, err
	}
	return int(binary.BigEndian.Uint16(b)), nil
}
