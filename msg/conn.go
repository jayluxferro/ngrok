package msg

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"ngrok/conn"
)

var maxMessageSize int64 = 4 * 1024 * 1024 // 4 MiB

func SetMaxMessageSize(size int64) {
	if size > 0 {
		maxMessageSize = size
	}
}

func readMsgShared(c conn.Conn) (buffer []byte, err error) {
	c.Debug("Waiting to read message")

	var sz int64
	err = binary.Read(c, binary.LittleEndian, &sz)
	if err != nil {
		return
	}
	c.Debug("Reading message with length: %d", sz)

	if sz <= 0 {
		return nil, fmt.Errorf("invalid message length: %d", sz)
	}
	if sz > maxMessageSize {
		return nil, fmt.Errorf("message length %d exceeds maximum %d", sz, maxMessageSize)
	}

	buffer = make([]byte, sz)
	n, err := io.ReadFull(c, buffer)
	c.Debug("Read message %s", redactSecrets(buffer))

	if err != nil {
		return
	}

	if int64(n) != sz {
		err = fmt.Errorf("expected to read %d bytes, but only read %d", sz, n)
		return
	}

	return
}

func ReadMsg(c conn.Conn) (msg Message, err error) {
	buffer, err := readMsgShared(c)
	if err != nil {
		return
	}

	return Unpack(buffer)
}

func ReadMsgInto(c conn.Conn, msg Message) (err error) {
	buffer, err := readMsgShared(c)
	if err != nil {
		return
	}
	return UnpackInto(buffer, msg)
}

func WriteMsg(c conn.Conn, msg interface{}) (err error) {
	buffer, err := Pack(msg)
	if err != nil {
		return
	}

	c.Debug("Writing message: %s", redactSecrets(buffer))
	err = binary.Write(c, binary.LittleEndian, int64(len(buffer)))

	if err != nil {
		return
	}

	if _, err = c.Write(buffer); err != nil {
		return
	}

	return nil
}

const (
	secretFieldName = `"Secret"`
	redactedSecret  = `"<redacted>"`
)

// redactSecrets returns the bytes to log for a serialized message: the same
// bytes with the value of every "Secret" field replaced by a placeholder.
//
// The two Debug calls in this file are the only places a whole wire message is
// written out, and a wire message carries the session secret (Auth, AuthResp,
// RegProxy, RegMux). Logging it verbatim turns the log into a credential store:
// the log file, the log shipper and whatever aggregates them each end up
// holding a bearer proof that attaches to a *live* session, kept far longer
// than the session itself and readable by everyone who can read logs.
//
// It works on the encoded bytes rather than on the struct because the read path
// never has the struct, and because doing it by name means a message type added
// later is covered without this function being told about it. The scan is
// deliberately literal about what it replaces:
//
//   - it matches the field name as JSON spells it, so a *value* that contains
//     the word Secret (a hostname, a policy field, a header) is not touched: a
//     quote inside a JSON string is escaped, so the bytes of such a value read
//     \"Secret\": and cannot match;
//   - an empty value is left alone, because "" is what a peer that sent no
//     secret sends, and telling that apart from a secret is the diagnostic the
//     refusal is about;
//   - a value with no closing quote ends the scan: the buffer is malformed (or
//     is not JSON at all), and guessing where the value ended is a worse
//     failure than leaving a line of a malformed message in a debug log.
//
// A message with nothing to redact is returned as-is, without copying: this
// runs on every message, and the fast path is the common one.
func redactSecrets(buffer []byte) []byte {
	out := make([]byte, 0, len(buffer))
	rest := buffer
	redacted := false

	for {
		i := bytes.Index(rest, []byte(secretFieldName))
		if i < 0 {
			break
		}

		// field name, optional space, colon, optional space, opening quote;
		// anything else is not this field, so keep the bytes and scan on
		j := i + len(secretFieldName)
		for j < len(rest) && rest[j] == ' ' {
			j++
		}
		if j < len(rest) && rest[j] == ':' {
			j++
			for j < len(rest) && rest[j] == ' ' {
				j++
			}
		}
		if j >= len(rest) || rest[j] != '"' {
			out = append(out, rest[:j]...)
			rest = rest[j:]
			continue
		}

		// the value string, with backslash escapes skipped so that an escaped
		// quote does not look like its end
		valueStart := j + 1
		end := valueStart
		for end < len(rest) {
			if rest[end] == '\\' {
				end += 2
				continue
			}
			if rest[end] == '"' {
				break
			}
			end++
		}
		if end >= len(rest) {
			break
		}

		if end == valueStart {
			// "" -- nothing to hide, and the quotes say so
			out = append(out, rest[:end]...)
			rest = rest[end:]
		} else {
			// everything up to the opening quote, then the placeholder --
			// quotes included -- in place of the value and both its quotes
			out = append(out, rest[:j]...)
			out = append(out, redactedSecret...)
			redacted = true
			rest = rest[end+1:]
		}
	}

	if !redacted {
		return buffer
	}
	return append(out, rest...)
}
