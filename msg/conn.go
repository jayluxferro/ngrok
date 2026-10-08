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

	// httpAuthFieldName is ReqTunnel.HttpAuth's JSON name: a base64
	// "user:password" the httpauth feature sends in the clear of its own
	// message. It was crossing the Debug wire log unredacted since before
	// vaults existed -- closed here, beside the fields that joined it in
	// needing it.
	httpAuthFieldName = `"HttpAuth"`

	// oidcSecretFieldName is the oidc action's "client_secret" (SPEC-CLUSTER18):
	// a *string* policy field, so it serializes outside the credential-array
	// redaction below and would cross both DEBUG wire logs in plaintext -- the
	// webhook e2e sentinel's exact class of leak, one field name over. It is
	// the one policy credential that must travel the wire (as its vault
	// reference, or inline when written inline); what must not travel is the
	// DEBUG log's copy of it.
	oidcSecretFieldName = `"client_secret"`
)

// policyCredentialFieldNames are the JSON field names of a traffic policy's
// credential lists -- credentials (basic-auth), tokens (bearer-auth), keys
// (apikey-auth), policy/auth_actions.go's credentialList fields. No wire
// message declares a field by these names: the only place they appear on the
// wire is inside ReqTunnel's TrafficPolicy, where each is an array of strings.
// Inline plaintext and vault-sourced credentials are indistinguishable here
// and both must be hidden (SPEC-CLUSTER9 3.3): the redaction is by field
// name, so it does not care which source filled the array.
var policyCredentialFieldNames = []string{`"credentials"`, `"tokens"`, `"keys"`,
	// "secrets" is webhook-verification's signing-key list (SPEC 10): the
	// same class of credential as the auth actions' lists -- an HMAC key is
	// if anything more sensitive, it forges signatures -- and it joined the
	// wire after the original three, crossing both DEBUG logs in plaintext
	// until the webhook e2e's sentinel scenario caught it.
	`"secrets"`}

// redactSecrets returns the bytes to log for a serialized message: the same
// bytes with the value of every "Secret" field replaced by a placeholder, and
// the elements of every serialized policy credential list replaced with it too.
//
// The two Debug calls in this file are the only places a whole wire message is
// written out, and a wire message carries the session secret (Auth, AuthResp,
// RegProxy, RegMux). Logging it verbatim turns the log into a credential store:
// the log file, the log shipper and whatever aggregates them each end up
// holding a bearer proof that attaches to a *live* session, kept far longer
// than the session itself and readable by everyone who can read logs. A
// tunnel's registration carries its traffic policy, and a policy's credential
// lists are credentials in exactly that sense -- long-lived bearer proofs for
// an endpoint rather than a session -- so they are hidden by the same
// mechanism, regardless of whether they were written inline or resolved from a
// vault.
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
	out, redacted := redactStringField(buffer, secretFieldName)
	if auth, authRedacted := redactStringField(out, httpAuthFieldName); authRedacted {
		out, redacted = auth, true
	}
	if cs, csRedacted := redactStringField(out, oidcSecretFieldName); csRedacted {
		out, redacted = cs, true
	}
	if creds, credRedacted := redactCredentialFields(out); credRedacted {
		return creds
	}
	if redacted {
		return out
	}
	return buffer
}

// redactStringField is the "Secret" scan: every occurrence of one JSON field
// name has its string value replaced by the placeholder. It reports whether it
// redacted anything; the buffer it returns is the caller's own bytes when it
// redacted nothing, so the no-match fast path of redactSecrets stays
// copy-free.
func redactStringField(buffer []byte, field string) ([]byte, bool) {
	name := []byte(field)
	out := make([]byte, 0, len(buffer))
	rest := buffer
	redacted := false

	for {
		i := bytes.Index(rest, name)
		if i < 0 {
			break
		}

		// field name, optional space, colon, optional space, opening quote;
		// anything else is not this field, so keep the bytes and scan on
		j := i + len(name)
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
		return buffer, false
	}
	return append(out, rest...), true
}

// redactCredentialFields redacts every element of every serialized policy
// credential list, one field name at a time. The lists are independent, so a
// pass that finds nothing costs a scan of bytes this function already runs on
// only when DEBUG logging is on -- and a buffer whose arrays do not parse as
// flat string lists is left exactly as this function found it, on the same
// reasoning the "Secret" scan has: guessing where a malformed value ended is
// a worse failure than leaving a line of a malformed message in a debug log.
func redactCredentialFields(buffer []byte) ([]byte, bool) {
	redacted := false
	for _, name := range policyCredentialFieldNames {
		var r bool
		buffer, r = redactCredentialArray(buffer, name)
		redacted = redacted || r
	}
	return buffer, redacted
}

// redactCredentialArray rewrites one credential list in place: each non-empty
// string element of the named field's array is replaced by the placeholder,
// so the log line stays a decodable message with the list's arity -- and
// stops being a credential store.
func redactCredentialArray(buffer []byte, field string) ([]byte, bool) {
	name := []byte(field)
	out := make([]byte, 0, len(buffer))
	rest := buffer
	redacted := false

scan:
	for {
		i := bytes.Index(rest, name)
		if i < 0 {
			break
		}

		// field name, optional space, colon, optional space, opening bracket;
		// anything else is not this field, so keep the bytes and scan on
		j := i + len(name)
		for j < len(rest) && rest[j] == ' ' {
			j++
		}
		if j < len(rest) && rest[j] == ':' {
			j++
			for j < len(rest) && rest[j] == ' ' {
				j++
			}
		}
		if j >= len(rest) || rest[j] != '[' {
			out = append(out, rest[:j]...)
			rest = rest[j:]
			continue
		}

		// the value is the array: copy through the opening bracket, then walk
		// one element at a time, keeping every byte that is not a redacted
		// value -- what remains logged must be the message, not a paraphrase
		out = append(out, rest[:j+1]...)
		rest = rest[j+1:]

		for {
			space, after := splitJSONSpace(rest)
			out = append(out, space...)
			rest = after
			if len(rest) == 0 {
				return buffer, false
			}
			if rest[0] == ']' {
				out = append(out, ']')
				rest = rest[1:]
				continue scan
			}
			if rest[0] != '"' {
				// not a string element: no valid policy produces this shape
				return buffer, false
			}

			// the element string, with escapes skipped as above
			end := 1
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
				return buffer, false
			}
			if end > 1 {
				out = append(out, redactedSecret...)
				redacted = true
			} else {
				// "" stays: an empty credential list entry is refused at
				// load, so an empty element is diagnostics, not a secret
				out = append(out, rest[:2]...)
			}
			rest = rest[end+1:]

			// after an element: a comma (next element) or the closing bracket
			space, after = splitJSONSpace(rest)
			out = append(out, space...)
			rest = after
			if len(rest) == 0 {
				return buffer, false
			}
			switch rest[0] {
			case ',':
				out = append(out, ',')
				rest = rest[1:]
			case ']':
				out = append(out, ']')
				rest = rest[1:]
				continue scan
			default:
				return buffer, false
			}
		}
	}

	if !redacted {
		return buffer, false
	}
	return append(out, rest...), true
}

// splitJSONSpace splits off the whitespace JSON allows between tokens, so the
// scanner can keep it (the bytes around a redacted value are not the value).
func splitJSONSpace(rest []byte) (space, after []byte) {
	k := 0
	for k < len(rest) {
		switch rest[k] {
		case ' ', '\t', '\n', '\r':
			k++
		default:
			return rest[:k], rest[k:]
		}
	}
	return rest, rest[len(rest):]
}
