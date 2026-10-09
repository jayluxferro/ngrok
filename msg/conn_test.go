package msg

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

type testConn struct {
	net.Conn
}

func (c *testConn) AddLogPrefix(string)          {}
func (c *testConn) SetLogPrefixes(...string)     {}
func (c *testConn) Debug(string, ...interface{}) {}
func (c *testConn) Info(string, ...interface{})  {}
func (c *testConn) Warn(string, ...interface{}) error {
	return nil
}
func (c *testConn) Error(string, ...interface{}) error {
	return nil
}
func (c *testConn) Id() string       { return "test" }
func (c *testConn) SetType(string)   {}
func (c *testConn) CloseRead() error { return nil }

// recordingConn is a conn.Conn whose Debug output the test can read back.
// Only Write and Read are overridden; the rest of net.Conn is promoted and
// never called on this side of these tests.
type recordingConn struct {
	net.Conn
	logged []string
}

func (c *recordingConn) AddLogPrefix(string)         {}
func (c *recordingConn) SetLogPrefixes(...string)    {}
func (c *recordingConn) Info(string, ...interface{}) {}
func (c *recordingConn) Id() string                  { return "test" }
func (c *recordingConn) SetType(string)              {}
func (c *recordingConn) CloseRead() error            { return nil }
func (c *recordingConn) Warn(string, ...interface{}) error {
	return nil
}
func (c *recordingConn) Error(string, ...interface{}) error { return nil }
func (c *recordingConn) Debug(format string, args ...interface{}) {
	c.logged = append(c.logged, fmt.Sprintf(format, args...))
}

func (c *recordingConn) log() string { return strings.Join(c.logged, "\n") }

func TestReadMsgRejectsLargeFrame(t *testing.T) {
	old := maxMessageSize
	SetMaxMessageSize(8)
	defer SetMaxMessageSize(old)

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	go func() {
		_ = binary.Write(client, binary.LittleEndian, int64(64))
		_ = client.SetDeadline(time.Now().Add(100 * time.Millisecond))
		_ = client.Close()
	}()

	_, err := ReadMsg(&testConn{Conn: server})
	if err == nil {
		t.Fatalf("expected oversized frame to fail")
	}
}

// The session secret is a bearer token for a live session: it must go over the
// wire and nowhere else. Both directions are checked against the real entry
// points (WriteMsg/ReadMsgInto), because the property belongs to them, not to
// redactSecrets: a call site that skips the redaction is the failure mode.
func TestSessionSecretIsSentButNotLogged(t *testing.T) {
	secret := strings.Repeat("0f", 32)

	t.Run("writing", func(t *testing.T) {
		server, client := net.Pipe()
		defer server.Close()
		defer client.Close()

		framed := make(chan []byte, 1)
		go func() {
			buffer, err := readMsgShared(&testConn{Conn: client})
			if err != nil {
				t.Errorf("the framed message could not be read back: %v", err)
			}
			framed <- buffer
		}()

		logged := &recordingConn{Conn: server}
		if err := WriteMsg(logged, &Auth{ClientId: "client-1", Secret: secret}); err != nil {
			t.Fatalf("WriteMsg failed: %v", err)
		}
		wire := <-framed

		if !bytes.Contains(wire, []byte(secret)) {
			t.Fatal("the secret did not reach the wire: the client cannot authenticate")
		}
		if strings.Contains(logged.log(), secret) {
			t.Fatalf("the secret was logged:\n%s", logged.log())
		}
		if !strings.Contains(logged.log(), "<redacted>") {
			t.Fatalf("nothing was redacted from the log line:\n%s", logged.log())
		}
		// redaction must not cost the log line its other evidence: the message
		// type is what makes the line worth having
		if !strings.Contains(logged.log(), `"Type":"Auth"`) {
			t.Fatalf("the logged line no longer identifies the message:\n%s", logged.log())
		}
	})

	t.Run("reading", func(t *testing.T) {
		server, client := net.Pipe()
		defer server.Close()
		defer client.Close()

		go func() {
			buffer, err := Pack(&AuthResp{ClientId: "client-1", Secret: secret})
			if err != nil {
				t.Errorf("failed to pack the message: %v", err)
				return
			}
			if err := binary.Write(client, binary.LittleEndian, int64(len(buffer))); err != nil {
				t.Errorf("failed to write the frame: %v", err)
				return
			}
			if _, err := client.Write(buffer); err != nil {
				t.Errorf("failed to write the payload: %v", err)
			}
		}()

		logged := &recordingConn{Conn: server}
		var got AuthResp
		if err := ReadMsgInto(logged, &got); err != nil {
			t.Fatalf("ReadMsgInto failed: %v", err)
		}

		if got.Secret != secret {
			t.Fatalf("the secret did not survive the read: got %q", got.Secret)
		}
		if strings.Contains(logged.log(), secret) {
			t.Fatalf("the secret was logged:\n%s", logged.log())
		}
	})
}

// TestRedactSecrets pins what the redaction does and does not touch, including
// the cases that are easy to get wrong: a value that merely contains the field
// name, a value that has been escaped, an empty value, and the promise that a
// message without a secret is returned without being copied.
func TestRedactSecrets(t *testing.T) {
	const secret = "9c1f"

	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "the field is redacted",
			in:   `{"Type":"Auth","Payload":{"ClientId":"c1","Secret":"` + secret + `"}}`,
			want: `{"Type":"Auth","Payload":{"ClientId":"c1","Secret":"<redacted>"}}`,
		},
		{
			name: "every occurrence is redacted",
			in:   `{"Secret":"` + secret + `","Nested":{"Secret":"` + secret + `"}}`,
			want: `{"Secret":"<redacted>","Nested":{"Secret":"<redacted>"}}`,
		},
		{
			name: "an empty value stays empty",
			in:   `{"Secret":""}`,
			want: `{"Secret":""}`,
		},
		{
			name: "spaces around the colon are tolerated",
			in:   `{"Secret" : "` + secret + `"}`,
			want: `{"Secret" : "<redacted>"}`,
		},
		{
			name: "a value that contains the field name is not a field",
			in:   `{"Hostname":"x.internal","Note":"\"Secret\":\"not-a-secret\""}`,
			want: `{"Hostname":"x.internal","Note":"\"Secret\":\"not-a-secret\""}`,
		},
		{
			name: "an escaped quote does not end the value",
			in:   `{"Secret":"a\"b"}`,
			want: `{"Secret":"<redacted>"}`,
		},
		{
			name: "an unterminated value is left alone",
			in:   `{"Secret":"` + secret,
			want: `{"Secret":"` + secret,
		},
		{
			name: "the field name alone redacts nothing",
			in:   `{"Note":"Secret"}`,
			want: `{"Note":"Secret"}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := redactSecrets([]byte(tc.in))
			if string(got) != tc.want {
				t.Fatalf("redactSecrets(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}

	t.Run("a message with nothing to redact is returned as it is", func(t *testing.T) {
		in := []byte(`{"Type":"Ping","Payload":{}}`)
		got := redactSecrets(in)
		if &got[0] != &in[0] {
			t.Fatal("a message without a secret was copied: this runs on every message")
		}
	})

	// the whole point of redacting rather than dropping the message: the log
	// line is still a decodable message, minus the one field that must not be
	// in it
	t.Run("a redacted message is still the message", func(t *testing.T) {
		secret := strings.Repeat("ab", 32)
		buffer, err := Pack(&AuthResp{ClientId: "client-1", Error: "refused", Secret: secret})
		if err != nil {
			t.Fatalf("failed to pack the message: %v", err)
		}

		redacted := redactSecrets(buffer)
		if bytes.Contains(redacted, []byte(secret)) {
			t.Fatalf("the secret survived the redaction: %s", redacted)
		}

		var got AuthResp
		if err := UnpackInto(redacted, &got); err != nil {
			t.Fatalf("the redacted message no longer decodes (%v): %s", err, redacted)
		}
		if got.Secret != "<redacted>" {
			t.Fatalf("Secret = %q, want the placeholder", got.Secret)
		}
		if got.ClientId != "client-1" || got.Error != "refused" {
			t.Fatalf("the redaction changed the rest of the message: %+v", got)
		}
	})
}
