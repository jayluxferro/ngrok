package msg

// The wire redaction pin for the traffic policy's credential lists
// (SPEC-CLUSTER9 3.3 and review gate 2): a tunnel registration carries its
// policy, and a policy's credentials/tokens/keys arrays are credentials --
// whether they were written inline or resolved from a vault, which the wire
// cannot and must not distinguish. This file pins that the DEBUG output of
// the real write and read paths never contains their values, and that what
// remains is still the message.

import (
	"bytes"
	"encoding/json"
	"net"
	"strings"
	"testing"

	"ngrok/policy"
)

// vaultedPolicyDoc is a policy in the shape a vault-using config produces:
// the credential positions hold references (each side resolves them against
// its own vaults), and next to them a plain inline credential in the same
// list -- the wire redaction is by field name precisely because both forms
// must be hidden.
func vaultedPolicyDoc() *policy.TrafficPolicy {
	return &policy.TrafficPolicy{
		OnHTTPRequest: []*policy.Action{
			{
				Name: policy.ActionBasicAuth,
				Config: map[string]interface{}{
					"credentials": []interface{}{`secret("main/alice")`, "bob:inline-pass"},
				},
			},
			{
				Name: policy.ActionBearerAuth,
				Config: map[string]interface{}{
					"tokens": []interface{}{`secret("main/tok")`},
				},
			},
			{
				Name: policy.ActionAPIKeyAuth,
				Config: map[string]interface{}{
					"keys": []interface{}{"ak-live-0001"},
				},
			},
			{
				// a policy field that is not a credential position: the
				// redaction has no business touching it
				Name: policy.ActionAddHeaders,
				Config: map[string]interface{}{
					"headers": map[string]interface{}{"x-tag": "public-value"},
				},
			},
		},
	}
}

func TestPolicyCredentialsAreSentButNotLogged(t *testing.T) {
	const (
		inlineCred = "bob:inline-pass"
		inlineTok  = "ak-live-0001"
	)

	req := &ReqTunnel{
		ReqId:         "1",
		Protocol:      "http",
		Subdomain:     "vaulted",
		TrafficPolicy: vaultedPolicyDoc(),
	}

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
	if err := WriteMsg(logged, req); err != nil {
		t.Fatalf("WriteMsg failed: %v", err)
	}
	wire := <-framed

	// the policy reached the wire -- the server cannot compile what it never
	// received. The references carry escaped quotes in the JSON spelling.
	for _, mustSend := range []string{`secret(\"main/alice\")`, inlineCred, `secret(\"main/tok\")`, inlineTok} {
		if !bytes.Contains(wire, []byte(mustSend)) {
			t.Fatalf("credential material %q did not reach the wire: the endpoint would come up unenforced", mustSend)
		}
	}

	// and none of it is in the log line, in either spelling
	for _, mustHide := range []string{`secret(\"main/alice\")`, inlineCred, `secret(\"main/tok\")`, inlineTok} {
		if strings.Contains(logged.log(), mustHide) {
			t.Fatalf("credential material %q was logged:\n%s", mustHide, logged.log())
		}
	}
	if !strings.Contains(logged.log(), "<redacted>") {
		t.Fatalf("nothing was redacted from the log line:\n%s", logged.log())
	}

	// the server's read path is covered by the same function; assert it the
	// same way, from the frame the client sent
	redacted := redactSecrets(bytes.Clone(wire))
	for _, mustHide := range []string{`secret(\"main/alice\")`, inlineCred, `secret(\"main/tok\")`, inlineTok} {
		if bytes.Contains(redacted, []byte(mustHide)) {
			t.Fatalf("the read path would log credential material %q: %s", mustHide, redacted)
		}
	}

	// what is logged still decodes, with the lists' arity intact: the
	// redaction hides values, not the shape of the policy
	var got ReqTunnel
	if err := UnpackInto(redacted, &got); err != nil {
		t.Fatalf("the redacted message no longer decodes (%v): %s", err, redacted)
	}
	if got.Subdomain != "vaulted" || got.Protocol != "http" {
		t.Fatalf("the redaction changed the rest of the message: %+v", got)
	}
	cfg := got.TrafficPolicy.OnHTTPRequest[0].Config
	creds, ok := cfg["credentials"].([]interface{})
	if !ok || len(creds) != 2 {
		t.Fatalf("the credentials list did not survive as a two-element list: %#v", cfg["credentials"])
	}
	for i, v := range creds {
		if v != "<redacted>" {
			t.Fatalf("credentials[%d] = %q, want the placeholder", i, v)
		}
	}
	if hdr := got.TrafficPolicy.OnHTTPRequest[3].Config["headers"].(map[string]interface{})["x-tag"]; hdr != "public-value" {
		t.Fatalf("a non-credential policy field was redacted: %q", hdr)
	}
}

// TestRedactSecretsLeavesCredentialFreeMessagesAlone pins the fast path on a
// message that has a policy but no credential positions and no Secret: this
// runs on every message, and the common case must stay copy-free.
func TestRedactSecretsLeavesCredentialFreeMessagesAlone(t *testing.T) {
	buffer, err := Pack(&ReqTunnel{
		ReqId:    "1",
		Protocol: "http",
		TrafficPolicy: &policy.TrafficPolicy{
			OnHTTPRequest: []*policy.Action{{
				Name:   policy.ActionAddHeaders,
				Config: map[string]interface{}{"headers": map[string]interface{}{"x-tag": "v"}},
			}},
		},
	})
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	got := redactSecrets(buffer)
	if &got[0] != &buffer[0] {
		t.Fatal("a message with nothing to redact was copied")
	}
	if !bytes.Contains(got, []byte("x-tag")) {
		t.Fatalf("the message was altered: %s", got)
	}
}

// TestRedactCredentialArrayPinsTheScanner pins the array scanner's edge cases
// directly, the way TestRedactSecrets pins the string scanner: empty elements
// stay, whitespace spellings are tolerated, escaped quotes do not end an
// element, and a shape no valid policy produces is left entirely alone rather
// than half-guessed.
func TestRedactCredentialArrayPinsTheScanner(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "every element is redacted",
			in:   `{"credentials":["a","b"]}`,
			want: `{"credentials":["<redacted>","<redacted>"]}`,
		},
		{
			name: "an empty element stays",
			in:   `{"credentials":[""]}`,
			want: `{"credentials":[""]}`,
		},
		{
			name: "an empty array stays",
			in:   `{"credentials":[]}`,
			want: `{"credentials":[]}`,
		},
		{
			name: "spaces around the tokens are tolerated",
			in:   `{ "tokens" : [ "a" , "b" ] }`,
			want: `{ "tokens" : [ "<redacted>" , "<redacted>" ] }`,
		},
		{
			name: "an escaped quote does not end the element",
			in:   `{"keys":["a\"b"]}`,
			want: `{"keys":["<redacted>"]}`,
		},
		{
			name: "the array is not the last thing in the buffer",
			in:   `{"keys":["a"],"ReqId":"1"}`,
			want: `{"keys":["<redacted>"],"ReqId":"1"}`,
		},
		{
			name: "a non-string element is not guessed at",
			in:   `{"keys":[42],"ReqId":"1"}`,
			want: `{"keys":[42],"ReqId":"1"}`,
		},
		{
			name: "the field name as a value is not the field",
			in:   `{"Note":"\"tokens\":[\"a\"]"}`,
			want: `{"Note":"\"tokens\":[\"a\"]"}`,
		},
		{
			name: "a value that is not an array is not touched",
			in:   `{"credentials":"alice:pw"}`,
			want: `{"credentials":"alice:pw"}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := string(redactSecrets([]byte(tc.in))); got != tc.want {
				t.Fatalf("redactSecrets(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestRedactSecretsRedactsSecretAndCredentialsTogether pins the composition:
// a message carrying both a session secret and a policy gets both scans.
func TestRedactSecretsRedactsSecretAndCredentialsTogether(t *testing.T) {
	const secret = "9c1f"
	// the token value is longer than the field name is: a value that is a
	// substring of "tokens" would make the assertion below read the field
	// name itself as a leak
	const token = "tok_bearer_value"
	in := `{"Type":"AuthResp","Payload":{"Secret":"` + secret + `"},"Policy":{"tokens":["` + token + `"]}}`
	got := redactSecrets([]byte(in))
	for _, mustHide := range []string{secret, token} {
		if bytes.Contains(got, []byte(mustHide)) {
			t.Fatalf("%q survived the redaction: %s", mustHide, got)
		}
	}
	if want := `{"Type":"AuthResp","Payload":{"Secret":"<redacted>"},"Policy":{"tokens":["<redacted>"]}}`; string(got) != want {
		t.Fatalf("redactSecrets = %s, want %s", got, want)
	}
}

// TestHttpAuthIsRedacted closes the one pre-vaults gap in the wire log's
// redaction: ReqTunnel.HttpAuth carries a base64 "user:password" and was
// crossing the Debug whole-message log in the clear since the httpauth
// feature existed.
func TestHttpAuthIsRedacted(t *testing.T) {
	secret := "dXNlcjpwYXNzd29yZA=="
	raw, err := json.Marshal(&ReqTunnel{
		Protocol: "http",
		Hostname: "redact.test",
		HttpAuth: secret,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	red := redactSecrets(raw)
	if bytes.Contains(red, []byte(secret)) {
		t.Fatalf("HttpAuth value survived redaction: %s", red)
	}
	if !bytes.Contains(red, []byte(redactedSecret)) {
		t.Fatalf("the placeholder is missing: %s", red)
	}
	if !bytes.Contains(red, []byte("redact.test")) {
		t.Fatalf("redaction must leave the rest of the message intact: %s", red)
	}
}
