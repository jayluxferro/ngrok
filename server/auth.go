package server

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strings"
)

func tokenDigest(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func tokenMatches(stored, candidate string) bool {
	if strings.HasPrefix(stored, "sha256:") {
		expected := strings.TrimPrefix(stored, "sha256:")
		got := tokenDigest(candidate)
		return subtle.ConstantTimeCompare([]byte(expected), []byte(got)) == 1
	}

	return subtle.ConstantTimeCompare([]byte(stored), []byte(candidate)) == 1
}

// sessionSecretBytes is the entropy in one session secret. 32 bytes is the
// usual "no shortcuts" size for a bearer token, and the encoding is hex so the
// secret is safe to carry in a JSON string with no escaping.
const sessionSecretBytes = 32

// newSessionSecret mints the secret that goes with a freshly assigned client id.
//
// This value is a credential, so it is generated once, stored on the Control,
// and never formatted into a log line, an event, a metric or an error message.
// The id it belongs to is public -- it is logged, cached and reported -- and
// the secret is the only thing that tells a resuming client from an impostor,
// so the whole design rests on it never leaving the two ends of the control
// channel (taken as given: the control channel is TLS in every real
// deployment; `ngrokd` without -tlsCrt is a development configuration).
func newSessionSecret() (string, error) {
	buf := make([]byte, sessionSecretBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("failed to generate a session secret: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// secretMatches reports whether candidate proves the stored session secret.
//
// The comparison is constant time so that a wrong guess leaks nothing about the
// stored value through timing, and an empty stored secret never matches
// anything: a control whose secret was never set (a fixture, or a bug) refuses
// resume rather than accepting the empty string an attacker would send.
func secretMatches(stored, candidate string) bool {
	if stored == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(stored), []byte(candidate)) == 1
}
