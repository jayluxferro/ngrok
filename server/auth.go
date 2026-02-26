package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
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
