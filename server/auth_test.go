package server

import "testing"

func TestTokenMatchesPlaintext(t *testing.T) {
	if !tokenMatches("abc123", "abc123") {
		t.Fatalf("expected plaintext token to match")
	}
	if tokenMatches("abc123", "wrong") {
		t.Fatalf("expected plaintext token mismatch")
	}
}

func TestTokenMatchesSHA256(t *testing.T) {
	digest := tokenDigest("secret-token")
	stored := "sha256:" + digest
	if !tokenMatches(stored, "secret-token") {
		t.Fatalf("expected hashed token to match")
	}
	if tokenMatches(stored, "different-token") {
		t.Fatalf("expected hashed token mismatch")
	}
}

