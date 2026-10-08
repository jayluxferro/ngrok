//go:build ignore

// scripts/oidc_fake_idp.go — the identity provider of the e2e oidc group
// (SPEC-CLUSTER18): a four-endpoint OIDC playground (discovery, JWKS,
// authorize, token) real enough to drive the authorization-code + PKCE flow
// end to end through a live tunnel with curl and a cookie jar.
//
// What "real enough" means here, and what it deliberately does not:
//
//   - It signs ID tokens with a fresh RSA-2048 key per run and serves the
//     matching JWKS, so the server under test walks its whole discovery ->
//     JWKS -> signature path, not a stub of it.
//   - It remembers, per issued code, the nonce and redirect_uri the
//     authorization request carried, and puts the nonce in the ID token and
//     rejects a token exchange whose redirect_uri disagrees — the two
//     bindings the RFC makes load-bearing — so a wiring that drops either
//     fails the loop loudly instead of passing vacuously.
//   - It checks the PKCE shapes (a S256 challenge at authorize, a verifier at
//     token) but does NOT verify the verifier against the challenge: that
//     arithmetic is the server-under-test's own unit suite's job (and is
//     pinned there); this side only proves the fields survive the wiring.
//   - It requires client_secret at the token endpoint, because the fork's
//     server must be proving it holds one; a flow that lost the secret on
//     its way through the policy compile would otherwise pass here.
//   - It does not authenticate anything, expires nothing but the ID token,
//     and issues one fixed identity (sub/email/preferred_username below).
//     It is a test fixture: its one user is alice, and every client is the
//     client_id the policy named.
//
// Build-ignored like h2c_upstream.go: test tooling, not module code. The
// harness runs it with
//
//	go run scripts/oidc_fake_idp.go 127.0.0.1:<port>
//
// The issuer the policy configures is then http://127.0.0.1:<port> — the
// loopback exemption in the issuer validation rule (checkJWKSURI's exact
// rule) exists for exactly this shape.
package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"
)

// fixedUser is the identity every successful flow mints. The e2e asserts
// these exact strings arrive at the upstream as X-Forwarded-User/-Email/
// -Preferred-Username, so a change here is a change to the scenario's
// expected body, not a free edit.
const (
	fixedSub     = "alice-1234"
	fixedEmail   = "alice@example.com"
	fixedLogin   = "alice"
	clientSecret = "e2e-fake-client-secret"
)

type issuedCode struct {
	nonce       string
	redirectURI string
	exp         time.Time
}

type idp struct {
	mu    sync.Mutex
	key   *rsa.PrivateKey
	jwks  []byte
	codes map[string]issuedCode // code -> what authorize bound it to
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: go run scripts/oidc_fake_idp.go <listen-addr>")
		os.Exit(2)
	}
	addr := os.Args[1]

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fake idp: keygen:", err)
		os.Exit(1)
	}
	jwks, err := buildJWKS(key)
	if err != nil {
		fmt.Fprintln(os.Stderr, "fake idp: jwks:", err)
		os.Exit(1)
	}
	s := &idp{key: key, jwks: jwks, codes: map[string]issuedCode{}}

	issuer := "http://" + addr
	mux := http.NewServeMux()

	// Discovery: the only endpoint the server under test finds on its own.
	// Endpoints are relative to the issuer exactly as the document says.
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]string{
			"issuer":                   issuer,
			"authorization_endpoint":   issuer + "/authorize",
			"token_endpoint":           issuer + "/token",
			"jwks_uri":                 issuer + "/jwks",
			"response_types_supported": "code",
		})
	})

	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(s.jwks)
	})

	// Authorize is where the visitor's curl lands after the server's 302.
	// A real IdP authenticates here; this one authenticates everyone, binds
	// the code to the nonce and redirect_uri, and sends the visitor back.
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("response_type") != "code" {
			http.Error(w, "response_type must be code", http.StatusBadRequest)
			return
		}
		if q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
			http.Error(w, "PKCE S256 challenge required", http.StatusBadRequest)
			return
		}
		redirectURI := q.Get("redirect_uri")
		if redirectURI == "" {
			http.Error(w, "redirect_uri required", http.StatusBadRequest)
			return
		}
		if _, err := url.Parse(redirectURI); err != nil {
			http.Error(w, "redirect_uri unparseable", http.StatusBadRequest)
			return
		}

		code := randomToken()
		s.mu.Lock()
		s.codes[code] = issuedCode{
			nonce:       q.Get("nonce"),
			redirectURI: redirectURI,
			exp:         time.Now().Add(5 * time.Minute),
		}
		s.mu.Unlock()

		back, err := url.Parse(redirectURI)
		if err != nil {
			http.Error(w, "redirect_uri unparseable", http.StatusBadRequest)
			return
		}
		backq := back.Query()
		backq.Set("code", code)
		backq.Set("state", q.Get("state")) // echoed verbatim; the server compares
		back.RawQuery = backq.Encode()
		http.Redirect(w, r, back.String(), http.StatusFound)
	})

	// Token is the server-under-test's backchannel POST. Every check here
	// exists to fail loudly on a wiring that silently dropped a field.
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "form unparseable", http.StatusBadRequest)
			return
		}
		if r.Form.Get("grant_type") != "authorization_code" {
			http.Error(w, "grant_type must be authorization_code", http.StatusBadRequest)
			return
		}
		if r.Form.Get("client_secret") != clientSecret {
			http.Error(w, "client_secret wrong or missing", http.StatusUnauthorized)
			return
		}
		if r.Form.Get("code_verifier") == "" {
			http.Error(w, "code_verifier required", http.StatusBadRequest)
			return
		}

		code := r.Form.Get("code")
		s.mu.Lock()
		ic, ok := s.codes[code]
		if ok {
			delete(s.codes, code) // single use: replay must fail, loudly
		}
		s.mu.Unlock()
		if !ok || time.Now().After(ic.exp) {
			http.Error(w, "unknown or expired code", http.StatusBadRequest)
			return
		}
		if ic.redirectURI != r.Form.Get("redirect_uri") {
			http.Error(w, "redirect_uri does not match the authorization request", http.StatusBadRequest)
			return
		}

		idToken, err := s.mintIDToken(issuer, r.Form.Get("client_id"), ic.nonce)
		if err != nil {
			http.Error(w, "signing failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]string{
			"access_token": "e2e-access-token",
			"token_type":   "Bearer",
			"id_token":     idToken,
		})
	})

	fmt.Fprintf(os.Stderr, "fake idp listening on %s (issuer %s)\n", addr, issuer)
	if err := http.ListenAndServe(addr, mux); err != nil {
		fmt.Fprintln(os.Stderr, "fake idp:", err)
		os.Exit(1)
	}
}

// mintIDToken builds the RS256 ID token with exactly the claims the flow's
// verification steps consume: iss/aud/exp (the parser), nonce (the
// post-signature exact match), and the three identity claims the session
// cookie and the X-Forwarded-* headers carry.
func (s *idp) mintIDToken(issuer, aud, nonce string) (string, error) {
	now := time.Now()
	claims := map[string]interface{}{
		"iss":                issuer,
		"aud":                aud,
		"sub":                fixedSub,
		"email":              fixedEmail,
		"preferred_username": fixedLogin,
		"exp":                now.Add(5 * time.Minute).Unix(),
		"iat":                now.Unix(),
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}

	header := map[string]string{"alg": "RS256", "typ": "JWT"}
	hb, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	pb, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := base64.RawURLEncoding.EncodeToString(hb) + "." +
		base64.RawURLEncoding.EncodeToString(pb)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// buildJWKS renders the signing key's public half as the JWK set the
// server's JWKS fetcher expects: one RSA key, RS256, sig use. The kid is
// fixed so the ID token's header (which mintIDToken leaves kid-less) and
// the set agree trivially — a single-key IdP needs no selection logic.
func buildJWKS(key *rsa.PrivateKey) ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"keys": []map[string]interface{}{{
			"kty": "RSA",
			"use": "sig",
			"alg": "RS256",
			"kid": "e2e-fake-idp-key",
			"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(bigEndianExponent(key.E)),
		}},
	})
}

// bigEndianExponent encodes the RSA public exponent the way JWK wants: the
// minimal big-endian byte form (65537 -> "AQAB").
func bigEndianExponent(e int) []byte {
	var b []byte
	for e > 0 {
		b = append([]byte{byte(e & 0xff)}, b...)
		e >>= 8
	}
	return b
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func randomToken() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		panic("fake idp: random source failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
