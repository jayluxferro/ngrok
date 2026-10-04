package client

// Tests for the agent TLS certificate models (SPEC-CLUSTER5 5.1/5.3). What a
// terminated connection does afterwards is proxy-path business (tested in
// agenttls_proxy_test.go); these tests are about the *tls.Config the agent
// terminates with: which model a tls block selects, that each model presents
// what it promises (a configured leaf, a CA-minted per-hostname chain, a
// temporary self-signed certificate), that the shared invariants hold on every
// model, and that broken material is an error naming the file rather than a
// tunnel that terminates nothing.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"ngrok/log"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// agentTestCA generates a throwaway certificate authority for the tests, as
// PEM certificate and PEM EC key -- the exact shapes the CA model's tls.ca_crt
// and tls.ca_key name.
func agentTestCA(t *testing.T) (caPEM, caKeyPEM []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate the test CA key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "agent tls test ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create the test CA: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("failed to marshal the test CA key: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

// agentTestLeafPEM signs a leaf with the test CA, as PEM certificate and key --
// the shapes the explicit model's tls.crt and tls.key name.
func agentTestLeafPEM(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, dnsName string) (crtPEM, keyPEM []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate the test leaf key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: dnsName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{dnsName},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create the test leaf: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("failed to marshal the test leaf key: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

// writeAgentTLSFile drops PEM material into the test's temp dir under the given
// name and returns its path.
func writeAgentTLSFile(t *testing.T, name string, contents []byte) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, contents, 0600); err != nil {
		t.Fatalf("failed to write %s: %v", name, err)
	}
	return path
}

// handshakeWith completes one real TLS handshake against cfg, as a visitor
// would: a tls.Client over one end of a pipe, trusting roots (or nothing, with
// skipVerify), presenting serverName. It returns the connection state the
// visitor ended up with -- the presented certificate chain lives on that side --
// or the handshake error.
func handshakeWith(t *testing.T, cfg *tls.Config, serverName string, roots *x509.CertPool, skipVerify bool) (tls.ConnectionState, error) {
	t.Helper()

	serverEnd, clientEnd := net.Pipe()
	defer clientEnd.Close()

	type clientResult struct {
		state tls.ConnectionState
		err   error
	}
	result := make(chan clientResult, 1)
	go func() {
		client := tls.Client(clientEnd, &tls.Config{
			ServerName:         serverName,
			RootCAs:            roots,
			InsecureSkipVerify: skipVerify,
			MinVersion:         tls.VersionTLS12,
		})
		err := client.Handshake()
		result <- clientResult{client.ConnectionState(), err}
	}()

	server := tls.Server(serverEnd, cfg)
	if err := server.Handshake(); err != nil {
		return tls.ConnectionState{}, err
	}

	res := <-result
	return res.state, res.err
}

func TestAgentTLSExplicitModel(t *testing.T) {
	caPEM, caKeyPEM := agentTestCA(t)
	caBlock, _ := pem.Decode(caPEM)
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		t.Fatalf("test CA is not parseable: %v", err)
	}
	keyBlock, _ := pem.Decode(caKeyPEM)
	caKey, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatalf("test CA key is not parseable: %v", err)
	}
	crtPEM, keyPEM := agentTestLeafPEM(t, caCert, caKey, "tunnel.example.com")

	crtPath := writeAgentTLSFile(t, "tunnel.crt", crtPEM)
	keyPath := writeAgentTLSFile(t, "tunnel.key", keyPEM)

	cfg, err := agentTLSConfig(&TunnelConfiguration{
		TLS: &TLSConfig{Crt: crtPath, Key: keyPath},
	})
	if err != nil {
		t.Fatalf("agentTLSConfig: %v", err)
	}

	// The explicit model presents a fixed certificate, not a GetCertificate
	// callback: what is on disk at load is what every handshake sees.
	if cfg.GetCertificate != nil {
		t.Fatal("the explicit model must present a fixed certificate, got a GetCertificate callback")
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("expected exactly one presented certificate, got %d", len(cfg.Certificates))
	}

	state, err := handshakeWith(t, cfg, "tunnel.example.com", nil, true)
	if err != nil {
		t.Fatalf("handshake with the explicit model failed: %v", err)
	}
	if got := state.PeerCertificates[0].DNSNames; !reflect.DeepEqual(got, []string{"tunnel.example.com"}) {
		t.Fatalf("presented leaf names %v, want [tunnel.example.com]", got)
	}

	// A CA-trusting visitor verifies the configured leaf too: the model must
	// not degrade the chain the file names.
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	if _, err := handshakeWith(t, cfg, "tunnel.example.com", pool, false); err != nil {
		t.Fatalf("a visitor trusting the leaf's CA failed the handshake: %v", err)
	}
}

func TestAgentTLSExplicitModelRejectsBrokenMaterial(t *testing.T) {
	caPEM, caKeyPEM := agentTestCA(t)
	caBlock, _ := pem.Decode(caPEM)
	caCert, _ := x509.ParseCertificate(caBlock.Bytes)
	keyBlock, _ := pem.Decode(caKeyPEM)
	caKey, _ := x509.ParseECPrivateKey(keyBlock.Bytes)
	goodCrt, goodKey := agentTestLeafPEM(t, caCert, caKey, "fine.example.com")

	cases := []struct {
		name     string
		tlsFiles *TLSConfig
		want     []string // substrings the error must contain
	}{
		{
			name:     "missing certificate file names the file and the key",
			tlsFiles: &TLSConfig{Crt: filepath.Join(t.TempDir(), "nope.crt"), Key: writeAgentTLSFile(t, "k.key", goodKey)},
			want:     []string{"nope.crt", "tls.crt"},
		},
		{
			name:     "missing key file names the file and the key",
			tlsFiles: &TLSConfig{Crt: writeAgentTLSFile(t, "c.crt", goodCrt), Key: filepath.Join(t.TempDir(), "nope.key")},
			want:     []string{"nope.key", "tls.key"},
		},
		{
			name:     "garbage certificate names the file",
			tlsFiles: &TLSConfig{Crt: writeAgentTLSFile(t, "junk.crt", []byte("this is not pem")), Key: writeAgentTLSFile(t, "k.key", goodKey)},
			want:     []string{"junk.crt"},
		},
		{
			name:     "half a pair is refused before any file is read",
			tlsFiles: &TLSConfig{Crt: writeAgentTLSFile(t, "c.crt", goodCrt)},
			want:     []string{"tls.key", "tls.crt"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := agentTLSConfig(&TunnelConfiguration{TLS: tc.tlsFiles})
			if err == nil {
				t.Fatal("expected broken material to be refused")
			}
			for _, want := range tc.want {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("error should name %q, got: %v", want, err)
				}
			}
		})
	}
}

func TestAgentTLSCAModelMintsPerHostname(t *testing.T) {
	caPEM, caKeyPEM := agentTestCA(t)
	caPath := writeAgentTLSFile(t, "ca.crt", caPEM)
	caKeyPath := writeAgentTLSFile(t, "ca.key", caKeyPEM)

	cfg, err := agentTLSConfig(&TunnelConfiguration{
		TLS: &TLSConfig{CaCrt: caPath, CaKey: caKeyPath},
	})
	if err != nil {
		t.Fatalf("agentTLSConfig: %v", err)
	}
	if cfg.GetCertificate == nil {
		t.Fatal("the CA model must mint per hostname, got a fixed certificate config")
	}

	caBlock, _ := pem.Decode(caPEM)
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		t.Fatalf("test CA is not parseable: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	// Mint for two names through the same callback the handshakes use.
	first, err := cfg.GetCertificate(&tls.ClientHelloInfo{ServerName: "a.example.com"})
	if err != nil {
		t.Fatalf("minting for a.example.com failed: %v", err)
	}
	second, err := cfg.GetCertificate(&tls.ClientHelloInfo{ServerName: "b.example.com"})
	if err != nil {
		t.Fatalf("minting for b.example.com failed: %v", err)
	}

	for _, tc := range []struct {
		name     string
		cert     *tls.Certificate
		dnsName  string
		wantName string
	}{
		{"a.example.com", first, "a.example.com", "a.example.com"},
		{"b.example.com", second, "b.example.com", "b.example.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The chain presents the leaf AND the CA: a visitor that trusts
			// only the CA can build the path from the handshake alone.
			if len(tc.cert.Certificate) != 2 {
				t.Fatalf("minted chain has %d certificates, want [leaf, ca]", len(tc.cert.Certificate))
			}
			if !reflect.DeepEqual(tc.cert.Certificate[1], caCert.Raw) {
				t.Fatal("the minted chain's second certificate is not the CA")
			}

			leaf, err := x509.ParseCertificate(tc.cert.Certificate[0])
			if err != nil {
				t.Fatalf("minted leaf does not parse: %v", err)
			}
			if !reflect.DeepEqual(leaf.DNSNames, []string{tc.wantName}) {
				t.Fatalf("minted leaf names %v, want [%s]", leaf.DNSNames, tc.wantName)
			}

			// The leaf verifies against the CA for its own name, and is
			// server-auth material.
			if _, err := leaf.Verify(x509.VerifyOptions{
				Roots:   pool,
				DNSName: tc.wantName,
			}); err != nil {
				t.Fatalf("minted leaf does not verify against the CA for %s: %v", tc.wantName, err)
			}

			// Spec shape: ECDSA P-256, 24h life, backdated for clock skew.
			if _, ok := tc.cert.PrivateKey.(*ecdsa.PrivateKey); !ok {
				t.Fatalf("leaf key is %T, want *ecdsa.PrivateKey", tc.cert.PrivateKey)
			}
			if leaf.PublicKeyAlgorithm != x509.ECDSA {
				t.Fatalf("leaf key algorithm is %v, want ECDSA", leaf.PublicKeyAlgorithm)
			}
			if got := leaf.NotAfter.Sub(leaf.NotBefore); got != agentLeafLifetime+agentLeafClockSkew {
				t.Fatalf("leaf validity is %v, want %v (lifetime plus the skew backdate)", got, agentLeafLifetime+agentLeafClockSkew)
			}
			if time.Until(leaf.NotAfter) > agentLeafLifetime {
				t.Fatalf("leaf outlives its %s validity window", agentLeafLifetime)
			}
			if leaf.KeyUsage&x509.KeyUsageCertSign != 0 {
				t.Fatal("a minted leaf must not be able to sign certificates")
			}
		})
	}

	// The cache: the same name gets the SAME certificate back (a client that
	// pinned the leaf rather than the CA must not see it change mid-session),
	// while another name still mints its own.
	again, err := cfg.GetCertificate(&tls.ClientHelloInfo{ServerName: "a.example.com"})
	if err != nil {
		t.Fatalf("re-requesting a.example.com failed: %v", err)
	}
	if !reflect.DeepEqual(first.Certificate, again.Certificate) {
		t.Fatal("the same hostname minted twice: the per-name cache is not caching")
	}
}

// TestAgentTLSCAModelNoSNI covers the hole in the SNI story: a ClientHello
// without the extension reaches the same callback with an empty name, and the
// minted certificate must still be presentable (a named, well-formed leaf) even
// though no visitor could have verified it in advance.
func TestAgentTLSCAModelNoSNI(t *testing.T) {
	caPEM, caKeyPEM := agentTestCA(t)
	cfg, err := agentTLSConfig(&TunnelConfiguration{
		TLS: &TLSConfig{
			CaCrt: writeAgentTLSFile(t, "ca.crt", caPEM),
			CaKey: writeAgentTLSFile(t, "ca.key", caKeyPEM),
		},
	})
	if err != nil {
		t.Fatalf("agentTLSConfig: %v", err)
	}

	cert, err := cfg.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("minting without SNI failed: %v", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("minted leaf does not parse: %v", err)
	}
	if !reflect.DeepEqual(leaf.DNSNames, []string{defaultLeafName}) {
		t.Fatalf("leaf minted without SNI names %v, want [%s]", leaf.DNSNames, defaultLeafName)
	}
}

func TestAgentTLSEphemeralModel(t *testing.T) {
	// The WARN is part of the model: an operator whose visitors see certificate
	// errors must be able to find out from the client's own log why, with the
	// fingerprint of the certificate to compare against. Capture the log the
	// same way the embedded-root tests do.
	logFile := filepath.Join(t.TempDir(), "client.log")
	log.LogTo(logFile, "DEBUG", "text")

	cfg, err := agentTLSConfig(&TunnelConfiguration{})
	if err != nil {
		t.Fatalf("agentTLSConfig with no tls block: %v", err)
	}

	if len(cfg.Certificates) != 1 {
		t.Fatalf("expected one temporary certificate, got %d", len(cfg.Certificates))
	}
	if cfg.GetCertificate != nil {
		t.Fatal("the ephemeral model must present its one temporary certificate, not a callback")
	}

	// The handshake works -- that is the model's whole promise -- even though
	// nothing can verify it in advance.
	state, err := handshakeWith(t, cfg, "whatever.example.com", nil, true)
	if err != nil {
		t.Fatalf("handshake with the temporary certificate failed: %v", err)
	}
	leaf := state.PeerCertificates[0]
	if got := sha256Hex(leaf.Raw); len(got) != 64 {
		t.Fatalf("fingerprint helper produced %q", got)
	}

	const marker = "ephemeral-log-scan-marker"
	log.Info(marker)
	content := waitForLogMarker(t, logFile, marker)

	for _, want := range []string{
		"temporary self-signed certificate",
		"sha256 fingerprint",
	} {
		if !strings.Contains(content, want) {
			t.Errorf("the log does not mention %q, so the temporary certificate would have gone unexplained:\n%s", want, content)
		}
	}

	// The WARN names the fingerprint of the certificate actually presented:
	// recompute it and require both hex strings on the log.
	fingerprint := sha256Hex(cfg.Certificates[0].Certificate[0])
	if !strings.Contains(content, fingerprint) {
		t.Errorf("the logged fingerprint is not the presented certificate's (want %s):\n%s", fingerprint, content)
	}

	// And it says how to make the situation better, in both spellings.
	for _, want := range []string{"tls.crt", "tls.key", "tls.ca_crt", "tls.ca_key"} {
		if !strings.Contains(content, want) {
			t.Errorf("the log's hint does not mention %q:\n%s", want, content)
		}
	}
}

// TestAgentTLSModelsShareTheInvariants walks the whole registry: every model a
// tls block can select terminates with the same floor (TLS 1.2, no client
// certificates), so adding a model cannot quietly lower the common denominator.
func TestAgentTLSModelsShareTheInvariants(t *testing.T) {
	caPEM, caKeyPEM := agentTestCA(t)
	caBlock, _ := pem.Decode(caPEM)
	caCert, _ := x509.ParseCertificate(caBlock.Bytes)
	keyBlock, _ := pem.Decode(caKeyPEM)
	caKey, _ := x509.ParseECPrivateKey(keyBlock.Bytes)
	crtPEM, keyPEM := agentTestLeafPEM(t, caCert, caKey, "inv.example.com")

	cases := []struct {
		name string
		tls  *TLSConfig
	}{
		{"explicit", &TLSConfig{
			Crt: writeAgentTLSFile(t, "inv.crt", crtPEM),
			Key: writeAgentTLSFile(t, "inv.key", keyPEM),
		}},
		{"ca", &TLSConfig{
			CaCrt: writeAgentTLSFile(t, "inv-ca.crt", caPEM),
			CaKey: writeAgentTLSFile(t, "inv-ca.key", caKeyPEM),
		}},
		{"ephemeral", nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := agentTLSConfig(&TunnelConfiguration{TLS: tc.tls})
			if err != nil {
				t.Fatalf("agentTLSConfig: %v", err)
			}
			if cfg.MinVersion != tls.VersionTLS12 {
				t.Fatalf("MinVersion = %v, want TLS 1.2", cfg.MinVersion)
			}
			if cfg.ClientAuth != tls.NoClientCert {
				t.Fatalf("ClientAuth = %v, want no client certificates", cfg.ClientAuth)
			}
		})
	}
}

// TestAgentTLSCAModelRefusesNonCA is the CA model's loudest failure mode: a
// plain leaf named as a CA would mint certificates nobody can verify, and the
// error has to say the named file is not an authority.
func TestAgentTLSCAModelRefusesNonCA(t *testing.T) {
	caPEM, caKeyPEM := agentTestCA(t)
	caBlock, _ := pem.Decode(caPEM)
	caCert, _ := x509.ParseCertificate(caBlock.Bytes)
	keyBlock, _ := pem.Decode(caKeyPEM)
	caKey, _ := x509.ParseECPrivateKey(keyBlock.Bytes)
	crtPEM, keyPEM := agentTestLeafPEM(t, caCert, caKey, "not-a-ca.example.com")

	_, err := agentTLSConfig(&TunnelConfiguration{TLS: &TLSConfig{
		CaCrt: writeAgentTLSFile(t, "leaf.crt", crtPEM),
		CaKey: writeAgentTLSFile(t, "leaf.key", keyPEM),
	}})
	if err == nil {
		t.Fatal("a non-CA certificate must not be accepted as a CA")
	}
	for _, want := range []string{"not a certificate authority", "leaf.crt"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error should mention %q, got: %v", want, err)
		}
	}
}

// sha256Hex is the fingerprint spelling the ephemeral WARN uses.
func sha256Hex(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}
