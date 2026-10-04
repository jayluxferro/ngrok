package client

// Tests for the QUIC dial's TLS trust pin (SPEC-CLUSTER7 5).
//
// dialQuicSession dials with the model's TLS configuration -- the same
// TrustHostRootCerts / embedded-CA / NGROK_INSECURE_SKIP_VERIFY decision the
// control channel made -- with only the ALPN added, and the ALPN must land on
// a CLONE: the model's tls.Config is shared by the control conn and every
// other dial the client makes, so a dial that mutated it would silently turn
// every future connection into a QUIC-ALPN one. The two regressions this file
// pins are the two ways that seam can fail: verification turned off (an
// untrusted server accepted where the configuration named a trust anchor), and
// the clone replaced by an alias (the shared config rewritten in place).
//
// The fixtures come from quic_test.go: a real quic-go listener on UDP loopback
// holding a self-signed certificate, and a model wired the way the real
// constructor wires one.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"slices"
	"strings"
	"testing"
	"time"
)

// unrelatedRootPool mints a self-signed CA that has nothing to do with the
// fake server's certificate and returns a pool trusting only it. A model
// configured with it is the "verification is on and named a real trust anchor"
// road of the real client (trust_host_root_certs=false with embedded or host
// CAs -- every shape of the configuration except skip-verify): the server's
// certificate signs itself, so no chain from it reaches this pool.
func unrelatedRootPool(t *testing.T) *x509.CertPool {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate the unrelated CA key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "unrelated ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create the unrelated CA certificate: %v", err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed to parse the unrelated CA certificate: %v", err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return pool
}

// TestQuicDialRejectsUntrustedServerCert pins the verification half of the
// dial's TLS trust: with the configuration carrying a trust anchor and
// InsecureSkipVerify false, a self-signed server must FAIL the QUIC dial, and
// the failure must say it was a certificate verification -- that is the exact
// fallback signal dialSession's comment describes ("a server this client does
// not trust"), and silently succeeding here would be the trust decision
// inverted. The control half dials the SAME listener with the skip-verify
// configuration the rest of this suite uses and must succeed, which is what
// makes the failure provably the trust decision and not the transport, the
// ALPN or a wiring bug.
func TestQuicDialRejectsUntrustedServerCert(t *testing.T) {
	publicUrl := "http://" + muxTestPublicHost
	srv := startFakeQuicServer(t, publicUrl)

	// The verifying model: a trust anchor configured, skip-verify explicitly
	// false -- the field newClientModel sets from the environment, stated here
	// so a future default cannot silently flip the pin's meaning.
	model := quicTestModel(t, publicUrl, "127.0.0.1:1", srv.addr)
	model.tlsConfig = &tls.Config{
		ServerName:         quicTestHost,
		RootCAs:            unrelatedRootPool(t),
		InsecureSkipVerify: false,
		MinVersion:         tls.VersionTLS12,
	}

	if _, err := model.dialQuicSession(); err == nil {
		t.Fatal("the QUIC dial succeeded against a server whose certificate no configured trust anchor signs")
	} else if !strings.Contains(err.Error(), "certificate") && !strings.Contains(err.Error(), "x509") {
		t.Fatalf("the dial failure does not name the certificate verification (want an x509-shaped error), got: %v", err)
	}

	// The control: the same listener, the suite's usual skip-verify
	// configuration -- the dial must complete and bind its session.
	okModel := quicTestModel(t, publicUrl, "127.0.0.1:1", srv.addr)
	sess, err := okModel.dialQuicSession()
	if err != nil {
		t.Fatalf("the skip-verify dial failed against the same listener: %v", err)
	}
	t.Cleanup(sess.Close)
	srv.acceptRegMux(t)
}

// TestQuicDialClonesTheModelTLSConfig pins the clone: the ALPN dialQuicSession
// needs must be set on a copy, never on the model's configuration itself. The
// assertion is byte-identity of the model's NextProtos across a dial -- empty
// before, still empty after -- and, because the dial here SUCCEEDS, the clone
// demonstrably carried the ALPN (the fake listener refuses an ALPN mismatch,
// which TestQuicDialFallsThroughToSmuxOnALPNMismatch pins separately): a dial
// that both succeeded and left the original empty can only have done its ALPN
// work on a clone. An alias would show up as quicALPN appearing in the
// model's config -- a rewrite every later control and proxy dial would inherit.
func TestQuicDialClonesTheModelTLSConfig(t *testing.T) {
	publicUrl := "http://" + muxTestPublicHost
	srv := startFakeQuicServer(t, publicUrl)

	model := quicTestModel(t, publicUrl, "127.0.0.1:1", srv.addr)
	before := append([]string(nil), model.tlsConfig.NextProtos...) // empty: no ALPN is configured at the model

	sess, err := model.dialQuicSession()
	if err != nil {
		t.Fatalf("dialQuicSession: %v", err)
	}
	t.Cleanup(sess.Close)
	srv.acceptRegMux(t) // the dial completed the handshake: the ALPN was negotiated

	after := model.tlsConfig.NextProtos
	if len(after) != 0 || len(before) != 0 {
		t.Fatalf("the model's tls.Config.NextProtos changed across the dial: before %q, after %q -- the ALPN must be set on a clone, not on the shared configuration", before, after)
	}
	if !slices.Equal(before, after) {
		t.Fatalf("the model's tls.Config.NextProtos changed across the dial: before %q, after %q", before, after)
	}
}
