package client

// Agent TLS termination (SPEC-CLUSTER5, 5.3).
//
// On an agent-terminated tunnel the ngrokd server never sees plaintext: it
// peeks the ClientHello's SNI, finds the tunnel, and relays the TLS records to
// this process untouched. This file is the other end of that bargain -- it
// builds the *tls.Config the agent terminates the PUBLIC side of the tunnel
// with, so that a visitor's handshake ends here and the local upstream receives
// plain HTTP.
//
// Three certificate models are supported, in priority order:
//
//  1. explicit -- tls.crt/tls.key name a leaf certificate the agent presents.
//  2. CA       -- tls.ca_crt/tls.ca_key name a certificate authority; the agent
//     mints a short-lived leaf per requested hostname (SNI) on demand. The CA
//     key never leaves the agent.
//  3. ephemeral -- nothing configured: a temporary self-signed certificate, one
//     per tunnel session, with a loud WARN (fingerprint + how to configure a
//     real one). This is the only silent-ish fallback in the feature, and it is
//     not actually silent: the WARN is the point.
//
// The models are a table (agentCertModels), not an if-chain, because SPEC-CLUSTER5
// review gate 8.5 asks for exactly that: a fourth model is one table entry, and
// the priority order is the slice order rather than something buried in control
// flow.
//
// Everything this file builds shares two invariants: MinVersion TLS 1.2, and no
// client-certificate request (mTLS of public visitors is a later cluster, spec
// section 2).

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"ngrok/log"
	"os"
	"sync"
	"time"
)

const (
	// Cert model names. They appear in log lines so an operator can tell which
	// model a session ended up on.
	certModelExplicit  = "explicit"
	certModelCA        = "ca"
	certModelEphemeral = "ephemeral"

	// agentLeafLifetime is how long a CA-minted leaf lives. 24h, per spec: it is
	// a per-name convenience certificate, not an identity, and it is re-minted
	// on demand after expiry.
	agentLeafLifetime = 24 * time.Hour

	// agentEphemeralLifetime is how long the temporary self-signed certificate
	// is valid. A tunnel session is shorter than this in practice; the value
	// only has to comfortably outlive the process.
	agentEphemeralLifetime = 24 * time.Hour

	// agentLeafClockSkew is how far back a minted leaf's NotBefore is set.
	// Visitors and the agent need not agree on time to the second, and a
	// certificate that is valid "in a few seconds" answers a perfectly healthy
	// client with a certificate error.
	agentLeafClockSkew = 1 * time.Hour

	// defaultLeafName is the hostname minted for when the ClientHello carries
	// no SNI. In production this is rarely reached (the server only routes a
	// connection to an agent-terminated tunnel when the SNI matched the
	// registry), but a client that omits the extension would otherwise produce
	// a certificate with no name at all, which no visitor can use even with
	// verification disabled -- some clients refuse an empty SAN list outright.
	defaultLeafName = "localhost"
)

// agentCertModel is one entry of the certificate-model registry: how to tell
// that a tunnel's tls block selects this model, and how to build the tls.Config
// for it. The slice below is the priority order.
type agentCertModel struct {
	name string

	// configured reports whether the tls block names this model. It must be a
	// total function of the block: the registry walk takes the first model that
	// reports true, so an entry later in the slice is only ever consulted when
	// every earlier entry said no.
	configured func(*TLSConfig) bool

	// build produces the model's tls.Config. File (or key generation) errors
	// are returned, not swallowed: every caller of agentTLSConfig treats an
	// error as "do not establish the tunnel".
	build func(*TLSConfig) (*tls.Config, error)
}

// agentCertModels is the registry, in priority order: an explicit leaf wins a
// CA pair if both were somehow named (the loader refuses that combination, so
// this order is belt-and-suspenders), and the ephemeral model -- whose
// configured is the constant true -- is the fallback that always answers.
var agentCertModels = []agentCertModel{
	{
		name:       certModelExplicit,
		configured: func(t *TLSConfig) bool { return t != nil && (t.Crt != "" || t.Key != "") },
		build:      buildExplicitAgentTLS,
	},
	{
		name:       certModelCA,
		configured: func(t *TLSConfig) bool { return t != nil && (t.CaCrt != "" || t.CaKey != "") },
		build:      buildCAAgentTLS,
	},
	{
		name:       certModelEphemeral,
		configured: func(*TLSConfig) bool { return true },
		build:      buildEphemeralAgentTLS,
	},
}

// agentTLSConfig builds the tls.Config that terminates the public https TLS of
// one agent-terminated tunnel, resolving the tunnel's cert model by the table
// above.
//
// It is called twice per tunnel by design: once at configuration load
// (validateAgentTLS), so that a certificate file that is missing or unparseable
// is a startup error naming the file, and once when the tunnel is established,
// whose result is the config that session actually uses -- re-reading the files,
// so a certificate rotated on disk between load and registration is picked up at
// the next (re)connect without restarting the client.
func agentTLSConfig(t *TunnelConfiguration) (*tls.Config, error) {
	var tlsFiles *TLSConfig
	if t != nil {
		tlsFiles = t.TLS
	}

	for _, model := range agentCertModels {
		if !model.configured(tlsFiles) {
			continue
		}

		cfg, err := model.build(tlsFiles)
		if err != nil {
			return nil, fmt.Errorf("%s cert model: %v", model.name, err)
		}
		var alpn []string
		if t != nil {
			alpn = t.Alpn
		}
		finishAgentTLSConfig(cfg, alpn)
		return cfg, nil
	}

	// Unreachable: the ephemeral model is configured for every input. If the
	// table is ever edited into a state where it is not, say so rather than
	// return a nil config that would terminate nothing.
	return nil, fmt.Errorf("no certificate model is configured for this tunnel")
}

// finishAgentTLSConfig applies the invariants every model shares. It is a
// function rather than inline lines so that "all models" is enforced in one
// place: a model added to the registry gets these by construction. alpn is the
// one per-tunnel input (SPEC-CLUSTER16 2): the tunnel's configured protocols,
// advertised in every handshake this config terminates.
func finishAgentTLSConfig(cfg *tls.Config, alpn []string) {
	// The public visitors of these endpoints are arbitrary clients, some of
	// them appliances that cannot do better; TLS 1.2 is the floor this build
	// commits to (anything older has known protocol-level breaks).
	cfg.MinVersion = tls.VersionTLS12

	// No client certificates: the agent authenticates visitors by their traffic
	// policies, not by TLS identities, and requesting a certificate would make
	// every client that cannot produce one fail the handshake.
	cfg.ClientAuth = tls.NoClientCert

	// The ALPN advertisement is set only when the tunnel configures one, and
	// left nil otherwise: a tunnel without the alpn key must produce
	// byte-identical handshakes to before the key existed. (That opt-in is
	// deliberate, SPEC-CLUSTER16 1: advertising h2 unconditionally would flip
	// every h2-capable visitor onto h2 toward local services that only speak
	// HTTP/1.1.) The list is assigned as written, order preserved -- "h2"
	// first means h2-capable visitors get h2, which is the operator's stated
	// preference -- and the negotiated protocol needs no branch after
	// termination: plaintext flows into the relay whatever was negotiated.
	//
	// The assignment is plain, with no clone-then-set: every model above built
	// a fresh *tls.Config for this one call, so nothing else holds this
	// pointer. That is the difference from the server's QUIC path, which must
	// clone before setting NextProtos because its TCP listener shares the
	// config whose handshakes must keep advertising no application protocol at
	// all (server/quic.go quicTLSConfig).
	if len(alpn) > 0 {
		cfg.NextProtos = alpn
	}
}

// readPEMFile reads one PEM file, naming the file and the config key it came
// from in every error. The key name is in there because these errors surface at
// config load, where "ca.pem" alone may be one of several paths in the block.
func readPEMFile(configKey, path string) ([]byte, error) {
	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s (%s): %v", configKey, path, err)
	}
	return buf, nil
}

// buildExplicitAgentTLS is model 1: load the named leaf and key and present
// them as the tunnel's certificate.
func buildExplicitAgentTLS(tlsFiles *TLSConfig) (*tls.Config, error) {
	if tlsFiles == nil || tlsFiles.Crt == "" || tlsFiles.Key == "" {
		return nil, fmt.Errorf("tls.crt and tls.key must both be set")
	}

	crtPEM, err := readPEMFile("tls.crt", tlsFiles.Crt)
	if err != nil {
		return nil, err
	}
	keyPEM, err := readPEMFile("tls.key", tlsFiles.Key)
	if err != nil {
		return nil, err
	}

	cert, err := tls.X509KeyPair(crtPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate %s or key %s: %v", tlsFiles.Crt, tlsFiles.Key, err)
	}
	// "leaf checked non-empty" (spec 5.3): X509KeyPair can succeed with an
	// empty chain in odd PEM shapes, and a config that terminates nothing must
	// not load.
	if len(cert.Certificate) == 0 {
		return nil, fmt.Errorf("certificate file %s contains no certificate", tlsFiles.Crt)
	}

	return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
}

// buildCAAgentTLS is model 2: load a CA certificate and key, and present a
// GetCertificate that mints a leaf per requested hostname on demand.
//
// The minter owns a small name-keyed cache (one certificate per SNI, minted
// once, reused for the life of the tunnel session): minting is two elliptic
// curve operations plus a signature, which is cheap, but a busy hostname should
// not pay it per handshake -- and the cache is what keeps every handshake for a
// name presenting the SAME certificate, which is what lets a client that pins
// the leaf (rather than trusting the CA) keep working.
func buildCAAgentTLS(tlsFiles *TLSConfig) (*tls.Config, error) {
	if tlsFiles == nil || tlsFiles.CaCrt == "" || tlsFiles.CaKey == "" {
		return nil, fmt.Errorf("tls.ca_crt and tls.ca_key must both be set")
	}

	caPEM, err := readPEMFile("tls.ca_crt", tlsFiles.CaCrt)
	if err != nil {
		return nil, err
	}
	caKeyPEM, err := readPEMFile("tls.ca_key", tlsFiles.CaKey)
	if err != nil {
		return nil, err
	}

	// X509KeyPair is the one stdlib call that parses a certificate and its
	// private key together and hands both back (tls.Certificate.PrivateKey),
	// whatever algorithm the key uses -- ECDSA, RSA or Ed25519 -- so the CA key
	// does not have to be parsed by algorithm-specific code here.
	ca, err := tls.X509KeyPair(caPEM, caKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate %s or key %s: %v", tlsFiles.CaCrt, tlsFiles.CaKey, err)
	}
	if len(ca.Certificate) == 0 {
		return nil, fmt.Errorf("CA certificate file %s contains no certificate", tlsFiles.CaCrt)
	}
	caCert, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate %s: %v", tlsFiles.CaCrt, err)
	}
	if !caCert.IsCA {
		return nil, fmt.Errorf("certificate %s is not a certificate authority (it lacks CA:TRUE), so it cannot mint per-hostname certificates", tlsFiles.CaCrt)
	}
	if caCert.CheckSignatureFrom(caCert) != nil {
		return nil, fmt.Errorf("certificate %s is not self-signed: a CA the agent mints from must be a self-signed root", tlsFiles.CaCrt)
	}

	minter := &caMinter{
		caCert: caCert,
		caKey:  ca.PrivateKey,
		caDER:  ca.Certificate[0],
		cache:  make(map[string]cachedLeaf),
		log:    log.NewPrefixLogger("tlsagent"),
	}

	return &tls.Config{GetCertificate: minter.certificateFor}, nil
}

// caMinter mints and caches one leaf per requested hostname. It is created once
// per tunnel session and used concurrently by handshakes, so the cache is
// guarded.
type caMinter struct {
	caCert *x509.Certificate
	caKey  crypto.PrivateKey
	caDER  []byte

	mu    sync.Mutex
	cache map[string]cachedLeaf

	// log receives one INFO per minted name: a name appearing here that the
	// operator did not expect is the visible trace of someone probing the
	// endpoint.
	log log.Logger
}

// cachedLeaf is one name's minted certificate and the moment it stops being
// presentable. The cache exists to keep handshakes cheap and a name's leaf
// stable across them -- not to serve a leaf past its expiry: a tunnel session
// can outlive the 24h leaf lifetime (long-lived streaming tunnels do exactly
// that), and without the expiry check every visitor after it would see a
// certificate error with no trace in any log.
type cachedLeaf struct {
	cert    *tls.Certificate
	expires time.Time
}

// leafReMintMargin is how long before a cached leaf's expiry a re-mint happens.
// It is small against the leaf lifetime: visitors and this agent need not agree
// on time to the second, but a leaf re-minted at its NotAfter would already be
// expired for clocks slightly ahead.
const leafReMintMargin = 5 * time.Minute

// certificateFor is a tls.Config.GetCertificate callback: it returns the leaf
// for the ClientHello's SNI, minting it on first use and caching it by name,
// and re-minting it when the cached leaf is within leafReMintMargin of expiry.
func (m *caMinter) certificateFor(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	name := hello.ServerName
	if name == "" {
		name = defaultLeafName
	}

	m.mu.Lock()
	cached, ok := m.cache[name]
	m.mu.Unlock()
	if ok && time.Now().Before(cached.expires.Add(-leafReMintMargin)) {
		return cached.cert, nil
	}

	leaf, notAfter, err := m.mint(name)
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	m.cache[name] = cachedLeaf{cert: leaf, expires: notAfter}
	m.mu.Unlock()
	m.log.Info("Minted a %s leaf for %q (valid for %s)", agentLeafLifetime, name, agentLeafLifetime)
	return leaf, nil
}

// mint signs one leaf for name with the CA. The leaf is ECDSA P-256 with the
// name as its only SAN: exactly the minimum a visitor verifying against the CA
// needs, and nothing that outlives its usefulness. The returned time is the
// leaf's NotAfter, which the cache re-mints against.
func (m *caMinter) mint(name string) (*tls.Certificate, time.Time, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("failed to generate a leaf key for %q: %v", name, err)
	}

	// The serial is random and non-zero: a fixed serial across minted leaves
	// would make them indistinguishable to revocation tooling, and Go's own
	// CreateCertificate refuses a zero serial outright.
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("failed to generate a serial for %q: %v", name, err)
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   name,
			Organization: []string{"ngrok agent"},
		},
		NotBefore:             now.Add(-agentLeafClockSkew),
		NotAfter:              now.Add(agentLeafLifetime),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{name},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, m.caCert, &key.PublicKey, m.caKey)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("failed to sign a leaf for %q: %v", name, err)
	}

	// The chain is [leaf, CA]: visitors that trust only the CA certificate can
	// build the path from what the handshake presents, without needing the CA
	// delivered out of band a second time.
	return &tls.Certificate{
		Certificate: [][]byte{der, m.caDER},
		PrivateKey:  key,
	}, tmpl.NotAfter, nil
}

// buildEphemeralAgentTLS is model 3: generate a one-off self-signed certificate
// for this tunnel session and warn about it, loudly. A visitor has no way to
// verify such a certificate -- the WARN exists so the operator can tell, from
// the client's own log, that this is why a browser or curl shows a certificate
// error, and the fingerprint pins which certificate a "-k" style run actually
// saw.
func buildEphemeralAgentTLS(*TLSConfig) (*tls.Config, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate a temporary key: %v", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate a serial: %v", err)
	}

	now := time.Now()
	// A leaf, nothing more: the old template carried CA:TRUE and keyCertSign
	// "to be safe", which is exactly backwards for a throwaway certificate --
	// capability nobody asked for is a signing key that could mint other
	// identities, however unlikely anyone is to use it.
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "ngrok temporary self-signed certificate",
			Organization: []string{"ngrok agent"},
		},
		NotBefore: now.Add(-agentLeafClockSkew),
		NotAfter:  now.Add(agentEphemeralLifetime),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
		DNSNames:              []string{defaultLeafName},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("failed to create a temporary self-signed certificate: %v", err)
	}

	fingerprint := sha256.Sum256(der)
	// The hint names both config spellings and both flag spellings: this WARN
	// is read by people whose next step is "make the certificate error go
	// away", and the way to do that is exactly one of these four things.
	log.Warn("Tunnel will present a temporary self-signed certificate (sha256 fingerprint %s) valid for %s; visitors will see a certificate error unless they skip verification. Configure tls.crt/tls.key or tls.ca_crt/tls.ca_key in the tunnel's tls block (or the -tls-crt/-tls-key, -tls-ca-crt/-tls-ca-key flags) to present a real certificate.",
		hex.EncodeToString(fingerprint[:]), agentEphemeralLifetime)

	return &tls.Config{Certificates: []tls.Certificate{
		{
			Certificate: [][]byte{der},
			PrivateKey:  key,
		},
	}}, nil
}
