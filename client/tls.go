package client

import (
	_ "crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"ngrok/client/assets"
	"ngrok/log"
)

// LoadTLSConfig builds the root CA pool from the certificates embedded in the
// binary. Every step can fail for a different reason, and every failure is
// logged: which roots a client trusts is a security-relevant fact, and a
// certificate that silently fails to load is a certificate the operator
// believes is pinned when it is not.
func LoadTLSConfig(rootCertPaths []string) (*tls.Config, error) {
	pool := x509.NewCertPool()
	certsLoaded := false

	for _, certPath := range rootCertPaths {
		rootCrt, err := assets.Asset(certPath)
		if err != nil {
			// Not embedded. This is a supported build (assets generated
			// without certificates), so it is not a warning, but it does mean
			// the client falls back to the host's roots.
			log.Info("Root CA %q is not embedded in this build, skipping it", certPath)
			continue
		}

		if addRootCA(pool, certPath, rootCrt) {
			certsLoaded = true
		}
	}

	// If no embedded certs were loaded, return empty config to use system root CAs
	if !certsLoaded {
		return &tls.Config{}, nil
	}

	return &tls.Config{RootCAs: pool}, nil
}

// addRootCA decodes one embedded certificate into pool and reports whether it
// made it in. It is separate from LoadTLSConfig so that the failure branches --
// which the shipped assets cannot exercise, because they contain no malformed
// certificate -- are reachable from a test.
func addRootCA(pool *x509.CertPool, certPath string, rootCrt []byte) bool {
	pemBlock, _ := pem.Decode(rootCrt)
	if pemBlock == nil {
		log.Warn("Root CA %q is not PEM data, ignoring it (this certificate will not be trusted)", certPath)
		return false
	}

	certs, err := x509.ParseCertificates(pemBlock.Bytes)
	if err != nil {
		// A certificate that is present but unparseable is the case worth
		// shouting about: it looks like a pinned root, and it is not one.
		log.Warn("Root CA %q failed to parse (%v), ignoring it (this certificate will not be trusted)", certPath, err)
		return false
	}

	if len(certs) == 0 {
		log.Warn("Root CA %q contains no certificate, ignoring it", certPath)
		return false
	}

	pool.AddCert(certs[0])

	return true
}
