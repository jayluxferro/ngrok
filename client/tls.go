package client

import (
	_ "crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"ngrok/client/assets"
)

func LoadTLSConfig(rootCertPaths []string) (*tls.Config, error) {
	pool := x509.NewCertPool()
	certsLoaded := false

	for _, certPath := range rootCertPaths {
		rootCrt, err := assets.Asset(certPath)
		if err != nil {
			// Certificate not found in assets, skip it
			// This allows building without certificates embedded
			continue
		}

		pemBlock, _ := pem.Decode(rootCrt)
		if pemBlock == nil {
			// Bad PEM data, skip this certificate
			continue
		}

		certs, err := x509.ParseCertificates(pemBlock.Bytes)
		if err != nil {
			// Failed to parse certificate, skip it
			continue
		}

		if len(certs) > 0 {
			pool.AddCert(certs[0])
			certsLoaded = true
		}
	}

	// If no embedded certs were loaded, return empty config to use system root CAs
	if !certsLoaded {
		return &tls.Config{}, nil
	}

	return &tls.Config{RootCAs: pool}, nil
}
