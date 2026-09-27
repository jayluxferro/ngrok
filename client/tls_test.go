package client

import (
	"bytes"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"crypto/x509"

	"ngrok/client/assets"
	"ngrok/log"
)

// These tests are about which roots the client ends up trusting, and about the
// client saying so out loud when a certificate it was told to embed does not
// make it into the pool. A pinned root that silently fails to load is worse
// than no pinning at all: the operator believes the tunnel can only be
// intercepted by the CA they shipped, and the client is quietly trusting
// whatever the host trusts.

const testRootCA = "assets/client/tls/ngrokroot.crt"

func TestLoadTLSConfigPinsTheEmbeddedCertificates(t *testing.T) {
	cfg, err := LoadTLSConfig([]string{testRootCA})
	if err != nil {
		t.Fatalf("LoadTLSConfig: %v", err)
	}
	if cfg.RootCAs == nil {
		t.Fatalf("expected the embedded certificate to be pinned, got the system root CAs")
	}

	subjects := cfg.RootCAs.Subjects()
	if len(subjects) != 1 {
		t.Fatalf("expected exactly 1 pinned root, got %d", len(subjects))
	}

	// ...and it is that certificate, not merely one certificate: compare the
	// pinned DER subject with the subject of the asset on disk.
	raw, err := assets.Asset(testRootCA)
	if err != nil {
		t.Fatalf("test asset %q is missing from the build: %v", testRootCA, err)
	}
	block, _ := pem.Decode(raw)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("test asset %q is not a parseable certificate: %v", testRootCA, err)
	}
	if !bytes.Equal(subjects[0], cert.RawSubject) {
		t.Errorf("the pinned root is not the embedded certificate: subject %x, want %x", subjects[0], cert.RawSubject)
	}
}

// TestLoadTLSConfigFallsBackToSystemRoots covers the build-without-certificates
// case: nothing loadable, so the client must return a config that means "use
// the host's roots" rather than an empty, trust-nothing pool.
func TestLoadTLSConfigFallsBackToSystemRoots(t *testing.T) {
	cfg, err := LoadTLSConfig([]string{"assets/client/tls/does-not-exist.crt"})
	if err != nil {
		t.Fatalf("LoadTLSConfig: %v", err)
	}
	if cfg.RootCAs != nil {
		t.Errorf("expected a nil RootCAs (system roots), got a pool with %d roots", len(cfg.RootCAs.Subjects()))
	}
}

// TestLoadTLSConfigKeepsGoingAfterABadCertificate is the mixed case, which is
// the one that can happen in practice: one root is fine, the others are not.
// The good root must still be pinned, and the bad ones must not abort the load.
func TestLoadTLSConfigKeepsGoingAfterABadCertificate(t *testing.T) {
	cfg, err := LoadTLSConfig([]string{
		"assets/client/page.html", // present, but not a certificate
		testRootCA,                // the real root
		"assets/client/tls/does-not-exist.crt",
	})
	if err != nil {
		t.Fatalf("LoadTLSConfig: %v", err)
	}
	if cfg.RootCAs == nil {
		t.Fatalf("a bad certificate in the list must not discard the good ones")
	}
	if got := len(cfg.RootCAs.Subjects()); got != 1 {
		t.Errorf("expected only the one valid root to be pinned, got %d", got)
	}
}

// TestAddRootCARejectsUnparseableCertificate reaches the branch the shipped
// assets cannot: PEM armor whose payload is not a certificate. That is the
// shape of a corrupted or truncated asset file, and it has to be both skipped
// and reported.
func TestAddRootCARejectsUnparseableCertificate(t *testing.T) {
	logFile := filepath.Join(t.TempDir(), "client.log")
	log.LogTo(logFile, "DEBUG", "text")

	pool := x509.NewCertPool()
	if addRootCA(pool, "assets/client/tls/corrupt.crt", []byte("-----BEGIN CERTIFICATE-----\nnot a certificate\n-----END CERTIFICATE-----\n")) {
		t.Error("a PEM block that is not a certificate must not be accepted")
	}
	if got := len(pool.Subjects()); got != 0 {
		t.Errorf("nothing may be added to the pool, got %d roots", got)
	}

	// Not PEM at all -- the shape of an asset that is the wrong file entirely.
	if addRootCA(pool, "assets/client/page.html", []byte("<html></html>")) {
		t.Error("data that is not PEM must not be accepted")
	}

	const marker = "tls-log-scan-marker"
	log.Info(marker)
	content := waitForLogMarker(t, logFile, marker)

	for _, want := range []string{"corrupt.crt", "page.html", "will not be trusted"} {
		if !strings.Contains(content, want) {
			t.Errorf("the log does not mention %q, so a skipped root would have gone unnoticed:\n%s", want, content)
		}
	}
}

// waitForLogMarker returns the log file's contents once the marker line has
// been written. log4go's file writer is asynchronous (records go through a
// channel to a writer goroutine), so the marker is what says "everything logged
// before this call is on disk now".
func waitForLogMarker(t *testing.T, logFile, marker string) string {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for {
		content, err := os.ReadFile(logFile)
		if err == nil && strings.Contains(string(content), marker) {
			return string(content)
		}
		if time.Now().After(deadline) {
			t.Fatalf("the marker %q never reached %s (last error: %v)", marker, logFile, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
