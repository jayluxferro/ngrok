package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ngrok/log"
	"ngrok/msg"
)

// TestServerConfigRejectsUnknownKeys pins the strict decode: a typo'd key in
// ngrokd's config file must fail the load rather than silently leaving the
// server unprotected (the auth_tokens misspelling is the one that matters).
func TestServerConfigRejectsUnknownKeys(t *testing.T) {
	dir := t.TempDir()

	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatalf("failed to write %s: %v", name, err)
		}
		return p
	}

	if _, err := loadServerConfig(write("typo.yml", "auth_toknes:\n  - secret\n")); err == nil {
		t.Fatal("a config with a misspelled key must fail the load")
	} else if !strings.Contains(err.Error(), "auth_toknes") {
		t.Fatalf("error must name the unknown key, got: %v", err)
	}

	cfg, err := loadServerConfig(write("valid.yml", "domain: example.com\nauth_tokens:\n  - secret\nmax_msg_bytes: 4194304\n"))
	if err != nil {
		t.Fatalf("a valid config must load, got: %v", err)
	}
	if len(cfg.AuthTokens) != 1 || cfg.AuthTokens[0] != "secret" {
		t.Fatalf("auth tokens not loaded: %+v", cfg.AuthTokens)
	}
}

// TestPublicVhostCannotEndInInternal pins the derived-url half of the
// .internal invariant: when the public vhost (domain or VHOST override) ends
// in .internal, every derived url would squat the reserved namespace through
// the public path, so registration is refused before a name is claimed.
func TestPublicVhostCannotEndInInternal(t *testing.T) {
	// endpointName reads the server's global options; the test binary never
	// runs parseArgs, so provide the one field the error path needs.
	oldOpts := opts
	opts = &Options{domain: "localhost"}
	defer func() { opts = oldOpts }()

	t.Setenv("VHOST", "foo.internal:80")

	tun := &Tunnel{req: &msg.ReqTunnel{Protocol: msg.ProtoHTTP, Subdomain: "x"}, Logger: log.NewPrefixLogger("test")}
	err := registerVhost(tun, msg.ProtoHTTP, 80)
	if err == nil {
		t.Fatal("a public vhost ending in .internal must refuse derived registrations")
	}
	if !strings.Contains(err.Error(), msg.InternalSuffix) {
		t.Fatalf("error must name the namespace, got: %v", err)
	}
}
