package client

// Tests for the config file's vaults: block (SPEC-CLUSTER9 3): that the keys
// decode, that loading installs the vaults BEFORE any tunnel is validated (a
// policy referencing a vault loads when the vault is there and fails naming
// vault and key when it is not), that a missing vault FILE is named, and that
// loading is hermetic -- one configuration's vaults never leak into the next
// load's.
//
// The resolution machinery itself is table-tested in policy/vault_test.go;
// these tests prove the wiring through the real LoadConfiguration.

import (
	"encoding/base64"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ngrok/policy"
)

// restoreVaults undoes whatever LoadConfiguration installed, so the tests do
// not order-depend on each other (or on the packages' other policy tests).
func restoreVaults(t *testing.T) {
	t.Helper()
	prev := policy.Vaults()
	t.Cleanup(func() { policy.SetVaults(prev) })
}

// vaultTunnelYAML is a config with one tunnel whose policy authenticates
// through a vault reference.
func vaultTunnelYAML(vaultBlock, credentials string) string {
	return `
vaults:
` + vaultBlock + `
tunnels:
  web:
    proto:
      http: 127.0.0.1:8080
    traffic_policy:
      on_http_request:
        - name: basic-auth
          config:
            credentials:
` + credentials
}

// loadConfig runs LoadConfiguration the way "ngrok start web" does.
func loadConfig(t *testing.T, contents string) (*Configuration, error) {
	t.Helper()
	configPath := filepath.Join(t.TempDir(), "ngrok.yml")
	if err := os.WriteFile(configPath, []byte(contents), 0600); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}
	return LoadConfiguration(&Options{config: configPath, command: "start", args: []string{"web"}})
}

// vaultTestLogger is the quiet logger Compiled.RequestHook wants.
type vaultTestLogger struct{}

func (vaultTestLogger) AddLogPrefix(string)                {}
func (vaultTestLogger) SetLogPrefixes(...string)           {}
func (vaultTestLogger) Debug(string, ...interface{})       {}
func (vaultTestLogger) Info(string, ...interface{})        {}
func (vaultTestLogger) Warn(string, ...interface{}) error  { return nil }
func (vaultTestLogger) Error(string, ...interface{}) error { return nil }

// requestWithBasicCreds drives the loaded policy's request hook the way the
// server will at the edge, and reports whether it admitted the request.
func requestWithBasicCreds(t *testing.T, config *Configuration, user, pass string) bool {
	t.Helper()
	compiled, err := config.Tunnels["web"].TrafficPolicy.Compile()
	if err != nil {
		t.Fatalf("the loaded policy did not compile: %v", err)
	}
	hook := compiled.RequestHook(vaultTestLogger{}, "1.2.3.4:1")
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(user+":"+pass)))
	return hook(req) == nil
}

func TestLoadConfigurationVaultsFile(t *testing.T) {
	restoreVaults(t)

	vaultPath := filepath.Join(t.TempDir(), "vault.yml")
	if err := os.WriteFile(vaultPath, []byte("alice: alice:from-vault\n"), 0600); err != nil {
		t.Fatalf("failed to write vault file: %v", err)
	}

	config, err := loadConfig(t, vaultTunnelYAML("  main:\n    file: "+vaultPath+"\n", `              - secret("main/alice")`))
	if err != nil {
		t.Fatalf("LoadConfiguration refused a config whose reference resolves: %v", err)
	}
	if !requestWithBasicCreds(t, config, "alice", "from-vault") {
		t.Fatal("the vault value did not authenticate: the client loaded but did not resolve")
	}
	if requestWithBasicCreds(t, config, "alice", "wrong") {
		t.Fatal("a wrong password was admitted")
	}
}

func TestLoadConfigurationVaultsEnv(t *testing.T) {
	restoreVaults(t)

	t.Setenv("NGROK_VAULT_MAIN_PASSWORD", "web:s3cret")
	config, err := loadConfig(t, vaultTunnelYAML("  main:\n    env_prefix: NGROK_VAULT_MAIN_\n", `              - secret("main/PASSWORD")`))
	if err != nil {
		t.Fatalf("LoadConfiguration refused a config whose env vault resolves: %v", err)
	}
	if !requestWithBasicCreds(t, config, "web", "s3cret") {
		t.Fatal("the env-sourced value did not authenticate")
	}
}

func TestLoadConfigurationVaultErrors(t *testing.T) {
	t.Run("missing vault file is named", func(t *testing.T) {
		restoreVaults(t)
		_, err := loadConfig(t, vaultTunnelYAML("  main:\n    file: /nonexistent/vault.yml\n", `              - secret("main/alice")`))
		if err == nil || !strings.Contains(err.Error(), `failed to read vault file /nonexistent/vault.yml`) {
			t.Fatalf("LoadConfiguration = %v, want the missing vault file named", err)
		}
	})

	t.Run("missing key names vault and key", func(t *testing.T) {
		restoreVaults(t)
		vaultPath := filepath.Join(t.TempDir(), "vault.yml")
		if err := os.WriteFile(vaultPath, []byte("other: v\n"), 0600); err != nil {
			t.Fatalf("failed to write vault file: %v", err)
		}
		_, err := loadConfig(t, vaultTunnelYAML("  main:\n    file: "+vaultPath+"\n", `              - secret("main/alice")`))
		if err == nil || !strings.Contains(err.Error(), `vault "main" has no key "alice"`) {
			t.Fatalf("LoadConfiguration = %v, want the missing key naming vault and key", err)
		}
		if !strings.Contains(err.Error(), `Tunnel web`) {
			t.Fatalf("the error does not name the tunnel: %v", err)
		}
	})

	t.Run("a reference with no vaults block is a load error", func(t *testing.T) {
		restoreVaults(t)
		_, err := loadConfig(t, vaultTunnelYAML("", `              - secret("main/alice")`))
		if err == nil {
			t.Fatal("LoadConfiguration accepted a secret() reference with no vaults configured")
		}
		if !strings.Contains(err.Error(), `names vault "main", but no vaults are configured`) {
			t.Fatalf("the error does not say no vaults are configured: %v", err)
		}
	})

	t.Run("both source fields are refused", func(t *testing.T) {
		restoreVaults(t)
		_, err := loadConfig(t, vaultTunnelYAML("  main:\n    file: a.yml\n    env_prefix: P_\n", `              - secret("main/alice")`))
		if err == nil || !strings.Contains(err.Error(), `vault "main": file and env_prefix are alternatives`) {
			t.Fatalf("LoadConfiguration = %v, want the alternatives refusal", err)
		}
	})

	t.Run("a typo'd source key is refused", func(t *testing.T) {
		restoreVaults(t)
		_, err := loadConfig(t, vaultTunnelYAML("  main:\n    envprefix: P_\n", `              - secret("main/alice")`))
		if err == nil || !strings.Contains(err.Error(), `vault "main": one of file or env_prefix is required`) {
			t.Fatalf("LoadConfiguration = %v, want the missing-source refusal naming the vault (the typo'd key decodes to nothing)", err)
		}
	})
}

// TestLoadConfigurationVaultsAreHermetic is why loadVaults installs
// unconditionally: LoadConfiguration runs many times in one process (the
// tests, but also any future reload path), and a vault installed by one
// configuration must not satisfy the next one's references.
func TestLoadConfigurationVaultsAreHermetic(t *testing.T) {
	restoreVaults(t)

	vaultPath := filepath.Join(t.TempDir(), "vault.yml")
	if err := os.WriteFile(vaultPath, []byte("alice: alice:from-vault\n"), 0600); err != nil {
		t.Fatalf("failed to write vault file: %v", err)
	}
	if _, err := loadConfig(t, vaultTunnelYAML("  main:\n    file: "+vaultPath+"\n", `              - secret("main/alice")`)); err != nil {
		t.Fatalf("the vaulted config did not load: %v", err)
	}

	// a second config, same reference, no vaults block: the first config's
	// vault must not answer it -- and the failure is "no vaults are
	// configured", the state this config's own (empty) block defines
	_, err := loadConfig(t, vaultTunnelYAML("", `              - secret("main/alice")`))
	if err == nil {
		t.Fatal("the previous configuration's vaults leaked into a config without any")
	}
	if !strings.Contains(err.Error(), `no vaults are configured`) {
		t.Fatalf("the second config failed for the wrong reason: %v", err)
	}

	// and policy.SetVaults is exported state: make sure the empty reset did
	// not leave the package able to resolve from the first config
	if policy.Vaults().Len() != 0 {
		t.Fatalf("the installed set is not the empty one (Len=%d)", policy.Vaults().Len())
	}
}

// TestLoadConfigurationVaultlessConfigUnchanged pins the review gate that a
// config without vaults behaves exactly as before: nothing installed, nothing
// refused.
func TestLoadConfigurationVaultlessConfigUnchanged(t *testing.T) {
	restoreVaults(t)

	config, err := loadConfig(t, tunnelYAML(
		"    traffic_policy:",
		"      on_http_request:",
		"        - name: basic-auth",
		"          config:",
		"            credentials:",
		"              - alice:inline-pass",
	))
	if err != nil {
		t.Fatalf("LoadConfiguration refused a plain inline-credential policy: %v", err)
	}
	if !requestWithBasicCreds(t, config, "alice", "inline-pass") {
		t.Fatal("an inline credential stopped authenticating")
	}
	if policy.Vaults().Len() != 0 {
		t.Fatalf("a vaultless config installed vaults (Len=%d)", policy.Vaults().Len())
	}
}
