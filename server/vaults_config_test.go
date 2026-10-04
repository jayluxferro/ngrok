package server

// Tests for the server-side vault loading (SPEC-CLUSTER9 3): that
// loadServerVaults installs the loaded set so that policy compilation at
// registration -- the server's half of the resolution -- resolves
// secret("vault/key") references, and that its failures are the loud,
// vault-and-file-naming kind the client's are.
//
// The strict-decode half of the wiring (the serverConfig field and the call
// in cli.go) is workstream B's this cluster; see the file comment in
// vaults_config.go for the exact two lines that remain.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ngrok/policy"
)

func TestLoadServerVaultsInstallsForPolicyCompile(t *testing.T) {
	prev := policy.Vaults()
	t.Cleanup(func() { policy.SetVaults(prev) })

	vaultPath := filepath.Join(t.TempDir(), "vault.yml")
	if err := os.WriteFile(vaultPath, []byte("tok: tok-from-server-vault\n"), 0600); err != nil {
		t.Fatalf("failed to write vault file: %v", err)
	}
	if err := loadServerVaults(map[string]policy.VaultSource{"main": {File: vaultPath}}); err != nil {
		t.Fatalf("loadServerVaults: %v", err)
	}

	// the compile a registration runs (NewTunnel -> TrafficPolicy.Compile)
	doc := &policy.TrafficPolicy{
		OnHTTPRequest: []*policy.Action{{
			Name:   policy.ActionBearerAuth,
			Config: map[string]interface{}{"tokens": []interface{}{`secret("main/tok")`}},
		}},
	}
	if _, err := doc.Compile(); err != nil {
		t.Fatalf("the server could not compile a policy its own vault satisfies: %v", err)
	}

	// and a reference its vaults do NOT satisfy fails the registration
	// loudly, naming vault and key -- never an endpoint that enforces less
	missing := &policy.TrafficPolicy{
		OnHTTPRequest: []*policy.Action{{
			Name:   policy.ActionBearerAuth,
			Config: map[string]interface{}{"tokens": []interface{}{`secret("main/nope")`}},
		}},
	}
	_, err := missing.Compile()
	if err == nil || !strings.Contains(err.Error(), `vault "main" has no key "nope"`) {
		t.Fatalf("Compile = %v, want the missing key naming vault and key", err)
	}
}

func TestLoadServerVaultsErrors(t *testing.T) {
	prev := policy.Vaults()
	t.Cleanup(func() { policy.SetVaults(prev) })

	if err := loadServerVaults(map[string]policy.VaultSource{"v": {File: "/nonexistent/vault.yml"}}); err == nil ||
		!strings.Contains(err.Error(), `failed to read vault file /nonexistent/vault.yml`) {
		t.Fatalf("loadServerVaults = %v, want the missing file named", err)
	}

	if err := loadServerVaults(map[string]policy.VaultSource{"v": {}}); err == nil ||
		!strings.Contains(err.Error(), `vault "v": one of file or env_prefix is required`) {
		t.Fatalf("loadServerVaults = %v, want the missing-source refusal", err)
	}

	// a failed load must not leave a half-installed set behind: the next
	// registration has to fail against what was there before (here: nothing)
	if got := policy.Vaults().Len(); got != 0 {
		t.Fatalf("a failed load installed %d vaults", got)
	}
}

func TestLoadServerVaultsEnvSource(t *testing.T) {
	prev := policy.Vaults()
	t.Cleanup(func() { policy.SetVaults(prev) })

	t.Setenv("NGROKD_VAULT_TOK", "tok-from-env")
	if err := loadServerVaults(map[string]policy.VaultSource{"main": {EnvPrefix: "NGROKD_VAULT_"}}); err != nil {
		t.Fatalf("loadServerVaults: %v", err)
	}

	doc := &policy.TrafficPolicy{
		OnHTTPRequest: []*policy.Action{{
			Name:   policy.ActionBearerAuth,
			Config: map[string]interface{}{"tokens": []interface{}{`secret("main/TOK")`}},
		}},
	}
	if _, err := doc.Compile(); err != nil {
		t.Fatalf("the env-sourced vault did not resolve: %v", err)
	}
}
