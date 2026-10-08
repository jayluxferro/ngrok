package bot

// Config tests (SPEC-CLUSTER20 testing strategy): the startup refusals, the
// env-over-file precedence for the two secrets, the defaults, and the secret
// masking on the startup log line. Each refusal test asserts the message
// names the fix, because an operator who cannot start the bot reads exactly
// one line before deciding what to do next.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ngrok-bot.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func mustLoad(t *testing.T, path string) *config {
	t.Helper()
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig refused a valid config: %v", err)
	}
	return cfg
}

func TestLoadConfigEnvOverridesFile(t *testing.T) {
	path := writeConfig(t, `
telegram_token: "111:file-token"
admin_url: "http://127.0.0.1:9090"
admin_token: "file-admin-token"
allowed_chats: [42]
`)
	t.Setenv(envTelegramToken, "222:env-token")
	t.Setenv(envAdminToken, "env-admin-token")

	cfg := mustLoad(t, path)
	if cfg.TelegramToken != "222:env-token" {
		t.Errorf("telegram token = %q, want the env value to win", cfg.TelegramToken)
	}
	if cfg.AdminToken != "env-admin-token" {
		t.Errorf("admin token = %q, want the env value to win", cfg.AdminToken)
	}
}

func TestLoadConfigFileTokenWithoutEnv(t *testing.T) {
	path := writeConfig(t, `
telegram_token: "111:file-token"
admin_url: "http://127.0.0.1:9090"
allowed_chats: [42]
`)
	// No env vars set (t.Setenv is not called): the file's token stands.
	cfg := mustLoad(t, path)
	if cfg.TelegramToken != "111:file-token" {
		t.Errorf("telegram token = %q, want the file value when no env override exists", cfg.TelegramToken)
	}
}

func TestLoadConfigRefusesEmptyAllowedChats(t *testing.T) {
	path := writeConfig(t, `
telegram_token: "111:abc"
admin_url: "http://127.0.0.1:9090"
`)
	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("LoadConfig accepted an empty allowed_chats: a bot that answers anyone is an ops-data leak")
	}
	if !strings.Contains(err.Error(), "allowed_chats") {
		t.Errorf("refusal %q does not name the offending key", err)
	}
}

func TestLoadConfigRefusesMissingTelegramToken(t *testing.T) {
	path := writeConfig(t, `
admin_url: "http://127.0.0.1:9090"
allowed_chats: [42]
`)
	_, err := LoadConfig(path)
	if err == nil || !strings.Contains(err.Error(), "telegram_token") {
		t.Fatalf("err = %v, want a refusal naming telegram_token", err)
	}
}

func TestLoadConfigRefusesBadAdminURLScheme(t *testing.T) {
	// URLs that parse with a non-http scheme get the scheme refusal.
	for _, bad := range []string{"ftp://127.0.0.1:9090", "file:///etc/passwd"} {
		path := writeConfig(t, `
telegram_token: "111:abc"
admin_url: "`+bad+`"
allowed_chats: [42]
`)
		_, err := LoadConfig(path)
		if err == nil {
			t.Fatalf("LoadConfig accepted admin_url %q", bad)
		}
		if !strings.Contains(err.Error(), "admin_url") || !strings.Contains(err.Error(), "http") {
			t.Errorf("refusal %q does not name admin_url and the allowed schemes", err)
		}
	}

	// A bare host:port does not even parse as a URL; the refusal still names
	// the key it came from.
	path := writeConfig(t, `
telegram_token: "111:abc"
admin_url: "127.0.0.1:9090"
allowed_chats: [42]
`)
	_, err := LoadConfig(path)
	if err == nil || !strings.Contains(err.Error(), "admin_url") {
		t.Fatalf("err = %v, want a refusal naming admin_url", err)
	}
}

func TestLoadConfigRefusesUnknownAlertEvent(t *testing.T) {
	path := writeConfig(t, `
telegram_token: "111:abc"
admin_url: "http://127.0.0.1:9090"
allowed_chats: [42]
alert_events: [auth_reject, auth_rejected]
`)
	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("LoadConfig accepted an unknown alert_events value: a typo can never fire, silence is the worst alert failure")
	}
	// Typo protection must be actionable: the valid set is in the message.
	if !strings.Contains(err.Error(), "auth_reject") || !strings.Contains(err.Error(), "rate_limit_drop") {
		t.Errorf("refusal %q does not name the valid set", err)
	}
}

func TestLoadConfigDefaults(t *testing.T) {
	path := writeConfig(t, `
telegram_token: "111:abc"
admin_url: "http://127.0.0.1:9090"
allowed_chats: [1, 2]
`)
	cfg := mustLoad(t, path)

	if cfg.TelegramAPI != "https://api.telegram.org" {
		t.Errorf("telegram_api default = %q", cfg.TelegramAPI)
	}
	got := map[string]bool{}
	for _, ev := range cfg.AlertEvents {
		got[ev] = true
	}
	want := defaultAlertEvents()
	if len(got) != len(want) {
		t.Fatalf("default alert set = %v, want %v", cfg.AlertEvents, want)
	}
	for _, ev := range want {
		if !got[ev] {
			t.Errorf("default alert set missing %q (got %v)", ev, cfg.AlertEvents)
		}
	}
	if cfg.HealthIntervalSeconds != 30 {
		t.Errorf("health_interval_seconds default = %d, want 30", cfg.HealthIntervalSeconds)
	}
	if cfg.CommandRatePerMin != 10 {
		t.Errorf("command_rate_per_min default = %d, want 10", cfg.CommandRatePerMin)
	}
	if cfg.CommandTimeoutSeconds != 10 {
		t.Errorf("command_timeout_seconds default = %d, want 10", cfg.CommandTimeoutSeconds)
	}
}

func TestLoadConfigNegativeValuesRefused(t *testing.T) {
	path := writeConfig(t, `
telegram_token: "111:abc"
admin_url: "http://127.0.0.1:9090"
allowed_chats: [42]
health_interval_seconds: -5
`)
	_, err := LoadConfig(path)
	if err == nil || !strings.Contains(err.Error(), "health_interval_seconds") {
		t.Fatalf("err = %v, want a refusal naming health_interval_seconds", err)
	}
}

func TestConfigStringMasksSecrets(t *testing.T) {
	cfg := &config{
		TelegramToken: "111:supersecret",
		AdminURL:      "http://127.0.0.1:9090",
		AdminToken:    "hush",
		AdminAuth:     "ops:letmein",
		AllowedChats:  []int64{42},
	}
	rendered := cfg.String()

	for _, secret := range []string{"supersecret", "hush", "letmein", "111:"} {
		if strings.Contains(rendered, secret) {
			t.Errorf("rendered config leaks %q:\n%s", secret, rendered)
		}
	}
	// The mask must say "configured", not "unset": an operator must be able
	// to tell a present secret from an absent one in the log.
	if !strings.Contains(rendered, "***") {
		t.Errorf("rendered config has no mask at all:\n%s", rendered)
	}
	for _, plain := range []string{"admin_url", "http://127.0.0.1:9090", "allowed_chats"} {
		if !strings.Contains(rendered, plain) {
			t.Errorf("rendered config lost non-secret field %q:\n%s", plain, rendered)
		}
	}
}

func TestDefaultConfigPath(t *testing.T) {
	t.Setenv("HOME", "/home/operator")
	if got, want := DefaultConfigPath(), "/home/operator/.ngrok-bot"; got != want {
		t.Errorf("DefaultConfigPath() = %q, want %q", got, want)
	}
}
