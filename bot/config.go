package bot

// Configuration (SPEC-CLUSTER20 §1). A single YAML document, loaded before
// anything else in the process runs; every rule it enforces is loud here or
// not at all. The rules exist because the bot holds ngrokd admin credentials
// and Telegram identity in one process, so a config that defaults wrong
// defaults dangerous: an empty allowlist would answer strangers with ops
// data, and a mistyped event name would silently silence exactly the alert
// the operator asked for.

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Environment variables that override the file's two secrets. Env wins over
// file because a secret checked into a config file outlives every rotation
// policy the operator meant to have; the env override lets a deployment keep
// the tokens out of the document entirely (and out of backups of it).
const (
	envTelegramToken = "NGROK_BOT_TELEGRAM_TOKEN"
	envAdminToken    = "NGROK_BOT_ADMIN_TOKEN"
)

// config is the YAML shape. Field types are the JSON/YAML scalars the file
// documents; there is deliberately no per-key flag, because a credential in
// argv is visible in `ps` to every process on the host.
type config struct {
	TelegramToken string   `yaml:"telegram_token"`
	TelegramAPI   string   `yaml:"telegram_api"`
	AdminURL      string   `yaml:"admin_url"`
	AdminToken    string   `yaml:"admin_token"`
	AdminAuth     string   `yaml:"admin_auth"`
	AllowedChats  []int64  `yaml:"allowed_chats"`
	AlertEvents   []string `yaml:"alert_events"`

	HealthIntervalSeconds int `yaml:"health_interval_seconds"`
	CommandRatePerMin     int `yaml:"command_rate_per_min"`
	CommandTimeoutSeconds int `yaml:"command_timeout_seconds"`
}

// LoadConfig reads and validates the document at path. Everything it refuses,
// it refuses with a message that names the fix: the operator reads this at
// boot, once, usually under pressure.
func LoadConfig(path string) (*config, error) {
	raw, err := os.ReadFile(path) // the one file read of the process (plus -log)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

	cfg := &config{}
	if err := yaml.Unmarshal(raw, cfg); err != nil {
		return nil, fmt.Errorf("parsing config %s: %w", path, err)
	}
	cfg.applyDefaults()

	// Env overrides the file for the two secrets (see the constants above).
	if v := os.Getenv(envTelegramToken); v != "" {
		cfg.TelegramToken = v
	}
	if v := os.Getenv(envAdminToken); v != "" {
		cfg.AdminToken = v
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// applyDefaults fills the keys whose zero value is not the documented
// default. Everything left zero after this is either a required key
// (validate's job) or genuinely optional with an off default.
func (c *config) applyDefaults() {
	if c.TelegramAPI == "" {
		c.TelegramAPI = "https://api.telegram.org"
	}
	if len(c.AlertEvents) == 0 {
		c.AlertEvents = defaultAlertEvents()
	}
	if c.HealthIntervalSeconds == 0 {
		c.HealthIntervalSeconds = 30
	}
	if c.CommandRatePerMin == 0 {
		c.CommandRatePerMin = 10
	}
	if c.CommandTimeoutSeconds == 0 {
		c.CommandTimeoutSeconds = 10
	}
}

// validate enforces the startup rules in the order an operator can act on
// them: identity first, then what it talks to, then behavior.
func (c *config) validate() error {
	if c.TelegramToken == "" {
		return errors.New("telegram_token is empty: set it in the config file or " + envTelegramToken)
	}

	// allowed_chats empty = refuse to start, not "allow everyone later": a bot
	// that answers anyone is an ops-data leak, and fail-closed is the only
	// correct default for a process holding admin credentials.
	if len(c.AllowedChats) == 0 {
		return errors.New("allowed_chats is empty: the bot refuses to answer anyone; list at least one chat id")
	}

	u, err := url.Parse(c.AdminURL)
	if err != nil {
		return fmt.Errorf("admin_url %q does not parse: %v", c.AdminURL, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("admin_url %q must use the http or https scheme", c.AdminURL)
	}
	if u.Host == "" {
		return fmt.Errorf("admin_url %q has no host", c.AdminURL)
	}

	// Typo protection on the alert vocabulary: config-time strict, because a
	// name unknown now can never fire. Runtime stays tolerant (see
	// formatEvent) because a newer ngrokd may legitimately emit types this
	// build has not heard of -- that crosses a wire the bot does not version.
	known := knownEventTypes()
	for _, ev := range c.AlertEvents {
		if !known[ev] {
			return fmt.Errorf("unknown alert_events value %q: valid values are %s", ev, joinSorted(known))
		}
	}

	if c.HealthIntervalSeconds < 0 {
		return errors.New("health_interval_seconds must be >= 0 (0 disables the watcher)")
	}
	if c.CommandRatePerMin < 0 {
		return errors.New("command_rate_per_min must be >= 0 (0 disables the budget)")
	}
	if c.CommandTimeoutSeconds < 0 {
		return errors.New("command_timeout_seconds must be >= 0")
	}
	return nil
}

// String renders the config for the startup log line with both secrets
// masked. A config that logs its own tokens puts them in every log shipper
// the operator runs; the masking is tested, not conventional.
func (c *config) String() string {
	masked := *c
	masked.TelegramToken = mask(c.TelegramToken)
	masked.AdminToken = mask(c.AdminToken)
	// admin_auth is user:password -- the password half is the secret.
	if masked.AdminAuth != "" {
		if i := strings.IndexByte(masked.AdminAuth, ':'); i >= 0 {
			masked.AdminAuth = masked.AdminAuth[:i+1] + "***"
		} else {
			masked.AdminAuth = "***"
		}
	}
	masked.AllowedChats = append([]int64(nil), c.AllowedChats...)
	masked.AlertEvents = append([]string(nil), c.AlertEvents...)

	out, err := yaml.Marshal(&masked)
	if err != nil {
		// Marshal of this struct cannot fail, but a masking bug must never
		// become a panic at boot: the fallback prints nothing secret-shaped.
		return "(config failed to render; not logging raw)"
	}
	return strings.TrimRight(string(out), "\n")
}

// mask replaces a non-empty secret with *** so the masked value still says
// "something was configured here" (an empty string would read as "unset").
func mask(s string) string {
	if s == "" {
		return ""
	}
	return "***"
}

// DefaultConfigPath is where -config with no argument looks, matching how the
// other binaries treat $HOME as the home of their dotfile.
func DefaultConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".ngrok-bot")
}

func joinSorted(set map[string]bool) string {
	names := make([]string, 0, len(set))
	for name := range set {
		names = append(names, name)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}
