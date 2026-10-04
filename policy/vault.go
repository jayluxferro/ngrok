package policy

// Secret vaults (SPEC-CLUSTER9 3): named sets of credential entries that a
// traffic policy's credential values may reference instead of carrying inline,
// so a deployment can keep its credentials out of the policy document -- and,
// with pre-digested entries, out of plaintext on disk entirely.
//
// The syntax is `secret("vault/key")`, and it is valid in exactly one place:
// as a whole string value of an auth action's credential list (basic-auth's
// credentials, bearer-auth's tokens, apikey-auth's keys). It is not a CEL
// function and never appears mid-string -- resolution belongs at load time
// (the build*Auth constructors, via credentialList), because putting it on the
// request path would put the vault on the data path and credential material
// into ${...} interpolation output. issuer/audience and every other config
// string are comparison values, not secrets, and are not resolved.
//
// Where resolution runs: credentialList resolves entries through the vault set
// installed in this package, immediately before digestsOf -- the last step at
// which a credential is ever held as plaintext in this engine. Both sides of
// the protocol run that one code path: the client at configuration load
// (validateTrafficPolicy) and the server at registration (Compile). Each side
// resolves against the vaults its OWN configuration defines; a document that
// references a vault the other side does not have fails THERE, loudly, and the
// endpoint never comes up edge-enforced-less. The consequence is deliberate:
// the same document plus the same vaults yields the same compiled digests on
// both sides, which TestVaultBothSidesResolveIdentically pins.
//
// The installed set is process configuration, like the rest of the loaded
// config file: set once by SetVaults at load, before any document is validated
// or compiled, and read by every later Compile. (Making it a parameter of
// Compile/Validate instead would thread a fourth argument through every
// builder for a value each process has exactly one of; the load-once set is
// the honest shape of that.) With no vaults installed -- the state every
// process that did not configure any is in -- a secret(...) reference is a
// load error, never a fallback to the reference text as a literal credential:
// a credential that is silently the string `secret("main/key")` is one that
// matches no request and enforces nothing.

import (
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync/atomic"

	"gopkg.in/yaml.v3"

	"ngrok/log"
)

// VaultSource is one named vault's configuration, as it appears under the
// config file's vaults: block. It is the type both sides decode: the client's
// non-strict YAML and the server's strict decode (server config) share it, so
// that the two configurations speak one shape. Exactly one of the two fields
// must be set:
//
//	vaults:
//	  main:
//	    file: /etc/ngrok/vault.yml      # a YAML key: value map
//	  staging:
//	    env_prefix: NGROK_VAULT_MAIN_   # NGROK_VAULT_MAIN_PROD_API=<value>
type VaultSource struct {
	// File names a YAML file of flat `key: value` pairs. Values are plaintext
	// credentials, or `sha256:<hex>` pre-digested entries (the dual form
	// server/auth.go stores session tokens in): a deployment can keep only
	// digests on disk and never hold the plaintext at all. A missing file is a
	// load error naming it.
	File string `yaml:"file,omitempty"`

	// EnvPrefix sources the vault from every environment variable whose name
	// starts with the prefix; the key is the rest of the variable's name,
	// verbatim. The verbatim rule is why an env vault and a file vault are not
	// key-compatible: the environment cannot carry a hyphen, so the file key
	// `prod-api` and the env key `PROD_API` are two different keys, and a
	// reference names whichever spelling its vault produces.
	EnvPrefix string `yaml:"env_prefix,omitempty"`
}

// vaultSetModel is the on-disk shape of a file-backed vault: a flat
// key -> value map. Values may be plaintext or sha256:<hex> pre-digested.
type vaultSetModel map[string]string

// VaultSet is the loaded form of a configuration's vaults: block. Built once
// by LoadVaults, installed by SetVaults, and read by every later compile.
// Immutable after load.
type VaultSet struct {
	// vaults maps a vault's name to its key -> value entries. The values are
	// as stored: plaintext, or sha256:<hex> (recognizable by the prefix, and
	// hex-validated at load). Key names, never values, appear in errors.
	vaults map[string]vaultSetModel
}

// digestPrefix marks a pre-digested vault entry, the spelling -hashToken
// prints and server/auth.go stores.
const digestPrefix = "sha256:"

// LoadVaults loads every named source and returns the set they define. An
// empty or nil map yields an empty set -- not an error -- so that installing
// the result unconditionally (client LoadConfiguration does) also resets a
// previously installed set, which is what keeps the package's vaults exactly
// this configuration's across repeated loads in one process.
//
// Every failure is a load error naming the vault and, where one is involved,
// the file: a credential source that cannot be read must stop the start, not
// become a policy that fails at the first registration.
func LoadVaults(sources map[string]VaultSource) (*VaultSet, error) {
	set := &VaultSet{vaults: make(map[string]vaultSetModel, len(sources))}

	for _, name := range sortedVaultNames(sources) {
		src := sources[name]
		file, env := src.File != "", src.EnvPrefix != ""
		switch {
		case file && env:
			return nil, fmt.Errorf("vault %q: file and env_prefix are alternatives -- choose one, not both", name)
		case !file && !env:
			return nil, fmt.Errorf("vault %q: one of file or env_prefix is required", name)
		case file:
			entries, err := loadVaultFile(name, src.File)
			if err != nil {
				return nil, err
			}
			set.vaults[name] = entries
		default:
			entries, err := loadVaultEnv(name, src.EnvPrefix)
			if err != nil {
				return nil, err
			}
			set.vaults[name] = entries
		}
	}

	return set, nil
}

// sortedVaultNames orders the sources for deterministic errors: a config with
// two bad vaults has to report the same one every run (map iteration order
// would not).
func sortedVaultNames(sources map[string]VaultSource) []string {
	return sortedMapNames(sources)
}

// sortedMapNames orders a map's keys: every sorted list of names in this file
// (sources, vaults, keys) exists so that an error is the same on every run of
// the same config.
func sortedMapNames[V any](m map[string]V) []string {
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// loadVaultFile reads one file-backed vault: a YAML document of flat
// `key: value` pairs. An empty file (or one of only comments) defines an empty
// vault rather than an error: the file exists, which is the affirmative act;
// references to missing keys are the loud failures, and they name the empty
// vault (see resolveCredential). An entry value of sha256:<hex> is checked to
// be a real SHA-256 digest here -- a typo'd digest would otherwise be a
// credential that silently matches nothing.
func loadVaultFile(name, path string) (vaultSetModel, error) {
	log.Info("Reading vault file %s", path)

	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("vault %q: failed to read vault file %s: %v", name, path, err)
	}

	entries := vaultSetModel{}
	if err := yaml.Unmarshal(buf, &entries); err != nil {
		return nil, fmt.Errorf("vault %q: error parsing vault file %s: %v (the file is a flat map of key: value pairs)", name, path, err)
	}

	for _, key := range sortedMapNames(entries) {
		if err := checkVaultKey(name, key, fmt.Sprintf("vault file %s", path)); err != nil {
			return nil, err
		}
		if err := checkVaultValue(name, key, entries[key]); err != nil {
			return nil, err
		}
	}

	return entries, nil
}

// loadVaultEnv reads one environment-sourced vault: every variable whose name
// carries the prefix contributes key = name-without-prefix, verbatim. Unlike a
// file vault, a prefix that matches no variable also defines an empty vault
// rather than an error (the environment is allowed to provision nothing, and
// the HttpProxy fallback set the lenient precedent); a reference into the
// empty vault says so. Values are taken as they are: an empty value or one
// carrying a CR/LF is refused when a policy resolves it, which has the
// context (action, field, entry) the load here would not.
func loadVaultEnv(name, prefix string) (vaultSetModel, error) {
	entries := vaultSetModel{}
	for _, kv := range os.Environ() {
		v, value, found := strings.Cut(kv, "=")
		if !found || !strings.HasPrefix(v, prefix) {
			continue
		}
		key := strings.TrimPrefix(v, prefix)
		if key == "" {
			return nil, fmt.Errorf("vault %q: environment variable %q defines an empty key (env_prefix %q)", name, v, prefix)
		}
		if err := checkVaultKey(name, key, fmt.Sprintf("environment variable %q", v)); err != nil {
			return nil, err
		}
		if err := checkVaultValue(name, key, value); err != nil {
			return nil, err
		}
		entries[key] = value
	}

	return entries, nil
}

// checkVaultKey refuses a key the secret("vault/key") form could never name:
// an empty one (a YAML `: value` line or a variable named exactly the
// prefix), or one carrying a slash (the syntax splits on the one slash) or a
// quote (the syntax has no escapes). Such a key is dead weight that an
// operator would read as configured; the file or variable naming it says so
// instead.
func checkVaultKey(vault, key, where string) error {
	switch {
	case key == "":
		return fmt.Errorf("vault %q: an empty key from %s cannot be referenced (the secret(\"vault/key\") form needs a name on both sides of the \"/\")", vault, where)
	case strings.ContainsRune(key, '/'):
		return fmt.Errorf("vault %q: key %q from %s contains '/', which the secret(\"vault/key\") syntax cannot name (it splits vault and key on the one slash)", vault, key, where)
	case strings.ContainsAny(key, `"\`):
		return fmt.Errorf("vault %q: key %q from %s contains a quote or a backslash, which the secret(\"vault/key\") syntax cannot carry (it has no escapes)", vault, key, where)
	}
	return nil
}

// checkVaultValue validates a pre-digested entry: a value written
// sha256:<hex> must be a whole SHA-256 digest, because the only thing such an
// entry can mean is "compare against this digest", and a truncated or
// non-hex one would be a credential that silently matches nothing.
func checkVaultValue(vault, key, value string) error {
	if !strings.HasPrefix(value, digestPrefix) {
		return nil
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(value, digestPrefix))
	if err != nil || len(raw) != 32 {
		return fmt.Errorf("vault %q: key %q: %q is not a SHA-256 digest (want %q followed by 64 hex characters)", vault, key, value, digestPrefix)
	}
	return nil
}

// The installed set. Stored behind a pointer so that the Compile calls racing
// a test's re-install (or a server registering tunnels while nothing else
// runs -- the production case is store-once, read-many) read one coherent
// value. Production sets it once at configuration load.
var installed atomic.Pointer[VaultSet]

// SetVaults installs the process-wide vault set that secret("vault/key")
// references resolve against. Call it once, at configuration load, before any
// policy document is validated or compiled: the client's LoadConfiguration and
// the server's startup each do. A nil set is the honest "no vaults", and a
// reference in that state is a load error naming the reference.
func SetVaults(vs *VaultSet) {
	installed.Store(vs)
}

// Vaults reports the installed set, nil when none was installed. It exists so
// a caller (and the tests) can save and restore the set around their own
// installation instead of assuming there was none.
func Vaults() *VaultSet {
	return installed.Load()
}

// Len reports how many vaults the set defines. A set of length zero is the
// state every reference fails against; the count exists so a caller holding a
// set across packages (client tests, the server loader's tests) can see that
// state without this package's map.
func (vs *VaultSet) Len() int {
	if vs == nil {
		return 0
	}
	return len(vs.vaults)
}

// resolvedCredential is one credential-list entry after vault resolution: the
// form the comparison digest is taken from. A vault entry stored pre-digested
// carries digested set, and value then holds the stored hex -- digesting it
// again would compare the digest of a digest, which no request could ever
// produce. vault/key record the provenance for the error messages of the
// checks that run on the resolved value (credentialList's CR/LF and shape
// checks); an inline entry leaves both empty, which is what keeps its error
// messages exactly what they were.
type resolvedCredential struct {
	value    string
	digested bool
	vault    string
	key      string
}

// digest returns the comparison form of the entry (see the file comment in
// auth_actions.go for why the comparison runs on digests).
func (c resolvedCredential) digest() string {
	if c.digested {
		return c.value
	}
	return credentialDigest(c.value)
}

// The secret("vault/key") spelling, matched as whole bytes: the reference is
// the ENTIRE config value -- a value that merely contains secret(...) is a
// literal, which is also what makes a resolved value that itself contains one
// safe (resolution runs once and never re-scans its output).
const (
	secretRefCall   = "secret("
	secretRefQuote  = `secret("`
	secretRefClose  = `")`
	secretRefSyntax = `secret("vault/key")`
)

// resolveCredential turns one raw credential-list entry into its resolved
// form. A whole-value secret("vault/key") reference is looked up in the
// installed vaults; anything else is itself, unchanged, which is why a
// document with no references behaves byte-identically to before vaults
// existed.
func resolveCredential(s string) (resolvedCredential, error) {
	if !strings.HasPrefix(s, secretRefCall) {
		return resolvedCredential{value: s}, nil
	}

	vault, key, err := parseSecretRef(s)
	if err != nil {
		return resolvedCredential{}, err
	}

	vs := installed.Load()
	if vs == nil || len(vs.vaults) == 0 {
		return resolvedCredential{}, fmt.Errorf("%s names vault %q, but no vaults are configured (define one under the configuration's vaults: block)", secretRefSyntax, vault)
	}
	entries, ok := vs.vaults[vault]
	if !ok {
		return resolvedCredential{}, fmt.Errorf("no vault named %q is configured (configured vaults: %s)", vault, strings.Join(sortedMapNames(vs.vaults), ", "))
	}
	value, ok := entries[key]
	if !ok {
		return resolvedCredential{}, fmt.Errorf("vault %q has no key %q%s", vault, key, missingKeyNote(entries))
	}

	if strings.HasPrefix(value, digestPrefix) {
		// pre-digested: strip the marker and record it, so digestsOf passes
		// the stored hex through instead of digesting it again
		return resolvedCredential{value: strings.TrimPrefix(value, digestPrefix), digested: true, vault: vault, key: key}, nil
	}
	return resolvedCredential{value: value, vault: vault, key: key}, nil
}

// parseSecretRef parses the exact form secret("vault/key"): one slash
// separating a non-empty vault name and key, no quotes or backslashes inside
// (the syntax has no escapes and no nesting). Only strings that open with the
// call spelling get here, so every malformed variant -- secret("a"),
// secret("a/b/c"), secret(a/b), a missing closing quote -- is a load error
// saying what the exact form is, never a literal credential that would
// silently match nothing.
func parseSecretRef(s string) (vault, key string, err error) {
	if !strings.HasPrefix(s, secretRefQuote) || !strings.HasSuffix(s, secretRefClose) || len(s) < len(secretRefQuote)+len(secretRefClose)+1 {
		return "", "", fmt.Errorf("not a valid secret() reference: the exact form is %s (quoted, one \"/\" between vault and key)", secretRefSyntax)
	}

	content := s[len(secretRefQuote) : len(s)-len(secretRefClose)]
	if strings.ContainsAny(content, `"\\`) {
		return "", "", fmt.Errorf("not a valid secret() reference: %s carries no escapes, so the name may not contain a quote or a backslash", secretRefSyntax)
	}
	i := strings.Index(content, "/")
	if i < 0 {
		return "", "", fmt.Errorf("not a valid secret() reference: %q has no \"/\" between vault and key", content)
	}
	if strings.Contains(content[i+1:], "/") {
		return "", "", fmt.Errorf("not a valid secret() reference: %q has more than one \"/\" (vault/key, no nesting)", content)
	}
	if i == 0 {
		return "", "", fmt.Errorf("not a valid secret() reference: the vault name before \"/\" is empty in %q", content)
	}
	if i == len(content)-1 {
		return "", "", fmt.Errorf("not a valid secret() reference: the key after \"/\" is empty in %q", content)
	}

	return content[:i], content[i+1:], nil
}

// missingKeyNote is the diagnostic after "vault %q has no key %q": a missing
// key is either a typo in the reference or an under-provisioned vault, and the
// configured key names (never values) or the empty vault's source tell an
// operator which.
func missingKeyNote(entries vaultSetModel) string {
	if len(entries) > 0 {
		names := sortedMapNames(entries)
		if len(names) > 8 {
			names = append(names[:8], fmt.Sprintf("... and %d more", len(names)-8))
		}
		return fmt.Sprintf(" (configured keys: %s)", strings.Join(names, ", "))
	}

	// The set keeps what its sources produced, not the sources themselves, so
	// the empty-vault note describes the two shapes generically.
	return " (the vault is empty: check the vault file's keys or the env_prefix's variables)"
}

// ResolveSecretRef resolves a whole-value secret("vault/key") reference to
// its stored plaintext, for configuration values that need the literal
// string at use time -- an event destination's auth_header value is the one
// today. It shares the credential path's loudness (no vaults configured,
// unknown vault, unknown key are all errors naming both) but none of its
// digest handling: the value is returned as stored, because a header needs
// the string itself, not its digest. A string that is not a reference is
// returned unchanged, so callers need not pre-check the shape.
func ResolveSecretRef(s string) (string, error) {
	if !strings.HasPrefix(s, secretRefCall) {
		return s, nil
	}
	vault, key, err := parseSecretRef(s)
	if err != nil {
		return "", err
	}
	vs := installed.Load()
	if vs == nil || len(vs.vaults) == 0 {
		return "", fmt.Errorf("%s names vault %q, but no vaults are configured (define one under the configuration's vaults: block)", secretRefSyntax, vault)
	}
	entries, ok := vs.vaults[vault]
	if !ok {
		return "", fmt.Errorf("no vault named %q is configured (configured vaults: %s)", vault, strings.Join(sortedMapNames(vs.vaults), ", "))
	}
	value, ok := entries[key]
	if !ok {
		return "", fmt.Errorf("vault %q has no key %q%s", vault, key, missingKeyNote(entries))
	}
	return value, nil
}
