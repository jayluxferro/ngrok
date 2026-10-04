package policy

// Tests for the secret vaults (SPEC-CLUSTER9 3): the secret("vault/key")
// resolution table of 3.4, plus the both-sides equivalence pin -- the same
// document over the same vaults must produce the same compiled digests
// whether the client built it at load or the server compiled it at
// registration.
//
// Every test installs its own vault set and restores whatever was installed
// before it: the installed set is package state (vault.go explains why), and
// the tests would otherwise order-depend on each other.

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"ngrok/rewriter"
)

// installVaults loads sources and installs them for the duration of the test,
// restoring the previous set afterwards.
func installVaults(t *testing.T, sources map[string]VaultSource) {
	t.Helper()
	prev := Vaults()
	vs, err := LoadVaults(sources)
	if err != nil {
		t.Fatalf("LoadVaults: %v", err)
	}
	SetVaults(vs)
	t.Cleanup(func() { SetVaults(prev) })
}

// writeVaultFile writes a vault file and returns its path.
func writeVaultFile(t *testing.T, entries map[string]string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vault.yml")
	buf := ""
	for key, value := range entries {
		buf += key + ": " + value + "\n"
	}
	if err := os.WriteFile(path, []byte(buf), 0600); err != nil {
		t.Fatalf("failed to write vault file: %v", err)
	}
	return path
}

// mainVaultSources writes the vault file most of the table runs against, with
// the shared entries plus any extra ones a case needs.
func mainVaultSources(t *testing.T, extra map[string]string) map[string]VaultSource {
	t.Helper()
	entries := map[string]string{
		"alpha":    "tok-alpha",
		"digested": "sha256:" + credentialDigest("tok-digested"),
		"literal":  `secret("main/alpha")`,
	}
	for k, v := range extra {
		entries[k] = v
	}
	return map[string]VaultSource{"main": {File: writeVaultFile(t, entries)}}
}

// bearerDoc is a one-rule bearer-auth policy over the given token entries.
func bearerDoc(tokens ...string) *TrafficPolicy {
	items := make([]interface{}, len(tokens))
	for i, tok := range tokens {
		items[i] = tok
	}
	return reqPolicy(rule(ActionBearerAuth, nil, map[string]interface{}{"tokens": items}))
}

// bearerHook compiles doc and returns the request hook, the same
// Compiled.RequestHook call the server's Tunnel.join makes.
func bearerHook(t *testing.T, doc *TrafficPolicy) func(*http.Request) *rewriter.RequestVerdict {
	t.Helper()
	c, lg := compileRequest(t, doc)
	return c.RequestHook(lg, "1.2.3.4:1")
}

// presentedAsToken admits-or-refuses: the verdict for a request whose
// Authorization carries the given bearer token.
func presentedAsToken(hook func(*http.Request) *rewriter.RequestVerdict, tok string) bool {
	return hook(get("/", map[string]string{"Authorization": "Bearer " + tok})) == nil
}

func TestVaultResolvesFileSource(t *testing.T) {
	installVaults(t, mainVaultSources(t, nil))
	hook := bearerHook(t, bearerDoc(`secret("main/alpha")`))

	if !presentedAsToken(hook, "tok-alpha") {
		t.Fatal("the vault-sourced token was refused: the reference did not resolve")
	}
	if presentedAsToken(hook, "tok-wrong") {
		t.Fatal("a wrong token was admitted")
	}
	// and the reference text itself is not a credential anyone can send
	if presentedAsToken(hook, `secret("main/alpha")`) {
		t.Fatal("the reference text itself was admitted: resolution replaced nothing")
	}
}

func TestVaultResolvesEnvSource(t *testing.T) {
	t.Setenv("NGROK_VAULT_MAIN_PROD_API", "tok-from-env")
	installVaults(t, map[string]VaultSource{"envv": {EnvPrefix: "NGROK_VAULT_MAIN_"}})
	hook := bearerHook(t, bearerDoc(`secret("envv/PROD_API")`))

	// the key is the variable's name minus the prefix, verbatim: the
	// environment cannot carry a hyphen, so the key is PROD_API
	if !presentedAsToken(hook, "tok-from-env") {
		t.Fatal("the env-sourced token was refused: the reference did not resolve")
	}
}

func TestVaultPreDigestedEntryRoundTrips(t *testing.T) {
	installVaults(t, mainVaultSources(t, nil))
	hook := bearerHook(t, bearerDoc(`secret("main/digested")`))

	if !presentedAsToken(hook, "tok-digested") {
		t.Fatal("the plaintext of a pre-digested vault entry was refused: the sha256: form did not survive the round trip")
	}

	// and what the compiled policy holds is exactly the stored digest -- not
	// the digest of the digest (which is what a resolver that ignored the
	// sha256: prefix would produce)
	c, _ := compileRequest(t, bearerDoc(`secret("main/digested")`))
	a, ok := c.request[0].auth.(*bearerAuthAction)
	if !ok {
		t.Fatalf("the compiled rule is %T, want *bearerAuthAction", c.request[0].auth)
	}
	if want := credentialDigest("tok-digested"); !reflect.DeepEqual(a.digests, []string{want}) {
		t.Fatalf("compiled digests = %v, want the digest of the plaintext (%s)", a.digests, want)
	}
}

func TestVaultNoDoubleResolution(t *testing.T) {
	// the vault entry "literal" is itself secret("main/alpha"): resolution
	// runs once, so the credential IS that text, and the value it names is
	// NOT reachable through it
	installVaults(t, mainVaultSources(t, nil))
	hook := bearerHook(t, bearerDoc(`secret("main/literal")`))

	if !presentedAsToken(hook, `secret("main/alpha")`) {
		t.Fatal("the literal text was not admitted: a resolved value was re-resolved")
	}
	if presentedAsToken(hook, "tok-alpha") {
		t.Fatal("the value the literal names was admitted: double resolution")
	}
}

func TestVaultMixedInlineAndVaultList(t *testing.T) {
	installVaults(t, mainVaultSources(t, nil))
	hook := bearerHook(t, bearerDoc("inline-tok", `secret("main/alpha")`))

	if !presentedAsToken(hook, "inline-tok") {
		t.Fatal("the inline entry stopped working next to a vault entry")
	}
	if !presentedAsToken(hook, "tok-alpha") {
		t.Fatal("the vault entry stopped working next to an inline entry")
	}
	if presentedAsToken(hook, "tok-neither") {
		t.Fatal("an unconfigured token was admitted")
	}
}

func TestVaultResolutionErrors(t *testing.T) {
	cases := []struct {
		name    string
		ref     string
		sources func(t *testing.T) map[string]VaultSource
		want    string // a substring of the load error
	}{
		{
			name:    "missing vault",
			ref:     `secret("nowhere/k")`,
			sources: func(t *testing.T) map[string]VaultSource { return mainVaultSources(t, nil) },
			want:    `no vault named "nowhere" is configured (configured vaults: main)`,
		},
		{
			name:    "missing key names vault and key",
			ref:     `secret("main/prod-api")`,
			sources: func(t *testing.T) map[string]VaultSource { return mainVaultSources(t, nil) },
			want:    `vault "main" has no key "prod-api" (configured keys: alpha, digested, literal)`,
		},
		{
			name: "no vaults installed at all",
			ref:  `secret("main/k")`,
			sources: func(t *testing.T) map[string]VaultSource {
				return nil // installed as an empty set below
			},
			want: `no vaults are configured (define one under the configuration's vaults: block)`,
		},
		{
			name: "empty vault",
			ref:  `secret("empty/k")`,
			sources: func(t *testing.T) map[string]VaultSource {
				return map[string]VaultSource{"empty": {File: writeVaultFile(t, nil)}}
			},
			want: `vault "empty" has no key "k" (the vault is empty`,
		},
		{
			name: "vault name without a key",
			ref:  `secret("main")`,
			sources: func(t *testing.T) map[string]VaultSource {
				return mainVaultSources(t, nil)
			},
			want: `"main" has no "/" between vault and key`,
		},
		{
			name:    "two slashes",
			ref:     `secret("a/b/c")`,
			sources: func(t *testing.T) map[string]VaultSource { return mainVaultSources(t, nil) },
			want:    `has more than one "/" (vault/key, no nesting)`,
		},
		{
			name:    "unquoted",
			ref:     `secret(main/alpha)`,
			sources: func(t *testing.T) map[string]VaultSource { return mainVaultSources(t, nil) },
			want:    `not a valid secret() reference: the exact form is secret("vault/key")`,
		},
		{
			name:    "trailing junk after the close",
			ref:     `secret("main/alpha") nope`,
			sources: func(t *testing.T) map[string]VaultSource { return mainVaultSources(t, nil) },
			want:    `not a valid secret() reference: the exact form is secret("vault/key")`,
		},
		{
			name:    "single quotes",
			ref:     `secret('main/alpha')`,
			sources: func(t *testing.T) map[string]VaultSource { return mainVaultSources(t, nil) },
			want:    `not a valid secret() reference: the exact form is secret("vault/key")`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.sources != nil {
				sources := tc.sources(t)
				if sources == nil {
					// the "no vaults installed" case: an explicitly empty set
					prev := Vaults()
					SetVaults(&VaultSet{vaults: map[string]vaultSetModel{}})
					t.Cleanup(func() { SetVaults(prev) })
				} else {
					installVaults(t, sources)
				}
			}

			err := bearerDoc(tc.ref).Validate()
			if err == nil {
				t.Fatalf("Validate accepted %s: the reference resolved when it must not", tc.ref)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error does not say what failed.\n got: %v\nwant substring: %s", err, tc.want)
			}
			// the load error carries the rule's identity, so an operator can
			// find the entry in their document
			if !strings.Contains(err.Error(), `on_http_request[0] (bearer-auth): config field "tokens" entry 0`) {
				t.Fatalf("error does not name the rule and entry: %v", err)
			}
		})
	}

	t.Run("a value that merely contains secret(...) is a literal, not a reference", func(t *testing.T) {
		installVaults(t, mainVaultSources(t, nil))
		// no spaces: a bearer credential cannot carry any, and this case is
		// about resolution, not the header grammar
		const literal = `prefix-secret("main/alpha")-suffix`
		hook := bearerHook(t, bearerDoc(literal))
		if !presentedAsToken(hook, literal) {
			t.Fatal("the mid-string spelling was resolved; only whole-value references resolve")
		}
		if presentedAsToken(hook, "tok-alpha") {
			t.Fatal("the value the mid-string spelling names was admitted")
		}
	})
}

func TestVaultRefusesCRAndLFPostResolution(t *testing.T) {
	// the CR/LF refusal must hold for a value the vault produced, not just
	// for an inline literal: build the case through the real loader (a YAML
	// double-quoted scalar is how a line break gets into a vault value)
	path := filepath.Join(t.TempDir(), "vault.yml")
	if err := os.WriteFile(path, []byte("bad: \"line1\\nline2\"\n"), 0600); err != nil {
		t.Fatalf("failed to write vault file: %v", err)
	}
	installVaults(t, map[string]VaultSource{"main": {File: path}})

	err := bearerDoc(`secret("main/bad")`).Validate()
	if err == nil {
		t.Fatal("Validate admitted a credential whose vault value carries an LF")
	}
	const want = `entry 0 (vault "main" key "bad") contains a CR or LF, which no credential should carry (header injection)`
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error does not name the provenance and the rule.\n got: %v\nwant substring: %s", err, want)
	}
}

func TestVaultBasicAuthSeparatorAppliesPostResolution(t *testing.T) {
	path := writeVaultFile(t, map[string]string{"alice": "alice:vaultpass", "nocolon": "no-colon-here"})
	installVaults(t, map[string]VaultSource{"main": {File: path}})

	t.Run("a well-shaped vault value authenticates", func(t *testing.T) {
		doc := reqPolicy(rule(ActionBasicAuth, nil, map[string]interface{}{
			"credentials": []interface{}{`secret("main/alice")`},
		}))
		c, lg := compileRequest(t, doc)
		hook := c.RequestHook(lg, "1.2.3.4:1")
		admitted(t, hook(get("/", map[string]string{
			"Authorization": "Basic " + basicCreds("alice", "vaultpass"),
		})))
	})

	t.Run("a vault value without the separator is refused, naming the vault", func(t *testing.T) {
		doc := reqPolicy(rule(ActionBasicAuth, nil, map[string]interface{}{
			"credentials": []interface{}{`secret("main/nocolon")`},
		}))
		err := doc.Validate()
		const want = `entry 0 (vault "main" key "nocolon") is not "user:password"-shaped: a ":" separator is required`
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("Validate = %v, want the separator refusal naming the provenance (%s...)", err, want[:60])
		}
	})
}

func TestVaultLoadVaultsErrors(t *testing.T) {
	t.Run("both source fields", func(t *testing.T) {
		_, err := LoadVaults(map[string]VaultSource{"v": {File: "a.yml", EnvPrefix: "P_"}})
		if err == nil || !strings.Contains(err.Error(), `vault "v": file and env_prefix are alternatives -- choose one, not both`) {
			t.Fatalf("LoadVaults = %v, want the alternatives refusal", err)
		}
	})

	t.Run("neither source field", func(t *testing.T) {
		_, err := LoadVaults(map[string]VaultSource{"v": {}})
		if err == nil || !strings.Contains(err.Error(), `vault "v": one of file or env_prefix is required`) {
			t.Fatalf("LoadVaults = %v, want the missing-source refusal", err)
		}
	})

	t.Run("missing file is named", func(t *testing.T) {
		_, err := LoadVaults(map[string]VaultSource{"v": {File: "/nonexistent/vault.yml"}})
		if err == nil || !strings.Contains(err.Error(), `vault "v": failed to read vault file /nonexistent/vault.yml`) {
			t.Fatalf("LoadVaults = %v, want the missing file named", err)
		}
	})

	t.Run("a bad sha256 entry is refused at load", func(t *testing.T) {
		path := writeVaultFile(t, map[string]string{"bad": "sha256:nothex"})
		_, err := LoadVaults(map[string]VaultSource{"v": {File: path}})
		if err == nil || !strings.Contains(err.Error(), `key "bad": "sha256:nothex" is not a SHA-256 digest`) {
			t.Fatalf("LoadVaults = %v, want the digest check", err)
		}
	})

	t.Run("a key with a slash can never be referenced", func(t *testing.T) {
		path := writeVaultFile(t, map[string]string{"a/b": "v"})
		_, err := LoadVaults(map[string]VaultSource{"v": {File: path}})
		if err == nil || !strings.Contains(err.Error(), `which the secret("vault/key") syntax cannot name`) {
			t.Fatalf("LoadVaults = %v, want the unreachable-key refusal", err)
		}
	})

	t.Run("an env variable named exactly the prefix", func(t *testing.T) {
		t.Setenv("NGROK_VAULT_EMPTY_", "value")
		_, err := LoadVaults(map[string]VaultSource{"v": {EnvPrefix: "NGROK_VAULT_EMPTY_"}})
		if err == nil || !strings.Contains(err.Error(), `defines an empty key`) {
			t.Fatalf("LoadVaults = %v, want the empty-key refusal", err)
		}
	})

	t.Run("a file entry with an empty key", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "vault.yml")
		// `"": value` is how YAML spells an empty key (a bare `: value` is
		// not a mapping at all and fails the parse instead)
		if err := os.WriteFile(path, []byte("\"\": value\n"), 0600); err != nil {
			t.Fatalf("failed to write vault file: %v", err)
		}
		_, err := LoadVaults(map[string]VaultSource{"v": {File: path}})
		if err == nil || !strings.Contains(err.Error(), `an empty key from vault file`) {
			t.Fatalf("LoadVaults = %v, want the empty-key refusal", err)
		}
	})

	t.Run("an empty source set loads to an empty set", func(t *testing.T) {
		vs, err := LoadVaults(nil)
		if err != nil || vs == nil || len(vs.vaults) != 0 {
			t.Fatalf("LoadVaults(nil) = %v, %v; want an empty set and no error", vs, err)
		}
	})
}

// TestVaultBothSidesResolveIdentically is SPEC-CLUSTER9 3.4's equivalence pin:
// the client validates the document at load and the server compiles it at
// registration, each against its own installed vaults. Same document, same
// vaults -- the pin is that the compiled digests are identical, which is the
// property "an endpoint authenticates the same way wherever it was built"
// reduces to. The "server" half travels the way registration really does: the
// document is serialized into a ReqTunnel and decoded back out of it.
func TestVaultBothSidesResolveIdentically(t *testing.T) {
	path := writeVaultFile(t, map[string]string{"alice": "alice:vaultpass"})
	installVaults(t, map[string]VaultSource{"main": {File: path}})

	doc := reqPolicy(rule(ActionBasicAuth, nil, map[string]interface{}{
		"credentials": []interface{}{`secret("main/alice")`},
	}))

	// client side: load-time validation (what LoadConfiguration runs) and the
	// compile the client itself does of the policy it is about to send
	if err := doc.Validate(); err != nil {
		t.Fatalf("client-side validation refused the document: %v", err)
	}
	client, err := doc.Compile()
	if err != nil {
		t.Fatalf("client-side compile: %v", err)
	}

	// server side: the document as it arrives in the registration
	wire, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("failed to serialize the policy: %v", err)
	}
	var received TrafficPolicy
	if err := json.Unmarshal(wire, &received); err != nil {
		t.Fatalf("the serialized policy does not decode: %v", err)
	}
	server, err := received.Compile()
	if err != nil {
		t.Fatalf("server-side compile: %v", err)
	}

	clientDigests := authDigestsOf(t, client)
	serverDigests := authDigestsOf(t, server)
	if !reflect.DeepEqual(clientDigests, serverDigests) {
		t.Fatalf("the two sides compiled different digests:\n client: %v\n server: %v", clientDigests, serverDigests)
	}
	if want := credentialDigest("alice:vaultpass"); !reflect.DeepEqual(serverDigests, []string{want}) {
		t.Fatalf("digests = %v, want the digest of the vault value (%s)", serverDigests, want)
	}

	// and the behavior agrees: both hooks answer the same request the same way
	for _, side := range []struct {
		name string
		c    *Compiled
	}{{"client", client}, {"server", server}} {
		hook := side.c.RequestHook(&testLogger{}, "1.2.3.4:1")
		admitted(t, hook(get("/", map[string]string{
			"Authorization": "Basic " + basicCreds("alice", "vaultpass"),
		})))
		terminated(t, hook(get("/", map[string]string{
			"Authorization": "Basic " + basicCreds("alice", "wrong"),
		})))
	}
}

// authDigestsOf digs the credential digests out of a compiled one-rule
// basic-auth policy.
func authDigestsOf(t *testing.T, c *Compiled) []string {
	t.Helper()
	if len(c.request) != 1 {
		t.Fatalf("the compiled policy has %d request rules, want 1", len(c.request))
	}
	a, ok := c.request[0].auth.(*basicAuthAction)
	if !ok {
		t.Fatalf("the rule is %T, want *basicAuthAction", c.request[0].auth)
	}
	return a.digests
}
