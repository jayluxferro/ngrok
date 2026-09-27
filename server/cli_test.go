package server

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
)

// The command line, the config file and the flag defaults all want to set the
// same 20 options, and the rule that decides between them (explicit flag >
// config file > built-in default) used to be re-implemented once per option as
// `if !seen["x"] && ...`. These tests are about that rule, not about any one
// option, because the rule is where the bug was: nothing tested it, so nobody
// noticed that a config file which mentioned nothing about rate limits turned
// both rate limits off.

// parseServerArgs runs parseArgs with a private FlagSet, the way the client
// package's parseArgs test helper does. parseArgs works on the flag package's
// global state, so CommandLine and os.Args are swapped for the duration of the
// call and restored afterwards.
func parseServerArgs(t *testing.T, argv []string) *Options {
	t.Helper()

	prevCommandLine, prevArgs := flag.CommandLine, os.Args
	flag.CommandLine = flag.NewFlagSet(argv[0], flag.ContinueOnError)
	os.Args = argv
	defer func() {
		flag.CommandLine, os.Args = prevCommandLine, prevArgs
	}()

	return parseArgs()
}

func writeServerConfig(t *testing.T, contents string) string {
	t.Helper()

	configPath := filepath.Join(t.TempDir(), "ngrokd.yml")
	if err := os.WriteFile(configPath, []byte(contents), 0600); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}

	return configPath
}

// TestConfigFileLeavesUnsetOptionsAlone is the regression test for the rate
// limits going to zero. A config file that sets two unrelated keys must change
// exactly those two keys: everything else keeps the default the flag declares.
func TestConfigFileLeavesUnsetOptionsAlone(t *testing.T) {
	configPath := writeServerConfig(t, `
admin_addr: localhost:9002
log_level: INFO
`)

	opts := parseServerArgs(t, []string{"ngrokd", "-config", configPath})

	// The file never mentions any rate limit, so the flag defaults -- the only
	// thing standing between one IP and unbounded admin and auth attempts --
	// have to survive.
	if opts.adminRate != 120 {
		t.Errorf("adminRate: the config file does not set admin_rate, expected the flag default 120, got %d", opts.adminRate)
	}
	if opts.authRate != 60 {
		t.Errorf("authRate: the config file does not set auth_rate, expected the flag default 60, got %d", opts.authRate)
	}
	if opts.publicRate != 0 {
		t.Errorf("publicRate: expected 0, got %d", opts.publicRate)
	}
	if opts.maxConnPerIP != 0 {
		t.Errorf("maxConnPerIP: expected 0, got %d", opts.maxConnPerIP)
	}
	if opts.maxMsgBytes != 4*1024*1024 {
		t.Errorf("maxMsgBytes: expected the 4MiB default, got %d", opts.maxMsgBytes)
	}

	// ...and the keys the file does set are the ones that change.
	if opts.adminAddr != "localhost:9002" {
		t.Errorf("adminAddr: config file value ignored, got %q", opts.adminAddr)
	}
	if opts.loglevel != "INFO" {
		t.Errorf("loglevel: config file value ignored, got %q", opts.loglevel)
	}
	if opts.httpAddr != ":80" {
		t.Errorf("httpAddr: expected the flag default, got %q", opts.httpAddr)
	}
}

// TestConfigFileStillAllowsExplicitZero pins the other half of the sentinel:
// 0 is a real setting for a rate limit (it disables the limit), so the loader
// has to report "set to 0" differently from "absent". This is the case that a
// naive fix -- skipping zero values -- would break.
func TestConfigFileStillAllowsExplicitZero(t *testing.T) {
	configPath := writeServerConfig(t, "auth_rate: 0\n")

	opts := parseServerArgs(t, []string{"ngrokd", "-config", configPath})
	if opts.authRate != 0 {
		t.Errorf("authRate: the config file asked for 0 (disabled), expected 0, got %d", opts.authRate)
	}
	// A different limit that the file did not mention is untouched.
	if opts.adminRate != 120 {
		t.Errorf("adminRate: expected the flag default 120, got %d", opts.adminRate)
	}
}

// TestCommandLineBeatsConfigFile is the first half of the precedence rule: an
// explicit flag is the more specific statement of intent and wins.
func TestCommandLineBeatsConfigFile(t *testing.T) {
	configPath := writeServerConfig(t, `
http_addr: ":8080"
admin_rate: 11
auth_rate: 22
domain: from-config.example
auth_tokens:
  - token-from-config
`)

	opts := parseServerArgs(t, []string{
		"ngrokd",
		"-config", configPath,
		"-httpAddr", ":9999",
		"-adminRate", "7",
		"-authRate", "8",
		"-domain", "from-flag.example",
		"-authToken", "token-from-flag",
	})

	if opts.httpAddr != ":9999" {
		t.Errorf("httpAddr: explicit flag should win over the config file, got %q", opts.httpAddr)
	}
	if opts.adminRate != 7 {
		t.Errorf("adminRate: explicit flag should win, got %d", opts.adminRate)
	}
	if opts.authRate != 8 {
		t.Errorf("authRate: explicit flag should win, got %d", opts.authRate)
	}
	if opts.domain != "from-flag.example" {
		t.Errorf("domain: explicit flag should win, got %q", opts.domain)
	}
	if len(opts.authTokens) != 1 || opts.authTokens[0] != "token-from-flag" {
		t.Errorf("authTokens: expected only the flag token, got %v", opts.authTokens)
	}
}

// TestConfigFileBeatsFlagDefaults is the other half: when nothing on the
// command line competes, the file wins over the defaults.
func TestConfigFileBeatsFlagDefaults(t *testing.T) {
	configPath := writeServerConfig(t, `
http_addr: ":8080"
https_addr: ""
admin_rate: 11
max_msg_bytes: 1024
auth_tokens:
  - a
  - b
`)

	opts := parseServerArgs(t, []string{"ngrokd", "-config", configPath})

	if opts.httpAddr != ":8080" {
		t.Errorf("httpAddr: config file value ignored, got %q", opts.httpAddr)
	}
	if opts.adminRate != 11 {
		t.Errorf("adminRate: config file value ignored, got %d", opts.adminRate)
	}
	if opts.maxMsgBytes != 1024 {
		t.Errorf("maxMsgBytes: config file value ignored, got %d", opts.maxMsgBytes)
	}
	if len(opts.authTokens) != 2 || opts.authTokens[0] != "a" || opts.authTokens[1] != "b" {
		t.Errorf("authTokens: expected [a b] from the config file, got %v", opts.authTokens)
	}
	// An empty string in the file is not a statement: there is no way to
	// disable an address from the config file, only by passing the flag.
	if opts.httpsAddr != ":443" {
		t.Errorf("httpsAddr: an empty config value must not clear the flag default, got %q", opts.httpsAddr)
	}
}

// TestOverridesHelpers exercises the three-way rule directly, without going
// through flag.Parse: each helper is four lines, but the failure mode they
// exist to prevent (a value leaking through when it should not, or being
// dropped when it should not) is invisible from the outside.
func TestOverridesHelpers(t *testing.T) {
	t.Run("str", func(t *testing.T) {
		dst := "default"
		(overrides{}).str(&dst, "from-config", "flag")
		if dst != "from-config" {
			t.Errorf("expected the config value, got %q", dst)
		}

		dst = "default"
		(overrides{}).str(&dst, "", "flag")
		if dst != "default" {
			t.Errorf("an empty config value must be a no-op, got %q", dst)
		}

		dst = "explicit"
		(overrides{"flag": true}).str(&dst, "from-config", "flag")
		if dst != "explicit" {
			t.Errorf("an explicit flag must not be overridden, got %q", dst)
		}
	})

	t.Run("num", func(t *testing.T) {
		zero := 0
		five := 5

		dst := 120
		(overrides{}).num(&dst, nil, "flag")
		if dst != 120 {
			t.Errorf("an unset config value must be a no-op, got %d", dst)
		}

		(overrides{}).num(&dst, &zero, "flag")
		if dst != 0 {
			t.Errorf("an explicit 0 in the config file must be applied, got %d", dst)
		}

		dst = 120
		(overrides{}).num(&dst, &five, "flag")
		if dst != 5 {
			t.Errorf("expected the config value 5, got %d", dst)
		}

		dst = 7
		(overrides{"flag": true}).num(&dst, &five, "flag")
		if dst != 7 {
			t.Errorf("an explicit flag must not be overridden, got %d", dst)
		}
	})

	t.Run("positive", func(t *testing.T) {
		var dst int64 = 4 * 1024 * 1024
		(overrides{}).positive(&dst, 0, "flag")
		if dst != 4*1024*1024 {
			t.Errorf("0 means unset for this option, expected the default, got %d", dst)
		}

		(overrides{}).positive(&dst, 1024, "flag")
		if dst != 1024 {
			t.Errorf("expected 1024, got %d", dst)
		}
	})

	t.Run("yes", func(t *testing.T) {
		dst := false
		(overrides{}).yes(&dst, true, "pprof")
		if !dst {
			t.Error("expected pprof to be enabled by the config file")
		}

		dst = false
		(overrides{"pprof": true}).yes(&dst, true, "pprof")
		if dst {
			t.Error("an explicit flag must not be overridden")
		}
	})
}
