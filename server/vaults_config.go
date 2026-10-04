package server

// The server side of the secret vaults (SPEC-CLUSTER9 3): loading the ngrokd
// config file's vaults: block into package policy, so that tunnel
// registration -- where every agent-supplied traffic policy is compiled
// (NewTunnel -> TrafficPolicy.Compile) -- resolves secret("vault/key")
// references against the SERVER's own vaults, exactly as the client resolved
// them against its own at load. Both sides run the one resolution path in
// policy/credentialList; what each side may resolve with is what its own
// configuration declared.
//
// COORDINATION (SPEC-CLUSTER9 5, workstream ownership): server/config.go and
// cli.go belong to workstream B this cluster. B's event-destination work has
// landed in those files, but without a vaults: key -- so the wiring below is
// still pending, and it is two one-liners for whoever lands it:
//
//  1. on serverConfig (server/config.go), the strict-decoded block:
//
//	Vaults map[string]policy.VaultSource `yaml:"vaults"`
//
//     policy.VaultSource is deliberately the client's own type
//     (policy/vault.go: file | env_prefix), so both configurations speak one
//     shape and strict decode polices its keys (a typo'd env_prefix fails the
//     load, KnownFields(true)).
//
//  2. in cli.go's parseArgs, inside the `if *configPath != ""` block, right
//     after loadServerConfig succeeds (before eventDestinations is collected,
//     and before any tunnel can register):
//
//	if err := loadServerVaults(cfg.Vaults); err != nil {
//		fmt.Fprintln(os.Stderr, "Failed to load vaults:", err.Error())
//		os.Exit(1)
//	}
//
// That call is also the composition point B's validateAuthHeader comment in
// config.go anticipates: a future auth_header secret() resolution would run
// against the set loadServerVaults installs.
//
// Until the wiring lands, a policy referencing secret(...) fails server-side
// registration with "no vaults are configured" -- the correct loud state
// (SPEC-CLUSTER9 6 gate 3: no silent fallback), and no change for any config
// that does not use vaults.

import (
	"ngrok/policy"
)

// loadServerVaults loads the server's vaults and installs them as the
// process-wide set package policy resolves against. It mirrors the client's
// Configuration.loadVaults (client/config.go), including its reset semantics:
// installing the loaded set unconditionally means the process's vaults are
// exactly this configuration's, never a leftover.
func loadServerVaults(sources map[string]policy.VaultSource) error {
	vaults, err := policy.LoadVaults(sources)
	if err != nil {
		return err
	}
	policy.SetVaults(vaults)
	return nil
}
