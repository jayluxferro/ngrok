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
// The wiring this file anticipated landed at cluster 9's review and is
// live: serverConfig carries the vaults: block (server/config.go) and cli.go
// installs it via loadServerVaults immediately after loadServerConfig --
// before any tunnel can register and before event destinations construct,
// which is what lets auth_header secret() references resolve against the
// same set at construction time.
//

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
