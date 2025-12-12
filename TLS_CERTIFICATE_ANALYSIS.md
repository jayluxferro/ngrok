# TLS Certificate Build-Time Dependency Analysis

## Current Situation

### Why Certificates Are Required at Build Time

1. **Asset Embedding Process:**
   - The Makefile runs `go-bindata` which embeds ALL files from `assets/client/...` into the binary
   - This includes the TLS certificates in `assets/client/tls/`:
     - `ngrokroot.crt` (required for release builds)
     - `snakeoilca.crt` (required for debug builds)
   - The certificates are embedded as Go code in `client/assets/assets_*.go`

2. **Runtime Certificate Loading:**
   - `client/debug.go` defines: `rootCrtPaths = []string{"assets/client/tls/ngrokroot.crt", "assets/client/tls/snakeoilca.crt"}`
   - `client/release.go` defines: `rootCrtPaths = []string{"assets/client/tls/ngrokroot.crt"}`
   - `client/model.go` calls `LoadTLSConfig(rootCrtPaths)` unless `TrustHostRootCerts: true`
   - `LoadTLSConfig()` in `client/tls.go` loads certificates via `assets.Asset(certPath)`
   - If certificates are missing, `LoadTLSConfig()` returns an error and the code **panics**

3. **Build-Time Dependency Chain:**
   ```
   make client
     → make deps
       → make assets
         → make client-assets
           → go-bindata assets/client/...
             → REQUIRES assets/client/tls/*.crt files to exist
   ```

## Options to Remove Build-Time Certificate Dependency

### Option 1: Make Certificates Optional with Fallback ⭐ RECOMMENDED

**Approach:** Modify `LoadTLSConfig()` to gracefully handle missing certificates and fall back to system root CAs.

**Changes Required:**
1. Modify `client/tls.go` to handle missing assets gracefully
2. Fall back to system root CAs if embedded certs are missing
3. Update `client/model.go` to handle the fallback case

**Pros:**
- ✅ No build-time dependency on certificates
- ✅ Works with or without certificates
- ✅ Backward compatible
- ✅ Minimal code changes

**Cons:**
- ⚠️ Slightly more complex error handling

**Implementation:**
```go
// client/tls.go
func LoadTLSConfig(rootCertPaths []string) (*tls.Config, error) {
	pool := x509.NewCertPool()
	certsLoaded := false

	for _, certPath := range rootCertPaths {
		rootCrt, err := assets.Asset(certPath)
		if err != nil {
			// Certificate not found in assets, skip it
			continue
		}

		pemBlock, _ := pem.Decode(rootCrt)
		if pemBlock == nil {
			continue
		}

		certs, err := x509.ParseCertificates(pemBlock.Bytes)
		if err != nil {
			continue
		}

		pool.AddCert(certs[0])
		certsLoaded = true
	}

	// If no embedded certs were loaded, use system root CAs
	if !certsLoaded {
		return &tls.Config{}, nil
	}

	return &tls.Config{RootCAs: pool}, nil
}
```

---

### Option 2: Exclude TLS Certificates from Asset Generation

**Approach:** Modify the Makefile to exclude the `tls/` directory from asset generation, then load certificates from filesystem at runtime.

**Changes Required:**
1. Modify Makefile to exclude `assets/client/tls/` from go-bindata
2. Update `LoadTLSConfig()` to try filesystem first, then assets
3. Update `client/debug.go` and `client/release.go` to use filesystem paths

**Pros:**
- ✅ No build-time dependency
- ✅ Certificates can be provided at runtime
- ✅ More flexible

**Cons:**
- ⚠️ Requires certificates to be present at runtime (different location)
- ⚠️ More complex asset generation
- ⚠️ Breaking change for release builds

**Implementation:**
```makefile
# Makefile - exclude tls directory
client-assets: bin/go-bindata
	@mkdir -p client/assets
	bin/go-bindata -nomemcopy -pkg=assets -tags=$(BUILDTAGS) \
		-debug=$(if $(findstring debug,$(BUILDTAGS)),true,false) \
		-o=client/assets/assets_$(BUILDTAGS).go \
		assets/client/... \
		-ignore="assets/client/tls/.*"
```

```go
// client/tls.go
func LoadTLSConfig(rootCertPaths []string) (*tls.Config, error) {
	pool := x509.NewCertPool()

	for _, certPath := range rootCertPaths {
		var rootCrt []byte
		var err error

		// Try filesystem first
		rootCrt, err = os.ReadFile(certPath)
		if err != nil {
			// Fall back to embedded assets
			rootCrt, err = assets.Asset(certPath)
			if err != nil {
				return nil, fmt.Errorf("certificate not found: %s", certPath)
			}
		}

		// ... rest of parsing logic
	}
}
```

---

### Option 3: Use System Root CAs by Default

**Approach:** Change the default behavior to use system root CAs, only use embedded certs if explicitly configured.

**Changes Required:**
1. Change default in `client/model.go` to use system certs
2. Make embedded certs optional
3. Add configuration option to use embedded certs

**Pros:**
- ✅ No build-time dependency
- ✅ Works out of the box with system certs
- ✅ More secure by default (uses system trust store)

**Cons:**
- ⚠️ Breaking change for existing deployments
- ⚠️ May not work with self-signed certs

**Implementation:**
```go
// client/model.go
// configure TLS
if config.TrustHostRootCerts {
	m.Info("Trusting host's root certificates")
	m.tlsConfig = &tls.Config{}
} else if config.UseEmbeddedCerts {
	// Only use embedded certs if explicitly requested
	m.Info("Trusting root CAs: %v", rootCrtPaths)
	var err error
	if m.tlsConfig, err = LoadTLSConfig(rootCrtPaths); err != nil {
		// Fall back to system certs if embedded certs fail
		m.Warn("Failed to load embedded certs, using system root CAs: %v", err)
		m.tlsConfig = &tls.Config{}
	}
} else {
	// Default: use system root CAs
	m.Info("Using system root CAs")
	m.tlsConfig = &tls.Config{}
}
```

---

### Option 4: Runtime Certificate Loading Only

**Approach:** Remove certificates from assets entirely, always load from filesystem or allow runtime configuration.

**Changes Required:**
1. Remove TLS certs from asset generation
2. Update `LoadTLSConfig()` to only use filesystem
3. Add configuration option for certificate paths
4. Update documentation

**Pros:**
- ✅ No build-time dependency
- ✅ Maximum flexibility
- ✅ Can use any certificate at runtime

**Cons:**
- ⚠️ Breaking change
- ⚠️ Requires certificates to be provided separately
- ⚠️ More complex deployment

---

## Recommendation: Option 1 (Optional Certificates with Fallback)

**Why Option 1 is best:**
1. **Zero breaking changes** - existing code continues to work
2. **No build-time dependency** - can build without certificates
3. **Graceful degradation** - falls back to system certs automatically
4. **Minimal code changes** - only need to modify `LoadTLSConfig()`
5. **Backward compatible** - if certs exist, they're used; if not, system certs are used

**Implementation Steps:**
1. Modify `client/tls.go` to handle missing certificates gracefully
2. Test with and without certificates present
3. Update documentation to note certificates are optional

---

## Current Certificate Usage

### Debug Builds
- Uses: `ngrokroot.crt` + `snakeoilca.crt`
- Purpose: Trust both ngrok.com and self-signed certificates
- `InsecureSkipVerify: true` (for development)

### Release Builds
- Uses: `ngrokroot.crt` only
- Purpose: Trust ngrok.com's certificate
- `InsecureSkipVerify: false` (for production)

### Configuration Override
- `trust_host_root_certs: true` → Uses system root CAs (no embedded certs needed)
- This already works! But it's not the default.

---

## Testing Strategy

After implementing Option 1, test:
1. ✅ Build with certificates present (should work as before)
2. ✅ Build without certificates (should use system certs)
3. ✅ Run with `trust_host_root_certs: true` (should use system certs)
4. ✅ Run with `trust_host_root_certs: false` and no embedded certs (should use system certs)
5. ✅ Run with embedded certs (should use embedded certs)

