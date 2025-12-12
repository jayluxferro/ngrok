# ngrok - Secure Tunnels to Localhost

ngrok is a tool that creates secure tunnels to localhost, allowing you to expose local servers to the internet. This is a modernized fork of the original ngrok v1 codebase, updated to work with current Go versions (1.21+).

## Features

- **HTTP/HTTPS Tunneling**: Expose local web servers to the internet
- **TCP Tunneling**: Tunnel arbitrary TCP traffic
- **Web Interface**: Inspect HTTP requests and responses in real-time
- **Terminal UI**: Beautiful terminal interface for monitoring tunnels
- **Self-Hosted**: Run your own ngrok server for complete control

## Quick Start

### Building from Source

**Requirements:**
- Go 1.21 or later
- Make (optional, for using the Makefile)

**Build the client and server:**
```bash
git clone <repository-url>
cd ngrok
make
```

This will create:
- `bin/ngrok` - The client binary
- `bin/ngrokd` - The server binary

**Build individual components:**
```bash
make client    # Build only the client
make server    # Build only the server
```

**Build release versions:**
```bash
make release-client  # Client with embedded assets
make release-server  # Server with embedded assets
make release-all     # Both release versions
```

### Running ngrok

**Using a public ngrok server:**
```bash
./bin/ngrok 8080
```

**Using your own server:**
1. Start your ngrok server (see [Self-Hosting](#self-hosting))
2. Create a config file `~/.ngrok`:
   ```yaml
   server_addr: your-server.com:4443
   trust_host_root_certs: true
   ```
3. Run the client:
   ```bash
   ./bin/ngrok -config=~/.ngrok 8080
   ```

## Self-Hosting

You can run your own ngrok server for complete control over your tunnels. See [docs/SELFHOSTING.md](docs/SELFHOSTING.md) for detailed instructions.

**Quick setup:**
1. Get an SSL certificate for your domain (wildcard recommended: `*.example.com`)
2. Set up DNS: point `*.example.com` to your server's IP
3. Compile the server: `make release-server`
4. Run the server:
   ```bash
   ./bin/ngrokd -tlsKey="/path/to/tls.key" -tlsCrt="/path/to/tls.crt" -domain="example.com"
   ```

## Development

### Project Structure

```
ngrok/
├── client/          # Client code
│   ├── assets/      # Generated asset files
│   ├── mvc/         # MVC framework
│   └── views/       # UI views (terminal & web)
├── server/          # Server code
│   └── assets/      # Generated asset files
├── conn/            # Connection handling
├── log/             # Logging utilities
├── msg/             # Protocol messages
├── proto/           # Protocol implementations (HTTP, TCP)
├── util/            # Utility functions
├── main/            # Entry points
│   ├── ngrok/       # Client main
│   └── ngrokd/      # Server main
└── assets/          # Static assets (HTML, CSS, JS, TLS certs)
```

### Development Workflow

**Debug builds** (read assets from filesystem):
```bash
make client    # Debug client
make server    # Debug server
```

**Release builds** (embed assets in binary):
```bash
make release-client
make release-server
```

**Local development setup:**

1. Add to `/etc/hosts`:
   ```
   127.0.0.1 ngrok.me
   127.0.0.1 test.ngrok.me
   ```

2. Run the server:
   ```bash
   ./bin/ngrokd -domain ngrok.me
   ```

3. Create `debug.yml`:
   ```yaml
   server_addr: ngrok.me:4443
   tunnels:
     test:
       proto:
         http: 8080
   ```

4. Run the client:
   ```bash
   ./bin/ngrok -config=debug.yml -log=ngrok.log start test
   ```

### Code Organization

- **Protocol**: Message definitions and wire format in `msg/`
- **Client**: Main logic in `client/`, MVC pattern for UI
- **Server**: Tunnel management in `server/`
- **Assets**: Static files in `assets/`, embedded via go-bindata

See [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) for more detailed development information.

## Configuration

ngrok reads configuration from `~/.ngrok` by default. You can specify a custom config file with `-config`.

**Example configuration:**
```yaml
server_addr: ngrokd.ngrok.com:443
inspect_addr: 127.0.0.1:4040
trust_host_root_certs: false
auth_token: your-auth-token

tunnels:
  web:
    subdomain: myapp
    proto:
      http: 8080
  api:
    hostname: api.example.com
    proto:
      https: 3000
  tcp:
    remote_port: 12345
    proto:
      tcp: 3306
```

## Command Line Options

**Client (`ngrok`):**
```bash
ngrok [OPTIONS] <local port or address>

Options:
  -config=path       Configuration file path (default: ~/.ngrok)
  -log=path          Log file path (default: stdout)
  -log-level=level  Log level: DEBUG, INFO, WARN, ERROR
  -subdomain=name    Request a specific subdomain
  -hostname=name     Request a specific hostname
  -authtoken=token   Authentication token
  -region=us         Server region (us, eu, ap, au, sa, jp, in)
```

**Server (`ngrokd`):**
```bash
ngrokd [OPTIONS]

Options:
  -domain=name       Domain to serve tunnels on
  -httpAddr=:80      HTTP listening address
  -httpsAddr=:443    HTTPS listening address
  -tunnelAddr=:4443  Tunnel control connection address
  -tlsKey=path       Path to TLS private key
  -tlsCrt=path       Path to TLS certificate
  -log=path          Log file path (default: stdout)
  -log-level=level  Log level: DEBUG, INFO, WARN, ERROR
```

## Protocol

ngrok uses a custom protocol over TLS for secure tunneling:

1. **Control Connection**: Long-lived TCP connection for tunnel management
2. **Proxy Connections**: Separate connections for each public request
3. **Message Format**: Netstring-encoded JSON messages

See [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) for detailed protocol documentation.

## Modernization

This fork has been updated to work with modern Go versions:

- ✅ Updated to Go 1.21+
- ✅ Migrated to Go modules
- ✅ Fixed deprecated APIs (`rand.Seed`, `ioutil` functions)
- ✅ Updated project structure for Go modules
- ✅ Modernized build system

## License

See [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## Related Projects

- [ngrok cloud service](https://ngrok.com) - Managed ngrok service
- [ngrok Kubernetes Ingress Controller](https://github.com/ngrok/kubernetes-ingress-controller)
- [ngrok Agent SDKs](https://ngrok.com/docs/agent-sdks/) - Official SDKs for various languages

## Acknowledgments

This is a modernized fork of the original ngrok v1 codebase developed by [inconshreveable](https://github.com/inconshreveable). The original codebase was actively developed from 2013-2016.
