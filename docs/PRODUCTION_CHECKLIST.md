# Production Checklist

Use this checklist before exposing tunnels publicly.

## TLS and Networking
- Use real certificates via `-tlsCrt` and `-tlsKey` (do not rely on embedded snakeoil certs).
- Set explicit `-domain`, `-httpAddr`, `-httpsAddr`, and `-tunnelAddr`.
- Restrict firewall ingress to required ports only.
- Enable `-adminAddr` on localhost or private network only.

## Auth and Access
- Set `-authToken` on `ngrokd`.
- Prefer hashed tokens with `sha256:<hex-digest>` in `-authToken`.
- Protect client inspector with `inspect_auth` and/or `inspect_token`.
- Protect admin endpoints with `-adminAuth` and/or `-adminToken`.
- Bind `-adminAddr` to localhost or a private management network.

## Limits and Abuse Protection
- Set `-maxMsgBytes` to a conservative value.
- Set `-authRate`, `-publicRate`, and `-maxConnPerIP` for your traffic profile.
- Set `inspect_max_body_bytes` to bound in-memory capture size.

Recommended starting values:
- `-maxMsgBytes=4194304`
- `-authRate=120`
- `-publicRate=200`
- `-maxConnPerIP=100`
- `inspect_max_body_bytes=1048576`
- `proxy_max_concurrency=64`

## Operational Safety
- Run as a non-root service account.
- Enable automatic restart (systemd/containers).
- Monitor `/healthz` and `/metrics` from `-adminAddr`.
- Use structured logs with `-log-format=json` if you need machine parsing.
