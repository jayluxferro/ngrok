#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

export GOCACHE="${GOCACHE:-/tmp/go-build-cache}"
export GOMODCACHE="${GOMODCACHE:-/tmp/go-mod-cache}"
export GOPATH="${GOPATH:-/tmp/go}"
export NGROK_INSECURE_SKIP_VERIFY="${NGROK_INSECURE_SKIP_VERIFY:-1}"

TMPDIR="$(mktemp -d)"
cleanup() {
  pkill -P $$ >/dev/null 2>&1 || true
  rm -rf "$TMPDIR"
}
trap cleanup EXIT

# The client appends to its -log= file: log4go opens the target with O_APPEND
# (filelog.go), so a "Tunnel established" line written by an earlier run stays
# in the file and can satisfy the waits below before the new client has even
# connected -- the curl after such a wait then races tunnel registration and is
# answered 404. Start from a clean slate rather than trusting the log's age.
rm -f /tmp/ngrok-e2e-*.log

echo "[e2e] building binaries"
if [[ "${SKIP_BUILD:-0}" != "1" ]]; then
  go build -tags debug -o bin/ngrok ./main/ngrok
  go build -tags debug -o bin/ngrokd ./main/ngrokd
fi

echo "[e2e] starting local upstream app"
cat > "$TMPDIR/app.py" <<'PY'
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type","text/plain")
        self.end_headers()
        self.wfile.write(b"e2e-ok")
    def log_message(self, *_): pass
HTTPServer(("127.0.0.1",19001), H).serve_forever()
PY
python3 "$TMPDIR/app.py" >/tmp/ngrok-e2e-app.log 2>&1 &

echo "[e2e] starting ngrokd"
./bin/ngrokd -domain=localhost -httpAddr=127.0.0.1:18080 -httpsAddr= -tunnelAddr=127.0.0.1:14443 -adminAddr=127.0.0.1:19090 >/tmp/ngrok-e2e-ngrokd.log 2>&1 &
sleep 1

echo "[e2e] starting ngrok client"
cat > "$TMPDIR/ngrok.yml" <<'YAML'
server_addr: 127.0.0.1:14443
trust_host_root_certs: true
tunnels:
  web:
    hostname: localhost
    proto:
      http: 19001
YAML
./bin/ngrok -config="$TMPDIR/ngrok.yml" -log=/tmp/ngrok-e2e-client.log start web >/tmp/ngrok-e2e-client-stdout.log 2>&1 &

echo "[e2e] waiting for tunnel establishment"
for i in {1..40}; do
  if grep -q "Tunnel established" /tmp/ngrok-e2e-client.log 2>/dev/null; then
    break
  fi
  sleep 0.5
done

if ! grep -q "Tunnel established" /tmp/ngrok-e2e-client.log 2>/dev/null; then
  echo "[e2e] tunnel did not establish"
  echo "[e2e] ngrokd log tail:"
  tail -n 80 /tmp/ngrok-e2e-ngrokd.log || true
  echo "[e2e] client log tail:"
  tail -n 80 /tmp/ngrok-e2e-client.log || true
  exit 1
fi

echo "[e2e] sending request through ngrokd public listener"
RESP="$(curl -fsS -H 'Host: localhost' http://127.0.0.1:18080/)"
if [[ "$RESP" != "e2e-ok" ]]; then
  echo "[e2e] unexpected response: $RESP"
  exit 1
fi

echo "[e2e] checking admin metrics"
curl -fsS http://127.0.0.1:19090/metrics >/dev/null
curl -fsS http://127.0.0.1:19090/tunnels >/dev/null

# ---------------------------------------------------------------------------
# Ollama-style scenario: the upstream refuses anything that does not address it
# as loopback, which is the 403 the header flags exist to fix.
# ---------------------------------------------------------------------------

echo "[e2e] starting Ollama-style upstream (403 unless Host is loopback)"
cat > "$TMPDIR/ollama.py" <<'PY'
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        # Ollama's check, verbatim in spirit: only localhost/127.0.0.1 get in.
        host = (self.headers.get("Host") or "").split(":")[0].strip().lower()
        if host not in ("localhost", "127.0.0.1"):
            self.send_response(403)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"forbidden: host is not loopback")
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok")
    def log_message(self, *_): pass
HTTPServer(("127.0.0.1",19002), H).serve_forever()
PY
python3 "$TMPDIR/ollama.py" >/tmp/ngrok-e2e-ollama-app.log 2>&1 &

# wait_for_tunnel <client log> <label>: the same wait the scenarios above do
# inline, pulled out because this scenario starts two clients in a row.
wait_for_tunnel() {
  local logfile="$1"
  local label="$2"
  for i in {1..40}; do
    if grep -q "Tunnel established" "$logfile" 2>/dev/null; then
      return 0
    fi
    sleep 0.5
  done

  echo "[e2e] tunnel $label did not establish"
  echo "[e2e] ngrokd log tail:"
  tail -n 80 /tmp/ngrok-e2e-ngrokd.log || true
  echo "[e2e] client log tail:"
  tail -n 80 "$logfile" || true
  return 1
}

# wait_for_public <hostname>: block until the public listener answers for
# <hostname> at all. ngrokd answers 404 for a hostname whose tunnel it does not
# have, so this waits on the thing the scenarios actually depend on (the
# registry) instead of on the agent's log line, which is only a proxy for it.
wait_for_public() {
  local host="$1"
  local code
  for i in {1..40}; do
    code="$(curl -sS -o /dev/null -w '%{http_code}' -H "Host: $host" http://127.0.0.1:18080/ || true)"
    if [[ "$code" != "404" ]]; then
      return 0
    fi
    sleep 0.25
  done

  echo "[e2e] the public listener never learned the hostname $host"
  return 1
}

cat > "$TMPDIR/ngrok-ollama.yml" <<'YAML'
server_addr: 127.0.0.1:14443
trust_host_root_certs: true
YAML

# The header flags only feed the synthesized "default" tunnel, so this scenario
# requests its tunnel the CLI way ("ngrok <port>") instead of naming one in the
# config file. -proto=http because ngrokd runs without an https listener here
# (-httpsAddr= above): asking for http+https would fail to allocate the https
# tunnel and take the client down with it.
echo "[e2e] starting ngrok client for the ollama tunnel, no header flags"
./bin/ngrok -config="$TMPDIR/ngrok-ollama.yml" -log=/tmp/ngrok-e2e-ollama-client-1.log -proto=http -hostname=ollama 19002 >/tmp/ngrok-e2e-ollama-client-stdout.log 2>&1 &
OLLAMA_CLIENT_PID=$!
wait_for_tunnel /tmp/ngrok-e2e-ollama-client-1.log "ollama (no flags)"
wait_for_public ollama

echo "[e2e] curl the tunnel without flags: expect the upstream's 403"
CODE="$(curl -sS -o /dev/null -w '%{http_code}' -H 'Host: ollama' http://127.0.0.1:18080/)"
if [[ "$CODE" != "403" ]]; then
  echo "[e2e] expected 403 from the upstream when Host is not rewritten, got $CODE"
  exit 1
fi

echo "[e2e] restarting the client with -host-header=rewrite"
kill "$OLLAMA_CLIENT_PID" 2>/dev/null || true
wait "$OLLAMA_CLIENT_PID" 2>/dev/null || true

# ngrokd forgets a tunnel when its control connection dies, but not always
# before the next client asks for the same hostname. 404 is its answer for an
# unknown host, so wait for that before re-registering.
for i in {1..40}; do
  CODE="$(curl -sS -o /dev/null -w '%{http_code}' -H 'Host: ollama' http://127.0.0.1:18080/ || true)"
  if [[ "$CODE" == "404" ]]; then
    break
  fi
  sleep 0.25
done

./bin/ngrok -config="$TMPDIR/ngrok-ollama.yml" -log=/tmp/ngrok-e2e-ollama-client-2.log -proto=http -hostname=ollama -host-header=rewrite -response-header-add=X-E2E:yes 19002 >/tmp/ngrok-e2e-ollama-client-stdout.log 2>&1 &
OLLAMA_CLIENT_PID=$!
wait_for_tunnel /tmp/ngrok-e2e-ollama-client-2.log "ollama (-host-header=rewrite)"
wait_for_public ollama

echo "[e2e] curl the tunnel with -host-header=rewrite: expect 200 and the added response header"
RESP="$(curl -fsS -H 'Host: ollama' http://127.0.0.1:18080/)"
if [[ "$RESP" != "ok" ]]; then
  echo "[e2e] unexpected response through the rewritten tunnel: $RESP"
  exit 1
fi

RESP_HEADERS="$(curl -fsS -D - -o /dev/null -H 'Host: ollama' http://127.0.0.1:18080/)"
if ! grep -qi '^X-E2E: yes' <<<"$RESP_HEADERS"; then
  echo "[e2e] -response-header-add=X-E2E:yes did not reach the public client:"
  echo "$RESP_HEADERS"
  exit 1
fi

# ---------------------------------------------------------------------------
# Response compression (SPEC 3.4): compression is on by default, so a client
# that asks for gzip gets a gzipped response and a client that does not gets
# the upstream's bytes untouched. -compression=false turns it off per tunnel.
# ---------------------------------------------------------------------------

echo "[e2e] starting compressible upstream (HTTP/1.1, 4000 bytes of text)"
cat > "$TMPDIR/compressible.py" <<'PY'
from http.server import BaseHTTPRequestHandler, HTTPServer
BODY = b"a" * 4000
class H(BaseHTTPRequestHandler):
    # HTTP/1.1 on purpose: the agent only re-frames a response when both the
    # client and the upstream speak HTTP/1.1 (SPEC 3.4's skip matrix), so an
    # HTTP/1.0 upstream would never be compressed.
    protocol_version = "HTTP/1.1"
    def do_GET(self):
        # text/plain and >= 128 bytes: both are conditions of the skip matrix.
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)
    def log_message(self, *_): pass
HTTPServer(("127.0.0.1",19003), H).serve_forever()
PY
python3 "$TMPDIR/compressible.py" >/tmp/ngrok-e2e-compressible-app.log 2>&1 &

# The CLI-tunnel scenarios below share this config: like ngrok-ollama.yml it
# only points the client at the local server, because the flags they exercise
# feed the synthesized "default" tunnel.
cat > "$TMPDIR/ngrok-cli.yml" <<'YAML'
server_addr: 127.0.0.1:14443
trust_host_root_certs: true
YAML

echo "[e2e] starting ngrok client for the compression tunnel (no flags: compression defaults on)"
./bin/ngrok -config="$TMPDIR/ngrok-cli.yml" -log=/tmp/ngrok-e2e-compress-client.log -proto=http -hostname=compressed 19003 >/tmp/ngrok-e2e-compress-client-stdout.log 2>&1 &
COMPRESS_CLIENT_PID=$!
wait_for_tunnel /tmp/ngrok-e2e-compress-client.log "compressed"
wait_for_public compressed

EXPECTED_BODY="$(python3 -c 'print("a" * 4000, end="")')"

echo "[e2e] curl --compressed: expect Content-Encoding: gzip and the upstream's body back"
GZIP_HEADERS="$(curl -fsS --compressed -D - -o "$TMPDIR/gzip.body" -H 'Host: compressed' http://127.0.0.1:18080/)"
if ! grep -qi '^Content-Encoding: gzip' <<<"$GZIP_HEADERS"; then
  echo "[e2e] expected Content-Encoding: gzip through the compression tunnel:"
  echo "$GZIP_HEADERS"
  exit 1
fi
# The compressed body is re-framed, so it cannot be close-delimited: the
# response has to arrive chunked (SPEC 3.4).
if ! grep -qi '^Transfer-Encoding: chunked' <<<"$GZIP_HEADERS"; then
  echo "[e2e] a compressed response must be re-framed as chunked:"
  echo "$GZIP_HEADERS"
  exit 1
fi
if [[ "$(cat "$TMPDIR/gzip.body")" != "$EXPECTED_BODY" ]]; then
  echo "[e2e] the decompressed body does not match the upstream's"
  exit 1
fi

echo "[e2e] curl without Accept-Encoding: expect no Content-Encoding at all"
PLAIN_HEADERS="$(curl -fsS -D - -o "$TMPDIR/plain.body" -H 'Host: compressed' http://127.0.0.1:18080/)"
if grep -qi '^Content-Encoding' <<<"$PLAIN_HEADERS"; then
  echo "[e2e] a client that never asked for gzip received an encoded response:"
  echo "$PLAIN_HEADERS"
  exit 1
fi
if [[ "$(cat "$TMPDIR/plain.body")" != "$EXPECTED_BODY" ]]; then
  echo "[e2e] the identity response does not match the upstream's bytes"
  exit 1
fi

echo "[e2e] restarting the client with -compression=false"
kill "$COMPRESS_CLIENT_PID" 2>/dev/null || true
wait "$COMPRESS_CLIENT_PID" 2>/dev/null || true

# Same wait as the ollama restart above: ngrokd has to forget the hostname
# before the next client can take it.
for i in {1..40}; do
  CODE="$(curl -sS -o /dev/null -w '%{http_code}' -H 'Host: compressed' http://127.0.0.1:18080/ || true)"
  if [[ "$CODE" == "404" ]]; then
    break
  fi
  sleep 0.25
done

./bin/ngrok -config="$TMPDIR/ngrok-cli.yml" -log=/tmp/ngrok-e2e-compress-client-2.log -proto=http -hostname=compressed -compression=false 19003 >/tmp/ngrok-e2e-compress-client-stdout.log 2>&1 &
wait_for_tunnel /tmp/ngrok-e2e-compress-client-2.log "compressed (-compression=false)"
wait_for_public compressed

echo "[e2e] curl --compressed through -compression=false: expect the upstream's bytes"
NOCOMP_HEADERS="$(curl -fsS --compressed -D - -o "$TMPDIR/nocomp.body" -H 'Host: compressed' http://127.0.0.1:18080/)"
if grep -qi '^Content-Encoding' <<<"$NOCOMP_HEADERS"; then
  echo "[e2e] -compression=false still produced an encoded response:"
  echo "$NOCOMP_HEADERS"
  exit 1
fi
if [[ "$(cat "$TMPDIR/nocomp.body")" != "$EXPECTED_BODY" ]]; then
  echo "[e2e] the opt-out response does not match the upstream's bytes"
  exit 1
fi

# ---------------------------------------------------------------------------
# Endpoint pooling (SPEC 3.2): two agents register the same url with -pooling
# and the server round-robins connections between them, while a third agent
# asking for the same url without -pooling is still refused it.
# ---------------------------------------------------------------------------

echo "[e2e] starting two pooling upstreams (each answers with its own name)"
cat > "$TMPDIR/pool_upstream.py" <<'PY'
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
NAME = sys.argv[1].encode()
class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(NAME)))
        self.end_headers()
        self.wfile.write(NAME)
    def log_message(self, *_): pass
HTTPServer(("127.0.0.1", int(sys.argv[2])), H).serve_forever()
PY
python3 "$TMPDIR/pool_upstream.py" upstream-a 19004 >/tmp/ngrok-e2e-pool-app-a.log 2>&1 &
python3 "$TMPDIR/pool_upstream.py" upstream-b 19005 >/tmp/ngrok-e2e-pool-app-b.log 2>&1 &

echo "[e2e] starting two ngrok clients on the same subdomain, both with -pooling"
./bin/ngrok -config="$TMPDIR/ngrok-cli.yml" -log=/tmp/ngrok-e2e-pool-client-1.log -proto=http -subdomain=pool -pooling 19004 >/tmp/ngrok-e2e-pool-client-1-stdout.log 2>&1 &
wait_for_tunnel /tmp/ngrok-e2e-pool-client-1.log "pool (first member)"
./bin/ngrok -config="$TMPDIR/ngrok-cli.yml" -log=/tmp/ngrok-e2e-pool-client-2.log -proto=http -subdomain=pool -pooling 19005 >/tmp/ngrok-e2e-pool-client-2-stdout.log 2>&1 &
wait_for_tunnel /tmp/ngrok-e2e-pool-client-2.log "pool (second member)"

# The public url is assigned by the server and keeps ngrokd's non-default http
# port (only :80 is stripped from a vhost), so read the url the client was
# given instead of guessing where the port went.
POOL_URL="$(sed -n 's/.*Tunnel established at \([^ ]*\).*/\1/p' /tmp/ngrok-e2e-pool-client-1.log | head -n 1)"
POOL_HOST="${POOL_URL#http://}"
if [[ -z "$POOL_HOST" || "$POOL_HOST" == "$POOL_URL" ]]; then
  echo "[e2e] could not read the pooling tunnel's public url from the client log"
  exit 1
fi

echo "[e2e] sending 8 requests through the pooled url $POOL_HOST"
wait_for_public "$POOL_HOST"
POOL_HITS_A=0
POOL_HITS_B=0
for _ in {1..8}; do
  BODY="$(curl -fsS -H "Host: $POOL_HOST" http://127.0.0.1:18080/ || true)"
  case "$BODY" in
    upstream-a) POOL_HITS_A=$((POOL_HITS_A + 1)) ;;
    upstream-b) POOL_HITS_B=$((POOL_HITS_B + 1)) ;;
    *)
      echo "[e2e] unexpected response from the pooled tunnel: $BODY"
      exit 1
      ;;
  esac
done

echo "[e2e] pooled hits: upstream-a=$POOL_HITS_A upstream-b=$POOL_HITS_B"
if [[ "$POOL_HITS_A" -lt 1 || "$POOL_HITS_B" -lt 1 ]]; then
  echo "[e2e] pooling did not distribute the connections across both agents"
  exit 1
fi

echo "[e2e] a third client without -pooling must be refused the pooled url"
./bin/ngrok -config="$TMPDIR/ngrok-cli.yml" -log=/tmp/ngrok-e2e-pool-conflict.log -proto=http -subdomain=pool 19004 >/tmp/ngrok-e2e-pool-conflict-stdout.log 2>&1 &
POOL_CONFLICT_PID=$!

POOL_CONFLICTED=0
for i in {1..40}; do
  if grep -q "failed to allocate tunnel" /tmp/ngrok-e2e-pool-conflict.log 2>/dev/null; then
    POOL_CONFLICTED=1
    break
  fi
  sleep 0.25
done

if [[ "$POOL_CONFLICTED" != "1" ]]; then
  echo "[e2e] a non-pooling registration of the pooled url was not refused:"
  tail -n 40 /tmp/ngrok-e2e-pool-conflict.log || true
  exit 1
fi
kill "$POOL_CONFLICT_PID" 2>/dev/null || true

# ---------------------------------------------------------------------------
# Internal endpoints and forward_to (SPEC 3.2/3.3): an internal endpoint is
# reachable only from another endpoint of the same account, through forward_to,
# and its hostname is invisible to the public listener.
# ---------------------------------------------------------------------------

echo "[e2e] starting an internal endpoint for the local app (client A)"
# -proto=https so the endpoint is registered as https://svc.internal: the
# internal registry key carries the scheme, and a forward_to has to name it
# with the same one. No https listener is needed for an internal endpoint.
./bin/ngrok -config="$TMPDIR/ngrok-cli.yml" -log=/tmp/ngrok-e2e-internal-client.log -proto=https -hostname=svc.internal -binding=internal 19001 >/tmp/ngrok-e2e-internal-client-stdout.log 2>&1 &
wait_for_tunnel /tmp/ngrok-e2e-internal-client.log "internal (svc.internal)"

echo "[e2e] starting a public endpoint that forwards to it (client B)"
# B's local port is never dialed: the server dispatches the connection through
# the internal endpoint's own agent (SPEC 3.3), so B's upstream is unused.
./bin/ngrok -config="$TMPDIR/ngrok-cli.yml" -log=/tmp/ngrok-e2e-forward-client.log -proto=http -hostname=forwarded -forward-to=https://svc.internal 19001 >/tmp/ngrok-e2e-forward-client-stdout.log 2>&1 &
wait_for_tunnel /tmp/ngrok-e2e-forward-client.log "forwarded -> svc.internal"
wait_for_public forwarded

echo "[e2e] curl the forwarding endpoint: expect the internal endpoint's upstream to answer"
RESP="$(curl -fsS -H 'Host: forwarded' http://127.0.0.1:18080/)"
if [[ "$RESP" != "e2e-ok" ]]; then
  echo "[e2e] the forward_to chain did not reach the internal upstream: $RESP"
  exit 1
fi

echo "[e2e] curl the public listener for the internal hostname: expect 404"
# The Host header is how a public client would have to ask for the internal
# name; the public listener must not know it at all.
CODE="$(curl -sS -o /dev/null -w '%{http_code}' -H 'Host: svc.internal' http://127.0.0.1:18080/)"
if [[ "$CODE" != "404" ]]; then
  echo "[e2e] a public lookup of an internal hostname returned $CODE, want 404"
  exit 1
fi

# ---------------------------------------------------------------------------
# Traffic policy (SPEC 3.4, cluster 4): the edge enforces a policy the client
# sent with its tunnel registration. Every action this cluster implements runs
# through a live tunnel here -- deny and custom-response terminate at the edge,
# restrict-ips decides before an agent is asked for anything, add/remove-headers
# transform both directions, set-vars feeds ${vars} into a later action, and log
# writes a line into ngrokd's log.
#
# One thing about the policy file below is not the order the docs introduce
# these actions in: set-vars comes *before* add-headers. Actions run in the
# order they are written, so a ${vars.who} in a header value is empty until
# set-vars has run -- the ordering is the feature, and this file is what proves
# it end to end.
# ---------------------------------------------------------------------------

# Every policy request below is bounded, and one that is never answered comes
# back as the status code 000 instead of hanging the script. The bound is not
# defensive padding: the edge answers a terminated request through the response
# side of its rewriter, and that side has to be woken for the answer to be
# emitted at all. A wake that does not work does not fail an assertion -- it
# stops the harness from ever reaching one, which is how the first run of this
# section presented itself (curl waiting on /blocked forever). The bound turns
# that into a wrong-status failure with a message.
POLICY_CURL_TIMEOUT="${POLICY_CURL_TIMEOUT:-15}"

# policy_curl echoes the response's status code (000 when curl never got one)
# and leaves the body in the -o file the caller named. The `|| true` is what
# keeps `set -e` from aborting on curl's nonzero exit before the caller can
# report the code it got.
policy_curl() {
  curl -sS --max-time "$POLICY_CURL_TIMEOUT" -w '%{http_code}' "$@" || true
}

echo "[e2e] starting the policy upstream (answers with the request headers it saw)"
cat > "$TMPDIR/policy_upstream.py" <<'PY'
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def do_GET(self):
        # The body carries the headers the policy is supposed to have added, so
        # the assertion reads them from the response the public client gets
        # instead of from a log the agent writes. BaseHTTPRequestHandler also
        # sends its own Server header, which is what the response-phase
        # remove-headers rule has to take away.
        body = ("x-policy=%s;x-who=%s" % (
            self.headers.get("X-Policy", ""), self.headers.get("X-Who", ""))).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *_): pass
HTTPServer(("127.0.0.1", 19006), H).serve_forever()
PY
python3 "$TMPDIR/policy_upstream.py" >/tmp/ngrok-e2e-policy-app.log 2>&1 &

cat > "$TMPDIR/ngrok-policy.yml" <<'YAML'
server_addr: 127.0.0.1:14443
trust_host_root_certs: true
tunnels:
  guarded:
    hostname: guarded
    proto:
      http: 19006
    traffic_policy:
      on_tcp_connect:
        - name: restrict-ips
          config:
            allow:
              - 127.0.0.0/8
              - "::1/128"
      on_http_request:
        - name: deny
          expressions:
            - 'req.url.path == "/blocked"'
        - name: set-vars
          config:
            vars:
              - who: policy
        - name: add-headers
          config:
            headers:
              X-Policy: checked
              X-Who: "${vars.who}"
        - name: custom-response
          expressions:
            - 'req.url.path == "/teapot"'
          config:
            status_code: 418
            body: "short and stout"
            headers:
              X-Flavour: tea
        - name: log
          config:
            metadata:
              hit: "${vars.who}"
      on_http_response:
        - name: remove-headers
          config:
            headers:
              - Server
        - name: add-headers
          config:
            headers:
              X-Edge: ngrokd
  restricted:
    hostname: restricted
    proto:
      http: 19006
    traffic_policy:
      on_tcp_connect:
        - name: restrict-ips
          config:
            deny:
              - 127.0.0.0/8
YAML

echo "[e2e] starting the policy tunnels (guarded, restricted)"
# One client, two tunnels: the config file carries both policies, so this also
# checks that a policy is attached per tunnel rather than per client.
./bin/ngrok -config="$TMPDIR/ngrok-policy.yml" -log=/tmp/ngrok-e2e-policy-client.log start guarded restricted >/tmp/ngrok-e2e-policy-client-stdout.log 2>&1 &
wait_for_tunnel /tmp/ngrok-e2e-policy-client.log "guarded+restricted"
wait_for_public guarded
wait_for_public restricted

echo "[e2e] policy: an allowed path reaches the upstream, carrying the added headers"
# X-Policy comes from add-headers, X-Who from ${vars.who} -- so this single
# assertion covers the request-phase add-headers, set-vars and the order they
# run in. The upstream echoes both back in the body.
RESP="$(curl -fsS -H 'Host: guarded' http://127.0.0.1:18080/allowed)"
if [[ "$RESP" != "x-policy=checked;x-who=policy" ]]; then
  echo "[e2e] the request-phase headers did not reach the upstream: got \"$RESP\""
  exit 1
fi

echo "[e2e] policy: deny terminates /blocked at the edge, before the upstream"
# -f is deliberately absent: a 403 is the answer under test. The request is
# bounded because this is the assertion whose failure mode is "no answer at
# all", and 000 names it.
CODE="$(policy_curl -o "$TMPDIR/policy-blocked.body" -H 'Host: guarded' http://127.0.0.1:18080/blocked)"
if [[ "$CODE" != "403" ]]; then
  echo "[e2e] expected the deny action to answer 403, got $CODE"
  if [[ "$CODE" == "000" ]]; then
    echo "[e2e] the edge never answered: the terminated request was not written back to the public client"
    echo "[e2e] (see the response-side wake in rewriter/conn.go: a parked read of a mux stream is not interrupted by SetReadDeadline)"
  fi
  exit 1
fi
# A denied request must not be answered by the app: the upstream always writes
# a body, so an empty one is the evidence that the edge answered instead.
if [[ -s "$TMPDIR/policy-blocked.body" ]]; then
  echo "[e2e] the denied request reached the upstream:"
  cat "$TMPDIR/policy-blocked.body"
  exit 1
fi

echo "[e2e] policy: custom-response answers /teapot with its own status, header and body"
TEAPOT_CODE="$(policy_curl -D "$TMPDIR/policy-teapot.headers" -o "$TMPDIR/policy-teapot.body" -H 'Host: guarded' http://127.0.0.1:18080/teapot)"
if [[ "$TEAPOT_CODE" != "418" ]]; then
  echo "[e2e] expected the custom-response status_code 418, got $TEAPOT_CODE"
  exit 1
fi
if ! grep -qi '^X-Flavour: tea' "$TMPDIR/policy-teapot.headers"; then
  echo "[e2e] the custom-response headers did not reach the public client:"
  cat "$TMPDIR/policy-teapot.headers"
  exit 1
fi
if [[ "$(cat "$TMPDIR/policy-teapot.body")" != "short and stout" ]]; then
  echo "[e2e] the custom-response body did not reach the public client:"
  cat "$TMPDIR/policy-teapot.body"
  exit 1
fi
# The 418 is the edge's own answer, and it still runs the response phase: ngrok
# documents this for a terminating on_http_request action ("actions defined in
# the on_http_response phase will still be executed"), and the guarded tunnel's
# response-phase add-headers is what makes it observable here. Headers are all
# the response phase can change on an edge answer -- the status and the body
# belong to the terminating action's config.
if ! grep -qi '^X-Edge: ngrokd' "$TMPDIR/policy-teapot.headers"; then
  echo "[e2e] the response phase did not run on the edge's own 418:"
  cat "$TMPDIR/policy-teapot.headers"
  exit 1
fi

echo "[e2e] policy: restrict-ips allows 127.0.0.0/8 on one tunnel and refuses it on the other"
# The allow half is the /allowed request above (it got through). On its own that
# proves nothing -- it would pass with no policy at all -- so the deny half is
# here too: the same client, the same source address, and a tunnel whose policy
# denies it.
RESTRICTED_CODE="$(policy_curl -o /dev/null -H 'Host: restricted' http://127.0.0.1:18080/)"
if [[ "$RESTRICTED_CODE" != "403" ]]; then
  echo "[e2e] expected restrict-ips to refuse 127.0.0.1 with 403, got $RESTRICTED_CODE"
  exit 1
fi

echo "[e2e] policy: the response phase removed the upstream's Server header and added X-Edge"
PUBLIC_HEADERS="$(curl -fsS -D - -o /dev/null -H 'Host: guarded' http://127.0.0.1:18080/allowed)"
if ! grep -qi '^X-Edge: ngrokd' <<<"$PUBLIC_HEADERS"; then
  echo "[e2e] the response-phase add-headers did not reach the public client:"
  echo "$PUBLIC_HEADERS"
  exit 1
fi
if grep -qi '^Server:' <<<"$PUBLIC_HEADERS"; then
  echo "[e2e] the response-phase remove-headers did not take the Server header away:"
  echo "$PUBLIC_HEADERS"
  exit 1
fi

echo "[e2e] policy: the log action wrote its metadata into ngrokd's log"
if ! grep -q 'traffic policy log action' /tmp/ngrok-e2e-ngrokd.log; then
  echo "[e2e] the log action wrote nothing to the server log"
  exit 1
fi
# The metadata is interpolated, like every other value in the phase: hit="policy"
# is ${vars.who}, which set-vars assigned earlier in the same phase.
if ! grep -q 'hit="policy"' /tmp/ngrok-e2e-ngrokd.log; then
  echo "[e2e] the log action's interpolated metadata is not in the server log"
  exit 1
fi

echo "[e2e] policy: -traffic-policy-file feeds a policy to the default tunnel"
# The file's top level *is* the policy document: the flag is not a folder of
# endpoints, it is one endpoint's policy.
cat > "$TMPDIR/policy-file.yml" <<'YAML'
on_tcp_connect:
  - name: restrict-ips
    config:
      allow:
        - 127.0.0.0/8
on_http_request:
  - name: deny
    expressions:
      - 'req.url.path == "/blocked"'
  - name: add-headers
    config:
      headers:
        # X-Policy, not a name of its own: the policy upstream echoes exactly
        # X-Policy and X-Who (policy_upstream.py), so a header under any other
        # name is invisible to the assertion below. The *value* is what shows
        # this header came from the file rather than from the guarded tunnel.
        X-Policy: from-file
YAML

./bin/ngrok -config="$TMPDIR/ngrok-cli.yml" -log=/tmp/ngrok-e2e-policy-file-client.log -proto=http -hostname=policyfile -traffic-policy-file="$TMPDIR/policy-file.yml" 19006 >/tmp/ngrok-e2e-policy-file-client-stdout.log 2>&1 &
wait_for_tunnel /tmp/ngrok-e2e-policy-file-client.log "policyfile (-traffic-policy-file)"
wait_for_public policyfile

FILE_CODE="$(policy_curl -o /dev/null -H 'Host: policyfile' http://127.0.0.1:18080/blocked)"
if [[ "$FILE_CODE" != "403" ]]; then
  echo "[e2e] the file-fed policy did not deny /blocked: got $FILE_CODE"
  exit 1
fi

# x-who is empty here on purpose: this policy has no set-vars, and the empty
# value is what proves the header came from this file rather than from the
# guarded tunnel's policy.
FILE_RESP="$(curl -fsS -H 'Host: policyfile' http://127.0.0.1:18080/allowed)"
if [[ "$FILE_RESP" != "x-policy=from-file;x-who=" ]]; then
  echo "[e2e] the file-fed policy's add-headers did not reach the upstream: got \"$FILE_RESP\""
  exit 1
fi

echo "[e2e] policy: a policy file the client cannot enforce stops it at startup"
# The client must refuse to start rather than come up with a rule that does less
# than it says: this is the same load-time validation the unit tests cover,
# driven through the real binary and the real flag.
cat > "$TMPDIR/policy-broken.yml" <<'YAML'
on_http_request:
  - name: rate-limit
    config:
      rate: 10
YAML

if ./bin/ngrok -config="$TMPDIR/ngrok-cli.yml" -proto=http -hostname=broken -traffic-policy-file="$TMPDIR/policy-broken.yml" 19006 >"$TMPDIR/policy-broken.out" 2>&1; then
  echo "[e2e] the client started with a policy it cannot enforce:"
  cat "$TMPDIR/policy-broken.out"
  exit 1
fi
if ! grep -q 'policy-broken.yml' "$TMPDIR/policy-broken.out"; then
  echo "[e2e] the startup failure does not name the policy file:"
  cat "$TMPDIR/policy-broken.out"
  exit 1
fi
if ! grep -q 'on_http_request\[0\] (rate-limit)' "$TMPDIR/policy-broken.out"; then
  echo "[e2e] the startup failure does not name the rule at fault:"
  cat "$TMPDIR/policy-broken.out"
  exit 1
fi

echo "[e2e] PASS"
