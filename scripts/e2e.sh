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

echo "[e2e] PASS"
