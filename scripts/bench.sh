#!/usr/bin/env bash
#
# scripts/bench.sh -- deterministic end-to-end throughput benchmarks for ngrok.
#
#   bash scripts/bench.sh                        # build the working tree, run once
#   bash scripts/bench.sh <baseline> <current>   # compare two dirs of binaries
#
# Each <dir> must hold an `ngrok` and an `ngrokd` binary. The two-directory form
# is meant for binaries captured before and after a change; the pre-mux baseline
# this cluster measures against lives in /tmp/bench-baseline.
#
# Every scenario runs end to end through a real ngrokd + ngrok pair: a python
# upstream on loopback, a public listener on 18180, a tunnel listener on 15443.
# Those ports are deliberately disjoint from scripts/e2e.sh (18080/14443/19001+)
# so the two harnesses can run at the same time without fighting over a port.
#
# What the scenarios measure, and what they do not:
#
#   bulk        64 MiB of incompressible random bytes through the tunnel to
#               /dev/null, MiB/s, median of 3 runs. The body is random on
#               purpose: compression is on by default in this fork, and a
#               compressible body would measure gzip rather than the tunnel.
#
#   conn-rate   200 sequential requests, each asking for `Connection: close`, so
#               every request pays a full public accept -> tunnel/proxy setup ->
#               upstream dial -> teardown cycle. Reported as req/s plus p50/p95
#               per-request wall time: the percentiles are what a mean hides, and
#               a mux path is supposed to move the tail, not just the average.
#
#   keep-alive  1000 requests in ONE curl invocation, so curl reuses the public
#               connection when the path allows it. req/s on its own would be
#               ambiguous here -- if the server closes each response the number
#               silently degrades into conn-rate again -- so the harness also
#               reports how many TCP connections curl actually had to open (the
#               sum of %{num_connects} over the transfers). 1-2 means reuse
#               worked; ~1000 means it did not, whatever the req/s says.
#
#   tls-conn-rate  200 requests through the HTTPS listener, each on a fresh TLS
#               connection (the TLS twin of conn-rate), twice: to an
#               edge-terminated endpoint, where the server terminates the TLS
#               with its own certificate, and to an agent-terminated one, where
#               the server peeks the ClientHello's SNI and relays the records.
#               The delta is the server-side difference itself -- peek + raw
#               join versus full termination and Host routing -- plus one
#               confound stated rather than hidden: the certificates are not
#               the same algorithm. The edge column terminates with the
#               server's embedded RSA-2048 development certificate, the agent
#               column with an ECDSA P-256 leaf it minted, and RSA-2048
#               handshakes cost measurably more on this box. Read the two
#               columns as "each route with its default certificate", not as a
#               pure routing comparison; a like-for-like one would point
#               -tlsCrt/-tlsKey at an ECDSA pair. The agent column verifies
#               its chain against the harness's own CA -- a run that silently
#               lost the zero-knowledge path would fail, not slow down.
#
# Honesty rules this script tries to keep:
#
#   - No knobs for the numbers. Fixed body size, fixed request counts, fixed
#     ports, so two runs are actually comparable.
#   - Every measurement is validated (byte counts, HTTP status codes) before it
#     is reported, so a truncated or failing run aborts instead of printing a
#     fast number.
#   - Same binaries twice should land near zero delta. That self-comparison is
#     the harness's own sanity check; run it after touching the script -- and read
#     the spread before believing a delta. Measured on this development box while
#     other work was compiling (load average ~4.5): identical binaries came back
#     637-743 MiB/s on bulk and 452-530 req/s on conn-rate, i.e. the second
#     variant ran up to 15% slower on every metric with no difference between the
#     binaries at all. All three bulk runs are kept in the JSON
#     (bulk_runs_mib_s): overlapping ranges mean noise, not a change. An idle
#     machine narrows this a lot, a loaded one widens it, and because the two
#     variants run one after the other rather than at the same time (they need
#     the same ports), a machine that changes speed mid-run lands in the table as
#     a delta.
#
# Output: progress on stderr, a markdown-ish table on stdout, and a JSON copy of
# every number in /tmp/ngrok-bench-result.json. Logs: /tmp/ngrok-bench-*.log.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# The same environment e2e.sh pins. The build path below needs it, and
# inheriting the caller's caches keeps a bench run from re-downloading the whole
# module graph.
# Go caches default to the machine's configured paths (`go env`), never to an
# empty /tmp directory: a hermetic-looking /tmp module cache is just a cold
# one -- every run re-downloads every module, and a sandbox whose /tmp lacks
# them fails the build outright. An inherited environment still wins.
export GOCACHE="${GOCACHE:-$(go env GOCACHE)}"
export GOMODCACHE="${GOMODCACHE:-$(go env GOMODCACHE)}"
export GOPATH="${GOPATH:-$(go env GOPATH)}"
export NGROK_INSECURE_SKIP_VERIFY="${NGROK_INSECURE_SKIP_VERIFY:-1}"

# Fixed parameters. Keeping these as constants rather than flags is deliberate.
BENCH_HOST="bench"            # vhost the tunnel registers; also the Host: header
BENCH_UPSTREAM_PORT=19101     # python fixture          (e2e.sh uses 19001-19005)
BENCH_HTTP_PORT=18180         # public listener         (e2e.sh uses 18080)
BENCH_HTTPS_PORT=18480        # public https listener   (e2e.sh uses 18443)
BENCH_TUNNEL_PORT=15443       # client <-> server       (e2e.sh uses 14443)
BENCH_ADMIN_PORT=19190        # admin                   (e2e.sh uses 19090)
BASE_URL="http://127.0.0.1:${BENCH_HTTP_PORT}"

# The tls-conn-rate scenario's two endpoints: same upstream, same listener,
# different terminator. "edge" is served with the server's own certificate
# (measured with verification off, like curl -k); "agent" is agent-terminated
# and is measured with FULL verification against the harness CA below -- the
# measurement doubles as a correctness check on the zero-knowledge path.
BENCH_TLS_EDGE_HOST="bench-tls"
BENCH_TLS_ZK_HOST="bench-zk"

BULK_BYTES=$((64 * 1024 * 1024))
BULK_RUNS=3
CONN_RATE_REQUESTS=200
KEEPALIVE_REQUESTS=1000
TLS_REQUESTS=200

RESULT_JSON="${BENCH_RESULT_JSON:-/tmp/ngrok-bench-result.json}"

WORKDIR="$(mktemp -d)"
PIDS=()
CLIENT_PID=""
NGROKD_PID=""
UPSTREAM_PID=""
CURRENT_LABEL=""

cleanup() {
  local pid
  for pid in ${PIDS[@]:-}; do
    kill "$pid" 2>/dev/null || true
  done
  # Belt and braces: anything this shell started directly that the list above
  # missed (the python fixtures fork nothing, but a stray curl would show up).
  pkill -P $$ >/dev/null 2>&1 || true
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

# A failing command under `set -e` exits with the logs still on disk but nothing
# pointing at them; this prints the tail of the variant that broke. `set +e`
# first so a missing log cannot re-enter the trap.
on_error() {
  local status=$?
  set +e
  echo "[bench] FAILED (exit $status) during variant '${CURRENT_LABEL:-none}'" >&2
  if [[ -n "$CURRENT_LABEL" ]]; then
    dump_logs "$CURRENT_LABEL"
  fi
  exit "$status"
}
trap on_error ERR

log()  { echo "[bench] $*" >&2; }
die()  { echo "[bench] $*" >&2; exit 1; }

usage() {
  cat <<'EOF'
usage: bash scripts/bench.sh [baseline_dir current_dir]

  no arguments   build the working tree with -tags debug and run once
  two dirs       run the suite against each dir (each must contain `ngrok` and
                 `ngrokd`) and print BASELINE | CURRENT | DELTA
EOF
}

# --- helpers -----------------------------------------------------------------

dump_logs() {
  local label="$1" f
  for f in /tmp/ngrok-bench-"$label"-ngrokd.log /tmp/ngrok-bench-"$label"-client.log; do
    echo "[bench] ---- $f (tail) ----" >&2
    tail -n 40 "$f" 2>/dev/null >&2 || true
  done
}

# port_in_use <port>: exit 0 when something is already listening on loopback.
# Cheap python socket rather than lsof/nc so the check does not depend on which
# tools this machine happens to have.
port_in_use() {
  python3 - "$1" <<'PY'
import socket, sys
s = socket.socket()
s.settimeout(0.3)
sys.exit(0 if s.connect_ex(("127.0.0.1", int(sys.argv[1]))) == 0 else 1)
PY
}

check_binaries() {
  local dir="$1" f
  for f in ngrok ngrokd; do
    if [[ ! -x "$dir/$f" ]]; then
      die "$dir/$f is missing or not executable"
    fi
  done
}

# wait_for_tunnel <label>: the client log is the only place the agent says it
# registered. It appends (log4go opens -log= with O_APPEND), so a stale line from
# an earlier run would satisfy this wait before the new agent has connected --
# which is why start_stack deletes the logs first (same trap e2e.sh documents).
wait_for_tunnel() {
  local label="$1" i
  for i in $(seq 1 40); do
    if grep -q "Tunnel established" "/tmp/ngrok-bench-$label-client.log" 2>/dev/null; then
      return 0
    fi
    sleep 0.5
  done
  log "tunnel did not establish for variant '$label'"
  dump_logs "$label"
  return 1
}

# wait_for_public <label>: block until the public listener knows the hostname.
# ngrokd answers 404 for a hostname it has no tunnel for, and 404 is also how it
# answers while the registry is still catching up, so this waits on the thing the
# scenarios depend on rather than on the agent's log line.
wait_for_public() {
  local label="$1" code i
  for i in $(seq 1 40); do
    code="$(curl -sS -o /dev/null -w '%{http_code}' -H "Host: $BENCH_HOST" "$BASE_URL/" 2>/dev/null || true)"
    if [[ "$code" != "404" ]]; then
      return 0
    fi
    sleep 0.25
  done
  log "the public listener never learned $BENCH_HOST for variant '$label'"
  dump_logs "$label"
  return 1
}

# wait_for_public_tls <label> <host> <ca|->: the https twin, over the https
# listener. --resolve is what sends the SNI (and spares /etc/hosts); the Host
# header is pinned to the bare hostname because curl would otherwise send
# "host:port" and the registry keys hostnames without a port. An empty/absent
# tunnel answers 404 like the http side; 000 here means the TLS handshake
# failed, which for the agent-terminated hostname is also "not registered yet"
# (the server terminates with its own certificate then, and --cacert rightly
# refuses it).
wait_for_public_tls() {
  local label="$1" host="$2" ca="$3" code i
  for i in $(seq 1 40); do
    if [[ "$ca" == "-" ]]; then
      code="$(curl -sSk -o /dev/null -w '%{http_code}' --resolve "$host:$BENCH_HTTPS_PORT:127.0.0.1" -H "Host: $host" "https://$host:$BENCH_HTTPS_PORT/" 2>/dev/null || true)"
    else
      code="$(curl -sS -o /dev/null -w '%{http_code}' --cacert "$ca" --resolve "$host:$BENCH_HTTPS_PORT:127.0.0.1" -H "Host: $host" "https://$host:$BENCH_HTTPS_PORT/" 2>/dev/null || true)"
    fi
    if [[ "$code" != "404" && "$code" != "000" ]]; then
      return 0
    fi
    sleep 0.25
  done
  log "the https listener never learned $host for variant '$label'"
  dump_logs "$label"
  return 1
}

# --- fixtures ----------------------------------------------------------------

write_fixtures() {
  cat > "$WORKDIR/bench_upstream.py" <<'PY'
# One upstream for every scenario: /bulk is BULK_BYTES of incompressible random
# bytes, /small is a handful of bytes.
#
# HTTP/1.1 with an explicit Content-Length on both, because that is what makes
# the keep-alive scenario measurable: a response that is neither close-delimited
# nor chunked leaves the upstream connection open, so the tunnel connection
# stays open with it and curl can send the next request down the same chain.
# With a HTTP/1.0 fixture (python's default) every response would close the
# chain and "keep-alive" would silently become "conn-rate with 1000 requests".
#
# The seed is fixed, so the bytes are the same on every run and across both
# variants of a comparison -- the workload is reproducible even though it looks
# random. Randomness only exists to defeat compression: with a body of 'a', a
# curl that asked for gzip would measure gzip instead of the tunnel. (curl sends
# no Accept-Encoding unless asked, so the gzip leg is skipped anyway; the random
# body removes the temptation.)
import random
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = int(sys.argv[1])
BULK = random.Random(0xB3C4).randbytes(int(sys.argv[2]))
SMALL = b"bench-ok"


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        bulk = self.path.startswith("/bulk")
        body = BULK if bulk else SMALL
        self.send_response(200)
        self.send_header(
            "Content-Type",
            "application/octet-stream" if bulk else "text/plain",
        )
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


HTTPServer(("127.0.0.1", PORT), H).serve_forever()
PY

  # The CA the agent-terminated bench tunnel mints its per-hostname leaves
  # from. -subj and </dev/null are load-bearing, not tidiness: without -subj
  # openssl prompts for the distinguished name even though the config's [dn]
  # section answers it, and a prompt on this script's stdin parks the whole
  # run (the same trap e2e.sh documents at its own CA generation).
  cat > "$WORKDIR/bench-ca.cnf" <<'EOF'
[req]
distinguished_name = dn
x509_extensions = v3_ca
[dn]
CN = bench-zk-ca
[v3_ca]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
EOF
  openssl req -x509 -newkey rsa:2048 -nodes -config "$WORKDIR/bench-ca.cnf" \
    -keyout "$WORKDIR/bench-ca.key" -out "$WORKDIR/bench-ca.crt" -days 2 \
    -subj "/CN=bench-zk-ca" </dev/null >/dev/null 2>&1
  [[ -s "$WORKDIR/bench-ca.crt" ]] || die "could not generate the bench CA"
}

# --- scenarios ---------------------------------------------------------------

# bulk -- MiB/s through the tunnel, median of BULK_RUNS, for #1
#
# curl -o /dev/null keeps the filesystem out of the measurement; %{size_download}
# still counts the bytes, which is how each run validates itself. A short body is
# a failed run, never a fast one.
#
# Two rates are recorded. The headline MiB/s is bytes over the whole transfer,
# handshake and time-to-first-byte included, which is what a user feels. The
# second subtracts time-to-first-byte to isolate the streaming rate; on loopback
# the setup is not free, so the two can differ by a few percent and the JSON
# keeps both rather than pretending the difference is not there.
scenario_bulk() {
  local label="$1"
  local raw="$WORKDIR/bulk-$label.txt"
  local i

  : > "$raw"
  for i in $(seq 1 "$BULK_RUNS"); do
    curl -sS --max-time 300 -o /dev/null \
      -w '%{size_download} %{time_total} %{time_starttransfer}\n' \
      -H "Host: $BENCH_HOST" "$BASE_URL/bulk" >> "$raw"
  done

  python3 - "$raw" "$BULK_BYTES" "$BULK_RUNS" >> "$WORKDIR/result-$label.env" <<'PY'
import sys

raw_path, want, runs_expected = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
whole, streaming = [], []
for line in open(raw_path):
    parts = line.split()
    if len(parts) != 3:
        continue
    size, total, ttfb = float(parts[0]), float(parts[1]), float(parts[2])
    if int(size) != want:
        sys.exit(
            "bulk: got %d of %d bytes -- the tunnel truncated the body"
            % (int(size), want)
        )
    whole.append(size / 1048576.0 / total)
    streaming.append(size / 1048576.0 / max(total - ttfb, 1e-9))

if len(whole) != runs_expected:
    sys.exit("bulk: %d of %d runs completed" % (len(whole), runs_expected))

whole.sort()
streaming.sort()
mid = len(whole) // 2  # median of an odd run count
print("bulk_mib_s=%.2f" % whole[mid])
print("bulk_runs_mib_s=%s" % ",".join("%.2f" % v for v in whole))
print("bulk_stream_mib_s=%.2f" % streaming[mid])
print("bulk_bytes=%d" % want)
print("bulk_runs=%d" % runs_expected)
PY
}

# conn-rate -- 200 short-lived requests, timed in-process, for #2
#
# Each request opens its own public connection and asks for `Connection: close`,
# so one sample covers accept, tunnel/proxy setup, upstream dial, response and
# teardown -- the whole cost of a request that does not get to reuse anything.
#
# The loop lives in python instead of shelling out to curl per request because
# spawning curl costs a few milliseconds, which is the same order as the quantity
# being measured once the mux path is in place; process spawn would blur p50. The
# responses are asserted rather than assumed: if a server ignored
# `Connection: close` the samples would silently stop being fresh connections, so
# every response must come back 200 with the fixture's exact body.
scenario_conn_rate() {
  local label="$1"
  python3 - "$BENCH_HOST" "$BENCH_HTTP_PORT" "$CONN_RATE_REQUESTS" >> "$WORKDIR/result-$label.env" <<'PY'
import http.client
import math
import sys
import time

host, port, n = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
times = []
for i in range(n):
    started = time.perf_counter()
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    conn.request(
        "GET", "/small", headers={"Host": host, "Connection": "close"}
    )
    resp = conn.getresponse()
    body = resp.read()
    if resp.status != 200 or body != b"bench-ok":
        sys.exit(
            "conn-rate: request %d answered %d %r" % (i + 1, resp.status, body[:64])
        )
    conn.close()
    times.append(time.perf_counter() - started)

total = sum(times)
ordered = sorted(times)


def pct(p):
    # nearest rank: with n=200 each percentile is a real sample, not an
    # interpolation between two of them
    return ordered[max(0, math.ceil(p * n) - 1)]


print("conn_rate_rps=%.1f" % (n / total))
print("conn_rate_total_s=%.3f" % total)
print("conn_rate_p50_ms=%.2f" % (pct(0.50) * 1000))
print("conn_rate_p95_ms=%.2f" % (pct(0.95) * 1000))
print("conn_rate_min_ms=%.2f" % (ordered[0] * 1000))
print("conn_rate_max_ms=%.2f" % (ordered[-1] * 1000))
print("conn_rate_n=%d" % n)
PY
}

# keep-alive -- 1000 requests in one curl invocation, for #3
#
# One curl process and 1000 globbed URLs: curl reuses the connection between
# transfers whenever the path allows it. The number of connects (%{num_connects},
# summed over transfers) is reported next to the rate because the two answer
# different questions -- 1000 req/s over 1000 connects is conn-rate spelled
# differently, 1000 req/s over 1 connect is an actually reused connection.
#
# The clock is python's because macOS date(1) has no %N; at 1000 requests curl's
# own startup is noise in the wall time. curl's exit status and every HTTP status
# code are checked, so a run that half-failed cannot be read as a fast one.
scenario_keepalive() {
  local label="$1"
  python3 - "$BENCH_HOST" "$BENCH_HTTP_PORT" "$KEEPALIVE_REQUESTS" >> "$WORKDIR/result-$label.env" <<'PY'
import subprocess
import sys
import time

host, port, n = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
url = "http://127.0.0.1:%d/?n=[1-%d]" % (port, n)
cmd = [
    "curl", "-sS", "--max-time", "300",
    "-o", "/dev/null",
    "-H", "Host: %s" % host,
    "-w", "%{http_code} %{num_connects}\n",
    url,
]
started = time.perf_counter()
proc = subprocess.run(cmd, capture_output=True, text=True)
wall = time.perf_counter() - started
if proc.returncode != 0:
    sys.exit(
        "keep-alive: curl failed (%d): %s"
        % (proc.returncode, proc.stderr.strip()[:400])
    )

lines = [line for line in proc.stdout.splitlines() if line.strip()]
if len(lines) != n:
    sys.exit("keep-alive: %d of %d transfers completed" % (len(lines), n))

conns = 0
for i, line in enumerate(lines):
    code, _, opens = line.partition(" ")
    if code != "200":
        sys.exit("keep-alive: transfer %d answered %s" % (i + 1, code))
    conns += int(opens)

print("keepalive_rps=%.1f" % (n / wall))
print("keepalive_wall_s=%.3f" % wall)
print("keepalive_conns=%d" % conns)
print("keepalive_n=%d" % n)
PY
}

# tls-conn-rate -- 200 requests over the https listener, fresh TLS connection
# each, once per terminator, for the zero-knowledge cluster.
#
# The request loop is python's for the same reason conn-rate's is: process
# spawn would sit inside the quantity being measured. SNI is sent explicitly
# (server_hostname), because the https listener routes on it -- a python
# client pointed at 127.0.0.1 would send none, and both endpoints would come
# back through the server-cert terminator instead of the two routes under
# test. Each sample is one full TCP + TLS + request + teardown cycle, which is
# the honest unit here: both terminators pay a handshake, so the difference is
# route + certificate, not TLS vs no TLS. The certificate caveat is stated in
# the header above (RSA-2048 server dev pair vs ECDSA P-256 minted leaf).
#
# The agent column handshakes with FULL verification against the harness CA
# (CERT_REQUIRED and hostname check are PROTOCOL_TLS_CLIENT's defaults), so it
# doubles as a correctness check: a bench run in which the passthrough path
# regressed into edge termination would fail on the certificate, not report a
# plausible-looking number measured through the wrong route.
scenario_tls_conn_rate() {
  local label="$1"
  python3 - "$BENCH_TLS_EDGE_HOST" "$BENCH_TLS_ZK_HOST" "$BENCH_HTTPS_PORT" \
    "$WORKDIR/bench-ca.crt" "$TLS_REQUESTS" >> "$WORKDIR/result-$label.env" <<'PY'
import math
import socket
import ssl
import sys
import time

edge_host, zk_host, port, ca_path, n = (
    sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4], int(sys.argv[5]),
)


def measure(host, ca):
    times = []
    for i in range(n):
        started = time.perf_counter()
        raw = socket.create_connection(("127.0.0.1", port), timeout=30)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        if ca:
            # defaults: CERT_REQUIRED, check_hostname on -- verified against
            # the harness CA and the SNI name, both of which the agent's
            # minted leaf must satisfy
            ctx.load_verify_locations(ca)
        else:
            # the server's own certificate is the embedded dev pair
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        tls = ctx.wrap_socket(raw, server_hostname=host)
        try:
            tls.sendall(
                (
                    "GET /small HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n"
                    % host
                ).encode()
            )
            data = b""
            while True:
                chunk = tls.recv(65536)
                if not chunk:
                    break
                data += chunk
        finally:
            tls.close()
        times.append(time.perf_counter() - started)

        head, _, body = data.partition(b"\r\n\r\n")
        parts = head.split(b" ")
        if len(parts) < 2 or parts[1] != b"200" or body != b"bench-ok":
            sys.exit(
                "tls-conn-rate (%s): request %d answered %r %r"
                % (host, i + 1, head[:64], body[:32])
            )
    return times


def report(prefix, times):
    ordered = sorted(times)
    total = sum(times)

    def pct(p):
        # nearest rank, like conn-rate
        return ordered[max(0, math.ceil(p * len(times)) - 1)]

    print("%s_rps=%.1f" % (prefix, len(times) / total))
    print("%s_p50_ms=%.2f" % (prefix, pct(0.50) * 1000))
    print("%s_p95_ms=%.2f" % (prefix, pct(0.95) * 1000))


report("tls_edge", measure(edge_host, None))
report("tls_agent", measure(zk_host, ca_path))
print("tls_requests=%d" % n)
PY
}

# --- variant lifecycle -------------------------------------------------------

start_stack() {
  local label="$1" dir="$2" port

  for port in "$BENCH_UPSTREAM_PORT" "$BENCH_HTTP_PORT" "$BENCH_HTTPS_PORT" "$BENCH_TUNNEL_PORT" "$BENCH_ADMIN_PORT"; do
    if port_in_use "$port"; then
      die "port $port is already in use -- a previous bench run (or another service) still holds it; this harness owns 19101/18180/18480/15443/19190"
    fi
  done

  # Stale logs are a correctness problem, not cosmetics: the client appends and
  # the tunnel wait greps, so an old "Tunnel established" would let the
  # scenarios start before this run's agent is up.
  rm -f /tmp/ngrok-bench-"$label"-*.log

  python3 "$WORKDIR/bench_upstream.py" "$BENCH_UPSTREAM_PORT" "$BULK_BYTES" \
    > "/tmp/ngrok-bench-$label-upstream.log" 2>&1 &
  UPSTREAM_PID=$!
  PIDS+=("$UPSTREAM_PID")

  # The https listener is enabled for tls-conn-rate; the http scenarios are
  # unaffected (the SNI peek lives entirely on the https path).
  "$dir/ngrokd" \
    -domain=localhost \
    -httpAddr="127.0.0.1:$BENCH_HTTP_PORT" \
    -httpsAddr="127.0.0.1:$BENCH_HTTPS_PORT" \
    -tunnelAddr="127.0.0.1:$BENCH_TUNNEL_PORT" \
    -adminAddr="127.0.0.1:$BENCH_ADMIN_PORT" \
    > "/tmp/ngrok-bench-$label-ngrokd.log" 2>&1 &
  NGROKD_PID=$!
  PIDS+=("$NGROKD_PID")
  sleep 1

  # Three tunnels, one client: the http bench endpoint, the same upstream over
  # an edge-terminated https endpoint, and over an agent-terminated one. All
  # three serve the same fixture, so a number that looks off between columns
  # cannot be the upstream's.
  cat > "$WORKDIR/ngrok-bench-$label.yml" <<YAML
server_addr: 127.0.0.1:$BENCH_TUNNEL_PORT
trust_host_root_certs: true
tunnels:
  bench:
    hostname: $BENCH_HOST
    proto:
      http: $BENCH_UPSTREAM_PORT
  bench-tls:
    hostname: $BENCH_TLS_EDGE_HOST
    proto:
      https: $BENCH_UPSTREAM_PORT
  bench-zk:
    hostname: $BENCH_TLS_ZK_HOST
    proto:
      https: $BENCH_UPSTREAM_PORT
    agent_tls_termination: true
    tls:
      ca_crt: $WORKDIR/bench-ca.crt
      ca_key: $WORKDIR/bench-ca.key
YAML

  "$dir/ngrok" -config="$WORKDIR/ngrok-bench-$label.yml" \
    -log="/tmp/ngrok-bench-$label-client.log" start bench bench-tls bench-zk \
    > "/tmp/ngrok-bench-$label-client-stdout.log" 2>&1 &
  CLIENT_PID=$!
  PIDS+=("$CLIENT_PID")
}

stop_stack() {
  local code i

  # The client goes first, and ngrokd is left up long enough to be asked: 404 is
  # ngrokd's answer for a hostname it has no tunnel for, and the next variant
  # cannot register `bench` until the registry has let go of it (e2e.sh documents
  # the same wait for its restarted clients).
  kill "$CLIENT_PID" 2>/dev/null || true
  wait "$CLIENT_PID" 2>/dev/null || true
  for i in $(seq 1 40); do
    code="$(curl -sS -o /dev/null -w '%{http_code}' -H "Host: $BENCH_HOST" "$BASE_URL/" 2>/dev/null || true)"
    if [[ "$code" == "404" ]]; then
      break
    fi
    sleep 0.25
  done

  kill "$NGROKD_PID" "$UPSTREAM_PID" 2>/dev/null || true
  wait "$NGROKD_PID" 2>/dev/null || true
  wait "$UPSTREAM_PID" 2>/dev/null || true
  CLIENT_PID=""
  NGROKD_PID=""
  UPSTREAM_PID=""

  # Go listeners set SO_REUSEADDR, so a quick rebind is fine; this pause is for
  # the connect probe above, which would otherwise race a half-closed socket.
  sleep 0.5
}

# One discarded request before the measured ones: the first request through a
# fresh tunnel pays client-side one-time setup that no later request pays, and it
# belongs to neither the first bulk sample nor the first conn-rate sample. It is
# never counted anywhere. The https endpoints get their own warmups for the same
# reason -- the agent-terminated one also mints its first leaf certificate on
# that handshake, which is exactly the kind of one-time cost warmup exists for.
warmup() {
  local label="$1"
  curl -sS --max-time 60 -o /dev/null -H "Host: $BENCH_HOST" "$BASE_URL/small" \
    || die "warmup request through variant '$label' failed"
  curl -sSk --max-time 60 -o /dev/null --resolve "$BENCH_TLS_EDGE_HOST:$BENCH_HTTPS_PORT:127.0.0.1" \
    -H "Host: $BENCH_TLS_EDGE_HOST" "https://$BENCH_TLS_EDGE_HOST:$BENCH_HTTPS_PORT/small" \
    || die "https warmup through variant '$label' failed (edge endpoint)"
  curl -sS --max-time 60 -o /dev/null --cacert "$WORKDIR/bench-ca.crt" \
    --resolve "$BENCH_TLS_ZK_HOST:$BENCH_HTTPS_PORT:127.0.0.1" \
    -H "Host: $BENCH_TLS_ZK_HOST" "https://$BENCH_TLS_ZK_HOST:$BENCH_HTTPS_PORT/small" \
    || die "https warmup through variant '$label' failed (agent-terminated endpoint)"
}

run_variant() {
  local label="$1" dir="$2"
  CURRENT_LABEL="$label"
  log "=== variant '$label': $dir ==="

  check_binaries "$dir"
  : > "$WORKDIR/result-$label.env"
  echo "dir=$dir" >> "$WORKDIR/result-$label.env"

  start_stack "$label" "$dir"
  wait_for_tunnel "$label"
  wait_for_public "$label"
  wait_for_public_tls "$label" "$BENCH_TLS_EDGE_HOST" "-"
  wait_for_public_tls "$label" "$BENCH_TLS_ZK_HOST" "$WORKDIR/bench-ca.crt"
  warmup "$label"

  log "bulk: $((BULK_BYTES / 1024 / 1024)) MiB x $BULK_RUNS runs"
  scenario_bulk "$label"
  log "conn-rate: $CONN_RATE_REQUESTS requests, Connection: close"
  scenario_conn_rate "$label"
  log "keep-alive: $KEEPALIVE_REQUESTS requests in one curl invocation"
  scenario_keepalive "$label"
  log "tls-conn-rate: $TLS_REQUESTS requests x {edge, agent-terminated} over https"
  scenario_tls_conn_rate "$label"

  stop_stack
  log "variant '$label' done (logs: /tmp/ngrok-bench-$label-*.log)"
}

# --- reporting ---------------------------------------------------------------

write_params() {
  local mode="$1" first="$2" second="$3"
  {
    echo "mode=$mode"
    echo "host=$BENCH_HOST"
    echo "public_port=$BENCH_HTTP_PORT"
    echo "https_port=$BENCH_HTTPS_PORT"
    echo "tunnel_port=$BENCH_TUNNEL_PORT"
    echo "upstream_port=$BENCH_UPSTREAM_PORT"
    echo "admin_port=$BENCH_ADMIN_PORT"
    echo "bulk_bytes=$BULK_BYTES"
    echo "bulk_runs=$BULK_RUNS"
    echo "conn_rate_requests=$CONN_RATE_REQUESTS"
    echo "keepalive_requests=$KEEPALIVE_REQUESTS"
    echo "tls_requests=$TLS_REQUESTS"
    echo "tls_edge_host=$BENCH_TLS_EDGE_HOST"
    echo "tls_zk_host=$BENCH_TLS_ZK_HOST"
    if [[ "$mode" == "compare" ]]; then
      echo "baseline_dir=$first"
      echo "current_dir=$second"
    else
      echo "built_dir=$first"
    fi
  } > "$WORKDIR/params.env"
}

# One python process renders the table AND the JSON from the same key=value
# files, so the two outputs cannot disagree about a number.
emit_report() {
  local mode="$1" params="$2"
  shift 2
  python3 - "$mode" "$RESULT_JSON" "$params" "$@" <<'PY'
import json
import sys
import time

mode, json_path, params_path = sys.argv[1], sys.argv[2], sys.argv[3]
specs = sys.argv[4:]

ROWS = [
    ("bulk MiB/s (median of 3)", "bulk_mib_s", "%.1f"),
    ("conn-rate req/s (200 x Connection: close)", "conn_rate_rps", "%.1f"),
    ("conn-rate p50 ms (lower is better)", "conn_rate_p50_ms", "%.2f"),
    ("conn-rate p95 ms (lower is better)", "conn_rate_p95_ms", "%.2f"),
    ("keep-alive req/s (1000, one curl)", "keepalive_rps", "%.1f"),
    ("keep-alive TCP conns opened", "keepalive_conns", "%d"),
    ("tls edge req/s (200 x fresh TLS conn)", "tls_edge_rps", "%.1f"),
    ("tls edge p50 ms (lower is better)", "tls_edge_p50_ms", "%.2f"),
    ("tls edge p95 ms (lower is better)", "tls_edge_p95_ms", "%.2f"),
    ("tls agent-passthrough req/s (same listener, CA-verified)", "tls_agent_rps", "%.1f"),
    ("tls agent-passthrough p50 ms (lower is better)", "tls_agent_p50_ms", "%.2f"),
    ("tls agent-passthrough p95 ms (lower is better)", "tls_agent_p95_ms", "%.2f"),
]


def load_kv(path):
    kv = {}
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, val = line.partition("=")
            kv[key.strip()] = val.strip()
    return kv


def number(val):
    # the key=value files are text; JSON should carry numbers as numbers
    for cast in (int, float):
        try:
            return cast(val)
        except ValueError:
            pass
    return val


def cell(kv, key, fmt):
    if key not in kv:
        return "n/a"
    try:
        return fmt % float(kv[key])
    except (TypeError, ValueError):
        return kv[key]


params = load_kv(params_path)
variants = []
for spec in specs:
    label, _, path = spec.partition("=")
    variants.append((label, load_kv(path)))

print(
    "bench: host=%s public=%s tunnel=%s upstream=%s admin=%s"
    % (
        params.get("host", "?"),
        params.get("public_port", "?"),
        params.get("tunnel_port", "?"),
        params.get("upstream_port", "?"),
        params.get("admin_port", "?"),
    )
)
print(
    "workload: bulk=%s MiB x %s runs, conn-rate=%s requests, keep-alive=%s requests in one curl, tls-conn-rate=%s requests x {edge, agent-terminated}"
    % (
        int(params.get("bulk_bytes", 0)) // 1024 // 1024,
        params.get("bulk_runs", "?"),
        params.get("conn_rate_requests", "?"),
        params.get("keepalive_requests", "?"),
        params.get("tls_requests", "?"),
    )
)
for label, kv in variants:
    print("%s: %s" % (label, kv.get("dir", "?")))
print()

if len(variants) == 1:
    label, kv = variants[0]
    print("| scenario | %s |" % label.upper())
    print("|---|---:|")
    for text, key, fmt in ROWS:
        print("| %s | %s |" % (text, cell(kv, key, fmt)))
else:
    base_label, base = variants[0]
    cur_label, cur = variants[1]
    print("| scenario | %s | %s | DELTA |" % (base_label.upper(), cur_label.upper()))
    print("|---|---:|---:|---:|")
    for text, key, fmt in ROWS:
        delta = "n/a"
        try:
            before, after = float(base[key]), float(cur[key])
            delta = "%+.1f%%" % ((after - before) / before * 100.0) if before else "+0.0%"
        except (KeyError, TypeError, ValueError):
            pass
        print(
            "| %s | %s | %s | %s |"
            % (text, cell(base, key, fmt), cell(cur, key, fmt), delta)
        )
print()

summary = {
    "mode": mode,
    "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
    "params": {key: number(val) for key, val in params.items()},
    "variants": {
        label: {key: number(val) for key, val in kv.items()}
        for label, kv in variants
    },
}

if len(variants) == 2:
    deltas = {}
    for _, key, _ in ROWS:
        try:
            before, after = float(variants[0][1][key]), float(variants[1][1][key])
        except (KeyError, TypeError, ValueError):
            continue
        if before:
            deltas[key] = round((after - before) / before * 100.0, 2)
    summary["delta_pct"] = deltas

with open(json_path, "w") as fh:
    json.dump(summary, fh, indent=2, sort_keys=True)
    fh.write("\n")
PY
}

# --- main --------------------------------------------------------------------

main() {
  case $# in
    0)
      local build_dir="$WORKDIR/bin"
      mkdir -p "$build_dir"
      log "building the working tree with -tags debug into $build_dir"
      go build -tags debug -o "$build_dir/ngrok" ./main/ngrok
      go build -tags debug -o "$build_dir/ngrokd" ./main/ngrokd
      write_fixtures
      write_params "single" "$build_dir" ""
      run_variant "single" "$build_dir"
      emit_report "single" "$WORKDIR/params.env" "single=$WORKDIR/result-single.env"
      ;;
    2)
      write_fixtures
      write_params "compare" "$1" "$2"
      run_variant "baseline" "$1"
      run_variant "current" "$2"
      emit_report "compare" "$WORKDIR/params.env" \
        "baseline=$WORKDIR/result-baseline.env" \
        "current=$WORKDIR/result-current.env"
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
  log "wrote $RESULT_JSON; logs in /tmp/ngrok-bench-*.log"
}

main "$@"
