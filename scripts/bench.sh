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
# Those ports are deliberately disjoint from scripts/e2e.sh so the two
# harnesses can run at the same time without fighting over a port. e2e.sh's
# full claims: public http :18080-:18092, https :18443-:18446, tunnel
# :14443-:14457, admin :19090-:19103, local upstreams :19001-:19022 -- its
# ngrok-bot group's ngrokd owns :19101, the fixture's original port, which is
# why the fixture moved to :19110 here.
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
#   quic columns  after each variant's smux numbers, the stack is torn down and
#               brought back up with the QUIC carrier: ngrokd additionally
#               runs -quicAddr (UDP on the tunnel port) and the client pins
#               proxy_transport: quic. bulk, conn-rate and keep-alive run
#               again, emitting quic_-prefixed keys; the harness FAILS the run
#               if the client log does not show an established QUIC carrier,
#               so a silent smux degradation can never be reported as a quic
#               number. The tls-conn-rate scenarios deliberately do not run
#               here -- the carrier under test is the agent leg, and one
#               http endpoint exercises it exactly as well as three.
#
#               THE HONESTY CAVEAT, which the table carries too (see the NOTE
#               row in ROWS): loopback has no packet loss, and QUIC's reason
#               to exist is per-stream independence under loss -- one lost
#               packet stalls every stream on the smux carrier and no stream
#               on the QUIC one. A lossless loopback cannot show that win.
#               These numbers establish PARITY between the carriers on the
#               happy path (and the cost of the QUIC handshake on
#               conn-rate's fresh sessions), not superiority.
#
#   dedup columns  a third leg per variant, for the carrier_dedup cluster:
#               the same stack shape run TWICE per carrier -- once over smux
#               (keys dedup_*) and once over QUIC (keys quic_dedup_, with
#               -quicAddr and proxy_transport: quic, gated on the carrier
#               line like the quic leg). The honest ON/OFF shape needs two
#               CLIENT processes on one ngrokd, not a flag flip: the dedup
#               proposal is client-granular (any carrier_dedup tunnel makes
#               the client propose on every stream it sends), so a single
#               client cannot be its own control. A plain client registers
#               `bench` (the OFF side); a second client registers `bench-dd`
#               with carrier_dedup: true (the ON side); both serve the same
#               upstream fixture. Three payloads:
#
#                 dedup-llm    100 POSTs over ONE keep-alive connection, each
#                              a ~200-byte timestamped head + shared ~32 KiB
#                              prompt + ~200-byte varying suffix (the head
#                              mutation is what forces the CDC resync). THE
#                              KILL CRITERION lives here: the pre-registered
#                              expectation is >= ~50% offered-bytes reduction
#                              on the request direction, read from the codec's
#                              per-stream close lines (server log = request
#                              direction, client log = response direction).
#                 dedup-sse    200 text/event-stream events of static
#                              boilerplate in one response, with and without
#                              Accept-Encoding: gzip. The no-gzip leg shows
#                              the win; the gzip leg shows its boundary --
#                              gzip'd bytes are incompressible fresh AEAD
#                              output to the codec, so saved% should collapse
#                              toward zero, which is the honest result, not a
#                              failure. (The upstream gzips only when asked.)
#                 dedup-bulk   the control: the same 64 MiB random body
#                              through both tunnels. Random bytes never
#                              repeat, so the codec can only add framing; the
#                              pre-registered expectation is <= ~1% wire
#                              overhead, measured as (framed-offered)/offered
#                              from the close lines -- a RATIO, and therefore
#                              exact -- not from wall-clock MiB/s, where this
#                              box's run-to-run spread (up to ~15%, documented
#                              above) dwarfs the quantity.
#
#               The close-line ratio (framed vs offered bytes) is the honest
#               measured quantity throughout because it is not a timing
#               measurement: loopback noise cannot move it. Wall-clock and
#               p95 numbers are recorded beside them for context, with the
#               standing admission that loopback p95 is expected neutral-
#               to-slightly-worse under the codec. CPU time of all three
#               processes (ngrokd, plain client, dedup client) is captured at
#               stack teardown; the readable delta is plain client vs dedup
#               client (same traffic shape, one running the codec). The ngrokd
#               figure mixes both clients' traffic in one process and cannot
#               be attributed -- reported as-is for completeness.
#
#   netem variant  the bandwidth-constrained run, where the byte win is
#               allowed to show as wall time. tc cannot do it in the target
#               environment (the container VM's kernel ships fq_codel only --
#               no htb/tbf/netem -- and its tc binary cannot load modules),
#               so the shaping lives in a userspace token-bucket relay
#               (scripts/bench-netem/relay.py, 10 Mbit/s) that owns the
#               dialed carrier address: it listens on 127.0.0.1:<tunnel
#               port> and forwards to ngrokd, which BENCH_TUNNEL_BIND parks
#               on 127.0.0.2. Clients still dial 127.0.0.1, the harness is
#               otherwise untouched, and OFF/ON traverse the same relay, so
#               the leg delta still isolates the codec. The whole run sits
#               in one `unshare -Urn` netns, so the relay's extra listener
#               and the 127.0.0.2 alias never outlive it.
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
# Guarded on the toolchain existing: the two-directory form runs prebuilt
# binaries and needs no Go -- on a machine without one (the bench VM), `go
# env` would abort under set -e before a single binary was even looked at.
if command -v go >/dev/null 2>&1; then
  export GOCACHE="${GOCACHE:-$(go env GOCACHE)}"
  export GOMODCACHE="${GOMODCACHE:-$(go env GOMODCACHE)}"
  export GOPATH="${GOPATH:-$(go env GOPATH)}"
fi
export NGROK_INSECURE_SKIP_VERIFY="${NGROK_INSECURE_SKIP_VERIFY:-1}"

# Fixed parameters. Keeping these as constants rather than flags is deliberate.
# The standing rule from e2e.sh: grep every port in every script before
# picking one. This harness owns the 18180/18480/15443/19110/19190 corner.
BENCH_HOST="bench"            # vhost the tunnel registers; also the Host: header
BENCH_UPSTREAM_PORT=19110     # python fixture (was 19101; e2e.sh's bot group owns that)
BENCH_HTTP_PORT=18180         # public listener         (e2e.sh uses 18080-18092)
BENCH_HTTPS_PORT=18480        # public https listener   (e2e.sh uses 18443-18446)
BENCH_TUNNEL_PORT=15443       # client <-> server       (e2e.sh uses 14443-14457)
BENCH_ADMIN_PORT=19190        # admin                   (e2e.sh uses 19090-19103)
# What ngrokd BINDS the tunnel listener on. Clients always dial 127.0.0.1, so
# the default is exactly what it always was; the netem variant sets 127.0.0.2
# so the shaping relay can own 127.0.0.1:<tunnel port> on the carrier path.
# It changes no measured quantity -- it exists so the harness needs no fork.
BENCH_TUNNEL_BIND="${BENCH_TUNNEL_BIND:-127.0.0.1}"
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

# The dedup leg's knobs (constants for the same reason everything above is):
# payload sizes and request counts match the e2e group's fixtures so the two
# harnesses' numbers describe the same workload, and the OFF/ON hostnames are
# fixed so a table row is reproducible.
DEDUP_LLM_REQUESTS=100
DEDUP_SSE_EVENTS=200
DEDUP_DD_HOST="bench-dd"

RESULT_JSON="${BENCH_RESULT_JSON:-/tmp/ngrok-bench-result.json}"

WORKDIR="$(mktemp -d)"
PIDS=()
CLIENT_PID=""
NGROKD_PID=""
UPSTREAM_PID=""
CURRENT_LABEL=""
VARIANT_LABEL=""   # the result file the dedup leg appends to (set by run_variant_dedup)

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

# The dedup leg's fixtures. Same layout as write_fixtures: an upstream with
# the routes the payloads need, a driver that speaks them, and a parser for
# the codec's close lines. The payload vocabulary and its history are
# documented once, in the driver, and both python files build payloads with
# the same pinned construction the e2e group uses (the digests below are the
# same pins).
write_dedup_fixtures() {
  cat > "$WORKDIR/dedup_upstream.py" <<'PY'
# The dedup leg's upstream. Same rules as bench_upstream.py: HTTP/1.1 with an
# explicit Content-Length on every response, because that is what keeps the
# keep-alive chain (and therefore the per-stream codec tables) alive. Routes:
#
#   /small             a handful of bytes, for warmup
#   POST /echo         answers "sha256:<hex>:<len>" of the exact bytes read,
#                      so the llm driver can assert byte-correctness through
#                      the whole chain on every request
#   /sse?events=N      N text/event-stream events of STATIC boilerplate (the
#                      payload's point: the repeated text is what the codec
#                      can reference) with a fixed-width varying id/seq near
#                      each event's head. Asked with Accept-Encoding: gzip,
#                      the whole stream comes back gzipped -- the
#                      dedup-under-gzip leg needs genuinely compressed bytes
#                      on the carrier, not a stub.
#   /bulk              BULK_BYTES of seeded random bytes -- the control
#                      payload, same seed discipline as bench_upstream.py.
import gzip
import hashlib
import random
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

PORT = int(sys.argv[1])
BULK = random.Random(0xB3C4).randbytes(int(sys.argv[2]))
SMALL = b"bench-ok"

# Must stay byte-identical to the driver's construction below -- the driver
# asserts the response equals its own build, so drift fails the run instead
# of benchmarking a different payload.
VOCAB = (
    "the of and a to in is you that it he was for on are as with his they at be this have from or one had by word but not what all were we when your can said there use an each which she do how their if will up other about out many then them these so some her would make like him into time has look two more write go see number no way could people my than first water been call who oil its now find long down day did get come made may part over new sound take only little work know place year live me back give most very after thing our just name good sentence man think say great where help through much before line right too mean old any same tell boy follow came want show also around form three small set put end does another well large must big even such because turn here why ask went light kind off need house picture try us again animal point mother world near build self earth father"
).split()
MASK = (1 << 64) - 1


class Xorshift:
    def __init__(self, seed):
        self.s = seed & MASK

    def next(self):
        self.s ^= (self.s << 13) & MASK
        self.s ^= self.s >> 7
        self.s ^= (self.s << 17) & MASK
        return self.s


def build_words(seed, n):
    x = Xorshift(seed)
    return "".join(VOCAB[x.next() % len(VOCAB)] + " " for _ in range(n)).encode()


SSE_STATIC = build_words(0x5EED, 1900)


def sse_payload(n):
    out = []
    for i in range(n):
        out.append(
            (
                'id: %04d\nevent: message\ndata: {"seq":%04d,"text":"' % (i, i)
            ).encode()
            + SSE_STATIC
            + b'"}\n\n'
        )
    return b"".join(out)


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def send_body(self, body, content_type, encoding=None):
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        if encoding:
            self.send_header("Content-Encoding", encoding)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        url = urlparse(self.path)
        if url.path == "/bulk":
            self.send_body(BULK, "application/octet-stream")
        elif url.path == "/sse":
            n = int(parse_qs(url.query).get("events", ["200"])[0])
            payload = sse_payload(n)
            if "gzip" in (self.headers.get("Accept-Encoding") or ""):
                self.send_body(gzip.compress(payload), "text/event-stream", "gzip")
            else:
                self.send_body(payload, "text/event-stream")
        else:
            self.send_body(SMALL, "text/plain")

    def do_POST(self):
        want = int(self.headers.get("Content-Length", "0") or "0")
        data = b""
        while len(data) < want:
            chunk = self.rfile.read(want - len(data))
            if not chunk:
                break
            data += chunk
        body = ("sha256:%s:%d" % (hashlib.sha256(data).hexdigest(), len(data))).encode()
        self.send_body(body, "text/plain")

    def log_message(self, *_):
        pass


HTTPServer(("127.0.0.1", PORT), H).serve_forever()
PY

  cat > "$WORKDIR/dedup_driver.py" <<'PY'
# The dedup leg's driver: one process per OFF/ON leg of one payload, printing
# its numbers as key=value lines that scenario_dedup_* appends to the result
# file. The payload construction is the SAME pinned one the e2e group uses
# (same vocabulary, same xorshift, same digests), and for the same reason:
#
# The first draft of the e2e fixtures built bodies by repeating one sentence,
# and strictly periodic text walks the Gear hash through a handful of
# distinct 12-byte windows -- the trigger never fires, every batch rides as
# an unsaved TAIL, and the payload meant to prove dedup works proves nothing.
# Real prompts have thousands of distinct windows; so does diverse word
# text. The digests asserted below were computed by a Go program running this
# exact construction, and the codec was probe-measured on those bytes (llm
# payload: ~83% saved over 100 requests), so any drift fails here instead of
# quietly benchmarking a different payload. (The vocabulary is 184 words: a
# once-200-word list that lost sixteen to a transcription slip before the
# constants were pinned; 184 is what the pins attest to.)
import hashlib
import http.client
import gzip as gzip_mod
import math
import sys
import time

mode, host, port, n, result_path, prefix = (
    sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]),
    sys.argv[5], sys.argv[6],
)
gzip_wanted = len(sys.argv) > 7 and sys.argv[7] == "gzip"

VOCAB = (
    "the of and a to in is you that it he was for on are as with his they at be this have from or one had by word but not what all were we when your can said there use an each which she do how their if will up other about out many then them these so some her would make like him into time has look two more write go see number no way could people my than first water been call who oil its now find long down day did get come made may part over new sound take only little work know place year live me back give most very after thing our just name good sentence man think say great where help through much before line right too mean old any same tell boy follow came want show also around form three small set put end does another well large must big even such because turn here why ask went light kind off need house picture try us again animal point mother world near build self earth father"
).split()
assert len(VOCAB) == 184
MASK = (1 << 64) - 1


class Xorshift:
    def __init__(self, seed):
        self.s = seed & MASK

    def next(self):
        self.s ^= (self.s << 13) & MASK
        self.s ^= self.s >> 7
        self.s ^= (self.s << 17) & MASK
        return self.s


def build_words(seed, n_words):
    x = Xorshift(seed)
    return "".join(VOCAB[x.next() % len(VOCAB)] + " " for _ in range(n_words)).encode()


PROMPT = build_words(0xC0FFEE, 6800)
SSE_STATIC = build_words(0x5EED, 1900)

for name, blob, want_len, want_sha in (
    ("prompt", PROMPT, 32715,
     "23fddb87539329f58e564df10ded84f67f0d085db6c36f732980044187a767e8"),
    ("sse-static", SSE_STATIC, 9128,
     "2d8a90a5986d36b2ec88f63130c89e011cc21f8257ed73314c5c114767c22fa9"),
):
    got = hashlib.sha256(blob).hexdigest()
    if len(blob) != want_len or got != want_sha:
        sys.exit("%s payload drifted: len=%d sha=%s, wanted len=%d sha=%s"
                 % (name, len(blob), got, want_len, want_sha))


def llm_body(i):
    head = ('{"ts":"2026-10-09T12:00:%02d.%03dZ","nonce":"%08x","model":"llama3.1:8b",'
            '"stream":false,"messages":[{"role":"system","content":"'
            % (i % 60, i, (i * 2654435761) & 0xFFFFFFFF))
    suffix = ('turn %04d: summarize the context above in one sentence and end with the '
              'unique tag zzz-%04d plus this padding phrase so the varying suffix stays '
              'near two hundred bytes: %04d."}]}' % (i, i, i))
    return (head + PROMPT.decode() + '"},{"role":"user","content":"' + suffix).encode()


_l0 = llm_body(0)
if len(_l0) != 33051 or hashlib.sha256(_l0).hexdigest() != (
    "1dbdbb3d89ab7f892a38f41768124675eab34c4f03d28f66a8e7c22f18fc7cca"
):
    sys.exit("llm payload drifted: len=%d sha=%s" % (len(_l0), hashlib.sha256(_l0).hexdigest()))


def sse_payload(count):
    out = []
    for i in range(count):
        out.append(
            (
                'id: %04d\nevent: message\ndata: {"seq":%04d,"text":"' % (i, i)
            ).encode()
            + SSE_STATIC
            + b'"}\n\n'
        )
    return b"".join(out)


out = open(result_path, "a")


def emit(key, val):
    out.write("%s%s=%s\n" % (prefix, key, val))


def p95(times):
    ordered = sorted(times)
    return ordered[max(0, math.ceil(0.95 * len(times)) - 1)]


if mode == "llm":
    # 100 POSTs over ONE keep-alive connection: the per-stream codec tables
    # only pay off within a stream, so the payload must ride one.
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=120)
    times = []
    for i in range(n):
        payload = llm_body(i)
        want = ("sha256:%s:%d" % (
            hashlib.sha256(payload).hexdigest(), len(payload)
        )).encode()
        started = time.perf_counter()
        conn.request("POST", "/echo", body=payload, headers={"Host": host})
        resp = conn.getresponse()
        answer = resp.read()
        times.append(time.perf_counter() - started)
        if resp.status != 200 or answer != want:
            sys.exit("llm: request %d answered %d %r" % (i, resp.status, answer[:96]))
    conn.close()
    emit("rps", "%.1f" % (n / sum(times)))
    emit("p95_ms", "%.2f" % (p95(times) * 1000))
    emit("wall_s", "%.3f" % sum(times))
    emit("n", n)
    emit("bytes_each", len(llm_body(0)))

elif mode == "sse":
    # One GET, one response of n events -- the honest unit for a stream
    # payload is events/s over the response, not requests/s.
    expected = sse_payload(n)
    headers = {"Host": host}
    if gzip_wanted:
        headers["Accept-Encoding"] = "gzip"
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=120)
    started = time.perf_counter()
    conn.request("GET", "/sse?events=%d" % n, headers=headers)
    resp = conn.getresponse()
    wire = resp.read()
    wall = time.perf_counter() - started
    conn.close()
    body = wire
    encoding = resp.getheader("Content-Encoding") or ""
    if gzip_wanted:
        if encoding != "gzip":
            sys.exit("sse: asked for gzip, answered Content-Encoding=%r" % encoding)
        body = gzip_mod.decompress(wire)
    elif encoding:
        sys.exit("sse: unanswered Content-Encoding=%r" % encoding)
    if body != expected:
        sys.exit("sse: body mismatch: got %d bytes, built %d" % (len(body), len(expected)))
    emit("events_per_s", "%.1f" % (n / wall))
    emit("mib_s", "%.2f" % (len(expected) / 1048576.0 / wall))
    emit("events", n)
    emit("plain_bytes", len(expected))
    emit("wire_bytes", len(wire))
    emit("gzip", 1 if gzip_wanted else 0)

elif mode == "bulk":
    # The control payload: n fresh-connection GETs of the random bulk, like
    # scenario_bulk's runs. Size-validated per run; a short body is a failed
    # run, never a fast one.
    bulk_bytes = int(sys.argv[7])
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=300)
    rates = []
    for i in range(n):
        started = time.perf_counter()
        conn.request("GET", "/bulk", headers={"Host": host})
        resp = conn.getresponse()
        data = resp.read()
        rates.append(time.perf_counter() - started)
        if resp.status != 200 or len(data) != bulk_bytes:
            sys.exit("bulk: run %d answered %d with %d of %d bytes"
                     % (i, resp.status, len(data), bulk_bytes))
    conn.close()
    mibs = sorted(bulk_bytes / 1048576.0 / t for t in rates)
    emit("mib_s", "%.2f" % mibs[len(mibs) // 2])
    emit("runs", ",".join("%.2f" % v for v in mibs))
    emit("n", n)
else:
    sys.exit("dedup_driver: unknown mode %r" % mode)

out.close()
PY

  cat > "$WORKDIR/dedup_close.py" <<'PY'
# Parses the codec's per-stream close lines -- carrier_dedup: offered=X
# framed=Y refs=Z -- out of one side's log, from a base offset the caller
# took BEFORE the scenario ran (logs accumulate across scenarios; offsets
# keep one scenario's numbers from reading another's streams). The ratio is
# the honest measured quantity of the whole leg: it is a byte count, not a
# timing measurement, so loopback noise cannot move it.
import re
import sys

log_path, base, want, result_path, prefix, metric = (
    sys.argv[1], int(sys.argv[2]), int(sys.argv[3]),
    sys.argv[4], sys.argv[5], sys.argv[6],
)
# Optional exclusive end bound: the sse scenario parses its two ON legs (the
# no-gzip connection and the gzip connection) SEPARATELY, so each needs a
# half-open slice of the log rather than everything from base onward.
#
# base and end are ORDINALS OF CLOSE LINES -- the same unit dd_close_count's
# `grep -c` produces -- NOT file line numbers. The first draft indexed file
# lines and mixed the two units; it survived the llm scenario (whose slice
# happened to start at file line 0) and died on the sse scenario, whose
# streams close hundreds of file lines apart. Indexed by ordinal, a warmup
# stream's close line before the offset is simply skipped.
end = int(sys.argv[7]) if len(sys.argv) > 7 else None

offered = framed = refs = lines = seen = 0
with open(log_path, errors="replace") as fh:
    for line in fh:
        m = re.search(r"carrier_dedup: offered=(\d+) framed=(\d+) refs=(\d+)", line)
        if not m:
            continue
        if seen < base or (end is not None and seen >= end):
            seen += 1
            continue
        a, b, c = (int(x) for x in m.groups())
        offered += a
        framed += b
        refs += c
        lines += 1
        seen += 1

if lines < want:
    sys.exit("%s: only %d of %d expected close lines from ordinal %d in %s"
             % (prefix, lines, want, base, log_path))

with open(result_path, "a") as out:
    out.write("%soffered=%d\n" % (prefix, offered))
    out.write("%sframed=%d\n" % (prefix, framed))
    out.write("%srefs=%d\n" % (prefix, refs))
    if metric == "saved":
        # saved = 1 - framed/offered, the share of the wire the codec did
        # not have to send; the kill criterion reads this on the llm
        # payload's request direction.
        pct = 100.0 * (1.0 - framed / offered) if offered else 0.0
        out.write("%ssaved_pct=%.2f\n" % (prefix, pct))
    elif metric == "overhead":
        # the control's quantity: framing bytes ADDed to the wire when
        # nothing can be referenced; the pre-registered bound is <= ~1%.
        pct = 100.0 * (framed - offered) / offered if offered else 0.0
        out.write("%soverhead_pct=%.3f\n" % (prefix, pct))
    else:
        sys.exit("dedup_close: unknown metric %r" % metric)
PY
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
  # key_prefix: "quic_" for the QUIC-carrier leg, empty for the smux one. The
  # measurement itself is identical -- only the names it reports under differ,
  # so the two carriers' rows can share a table without displacing each other.
  local key_prefix="${2:-}"
  local raw="$WORKDIR/bulk-$label.txt"
  local i

  : > "$raw"
  for i in $(seq 1 "$BULK_RUNS"); do
    curl -sS --max-time 300 -o /dev/null \
      -w '%{size_download} %{time_total} %{time_starttransfer}\n' \
      -H "Host: $BENCH_HOST" "$BASE_URL/bulk" >> "$raw"
  done

  python3 - "$raw" "$BULK_BYTES" "$BULK_RUNS" "$key_prefix" >> "$WORKDIR/result-$label.env" <<'PY'
import sys

raw_path, want, runs_expected = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
prefix = sys.argv[4]
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
print(prefix + "bulk_mib_s=%.2f" % whole[mid])
print(prefix + "bulk_runs_mib_s=%s" % ",".join("%.2f" % v for v in whole))
print(prefix + "bulk_stream_mib_s=%.2f" % streaming[mid])
print(prefix + "bulk_bytes=%d" % want)
print(prefix + "bulk_runs=%d" % runs_expected)
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
  local key_prefix="${2:-}"
  python3 - "$BENCH_HOST" "$BENCH_HTTP_PORT" "$CONN_RATE_REQUESTS" "$key_prefix" >> "$WORKDIR/result-$label.env" <<'PY'
import http.client
import math
import sys
import time

host, port, n = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
prefix = sys.argv[4]
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


print(prefix + "conn_rate_rps=%.1f" % (n / total))
print(prefix + "conn_rate_total_s=%.3f" % total)
print(prefix + "conn_rate_p50_ms=%.2f" % (pct(0.50) * 1000))
print(prefix + "conn_rate_p95_ms=%.2f" % (pct(0.95) * 1000))
print(prefix + "conn_rate_min_ms=%.2f" % (ordered[0] * 1000))
print(prefix + "conn_rate_max_ms=%.2f" % (ordered[-1] * 1000))
print(prefix + "conn_rate_n=%d" % n)
# The report's QUIC tail-latency row is keyed quic_p95_ms -- the one place
# the table drops the scenario name, because the row's point is "the tail on
# the QUIC carrier" beside the smux p95 row above it. Same number, explicit
# alias rather than a renamed key, so the JSON keeps the canonical name too.
if prefix:
    print(prefix + "p95_ms=%.2f" % (pct(0.95) * 1000))
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
  local key_prefix="${2:-}"
  python3 - "$BENCH_HOST" "$BENCH_HTTP_PORT" "$KEEPALIVE_REQUESTS" "$key_prefix" >> "$WORKDIR/result-$label.env" <<'PY'
import subprocess
import sys
import time

host, port, n = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
prefix = sys.argv[4]
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

print(prefix + "keepalive_rps=%.1f" % (n / wall))
print(prefix + "keepalive_wall_s=%.3f" % wall)
print(prefix + "keepalive_conns=%d" % conns)
print(prefix + "keepalive_n=%d" % n)
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

  local guard_ports=("$BENCH_UPSTREAM_PORT" "$BENCH_HTTP_PORT" "$BENCH_HTTPS_PORT" "$BENCH_ADMIN_PORT")
  # The tunnel port joins the guard only while the harness owns the dialed
  # address. With BENCH_TUNNEL_BIND moved (the netem variant), a shaping
  # relay is SUPPOSED to be listening on 127.0.0.1:<tunnel port> before the
  # stack starts -- skipping the check is the point, not a hole: ngrokd's
  # real bind on $BENCH_TUNNEL_BIND is still guarded transitively, because
  # if something squats there the client's carrier simply never establishes.
  if [[ "$BENCH_TUNNEL_BIND" == "127.0.0.1" ]]; then
    guard_ports+=("$BENCH_TUNNEL_PORT")
  fi
  for port in "${guard_ports[@]}"; do
    if port_in_use "$port"; then
      die "port $port is already in use -- a previous bench run (or another service) still holds it; this harness owns 19110/18180/18480/15443/19190"
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
    -tunnelAddr="$BENCH_TUNNEL_BIND:$BENCH_TUNNEL_PORT" \
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

# --- QUIC variant lifecycle ---------------------------------------------------
#
# The QUIC leg re-runs the http scenarios with the carrier swapped. Everything
# about the stack is the same shape as start_stack/stop_stack -- same ports,
# same fixture, same public hostname -- so a quic number and its smux neighbor
# in the table differ by the carrier and nothing else. Two differences:
#
#   - ngrokd gets -quicAddr on the tunnel port. A port number is two
#     independent bindings, one per protocol, so the QUIC listener sits on
#     UDP alongside the TCP tunnel listener, which is exactly where the
#     client looks for it (it dials the server address, UDP side).
#   - the client config pins proxy_transport: quic and registers only the
#     http endpoint: the pinned setting is what makes the leg deterministic
#     (auto would also pick QUIC here, but a pin cannot drift), and the
#     https endpoints are not measured on this leg.

start_stack_quic() {
  local label="$1" dir="$2" port

  # Same ownership check as start_stack: this harness owns these ports, and
  # anything already holding one belongs to a stale run.
  local guard_ports=("$BENCH_UPSTREAM_PORT" "$BENCH_HTTP_PORT" "$BENCH_HTTPS_PORT" "$BENCH_ADMIN_PORT")
  # The tunnel port joins the guard only while the harness owns the dialed
  # address. With BENCH_TUNNEL_BIND moved (the netem variant), a shaping
  # relay is SUPPOSED to be listening on 127.0.0.1:<tunnel port> before the
  # stack starts -- skipping the check is the point, not a hole: ngrokd's
  # real bind on $BENCH_TUNNEL_BIND is still guarded transitively, because
  # if something squats there the client's carrier simply never establishes.
  if [[ "$BENCH_TUNNEL_BIND" == "127.0.0.1" ]]; then
    guard_ports+=("$BENCH_TUNNEL_PORT")
  fi
  for port in "${guard_ports[@]}"; do
    if port_in_use "$port"; then
      die "port $port is already in use before the QUIC variant of '$label' -- stop_stack did not release it"
    fi
  done

  # Own log namespace ($label-quic): the smux leg's logs stay intact for
  # dump_logs, and the carrier wait below cannot match a line the smux leg
  # wrote into a shared file.
  rm -f /tmp/ngrok-bench-"$label"-*.log

  python3 "$WORKDIR/bench_upstream.py" "$BENCH_UPSTREAM_PORT" "$BULK_BYTES" \
    > "/tmp/ngrok-bench-$label-upstream.log" 2>&1 &
  UPSTREAM_PID=$!
  PIDS+=("$UPSTREAM_PID")

  "$dir/ngrokd" \
    -domain=localhost \
    -httpAddr="127.0.0.1:$BENCH_HTTP_PORT" \
    -httpsAddr="127.0.0.1:$BENCH_HTTPS_PORT" \
    -tunnelAddr="$BENCH_TUNNEL_BIND:$BENCH_TUNNEL_PORT" \
    -adminAddr="127.0.0.1:$BENCH_ADMIN_PORT" \
    -quicAddr="$BENCH_TUNNEL_BIND:$BENCH_TUNNEL_PORT" \
    > "/tmp/ngrok-bench-$label-ngrokd.log" 2>&1 &
  NGROKD_PID=$!
  PIDS+=("$NGROKD_PID")
  # Unlike start_stack's sleep 1, wait for the thing that matters: the QUIC
  # listener line proves -quicAddr was accepted AND the capability is being
  # advertised (it is only sent once the listener is up).
  local i
  for i in $(seq 1 40); do
    if grep -q "Listening for QUIC proxy sessions" "/tmp/ngrok-bench-$label-ngrokd.log" 2>/dev/null; then
      break
    fi
    sleep 0.25
  done
  if ! grep -q "Listening for QUIC proxy sessions" "/tmp/ngrok-bench-$label-ngrokd.log" 2>/dev/null; then
    dump_logs "$label"
    die "the QUIC listener never came up for variant '$label'"
  fi

  cat > "$WORKDIR/ngrok-bench-$label.yml" <<YAML
server_addr: 127.0.0.1:$BENCH_TUNNEL_PORT
trust_host_root_certs: true
proxy_transport: quic
tunnels:
  bench:
    hostname: $BENCH_HOST
    proto:
      http: $BENCH_UPSTREAM_PORT
YAML

  "$dir/ngrok" -config="$WORKDIR/ngrok-bench-$label.yml" \
    -log="/tmp/ngrok-bench-$label-client.log" start bench \
    > "/tmp/ngrok-bench-$label-client-stdout.log" 2>&1 &
  CLIENT_PID=$!
  PIDS+=("$CLIENT_PID")
}

# wait_for_quic_carrier <label>: the honesty gate on the whole QUIC leg.
# proxy_transport: quic DEGRADES to smux when the capability is missing --
# that is the right client behavior and the wrong bench result, because it
# would report smux numbers under a quic_ key. The carrier line in the client
# log is the only place the truth lives, so the run aborts without one.
wait_for_quic_carrier() {
  local label="$1" i
  for i in $(seq 1 40); do
    if grep -q "(quic carrier)" "/tmp/ngrok-bench-$label-client.log" 2>/dev/null; then
      return 0
    fi
    sleep 0.5
  done
  log "the client never established a QUIC carrier for variant '$label' -- refusing to report quic numbers"
  dump_logs "$label"
  return 1
}

warmup_quic() {
  local label="$1"
  # One discarded request: on this leg it pays the QUIC handshake, the
  # session's RegMux bind and the first stream's RegProxy, none of which any
  # measured request pays again -- the same one-time-cost rule warmup()
  # applies to the smux and TLS legs.
  curl -sS --max-time 60 -o /dev/null -H "Host: $BENCH_HOST" "$BASE_URL/small" \
    || die "warmup request through variant '$label' (quic) failed"
}

# --- dedup leg lifecycle ------------------------------------------------------
#
# Two client processes on one ngrokd, because the proposal is client-granular
# (see the header): the plain client's streams are the OFF side, the
# carrier_dedup client's are the ON side. The close-line offsets are taken
# BEFORE each measured run because the logs accumulate across scenarios --
# the same discipline the e2e group uses, and for the same reason.

DD_PLAIN_PID=""
DD_CLIENT_PID=""
DD_NGROKD_PID=""

dd_wait_tunnel() {  # <log> <label>
  local log="$1" label="$2" i
  for i in $(seq 1 40); do
    if grep -q "Tunnel established" "$log" 2>/dev/null; then
      return 0
    fi
    sleep 0.5
  done
  log "tunnel did not establish for $label"
  dump_logs "$label"
  return 1
}

# dd_wait_carrier <log> <carrier> <label>: the honesty gate, same reasoning
# as wait_for_quic_carrier but per-client-log and carrier-parameterized: a
# pinned transport that silently degraded would put the wrong carrier's
# numbers under this leg's keys.
dd_wait_carrier() {
  local log="$1" carrier="$2" label="$3" i
  for i in $(seq 1 40); do
    if grep -q "($carrier carrier)" "$log" 2>/dev/null; then
      return 0
    fi
    sleep 0.5
  done
  log "the client never established a $carrier carrier for $label -- refusing to report"
  dump_logs "$label"
  return 1
}

# dd_wait_public <host> <label>: first non-404 on the http listener for this
# hostname (404 is ngrokd's answer for an unknown tunnel AND a still-catching-
# up registry, so neither can end the wait -- wait_for_public's reasoning,
# with the hostname as a parameter because this leg has two).
dd_wait_public() {
  local host="$1" label="$2" code i
  for i in $(seq 1 40); do
    code="$(curl -sS -o /dev/null -w '%{http_code}' -H "Host: $host" "$BASE_URL/" 2>/dev/null || true)"
    if [[ "$code" != "404" && "$code" != "000" ]]; then
      return 0
    fi
    sleep 0.25
  done
  log "the public listener never learned $host for $label"
  dump_logs "$label"
  return 1
}

dd_close_count() {  # <log> -> close lines so far (0 when none)
  grep -c 'carrier_dedup: offered=' "$1" 2>/dev/null || true
}

# dd_wait_close_lines <log> <base> <want> <label>: close lines land at stream
# teardown, which can lag the driver's exit by a beat -- bounded retry on a
# count, never a bare sleep.
dd_wait_close_lines() {
  local log="$1" base="$2" want="$3" label="$4" i
  for i in $(seq 1 40); do
    if [[ "$(($(dd_close_count "$log") - base))" -ge "$want" ]]; then
      return 0
    fi
    sleep 0.25
  done
  log "$label: only $(($(dd_close_count "$log") - base)) of $want close lines in $log"
  dump_logs "$label"
  return 1
}

start_stack_dedup() {
  local label="$1" dir="$2" carrier="$3" port

  local guard_ports=("$BENCH_UPSTREAM_PORT" "$BENCH_HTTP_PORT" "$BENCH_HTTPS_PORT" "$BENCH_ADMIN_PORT")
  # The tunnel port joins the guard only while the harness owns the dialed
  # address. With BENCH_TUNNEL_BIND moved (the netem variant), a shaping
  # relay is SUPPOSED to be listening on 127.0.0.1:<tunnel port> before the
  # stack starts -- skipping the check is the point, not a hole: ngrokd's
  # real bind on $BENCH_TUNNEL_BIND is still guarded transitively, because
  # if something squats there the client's carrier simply never establishes.
  if [[ "$BENCH_TUNNEL_BIND" == "127.0.0.1" ]]; then
    guard_ports+=("$BENCH_TUNNEL_PORT")
  fi
  for port in "${guard_ports[@]}"; do
    if port_in_use "$port"; then
      die "port $port is already in use before the dedup ($carrier) stack of '$label' -- a previous leg did not release it"
    fi
  done

  rm -f /tmp/ngrok-bench-"$label"-*.log

  python3 "$WORKDIR/dedup_upstream.py" "$BENCH_UPSTREAM_PORT" "$BULK_BYTES" \
    > "/tmp/ngrok-bench-$label-upstream.log" 2>&1 &
  UPSTREAM_PID=$!
  PIDS+=("$UPSTREAM_PID")

  if [[ "$carrier" == "quic" ]]; then
    "$dir/ngrokd" \
      -domain=localhost \
      -httpAddr="127.0.0.1:$BENCH_HTTP_PORT" \
      -httpsAddr="127.0.0.1:$BENCH_HTTPS_PORT" \
      -tunnelAddr="$BENCH_TUNNEL_BIND:$BENCH_TUNNEL_PORT" \
      -adminAddr="127.0.0.1:$BENCH_ADMIN_PORT" \
      -quicAddr="$BENCH_TUNNEL_BIND:$BENCH_TUNNEL_PORT" \
      > "/tmp/ngrok-bench-$label-ngrokd.log" 2>&1 &
  else
    # No -quicAddr on the smux leg: with no QUIC listener advertised, auto
    # transport cannot drift onto QUIC -- the smux gate below only has to
    # catch a client-side surprise, not a server-side one.
    "$dir/ngrokd" \
      -domain=localhost \
      -httpAddr="127.0.0.1:$BENCH_HTTP_PORT" \
      -httpsAddr="127.0.0.1:$BENCH_HTTPS_PORT" \
      -tunnelAddr="$BENCH_TUNNEL_BIND:$BENCH_TUNNEL_PORT" \
      -adminAddr="127.0.0.1:$BENCH_ADMIN_PORT" \
      > "/tmp/ngrok-bench-$label-ngrokd.log" 2>&1 &
  fi
  DD_NGROKD_PID=$!
  PIDS+=("$DD_NGROKD_PID")

  if [[ "$carrier" == "quic" ]]; then
    local i
    for i in $(seq 1 40); do
      if grep -q "Listening for QUIC proxy sessions" "/tmp/ngrok-bench-$label-ngrokd.log" 2>/dev/null; then
        break
      fi
      sleep 0.25
    done
    if ! grep -q "Listening for QUIC proxy sessions" "/tmp/ngrok-bench-$label-ngrokd.log" 2>/dev/null; then
      dump_logs "$label"
      die "the QUIC listener never came up for the dedup leg of '$label'"
    fi
  else
    sleep 1
  fi

  # The OFF client: the plain bench tunnel, no dedup key anywhere in the
  # config -- its streams never propose, which is what makes it a control.
  # The ON client: one tunnel, same upstream, carrier_dedup: true. On the
  # QUIC carrier both clients pin proxy_transport for the same reason the
  # QUIC leg pins it (auto would likely pick QUIC; a pin cannot drift).
  local transport_yaml=""
  if [[ "$carrier" == "quic" ]]; then
    transport_yaml=$'proxy_transport: quic\n'
  fi

  cat > "$WORKDIR/ngrok-dd-plain-$label.yml" <<YAML
server_addr: 127.0.0.1:$BENCH_TUNNEL_PORT
trust_host_root_certs: true
${transport_yaml}tunnels:
  bench:
    hostname: $BENCH_HOST
    proto:
      http: $BENCH_UPSTREAM_PORT
YAML

  cat > "$WORKDIR/ngrok-dd-$label.yml" <<YAML
server_addr: 127.0.0.1:$BENCH_TUNNEL_PORT
trust_host_root_certs: true
${transport_yaml}tunnels:
  bench-dd:
    hostname: $DEDUP_DD_HOST
    proto:
      http: $BENCH_UPSTREAM_PORT
    carrier_dedup: true
YAML

  "$dir/ngrok" -config="$WORKDIR/ngrok-dd-plain-$label.yml" \
    -log="/tmp/ngrok-bench-$label-client-plain.log" start bench \
    > "/tmp/ngrok-bench-$label-client-plain-stdout.log" 2>&1 &
  DD_PLAIN_PID=$!
  PIDS+=("$DD_PLAIN_PID")

  "$dir/ngrok" -config="$WORKDIR/ngrok-dd-$label.yml" \
    -log="/tmp/ngrok-bench-$label-client-dd.log" start bench-dd \
    > "/tmp/ngrok-bench-$label-client-dd-stdout.log" 2>&1 &
  DD_CLIENT_PID=$!
  PIDS+=("$DD_CLIENT_PID")
}

# stop_stack_dedup <label> <pfx>: captures the CPU clocks FIRST (the rows the
# report carries), then tears down clients -> registry -> server, the same
# order stop_stack uses. The readable CPU delta is plain vs dd client (same
# traffic shape, one running the codec); the ngrokd figure mixes both
# clients' traffic in one process and cannot be attributed -- reported
# as-is (header note).
stop_stack_dedup() {
  local label="$1" pfx="$2" code code2 cpu i
  # CPU via ps(1) when the box has one. The bench container VM ships no
  # procps, and a failed substitution here kills the whole run SILENTLY
  # (exit 127; neither set -e's death nor the ERR trap prints anything --
  # verified on the VM with a minimal repro), so a missing ps must degrade
  # to an explicit "unavailable" row, never to a dead harness.
  if command -v ps >/dev/null 2>&1; then
    {
      cpu="$(ps -o cputime= -p "$DD_NGROKD_PID" 2>/dev/null | tr -d ' ')"
      echo "${pfx}cpu_ngrokd=${cpu:-unknown}"
      cpu="$(ps -o cputime= -p "$DD_PLAIN_PID" 2>/dev/null | tr -d ' ')"
      echo "${pfx}cpu_plain_client=${cpu:-unknown}"
      cpu="$(ps -o cputime= -p "$DD_CLIENT_PID" 2>/dev/null | tr -d ' ')"
      echo "${pfx}cpu_dd_client=${cpu:-unknown}"
    } >> "$WORKDIR/result-${VARIANT_LABEL}.env"
  else
    {
      echo "${pfx}cpu_ngrokd=unavailable-no-ps"
      echo "${pfx}cpu_plain_client=unavailable-no-ps"
      echo "${pfx}cpu_dd_client=unavailable-no-ps"
    } >> "$WORKDIR/result-${VARIANT_LABEL}.env"
  fi

  kill "$DD_CLIENT_PID" "$DD_PLAIN_PID" 2>/dev/null || true
  wait "$DD_CLIENT_PID" "$DD_PLAIN_PID" 2>/dev/null || true
  for i in $(seq 1 40); do
    code="$(curl -sS -o /dev/null -w '%{http_code}' -H "Host: $BENCH_HOST" "$BASE_URL/" 2>/dev/null || true)"
    code2="$(curl -sS -o /dev/null -w '%{http_code}' -H "Host: $DEDUP_DD_HOST" "$BASE_URL/" 2>/dev/null || true)"
    if [[ "$code" == "404" && "$code2" == "404" ]]; then
      break
    fi
    sleep 0.25
  done

  kill "$DD_NGROKD_PID" "$UPSTREAM_PID" 2>/dev/null || true
  wait "$DD_NGROKD_PID" "$UPSTREAM_PID" 2>/dev/null || true
  DD_CLIENT_PID=""
  DD_PLAIN_PID=""
  DD_NGROKD_PID=""
  UPSTREAM_PID=""

  sleep 0.5
}

# --- dedup scenarios -----------------------------------------------------------
#
# Each runs the OFF leg first (plain client), then the ON leg (dedup client),
# then parses the close lines the ON side's streams wrote. The offsets are
# taken before anything runs so one scenario can never read another's streams.

scenario_dedup_llm() {  # <leg-label> <pfx>
  local leg="$1" pfx="$2" base_s base_c
  base_s="$(dd_close_count "/tmp/ngrok-bench-$leg-ngrokd.log")"
  base_c="$(dd_close_count "/tmp/ngrok-bench-$leg-client-dd.log")"

  python3 "$WORKDIR/dedup_driver.py" llm "$BENCH_HOST" "$BENCH_HTTP_PORT" \
    "$DEDUP_LLM_REQUESTS" "$WORKDIR/result-${VARIANT_LABEL}.env" "${pfx}llm_off_"
  python3 "$WORKDIR/dedup_driver.py" llm "$DEDUP_DD_HOST" "$BENCH_HTTP_PORT" \
    "$DEDUP_LLM_REQUESTS" "$WORKDIR/result-${VARIANT_LABEL}.env" "${pfx}llm_on_"

  # One keep-alive connection per leg -> one proxy stream -> one close line
  # per direction: server log = request direction (the kill criterion's
  # home), client log = response direction.
  dd_wait_close_lines "/tmp/ngrok-bench-$leg-ngrokd.log" "$base_s" 1 "dedup-llm (server)"
  dd_wait_close_lines "/tmp/ngrok-bench-$leg-client-dd.log" "$base_c" 1 "dedup-llm (client)"
  python3 "$WORKDIR/dedup_close.py" "/tmp/ngrok-bench-$leg-ngrokd.log" "$base_s" 1 \
    "$WORKDIR/result-${VARIANT_LABEL}.env" "${pfx}llm_" saved
  python3 "$WORKDIR/dedup_close.py" "/tmp/ngrok-bench-$leg-client-dd.log" "$base_c" 1 \
    "$WORKDIR/result-${VARIANT_LABEL}.env" "${pfx}llm_resp_" saved
}

scenario_dedup_sse() {  # <leg-label> <pfx>
  local leg="$1" pfx="$2" base_c
  # Only the response direction carries this payload (the requests are tiny
  # GETs), so only the CLIENT log's close lines are parsed here.
  base_c="$(dd_close_count "/tmp/ngrok-bench-$leg-client-dd.log")"

  python3 "$WORKDIR/dedup_driver.py" sse "$BENCH_HOST" "$BENCH_HTTP_PORT" \
    "$DEDUP_SSE_EVENTS" "$WORKDIR/result-${VARIANT_LABEL}.env" "${pfx}sse_off_"
  python3 "$WORKDIR/dedup_driver.py" sse "$DEDUP_DD_HOST" "$BENCH_HTTP_PORT" \
    "$DEDUP_SSE_EVENTS" "$WORKDIR/result-${VARIANT_LABEL}.env" "${pfx}sse_on_"
  python3 "$WORKDIR/dedup_driver.py" sse "$DEDUP_DD_HOST" "$BENCH_HTTP_PORT" \
    "$DEDUP_SSE_EVENTS" "$WORKDIR/result-${VARIANT_LABEL}.env" "${pfx}sse_gzip_" gzip

  # The two ON legs rode separate connections, so their close lines are
  # separate: [base, base+1) is the no-gzip stream, [base+1, base+2) the
  # gzip one -- the end bound keeps the gzip stream's numbers out of the
  # no-gzip ratio, which matters because they are the two halves of the
  # comparison (win, then the win's boundary).
  dd_wait_close_lines "/tmp/ngrok-bench-$leg-client-dd.log" "$base_c" 2 "dedup-sse (client)"
  python3 "$WORKDIR/dedup_close.py" "/tmp/ngrok-bench-$leg-client-dd.log" "$base_c" 1 \
    "$WORKDIR/result-${VARIANT_LABEL}.env" "${pfx}sse_resp_" saved "$((base_c + 1))"
  python3 "$WORKDIR/dedup_close.py" "/tmp/ngrok-bench-$leg-client-dd.log" "$((base_c + 1))" 1 \
    "$WORKDIR/result-${VARIANT_LABEL}.env" "${pfx}sse_gzip_resp_" saved
}

scenario_dedup_bulk() {  # <leg-label> <pfx>
  local leg="$1" pfx="$2" base_c
  # The 64 MiB payload is the RESPONSE direction (upstream -> visitor), which
  # the CLIENT encodes onto the carrier -- so the control's close lines live
  # in the dd CLIENT log, not the server's. (The first run parsed the server
  # log and got 4.6% "overhead": that was the framing on the ~70-byte GET
  # requests, where a 3-byte frame header is not small -- a direction error,
  # not a codec one.)
  base_c="$(dd_close_count "/tmp/ngrok-bench-$leg-client-dd.log")"

  python3 "$WORKDIR/dedup_driver.py" bulk "$BENCH_HOST" "$BENCH_HTTP_PORT" \
    "$BULK_RUNS" "$WORKDIR/result-${VARIANT_LABEL}.env" "${pfx}bulk_off_" "$BULK_BYTES"
  python3 "$WORKDIR/dedup_driver.py" bulk "$DEDUP_DD_HOST" "$BENCH_HTTP_PORT" \
    "$BULK_RUNS" "$WORKDIR/result-${VARIANT_LABEL}.env" "${pfx}bulk_on_" "$BULK_BYTES"

  # The ON driver's three GETs ride ONE connection, so one close line; the
  # control's number is the ratio over that stream: random bytes never
  # reference anything, so framed-offered is pure framing overhead.
  dd_wait_close_lines "/tmp/ngrok-bench-$leg-client-dd.log" "$base_c" 1 "dedup-bulk (client)"
  python3 "$WORKDIR/dedup_close.py" "/tmp/ngrok-bench-$leg-client-dd.log" "$base_c" 1 \
    "$WORKDIR/result-${VARIANT_LABEL}.env" "${pfx}bulk_" overhead
}

run_variant_dedup() {  # <variant-label> <dir> <carrier>
  local label="$1" dir="$2" carrier="$3"
  local dlog pfx
  if [[ "$carrier" == "quic" ]]; then
    dlog="$label-ddq"
    pfx="quic_dedup_"
  else
    dlog="$label-dd"
    pfx="dedup_"
  fi
  CURRENT_LABEL="$dlog"
  VARIANT_LABEL="$label"
  log "=== variant '$dlog': $dir (dedup payloads, $carrier carrier) ==="

  start_stack_dedup "$dlog" "$dir" "$carrier"
  dd_wait_tunnel "/tmp/ngrok-bench-$dlog-client-plain.log" "$dlog (plain client)"
  dd_wait_tunnel "/tmp/ngrok-bench-$dlog-client-dd.log" "$dlog (dedup client)"
  if [[ "$carrier" == "quic" ]]; then
    dd_wait_carrier "/tmp/ngrok-bench-$dlog-client-plain.log" quic "$dlog (plain client)"
    dd_wait_carrier "/tmp/ngrok-bench-$dlog-client-dd.log" quic "$dlog (dedup client)"
  else
    dd_wait_carrier "/tmp/ngrok-bench-$dlog-client-dd.log" smux "$dlog (dedup client)"
  fi
  dd_wait_public "$BENCH_HOST" "$dlog (plain)"
  dd_wait_public "$DEDUP_DD_HOST" "$dlog (dedup)"

  # Warmups on BOTH tunnels (same one-time-cost rule as warmup(); on the ON
  # side this also pays the codec's one-time negotiation, not the per-stream
  # table fill -- tables are per stream, so each measured connection fills
  # its own, and that cost is inside the ON numbers by design).
  curl -sS --max-time 60 -o /dev/null -H "Host: $BENCH_HOST" "$BASE_URL/small" \
    || die "warmup through variant '$dlog' failed (plain)"
  curl -sS --max-time 60 -o /dev/null -H "Host: $DEDUP_DD_HOST" "$BASE_URL/small" \
    || die "warmup through variant '$dlog' failed (dedup)"

  # The warmups' OWN streams must tear down before the scenarios take their
  # close-line offsets, or a late warmup line would land inside the first
  # scenario's slice. (The first live run proved these lines exist: the dd
  # warmup's response direction wrote offered=145 on its own stream.)
  dd_wait_close_lines "/tmp/ngrok-bench-$dlog-ngrokd.log" 0 1 "$dlog warmup (server)"
  dd_wait_close_lines "/tmp/ngrok-bench-$dlog-client-dd.log" 0 1 "$dlog warmup (client)"

  local want
  for want in ${BENCH_SCENARIOS:-dedup-llm dedup-sse dedup-bulk}; do
    case "$want" in
      dedup-llm)
        log "dedup-llm ($carrier): $DEDUP_LLM_REQUESTS POSTs x {plain, carrier_dedup}, one conn each"
        scenario_dedup_llm "$dlog" "$pfx" ;;
      dedup-sse)
        log "dedup-sse ($carrier): $DEDUP_SSE_EVENTS events x {plain, dedup, dedup+gzip}"
        scenario_dedup_sse "$dlog" "$pfx" ;;
      dedup-bulk)
        log "dedup-bulk ($carrier): $((BULK_BYTES / 1024 / 1024)) MiB x $BULK_RUNS runs x {plain, dedup}"
        scenario_dedup_bulk "$dlog" "$pfx" ;;
      *) ;; # not a dedup-leg scenario; the other legs own it
    esac
  done

  stop_stack_dedup "$dlog" "$pfx"
  log "variant '$dlog' done (logs: /tmp/ngrok-bench-$dlog-*.log)"
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

  # BENCH_SCENARIOS selects a subset (default: everything) so a focused run --
  # e.g. BENCH_SCENARIOS="bulk conn-rate keep-alive" for a QUIC-parity
  # question, or BENCH_SCENARIOS="dedup-llm" for a codec question -- fits a
  # coffee break instead of the full suite's half hour. Each leg runs the
  # scenarios it owns and skips the others'; an unknown name still exits 2.
  local want
  for want in ${BENCH_SCENARIOS:-bulk conn-rate keep-alive tls-conn-rate dedup-llm dedup-sse dedup-bulk}; do
    case "$want" in
      bulk)
        log "bulk: $((BULK_BYTES / 1024 / 1024)) MiB x $BULK_RUNS runs"
        scenario_bulk "$label" ;;
      conn-rate)
        log "conn-rate: $CONN_RATE_REQUESTS requests, Connection: close"
        scenario_conn_rate "$label" ;;
      keep-alive)
        log "keep-alive: $KEEPALIVE_REQUESTS requests in one curl invocation"
        scenario_keepalive "$label" ;;
      tls-conn-rate)
        log "tls-conn-rate: $TLS_REQUESTS requests x {edge, agent-terminated} over https"
        scenario_tls_conn_rate "$label" ;;
      dedup-llm|dedup-sse|dedup-bulk) ;; # owned by the dedup legs, below
      *)
        echo "unknown scenario '$want' (bulk | conn-rate | keep-alive | tls-conn-rate | dedup-llm | dedup-sse | dedup-bulk)" >&2
        exit 2 ;;
    esac
  done

  stop_stack

  # The QUIC leg appends quic_-prefixed keys to the SAME result file, so a
  # variant's numbers travel together and the report's quic rows render in
  # both single and compare modes without a second pass. The legs run one
  # after the other because they need the same ports -- which puts them under
  # the same mid-run-drift caveat the header documents for the two-dir form.
  # The dedup legs follow (spec 6: the payloads run on/off x smux/QUIC), the
  # same ports again, for the same reason.
  run_variant_quic "$label" "$dir"
  run_variant_dedup "$label" "$dir" smux
  run_variant_dedup "$label" "$dir" quic

  log "variant '$label' done (logs: /tmp/ngrok-bench-$label-*.log)"
}

run_variant_quic() {
  local label="$1" dir="$2"
  # Distinct log namespace, shared result file: the quic keys land next to
  # the smux ones for this variant, while the logs of the two legs stay
  # separated (the carrier wait greps a file the smux leg never wrote).
  local qlog="$label-quic"
  CURRENT_LABEL="$qlog"
  log "=== variant '$qlog': $dir (QUIC carrier) ==="

  start_stack_quic "$qlog" "$dir"
  wait_for_tunnel "$qlog"
  wait_for_quic_carrier "$qlog"
  wait_for_public "$qlog"
  warmup_quic "$qlog"

  # The QUIC leg honors the same BENCH_SCENARIOS selection (minus
  # tls-conn-rate, which the quic leg has never run -- its TLS endpoints
  # ride the smux-carried stack by design, and the dedup- scenarios, which
  # the dedup legs own; see the header note).
  local want
  for want in ${BENCH_SCENARIOS:-bulk conn-rate keep-alive}; do
    case "$want" in
      bulk)
        log "quic bulk: $((BULK_BYTES / 1024 / 1024)) MiB x $BULK_RUNS runs"
        scenario_bulk "$label" "quic_" ;;
      conn-rate)
        log "quic conn-rate: $CONN_RATE_REQUESTS requests, Connection: close"
        scenario_conn_rate "$label" "quic_" ;;
      keep-alive)
        log "quic keep-alive: $KEEPALIVE_REQUESTS requests in one curl invocation"
        scenario_keepalive "$label" "quic_" ;;
      tls-conn-rate|dedup-llm|dedup-sse|dedup-bulk) ;; # owned by other legs
      *)
        echo "unknown scenario '$want'" >&2
        exit 2 ;;
    esac
  done

  stop_stack
  log "variant '$qlog' done (logs: /tmp/ngrok-bench-$qlog-*.log)"
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
    echo "tunnel_bind=$BENCH_TUNNEL_BIND"
    echo "upstream_port=$BENCH_UPSTREAM_PORT"
    echo "admin_port=$BENCH_ADMIN_PORT"
    echo "bulk_bytes=$BULK_BYTES"
    echo "bulk_runs=$BULK_RUNS"
    echo "conn_rate_requests=$CONN_RATE_REQUESTS"
    echo "keepalive_requests=$KEEPALIVE_REQUESTS"
    echo "tls_requests=$TLS_REQUESTS"
    echo "tls_edge_host=$BENCH_TLS_EDGE_HOST"
    echo "tls_zk_host=$BENCH_TLS_ZK_HOST"
    # The QUIC leg's wiring, for the JSON record: the QUIC listener shares the
    # tunnel port (UDP beside TCP), and the client pins the carrier.
    echo "quic_addr_port=$BENCH_TUNNEL_PORT"
    echo "quic_client_proxy_transport=quic"
    # The dedup legs' wiring: plain and carrier_dedup clients on one ngrokd,
    # payload sizes matching the e2e group's pinned fixtures.
    echo "dedup_plain_host=$BENCH_HOST"
    echo "dedup_dd_host=$DEDUP_DD_HOST"
    echo "dedup_llm_requests=$DEDUP_LLM_REQUESTS"
    echo "dedup_sse_events=$DEDUP_SSE_EVENTS"
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
    # The quic rows and the note row under them are one unit: the note is not
    # prose about the table, it IS a row of it, because the caveat changes
    # what the numbers are allowed to claim (SPEC-CLUSTER7 gate 6). Loopback
    # delivers no packet loss, and QUIC's win is per-stream independence
    # UNDER LOSS -- a lossless wire makes the two carriers look the same by
    # construction, so these rows establish parity on the happy path (plus
    # the cost of QUIC handshakes on conn-rate's fresh sessions), never
    # superiority. The key is deliberately absent from every result file, so
    # cell() renders the value columns as n/a and only the text is read.
    ("quic bulk MiB/s (median of 3, QUIC carrier)", "quic_bulk_mib_s", "%.1f"),
    ("quic conn-rate req/s (200 x Connection: close)", "quic_conn_rate_rps", "%.1f"),
    ("quic conn-rate p95 ms (lower is better)", "quic_p95_ms", "%.2f"),
    ("quic keep-alive req/s (1000, one curl)", "quic_keepalive_rps", "%.1f"),
    ("NOTE quic rows: loopback has no packet loss, so QUIC's head-of-line-blocking win cannot show here -- these numbers establish parity with the smux rows, not superiority", "quic_caveat_row_marker", "%s"),
    # The dedup rows (SPEC-CLUSTER21). The saved%/overhead% rows are codec
    # close-line ratios -- exact byte counts, not timings, so loopback noise
    # cannot move them; that is why the leg's claims live there. The req/s
    # and p95 rows beside them are loopback timings and carry the standing
    # admission: no bandwidth constraint means the win cannot show as wall
    # time (the netem variant's job), and the codec's work on the hot path
    # is expected to cost a little p95 -- "neutral-to-slightly-worse" is the
    # pre-registered expectation, not a surprise to explain away.
    ("dedup llm OFF req/s (plain client, 100 POSTs, one conn)", "dedup_llm_off_rps", "%.1f"),
    ("dedup llm ON req/s (carrier_dedup client)", "dedup_llm_on_rps", "%.1f"),
    ("dedup llm p95 ms OFF (lower is better)", "dedup_llm_off_p95_ms", "%.2f"),
    ("dedup llm p95 ms ON (lower is better)", "dedup_llm_on_p95_ms", "%.2f"),
    ("dedup llm saved % REQUESTS (server close lines; kill line >= 50)", "dedup_llm_saved_pct", "%.1f"),
    ("dedup llm saved % responses (client close lines)", "dedup_llm_resp_saved_pct", "%.1f"),
    ("dedup sse OFF events/s (plain, 200 events, one response)", "dedup_sse_off_events_per_s", "%.1f"),
    ("dedup sse ON events/s (no gzip)", "dedup_sse_on_events_per_s", "%.1f"),
    ("dedup sse ON events/s (Accept-Encoding: gzip)", "dedup_sse_gzip_events_per_s", "%.1f"),
    ("dedup sse saved % responses, no gzip (client close lines)", "dedup_sse_resp_saved_pct", "%.1f"),
    ("dedup sse saved % responses, gzip (the win's boundary; ~0 expected)", "dedup_sse_gzip_resp_saved_pct", "%.1f"),
    ("dedup bulk control OFF MiB/s (median of 3)", "dedup_bulk_off_mib_s", "%.1f"),
    ("dedup bulk control ON MiB/s (median of 3)", "dedup_bulk_on_mib_s", "%.1f"),
    ("dedup bulk control overhead % (close-line framing; <= ~1 expected)", "dedup_bulk_overhead_pct", "%.3f"),
    ("dedup CPU ngrokd (both clients' traffic; not attributable)", "dedup_cpu_ngrokd", "%s"),
    ("dedup CPU plain client", "dedup_cpu_plain_client", "%s"),
    ("dedup CPU dedup client (the codec's bill)", "dedup_cpu_dd_client", "%s"),
    ("NOTE dedup rows: saved%/overhead% are exact byte ratios from the codec's close lines; the req/s, p95 and MiB/s rows are loopback timings (no bandwidth constraint, so the byte win cannot show as wall time -- the netem variant's job)", "dedup_caveat_row_marker", "%s"),
    # The dedup payloads re-run over the QUIC carrier (spec 6: on/off x
    # smux/QUIC), gated on the QUIC carrier line like the quic leg above.
    ("quic dedup llm OFF req/s (plain client)", "quic_dedup_llm_off_rps", "%.1f"),
    ("quic dedup llm ON req/s (carrier_dedup client)", "quic_dedup_llm_on_rps", "%.1f"),
    ("quic dedup llm p95 ms OFF (lower is better)", "quic_dedup_llm_off_p95_ms", "%.2f"),
    ("quic dedup llm p95 ms ON (lower is better)", "quic_dedup_llm_on_p95_ms", "%.2f"),
    ("quic dedup llm saved % REQUESTS (kill line >= 50)", "quic_dedup_llm_saved_pct", "%.1f"),
    ("quic dedup llm saved % responses", "quic_dedup_llm_resp_saved_pct", "%.1f"),
    ("quic dedup sse OFF events/s", "quic_dedup_sse_off_events_per_s", "%.1f"),
    ("quic dedup sse ON events/s (no gzip)", "quic_dedup_sse_on_events_per_s", "%.1f"),
    ("quic dedup sse ON events/s (gzip)", "quic_dedup_sse_gzip_events_per_s", "%.1f"),
    ("quic dedup sse saved % responses, no gzip", "quic_dedup_sse_resp_saved_pct", "%.1f"),
    ("quic dedup sse saved % responses, gzip", "quic_dedup_sse_gzip_resp_saved_pct", "%.1f"),
    ("quic dedup bulk control OFF MiB/s (median of 3)", "quic_dedup_bulk_off_mib_s", "%.1f"),
    ("quic dedup bulk control ON MiB/s (median of 3)", "quic_dedup_bulk_on_mib_s", "%.1f"),
    ("quic dedup bulk control overhead % (<= ~1 expected)", "quic_dedup_bulk_overhead_pct", "%.3f"),
    ("quic dedup CPU ngrokd (mixed traffic)", "quic_dedup_cpu_ngrokd", "%s"),
    ("quic dedup CPU plain client", "quic_dedup_cpu_plain_client", "%s"),
    ("quic dedup CPU dedup client", "quic_dedup_cpu_dd_client", "%s"),
    ("NOTE quic dedup rows: the dedup rows' caveat plus the quic rows' no-loss caveat both apply", "quic_dedup_caveat_row_marker", "%s"),
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
    "workload: bulk=%s MiB x %s runs, conn-rate=%s requests, keep-alive=%s requests in one curl, tls-conn-rate=%s requests x {edge, agent-terminated}; QUIC leg re-runs bulk/conn-rate/keep-alive with server -quicAddr + client proxy_transport=quic; dedup legs (smux + QUIC) run llm/sse/control payloads through a plain client and a carrier_dedup client on one ngrokd"
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
      write_dedup_fixtures
      write_params "single" "$build_dir" ""
      run_variant "single" "$build_dir"
      emit_report "single" "$WORKDIR/params.env" "single=$WORKDIR/result-single.env"
      ;;
    2)
      write_fixtures
      write_dedup_fixtures
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
