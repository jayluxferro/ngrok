#!/usr/bin/env bash
#
# scripts/bench-netem/netem-run.sh -- the bandwidth-constrained bench variant.
#
# Runs the whole bench inside a throwaway `unshare -Urn` netns, where this
# shell DOES have CAP_NET_ADMIN (the container itself does not): lo comes up
# there with an extra 127.0.0.2 address, the token-bucket relay owns
# 127.0.0.1:<tunnel port> (the address clients dial), and
# BENCH_TUNNEL_BIND=127.0.0.2 parks ngrokd behind it. Nothing here outlives
# the unshare process -- no qdisc to remove, no address alias to undo.
#
# Why a userspace relay instead of tc: the bench VM's kernel has
# CONFIG_NET_SCH_FQ_CODEL and nothing else (no htb/tbf/netem), its tc binary
# cannot load modules, and the container lacks NET_ADMIN -- the full
# elimination is documented in scripts/bench.sh and relay.py.
#
#   usage: netem-run.sh <bin-dir>
#          (both bench.sh variants point at the same binaries: the compare
#          is OFF-vs-ON within each leg, so baseline==current is the point,
#          and the second column doubles as a same-binary noise check)
#
#   env:   BENCH_SCENARIOS    which scenarios (default: dedup-llm, the
#                            spec's netem payload)
#          BENCH_NETEM_RATE   bucket rate in bytes/s (default 1250000 ~ 10
#                            Mbit/s)
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

BIN_DIR="${1:?usage: netem-run.sh <bin-dir-with-ngrok-and-ngrokd>}"
[[ -x "$BIN_DIR/ngrok" && -x "$BIN_DIR/ngrokd" ]] || {
  echo "netem-run: need an ngrok and an ngrokd in $BIN_DIR" >&2
  exit 2
}
RATE="${BENCH_NETEM_RATE:-1250000}"
SCEN="${BENCH_SCENARIOS:-dedup-llm}"

# The inner script is written to a file (not piped) so quoting stays boring:
# the outer shell expands $ROOT/$BIN_DIR/$RATE/$SCEN once, here; everything
# meant to run inside the netns is escaped from THIS heredoc only.
INNER="$(mktemp /tmp/netem-inner.XXXXXX.sh)"
cat > "$INNER" <<NETEM
set -euo pipefail
ip link set lo up
ip addr add 127.0.0.2/8 dev lo
echo "[netem] netns ready: lo up with 127.0.0.1 and 127.0.0.2"
python3 "$ROOT/scripts/bench-netem/relay.py" --listen 127.0.0.1 --port 15443 \\
  --target 127.0.0.2 --target-port 15443 --rate "$RATE" &
RELAY=\$!
trap 'kill \$RELAY 2>/dev/null || true' EXIT
sleep 0.5
cd "$ROOT"
echo "[netem] bench start: scenarios='$SCEN' rate=$RATE B/s both-variants=$BIN_DIR"
BENCH_TUNNEL_BIND=127.0.0.2 BENCH_SCENARIOS="$SCEN" bash scripts/bench.sh "$BIN_DIR" "$BIN_DIR"
NETEM

exec unshare -Urn bash "$INNER"
