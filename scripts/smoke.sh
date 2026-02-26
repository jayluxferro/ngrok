#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
export GOCACHE="${GOCACHE:-/tmp/go-build-cache}"
export GOMODCACHE="${GOMODCACHE:-/tmp/go-mod-cache}"
export GOPATH="${GOPATH:-/tmp/go}"

echo "[smoke] building binaries"
go build -tags debug -o bin/ngrok ./main/ngrok
go build -tags debug -o bin/ngrokd ./main/ngrokd

echo "[smoke] starting ngrokd"
./bin/ngrokd -domain=ngrok.me -httpAddr=127.0.0.1:18080 -httpsAddr= -tunnelAddr=127.0.0.1:14443 -adminAddr=127.0.0.1:19090 >/tmp/ngrokd-smoke.log 2>&1 &
NGROKD_PID=$!
trap 'kill $NGROKD_PID >/dev/null 2>&1 || true' EXIT
sleep 1

echo "[smoke] checking health endpoint"
curl -fsS http://127.0.0.1:19090/healthz >/dev/null
curl -fsS http://127.0.0.1:19090/metrics >/dev/null

echo "[smoke] hashing token helper"
./bin/ngrokd -hashToken=test >/dev/null

echo "[smoke] OK"
