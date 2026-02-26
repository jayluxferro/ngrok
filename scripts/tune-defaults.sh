#!/usr/bin/env bash
set -euo pipefail

ADMIN_URL="${1:-http://127.0.0.1:9090}"
WINDOW="${WINDOW:-900}"
AUTH_HEADER="${NGROK_ADMIN_TOKEN:-}"

hdr=()
if [[ -n "$AUTH_HEADER" ]]; then
  hdr=(-H "X-Ngrok-Admin-Token: $AUTH_HEADER")
fi

echo "[tune] querying recommendations from ${ADMIN_URL}/recommendations?window=${WINDOW}" >&2
json="$(curl -fsS "${hdr[@]}" "${ADMIN_URL}/recommendations?window=${WINDOW}")"

public_rate="$(python3 - <<'PY' "$json"
import json, sys
j=json.loads(sys.argv[1]); print(j["recommended"]["publicRate"])
PY
)"
max_conn="$(python3 - <<'PY' "$json"
import json, sys
j=json.loads(sys.argv[1]); print(j["recommended"]["maxConnPerIP"])
PY
)"
auth_rate="$(python3 - <<'PY' "$json"
import json, sys
j=json.loads(sys.argv[1]); print(j["recommended"]["authRate"])
PY
)"

cat <<EOF
# Suggested server flags from observed traffic window (${WINDOW}s):
-publicRate=${public_rate}
-maxConnPerIP=${max_conn}
-authRate=${auth_rate}

# Raw recommendation payload:
${json}
EOF

