#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8080}"
EXEC_ID="${EXEC_ID:-$(cat /proc/sys/kernel/random/uuid)}"

for cmd in curl jq; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "missing prerequisite: $cmd" >&2; exit 1; }
done

read -r -d '' CODE <<'SH' || true
set -euo pipefail
cat /etc/hostname >/dev/null
/bin/sh -lc 'printf child > /tmp/runtime-child.txt'
cat > /tmp/net_connect_probe.py <<'PY'
import socket
import threading
import time

ready = threading.Event()

def serve():
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 17777))
    srv.listen(1)
    ready.set()
    conn, _ = srv.accept()
    conn.recv(1)
    time.sleep(0.2)
    conn.close()
    srv.close()

thread = threading.Thread(target=serve, daemon=True)
thread.start()
if not ready.wait(2):
    raise SystemExit("server not ready")
client = socket.create_connection(("127.0.0.1", 17777), timeout=2)
client.sendall(b"x")
client.close()
thread.join(timeout=2)
print("runtime-event-demo")
PY
python3 /tmp/net_connect_probe.py
SH

payload="$(jq -nc --arg exec_id "$EXEC_ID" --arg code "$CODE" '{execution_id:$exec_id,lang:"bash",code:$code,timeout_ms:10000}')"
response="$(curl -sS --fail-with-body -X POST "$BASE_URL/v1/execute" -H 'Content-Type: application/json' -d "$payload")"
echo "$response"
echo "execution_id=$EXEC_ID"
echo "grep execution logs: grep -n $EXEC_ID /tmp/aegis-orchestrator.log"
echo "grep normalized runtime events: grep -n runtime_event /tmp/aegis-orchestrator.log | grep $EXEC_ID"
echo "follow SSE manually: curl -N $BASE_URL/v1/events/$EXEC_ID"
