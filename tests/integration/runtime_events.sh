#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8080}"
EXEC_ID="${EXEC_ID:-$(cat /proc/sys/kernel/random/uuid)}"
EVENTS_FILE="$(mktemp)"
STREAM_PID=""

cleanup() {
  if [ -n "$STREAM_PID" ]; then
    kill "$STREAM_PID" >/dev/null 2>&1 || true
    wait "$STREAM_PID" 2>/dev/null || true
  fi
  rm -f "$EVENTS_FILE"
}
trap cleanup EXIT

for cmd in curl jq python3; do
  command -v "$cmd" >/dev/null 2>&1 || { echo "missing prerequisite: $cmd" >&2; exit 1; }
done

read -r -d '' CODE <<'SH' || true
set -euo pipefail
sleep 0.2
cat /etc/hostname >/dev/null
/bin/sh -lc 'printf child > /tmp/runtime-child.txt'
: >/dev/tcp/127.0.0.1/17777 || true
printf runtime-event-demo\n
SH

curl -sS -N --fail "$BASE_URL/v1/events/$EXEC_ID" >"$EVENTS_FILE" &
STREAM_PID=$!
sleep 0.5

payload="$(jq -nc --arg exec_id "$EXEC_ID" --arg code "$CODE" '{execution_id:$exec_id,lang:"bash",code:$code,timeout_ms:10000}')"
response="$(curl -sS --fail-with-body -X POST "$BASE_URL/v1/execute" -H 'Content-Type: application/json' -d "$payload")"
echo "$response"

error="$(printf '%s' "$response" | jq -r '.error // empty')"
[ -z "$error" ] || { echo "execution error: $error" >&2; exit 1; }
exit_code="$(printf '%s' "$response" | jq -r '.exit_code // 0')"
[ "$exit_code" = "0" ] || { echo "unexpected exit code: $exit_code" >&2; exit 1; }

sleep 2
kill "$STREAM_PID" >/dev/null 2>&1 || true
wait "$STREAM_PID" 2>/dev/null || true
STREAM_PID=""

python3 - "$EVENTS_FILE" "$EXEC_ID" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
exec_id = sys.argv[2]
raw = path.read_text()
if not raw.strip():
    raise SystemExit(f'no SSE data captured for {exec_id}')

runtime_events = []
for line in raw.splitlines():
    if not line.startswith('data: '):
        continue
    outer = json.loads(line[6:])
    if outer.get('kind') != 'runtime.event.v1':
        continue
    payload = json.loads(outer['data']) if isinstance(outer.get('data'), str) else outer['data']
    runtime_events.append(payload)

if not runtime_events:
    raise SystemExit(f'no runtime.event.v1 records observed for {exec_id}')

required = {'process.exec', 'process.fork', 'process.exit', 'net.connect'}
seen = [event['type'] for event in runtime_events]
missing = sorted(required - set(seen))
if missing:
    raise SystemExit(f'missing runtime event types: {missing}; seen={seen}')

seqs = [event['seq'] for event in runtime_events]
if seqs != sorted(seqs) or len(set(seqs)) != len(seqs):
    raise SystemExit(f'non-monotonic seq values: {seqs}')

if any(event['backend'] != 'firecracker' for event in runtime_events):
    raise SystemExit(f'unexpected backend values: {[event["backend"] for event in runtime_events]}')

if any(event['dropped_since_last'] < 0 for event in runtime_events):
    raise SystemExit('invalid dropped_since_last value')

print('runtime event demo passed')
print('execution_id=', exec_id)
print('seen_types=', seen)
print('seqs=', seqs)
PY
