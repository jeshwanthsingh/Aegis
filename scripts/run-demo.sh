#!/bin/bash
set -e
# Timeouts are tuned for WSL2 cold boot (~6-7s boot + execution)
# On bare metal Linux, reduce timeouts to 3000-5000ms
BASE="http://localhost:8080/v1/execute"

echo "================================================"
echo " AEGIS - Threat Model Demo"
echo "================================================"
echo ""

echo "TEST 1: Fork Bomb (pids.max enforcement)"
echo "----------------------------------------"
echo "  Note: WSL2 adds ~10s overhead vs bare metal due to KVM emulation layer."
RESULT=$(curl -s -X POST $BASE \
  -H "Content-Type: application/json" \
  -d '{"lang":"python","code":"import os\nwhile True:\n    os.fork()","timeout_ms":8000}')
echo $RESULT | jq .
ERROR=$(echo $RESULT | jq -r '.error // ""')
if [ -n "$ERROR" ]; then
  echo "PASS — fork bomb contained: $ERROR"
else
  echo "FAIL — fork bomb was not stopped"
fi

echo ""
echo "TEST 2: Network Exfiltration (deny-all networking)"
echo "---------------------------------------------------"
echo "  Note: WSL2 adds ~10s overhead vs bare metal; urllib DNS/TCP timeout is expected."
RESULT=$(curl -s -X POST $BASE \
  -H "Content-Type: application/json" \
  -d '{"lang":"python","code":"import urllib.request\nurllib.request.urlopen(\"http://example.com\")","timeout_ms":10000}')
echo $RESULT | jq .
STDERR=$(echo $RESULT | jq -r '.stderr // ""')
EXITCODE=$(echo $RESULT | jq -r '.exit_code // "0"')
ERROR=$(echo $RESULT | jq -r '.error // ""')
# Timeout or non-zero exit both mean exfiltration failed — both are PASS
if [ "$EXITCODE" != "0" ] || [ -n "$ERROR" ]; then
  echo "PASS — exfiltration blocked (network unreachable or execution contained)"
else
  echo "FAIL — network was reachable inside VM"
fi

echo ""
echo "TEST 3: Host Filesystem Escape (KVM boundary)"
echo "----------------------------------------------"
RESULT=$(curl -s -X POST $BASE \
  -H "Content-Type: application/json" \
  -d '{"lang":"python","code":"print(open(\"/etc/passwd\").read())","timeout_ms":10000}')
echo $RESULT | jq .
STDOUT=$(echo $RESULT | jq -r '.stdout // ""')
if echo "$STDOUT" | grep -q "root:x:0:0"; then
  LINE_COUNT=$(echo "$STDOUT" | wc -l)
  HOST_COUNT=$(cat /etc/passwd | wc -l)
  if [ "$LINE_COUNT" -lt "$HOST_COUNT" ]; then
    echo "PASS — read VM's /etc/passwd ($LINE_COUNT lines), not host ($HOST_COUNT lines)"
  else
    echo "WARN — line counts match, verify manually"
  fi
else
  echo "FAIL — could not read /etc/passwd at all"
fi

echo ""
echo "TEST 4: Worker Pool Concurrency (5 simultaneous requests)"
echo "----------------------------------------------------------"
PIDS=()
RESULTS=()
TMPDIR_TEST=$(mktemp -d)

for i in 1 2 3 4 5; do
  curl -s -X POST $BASE \
    -H "Content-Type: application/json" \
    -d "{\"lang\":\"python\",\"code\":\"print('worker $i')\",\"timeout_ms\":10000}" \
    > "$TMPDIR_TEST/result_$i.json" &
  PIDS+=($!)
done

# Wait for all 5 requests to complete
for pid in "${PIDS[@]}"; do
  wait "$pid"
done

PASS_COUNT=0
FAIL_COUNT=0
for i in 1 2 3 4 5; do
  STDOUT=$(cat "$TMPDIR_TEST/result_$i.json" | jq -r '.stdout // ""')
  ERROR=$(cat "$TMPDIR_TEST/result_$i.json" | jq -r '.error // ""')
  if [ -n "$STDOUT" ] && [ -z "$ERROR" ]; then
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    echo "  worker $i FAIL: $(cat "$TMPDIR_TEST/result_$i.json")"
  fi
done

rm -rf "$TMPDIR_TEST"

# Scratch images must be gone — no leaked VMs
SCRATCH_COUNT=$(ls /tmp/aegis/scratch-*.ext4 2>/dev/null | wc -l)

if [ "$PASS_COUNT" -eq 5 ] && [ "$SCRATCH_COUNT" -eq 0 ]; then
  echo "PASS — all 5 concurrent workers succeeded, /tmp/aegis/ clean"
elif [ "$PASS_COUNT" -lt 5 ]; then
  echo "FAIL — only $PASS_COUNT/5 workers succeeded"
else
  echo "FAIL — $SCRATCH_COUNT scratch image(s) leaked in /tmp/aegis/"
fi

echo ""
echo "================================================"
echo " Demo complete. Check audit log:"
echo " psql -h localhost -U postgres -d aegis -c \"SELECT execution_id, outcome, duration_ms FROM executions ORDER BY created_at DESC LIMIT 3;\""
echo "================================================"


