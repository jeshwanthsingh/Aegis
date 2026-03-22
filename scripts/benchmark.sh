#!/bin/bash
BASE="http://localhost:8080/v1/execute"
N=10

echo "================================================"
echo " AEGIS - Benchmark ($N sequential executions)"
echo "================================================"
echo ""

DURATIONS=()

for i in $(seq 1 $N); do
  RESULT=$(curl -s -X POST $BASE \
    -H "Content-Type: application/json" \
    -d '{"lang":"python","code":"print(\"hello\")","timeout_ms":10000}')
  DUR=$(echo $RESULT | jq -r '.duration_ms // "0"')
  ERR=$(echo $RESULT | jq -r '.error // ""')
  if [ -n "$ERR" ]; then
    echo "  run $i: ERROR — $ERR"
  else
    echo "  run $i: ${DUR}ms"
    DURATIONS+=($DUR)
  fi
done

echo ""
if [ ${#DURATIONS[@]} -eq 0 ]; then
  echo "No successful runs."
  exit 1
fi

MIN=${DURATIONS[0]}
MAX=${DURATIONS[0]}
SUM=0

for D in "${DURATIONS[@]}"; do
  (( D < MIN )) && MIN=$D
  (( D > MAX )) && MAX=$D
  (( SUM += D ))
done

AVG=$(( SUM / ${#DURATIONS[@]} ))

echo "Results (${#DURATIONS[@]}/${N} successful):"
echo "  min: ${MIN}ms"
echo "  max: ${MAX}ms"
echo "  avg: ${AVG}ms"
echo ""
echo "NOTE: Numbers reflect cold boot + full-copy clone."
echo "      Overlayfs / snapshot restore is the v2 path to sub-150ms boot."
