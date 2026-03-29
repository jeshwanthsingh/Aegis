#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8080}"
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

hold_payload='{"lang":"bash","code":"sleep 8","timeout_ms":9000}'

curl -sS \
  -o "$tmpdir/hold.body" \
  -D "$tmpdir/hold.headers" \
  -X POST "$BASE_URL/v1/execute" \
  -H "Content-Type: application/json" \
  -d "$hold_payload" > /dev/null &
hold_pid=$!

TAP=""
for _ in $(seq 1 20); do
  TAP="$(ip -o link show | awk -F': ' '/tap-/{print $2; exit}' || true)"
  if [ -n "$TAP" ]; then
    break
  fi
  sleep 0.5
done

[ -n "$TAP" ] || {
  echo "failed to observe an Aegis tap-* interface during isolated execution" >&2
  wait "$hold_pid" || true
  exit 1
}

echo "TAP device: $TAP"

HOST_CIDR="$(ip -4 -o addr show dev "$TAP" | awk '{print $4; exit}')"
[ -n "$HOST_CIDR" ] || {
  echo "failed to determine host CIDR for $TAP" >&2
  wait "$hold_pid" || true
  exit 1
}
SUBNET_CIDR="$(python3 - <<'PY' "$HOST_CIDR"
import ipaddress, sys
print(ipaddress.ip_interface(sys.argv[1]).network)
PY
)"

echo "Host CIDR: $HOST_CIDR"
echo "Subnet CIDR: $SUBNET_CIDR"

echo "=== iptables FORWARD rules ==="
sudo iptables -L FORWARD -n -v

echo "=== iptables NAT POSTROUTING rules ==="
sudo iptables -t nat -L POSTROUTING -n -v

assert_rule() {
  local label="$1"
  shift
  if ! "$@"; then
    echo "missing rule: $label" >&2
    wait "$hold_pid" || true
    exit 1
  fi
}

assert_rule "FORWARD catch-all DROP" sudo iptables -C FORWARD -i "$TAP" -j DROP
assert_rule "FORWARD UDP DNS DROP" sudo iptables -C FORWARD -i "$TAP" -p udp --dport 53 -j DROP
assert_rule "FORWARD TCP DNS DROP" sudo iptables -C FORWARD -i "$TAP" -p tcp --dport 53 -j DROP
assert_rule "FORWARD 10/8 DROP" sudo iptables -C FORWARD -i "$TAP" -d 10.0.0.0/8 -j DROP
assert_rule "FORWARD 172.16/12 DROP" sudo iptables -C FORWARD -i "$TAP" -d 172.16.0.0/12 -j DROP
assert_rule "FORWARD 192.168/16 DROP" sudo iptables -C FORWARD -i "$TAP" -d 192.168.0.0/16 -j DROP
assert_rule "FORWARD metadata DROP" sudo iptables -C FORWARD -i "$TAP" -d 169.254.169.254 -j DROP
assert_rule "FORWARD tcp/80 ACCEPT" sudo iptables -C FORWARD -i "$TAP" -p tcp --dport 80 -j ACCEPT
assert_rule "FORWARD tcp/443 ACCEPT" sudo iptables -C FORWARD -i "$TAP" -p tcp --dport 443 -j ACCEPT
assert_rule "POSTROUTING MASQUERADE" sudo iptables -t nat -C POSTROUTING -s "$SUBNET_CIDR" ! -d "$SUBNET_CIDR" -j MASQUERADE

wait "$hold_pid" || true
echo "Isolation firewall rules verified against real Aegis TAP state"
