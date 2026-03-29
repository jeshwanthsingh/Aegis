#!/usr/bin/env bash
set -euo pipefail

TAP="$(ip link show | grep 'tap-' | head -1 | awk '{print $2}' | tr -d ':' || true)"
echo "TAP device: ${TAP:-<none>}"

echo "=== iptables FORWARD rules ==="
sudo iptables -L FORWARD -n -v

sudo ip tuntap add dev tap-test mode tap 2>/dev/null || true
sudo ip addr add 172.99.99.1/30 dev tap-test 2>/dev/null || true
sudo ip link set tap-test up 2>/dev/null || true
sudo iptables -I FORWARD 1 -i tap-test -j DROP
sudo iptables -I FORWARD 1 -i tap-test -p udp --dport 53 -j DROP

DNS_RULE="$(sudo iptables -L FORWARD -n -v | grep 'tap-test' | grep 'dpt:53' | grep 'DROP' || true)"
FORWARD_RULE="$(sudo iptables -L FORWARD -n -v | grep 'tap-test' | grep -v 'dpt:53' | grep 'DROP' || true)"

echo "DNS FORWARD rule: $DNS_RULE"
echo "FORWARD DROP catch-all: $FORWARD_RULE"

[ -n "$DNS_RULE" ] || { echo "DNS FORWARD rule not found" >&2; exit 1; }
[ -n "$FORWARD_RULE" ] || { echo "FORWARD DROP catch-all rule not found" >&2; exit 1; }

sudo iptables -D FORWARD -i tap-test -p udp --dport 53 -j DROP 2>/dev/null || true
sudo iptables -D FORWARD -i tap-test -j DROP 2>/dev/null || true
sudo ip link del tap-test 2>/dev/null || true
