#!/bin/bash
# SPDX-License-Identifier: MIT
#
# Integration test for arp-monitor using veth pair + network namespace.
# Sends ARP packets and verifies detection output.
#
# Usage: sudo ./test_veth.sh <path-to-arp-monitor-binary>
#
set -euo pipefail

BINARY="${1:?Usage: $0 <path-to-arp-monitor>}"
NS="arp_test_ns"
VETH_HOST="veth-host"
VETH_NS="veth-ns"
HOST_IP="10.99.0.1"
NS_IP="10.99.0.2"
TIMEOUT=10
PASS=0
FAIL=0

cleanup() {
    echo "[*] Cleaning up..."
    # Kill monitor if running
    if [[ -n "${MONITOR_PID:-}" ]] && kill -0 "$MONITOR_PID" 2>/dev/null; then
        kill "$MONITOR_PID" 2>/dev/null || true
        wait "$MONITOR_PID" 2>/dev/null || true
    fi
    ip link del "$VETH_HOST" 2>/dev/null || true
    ip netns del "$NS" 2>/dev/null || true
    rm -f /tmp/arp_monitor_test_output.txt
}

trap cleanup EXIT

assert_contains() {
    local file="$1"
    local pattern="$2"
    local desc="$3"

    if grep -qE "$pattern" "$file"; then
        echo "  [PASS] $desc"
        ((PASS++))
    else
        echo "  [FAIL] $desc (pattern: $pattern)"
        ((FAIL++))
    fi
}

echo "=== ARP Monitor Integration Test ==="
echo ""

# Check privileges
if [[ $EUID -ne 0 ]]; then
    echo "Error: This test requires root privileges"
    exit 1
fi

# Check binary exists
if [[ ! -x "$BINARY" ]]; then
    echo "Error: Binary not found or not executable: $BINARY"
    exit 1
fi

# ─── Setup network namespace + veth pair ─────────────────────────────────
echo "[*] Setting up test environment..."
ip netns add "$NS"
ip link add "$VETH_HOST" type veth peer name "$VETH_NS"
ip link set "$VETH_NS" netns "$NS"

ip addr add "${HOST_IP}/24" dev "$VETH_HOST"
ip link set "$VETH_HOST" up

ip netns exec "$NS" ip addr add "${NS_IP}/24" dev "$VETH_NS"
ip netns exec "$NS" ip link set "$VETH_NS" up
ip netns exec "$NS" ip link set lo up

# Wait for interfaces to be ready
sleep 1

# ─── Test 1: Basic ARP capture ───────────────────────────────────────────
echo ""
echo "[*] Test 1: Basic ARP capture"

"$BINARY" -i "$VETH_HOST" -j > /tmp/arp_monitor_test_output.txt 2>/dev/null &
MONITOR_PID=$!
sleep 2

# Generate ARP traffic
ip netns exec "$NS" ping -c 1 -W 2 "$HOST_IP" > /dev/null 2>&1 || true
sleep 2

kill "$MONITOR_PID" 2>/dev/null || true
wait "$MONITOR_PID" 2>/dev/null || true

assert_contains /tmp/arp_monitor_test_output.txt '"opcode"' "JSON output format"
assert_contains /tmp/arp_monitor_test_output.txt '"sender_ip"' "Contains sender IP field"
assert_contains /tmp/arp_monitor_test_output.txt "10\.99\.0\." "Contains test subnet IP"

# ─── Test 2: Spoof detection ─────────────────────────────────────────────
echo ""
echo "[*] Test 2: ARP spoof detection (MAC flip)"

> /tmp/arp_monitor_test_output.txt
"$BINARY" -i "$VETH_HOST" -j -t 2 > /tmp/arp_monitor_test_output.txt 2>/dev/null &
MONITOR_PID=$!
sleep 2

# Simulate MAC changes by manipulating the namespace interface
# Change MAC, send ARP, change again — triggers flip detection
ip netns exec "$NS" ip link set "$VETH_NS" down
ip netns exec "$NS" ip link set "$VETH_NS" address aa:bb:cc:dd:ee:01
ip netns exec "$NS" ip link set "$VETH_NS" up
sleep 1
ip netns exec "$NS" ping -c 1 -W 2 "$HOST_IP" > /dev/null 2>&1 || true
sleep 1

ip netns exec "$NS" ip link set "$VETH_NS" down
ip netns exec "$NS" ip link set "$VETH_NS" address aa:bb:cc:dd:ee:02
ip netns exec "$NS" ip link set "$VETH_NS" up
sleep 1
ip netns exec "$NS" ping -c 1 -W 2 "$HOST_IP" > /dev/null 2>&1 || true
sleep 1

ip netns exec "$NS" ip link set "$VETH_NS" down
ip netns exec "$NS" ip link set "$VETH_NS" address aa:bb:cc:dd:ee:03
ip netns exec "$NS" ip link set "$VETH_NS" up
sleep 1
ip netns exec "$NS" ping -c 1 -W 2 "$HOST_IP" > /dev/null 2>&1 || true
sleep 2

kill "$MONITOR_PID" 2>/dev/null || true
wait "$MONITOR_PID" 2>/dev/null || true

assert_contains /tmp/arp_monitor_test_output.txt '"spoof_detected":true' "Spoof detection triggered"
assert_contains /tmp/arp_monitor_test_output.txt '"new_host":true' "New host flagged on first appearance"

# ─── Results ──────────────────────────────────────────────────────────────
echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
exit $((FAIL > 0 ? 1 : 0))
