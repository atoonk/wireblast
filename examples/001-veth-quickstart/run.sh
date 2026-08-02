#!/usr/bin/env bash
# A sender and receiver on one machine, using a veth pair in a network namespace.
set -euo pipefail

NS=${NS:-wblab}
NEAR=${NEAR:-wb0}
FAR=${FAR:-wb1}
NEAR_IP=${NEAR_IP:-10.99.0.1}
FAR_IP=${FAR_IP:-10.99.0.2}
SIZE=${SIZE:-512}
PPS=${PPS:-100k}
DUR=${DUR:-10s}
KEEP=${KEEP:-0}

need_root() { [ "$(id -u)" -eq 0 ] || exec sudo -E "$0" "$@"; }
need_root "$@"

cleanup() {
  [ "$KEEP" = "1" ] && { echo "Lab left up. Remove it with: ip netns del $NS"; return; }
  ip netns del "$NS" 2>/dev/null || true
  ip link del "$NEAR" 2>/dev/null || true
}
trap cleanup EXIT

echo "Building the lab..."
ip netns add "$NS"
ip link add "$NEAR" type veth peer name "$FAR"
ip link set "$FAR" netns "$NS"
ip addr add "$NEAR_IP/24" dev "$NEAR"
ip link set "$NEAR" up
ip netns exec "$NS" ip addr add "$FAR_IP/24" dev "$FAR"
ip netns exec "$NS" ip link set "$FAR" up
ip netns exec "$NS" ip link set lo up

echo "Checking the cable..."
ping -c2 -W2 "$FAR_IP" >/dev/null && echo "  ok"

echo
echo "To count what arrives, run this in another window first:"
echo "  sudo ip netns exec $NS wireblast -i $FAR --mode receive \\"
echo "    --rx-mode udp-port --rx-port 9000 -d 60s"
echo "  (then re-run this script with KEEP=1)"
echo

wireblast -i "$NEAR" --dst-ip "$FAR_IP" --dst-port 9000 \
  --packet-size "$SIZE" --pps "$PPS" -d "$DUR" --start -y
