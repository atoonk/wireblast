#!/usr/bin/env bash
# The same packet rate at three frame sizes, back to back.
set -euo pipefail

IFACE=${IFACE:?set IFACE, e.g. IFACE=eth1}
DST=${DST:?set DST, e.g. DST=192.0.2.10}
PPS=${PPS:-500k}
DUR=${DUR:-15s}

for SIZE in 64 512 1518; do
  echo
  echo "=== ${SIZE}-byte frames at ${PPS} ==="
  sudo wireblast --no-tui -i "$IFACE" --dst-ip "$DST" \
    --packet-size "$SIZE" --pps "$PPS" -d "$DUR" -y
done
