#!/usr/bin/env bash
# Run the same rate at 1, 2, 4 and all queues to show the limit is aggregate.
set -euo pipefail

IFACE=${IFACE:?set IFACE, e.g. IFACE=eth1}
DST=${DST:?set DST, e.g. DST=192.0.2.10}
SIZE=${SIZE:-64}
PPS=${PPS:-1M}
DUR=${DUR:-15s}

for Q in 1 2 4 0; do
  LABEL=$([ "$Q" = 0 ] && echo "all" || echo "$Q")
  echo
  echo "=== $LABEL queue(s), ${PPS} ==="
  sudo wireblast --no-tui -i "$IFACE" --dst-ip "$DST" \
    --queues "$Q" --packet-size "$SIZE" --pps "$PPS" -d "$DUR" -y | grep -E "^  tx:|^started"
done
