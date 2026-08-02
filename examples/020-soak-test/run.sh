#!/usr/bin/env bash
# Run unattended for hours, logging to a file.
set -euo pipefail

IFACE=${IFACE:?set IFACE, e.g. IFACE=eth1}
DST=${DST:?set DST, e.g. DST=192.0.2.10}
HOURS=${HOURS:-8}
PPS=${PPS:-500k}
LOG=${LOG:-/var/log/wireblast-soak.log}

DUR=$(( HOURS * 3600 ))s

echo "Soaking $IFACE -> $DST at $PPS for ${HOURS}h."
echo "Logging to $LOG. Stop with: sudo pkill -INT wireblast"

sudo nohup wireblast --no-tui -i "$IFACE" --dst-ip "$DST" \
  --mode imix --pps "$PPS" -d "$DUR" -y > "$LOG" 2>&1 &

echo "Started as PID $!."
