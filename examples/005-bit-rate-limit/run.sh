#!/usr/bin/env bash
# Limit by bits per second (L1) rather than packets per second.
set -euo pipefail

IFACE=${IFACE:?set IFACE, e.g. IFACE=eth1}
DST=${DST:?set DST, e.g. DST=192.0.2.10}
SIZE=${SIZE:-1518}
BPS=${BPS:-2.5G}
DUR=${DUR:-30s}

exec sudo wireblast -i "$IFACE" --dst-ip "$DST" \
  --packet-size "$SIZE" --bps "$BPS" -d "$DUR" --start
