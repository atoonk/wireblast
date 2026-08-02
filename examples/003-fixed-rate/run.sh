#!/usr/bin/env bash
# Pin the packet rate and duration so runs are comparable.
set -euo pipefail

IFACE=${IFACE:?set IFACE, e.g. IFACE=eth1}
DST=${DST:?set DST, e.g. DST=192.0.2.10}
SIZE=${SIZE:-512}
PPS=${PPS:-1M}
DUR=${DUR:-60s}

exec sudo wireblast -i "$IFACE" --dst-ip "$DST" \
  --packet-size "$SIZE" --pps "$PPS" -d "$DUR" --start
