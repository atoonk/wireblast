#!/usr/bin/env bash
# Generate many distinct flows rather than a single tuple.
set -euo pipefail

IFACE=${IFACE:?set IFACE, e.g. IFACE=eth1}
DST=${DST:?set DST, e.g. DST=192.0.2.10}
FLOWS=${FLOWS:-1000}
SIZE=${SIZE:-512}
PPS=${PPS:-1M}
DUR=${DUR:-30s}

exec sudo wireblast -i "$IFACE" --dst-ip "$DST" \
  --flows "$FLOWS" --packet-size "$SIZE" --pps "$PPS" -d "$DUR" --start
