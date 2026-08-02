#!/usr/bin/env bash
# The simplest useful Wireblast run: one flow of 512-byte UDP frames.
set -euo pipefail

IFACE=${IFACE:?set IFACE, e.g. IFACE=eth1}
DST=${DST:?set DST, e.g. DST=192.0.2.10}
SIZE=${SIZE:-512}
PPS=${PPS:-100k}
DUR=${DUR:-30s}

exec sudo wireblast -i "$IFACE" --dst-ip "$DST" \
  --packet-size "$SIZE" --pps "$PPS" -d "$DUR" --start
