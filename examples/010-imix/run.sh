#!/usr/bin/env bash
# The classic 7:4:1 IMIX of 64, 594 and 1518-byte frames.
set -euo pipefail

IFACE=${IFACE:?set IFACE, e.g. IFACE=eth1}
DST=${DST:?set DST, e.g. DST=192.0.2.10}
FLOWS=${FLOWS:-64}
PPS=${PPS:-200k}
DUR=${DUR:-30s}

exec sudo wireblast -i "$IFACE" --dst-ip "$DST" --mode imix \
  --flows "$FLOWS" --pps "$PPS" -d "$DUR" --start
