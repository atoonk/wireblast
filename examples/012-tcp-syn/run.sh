#!/usr/bin/env bash
# Stateless TCP SYNs across many flows.
set -euo pipefail

IFACE=${IFACE:?set IFACE, e.g. IFACE=eth1}
DST=${DST:?set DST, e.g. DST=192.0.2.10}
PORT=${PORT:-443}
FLOWS=${FLOWS:-100000}
PPS=${PPS:-1M}
DUR=${DUR:-30s}

exec sudo wireblast -i "$IFACE" --dst-ip "$DST" --mode tcp-syn \
  --dst-port "$PORT" --flows "$FLOWS" --pps "$PPS" -d "$DUR" --start
