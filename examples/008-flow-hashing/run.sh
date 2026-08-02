#!/usr/bin/env bash
# Maximum flow entropy: many flows, both ports varying, scattered order.
set -euo pipefail

IFACE=${IFACE:?set IFACE, e.g. IFACE=eth1}
DST=${DST:?set DST, e.g. DST=192.0.2.10}
FLOWS=${FLOWS:-10000}
SIZE=${SIZE:-512}
PPS=${PPS:-1M}
DUR=${DUR:-60s}

exec sudo wireblast -i "$IFACE" --dst-ip "$DST" \
  --flows "$FLOWS" --vary-dst-port --flow-order random \
  --packet-size "$SIZE" --pps "$PPS" -d "$DUR" --start
