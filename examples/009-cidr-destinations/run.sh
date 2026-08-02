#!/usr/bin/env bash
# Cycle destination addresses across a CIDR.
set -euo pipefail

IFACE=${IFACE:?set IFACE, e.g. IFACE=eth1}
DST=${DST:?set DST as a CIDR, e.g. DST=10.0.0.0/24}
FLOWS=${FLOWS:-254}
SIZE=${SIZE:-512}
PPS=${PPS:-1M}
DUR=${DUR:-30s}

ARGS=(-i "$IFACE" --dst-ip "$DST" --flows "$FLOWS"
      --packet-size "$SIZE" --pps "$PPS" -d "$DUR" --start)

# A directly connected CIDR needs one MAC per destination, which Wireblast will not
# guess. Point it at a router instead by setting DSTMAC.
[ -n "${DSTMAC:-}" ] && ARGS+=(--dst-mac "$DSTMAC")

exec sudo wireblast "${ARGS[@]}"
