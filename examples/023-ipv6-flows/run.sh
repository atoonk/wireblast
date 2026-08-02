#!/usr/bin/env bash
# Many IPv6 flows, optionally cycling destination addresses across a CIDR.
set -euo pipefail

IFACE=${IFACE:?set IFACE, e.g. IFACE=eth1}
DST=${DST:?set an IPv6 DST or CIDR, e.g. DST=2001:db8::/64}
FLOWS=${FLOWS:-10000}
SIZE=${SIZE:-128}
PPS=${PPS:-1M}
DUR=${DUR:-30s}

ARGS=(-i "$IFACE" --dst-ip "$DST" --flows "$FLOWS"
      --packet-size "$SIZE" --pps "$PPS" -d "$DUR" --start)
[ -n "${SRCIP:-}" ] && ARGS+=(--src-ip "$SRCIP")
[ -n "${DSTMAC:-}" ] && ARGS+=(--dst-mac "$DSTMAC")
[ -n "${VARY_DST_PORT:-}" ] && ARGS+=(--vary-dst-port)

exec sudo wireblast "${ARGS[@]}"
