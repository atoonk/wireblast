#!/usr/bin/env bash
# An IPv6 UDP blast. Give it a v6 destination and Wireblast builds v6 frames.
set -euo pipefail

IFACE=${IFACE:?set IFACE, e.g. IFACE=eth1}
DST=${DST:?set an IPv6 DST, e.g. DST=2001:db8::2}
SIZE=${SIZE:-66}   # IPv6 UDP minimum on the wire is 66 bytes
PPS=${PPS:-1M}
DUR=${DUR:-30s}

ARGS=(-i "$IFACE" --dst-ip "$DST" --packet-size "$SIZE" --pps "$PPS" -d "$DUR" --start)
[ -n "${SRCIP:-}" ] && ARGS+=(--src-ip "$SRCIP")
[ -n "${DSTMAC:-}" ] && ARGS+=(--dst-mac "$DSTMAC")

exec sudo wireblast "${ARGS[@]}"
