#!/usr/bin/env bash
# 802.1Q tagged frames. Bind the physical NIC and let Wireblast build the tag.
set -euo pipefail

IFACE=${IFACE:?set IFACE, e.g. IFACE=eth1}
DST=${DST:?set DST, e.g. DST=192.0.2.10}
VLAN=${VLAN:?set VLAN, e.g. VLAN=100}
SIZE=${SIZE:-68}
PPS=${PPS:-1M}
DUR=${DUR:-30s}

ARGS=(-i "$IFACE" --vlan "$VLAN" --dst-ip "$DST"
      --packet-size "$SIZE" --pps "$PPS" -d "$DUR" --start)
[ -n "${SRCIP:-}" ] && ARGS+=(--src-ip "$SRCIP")
[ -n "${DSTMAC:-}" ] && ARGS+=(--dst-mac "$DSTMAC")

exec sudo wireblast "${ARGS[@]}"
