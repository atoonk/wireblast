#!/usr/bin/env bash
# The sender half of a two-box IMIX test. Start the receiver first (see README).
set -euo pipefail

IFACE=${IFACE:?set IFACE, e.g. IFACE=eth1}
DST=${DST:?set DST, e.g. DST=192.0.2.20}
PORT=${PORT:-9000}
FLOWS=${FLOWS:-64}
PPS=${PPS:-200k}
DUR=${DUR:-30s}

ARGS=(-i "$IFACE" --mode imix --dst-ip "$DST" --dst-port "$PORT"
      --flows "$FLOWS" --pps "$PPS" -d "$DUR" --start)
[ -n "${VLAN:-}" ]   && ARGS+=(--vlan "$VLAN")
[ -n "${SRCIP:-}" ]  && ARGS+=(--src-ip "$SRCIP")
[ -n "${DSTMAC:-}" ] && ARGS+=(--dst-mac "$DSTMAC")

cat <<MSG
Start the receiver in another window first:
  sudo wireblast -i <recv-iface> --mode receive --rx-mode udp-port --rx-port $PORT -d 90s

MSG

exec sudo wireblast "${ARGS[@]}"
