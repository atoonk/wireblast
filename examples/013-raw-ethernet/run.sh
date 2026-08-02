#!/usr/bin/env bash
# Raw Ethernet frames with a fixed EtherType and no IP layer.
set -euo pipefail

IFACE=${IFACE:?set IFACE, e.g. IFACE=eth1}
DSTMAC=${DSTMAC:?set DSTMAC, e.g. DSTMAC=3c:ec:ef:b4:c2:dc}
ETHERTYPE=${ETHERTYPE:-0x88b5}
SIZE=${SIZE:-128}
PPS=${PPS:-1M}
DUR=${DUR:-30s}

exec sudo wireblast -i "$IFACE" --mode raw \
  --ethertype "$ETHERTYPE" --dst-mac "$DSTMAC" \
  --packet-size "$SIZE" --pps "$PPS" -d "$DUR" --start
