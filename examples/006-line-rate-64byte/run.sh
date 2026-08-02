#!/usr/bin/env bash
# 64-byte frames at unlimited rate: the small-frame ceiling.
set -euo pipefail

IFACE=${IFACE:?set IFACE, e.g. IFACE=eth1}
DST=${DST:?set DST, e.g. DST=192.0.2.10}
DUR=${DUR:-30s}

echo "Sending 64-byte frames as fast as $IFACE will take them."
echo "10G line rate at this size is 14.88 Mpps."
echo

exec sudo wireblast -i "$IFACE" --dst-ip "$DST" \
  --packet-size 64 --pps unlimited -d "$DUR" --start
