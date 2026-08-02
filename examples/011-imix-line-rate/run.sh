#!/usr/bin/env bash
# IMIX at unlimited rate to find the ceiling.
set -euo pipefail

IFACE=${IFACE:?set IFACE, e.g. IFACE=eth1}
DST=${DST:?set DST, e.g. DST=192.0.2.10}
FLOWS=${FLOWS:-64}
DUR=${DUR:-30s}

exec sudo wireblast -i "$IFACE" --dst-ip "$DST" --mode imix \
  --flows "$FLOWS" --pps unlimited -d "$DUR" --start
