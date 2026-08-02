#!/usr/bin/env bash
# Receive-only: count what arrives on a narrow filter.
set -euo pipefail

IFACE=${IFACE:?set IFACE, e.g. IFACE=eth1}
PORT=${PORT:-9000}
PROTO=${PROTO:-udp}   # udp or tcp
DUR=${DUR:-60s}

exec sudo wireblast -i "$IFACE" --mode receive \
  --rx-mode "${PROTO}-port" --rx-port "$PORT" -d "$DUR" --start
