#!/usr/bin/env bash
# Capture everything except management (SSH and DNS) on a shared interface.
# Safe to run on the NIC you are logged in over: it cannot cut off your session.
set -euo pipefail

IFACE=${IFACE:?set IFACE, e.g. IFACE=eth1}
DUR=${DUR:-60s}

exec sudo wireblast -i "$IFACE" --mode receive \
  --rx-mode keep-management -d "$DUR" --start
