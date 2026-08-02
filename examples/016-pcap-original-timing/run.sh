#!/usr/bin/env bash
# Replay a capture at its recorded timing, exactly once.
set -euo pipefail
cd "$(dirname "$0")"

IFACE=${IFACE:?set IFACE, e.g. IFACE=eth1}
PCAP=${PCAP:-../015-pcap-replay/sample.pcap}

exec sudo wireblast -i "$IFACE" --pcap "$PCAP" \
  --pcap-timing original --pcap-loop=false --start
