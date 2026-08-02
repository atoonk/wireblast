#!/usr/bin/env bash
# Replay a capture at a rate you choose (loops by default).
set -euo pipefail
cd "$(dirname "$0")"

IFACE=${IFACE:?set IFACE, e.g. IFACE=eth1}
PCAP=${PCAP:-sample.pcap}
PPS=${PPS:-100k}
DUR=${DUR:-30s}

exec sudo wireblast -i "$IFACE" --pcap "$PCAP" --pps "$PPS" -d "$DUR" --start
