# 010 - the internet mix

A realistic spread of frame sizes instead of one artificial size.

```bash
IFACE=eth1 DST=192.0.2.10 ./run.sh
```

## The mix

| Frame size | Weight | Represents |
|---|---|---|
| 64 B | 7 | a bare TCP ack (40-byte IP packet) |
| 594 B | 4 | the old minimum reassembly buffer (576-byte IP packet) |
| 1518 B | 1 | a full Ethernet MTU (1500-byte IP packet) |

Mean frame size is **362 bytes**. Sizes are total Ethernet frame bytes including the
FCS, the same units as `--packet-size`, which IMIX otherwise ignores.

## What to expect

```
[0:05] tx 949.81 k pkts  200 kpps  L1 610.96 Mbit/s  L2 578.96 Mbit/s  avg 362B

ran for 0:12
  tx: 2.4 M packets, 868.24 MB, 199.86 kpps, L1 610.52 Mbit/s, L2 578.54 Mbit/s, avg frame 362B
```

`avg frame 362B` is your confirmation the mix came out right.

## Sizes are interleaved, not batched

Wireblast expands the mix into a 12-entry cycle using weighted round-robin, the same
smooth scheduling nginx uses, so the instantaneous bit rate stays near the average
instead of pulsing once per cycle. It's fully deterministic.
