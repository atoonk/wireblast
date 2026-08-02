# 004 - the same rate at three frame sizes

Runs 64, 512 and 1518-byte frames back to back at the same packet rate, so you can see
packet rate and bit rate trade off against each other.

```bash
IFACE=eth1 DST=192.0.2.10 ./run.sh
```

## What it shows

At a fixed packet rate, bits scale with frame size:

| Frame | L1 at 1 Mpps |
|---|---|
| 64 B | 672 Mbit/s |
| 512 B | 4.26 Gbit/s |
| 1518 B | 12.3 Gbit/s (above 10G line rate, so it will fall short) |

Small frames are a packet-rate problem. Large frames are a bit-rate problem. Systems
usually fail at one end or the other, which is why testing a single size hides things.

## --packet-size includes the FCS

`--packet-size 64` is the classic 64-byte frame. Wireblast writes 60 bytes and the NIC
appends the 4-byte frame check sequence. This is the definition that trips people up
most often.
