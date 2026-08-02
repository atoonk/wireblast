# 018 - two-box IMIX test

Sender on one machine, receiver on the other. When both ends report the same packet
count, the path between them carried everything.

## On the receiver, first

Start this before the sender, on an interface you are not managing the box over:

```bash
sudo wireblast -i eth1 --mode receive --rx-mode udp-port --rx-port 9000 -d 90s
```

## On the sender

```bash
IFACE=eth1 DST=192.0.2.20 DSTMAC=3c:ec:ef:b4:c2:dc ./run.sh
```

`run.sh` sends IMIX at a fixed rate for a shorter duration than the receiver's, so the
receiver is listening for the whole run.

## What to expect

Both ends steady at the same packets/sec and the same L1 bit rate during the overlap.
Real numbers from a 10G ixgbe pair:

```
sender    tx: 2.4 M packets, 199.86 kpps, L1 610.52 Mbit/s, avg frame 362B
receiver  rx: ~200 kpps,                  L1 ~614 Mbit/s,    avg frame 364B
```

The receiver's average over its whole run is lower, because it was idle before and
after. Compare the per-second lines, not the run averages.

## Why give the MAC explicitly

If the receiver doesn't own the destination IP, it won't answer ARP, and giving
`DSTMAC` skips resolution. Drop it if both boxes are properly addressed on one subnet.
