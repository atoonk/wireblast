# 001 - veth quickstart

A sender and a receiver on one machine, with no NIC involved at all. This is the
safest place to learn Wireblast: a `veth` pair inside a throwaway network namespace
cannot touch your real network.

`run.sh` builds the lab, sends traffic across it, and tears it down again.

## What to expect

```
started: wb0: 1 queue(s), copy, native XDP, rx filter none
ran for 0:10
  tx: 1 M packets, 512.03 MB, 99.95 kpps, L1 425.38 Mbit/s, L2 409.39 Mbit/s, avg frame 512B
```

Two things differ from a physical NIC:

- **No link bounce.** There's no carrier to renegotiate, so the attach is instant.
- **`copy`, not `zero-copy`, and one queue.** Expected on veth.

## How fast does veth go?

Measured on a 12-core box, single queue:

| Far end | Rate |
|---|---|
| kernel stack consuming the packets | ~530 kpps, regardless of frame size |
| a Wireblast receiver draining via AF_XDP | ~800 kpps, zero loss |

It's packet-rate bound rather than bit-rate bound, so 1518-byte frames reach about
6.5 Gbit/s while 64-byte frames reach about 0.37 Gbit/s. These numbers tell you about
your CPU and the kernel, not about any NIC.

## Add a receiver

In a second window, before starting the sender:

```bash
sudo ip netns exec wblab wireblast -i wb1 \
  --mode receive --rx-mode udp-port --rx-port 9000 -d 60s
```

Then run `./run.sh` with `KEEP=1` so it doesn't tear the lab down underneath you.

Sent and received packet counts should match exactly.
