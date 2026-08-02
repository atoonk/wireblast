# 022 - IPv6 UDP blast

Everything Wireblast does over IPv4, it does over IPv6 too. Give it a v6
destination and it builds v6 frames. That's the whole change on your end.

```bash
IFACE=eth1 DST=2001:db8::2 ./run.sh
```

## What differs from IPv4

Nothing you have to think about, but two things happen under the hood:

- The IPv6 header is 40 bytes (versus 20 for IPv4), so the smallest UDP frame is
  66 bytes on the wire rather than 64. Ask for less and Wireblast tells you the
  real minimum.
- The UDP checksum is mandatory over IPv6 (it may not be left at zero the way it
  can for IPv4), so Wireblast computes and maintains it. You get correct frames
  either way; it just does a touch more work per packet.

## Addressing

Wireblast picks a source address of the right scope from the interface: a
global/ULA address for a global destination, the link-local one for a
link-local destination. Override it with `SRCIP` if you want a specific source:

```bash
IFACE=eth1 DST=2001:db8::2 SRCIP=2001:db8::1234 ./run.sh
```

The next-hop MAC is resolved by neighbour discovery (the v6 equivalent of ARP),
exactly the same way, with no configuration from you. If the target will not
answer ND (a black hole, a tap), give `DSTMAC` directly.

## Line rate is line rate

The 40-byte header eats a little more of each small frame, but the packet-rate
ceiling is unchanged: 64-byte-class frames still top out at 14.88 Mpps on 10G.
