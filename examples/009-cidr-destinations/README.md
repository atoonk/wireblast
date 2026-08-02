# 009 - cycling destinations across a subnet

Give `--dst-ip` a CIDR instead of a single address and destinations cycle across flows.

```bash
IFACE=eth1 DST=10.0.0.0/24 ./run.sh
```

## Address selection

Network and broadcast addresses are skipped for /30 and shorter. A /31 uses both of its
addresses, per RFC 3021. A /32 uses its single address.

## One catch: the next-hop MAC

If the CIDR is **directly connected** to your interface, each destination would need
its own MAC address, and Wireblast resolves one next hop per run:

```
10.0.0.0/24 is directly connected to eno2, and a run across 254 destinations in it
would need a different MAC address for each one. Wireblast resolves one next hop per
run, so it cannot do that automatically.
```

Two ways round it. Point the run at a router and let it forward:

```bash
IFACE=eth1 DST=10.0.0.0/24 DSTMAC=00:1a:2b:3c:4d:5e ./run.sh
```

Or target a range that isn't on-link, so the routing table gives a single gateway.
