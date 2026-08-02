# 023 - many IPv6 flows

The flow machinery is identical for IPv6: `--flows` gives you distinct tuples,
and a CIDR destination cycles addresses across them. The difference is scale.

```bash
IFACE=eth1 DST=2001:db8::/64 FLOWS=10000 ./run.sh
```

## Cycling a /64

An IPv6 subnet is enormous (a /64 holds 2^64 addresses), and there is no network
or broadcast address to skip, so Wireblast simply walks addresses in order from
the base of the prefix. Ten thousand flows across a /64 gives you ten thousand
distinct destination addresses, which is a good way to exercise hashing (ECMP,
LAG, RSS) on v6.

```bash
# vary the source port per flow (default), fixed destination port
IFACE=eth1 DST=2001:db8::/64 FLOWS=10000 ./run.sh
# vary both ports as well, for a wider hash spread
IFACE=eth1 DST=2001:db8::/64 FLOWS=10000 VARY_DST_PORT=1 ./run.sh
```

## Determinism holds

Like IPv4, the flow set is a pure function of the config: the same run produces
the same tuples in the same order, whatever the queue count. So you can change
one variable at a time and trust the comparison.

## Receiving IPv6

For the receive side, `--rx-mode cidr` and `--rx-mode generated-flow` work for
IPv6 today (the address filters are family-aware). Port filters
(`--rx-mode udp-port`/`tcp-port`) are IPv4-only for now, so on a v6 run use cidr
or generated-flow, or capture with kernel counters on the far end.
