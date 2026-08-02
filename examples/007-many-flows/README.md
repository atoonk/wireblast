# 007 - a thousand flows

One flow only ever takes one path through a network. To exercise anything that hashes,
you need many.

```bash
IFACE=eth1 DST=192.0.2.10 FLOWS=1000 ./run.sh
```

## What a flow is here

A stable combination of source IP, destination IP, source port and destination port.
By default the source port increments per flow and the destination port stays fixed,
which mirrors real client traffic hitting one service port.

## It's deterministic

The same configuration always produces the same tuples in the same order. That holds
regardless of queue count: queue *q* of *Q* takes flow *q* and steps by *Q*, so between
them they cover every flow exactly once per cycle.

So you can change one variable at a time and trust the comparison.
