# 008 - spreading across ECMP, LAG or RSS

Widen the hash space as far as Wireblast can: many flows, both ports varying, and a
scattered order so consecutive packets land on different tuples.

```bash
IFACE=eth1 DST=192.0.2.10 ./run.sh
```

## The three knobs

- **`--flows 10000`** creates ten thousand distinct tuples.
- **`--vary-dst-port`** increments the destination port as well as the source port,
  which doubles the entropy most hash functions see.
- **`--flow-order random`** scatters the walk. It's a fixed permutation derived from a
  golden-ratio stride, not actual randomness, so runs stay reproducible.

## Checking the spread

Look at the far end, not at Wireblast. On a LAG, check per-member counters. On a
router, check per-nexthop. An even spread means the hash is doing its job; a lopsided
one is the finding you were looking for.

To spread destination addresses too, see example 009.
