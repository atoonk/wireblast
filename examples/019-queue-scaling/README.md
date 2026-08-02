# 019 - queue scaling

Proves the rate limit is aggregate, not per queue, and shows whether adding queues
helps. Runs the same rate at 1, 2, 4 and all queues.

```bash
IFACE=eth1 DST=192.0.2.10 ./run.sh
```

## What it shows

At a fixed `--pps`, the achieved rate should barely move with queue count. Measured on
a 10G ixgbe NIC at `--pps 1M`:

| Queues | Achieved |
|---|---|
| 1 | 999.34 kpps |
| 4 | 999.35 kpps |
| 12 | 999.44 kpps |

That's what a working aggregate rate limiter looks like.

## Where it does matter

At **unlimited** rate, queue count is your parallelism. If `--queues 1` maxes out well
below `--queues 12`, you're CPU-bound and more queues will help. If they're equal,
adding cores isn't your bottleneck.

To test that, run this with `PPS=unlimited`.

## Note

Changing the queue count forces a fresh XDP attach, so on a physical NIC each step pays
the link bounce. This example is slower than the others for that reason.
