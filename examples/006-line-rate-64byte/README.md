# 006 - the small-frame ceiling

64-byte frames at unlimited rate. This is the hardest thing you can ask a NIC to do,
and the number that tells you what your hardware is really worth.

```bash
IFACE=eth1 DST=192.0.2.10 ./run.sh
```

## The target

10G line rate with 64-byte frames is **14.88 Mpps**. Each frame occupies 84 bytes of
wire time once you count the preamble, start-frame delimiter and interframe gap.

| Link | 64-byte line rate |
|---|---|
| 1G | 1.488 Mpps |
| 10G | 14.88 Mpps |
| 25G | 37.2 Mpps |
| 100G | 148.8 Mpps |

## If you fall short

Check the header first. `generic XDP` or `copy` will cap you well below the hardware.
With `native XDP` and `zero-copy`, try more queues, then look at whether the receiver
or the path is the constraint. Example 019 walks through isolating it.

## Safety

<!-- -->
Unlimited rate on an interface carrying your default route will starve the host's own
traffic, and Wireblast will make you confirm it. Use a test NIC.
