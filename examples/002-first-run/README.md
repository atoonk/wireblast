# 002 - your first run on a real interface

The simplest useful command. One flow of 512-byte UDP frames at a modest rate.

```bash
IFACE=eth1 DST=192.0.2.10 ./run.sh
```

## What to expect

On a physical NIC the first thing you'll see is the link bouncing:

```
attaching XDP to eno2 and waiting for the link...
link came back after 11.8s
```

That's normal. Attaching a native XDP program makes the driver reinitialise its
queues, which drops carrier for several seconds. The run clock doesn't start until
the link is back, so you don't lose any of your requested duration.

Then:

```
started: eno2: 12 queue(s), zero-copy, native XDP, driver ixgbe, rx filter none
```

`native XDP` and `zero-copy` mean you're on the fast path. `generic XDP` or `copy`
means your driver has less support, which still works but is slower.

## Safety

This is transmit-only. Nothing is taken away from the kernel, so your SSH session and
everything else on the box keep working.

Do use an interface you are **not** logged in over, because the link bounce will
interrupt anything running across it.
