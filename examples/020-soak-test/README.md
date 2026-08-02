# 020 - soak test

Run for hours, unattended, logging to a file. For catching the failures that only show
up after a while: thermal throttling, memory leaks in the device under test, slow
counter drift.

```bash
IFACE=eth1 DST=192.0.2.10 HOURS=8 ./run.sh
```

## How it runs

`--no-tui` with `nohup`, so it survives your shell closing. IMIX at a steady rate, which
is gentler and more realistic than hammering one frame size.

The log gets one line per second plus a summary at the end. Tail it any time:

```bash
tail -f /var/log/wireblast-soak.log
```

## Stopping cleanly

```bash
sudo pkill -INT wireblast
```

Wireblast drains its transmit rings, collects final counts and detaches the XDP program
before exiting, so the log ends with a proper summary rather than a truncated line.

## What to watch for

- **TX errors** climbing from zero: the box started rejecting descriptors.
- **Actual rate** drifting below the set rate: thermal throttling or contention.
- On the **receiver**, drops appearing after a long clean stretch.
