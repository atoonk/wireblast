# 016 - replay a capture at its own timing

The same capture as example 015, but replayed with its recorded gaps between packets
instead of at a rate you set. This reproduces a scenario, not a load.

```bash
IFACE=eth1 PCAP=../015-pcap-replay/sample.pcap ./run.sh
```

## Rate versus original

- **`--pcap-timing rate`** (the default, example 015) ignores timestamps and paces with
  `--pps`. The capture becomes a source of packet content.
- **`--pcap-timing original`** preserves the gaps. A capture spanning 441ms replays in
  about 441ms.

Use original timing to reproduce a burst, a microburst, or a specific interleaving.

## One pass or looped

This example sets `--pcap-loop=false`, so the capture plays exactly once and stops,
whatever `--duration` says. A one-pass replay runs on a single queue in capture order,
which is the point: order is what you're preserving.

## Fine print on timing

Gaps below 250µs can't be slept on accurately, so Wireblast accumulates them and pays
them together. Timing stays right in aggregate; individual sub-millisecond gaps are
approximate. A rate limit still applies on top, and the slower constraint wins.
