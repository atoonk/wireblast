# 015 - replay a capture

Put a real capture back on the wire at a rate you choose. This directory ships a small
`sample.pcap` so it runs out of the box.

```bash
IFACE=eth1 ./run.sh
```

Replace it with your own capture by setting `PCAP`:

```bash
IFACE=eth1 PCAP=/path/to/yours.pcap ./run.sh
```

## About the sample

`sample.pcap` is 500 small UDP frames, generated with Wireblast itself and captured on
the receiving side. Wireblast summarises what it loaded before it sends anything:

```
capture  sample.pcap: 500 packets, 86-100 bytes (mean 99), spanning 441ms
```

## What replay does

Frames go out **byte for byte** as captured. Wireblast doesn't rewrite addresses or
recompute checksums unless you explicitly override the MACs with `--src-mac` /
`--dst-mac`.

By default the capture **loops** until the duration expires, and the pace comes from
`--pps`. That's what makes a short capture useful as a traffic source. To preserve the
capture's own timing instead, see example 016.

## Making your own

```bash
sudo tcpdump -ni eth1 -c 1000 -w mycapture.pcap
```

It must be an Ethernet capture. Wireblast refuses link types it can't put on a wire.
