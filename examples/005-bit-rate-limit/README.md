# 005 - limiting by bits instead of packets

Sometimes you want "fill 2.5 gigabit" rather than "send this many packets".

```bash
IFACE=eth1 DST=192.0.2.10 BPS=2.5G ./run.sh
```

## --bps is measured in L1

L1 is the frame plus its physical framing: a 7-byte preamble, a 1-byte start-frame
delimiter and a 12-byte interframe gap. That's what link utilisation means, so
`--bps 10G` means 10G line rate.

It's also the only definition under which small frames can saturate a 10G link. A
64-byte frame occupies 84 bytes of wire time, which is why line rate is 14.88 Mpps
rather than 19.5 Mpps.

## Setting both limits

You can set `--pps` and `--bps` together, and the slower one binds:

```bash
sudo wireblast -i eth1 --dst-ip 192.0.2.10 --pps 1M --bps 100M -d 30s
```

Setting `--bps` on its own lifts the default 100 kpps cap, or `--bps 1G` would quietly
run at 100 kpps.
