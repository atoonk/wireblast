# 003 - a fixed packet rate

Pin the rate and the duration so runs are comparable with each other.

```bash
IFACE=eth1 DST=192.0.2.10 PPS=1M DUR=60s ./run.sh
```

## Rates are aggregate

`--pps 1M` is a million packets per second in total, not per queue. Measured across
1, 4 and 12 queues on the same 10G NIC: 999.34, 999.35 and 999.44 kpps.

## Reading the result

The header tells you whether the box is keeping up:

```
rate       set 1Mpps  actual 999.4 kpps
```

If `actual` falls short of `set` and TX errors stay at zero, you've found the limit of
the machine rather than a fault. Example 019 helps you work out which limit.

## Suffixes

`1M`, `500k`, `14.88M` are decimal SI, not powers of two. `unlimited`, `line-rate`,
`max`, `none` and `0` all mean no limit.
