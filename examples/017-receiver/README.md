# 017 - count what arrives

Turn a box into a sink that transmits nothing and counts what lands on it. This is the
receiving half of a two-box test.

```bash
IFACE=eth1 PORT=9000 ./run.sh
```

## This one takes packets from the kernel

Unlike the transmit examples, a receive mode redirects matching packets away from the
kernel network stack. The default here is narrow, taking only UDP to one port:

```
rx filter  udp/9000
```

Everything else on the interface keeps flowing normally.

Still, run it on an interface you are **not** logged in over. And read
[transmit and receive](https://wireblast.mintlify.site/concepts/receive) before
widening the filter.

## Reading the result

The TX column becomes an idle block. Watch the RX column, and `Drops/errors` in
particular: climbing drops mean packets arrived faster than they could be collected.

The run's average rate will look low because it counts idle time before and after the
sender ran. Compare the per-second lines during the overlap, and the packet totals.
