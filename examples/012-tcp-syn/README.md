# 012 - stateless TCP SYNs

Many SYNs, many flows, no handshake. Useful for stressing a firewall or load balancer's
connection table.

```bash
IFACE=eth1 DST=192.0.2.10 PORT=443 ./run.sh
```

## Stateless

Correct checksums, but no handshake, no connection state, no retransmission. Wireblast
sends SYNs and counts them. Whatever the far end replies goes to its kernel as normal
unless you turn on a receive mode.

## This is a SYN flood

Only point it at something you own and have permission to test.
