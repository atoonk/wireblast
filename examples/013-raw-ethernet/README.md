# 013 - raw Ethernet

No IP, no ports. A fixed EtherType and a repeating payload byte. For testing switches,
tag handling, or anything that shouldn't care what's inside the frame.

```bash
IFACE=eth1 DSTMAC=3c:ec:ef:b4:c2:dc ./run.sh
```

## --dst-mac is required

Raw frames carry no IP addresses, so there's nothing to resolve a next hop from:

```
raw Ethernet frames carry no IP addresses, so there is nothing to resolve a
next-hop MAC from.
```

Set `DSTMAC` and the script passes it through.

## EtherType

Must be 0x0600 or above, since below that the field is a length, not a type. The
default here is 0x88b5, which is reserved for local experimental use.
