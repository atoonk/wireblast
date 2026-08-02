# 014 - VLAN-tagged frames

802.1Q tagged traffic. Wireblast builds the tag itself, so you bind the physical NIC,
not a VLAN sub-interface.

```bash
IFACE=eth1 DST=192.0.2.10 VLAN=100 ./run.sh
```

## Bind the physical NIC

AF_XDP attaches to the real device. Use `--interface eth1 --vlan 100`, not
`--interface vlan.100`. Wireblast catches the mistake and tells you the right form.

## The 68-byte minimum

The 64-byte Ethernet minimum is measured on the untagged frame, so a tagged frame can't
be smaller than 68. The NIC pads anything shorter, which would make the reported rates
disagree with the wire. So this example uses 68 by default.

## Addressing

If a matching VLAN sub-interface exists, Wireblast uses it for the source address and
next-hop MAC. If not, pass them explicitly with SRCIP and DSTMAC.
