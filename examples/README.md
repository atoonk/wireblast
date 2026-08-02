# Wireblast examples

Runnable examples, numbered roughly from simplest to most advanced. Each directory
has a `README.md` explaining what it demonstrates and a `run.sh` you can execute
directly.

```bash
cd examples/001-veth-quickstart
./run.sh
```

Every script takes its settings from environment variables so you don't have to edit
anything:

```bash
IFACE=eth1 DST=192.0.2.10 ./run.sh
```

## The examples

| | What it shows |
|---|---|
| [001-veth-quickstart](001-veth-quickstart) | A sender and a receiver on one machine, no NIC needed |
| [002-first-run](002-first-run) | The simplest possible run on a real interface |
| [003-fixed-rate](003-fixed-rate) | Setting a packet rate and a duration |
| [004-packet-sizes](004-packet-sizes) | The same rate at 64, 512 and 1518 bytes |
| [005-bit-rate-limit](005-bit-rate-limit) | Limiting by bits instead of packets |
| [006-line-rate-64byte](006-line-rate-64byte) | Small-frame ceiling: the hardest thing a NIC does |
| [007-many-flows](007-many-flows) | A thousand distinct flows |
| [008-flow-hashing](008-flow-hashing) | Spreading across ECMP, LAG or RSS |
| [009-cidr-destinations](009-cidr-destinations) | Cycling destinations across a subnet |
| [010-imix](010-imix) | The classic 7:4:1 internet mix |
| [011-imix-line-rate](011-imix-line-rate) | Finding the IMIX ceiling |
| [012-tcp-syn](012-tcp-syn) | Stateless SYNs against a connection table |
| [013-raw-ethernet](013-raw-ethernet) | No IP at all, just an EtherType |
| [014-vlan-tagged](014-vlan-tagged) | 802.1Q tagged frames |
| [015-pcap-replay](015-pcap-replay) | Replaying a capture at a rate you choose |
| [016-pcap-original-timing](016-pcap-original-timing) | Replaying a capture at its recorded timing |
| [017-receiver](017-receiver) | Counting what arrives |
| [018-two-box-imix](018-two-box-imix) | Sender and receiver on separate machines |
| [019-queue-scaling](019-queue-scaling) | Proving the rate limit is aggregate, not per queue |
| [020-soak-test](020-soak-test) | Running unattended for hours |

## About the receiver

Most examples are **transmit-only**, which is safe on a live box: nothing is taken
away from the kernel network stack.

Where a receiver is useful, the example's README gives you the command but doesn't run
it for you. Receiving takes packets away from the kernel, and how broad a filter is
safe depends on your machine. A narrow filter is almost always what you want:

```bash
sudo wireblast -i eth1 --mode receive --rx-mode udp-port --rx-port 9000 -d 60s
```

Run that in a second window, on an interface you are **not** logged in over.

`--rx-mode all` takes every packet on the interface, including SSH. It's deliberately
left out of these examples. If you need it, read
[transmit and receive](https://wireblast.mintlify.site/concepts/receive) first.

## Requirements

- Linux, kernel 5.4+ (5.9+ preferred)
- `wireblast` on your `PATH`
- root, or `cap_net_raw,cap_bpf,cap_sys_resource`
