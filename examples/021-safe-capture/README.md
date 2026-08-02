# 021 - safe capture on a shared interface

Capture everything arriving on an interface, on the very NIC you're logged in
over, without losing your SSH session. This is `--rx-mode keep-management`.

```bash
IFACE=eth1 ./run.sh
```

## What it does

It redirects every packet on the interface to Wireblast, then carves out the
traffic that keeps the box reachable:

- ARP and IPv6 neighbour discovery (without these the box goes unreachable in
  about a minute, whatever else you spared)
- SSH to and from this host (TCP 22)
- DNS replies (UDP and TCP source port 53)

So unlike `--rx-mode all`, it needs no `--allow-match-all` and no typed
confirmation: it cannot strand you. It's the denylist counterpart to the
allowlist filters, "take everything except what would cut me off."

```
rx filter  all except management
Everything except management. Every packet eth1 receives is taken by Wireblast,
but SSH and DNS to and from this host, plus ARP and IPv6 neighbour discovery,
still reach the kernel, so the box stays reachable and your session survives.
```

## Worth knowing

- **Other services on this NIC stop receiving for the run.** A web server or
  database listening here goes quiet until the capture ends. Your SSH and DNS
  keep working; everything else is captured. That's the point, but it matters on
  a box that does more than testing.
- **The exceptions are the standard ports.** SSH on a non-standard port is not
  spared. Pass it through by widening the mode later, or capture on a different
  interface than you manage over.
- If you administer the box over a **different** interface than the one you're
  capturing on, you don't need this at all: a plain filter can't touch your
  management NIC.

## Pair it with a sender

Point [example 002](../002-first-run) or [007](../007-many-flows) at this box
from another machine and watch the RX column fill. Because keep-management takes
all of it, you don't have to match a port on the sender.

For high receive rates, make sure the sender uses many flows and the receiver
NIC hashes UDP on ports (`ethtool -N eth1 rx-flow-hash udp4 sdfn`), or everything
lands on one queue.
