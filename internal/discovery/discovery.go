// Package discovery reads the system's network configuration — interfaces,
// addresses, routes and neighbours — and works out the things a user should
// not have to type: which interface to use, what source address to send from,
// and which MAC address the next hop has.
//
// Everything it needs from the kernel goes through the [Source] interface, so
// the decision logic is ordinary testable code with no root, no netlink and no
// hardware. [NewSource] returns the real netlink-backed implementation.
package discovery

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"time"
)

// Link is one network interface.
type Link struct {
	Name  string
	Index int
	MAC   net.HardwareAddr
	MTU   int

	// Up is the administrative state; Carrier is whether the link is
	// operationally up (a cable is plugged in and negotiated).
	Up      bool
	Carrier bool

	Loopback bool
	Driver   string

	// Addrs holds the interface's addresses, IPv4 and IPv6 alike, so the
	// wizard can show what the user expects to see.
	Addrs []netip.Prefix

	// VLANID and ParentIndex are set for an 802.1Q sub-interface; VLANID is 0
	// on any other kind of device.
	VLANID      int
	ParentIndex int

	// RxQueues is how many receive queues the device exposes. AF_XDP binds one
	// socket per queue, so a device with none cannot be used.
	RxQueues int
}

// IPv4 returns the link's IPv4 prefixes, in the order the kernel reports them.
func (l Link) IPv4() []netip.Prefix { return l.addrsForFamily(false) }

// addrsForFamily returns the link's prefixes of the requested family, in the
// order the kernel reports them.
func (l Link) addrsForFamily(v6 bool) []netip.Prefix {
	var out []netip.Prefix
	for _, p := range l.Addrs {
		if p.Addr().Is6() == v6 {
			out = append(out, p)
		}
	}
	return out
}

// orderV6Sources puts the source addresses of the right scope first: a
// link-local source for a link-local destination, a routable one otherwise. A
// link-local address is always present on an IPv6 interface but is the wrong
// source for global traffic.
func orderV6Sources(addrs []netip.Prefix, dst netip.Addr) []netip.Prefix {
	dstLL := dst.IsLinkLocalUnicast()
	var match, other []netip.Prefix
	for _, p := range addrs {
		if p.Addr().IsLinkLocalUnicast() == dstLL {
			match = append(match, p)
		} else {
			other = append(other, p)
		}
	}
	return append(match, other...)
}

// IsVLAN reports whether this is an 802.1Q sub-interface.
func (l Link) IsVLAN() bool { return l.VLANID != 0 }

// Route is one routing-table entry.
type Route struct {
	// Dst is the destination prefix. The zero Prefix means the default route.
	Dst netip.Prefix
	// Gateway is the next hop, or the zero Addr for a directly connected
	// ("on-link") route.
	Gateway   netip.Addr
	LinkIndex int
	Priority  int
	Src       netip.Addr
}

// IsDefault reports whether this is the default route.
func (r Route) IsDefault() bool { return !r.Dst.IsValid() || r.Dst.Bits() == 0 }

// Bits is the route's prefix length, treating an invalid prefix as /0.
func (r Route) Bits() int {
	if !r.Dst.IsValid() {
		return 0
	}
	return r.Dst.Bits()
}

// Contains reports whether this route covers an address.
func (r Route) Contains(a netip.Addr) bool {
	if r.IsDefault() {
		// A default route covers its whole family. When the prefix is set (the
		// normal case, 0.0.0.0/0 or ::/0) match on family; otherwise assume IPv4.
		if r.Dst.IsValid() {
			return r.Dst.Addr().Is4() == a.Is4()
		}
		return a.Is4()
	}
	return r.Dst.Contains(a)
}

// Neighbor is one entry from the IPv4 neighbour (ARP) table.
type Neighbor struct {
	IP        netip.Addr
	MAC       net.HardwareAddr
	LinkIndex int
	// Reachable is true for entries the kernel considers usable (REACHABLE,
	// STALE, PERMANENT and friends) rather than incomplete or failed.
	Reachable bool
}

// Source supplies the system state discovery reasons about. It exists so the
// interface-selection and next-hop logic can be unit-tested against fixtures
// instead of whatever machine the tests happen to run on.
type Source interface {
	Links() ([]Link, error)
	Routes() ([]Route, error)
	Neighbors(linkIndex int) ([]Neighbor, error)
	// Probe provokes IPv4 neighbour resolution for dst out of the given link
	// and waits up to timeout for the kernel to answer. Returning an error is
	// not fatal — the caller checks the neighbour table afterwards either way.
	Probe(link Link, dst netip.Addr, timeout time.Duration) error
}

// Usable reports whether an interface can carry an AF_XDP run: administratively
// up, not loopback, with a real 6-byte hardware address and at least one
// receive queue.
//
// VLAN sub-interfaces are excluded on purpose. Binding AF_XDP to one only ever
// gets the slow generic path, and the right answer is always to bind the
// parent NIC and set --vlan, which Wireblast says explicitly when a user picks
// one. See [ExplainVLANInterface].
func Usable(l Link) bool {
	return l.Up && !l.Loopback && len(l.MAC) == 6 && l.RxQueues > 0 && !l.IsVLAN()
}

// Interfaces returns the interfaces a user may choose from, best candidate
// first.
//
// The ordering matters more than it sounds: a busy host can have twenty veth,
// dummy and bridge devices that are technically usable but never what someone
// running a traffic generator wants. Physical NICs — the ones with a real
// kernel driver — come first, then those with a carrier, then those with an
// IPv4 address, then by name.
func Interfaces(s Source) ([]Link, error) {
	links, err := s.Links()
	if err != nil {
		return nil, err
	}
	var out []Link
	for _, l := range links {
		if Usable(l) {
			out = append(out, l)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if ah, bh := a.Driver != "", b.Driver != ""; ah != bh {
			return ah
		}
		if a.Carrier != b.Carrier {
			return a.Carrier
		}
		if ai, bi := len(a.Addrs) > 0, len(b.Addrs) > 0; ai != bi {
			return ai
		}
		return a.Name < b.Name
	})
	return out, nil
}

// IsPhysical reports whether the interface is backed by a real kernel driver
// rather than being a virtual device. Used to sort and label the wizard's
// interface list.
func (l Link) IsPhysical() bool { return l.Driver != "" }

// DefaultRouteLink returns the index of the interface that owns the default
// route, and whether there is one. Used to warn before blasting traffic out of
// the interface the machine reaches the world through.
func DefaultRouteLink(s Source) (int, bool) {
	routes, err := s.Routes()
	if err != nil {
		return 0, false
	}
	best := -1
	bestPrio := 0
	for _, r := range routes {
		if !r.IsDefault() {
			continue
		}
		if best == -1 || r.Priority < bestPrio {
			best, bestPrio = r.LinkIndex, r.Priority
		}
	}
	return best, best != -1
}

// FindLink returns the link with the given name.
func FindLink(s Source, name string) (Link, error) {
	links, err := s.Links()
	if err != nil {
		return Link{}, err
	}
	for _, l := range links {
		if l.Name == name {
			return l, nil
		}
	}
	return Link{}, fmt.Errorf("no interface named %q", name)
}

// ExplainVLANInterface builds the message shown when a user selects an 802.1Q
// sub-interface. Rather than a bare rejection it names the interface and flag
// combination that does what they meant.
func ExplainVLANInterface(s Source, l Link) string {
	parent := fmt.Sprintf("interface %d", l.ParentIndex)
	if links, err := s.Links(); err == nil {
		for _, p := range links {
			if p.Index == l.ParentIndex {
				parent = p.Name
				break
			}
		}
	}
	return fmt.Sprintf("%s is a VLAN sub-interface (VLAN %d on %s). AF_XDP attaches to the "+
		"physical NIC, so use --interface %s --vlan %d instead and Wireblast will emit "+
		"tagged frames itself.", l.Name, l.VLANID, parent, parent, l.VLANID)
}

// VLANLink finds the 802.1Q sub-interface carrying vlanID on top of parent, if
// one exists. Wireblast uses it for routing, neighbour lookups and ARP probes,
// because that is where the kernel keeps the addressing for that VLAN.
func VLANLink(s Source, parent Link, vlanID int) (Link, bool) {
	if vlanID == 0 {
		return parent, true
	}
	links, err := s.Links()
	if err != nil {
		return Link{}, false
	}
	for _, l := range links {
		if l.VLANID == vlanID && l.ParentIndex == parent.Index {
			return l, true
		}
	}
	return Link{}, false
}
