package discovery

import (
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

// fakeSource is a scripted [Source]. It models the real test bench: a
// management NIC owning the default route, a second NIC used for traffic, and
// an 802.1Q sub-interface on top of that second NIC.
type fakeSource struct {
	links  []Link
	routes []Route
	neighs map[int][]Neighbor

	// probes records every Probe call, so tests can assert that a lookup that
	// should have hit the neighbour table did not go to the wire.
	probes []probe
	// onProbe simulates the result: return a Neighbor to have it appear in the
	// table afterwards, as a real ARP exchange would.
	onProbe   func(l Link, dst netip.Addr) (Neighbor, bool)
	linksErr  error
	routesErr error
}

type probe struct {
	link string
	dst  netip.Addr
}

func mac(s string) net.HardwareAddr {
	m, err := net.ParseMAC(s)
	if err != nil {
		panic(err)
	}
	return m
}

func pfx(s string) netip.Prefix { return netip.MustParsePrefix(s) }
func addr(s string) netip.Addr  { return netip.MustParseAddr(s) }

// bench builds the standard topology used by most tests:
//
//	lo        1  loopback
//	eno1      2  206.223.228.203/31, owns the default route via .202
//	eno2      3  no addresses — the traffic NIC
//	vlan.2131 7  VLAN 2131 on eno2, 192.168.0.2/24 and 10.2.0.2/16
//	down0     4  administratively down
//	novq      5  up, but no receive queues
func bench() *fakeSource {
	return &fakeSource{
		links: []Link{
			{Name: "lo", Index: 1, MTU: 65536, Up: true, Carrier: true, Loopback: true, RxQueues: 1},
			{
				Name: "eno1", Index: 2, MAC: mac("aa:bb:cc:00:00:01"), MTU: 1500,
				Up: true, Carrier: true, Driver: "ixgbe", RxQueues: 12,
				Addrs: []netip.Prefix{pfx("206.223.228.203/31")},
			},
			{
				Name: "eno2", Index: 3, MAC: mac("aa:bb:cc:00:00:02"), MTU: 1500,
				Up: true, Carrier: true, Driver: "ixgbe", RxQueues: 12,
			},
			{Name: "down0", Index: 4, MAC: mac("aa:bb:cc:00:00:04"), Up: false, RxQueues: 4},
			{Name: "novq", Index: 5, MAC: mac("aa:bb:cc:00:00:05"), Up: true, Carrier: true, RxQueues: 0},
			{
				Name: "vlan.2131", Index: 7, MAC: mac("aa:bb:cc:00:00:02"), MTU: 1500,
				Up: true, Carrier: true, VLANID: 2131, ParentIndex: 3, RxQueues: 1,
				Addrs: []netip.Prefix{pfx("192.168.0.2/24"), pfx("10.2.0.2/16")},
			},
		},
		routes: []Route{
			{Dst: pfx("0.0.0.0/0"), Gateway: addr("206.223.228.202"), LinkIndex: 2},
			{Dst: pfx("206.223.228.202/31"), LinkIndex: 2},
			{Dst: pfx("192.168.0.0/24"), LinkIndex: 7},
			{Dst: pfx("10.2.0.0/16"), LinkIndex: 7},
			{Dst: pfx("10.3.0.0/16"), Gateway: addr("10.2.0.1"), LinkIndex: 7},
			{Dst: pfx("172.16.0.0/16"), Gateway: addr("206.223.228.202"), LinkIndex: 2},
		},
		neighs: map[int][]Neighbor{
			2: {{IP: addr("206.223.228.202"), MAC: mac("de:ad:be:ef:00:01"), LinkIndex: 2, Reachable: true}},
			7: {
				{IP: addr("192.168.0.3"), MAC: mac("de:ad:be:ef:00:03"), LinkIndex: 7, Reachable: true},
				{IP: addr("10.2.0.1"), MAC: mac("de:ad:be:ef:00:0a"), LinkIndex: 7, Reachable: true},
				// An incomplete entry must be ignored, not used as an answer.
				{IP: addr("192.168.0.9"), MAC: mac("00:00:00:00:00:00"), LinkIndex: 7, Reachable: false},
			},
		},
	}
}

func (f *fakeSource) Links() ([]Link, error) {
	if f.linksErr != nil {
		return nil, f.linksErr
	}
	return f.links, nil
}

func (f *fakeSource) Routes() ([]Route, error) {
	if f.routesErr != nil {
		return nil, f.routesErr
	}
	return f.routes, nil
}

func (f *fakeSource) Neighbors(idx int) ([]Neighbor, error) { return f.neighs[idx], nil }

func (f *fakeSource) Probe(l Link, dst netip.Addr, _ time.Duration) error {
	f.probes = append(f.probes, probe{l.Name, dst})
	if f.onProbe == nil {
		return errors.New("no answer")
	}
	n, ok := f.onProbe(l, dst)
	if !ok {
		return errors.New("no answer")
	}
	f.neighs[l.Index] = append(f.neighs[l.Index], n)
	return nil
}

// answersARP makes the fake resolve any probed address to a derived MAC.
func (f *fakeSource) answersARP() {
	f.onProbe = func(l Link, dst netip.Addr) (Neighbor, bool) {
		b := dst.As4()
		return Neighbor{
			IP:        dst,
			MAC:       net.HardwareAddr{0x02, 0, b[0], b[1], b[2], b[3]},
			LinkIndex: l.Index,
			Reachable: true,
		}, true
	}
}

func (f *fakeSource) probedFor(t *testing.T, dst string) bool {
	t.Helper()
	for _, p := range f.probes {
		if p.dst == addr(dst) {
			return true
		}
	}
	return false
}
