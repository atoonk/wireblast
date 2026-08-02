package discovery

import (
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/atoonk/wireblast/internal/config"
)

// base returns a config for a plain UDP run on eno2.
func base(mut func(*config.Config)) *config.Config {
	c := config.Default()
	c.Interface = "eno2"
	c.DstIP = "192.168.0.3"
	c.VLAN = 2131
	if mut != nil {
		mut(&c)
	}
	return &c
}

func TestInterfaceListing(t *testing.T) {
	s := bench()
	// A pile of virtual devices, as a real host accumulates. They are usable,
	// but must never outrank a physical NIC in the list.
	s.links = append(s.links,
		Link{Name: "docker0", Index: 20, MAC: mac("aa:00:00:00:00:20"), Up: true, Carrier: true,
			RxQueues: 1, Addrs: []netip.Prefix{pfx("172.17.0.1/16")}},
		Link{Name: "aveth0", Index: 21, MAC: mac("aa:00:00:00:00:21"), Up: true, Carrier: true, RxQueues: 1},
	)

	got, err := Interfaces(s)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, l := range got {
		names = append(names, l.Name)
	}
	// The two ixgbe NICs first (eno1 ahead of eno2 because it has an address),
	// then the virtual devices. lo, down0, novq and the VLAN sub-interface are
	// filtered out entirely.
	want := []string{"eno1", "eno2", "docker0", "aveth0"}
	if len(names) != len(want) {
		t.Fatalf("interfaces = %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("interfaces = %v, want %v", names, want)
		}
	}
}

func TestUsable(t *testing.T) {
	tests := []struct {
		name string
		link Link
		want bool
	}{
		{"good", Link{Up: true, MAC: mac("aa:bb:cc:dd:ee:ff"), RxQueues: 4}, true},
		{"down", Link{Up: false, MAC: mac("aa:bb:cc:dd:ee:ff"), RxQueues: 4}, false},
		{"loopback", Link{Up: true, Loopback: true, MAC: mac("aa:bb:cc:dd:ee:ff"), RxQueues: 4}, false},
		{"no mac", Link{Up: true, RxQueues: 4}, false},
		{"no queues", Link{Up: true, MAC: mac("aa:bb:cc:dd:ee:ff")}, false},
		{"vlan", Link{Up: true, MAC: mac("aa:bb:cc:dd:ee:ff"), RxQueues: 1, VLANID: 10}, false},
		// An interface with no carrier is still offered: the user may be about
		// to plug the cable in, and native XDP bounces the link anyway.
		{"no carrier", Link{Up: true, MAC: mac("aa:bb:cc:dd:ee:ff"), RxQueues: 4}, true},
	}
	for _, tt := range tests {
		if got := Usable(tt.link); got != tt.want {
			t.Errorf("%s: Usable = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestDefaultRouteLink(t *testing.T) {
	idx, ok := DefaultRouteLink(bench())
	if !ok || idx != 2 {
		t.Errorf("DefaultRouteLink = %d, %v; want 2, true (eno1)", idx, ok)
	}
	empty := &fakeSource{}
	if _, ok := DefaultRouteLink(empty); ok {
		t.Error("a table with no default route should report none")
	}
}

// An explicit --dst-mac must win outright, without any lookup at all.
func TestExplicitDstMACWinsAndSkipsLookups(t *testing.T) {
	s := bench()
	cfg := base(func(c *config.Config) {
		c.DstIP = "203.0.113.99" // unroutable from eno2
		c.DstMAC = "12:34:56:78:9a:bc"
		c.SrcIP = "192.168.0.99"
	})
	r, err := Resolve(s, cfg, Options{})
	if err != nil {
		t.Fatalf("an explicit --dst-mac should always work: %v", err)
	}
	if r.DstMAC.String() != "12:34:56:78:9a:bc" {
		t.Errorf("DstMAC = %v, want the flag's value", r.DstMAC)
	}
	if r.MACSource != MACFromFlag {
		t.Errorf("MACSource = %q, want %q", r.MACSource, MACFromFlag)
	}
	if len(s.probes) != 0 {
		t.Errorf("an explicit MAC must not trigger ARP probes, got %v", s.probes)
	}
}

// The common case: a single on-link destination already in the ARP table.
func TestOnLinkFromNeighborTable(t *testing.T) {
	s := bench()
	r, err := Resolve(s, base(nil), Options{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if r.DstMAC.String() != "de:ad:be:ef:00:03" {
		t.Errorf("DstMAC = %v, want de:ad:be:ef:00:03", r.DstMAC)
	}
	if r.MACSource != MACFromNeighbor {
		t.Errorf("MACSource = %q, want %q", r.MACSource, MACFromNeighbor)
	}
	if !r.OnLink || r.NextHop != addr("192.168.0.3") {
		t.Errorf("next hop = %v (on-link %v), want 192.168.0.3 on-link", r.NextHop, r.OnLink)
	}
	if len(s.probes) != 0 {
		t.Errorf("a cached neighbour should not need an ARP probe, got %v", s.probes)
	}
	// Source addressing comes from the VLAN interface, and prefers the subnet
	// the destination is in.
	if r.SrcIP != addr("192.168.0.2") {
		t.Errorf("SrcIP = %v, want 192.168.0.2 (the address on the destination's subnet)", r.SrcIP)
	}
	if r.SrcMAC.String() != "aa:bb:cc:00:00:02" {
		t.Errorf("SrcMAC = %v, want eno2's address", r.SrcMAC)
	}
	if r.Link.Name != "eno2" || r.L3Link.Name != "vlan.2131" {
		t.Errorf("bound to %s with L3 on %s, want eno2 / vlan.2131", r.Link.Name, r.L3Link.Name)
	}
}

// Not in the table yet: Wireblast must actively provoke ARP rather than give up.
func TestOnLinkResolvesByActiveARP(t *testing.T) {
	s := bench()
	s.answersARP()
	cfg := base(func(c *config.Config) { c.DstIP = "192.168.0.50" })

	r, err := Resolve(s, cfg, Options{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !s.probedFor(t, "192.168.0.50") {
		t.Error("an unknown on-link destination should have been probed")
	}
	if r.MACSource != MACFromARP {
		t.Errorf("MACSource = %q, want %q", r.MACSource, MACFromARP)
	}
	if r.DstMAC.String() != "02:00:c0:a8:00:32" {
		t.Errorf("DstMAC = %v, want the probed answer", r.DstMAC)
	}
	// The probe must leave through the VLAN interface, not the raw NIC.
	if s.probes[0].link != "vlan.2131" {
		t.Errorf("probed on %s, want vlan.2131", s.probes[0].link)
	}
}

func TestOnLinkARPFailureExplains(t *testing.T) {
	s := bench()
	cfg := base(func(c *config.Config) { c.DstIP = "192.168.0.77" })

	_, err := Resolve(s, cfg, Options{})
	if err == nil {
		t.Fatal("a destination that does not answer ARP should fail")
	}
	var need *NeedsDstMACError
	if !errors.As(err, &need) {
		t.Fatalf("error = %T, want *NeedsDstMACError", err)
	}
	for _, want := range []string{"192.168.0.77", "ARP", "--dst-mac", "ping"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q:\n%s", want, err)
		}
	}
}

// An entry the kernel has not completed is not an answer.
func TestIncompleteNeighborIsNotUsed(t *testing.T) {
	s := bench()
	cfg := base(func(c *config.Config) { c.DstIP = "192.168.0.9" })
	if _, err := Resolve(s, cfg, Options{}); err == nil {
		t.Fatal("an incomplete neighbour entry must not be accepted as a MAC")
	}
	if !s.probedFor(t, "192.168.0.9") {
		t.Error("an incomplete entry should still trigger a probe")
	}
}

func TestOffLinkUsesGateway(t *testing.T) {
	s := bench()
	cfg := base(func(c *config.Config) { c.DstIP = "10.3.0.5" })

	r, err := Resolve(s, cfg, Options{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if r.OnLink {
		t.Error("10.3.0.5 is off-link")
	}
	if r.NextHop != addr("10.2.0.1") {
		t.Errorf("next hop = %v, want the gateway 10.2.0.1", r.NextHop)
	}
	if r.DstMAC.String() != "de:ad:be:ef:00:0a" {
		t.Errorf("DstMAC = %v, want the gateway's MAC", r.DstMAC)
	}
	if r.MACSource != MACFromGateway {
		t.Errorf("MACSource = %q, want %q", r.MACSource, MACFromGateway)
	}
	if !strings.Contains(strings.Join(r.Notes, "\n"), "gateway 10.2.0.1") {
		t.Errorf("the review notes should name the gateway: %v", r.Notes)
	}
	// The source address should come from the VLAN interface's other subnet.
	if r.SrcIP != addr("192.168.0.2") && r.SrcIP != addr("10.2.0.2") {
		t.Errorf("SrcIP = %v, want an address of vlan.2131", r.SrcIP)
	}
}

// The route says one interface, the user says another: never resolve silently
// through somebody else's interface.
func TestRouteOnAnotherInterfaceIsRefused(t *testing.T) {
	s := bench()
	// 172.16.0.0/16 routes via eno1, but the run is pinned to eno2.
	cfg := base(func(c *config.Config) {
		c.DstIP = "172.16.5.5"
		c.SrcIP = "192.168.0.99"
	})

	_, err := Resolve(s, cfg, Options{})
	if err == nil {
		t.Fatal("a route through another interface must not be used silently")
	}
	for _, want := range []string{"eno1", "eno2", "--dst-mac", "--interface eno1"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the conflict should be explained with %q:\n%s", want, err)
		}
	}
	if len(s.probes) != 0 {
		t.Error("a conflicting route should be reported, not probed")
	}
}

// A directly connected CIDR needs one MAC per destination, which cannot be
// resolved to a single next hop. Say so specifically.
func TestConnectedCIDRRequiresExplicitMAC(t *testing.T) {
	s := bench()
	cfg := base(func(c *config.Config) { c.DstIP = "192.168.0.0/24" })

	_, err := Resolve(s, cfg, Options{})
	if err == nil {
		t.Fatal("a connected CIDR with many hosts should require --dst-mac")
	}
	var need *NeedsDstMACError
	if !errors.As(err, &need) {
		t.Fatalf("error = %T, want *NeedsDstMACError", err)
	}
	for _, want := range []string{"directly connected", "254", "--dst-mac", "192.168.0.1"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the explanation should mention %q:\n%s", want, err)
		}
	}

	// ...and supplying one makes it work.
	cfg.DstMAC = "de:ad:be:ef:00:03"
	r, err := Resolve(s, cfg, Options{})
	if err != nil {
		t.Fatalf("an explicit MAC should resolve a connected CIDR: %v", err)
	}
	if r.Dst != pfx("192.168.0.0/24") {
		t.Errorf("Dst = %v, want 192.168.0.0/24", r.Dst)
	}
}

// A /32 written as a CIDR is still a single destination.
func TestSlash32IsASingleDestination(t *testing.T) {
	s := bench()
	cfg := base(func(c *config.Config) { c.DstIP = "192.168.0.3/32" })
	r, err := Resolve(s, cfg, Options{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if r.DstMAC.String() != "de:ad:be:ef:00:03" {
		t.Errorf("DstMAC = %v, want the on-link neighbour's MAC", r.DstMAC)
	}
}

// A /31 has two usable addresses, so it needs an explicit MAC like any other
// multi-destination connected range.
func TestConnectedSlash31RequiresExplicitMAC(t *testing.T) {
	s := bench()
	cfg := base(func(c *config.Config) { c.DstIP = "192.168.0.4/31" })
	if _, err := Resolve(s, cfg, Options{}); err == nil {
		t.Fatal("a /31 spans two destinations, so it should require --dst-mac")
	}
}

// An off-link CIDR that all goes through one gateway resolves fine.
func TestOffLinkCIDRUsesTheSharedGateway(t *testing.T) {
	s := bench()
	cfg := base(func(c *config.Config) { c.DstIP = "10.3.5.0/24" })

	r, err := Resolve(s, cfg, Options{})
	if err != nil {
		t.Fatalf("a CIDR behind one gateway should resolve: %v", err)
	}
	if r.NextHop != addr("10.2.0.1") || r.MACSource != MACFromGateway {
		t.Errorf("next hop = %v (%s), want the gateway 10.2.0.1", r.NextHop, r.MACSource)
	}
}

// ...but if a more specific route splits the range, different destinations
// would take different next hops, and Wireblast must not pick one.
func TestCIDRSplitByMoreSpecificRouteIsRefused(t *testing.T) {
	s := bench()
	s.routes = append(s.routes, Route{
		Dst: pfx("10.3.0.0/24"), Gateway: addr("192.168.0.3"), LinkIndex: 7,
	})
	cfg := base(func(c *config.Config) { c.DstIP = "10.3.0.0/16" })

	_, err := Resolve(s, cfg, Options{})
	if err == nil {
		t.Fatal("a CIDR spanning two next hops should be refused")
	}
	for _, want := range []string{"single next hop", "10.3.0.0/24"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the explanation should mention %q:\n%s", want, err)
		}
	}
}

func TestNoRouteAtAll(t *testing.T) {
	s := bench()
	s.routes = []Route{{Dst: pfx("192.168.0.0/24"), LinkIndex: 7}}
	cfg := base(func(c *config.Config) {
		c.DstIP = "198.51.100.7"
		c.SrcIP = "192.168.0.99"
	})
	_, err := Resolve(s, cfg, Options{})
	if err == nil || !strings.Contains(err.Error(), "no route") {
		t.Fatalf("error = %v, want a 'no route' message", err)
	}
}

// Selecting a VLAN sub-interface should teach the user the right invocation,
// not just refuse.
func TestSelectingAVLANInterfaceExplains(t *testing.T) {
	s := bench()
	cfg := base(func(c *config.Config) { c.Interface = "vlan.2131" })
	_, err := Resolve(s, cfg, Options{})
	if err == nil {
		t.Fatal("binding to a VLAN sub-interface should be refused")
	}
	for _, want := range []string{"--interface eno2", "--vlan 2131", "physical NIC"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the message should mention %q:\n%s", want, err)
		}
	}
}

// Tagging a VLAN this host has no interface for is allowed — that is exactly
// the "blast into a VLAN we are not a member of" case — but only with the
// addressing spelled out.
func TestVLANWithNoLocalInterface(t *testing.T) {
	s := bench()
	cfg := base(func(c *config.Config) {
		c.VLAN = 4000
		c.DstIP = "192.168.9.9"
		c.SrcIP = "192.168.9.1"
		c.DstMAC = "aa:aa:aa:aa:aa:aa"
	})
	r, err := Resolve(s, cfg, Options{})
	if err != nil {
		t.Fatalf("with --src-ip and --dst-mac this should work: %v", err)
	}
	if !strings.Contains(strings.Join(r.Notes, "\n"), "no VLAN 4000 interface") {
		t.Errorf("the notes should say the VLAN is not configured locally: %v", r.Notes)
	}
	if r.L3Link.Name != "eno2" {
		t.Errorf("L3Link = %s, want the parent when there is no sub-interface", r.L3Link.Name)
	}

	// Without a source address there is nothing sensible to pick.
	cfg.SrcIP = ""
	if _, err := Resolve(s, cfg, Options{}); err == nil {
		t.Fatal("an unconfigured VLAN with no --src-ip should fail")
	} else if !strings.Contains(err.Error(), "--src-ip") {
		t.Errorf("error should point at --src-ip: %v", err)
	}
}

func TestSourceIPSelection(t *testing.T) {
	s := bench()
	s.answersARP() // this test is about the source address, not the next hop

	// An explicit --src-ip is used verbatim, even off-subnet.
	cfg := base(func(c *config.Config) { c.SrcIP = "203.0.113.7" })
	r, err := Resolve(s, cfg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if r.SrcIP != addr("203.0.113.7") {
		t.Errorf("SrcIP = %v, want the explicit 203.0.113.7", r.SrcIP)
	}

	// Otherwise prefer the address on the destination's subnet...
	cfg = base(func(c *config.Config) { c.DstIP = "10.2.9.9" })
	r, err = Resolve(s, cfg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if r.SrcIP != addr("10.2.0.2") {
		t.Errorf("SrcIP = %v, want 10.2.0.2 (same subnet as the destination)", r.SrcIP)
	}

	// ...and mention that there was a choice.
	cfg = base(func(c *config.Config) {
		c.DstIP = "10.3.0.5"
		c.VLAN = 2131
	})
	r, err = Resolve(s, cfg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Notes) == 0 {
		t.Error("with several candidate source addresses the choice should be noted")
	}
}

func TestSourceCandidates(t *testing.T) {
	l := bench().links[5] // vlan.2131
	got := SourceCandidates(l, pfx("10.2.9.0/24"))
	if len(got) != 2 {
		t.Fatalf("candidates = %v, want 2", got)
	}
	if got[0] != addr("10.2.0.2") {
		t.Errorf("first candidate = %v, want the on-subnet 10.2.0.2", got[0])
	}
}

func TestUnusableInterfaceIsExplained(t *testing.T) {
	s := bench()
	for _, tt := range []struct{ iface, want string }{
		{"down0", "administratively down"},
		{"novq", "no receive queues"},
		{"lo", "loopback"},
		{"nope0", "no interface named"},
	} {
		cfg := base(func(c *config.Config) { c.Interface = tt.iface })
		_, err := Resolve(s, cfg, Options{})
		if err == nil {
			t.Errorf("%s should be refused", tt.iface)
			continue
		}
		if !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: error %q should mention %q", tt.iface, err, tt.want)
		}
	}
}

// However resolution goes, the answer is never the broadcast address.
func TestNeverResolvesToBroadcast(t *testing.T) {
	s := bench()
	s.answersARP()
	for _, dst := range []string{"192.168.0.3", "192.168.0.50", "10.3.0.5", "10.2.0.7"} {
		cfg := base(func(c *config.Config) { c.DstIP = dst })
		r, err := Resolve(s, cfg, Options{})
		if err != nil {
			continue
		}
		if r.DstMAC.String() == "ff:ff:ff:ff:ff:ff" {
			t.Errorf("%s resolved to the broadcast MAC", dst)
		}
	}
}

func TestPCAPModePreservesCapturedMACs(t *testing.T) {
	s := bench()
	cfg := base(func(c *config.Config) {
		c.Mode = config.ModePCAP
		c.PCAPFile = "x.pcap"
		c.DstIP = ""
	})
	r, err := Resolve(s, cfg, Options{})
	if err != nil {
		t.Fatalf("pcap replay needs no addressing: %v", err)
	}
	if r.DstMAC != nil || r.MACSource != MACPreserved {
		t.Errorf("DstMAC = %v (%s), want none for a plain replay", r.DstMAC, r.MACSource)
	}

	cfg.DstMAC = "11:22:33:44:55:66"
	r, err = Resolve(s, cfg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if r.DstMAC.String() != "11:22:33:44:55:66" || r.MACSource != MACFromFlag {
		t.Errorf("the MAC override was not applied: %v (%s)", r.DstMAC, r.MACSource)
	}
}

func TestRawModeNeedsAnExplicitMAC(t *testing.T) {
	s := bench()
	cfg := base(func(c *config.Config) {
		c.Mode = config.ModeRaw
		c.DstIP = ""
	})
	_, err := Resolve(s, cfg, Options{})
	if err == nil || !strings.Contains(err.Error(), "no IP addresses") {
		t.Fatalf("error = %v, want an explanation that raw frames carry no IP", err)
	}

	cfg.DstMAC = "11:22:33:44:55:66"
	if _, err := Resolve(s, cfg, Options{}); err != nil {
		t.Fatalf("raw mode with an explicit MAC should work: %v", err)
	}
}

func TestProbingCanBeDisabled(t *testing.T) {
	s := bench()
	s.answersARP()
	cfg := base(func(c *config.Config) { c.DstIP = "192.168.0.50" })
	if _, err := Resolve(s, cfg, Options{ProbeTimeout: -1}); err == nil {
		t.Fatal("with probing disabled an unknown destination should fail")
	}
	if len(s.probes) != 0 {
		t.Errorf("probing was disabled but %d probes were sent", len(s.probes))
	}
}

func TestBadAddressesAreRejected(t *testing.T) {
	s := bench()
	tests := []struct {
		name, want string
		mut        func(*config.Config)
	}{
		{"src mac", "--src-mac", func(c *config.Config) { c.SrcMAC = "zz" }},
		{"dst mac", "--dst-mac", func(c *config.Config) { c.DstMAC = "zz" }},
		{"dst ip", "--dst-ip", func(c *config.Config) { c.DstIP = "not-an-ip" }},
		{"src ip", "--src-ip", func(c *config.Config) { c.SrcIP = "999.1.1.1" }},
	}
	for _, tt := range tests {
		_, err := Resolve(s, base(tt.mut), Options{})
		if err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: error = %v, want a message naming %s", tt.name, err, tt.want)
		}
	}
}

func TestBestRoute(t *testing.T) {
	routes := []Route{
		{Dst: pfx("0.0.0.0/0"), Gateway: addr("10.0.0.1"), LinkIndex: 1, Priority: 100},
		{Dst: pfx("10.0.0.0/8"), Gateway: addr("10.0.0.2"), LinkIndex: 2},
		{Dst: pfx("10.1.0.0/16"), Gateway: addr("10.0.0.3"), LinkIndex: 3},
		{Dst: pfx("0.0.0.0/0"), Gateway: addr("10.0.0.9"), LinkIndex: 9, Priority: 50},
	}
	tests := []struct {
		dst  string
		want int // expected LinkIndex
	}{
		{"10.1.2.3", 3}, // longest prefix wins
		{"10.9.9.9", 2}, //
		{"8.8.8.8", 9},  // among equal-length defaults, lowest metric wins
		{"10.1.0.0", 3}, //
	}
	for _, tt := range tests {
		got, ok := bestRoute(routes, addr(tt.dst))
		if !ok {
			t.Errorf("no route for %s", tt.dst)
			continue
		}
		if got.LinkIndex != tt.want {
			t.Errorf("bestRoute(%s) = link %d, want %d", tt.dst, got.LinkIndex, tt.want)
		}
	}
	if _, ok := bestRoute(nil, addr("1.2.3.4")); ok {
		t.Error("an empty table should have no route")
	}
}

func TestFirstUsable(t *testing.T) {
	tests := []struct{ cidr, want string }{
		{"192.0.2.0/24", "192.0.2.1"},
		{"10.0.0.0/30", "10.0.0.1"},
		{"10.0.0.0/31", "10.0.0.0"},
		{"10.0.0.7/32", "10.0.0.7"},
	}
	for _, tt := range tests {
		if got := firstUsable(pfx(tt.cidr)); got != netip.MustParseAddr(tt.want) {
			t.Errorf("firstUsable(%s) = %v, want %v", tt.cidr, got, tt.want)
		}
	}
}

func TestSourceErrorsPropagate(t *testing.T) {
	s := bench()
	s.linksErr = errors.New("netlink is unhappy")
	if _, err := Resolve(s, base(nil), Options{}); err == nil {
		t.Error("a failure listing interfaces should be reported")
	}

	s = bench()
	s.routesErr = errors.New("no routes for you")
	cfg := base(func(c *config.Config) { c.DstIP = "10.3.0.5" })
	if _, err := Resolve(s, cfg, Options{}); err == nil {
		t.Error("a failure listing routes should be reported")
	}
}
