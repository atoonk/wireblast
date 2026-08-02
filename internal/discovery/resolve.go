package discovery

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/atoonk/wireblast/internal/config"
	"github.com/atoonk/wireblast/internal/generator"
)

// generatorAddresses is how many distinct destinations a prefix contributes.
// It defers to the generator so this guard cannot drift from the addresses the
// run would actually send to.
func generatorAddresses(p netip.Prefix) uint64 { return generator.UsableAddresses(p) }

// DefaultProbeTimeout is how long an active ARP probe waits for an answer
// before giving up. Long enough for a switched LAN, short enough that a
// mistyped address does not feel like a hang.
const DefaultProbeTimeout = 1500 * time.Millisecond

// MACSource records how the destination MAC was arrived at, so the review
// screen can say where the number came from rather than presenting it as
// magic.
type MACSource string

const (
	MACFromFlag     MACSource = "given with --dst-mac"
	MACFromNeighbor MACSource = "from the neighbour table"
	MACFromARP      MACSource = "resolved by ARP"
	MACFromND       MACSource = "resolved by neighbour discovery"
	MACFromGateway  MACSource = "gateway's MAC"
	MACPreserved    MACSource = "not needed (the capture's own MACs are preserved)"
	MACNotNeeded    MACSource = "not needed"
)

// Resolved is everything discovery worked out for a run: which interface to
// transmit from, which addresses to put in the packets, and the next-hop MAC.
type Resolved struct {
	// Link is the interface AF_XDP binds to — always a physical NIC.
	Link Link
	// L3Link is where addressing lives. It is the VLAN sub-interface when
	// --vlan names one, and Link otherwise.
	L3Link Link

	SrcMAC net.HardwareAddr
	SrcIP  netip.Addr
	Dst    netip.Prefix

	DstMAC    net.HardwareAddr
	MACSource MACSource
	// NextHop is the address the MAC belongs to: the destination itself when
	// it is on-link, or the gateway when it is not.
	NextHop netip.Addr
	OnLink  bool

	// Notes are informational lines for the review screen.
	Notes []string
}

// NeedsDstMACError is returned when the destination cannot be resolved
// automatically but a user-supplied --dst-mac would work. It carries an
// explanation of why, so the TUI can show the reason instead of a generic
// validation failure.
type NeedsDstMACError struct {
	Reason string
	// Suggestion, when set, is a command the user could run to fix things.
	Suggestion string
}

func (e *NeedsDstMACError) Error() string {
	s := e.Reason + "\nGive an explicit --dst-mac (or fill in Destination MAC in the wizard) to continue."
	if e.Suggestion != "" {
		s += "\n" + e.Suggestion
	}
	return s
}

// Options tunes resolution, mostly for tests.
type Options struct {
	// ProbeTimeout bounds the active ARP probe. Zero uses DefaultProbeTimeout;
	// negative disables probing so only the existing neighbour table is used.
	ProbeTimeout time.Duration
}

// Resolve works out the addressing for a run.
//
// The order of preference is deliberate and never guesses: an explicit
// --dst-mac always wins; otherwise an on-link destination is resolved through
// the neighbour table and then an active ARP probe; an off-link destination is
// resolved through the route the user's own interface would use. If the
// routing table disagrees with the chosen interface, or a destination CIDR
// spans more than one next hop, Resolve stops and explains rather than
// picking something plausible. It never falls back to the broadcast address.
func Resolve(s Source, cfg *config.Config, opts Options) (*Resolved, error) {
	link, err := FindLink(s, cfg.Interface)
	if err != nil {
		return nil, err
	}
	if link.IsVLAN() {
		return nil, errors.New(ExplainVLANInterface(s, link))
	}
	if !Usable(link) {
		return nil, fmt.Errorf("%s cannot be used for AF_XDP: %s", link.Name, unusableReason(link))
	}

	r := &Resolved{Link: link, L3Link: link}

	// Addressing for a tagged run lives on the VLAN sub-interface, not on the
	// physical NIC, so that is where routes and neighbours are looked up.
	if cfg.VLAN != 0 {
		vl, ok := VLANLink(s, link, cfg.VLAN)
		if !ok {
			// Not fatal on its own: with an explicit --dst-mac and --src-ip a
			// user can happily blast into a VLAN this host has no interface on.
			r.Notes = append(r.Notes, fmt.Sprintf(
				"this host has no VLAN %d interface on %s, so addresses and the next-hop MAC "+
					"cannot be looked up for that VLAN", cfg.VLAN, link.Name))
		} else {
			r.L3Link = vl
			r.Notes = append(r.Notes, fmt.Sprintf(
				"VLAN %d addressing taken from %s", cfg.VLAN, vl.Name))
		}
	}

	if err := resolveSrcMAC(r, cfg); err != nil {
		return nil, err
	}
	switch {
	case !cfg.Transmits():
		// Nothing is sent, so there is no next hop to find.
		r.MACSource = MACNotNeeded
	case cfg.UsesIPStack() || cfg.Mode == config.ModeRaw:
		if err := resolveDst(s, r, cfg, opts); err != nil {
			return nil, err
		}
	default:
		if err := resolvePCAPMACs(r, cfg); err != nil {
			return nil, err
		}
	}
	return r, nil
}

func unusableReason(l Link) string {
	switch {
	case !l.Up:
		return "it is administratively down (try `ip link set " + l.Name + " up`)"
	case l.Loopback:
		return "it is the loopback interface"
	case len(l.MAC) != 6:
		return "it has no Ethernet hardware address"
	case l.RxQueues == 0:
		return "it exposes no receive queues"
	}
	return "it is not a suitable device"
}

func resolveSrcMAC(r *Resolved, cfg *config.Config) error {
	if cfg.SrcMAC != "" {
		mac, err := config.ParseMAC(cfg.SrcMAC)
		if err != nil {
			return fmt.Errorf("--src-mac: %w", err)
		}
		r.SrcMAC = mac
		return nil
	}
	r.SrcMAC = r.Link.MAC
	return nil
}

// resolvePCAPMACs handles the replay case, where the capture's own addresses
// are preserved unless the user asked to rewrite them.
func resolvePCAPMACs(r *Resolved, cfg *config.Config) error {
	if cfg.DstMAC == "" {
		r.MACSource = MACPreserved
		return nil
	}
	mac, err := config.ParseMAC(cfg.DstMAC)
	if err != nil {
		return fmt.Errorf("--dst-mac: %w", err)
	}
	r.DstMAC, r.MACSource = mac, MACFromFlag
	return nil
}

// resolveDst fills in the source address, destination prefix and next-hop MAC.
func resolveDst(s Source, r *Resolved, cfg *config.Config, opts Options) error {
	if cfg.Mode == config.ModeRaw {
		// Raw Ethernet has no IP layer, so only the MAC matters.
		if cfg.DstMAC == "" {
			return &NeedsDstMACError{
				Reason: "raw Ethernet frames carry no IP addresses, so there is nothing to " +
					"resolve a next-hop MAC from.",
			}
		}
		mac, err := config.ParseMAC(cfg.DstMAC)
		if err != nil {
			return fmt.Errorf("--dst-mac: %w", err)
		}
		r.DstMAC, r.MACSource = mac, MACFromFlag
		return nil
	}

	dst, err := config.ParseDst(cfg.DstIP)
	if err != nil {
		return fmt.Errorf("--dst-ip: %w", err)
	}
	r.Dst = dst

	if err := resolveSrcIP(r, cfg, dst); err != nil {
		return err
	}

	// An explicit MAC always wins, and skips every lookup below.
	if cfg.DstMAC != "" {
		mac, err := config.ParseMAC(cfg.DstMAC)
		if err != nil {
			return fmt.Errorf("--dst-mac: %w", err)
		}
		r.DstMAC, r.MACSource = mac, MACFromFlag
		return nil
	}
	return resolveNextHop(s, r, dst, opts)
}

// resolveSrcIP picks the address packets are sent from: the user's if given,
// otherwise an address of the L3 interface — preferring one in the same subnet
// as the destination, since that is the one return traffic can come back to.
func resolveSrcIP(r *Resolved, cfg *config.Config, dst netip.Prefix) error {
	if cfg.SrcIP != "" {
		ip, err := config.ParseHostIP(cfg.SrcIP)
		if err != nil {
			return fmt.Errorf("--src-ip: %w", err)
		}
		r.SrcIP = ip
		return nil
	}
	v6 := dst.Addr().Is6()
	addrs := r.L3Link.addrsForFamily(v6)
	if v6 {
		addrs = orderV6Sources(addrs, dst.Addr())
	}
	fam := "IPv4"
	if v6 {
		fam = "IPv6"
	}
	if len(addrs) == 0 {
		return fmt.Errorf("%s has no %s address to send from; set --src-ip explicitly",
			r.L3Link.Name, fam)
	}
	for _, p := range addrs {
		if p.Contains(dst.Addr()) {
			r.SrcIP = p.Addr()
			return nil
		}
	}
	r.SrcIP = addrs[0].Addr()
	if len(addrs) > 1 {
		r.Notes = append(r.Notes, fmt.Sprintf(
			"%s has %d %s addresses; using %s (override with --src-ip)",
			r.L3Link.Name, len(addrs), fam, r.SrcIP))
	}
	return nil
}

// SourceCandidates lists the addresses a user may pick as the source for a run,
// in the order the wizard should offer them: matching the destination's family
// and scope, and on the same subnet, first.
func SourceCandidates(l Link, dst netip.Prefix) []netip.Addr {
	addrs := l.addrsForFamily(dst.Addr().Is6())
	if dst.Addr().Is6() {
		addrs = orderV6Sources(addrs, dst.Addr())
	}
	var onSubnet, rest []netip.Addr
	for _, p := range addrs {
		if dst.IsValid() && p.Contains(dst.Addr()) {
			onSubnet = append(onSubnet, p.Addr())
		} else {
			rest = append(rest, p.Addr())
		}
	}
	return append(onSubnet, rest...)
}

// resolveNextHop is the decision tree for finding a destination MAC.
func resolveNextHop(s Source, r *Resolved, dst netip.Prefix, opts Options) error {
	single := dst.Bits() == dst.Addr().BitLen() // /32 for IPv4, /128 for IPv6

	// Is the destination directly connected on the interface we are using?
	for _, p := range r.L3Link.addrsForFamily(dst.Addr().Is6()) {
		if !p.Overlaps(dst) {
			continue
		}
		if !single && p.Contains(dst.Addr()) && dst.Bits() < p.Bits() {
			break // the destination is wider than the local subnet; route it
		}
		if single {
			r.OnLink, r.NextHop = true, dst.Addr()
			return lookupMAC(s, r, dst.Addr(), MACFromNeighbor, opts)
		}
		// A connected CIDR with more than one destination: each address can
		// have a different MAC, and Wireblast will not guess or broadcast.
		if generatorAddresses(dst) > 1 {
			return &NeedsDstMACError{
				Reason: fmt.Sprintf(
					"%s is directly connected to %s, and a run across %d destinations in it "+
						"would need a different MAC address for each one. Wireblast resolves one "+
						"next hop per run, so it cannot do that automatically.",
					dst, r.L3Link.Name, generatorAddresses(dst)),
				Suggestion: "Either target a single address (for example --dst-ip " +
					firstUsable(dst).String() + "), or point the run at a router and give its MAC.",
			}
		}
		r.OnLink, r.NextHop = true, firstUsable(dst)
		return lookupMAC(s, r, r.NextHop, MACFromNeighbor, opts)
	}

	// Not on-link: consult the routing table.
	routes, err := s.Routes()
	if err != nil {
		return fmt.Errorf("read the routing table: %w", err)
	}
	if !single {
		if split := splittingRoute(routes, dst); split != nil {
			return &NeedsDstMACError{
				Reason: fmt.Sprintf(
					"the destination %s is not covered by a single next hop: the routing table "+
						"has a more specific route for %s, so different destinations in the range "+
						"would leave through different next hops.", dst, split.Dst),
			}
		}
	}

	route, ok := bestRoute(routes, dst.Addr())
	if !ok {
		return fmt.Errorf("no route to %s; check the destination, or give --dst-mac to send anyway",
			dst.Addr())
	}
	if route.LinkIndex != r.L3Link.Index {
		return routeConflict(s, r, dst, route)
	}
	if !route.Gateway.IsValid() {
		// An on-link route through our own interface for a prefix we have no
		// address in — unusual, but it means the destination is directly
		// reachable, so resolve it the same way.
		if !single && generatorAddresses(dst) > 1 {
			return &NeedsDstMACError{
				Reason: fmt.Sprintf("%s is routed on-link via %s with no gateway, so every "+
					"destination in the range would have its own MAC address.", dst, r.L3Link.Name),
			}
		}
		r.OnLink, r.NextHop = true, firstUsable(dst)
		return lookupMAC(s, r, r.NextHop, MACFromNeighbor, opts)
	}

	r.OnLink, r.NextHop = false, route.Gateway
	r.Notes = append(r.Notes, fmt.Sprintf("%s is reached via the gateway %s on %s",
		dst, route.Gateway, r.L3Link.Name))
	return lookupMAC(s, r, route.Gateway, MACFromGateway, opts)
}

// routeConflict builds the message for a destination whose route leaves
// through an interface other than the one the user chose. Silently switching
// interfaces would send traffic somewhere the user did not ask for, so this is
// always an error.
func routeConflict(s Source, r *Resolved, dst netip.Prefix, route Route) error {
	via := fmt.Sprintf("interface index %d", route.LinkIndex)
	if links, err := s.Links(); err == nil {
		for _, l := range links {
			if l.Index == route.LinkIndex {
				via = l.Name
				break
			}
		}
	}
	chosen := r.Link.Name
	if r.L3Link.Index != r.Link.Index {
		chosen = fmt.Sprintf("%s (VLAN %d, %s)", r.Link.Name, r.L3Link.VLANID, r.L3Link.Name)
	}
	return &NeedsDstMACError{
		Reason: fmt.Sprintf(
			"the route to %s leaves through %s, but the run is configured to transmit from %s. "+
				"Wireblast will not quietly send from a different interface than you chose.",
			dst, via, chosen),
		Suggestion: fmt.Sprintf(
			"Either transmit from that interface (--interface %s), or keep %s and give the "+
				"next-hop MAC on it with --dst-mac.", via, r.Link.Name),
	}
}

// lookupMAC finds the MAC for one address: the neighbour table first, then an
// active probe, then the neighbour table again.
func lookupMAC(s Source, r *Resolved, target netip.Addr, src MACSource, opts Options) error {
	if mac, ok := neighborMAC(s, r.L3Link.Index, target); ok {
		r.DstMAC, r.MACSource = mac, src
		return nil
	}

	timeout := opts.ProbeTimeout
	if timeout == 0 {
		timeout = DefaultProbeTimeout
	}
	if timeout > 0 {
		_ = s.Probe(r.L3Link, target, timeout)
		if mac, ok := neighborMAC(s, r.L3Link.Index, target); ok {
			if src == MACFromNeighbor {
				src = MACFromARP
				if target.Is6() {
					src = MACFromND
				}
			}
			r.DstMAC, r.MACSource = mac, src
			return nil
		}
	}

	what := "destination"
	if src == MACFromGateway {
		what = "gateway"
	}
	resolution := "ARP"
	if target.Is6() {
		resolution = "neighbour discovery"
	}
	return &NeedsDstMACError{
		Reason: fmt.Sprintf("the %s %s did not answer %s on %s, so its MAC address is unknown.",
			what, target, resolution, r.L3Link.Name),
		Suggestion: fmt.Sprintf("Check it is reachable (`ping -c1 %s`), then try again, or give "+
			"--dst-mac directly.", target),
	}
}

func neighborMAC(s Source, linkIndex int, target netip.Addr) (net.HardwareAddr, bool) {
	neighs, err := s.Neighbors(linkIndex)
	if err != nil {
		return nil, false
	}
	for _, n := range neighs {
		if n.IP == target && n.Reachable && len(n.MAC) == 6 && !isZeroMAC(n.MAC) {
			return n.MAC, true
		}
	}
	return nil, false
}

func isZeroMAC(m net.HardwareAddr) bool {
	for _, b := range m {
		if b != 0 {
			return false
		}
	}
	return true
}

// bestRoute picks the route for an address: longest prefix wins, then the
// lowest metric.
func bestRoute(routes []Route, dst netip.Addr) (Route, bool) {
	var best Route
	found := false
	for _, r := range routes {
		if !r.Contains(dst) {
			continue
		}
		switch {
		case !found,
			r.Bits() > best.Bits(),
			r.Bits() == best.Bits() && r.Priority < best.Priority:
			best, found = r, true
		}
	}
	return best, found
}

// splittingRoute reports a route more specific than the destination prefix but
// overlapping it, which means different addresses in the range would take
// different next hops.
func splittingRoute(routes []Route, dst netip.Prefix) *Route {
	for i := range routes {
		r := routes[i]
		if r.IsDefault() || !r.Dst.IsValid() {
			continue // Overlaps below is family-aware, so no need to filter here
		}
		if r.Dst.Bits() > dst.Bits() && dst.Overlaps(r.Dst) {
			return &routes[i]
		}
	}
	return nil
}

// firstUsable is the first address the generator would send to in a prefix.
// IPv4 skips the network address for /30 and shorter; IPv6 has no reserved
// network address, so the masked base is usable.
func firstUsable(p netip.Prefix) netip.Addr {
	p = p.Masked()
	if p.Addr().Is6() || p.Bits() >= 31 {
		return p.Addr()
	}
	return p.Addr().Next()
}
