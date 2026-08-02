package generator

import (
	"net/netip"
	"testing"

	"github.com/atoonk/wireblast/internal/packet"
	"github.com/atoonk/wireblast/internal/stats"
)

// IPv6 has no network/broadcast reservation, so a prefix contributes every
// address, cycling in order and repeating after the prefix is exhausted.
func TestIPv6FlowCyclingIsDistinctAndInPrefix(t *testing.T) {
	p := netip.MustParsePrefix("2001:db8::/120") // 256 addresses
	seen := map[netip.Addr]int{}
	for n := range 256 {
		a := nthAddr(p, n)
		if !p.Contains(a) {
			t.Fatalf("nthAddr(%d) = %s is outside the prefix", n, a)
		}
		seen[a]++
	}
	if len(seen) != 256 {
		t.Fatalf("a /120 produced %d distinct addresses, want 256", len(seen))
	}
	// The first address of the prefix is usable in IPv6 (no network address).
	if _, ok := seen[netip.MustParseAddr("2001:db8::")]; !ok {
		t.Error("the prefix's base address must be a valid IPv6 destination")
	}
	// The cycle repeats after the prefix is exhausted.
	if nthAddr(p, 256) != nthAddr(p, 0) {
		t.Error("the address cycle should repeat after every address")
	}
}

// A single IPv6 flow is stable, and its tuple carries the v6 addresses.
func TestIPv6SingleFlowStable(t *testing.T) {
	s := FlowSpec{
		SrcIP:   netip.MustParseAddr("2001:db8::99"),
		Dst:     netip.MustParsePrefix("2001:db8::2/128"),
		SrcPort: 1024, DstPort: 9000, Flows: 1,
	}
	f := s.At(0)
	if !f.SrcIP.Is6() || !f.DstIP.Is6() {
		t.Fatalf("flow addresses are not IPv6: src %s dst %s", f.SrcIP, f.DstIP)
	}
	if f.DstIP != netip.MustParseAddr("2001:db8::2") {
		t.Errorf("dst = %s, want 2001:db8::2", f.DstIP)
	}
}

// The receive/stats classifier must see UDP and TCP through an IPv6 header, and
// bucket an extension-header chain (which it does not walk) as Other.
func TestClassifyIPv6(t *testing.T) {
	for _, proto := range []uint8{packet.ProtoUDP, packet.ProtoTCP} {
		tmpl, err := packet.Build(packet.Spec{
			SrcMAC: [6]byte{2, 0, 0, 0, 0, 1}, DstMAC: [6]byte{2, 0, 0, 0, 0, 2},
			SrcIP: netip.MustParseAddr("2001:db8::1"), DstIP: netip.MustParseAddr("2001:db8::2"),
			Proto: proto, SrcPort: 1024, DstPort: 9000, FrameLen: 80,
		})
		if err != nil {
			t.Fatal(err)
		}
		want := stats.ClassUDP
		if proto == packet.ProtoTCP {
			want = stats.ClassTCP
		}
		if got := classify(tmpl.Bytes()); got != want {
			t.Errorf("classify IPv6 proto %d = %v, want %v", proto, got, want)
		}
	}

	// An IPv6 frame whose Next Header is an extension header (hop-by-hop, 0) is
	// not walked, so it counts as Other rather than being misread.
	frame := make([]byte, 80)
	frame[12], frame[13] = 0x86, 0xdd // EtherType IPv6
	frame[14] = 0x60                  // version 6
	frame[14+6] = 0                   // Next Header: hop-by-hop options
	if got := classify(frame); got != stats.ClassOther {
		t.Errorf("an IPv6 extension-header frame classified as %v, want Other", got)
	}
}
