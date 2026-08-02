package generator

import (
	"net/netip"
	"testing"
)

func ip4(s string) netip.Addr { return netip.MustParseAddr(s) }

func TestFlowSpecSequential(t *testing.T) {
	s := FlowSpec{
		SrcIP:   netip.MustParseAddr("192.168.0.99"),
		Dst:     netip.MustParsePrefix("192.0.2.10/32"),
		SrcPort: 1024,
		DstPort: 9000,
		Flows:   4,
	}
	want := []Flow{
		{ip4("192.168.0.99"), ip4("192.0.2.10"), 1024, 9000},
		{ip4("192.168.0.99"), ip4("192.0.2.10"), 1025, 9000},
		{ip4("192.168.0.99"), ip4("192.0.2.10"), 1026, 9000},
		{ip4("192.168.0.99"), ip4("192.0.2.10"), 1027, 9000},
	}
	for n, w := range want {
		if got := s.At(n); got != w {
			t.Errorf("At(%d) = %+v, want %+v", n, got, w)
		}
	}
	// The sequence repeats exactly: flow n and flow n+Flows are the same flow.
	for n := range 20 {
		if s.At(n) != s.At(n+s.Flows) {
			t.Errorf("At(%d) != At(%d); the flow space is not cyclic", n, n+s.Flows)
		}
	}
	// A negative index must fold back into range rather than panic.
	if s.At(-1) != s.At(3) {
		t.Error("At(-1) should be the last flow")
	}
}

func TestFlowSpecSingleFlowIsStable(t *testing.T) {
	s := FlowSpec{
		SrcIP:   netip.MustParseAddr("10.0.0.1"),
		Dst:     netip.MustParsePrefix("10.0.0.2/32"),
		SrcPort: 1024, DstPort: 53, Flows: 1,
	}
	first := s.At(0)
	for n := range 100 {
		if got := s.At(n); got != first {
			t.Fatalf("flows=1 must produce one stable tuple; At(%d) = %+v, want %+v", n, got, first)
		}
	}
}

func TestVaryDstPort(t *testing.T) {
	s := FlowSpec{
		SrcIP:   netip.MustParseAddr("10.0.0.1"),
		Dst:     netip.MustParsePrefix("10.0.0.2/32"),
		SrcPort: 1024, DstPort: 9000, Flows: 3,
	}
	// By default the destination port is fixed: many flows, one server port.
	for n := range 3 {
		if got := s.At(n).DstPort; got != 9000 {
			t.Errorf("At(%d).DstPort = %d, want 9000", n, got)
		}
	}
	s.VaryDstPort = true
	for n := range 3 {
		if got, want := s.At(n).DstPort, uint16(9000+n); got != want {
			t.Errorf("with --vary-dst-port, At(%d).DstPort = %d, want %d", n, got, want)
		}
	}
}

func TestPortWraparound(t *testing.T) {
	tests := []struct {
		start uint16
		n     int
		want  uint16
	}{
		{1024, 0, 1024},
		{1024, 1, 1025},
		{65535, 0, 65535},
		{65535, 1, 1},     // would be 0, which is never a usable port
		{65535, 2, 1},     // 1 again: the documented cost of skipping 0
		{65534, 1, 65535}, //
		{65534, 2, 1},     // wraps past 0
		{65534, 3, 1},
		{1024, 65536, 1024}, // a full lap
	}
	for _, tt := range tests {
		if got := portAt(tt.start, tt.n); got != tt.want {
			t.Errorf("portAt(%d, %d) = %d, want %d", tt.start, tt.n, got, tt.want)
		}
	}
	// Port 0 must never be produced, whatever the offset.
	for n := range 70000 {
		if portAt(65530, n) == 0 {
			t.Fatalf("portAt(65530, %d) produced port 0", n)
		}
	}
}

func TestCIDRCycling(t *testing.T) {
	tests := []struct {
		cidr string
		want []string // the first few destinations, in order
	}{
		// A /24 skips .0 (network) and .255 (broadcast).
		{"192.0.2.0/24", []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"}},
		// A /30 has exactly two usable hosts, then repeats.
		{"10.0.0.0/30", []string{"10.0.0.1", "10.0.0.2", "10.0.0.1", "10.0.0.2"}},
		// RFC 3021: both addresses of a /31 are usable.
		{"10.0.0.0/31", []string{"10.0.0.0", "10.0.0.1", "10.0.0.0"}},
		// A /32 is a single host, forever.
		{"10.0.0.7/32", []string{"10.0.0.7", "10.0.0.7"}},
		// A host address inside a wider prefix is masked to the network first.
		{"192.0.2.55/24", []string{"192.0.2.1", "192.0.2.2"}},
	}
	for _, tt := range tests {
		p := netip.MustParsePrefix(tt.cidr)
		for n, want := range tt.want {
			got := netip.AddrFrom4(nthUsable(p, n))
			if got != netip.MustParseAddr(want) {
				t.Errorf("%s: address %d = %v, want %v", tt.cidr, n, got, want)
			}
		}
	}
}

// Cycling a /24 must visit every usable host exactly once before repeating,
// and must never touch the network or broadcast address.
func TestCIDRCoversEveryUsableHost(t *testing.T) {
	p := netip.MustParsePrefix("192.0.2.0/24")
	seen := map[[4]byte]int{}
	for n := range 254 {
		seen[nthUsable(p, n)]++
	}
	if len(seen) != 254 {
		t.Fatalf("a /24 produced %d distinct addresses, want 254", len(seen))
	}
	for _, forbidden := range []string{"192.0.2.0", "192.0.2.255"} {
		if _, bad := seen[ip4(forbidden).As4()]; bad {
			t.Errorf("%s (network or broadcast) must never be a destination", forbidden)
		}
	}
	// The 255th address wraps back to the first.
	if nthUsable(p, 254) != nthUsable(p, 0) {
		t.Error("the address cycle should repeat after every usable host")
	}
}

func TestUsableAddresses(t *testing.T) {
	tests := []struct {
		cidr string
		want uint64
	}{
		{"10.0.0.1/32", 1},
		{"10.0.0.0/31", 2},
		{"10.0.0.0/30", 2},
		{"10.0.0.0/24", 254},
		{"10.0.0.0/16", 65534},
		{"2001:db8::1/128", 1},
		{"2001:db8::/120", 256},
	}
	for _, tt := range tests {
		if got := UsableAddresses(netip.MustParsePrefix(tt.cidr)); got != tt.want {
			t.Errorf("UsableAddresses(%s) = %d, want %d", tt.cidr, got, tt.want)
		}
	}
}

// The set of flows a run produces must not depend on how many queues carry
// them; only the interleaving changes.
func TestQueueCursorsCoverTheFlowSpaceOnce(t *testing.T) {
	const flows = 100
	for _, queues := range []int{1, 2, 3, 8, 12} {
		counts := make([]int, flows)
		for q := range queues {
			c := newQueueCursor(q, queues, flows)
			// Each queue walks flows/queues of the space per cycle; together
			// they complete exactly one cycle in `flows` steps.
			for range flows / queues {
				counts[c.next()]++
			}
		}
		total := 0
		for _, n := range counts {
			total += n
		}
		if want := (flows / queues) * queues; total != want {
			t.Errorf("queues=%d: produced %d flows, want %d", queues, total, want)
		}
		// No flow may be produced twice while others are untouched.
		for i, n := range counts {
			if n > 1 {
				t.Errorf("queues=%d: flow %d produced %d times in one cycle", queues, i, n)
			}
		}
	}
}

// With fewer flows than queues, every queue must still have work — otherwise
// a single-flow test would only ever use one of twelve queues.
func TestQueueCursorWithFewerFlowsThanQueues(t *testing.T) {
	for q := range 12 {
		c := newQueueCursor(q, 12, 1)
		for range 5 {
			if got := c.next(); got != 0 {
				t.Fatalf("queue %d produced flow %d, want 0", q, got)
			}
		}
	}
	// Three flows over 12 queues: each queue sticks to one flow, all covered.
	seen := map[int]bool{}
	for q := range 12 {
		c := newQueueCursor(q, 12, 3)
		seen[c.next()] = true
	}
	if len(seen) != 3 {
		t.Errorf("3 flows over 12 queues covered %d flows, want 3", len(seen))
	}
}

func BenchmarkFlowSpecAt(b *testing.B) {
	s := FlowSpec{
		SrcIP:   netip.MustParseAddr("192.168.0.99"),
		Dst:     netip.MustParsePrefix("10.0.0.0/8"),
		SrcPort: 1024, DstPort: 9000, Flows: 1_000_000,
	}
	b.ReportAllocs()
	n := 0
	for b.Loop() {
		n++
		_ = s.At(n)
	}
}

// Scattered order visits exactly the same flows, just not in counting order.
func TestScatteredOrderIsAPermutation(t *testing.T) {
	for _, flows := range []int{1, 2, 3, 4, 7, 64, 100, 254, 1000, 65536} {
		seq := FlowSpec{
			SrcIP:   netip.MustParseAddr("10.0.0.1"),
			Dst:     netip.MustParsePrefix("10.1.0.0/16"),
			SrcPort: 1024, DstPort: 9000, Flows: flows,
		}
		rnd := seq
		rnd.Scatter = true

		seen := make(map[Flow]bool, flows)
		want := make(map[Flow]bool, flows)
		for n := range flows {
			seen[rnd.At(n)] = true
			want[seq.At(n)] = true
		}
		if len(seen) != flows {
			t.Errorf("flows=%d: scattered order produced %d distinct flows, want %d",
				flows, len(seen), flows)
		}
		// The *set* must be identical — only the order differs.
		if len(seen) != len(want) {
			t.Errorf("flows=%d: the scattered set has %d flows, sequential has %d",
				flows, len(seen), len(want))
			continue
		}
		for f := range want {
			if !seen[f] {
				t.Errorf("flows=%d: scattered order is missing a flow sequential produced", flows)
				break
			}
		}
	}
}

// It must actually scatter, and must still be reproducible run to run.
func TestScatteredOrderIsScrambledButDeterministic(t *testing.T) {
	s := FlowSpec{
		SrcIP:   netip.MustParseAddr("10.0.0.1"),
		Dst:     netip.MustParsePrefix("10.0.0.2/32"),
		SrcPort: 1024, DstPort: 9000, Flows: 1000, Scatter: true,
	}
	consecutive := 0
	for n := range 999 {
		if s.At(n+1).SrcPort == s.At(n).SrcPort+1 {
			consecutive++
		}
	}
	if consecutive > 100 {
		t.Errorf("%d of 999 steps were consecutive ports; that is not scattered", consecutive)
	}
	// Same spec, same sequence, every time.
	for n := range 100 {
		if s.At(n) != s.At(n) {
			t.Fatal("scattered order must be reproducible")
		}
	}
	other := s
	for n := range 100 {
		if other.At(n) != s.At(n) {
			t.Fatal("two identical specs must produce identical sequences")
		}
	}
}
