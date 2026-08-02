package dataplane

import (
	"errors"
	"testing"

	afxdp "github.com/atoonk/go-afxdp"

	"github.com/atoonk/wireblast/internal/config"
	"github.com/atoonk/wireblast/internal/stats"
)

// key builds a fleetKey with one field changed, for the comparison tests.
func key(mut func(*fleetKey)) fleetKey {
	k := fleetKey{
		iface: "eth0", queues: 8, filter: "none (transmit only)",
		numFrames: 4096, frameSize: 2048, receives: false,
	}
	if mut != nil {
		mut(&k)
	}
	return k
}

// Reusing an attachment that does not actually match would run the test
// against the wrong XDP program, so every field has to count.
func TestFleetKeyDistinguishesEverythingThatMatters(t *testing.T) {
	base := key(nil)
	tests := []struct {
		what string
		mut  func(*fleetKey)
	}{
		{"a different interface", func(k *fleetKey) { k.iface = "eth1" }},
		{"a different queue count", func(k *fleetKey) { k.queues = 4 }},
		{"a different filter", func(k *fleetKey) { k.filter = "udp/9000" }},
		{"a different UMEM depth", func(k *fleetKey) { k.numFrames = 8192 }},
		{"a different frame size", func(k *fleetKey) { k.frameSize = 4096 }},
		{"receiving turned on", func(k *fleetKey) { k.receives = true }},
	}
	for _, tt := range tests {
		if got := key(tt.mut); got == base {
			t.Errorf("%s must not compare equal to the original key", tt.what)
		}
	}
	// ...and an identical key does match, or nothing would ever be reused.
	if key(nil) != base {
		t.Error("two identical keys should compare equal")
	}
}

// The whole point: a matching key hands back the fleet without attaching
// again, which is what saves the link bounce.
func TestSessionReusesAMatchingFleet(t *testing.T) {
	s := NewSession()
	opens := 0
	open := func() (*afxdp.Fleet, error) { opens++; return nil, nil }

	if _, reused, err := s.Fleet(key(nil), open); err != nil || reused {
		t.Fatalf("the first call must attach: reused=%v err=%v", reused, err)
	}
	if opens != 1 {
		t.Fatalf("opens = %d, want 1", opens)
	}
	if !s.Attached() {
		t.Error("the session should be holding the fleet")
	}

	for i := range 3 {
		_, reused, err := s.Fleet(key(nil), open)
		if err != nil {
			t.Fatalf("rerun %d: %v", i, err)
		}
		if !reused {
			t.Errorf("rerun %d attached again; the whole point is that it should not", i)
		}
	}
	if opens != 1 {
		t.Errorf("opens = %d after three reruns, want 1", opens)
	}
}

// Changing something the attachment depends on has to reattach, even though
// that costs the bounce — running against a stale XDP program would be worse.
func TestSessionReattachesWhenTheKeyChanges(t *testing.T) {
	s := NewSession()
	opens := 0
	open := func() (*afxdp.Fleet, error) { opens++; return nil, nil }

	s.Fleet(key(nil), open)
	_, reused, err := s.Fleet(key(func(k *fleetKey) { k.filter = "udp/9000" }), open)
	if err != nil {
		t.Fatal(err)
	}
	if reused {
		t.Error("a different filter must not reuse the old attachment")
	}
	if opens != 2 {
		t.Errorf("opens = %d, want 2", opens)
	}

	// Going back to the first key reattaches again rather than resurrecting
	// the original: only one fleet is ever held.
	if _, reused, _ := s.Fleet(key(nil), open); reused {
		t.Error("the previous attachment is gone and must not be reported as reused")
	}
}

func TestSessionCloseIsIdempotent(t *testing.T) {
	s := NewSession()
	if err := s.Close(); err != nil {
		t.Errorf("closing an empty session: %v", err)
	}
	s.Fleet(key(nil), func() (*afxdp.Fleet, error) { return nil, nil })
	if !s.Attached() {
		t.Fatal("expected an attachment")
	}
	if err := s.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
	if s.Attached() {
		t.Error("Close should have released it")
	}
	if err := s.Close(); err != nil {
		t.Errorf("a second Close should be a no-op: %v", err)
	}

	// After closing, the next run attaches fresh.
	opens := 0
	if _, reused, _ := s.Fleet(key(nil), func() (*afxdp.Fleet, error) {
		opens++
		return nil, nil
	}); reused || opens != 1 {
		t.Errorf("after Close: reused=%v opens=%d, want false/1", reused, opens)
	}
}

func TestSessionReportsOpenFailures(t *testing.T) {
	s := NewSession()
	want := errors.New("driver said no")
	_, reused, err := s.Fleet(key(nil), func() (*afxdp.Fleet, error) { return nil, want })
	if !errors.Is(err, want) {
		t.Errorf("err = %v, want the opener's error", err)
	}
	if reused {
		t.Error("a failed attach is not a reuse")
	}
	if s.Attached() {
		t.Error("a failed attach must not leave the session thinking it holds one")
	}
}

// A reused fleet carries the previous run's counters. Reporting those as this
// run's would show drops that happened before it started.
func TestKernelCountersAreBaselined(t *testing.T) {
	base := stats.Kernel{
		RxPackets: 1000, TxPackets: 2000, RxDropped: 7, RxRingFull: 3,
		TxInvalidDescs: 1,
		PerQueue: []stats.KernelQueue{
			{Queue: 0, RxPackets: 600, TxPackets: 1200, RxDropped: 4},
			{Queue: 1, RxPackets: 400, TxPackets: 800, RxDropped: 3},
		},
	}
	now := stats.Kernel{
		Queues: 2, RxPackets: 1500, TxPackets: 2500, RxDropped: 9, RxRingFull: 3,
		TxInvalidDescs: 1,
		PerQueue: []stats.KernelQueue{
			{Queue: 0, RxPackets: 900, TxPackets: 1500, RxDropped: 5},
			{Queue: 1, RxPackets: 600, TxPackets: 1000, RxDropped: 4},
		},
	}

	got := subtractKernel(now, base)
	if got.RxPackets != 500 || got.TxPackets != 500 {
		t.Errorf("packets = %d/%d, want 500/500", got.RxPackets, got.TxPackets)
	}
	if got.RxDropped != 2 {
		t.Errorf("RxDropped = %d, want 2 — only the drops since this run began", got.RxDropped)
	}
	// Unchanged counters must read zero, not carry the old total forward.
	if got.RxRingFull != 0 || got.TxInvalidDescs != 0 {
		t.Errorf("unchanged counters leaked through: ringfull=%d invalid=%d",
			got.RxRingFull, got.TxInvalidDescs)
	}
	if len(got.PerQueue) != 2 {
		t.Fatalf("PerQueue has %d entries, want 2", len(got.PerQueue))
	}
	if got.PerQueue[0].RxPackets != 300 || got.PerQueue[1].RxPackets != 200 {
		t.Errorf("per-queue = %d/%d, want 300/200",
			got.PerQueue[0].RxPackets, got.PerQueue[1].RxPackets)
	}
}

// A fresh attach zeroes the kernel's counters while the baseline still holds
// the old totals. That must read as zero, not underflow to something enormous.
func TestKernelBaselineSurvivesACounterReset(t *testing.T) {
	base := stats.Kernel{RxPackets: 1000, RxDropped: 5}
	fresh := stats.Kernel{RxPackets: 10, RxDropped: 0}

	got := subtractKernel(fresh, base)
	if got.RxPackets != 0 || got.RxDropped != 0 {
		t.Errorf("a reset counter gave %d packets / %d drops, want 0/0 — not an underflow",
			got.RxPackets, got.RxDropped)
	}

	// Fewer queues than the baseline must not index out of range either.
	base.PerQueue = []stats.KernelQueue{{Queue: 0, RxPackets: 5}, {Queue: 1, RxPackets: 5}}
	fresh.PerQueue = []stats.KernelQueue{{Queue: 0, RxPackets: 1}}
	if got := subtractKernel(fresh, base); len(got.PerQueue) != 1 {
		t.Errorf("PerQueue = %d entries, want 1", len(got.PerQueue))
	}
}

// Only a Runner that opened its own fleet may close it; one borrowing from a
// session must leave the program attached for the next run.
func TestRunnerFleetKeyTracksItsConfiguration(t *testing.T) {
	mk := func(mut func(*config.Config)) fleetKey {
		cfg := cfgFor(mut)
		r, err := New(cfg, resolved(), Options{})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		return r.fleetKey()
	}

	base := mk(nil)
	// Things that do not touch the attachment must not force a reattach —
	// these are exactly what people change between runs.
	for _, tt := range []struct {
		what string
		mut  func(*config.Config)
	}{
		{"the packet rate", func(c *config.Config) { c.PPS = 5_000_000 }},
		{"the duration", func(c *config.Config) { c.Duration = 0 }},
		{"the flow count", func(c *config.Config) { c.Flows = 5000 }},
		{"the destination port", func(c *config.Config) { c.DstPort = 1234 }},
	} {
		if got := mk(tt.mut); got != base {
			t.Errorf("changing %s should not need a reattach:\n got %+v\nwant %+v",
				tt.what, got, base)
		}
	}

	// Things that do.
	for _, tt := range []struct {
		what string
		mut  func(*config.Config)
	}{
		{"the receive mode", func(c *config.Config) {
			c.RxMode = config.RxUDPPort
			c.RxPorts = []uint16{9000}
		}},
		{"the queue count", func(c *config.Config) { c.Queues = 2 }},
		{"a jumbo packet size", func(c *config.Config) { c.PacketSize = 9000 }},
	} {
		if got := mk(tt.mut); got == base {
			t.Errorf("changing %s must force a reattach, but the key is unchanged", tt.what)
		}
	}
}
