package stats

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeClock struct{ ns atomic.Int64 }

func newClock() *fakeClock {
	c := &fakeClock{}
	c.ns.Store(time.Unix(1, 0).UnixNano())
	return c
}

func (c *fakeClock) Now() time.Time          { return time.Unix(0, c.ns.Load()) }
func (c *fakeClock) Advance(d time.Duration) { c.ns.Add(int64(d)) }

func TestCountersAndSnapshot(t *testing.T) {
	c := New(2, 0, nil)
	c.Queue(0).AddTx(10, 640, ClassUDP)
	c.Queue(1).AddTx(5, 320, ClassTCP)
	c.Queue(1).AddTx(1, 1514, ClassOther)
	c.Queue(0).AddRx(64, ClassUDP)

	s := c.Sample()
	if s.TX.Packets != 16 {
		t.Errorf("TX.Packets = %d, want 16", s.TX.Packets)
	}
	if s.TX.Bytes != 640+320+1514 {
		t.Errorf("TX.Bytes = %d, want %d", s.TX.Bytes, 640+320+1514)
	}
	if s.TX.UDP != 10 || s.TX.TCP != 5 || s.TX.Other != 1 {
		t.Errorf("protocol split = udp %d tcp %d other %d, want 10/5/1", s.TX.UDP, s.TX.TCP, s.TX.Other)
	}
	if s.RX.Packets != 1 || s.RX.UDP != 1 {
		t.Errorf("RX = %d packets (%d udp), want 1 (1)", s.RX.Packets, s.RX.UDP)
	}
	if got, want := s.TX.AvgFrame(), float64(640+320+1514)/16; got != want {
		t.Errorf("AvgFrame = %v, want %v", got, want)
	}
	// AddTx with a non-positive count must be ignored, not corrupt the totals.
	c.Queue(0).AddTx(0, 999, ClassUDP)
	c.Queue(0).AddTx(-3, 999, ClassUDP)
	if s := c.Sample(); s.TX.Packets != 16 || s.TX.Bytes != 640+320+1514 {
		t.Errorf("a zero/negative batch changed the totals: %+v", s.TX)
	}
}

func TestRates(t *testing.T) {
	clk := newClock()
	// A 2-sample window means rates are measured across one tick.
	c := New(1, 0, nil, WithClock(clk.Now), WithWindow(2))

	// Two ticks of 1000 64-byte frames each, a second apart. Byte counts
	// include the FCS, matching --packet-size.
	for i := 0; i < 2; i++ {
		c.Queue(0).AddTx(1000, 1000*64, ClassUDP)
		clk.Advance(time.Second)
		c.Sample()
	}
	s := c.Snapshot()
	if got := s.TXRate.PPS; got < 990 || got > 1010 {
		t.Errorf("TXRate.PPS = %v, want ~1000", got)
	}
	// 64 frame bytes per packet.
	if got := s.TXRate.FrameBPS; got < 0.99*512e3 || got > 1.01*512e3 {
		t.Errorf("FrameBPS = %v, want ~512000", got)
	}
	// ...and 84 wire bytes (64 + 20 of preamble, SFD and interframe gap).
	if got := s.TXRate.WireBPS; got < 0.99*672e3 || got > 1.01*672e3 {
		t.Errorf("WireBPS = %v, want ~672000", got)
	}
	if got := s.TX.AvgFrame(); got != 64 {
		t.Errorf("AvgFrame = %v, want 64 — the same units as --packet-size", got)
	}
	if s.TXRate.WireBPS <= s.TXRate.FrameBPS {
		t.Error("wire rate must exceed frame rate; the framing overhead is missing")
	}
}

func TestElapsedAndRemaining(t *testing.T) {
	clk := newClock()
	c := New(1, 30*time.Second, nil, WithClock(clk.Now))

	clk.Advance(10 * time.Second)
	s := c.Sample()
	if s.Elapsed != 10*time.Second {
		t.Errorf("Elapsed = %v, want 10s", s.Elapsed)
	}
	if s.Remaining != 20*time.Second {
		t.Errorf("Remaining = %v, want 20s", s.Remaining)
	}

	clk.Advance(25 * time.Second)
	if s := c.Sample(); s.Remaining != 0 {
		t.Errorf("Remaining past the duration = %v, want 0", s.Remaining)
	}

	// An open-ended run never reports a remaining time.
	c2 := New(1, 0, nil, WithClock(clk.Now))
	clk.Advance(time.Hour)
	if s := c2.Sample(); s.Remaining != 0 {
		t.Errorf("Remaining with no duration = %v, want 0", s.Remaining)
	}
}

// The `r` hotkey clears what is on screen but must never lose the lifetime
// totals the final summary reports.
func TestResetIntervalKeepsLifetimeTotals(t *testing.T) {
	clk := newClock()
	c := New(1, 0, nil, WithClock(clk.Now))

	c.Queue(0).AddTx(100, 6000, ClassUDP)
	c.Queue(0).AddRx(64, ClassUDP)
	clk.Advance(time.Second)
	c.Sample()

	c.ResetInterval()
	s := c.Snapshot()
	if s.TX.Packets != 0 || s.RX.Packets != 0 {
		t.Errorf("after reset, visible TX/RX = %d/%d, want 0/0", s.TX.Packets, s.RX.Packets)
	}
	if s.TotalTX.Packets != 100 || s.TotalRX.Packets != 1 {
		t.Errorf("after reset, lifetime TX/RX = %d/%d, want 100/1", s.TotalTX.Packets, s.TotalRX.Packets)
	}
	if s.IntervalSince.IsZero() {
		t.Error("IntervalSince should record when the reset happened")
	}

	c.Queue(0).AddTx(50, 3000, ClassUDP)
	clk.Advance(time.Second)
	s = c.Sample()
	if s.TX.Packets != 50 {
		t.Errorf("visible TX after reset = %d, want 50", s.TX.Packets)
	}
	if s.TotalTX.Packets != 150 {
		t.Errorf("lifetime TX = %d, want 150", s.TotalTX.Packets)
	}
}

func TestKernelCountersMerge(t *testing.T) {
	k := Kernel{
		Queues:    2,
		TxPackets: 12345,
		RxDropped: 7, RxRingFull: 3, TxInvalidDescs: 2,
		PerQueue: []KernelQueue{
			{Queue: 0, RxPackets: 100},
			{Queue: 1, RxPackets: 50, RxRingFull: 3},
		},
	}
	c := New(2, 0, func() (Kernel, error) { return k, nil })
	s := c.Sample()
	if s.Kernel.TxPackets != 12345 {
		t.Errorf("Kernel.TxPackets = %d, want 12345", s.Kernel.TxPackets)
	}
	if s.RX.Drops != 10 {
		t.Errorf("RX.Drops = %d, want 10 (dropped + ring full)", s.RX.Drops)
	}
	if s.TX.Errors != 2 {
		t.Errorf("TX.Errors = %d, want 2 (invalid tx descriptors)", s.TX.Errors)
	}
	if len(s.Problems) != 1 || !strings.Contains(s.Problems[0], "queue 1") {
		t.Errorf("Problems = %v, want one entry naming queue 1", s.Problems)
	}
}

// A failing kernel read must not take the snapshot down with it.
func TestKernelErrorIsTolerated(t *testing.T) {
	c := New(1, 0, func() (Kernel, error) { return Kernel{}, context.DeadlineExceeded })
	c.Queue(0).AddTx(5, 300, ClassUDP)
	s := c.Sample()
	if s.TX.Packets != 5 {
		t.Errorf("application counters lost when the kernel read failed: %+v", s.TX)
	}
}

func TestStateTransitions(t *testing.T) {
	c := New(1, 0, nil)
	if s := c.Sample(); s.State != StateStarting {
		t.Errorf("initial state = %v, want starting", s.State)
	}
	for _, st := range []State{StateRunning, StatePaused, StateStopping, StateComplete} {
		c.SetState(st)
		if got := c.Sample().State; got != st {
			t.Errorf("state = %v, want %v", got, st)
		}
		if c.State() != st {
			t.Errorf("State() = %v, want %v", c.State(), st)
		}
	}
	if StateRunning.String() != "running" || State(99).String() != "unknown" {
		t.Error("State.String is wrong")
	}
}

func TestRunPublishesUntilCancelled(t *testing.T) {
	c := New(1, 0, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); c.Run(ctx, time.Millisecond) }()

	c.Queue(0).AddTx(1, 64, ClassUDP)
	deadline := time.After(2 * time.Second)
	for c.Snapshot().TX.Packets == 0 {
		select {
		case <-deadline:
			t.Fatal("Run never published a snapshot with the new counters")
		default:
			time.Sleep(time.Millisecond)
		}
	}

	// Cancellation must publish one last snapshot so the summary is current.
	c.Queue(0).AddTx(9, 576, ClassUDP)
	cancel()
	<-done
	if got := c.Snapshot().TotalTX.Packets; got != 10 {
		t.Errorf("final snapshot TX = %d, want 10", got)
	}
}

// The counters are written by queue goroutines and read by the collector; that
// must be race-free.
func TestConcurrentCountersAndSnapshots(t *testing.T) {
	const queues, iters = 8, 5000
	c := New(queues, 0, nil)
	var wg sync.WaitGroup
	for q := 0; q < queues; q++ {
		wg.Add(1)
		go func(q int) {
			defer wg.Done()
			ctr := c.Queue(q)
			for i := 0; i < iters; i++ {
				ctr.AddTx(1, 60, ClassUDP)
				ctr.AddRx(60, ClassTCP)
			}
		}(q)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			_ = c.Sample()
			c.ResetInterval()
		}
	}()
	wg.Wait()

	s := c.Sample()
	if s.TotalTX.Packets != queues*iters {
		t.Errorf("lifetime TX = %d, want %d", s.TotalTX.Packets, queues*iters)
	}
	if s.TotalRX.Packets != queues*iters {
		t.Errorf("lifetime RX = %d, want %d", s.TotalRX.Packets, queues*iters)
	}
}

func TestSnapshotIsImmutableAcrossSamples(t *testing.T) {
	c := New(1, 0, nil)
	c.Queue(0).AddTx(1, 64, ClassUDP)
	first := c.Sample()
	c.Queue(0).AddTx(1, 64, ClassUDP)
	second := c.Sample()
	if first == second {
		t.Fatal("Sample must publish a new snapshot, not mutate the old one")
	}
	if first.TX.Packets != 1 {
		t.Errorf("the earlier snapshot changed under us: %d", first.TX.Packets)
	}
}

func BenchmarkAddTx(b *testing.B) {
	c := New(1, 0, nil)
	q := c.Queue(0)
	b.ReportAllocs()
	for b.Loop() {
		q.AddTx(256, 256*60, ClassUDP)
	}
}

func BenchmarkAddRx(b *testing.B) {
	c := New(1, 0, nil)
	q := c.Queue(0)
	b.ReportAllocs()
	for b.Loop() {
		q.AddRx(60, ClassUDP)
	}
}

func BenchmarkSnapshotRead(b *testing.B) {
	c := New(12, 0, nil)
	b.ReportAllocs()
	for b.Loop() {
		_ = c.Snapshot()
	}
}

// Attaching native XDP bounces the link for seconds. That wait must not be
// counted as part of the run, or every average rate is understated.
func TestMarkStartRestartsTheClock(t *testing.T) {
	clk := newClock()
	c := New(1, 30*time.Second, nil, WithClock(clk.Now))

	clk.Advance(9 * time.Second) // the link comes back
	c.MarkStart()

	clk.Advance(10 * time.Second)
	s := c.Sample()
	if s.Elapsed != 10*time.Second {
		t.Errorf("Elapsed = %v, want 10s — the link wait must not count", s.Elapsed)
	}
	if s.Remaining != 20*time.Second {
		t.Errorf("Remaining = %v, want 20s", s.Remaining)
	}
}

// History is recorded once a second, not once per sample — the collector runs
// four times as often as the graph needs.
func TestHistoryIsRecordedPerSecond(t *testing.T) {
	clk := newClock()
	c := New(1, 0, nil, WithClock(clk.Now))

	// Ten seconds of traffic, sampled every 250ms as the dataplane does.
	for range 40 {
		c.Queue(0).AddTx(250, 250*64, ClassUDP)
		clk.Advance(250 * time.Millisecond)
		c.Sample()
	}

	h := c.Snapshot().History
	if len(h) < 9 || len(h) > 11 {
		t.Fatalf("10 seconds produced %d history points, want about 10", len(h))
	}
	// Oldest first, strictly increasing in time.
	for i := 1; i < len(h); i++ {
		if !h[i].At.After(h[i-1].At) {
			t.Fatalf("history is not ordered oldest-first at index %d", i)
		}
		if gap := h[i].At.Sub(h[i-1].At); gap < 900*time.Millisecond || gap > 1100*time.Millisecond {
			t.Errorf("points %d and %d are %v apart, want about a second", i-1, i, gap)
		}
	}
	// The recorded rate is the smoothed rate, so it should be near 1000 pps.
	last := h[len(h)-1]
	if last.TX.PPS < 900 || last.TX.PPS > 1100 {
		t.Errorf("recorded TX rate = %v, want about 1000 pps", last.TX.PPS)
	}
}

func TestHistoryRingWrapsAndCaps(t *testing.T) {
	clk := newClock()
	c := New(1, 0, nil, WithClock(clk.Now))

	for range historyLen + 50 {
		c.Queue(0).AddTx(100, 100*64, ClassUDP)
		clk.Advance(time.Second)
		c.Sample()
	}
	h := c.Snapshot().History
	if len(h) != historyLen {
		t.Fatalf("history holds %d points, want the %d cap", len(h), historyLen)
	}
	for i := 1; i < len(h); i++ {
		if !h[i].At.After(h[i-1].At) {
			t.Fatalf("a wrapped ring must still read oldest-first; broken at %d", i)
		}
	}
	// The oldest point kept should be the 51st, not the 1st.
	if h[0].At.Before(c.Snapshot().At.Add(-time.Duration(historyLen) * time.Second)) {
		t.Error("the ring kept points older than its capacity")
	}
}

// The link-bounce wait before traffic can flow must not appear as a flat
// lead-in on the graph.
func TestMarkStartClearsHistory(t *testing.T) {
	clk := newClock()
	c := New(1, 0, nil, WithClock(clk.Now))
	for range 10 {
		clk.Advance(time.Second)
		c.Sample()
	}
	if len(c.Snapshot().History) == 0 {
		t.Fatal("expected history before MarkStart")
	}

	c.MarkStart()
	if h := c.Sample().History; len(h) != 0 {
		t.Errorf("MarkStart left %d points behind, want none", len(h))
	}
}

// `r` re-baselines counters. Rates are not counters, and the shape of the
// traffic is exactly what someone pressing `r` is still watching.
func TestResetIntervalKeepsHistory(t *testing.T) {
	clk := newClock()
	c := New(1, 0, nil, WithClock(clk.Now))
	for range 10 {
		c.Queue(0).AddTx(1000, 1000*64, ClassUDP)
		clk.Advance(time.Second)
		c.Sample()
	}
	before := len(c.Snapshot().History)
	if before == 0 {
		t.Fatal("expected history")
	}

	c.ResetInterval()
	if after := len(c.Snapshot().History); after != before {
		t.Errorf("ResetInterval changed the history from %d to %d points", before, after)
	}
}

// A run that has just started has no history, and callers must cope.
func TestHistoryStartsEmpty(t *testing.T) {
	c := New(1, 0, nil)
	if h := c.Snapshot().History; len(h) != 0 {
		t.Errorf("a new collector has %d history points, want none", len(h))
	}
}

// A paused stretch is recorded, not skipped: the flat run on the graph is how
// you see the pause.
func TestHistoryRecordsIdleTime(t *testing.T) {
	clk := newClock()
	c := New(1, 0, nil, WithClock(clk.Now))
	for range 5 {
		clk.Advance(time.Second)
		c.Sample()
	}
	h := c.Snapshot().History
	if len(h) < 4 {
		t.Fatalf("idle time should still be recorded, got %d points", len(h))
	}
	for i, p := range h {
		if p.TX.PPS != 0 {
			t.Errorf("point %d has rate %v, want 0 for an idle run", i, p.TX.PPS)
		}
	}
}
