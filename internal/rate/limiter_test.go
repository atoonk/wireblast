package rate

import (
	"math"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeClock is a manually advanced time source so rate tests are exact and
// instant rather than wall-clock dependent.
type fakeClock struct{ ns atomic.Int64 }

func newClock() *fakeClock {
	c := &fakeClock{}
	c.ns.Store(int64(time.Unix(0, 0).UnixNano()))
	return c
}

func (c *fakeClock) Now() time.Time          { return time.Unix(0, c.ns.Load()) }
func (c *fakeClock) Advance(d time.Duration) { c.ns.Add(int64(d)) }

// drain models what the transmit workers really do: step the clock, then let
// every queue keep asking for batches until the limiter stops granting. It
// returns the total packets and wire bytes granted — i.e. the aggregate rate
// the limiter actually allowed.
func drain(l *Limiter, c *fakeClock, queues, wireBytes int, steps int, step time.Duration) (packets int, bytes uint64) {
	for i := 0; i < steps; i++ {
		c.Advance(step)
		for {
			granted := 0
			for q := 0; q < queues; q++ {
				g, _ := l.Acquire(256, wireBytes)
				granted += g.Packets
			}
			if granted == 0 {
				break
			}
			packets += granted
			bytes += uint64(granted) * uint64(wireBytes)
		}
	}
	return packets, bytes
}

// within checks that got is within tolerance (as a fraction) of want.
func within(t *testing.T, what string, got, want float64, tol float64) {
	t.Helper()
	if want == 0 {
		if got != 0 {
			t.Errorf("%s = %g, want 0", what, got)
		}
		return
	}
	if d := math.Abs(got-want) / want; d > tol {
		t.Errorf("%s = %g, want %g (±%.0f%%), off by %.1f%%", what, got, want, tol*100, d*100)
	}
}

func TestPPSLimiting(t *testing.T) {
	for _, pps := range []uint64{1_000, 100_000, 1_000_000, 14_880_000} {
		c := newClock()
		l := New(pps, 0, WithClock(c.Now))
		got, _ := drain(l, c, 1, 84, 1000, time.Millisecond)
		within(t, "packets in 1s", float64(got), float64(pps), 0.02)
	}
}

func TestBPSLimiting(t *testing.T) {
	const wireBytes = 84 // a 64-byte frame plus framing
	for _, bps := range []uint64{1e6, 1e8, 1e9, 10e9} {
		c := newClock()
		l := New(0, bps, WithClock(c.Now))
		_, bytes := drain(l, c, 1, wireBytes, 1000, time.Millisecond)
		within(t, "bits in 1s", float64(bytes*8), float64(bps), 0.02)
	}
}

// With both limits set, the effective rate is whichever is reached first.
func TestCombinedLimits(t *testing.T) {
	const wireBytes = 84
	tests := []struct {
		name      string
		pps, bps  uint64
		wantPkts  float64
		tolerance float64
	}{
		// 1 Mpps of 84-byte frames is 672 Mbit/s, so a 10G ceiling is slack:
		// the packet limit binds.
		{"packets bind", 1_000_000, 10e9, 1_000_000, 0.02},
		// 100 Mbit/s of 84-byte frames is ~148.8 kpps, well under 1 Mpps: the
		// bit limit binds.
		{"bits bind", 1_000_000, 100e6, 100e6 / (wireBytes * 8), 0.02},
		// Equal pressure: both are satisfied, neither is exceeded.
		{"both at once", 148_809, 100e6, 148_809, 0.03},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := newClock()
			l := New(tt.pps, tt.bps, WithClock(c.Now))
			pkts, bytes := drain(l, c, 1, wireBytes, 1000, time.Millisecond)
			within(t, "packets in 1s", float64(pkts), tt.wantPkts, tt.tolerance)
			if tt.pps != 0 && uint64(pkts) > tt.pps*102/100 {
				t.Errorf("sent %d packets, exceeding the %d pps limit", pkts, tt.pps)
			}
			if tt.bps != 0 && bytes*8 > tt.bps*102/100 {
				t.Errorf("sent %d bits, exceeding the %d bps limit", bytes*8, tt.bps)
			}
		})
	}
}

// The configured rate is aggregate: adding queues must not multiply it.
func TestAggregateRateAcrossQueues(t *testing.T) {
	const pps = 1_000_000
	for _, queues := range []int{1, 2, 4, 8, 12} {
		c := newClock()
		l := New(pps, 0, WithClock(c.Now))
		got, _ := drain(l, c, queues, 84, 1000, time.Millisecond)
		within(t, "packets in 1s", float64(got), pps, 0.02)
	}
}

func TestAggregateRateAcrossConcurrentQueues(t *testing.T) {
	const (
		pps    = 2_000_000
		queues = 8
		steps  = 1000
	)
	c := newClock()
	l := New(pps, 0, WithClock(c.Now))

	var total atomic.Int64
	for i := 0; i < steps; i++ {
		c.Advance(time.Millisecond)
		var wg sync.WaitGroup
		for q := 0; q < queues; q++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					g, _ := l.Acquire(256, 84)
					if g.Packets == 0 {
						return
					}
					total.Add(int64(g.Packets))
				}
			}()
		}
		wg.Wait()
	}
	within(t, "packets in 1s across 8 goroutines", float64(total.Load()), pps, 0.02)
}

func TestUnlimited(t *testing.T) {
	l := New(0, 0)
	if !l.Unlimited() {
		t.Fatal("pps=0 bps=0 should be unlimited")
	}
	g, wait := l.Acquire(256, 84)
	if g.Packets != 256 || wait != 0 {
		t.Fatalf("unlimited Acquire = %d packets, wait %v; want 256, 0", g.Packets, wait)
	}
	// Settle must be harmless on the fast path.
	l.Settle(g, 200, 200*84)
	if g2, _ := l.Acquire(256, 84); g2.Packets != 256 {
		t.Fatalf("unlimited Acquire after Settle = %d, want 256", g2.Packets)
	}
}

func TestPauseAndResume(t *testing.T) {
	const pps = 1_000_000
	c := newClock()
	l := New(pps, 0, WithClock(c.Now))

	got, _ := drain(l, c, 1, 84, 100, time.Millisecond) // 100ms of traffic
	within(t, "packets in 100ms", float64(got), pps/10, 0.05)

	l.SetPaused(true)
	if !l.Paused() {
		t.Fatal("SetPaused(true) did not take effect")
	}
	paused, _ := drain(l, c, 1, 84, 1000, time.Millisecond) // a full second paused
	if paused != 0 {
		t.Errorf("granted %d packets while paused, want 0", paused)
	}

	// Resuming after a long pause must not release a stored-up burst.
	l.SetPaused(false)
	c.Advance(time.Millisecond)
	first, _ := l.Acquire(1<<20, 84)
	if float64(first.Packets) > pps/1000*3 {
		t.Errorf("first grant after a 1s pause was %d packets; a burst leaked through", first.Packets)
	}

	after, _ := drain(l, c, 1, 84, 100, time.Millisecond)
	within(t, "packets in 100ms after resume", float64(after), pps/10, 0.05)
}

// A worker that stops asking for a while must not be able to catch up all at
// once when it comes back.
func TestNoBurstAfterIdle(t *testing.T) {
	const pps = 1_000_000
	c := newClock()
	l := New(pps, 0, WithClock(c.Now))
	c.Advance(10 * time.Second) // a long stall

	g, _ := l.Acquire(1<<20, 84)
	// The bucket holds about 2ms of credit, so a 10-second stall releases
	// milliseconds of traffic, not seconds of it.
	if g.Packets > 2*pps/1000 {
		t.Errorf("first grant after a 10s stall was %d packets; the bucket is not capped", g.Packets)
	}
}

func TestWaitIsBounded(t *testing.T) {
	c := newClock()
	l := New(10, 0, WithClock(c.Now)) // very slow: 10 pps
	// No time has passed, so there is no credit and the caller must be told to
	// wait — but never to spin, and never for longer than MaxWait.
	g, wait := l.Acquire(256, 84)
	if g.Packets != 0 {
		t.Fatalf("expected no credit, got %d packets", g.Packets)
	}
	if wait < MinWait || wait > MaxWait {
		t.Errorf("wait = %v, want between %v and %v", wait, MinWait, MaxWait)
	}

	l.SetPaused(true)
	if _, wait := l.Acquire(256, 84); wait != MaxWait {
		t.Errorf("paused wait = %v, want %v", wait, MaxWait)
	}
}

// Variable-size traffic charges an estimate up front and corrects it in
// Settle; over a run the bit rate must still come out right.
func TestSettleReconcilesVariableSizes(t *testing.T) {
	const bps = 1e9
	// Estimate a 353-byte IMIX average but actually send 1518-byte frames.
	const estBytes, realBytes = 353 + 20, 1518 + 20

	c := newClock()
	l := New(0, bps, WithClock(c.Now))
	var bits uint64
	for i := 0; i < 1000; i++ {
		c.Advance(time.Millisecond)
		g, _ := l.Acquire(256, estBytes)
		if g.Packets == 0 {
			continue
		}
		actual := uint64(g.Packets) * realBytes
		bits += actual * 8
		l.Settle(g, g.Packets, actual)
	}
	within(t, "bits in 1s with a bad estimate", float64(bits), bps, 0.05)
}

// Unsent packets must be handed back, not silently consumed.
func TestSettleRefundsUnsent(t *testing.T) {
	const pps = 1_000_000
	c := newClock()
	l := New(pps, 0, WithClock(c.Now))
	c.Advance(time.Millisecond)

	g, _ := l.Acquire(256, 84)
	if g.Packets == 0 {
		t.Fatal("expected credit")
	}
	// The ring was full: nothing actually went out.
	l.Settle(g, 0, 0)

	g2, _ := l.Acquire(256, 84)
	if g2.Packets < g.Packets {
		t.Errorf("after refunding %d packets the next grant was only %d", g.Packets, g2.Packets)
	}
}

func TestSetRate(t *testing.T) {
	c := newClock()
	l := New(1_000_000, 0, WithClock(c.Now))
	got, _ := drain(l, c, 1, 84, 100, time.Millisecond)
	within(t, "packets at 1Mpps", float64(got), 100_000, 0.05)

	l.SetRate(2_000_000, 0)
	if pps, bps := l.Rate(); pps != 2_000_000 || bps != 0 {
		t.Fatalf("Rate() = %d/%d, want 2000000/0", pps, bps)
	}
	got, _ = drain(l, c, 1, 84, 100, time.Millisecond)
	within(t, "packets at 2Mpps", float64(got), 200_000, 0.05)

	// Dropping to unlimited must take the fast path.
	l.SetRate(0, 0)
	if !l.Unlimited() {
		t.Fatal("SetRate(0,0) should be unlimited")
	}
	if g, _ := l.Acquire(256, 84); g.Packets != 256 {
		t.Errorf("unlimited grant = %d, want 256", g.Packets)
	}
}

func TestScale(t *testing.T) {
	l := New(1_000_000, 2_000_000_000)
	pps, bps := l.Scale(1.1)
	if pps != 1_100_000 || bps != 2_200_000_000 {
		t.Errorf("Scale(1.1) = %d/%d, want 1100000/2200000000", pps, bps)
	}
	pps, bps = l.Scale(0.9)
	if pps != 990_000 || bps != 1_980_000_000 {
		t.Errorf("Scale(0.9) = %d/%d, want 990000/1980000000", pps, bps)
	}

	// An unlimited bucket stays unlimited, so scaling never changes which
	// constraint is active.
	l2 := New(1_000_000, 0)
	pps, bps = l2.Scale(1.1)
	if pps != 1_100_000 || bps != 0 {
		t.Errorf("Scale on a pps-only limiter = %d/%d, want 1100000/0", pps, bps)
	}

	// Repeated decreases must bottom out at 1, never at 0 (which would mean
	// unlimited — the opposite of what the user asked for).
	l3 := New(4, 0)
	for i := 0; i < 40; i++ {
		l3.Scale(0.9)
	}
	if pps, _ := l3.Rate(); pps != 1 {
		t.Errorf("after 40 decreases pps = %d, want 1", pps)
	}
	if l3.Unlimited() {
		t.Error("scaling down must never turn a limit into unlimited")
	}
}

func TestAcquireEdgeCases(t *testing.T) {
	c := newClock()
	l := New(1_000_000, 1e9, WithClock(c.Now))
	c.Advance(time.Second)
	if g, _ := l.Acquire(0, 84); g.Packets != 0 {
		t.Error("Acquire(0) should grant nothing")
	}
	if g, _ := l.Acquire(-5, 84); g.Packets != 0 {
		t.Error("Acquire with a negative count should grant nothing")
	}
	// A zero size estimate must not divide by zero or grant infinity.
	if g, _ := l.Acquire(10, 0); g.Packets > 10 {
		t.Errorf("Acquire with a zero size granted %d, want at most 10", g.Packets)
	}
	// Settle on an empty grant is a no-op.
	l.Settle(Grant{}, 0, 0)
}

func BenchmarkAcquireLimited(b *testing.B) {
	l := New(100_000_000, 0)
	b.ReportAllocs()
	for b.Loop() {
		g, _ := l.Acquire(256, 84)
		_ = g
	}
}

func BenchmarkAcquireUnlimited(b *testing.B) {
	l := New(0, 0)
	b.ReportAllocs()
	for b.Loop() {
		g, _ := l.Acquire(256, 84)
		_ = g
	}
}

func BenchmarkAcquireSettle(b *testing.B) {
	l := New(100_000_000, 1e12)
	b.ReportAllocs()
	for b.Loop() {
		g, _ := l.Acquire(256, 84)
		l.Settle(g, g.Packets, uint64(g.Packets)*84)
	}
}

func BenchmarkAcquireParallel(b *testing.B) {
	l := New(1_000_000_000, 0)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			g, _ := l.Acquire(256, 84)
			_ = g
		}
	})
}

// A batch that is too small costs more in ring bookkeeping than it delivers,
// which measurably undershoots the rate on real hardware. At high rates the
// limiter must therefore hand out substantial batches rather than dribbling.
func TestGrantsAreWorthwhileBatches(t *testing.T) {
	tests := []struct {
		pps      uint64
		minGrant int
	}{
		{14_880_000, 200}, // 10G line rate: full batches
		{1_000_000, 200},  // 1 Mpps: still full batches
		{100_000, 50},     // 100 kpps: ~100 packets a millisecond
	}
	for _, tt := range tests {
		c := newClock()
		l := New(tt.pps, 0, WithClock(c.Now))
		c.Advance(time.Millisecond)
		g, _ := l.Acquire(256, 84)
		if g.Packets < tt.minGrant {
			t.Errorf("at %d pps the first grant was %d packets, want at least %d",
				tt.pps, g.Packets, tt.minGrant)
		}
	}

	// A slow run must not be held back waiting to accumulate a batch: at
	// 1 kpps a single packet per millisecond is exactly right.
	c := newClock()
	l := New(1000, 0, WithClock(c.Now))
	c.Advance(time.Millisecond)
	if g, _ := l.Acquire(256, 84); g.Packets != 1 {
		t.Errorf("at 1 kpps a millisecond should yield 1 packet, got %d", g.Packets)
	}
}

// A limiter built well before it is first used must not open with everything
// it banked in between. This is the real shape of a Wireblast run: the limiter
// is constructed during setup, and the first Acquire comes seconds later, once
// native XDP has finished bouncing the link.
func TestNoBurstAfterAnIdleSetup(t *testing.T) {
	for _, pps := range []uint64{100, 1_000, 100_000, 1_000_000} {
		c := newClock()
		l := New(pps, 0, WithClock(c.Now))
		c.Advance(10 * time.Second) // the link renegotiating

		g, _ := l.Acquire(256, 84)
		// At most a couple of milliseconds of the configured rate, and never
		// more than one batch.
		limit := max(2*float64(pps)/1000, 1)
		if float64(g.Packets) > limit+1 {
			t.Errorf("at %d pps, the first grant after a 10s idle was %d packets; "+
				"want no more than %.0f", pps, g.Packets, limit)
		}
	}
}

// Reset is the belt to that braces: it clears the bucket outright.
func TestReset(t *testing.T) {
	c := newClock()
	l := New(1000, 0, WithClock(c.Now))
	c.Advance(10 * time.Second)
	l.Reset()
	if g, _ := l.Acquire(256, 84); g.Packets != 0 {
		t.Errorf("after Reset the bucket should be empty, got %d packets", g.Packets)
	}
	// ...and it accrues normally from there.
	c.Advance(time.Second)
	if g, _ := l.Acquire(256, 84); g.Packets == 0 {
		t.Error("a second after Reset there should be credit again")
	}
}
