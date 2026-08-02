// Package stats collects Wireblast's traffic counters and turns them into
// periodic snapshots.
//
// The split is deliberate: the transmit and receive loops touch nothing but a
// handful of per-queue atomic counters, and every bit of arithmetic,
// formatting and rate calculation happens in a separate collector goroutine.
// Nothing here is called from a packet hot path except [Counters.AddTx] and
// [Counters.AddRx], which are a few atomic adds and no allocation.
//
// The same [Snapshot] feeds the TUI dashboard and the --no-tui periodic
// output, so both report identical numbers.
package stats

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// State is what the run is currently doing.
type State int

const (
	StateStarting State = iota
	StateRunning
	StatePaused
	StateStopping
	StateComplete
)

func (s State) String() string {
	switch s {
	case StateStarting:
		return "starting"
	case StateRunning:
		return "running"
	case StatePaused:
		return "paused"
	case StateStopping:
		return "stopping"
	case StateComplete:
		return "complete"
	}
	return "unknown"
}

// Class is the protocol bucket a packet is counted under. Classification is
// done by the generator (which already knows) on transmit, and by a minimal
// header peek on receive.
type Class uint8

const (
	ClassOther Class = iota
	ClassUDP
	ClassTCP
)

// cacheLine is the padding applied between per-queue counter blocks so two
// queues on different cores never share a cache line. 128 bytes covers the
// 64-byte lines of x86-64 and arm64 plus adjacent-line prefetching.
const cacheLine = 128

// Counters is one queue's counters. Each queue gets its own, so the transmit
// and receive loops never contend with each other.
//
// The fields are atomic because the collector reads them concurrently, but
// they are only ever written by that queue's own goroutine.
type Counters struct {
	TxPackets atomic.Uint64
	TxBytes   atomic.Uint64 // total Ethernet frame bytes, including the FCS
	TxUDP     atomic.Uint64
	TxTCP     atomic.Uint64
	TxOther   atomic.Uint64
	TxErrors  atomic.Uint64

	RxPackets atomic.Uint64
	RxBytes   atomic.Uint64
	RxUDP     atomic.Uint64
	RxTCP     atomic.Uint64
	RxOther   atomic.Uint64
	RxErrors  atomic.Uint64

	_ [cacheLine]byte
}

// AddTx records a batch of transmitted packets of one protocol class. It is
// called once per batch, not once per packet.
func (c *Counters) AddTx(packets int, bytes uint64, class Class) {
	if packets <= 0 {
		return
	}
	c.TxPackets.Add(uint64(packets))
	c.TxBytes.Add(bytes)
	switch class {
	case ClassUDP:
		c.TxUDP.Add(uint64(packets))
	case ClassTCP:
		c.TxTCP.Add(uint64(packets))
	default:
		c.TxOther.Add(uint64(packets))
	}
}

// AddRx records one received packet and its protocol class.
func (c *Counters) AddRx(bytes uint64, class Class) {
	c.RxPackets.Add(1)
	c.RxBytes.Add(bytes)
	switch class {
	case ClassUDP:
		c.RxUDP.Add(1)
	case ClassTCP:
		c.RxTCP.Add(1)
	default:
		c.RxOther.Add(1)
	}
}

// Kernel holds the counters the AF_XDP library reports, copied into a
// library-independent shape so this package does not depend on go-afxdp (and
// so tests need no AF_XDP at all).
type Kernel struct {
	Queues          int
	RxPackets       uint64
	TxPackets       uint64
	RxDropped       uint64
	RxRingFull      uint64
	RxFillRingEmpty uint64
	RxInvalidDescs  uint64
	TxInvalidDescs  uint64
	TxRingEmpty     uint64
	PerQueue        []KernelQueue
}

// KernelQueue is one queue's slice of the kernel counters, used to point at a
// queue that is dropping or stalled.
type KernelQueue struct {
	Queue      int
	RxPackets  uint64
	TxPackets  uint64
	RxDropped  uint64
	RxRingFull uint64
}

// KernelFunc reports the current kernel counters. It is injected so the
// collector can be tested without an AF_XDP fleet.
type KernelFunc func() (Kernel, error)

// Totals is one direction's counters at a point in time.
type Totals struct {
	Packets uint64
	// Bytes is the total Ethernet frame size, including the 4-byte FCS — the
	// same definition as --packet-size, so a run of 64-byte frames reports an
	// average frame size of 64.
	Bytes  uint64
	UDP    uint64
	TCP    uint64
	Other  uint64
	Errors uint64
	Drops  uint64
}

func (t Totals) sub(o Totals) Totals {
	return Totals{
		Packets: t.Packets - o.Packets,
		Bytes:   t.Bytes - o.Bytes,
		UDP:     t.UDP - o.UDP,
		TCP:     t.TCP - o.TCP,
		Other:   t.Other - o.Other,
		Errors:  t.Errors - o.Errors,
		Drops:   t.Drops - o.Drops,
	}
}

// AvgFrame is the mean total frame size in bytes, including the FCS.
func (t Totals) AvgFrame() float64 {
	if t.Packets == 0 {
		return 0
	}
	return float64(t.Bytes) / float64(t.Packets)
}

// Rates are the per-second figures computed over the sampling window.
//
// The two bit rates are the same two T-Rex reports, and are shown under those
// names: FrameBPS is L2, WireBPS is L1.
type Rates struct {
	PPS float64

	// FrameBPS is **L2**: the Ethernet frame itself, including its 4-byte FCS.
	//
	// Note that the kernel's own netdev counters — what bwm-ng, iftop, nload
	// and `ip -s link` report — exclude the FCS by specification, so they read
	// 4 bytes per packet below this. That is about 6% at 64-byte frames and 1%
	// at IMIX, and it is a different measurement rather than a disagreement.
	FrameBPS float64

	// WireBPS is **L1**: the frame plus the 20 bytes of physical framing every
	// packet costs — 7-byte preamble, 1-byte start-frame delimiter and 12-byte
	// interframe gap. This is link utilisation, and it is the unit --bps is
	// measured in: 10G line rate means 10 Gbit/s of L1.
	WireBPS float64
}

// History tuning. One point a second is what a sparkline wants: fine enough to
// see a rate change land, coarse enough that a minute fits on screen.
const (
	historyInterval = time.Second
	// historyLen is generous — a wide terminal can show well over a hundred
	// seconds, and running out of history on a big screen would be the obvious
	// way to get this wrong. Five minutes costs about 20 KB.
	historyLen = 300
)

// HistoryPoint is one second of the run, kept so the dashboard can show where
// the rate has been rather than only where it is.
type HistoryPoint struct {
	At     time.Time
	TX, RX Rates
}

// wireOverheadPerFrame is the bytes of physical framing beyond the frame
// itself: 7-byte preamble + 1-byte start-frame delimiter + 12-byte interframe
// gap. The FCS is already counted inside the frame bytes, which is why this is
// 20 and not 24. Adding it to L2 gives L1.
const wireOverheadPerFrame = 20

// Snapshot is an immutable view of the run, published by the collector and
// consumed by the TUI and the noninteractive printer.
type Snapshot struct {
	At        time.Time
	Elapsed   time.Duration
	Remaining time.Duration // 0 when the run has no duration limit
	State     State

	// TX and RX are the visible counters, measured since the last interval
	// reset. TotalTX and TotalRX are the lifetime figures, which the final
	// summary reports and which an interval reset never disturbs.
	TX, RX           Totals
	TotalTX, TotalRX Totals
	TXRate, RXRate   Rates

	// IntervalSince is when the visible counters were last reset.
	IntervalSince time.Time

	Kernel Kernel

	// Problems names queues that are dropping or stalled, ready to display.
	Problems []string

	// Transmits is false for a receive-only run, so the status line can leave
	// out a transmit half that will only ever read zero.
	Transmits bool

	// History is one point per second, oldest first, for the dashboard's
	// sparklines. It spans at most historyLen seconds.
	History []HistoryPoint
}

// Collector owns the per-queue counters and publishes snapshots.
type Collector struct {
	queues    []Counters
	kernel    KernelFunc
	start     time.Time
	limit     time.Duration // configured run duration, 0 for open-ended
	now       func() time.Time
	transmits bool

	state atomic.Int32
	snap  atomic.Pointer[Snapshot]

	mu         sync.Mutex
	baseTX     Totals // counters at the last interval reset
	baseRX     Totals
	baseKernel Kernel // kernel drop/error counters at the last interval reset
	baseAt     time.Time
	window     []sample // ring of recent samples, for smoothed rates
	windowAt   int

	// history is a ring of per-second rates. historyN counts how many points
	// have been written, so a partly-filled ring reads back in the right order.
	history     []HistoryPoint
	historyN    int
	lastHistory time.Time
}

type sample struct {
	at time.Time
	tx Totals
	rx Totals
}

// Option configures a Collector.
type Option func(*Collector)

// WithClock replaces the time source, for tests.
func WithClock(now func() time.Time) Option {
	return func(c *Collector) { c.now = now }
}

// WithoutTransmit marks the run as receive-only, so the status line does not
// carry a transmit half that will only ever read zero.
func WithoutTransmit() Option {
	return func(c *Collector) { c.transmits = false }
}

// WithWindow sets how many samples the rate average spans. With the default
// 250ms sampling interval, 4 samples means rates are averaged over a second
// and refreshed four times a second.
func WithWindow(n int) Option {
	return func(c *Collector) {
		if n > 1 {
			c.window = make([]sample, n)
		}
	}
}

// New creates a collector for numQueues queues. kernel may be nil, in which
// case the kernel counters stay zero (useful in tests and before the fleet is
// open).
func New(numQueues int, limit time.Duration, kernel KernelFunc, opts ...Option) *Collector {
	c := &Collector{
		queues:    make([]Counters, numQueues),
		kernel:    kernel,
		limit:     limit,
		now:       time.Now,
		window:    make([]sample, 4),
		history:   make([]HistoryPoint, historyLen),
		transmits: true,
	}
	for _, o := range opts {
		o(c)
	}
	c.start = c.now()
	c.baseAt = c.start
	c.lastHistory = c.start
	for i := range c.window {
		c.window[i] = sample{at: c.start}
	}
	c.snap.Store(c.build())
	return c
}

// Queue returns the counters for one queue. The dataplane hands each worker
// its own pointer at startup so the hot path never indexes a slice.
func (c *Collector) Queue(i int) *Counters { return &c.queues[i] }

// NumQueues returns how many queues the collector tracks.
func (c *Collector) NumQueues() int { return len(c.queues) }

// SetState records what the run is doing; it shows up in the next snapshot.
func (c *Collector) SetState(s State) { c.state.Store(int32(s)) }

// State returns the current run state.
func (c *Collector) State() State { return State(c.state.Load()) }

// Snapshot returns the most recently published snapshot. It never blocks and
// never allocates, so the TUI can call it as often as it repaints.
func (c *Collector) Snapshot() *Snapshot { return c.snap.Load() }

// MarkStart restarts the run clock as of now.
//
// The dataplane calls this once the link is up. Attaching native XDP bounces
// the link for several seconds on many drivers, and counting that wait as part
// of the run would understate every average rate and make a 30-second run
// report 40 seconds.
func (c *Collector) MarkStart() {
	now := c.now()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.start = now
	c.baseAt = now
	for i := range c.window {
		c.window[i] = sample{at: now}
	}
	c.windowAt = 0

	// Drop any history from before traffic could flow. Several seconds of
	// enforced silence while the link renegotiates is not part of the run, and
	// a flat lead-in on the graph would only be misread.
	c.historyN = 0
	c.lastHistory = now
}

// ResetInterval zeroes the visible counters while leaving the lifetime totals
// untouched. This is the `r` hotkey.
func (c *Collector) ResetInterval() {
	tx, rx := c.readTotals()
	k := c.readKernel()
	// The kernel-sourced drops and errors are cumulative and only merged into the
	// totals in build(), so fold them into the baseline here too. Otherwise the
	// Errors/Drops counter and the per-queue problem lines would keep showing the
	// lifetime figure and never clear on reset.
	tx.Errors += k.TxInvalidDescs
	rx.Drops = k.RxDropped + k.RxRingFull
	c.mu.Lock()
	c.baseTX, c.baseRX, c.baseKernel, c.baseAt = tx, rx, k, c.now()
	c.mu.Unlock()
	c.snap.Store(c.build())
}

// Run samples and publishes a snapshot every interval until ctx is cancelled.
// It publishes one final snapshot on the way out so the summary reflects the
// last packets sent.
func (c *Collector) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			c.Sample()
			return
		case <-t.C:
			c.Sample()
		}
	}
}

// Sample takes a reading now and publishes it. Run calls it on a ticker; the
// dataplane also calls it directly when it wants a fresh final snapshot.
func (c *Collector) Sample() *Snapshot {
	s := c.build()
	c.snap.Store(s)
	return s
}

// readTotals sums the per-queue counters. This is the only place that walks
// every queue, and it runs a few times a second, not per packet.
func (c *Collector) readTotals() (tx, rx Totals) {
	for i := range c.queues {
		q := &c.queues[i]
		tx.Packets += q.TxPackets.Load()
		tx.Bytes += q.TxBytes.Load()
		tx.UDP += q.TxUDP.Load()
		tx.TCP += q.TxTCP.Load()
		tx.Other += q.TxOther.Load()
		tx.Errors += q.TxErrors.Load()

		rx.Packets += q.RxPackets.Load()
		rx.Bytes += q.RxBytes.Load()
		rx.UDP += q.RxUDP.Load()
		rx.TCP += q.RxTCP.Load()
		rx.Other += q.RxOther.Load()
		rx.Errors += q.RxErrors.Load()
	}
	return tx, rx
}

// readKernel reads the current kernel counters, returning the zero value if no
// kernel source is configured or the read fails, so a failing read never takes
// the snapshot down with it.
func (c *Collector) readKernel() Kernel {
	if c.kernel == nil {
		return Kernel{}
	}
	k, err := c.kernel()
	if err != nil {
		return Kernel{}
	}
	return k
}

func (c *Collector) build() *Snapshot {
	now := c.now()
	tx, rx := c.readTotals()

	k := c.readKernel()
	rx.Drops = k.RxDropped + k.RxRingFull
	tx.Errors += k.TxInvalidDescs

	s := &Snapshot{
		At:        now,
		State:     State(c.state.Load()),
		TotalTX:   tx,
		TotalRX:   rx,
		Kernel:    k,
		Transmits: c.transmits,
	}

	c.mu.Lock()
	s.Elapsed = now.Sub(c.start)
	s.TX = tx.sub(c.baseTX)
	s.RX = rx.sub(c.baseRX)
	baseKernel := c.baseKernel
	s.IntervalSince = c.baseAt

	// Rates come from the oldest sample still in the window, so they are
	// smoothed over roughly a second rather than jumping with each tick.
	oldest := c.window[c.windowAt]
	c.window[c.windowAt] = sample{at: now, tx: tx, rx: rx}
	c.windowAt = (c.windowAt + 1) % len(c.window)
	c.mu.Unlock()

	if c.limit > 0 {
		if r := c.limit - s.Elapsed; r > 0 {
			s.Remaining = r
		}
	}
	if dt := now.Sub(oldest.at).Seconds(); dt > 0 {
		s.TXRate = rateOver(tx, oldest.tx, dt)
		s.RXRate = rateOver(rx, oldest.rx, dt)
	}

	// Sampling happens four times a second; history is recorded once. The
	// rates are already smoothed over the window, so the point that lands is
	// representative rather than whichever quarter-second it fell on.
	c.mu.Lock()
	if now.Sub(c.lastHistory) >= historyInterval {
		c.lastHistory = now
		c.history[c.historyN%len(c.history)] = HistoryPoint{At: now, TX: s.TXRate, RX: s.RXRate}
		c.historyN++
	}
	s.History = c.historyLocked()
	c.mu.Unlock()

	s.Problems = problems(k, baseKernel)
	return s
}

// historyLocked copies the ring out in order, oldest first. The caller must
// hold the mutex.
//
// A fresh slice per sample is four small allocations a second on a display
// path, which buys an immutable Snapshot that the TUI can read without any
// locking of its own.
func (c *Collector) historyLocked() []HistoryPoint {
	n := min(c.historyN, len(c.history))
	if n == 0 {
		return nil
	}
	out := make([]HistoryPoint, 0, n)
	start := c.historyN - n
	for i := range n {
		out = append(out, c.history[(start+i)%len(c.history)])
	}
	return out
}

func rateOver(now, then Totals, dt float64) Rates {
	dp := float64(now.Packets - then.Packets)
	db := float64(now.Bytes - then.Bytes)
	return Rates{
		PPS:      dp / dt,
		FrameBPS: db * 8 / dt,
		WireBPS:  (db + dp*wireOverheadPerFrame) * 8 / dt,
	}
}

// problems turns the per-queue kernel counters into short, displayable
// descriptions of queues that are losing packets.
// problems names queues that are dropping or stalling, counting only what has
// happened since the last reset (base) so the `r` hotkey clears them.
func problems(k, base Kernel) []string {
	baseQ := make(map[int]KernelQueue, len(base.PerQueue))
	for _, q := range base.PerQueue {
		baseQ[q.Queue] = q
	}
	var out []string
	for _, q := range k.PerQueue {
		b := baseQ[q.Queue]
		switch {
		case q.RxRingFull > b.RxRingFull:
			out = append(out, formatQueueProblem(q.Queue, "rx ring full", q.RxRingFull-b.RxRingFull))
		case q.RxDropped > b.RxDropped:
			out = append(out, formatQueueProblem(q.Queue, "rx dropped", q.RxDropped-b.RxDropped))
		}
	}
	return out
}
