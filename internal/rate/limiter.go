// Package rate implements Wireblast's aggregate packet- and bit-rate limiter.
//
// One Limiter governs the whole run, not one per queue: --pps 1M means a
// million packets per second in total, whether that is spread over one queue
// or twelve. Queue workers draw credit in batches, so the shared state is
// touched once per few hundred packets rather than once per packet, and the
// steady-state path allocates nothing.
//
// Both limits are token buckets. When both are set a packet needs credit from
// both, so the binding constraint is simply whichever runs out first. A limit
// of zero means "no limit" for that bucket; both zero means line rate, which
// takes a lock-free fast path.
package rate

import (
	"sync"
	"sync/atomic"
	"time"
)

// Sleep bounds used when a worker has to wait for credit. The lower bound
// keeps a low-rate run from spinning on the clock; the upper bound keeps rate
// changes and pause/resume responsive.
const (
	MinWait = 50 * time.Microsecond
	MaxWait = 2 * time.Millisecond
)

// maxWireBits is the largest number of on-the-wire bits a single frame can
// cost (a 9018-byte jumbo frame plus framing). The bit bucket's capacity never
// drops below this, or a large frame could never accumulate enough credit.
const maxWireBits = (9018 + 20) * 8

// Grant is permission to transmit, returned by [Limiter.Acquire]. It carries
// the estimate the limiter charged for, so [Limiter.Settle] can correct the
// accounting once the true sizes are known.
type Grant struct {
	// Packets is how many packets may be sent. Zero means no credit yet.
	Packets int
	// chargedBits is what the bit bucket was debited, based on the caller's
	// per-packet estimate.
	chargedBits float64
}

// Limiter is an aggregate packet/bit rate limiter shared by every queue.
//
// The zero value is not usable; call [New].
type Limiter struct {
	// fast is 1 when the limiter is unlimited and not paused, letting Acquire
	// return without touching the mutex at all.
	fast atomic.Bool
	// paused is duplicated as an atomic so callers can read it cheaply.
	paused atomic.Bool

	mu     sync.Mutex
	pps    float64 // 0 means unlimited
	bps    float64 // 0 means unlimited
	tokenP float64
	tokenB float64
	capP   float64
	capB   float64
	last   time.Time

	batch int
	now   func() time.Time
}

// Option configures a Limiter.
type Option func(*Limiter)

// WithClock replaces the time source, for tests.
func WithClock(now func() time.Time) Option {
	return func(l *Limiter) { l.now = now }
}

// WithBatch sets the batch size the bucket capacities are sized against. It
// should match the transmit loop's batch. Default 256.
func WithBatch(n int) Option {
	return func(l *Limiter) {
		if n > 0 {
			l.batch = n
		}
	}
}

// New creates a limiter for the given packet and bit rates. Either may be 0,
// meaning that limit is not enforced; both 0 means unlimited.
//
// The bit rate is measured in on-the-wire bits, so callers should charge each
// frame its full framing cost (frame bytes + 20) * 8.
func New(pps, bps uint64, opts ...Option) *Limiter {
	l := &Limiter{batch: 256, now: time.Now}
	for _, o := range opts {
		o(l)
	}
	l.last = l.now()
	l.setRateLocked(pps, bps)
	// Start empty rather than full: a run should ramp into its rate, not open
	// with a burst.
	l.tokenP, l.tokenB = 0, 0
	return l
}

// Unlimited reports whether neither limit is in force.
func (l *Limiter) Unlimited() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.pps == 0 && l.bps == 0
}

// Rate returns the configured packet and bit rates, 0 meaning unlimited.
func (l *Limiter) Rate() (pps, bps uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return uint64(l.pps), uint64(l.bps)
}

// SetRate changes both limits while the run is in flight. Credit already
// accrued is discarded so the new rate takes effect immediately rather than
// after a burst at the old one.
func (l *Limiter) SetRate(pps, bps uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.accrueLocked()
	l.setRateLocked(pps, bps)
	if l.tokenP > l.capP {
		l.tokenP = l.capP
	}
	if l.tokenB > l.capB {
		l.tokenB = l.capB
	}
}

// Scale multiplies both limits by factor, which is how the +/- hotkeys adjust
// the rate. A limit that is unlimited stays unlimited, so which constraint is
// active does not change. Rates are clamped to at least 1 so repeated
// decreases cannot reach zero and silently mean "unlimited".
func (l *Limiter) Scale(factor float64) (pps, bps uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.accrueLocked()
	scale := func(v float64) uint64 {
		if v == 0 {
			return 0 // unlimited stays unlimited
		}
		n := v * factor
		if n < 1 {
			n = 1
		}
		return uint64(n)
	}
	np, nb := scale(l.pps), scale(l.bps)
	l.setRateLocked(np, nb)
	if l.tokenP > l.capP {
		l.tokenP = l.capP
	}
	if l.tokenB > l.capB {
		l.tokenB = l.capB
	}
	return np, nb
}

func (l *Limiter) setRateLocked(pps, bps uint64) {
	l.pps, l.bps = float64(pps), float64(bps)
	// Cap each bucket at about two milliseconds of credit. This is what stops
	// a long pause, a stalled queue or a clock jump from being followed by a
	// giant burst.
	//
	// Two milliseconds rather than one: credit left over after a batch has to
	// survive until the next accrual, or every round trip quietly discards the
	// remainder and the delivered rate lands below the requested one.
	//
	// The floors here are minimal — just enough that a bucket can always reach
	// one packet. Acquire raises them to exactly what the batch it is about to
	// grant requires, so a slow run never banks a burst it could not have sent
	// anyway.
	l.capP = max(2*l.pps/1000, 1)
	l.capB = max(2*l.bps/1000, maxWireBits)
	l.fast.Store(l.pps == 0 && l.bps == 0 && !l.paused.Load())
}

// SetPaused stops or resumes granting. While paused no credit accrues, so a
// long pause is not followed by a catch-up burst.
func (l *Limiter) SetPaused(p bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.paused.Load() == p {
		return
	}
	// Fold in the time up to the pause, then freeze the clock at "now" so the
	// paused interval accrues nothing.
	l.accrueLocked()
	l.paused.Store(p)
	l.last = l.now()
	if p {
		// Drop accrued credit as well, so resuming starts clean.
		l.tokenP, l.tokenB = 0, 0
	}
	l.fast.Store(l.pps == 0 && l.bps == 0 && !p)
}

// Paused reports whether transmission is currently paused.
func (l *Limiter) Paused() bool { return l.paused.Load() }

// Reset discards accrued credit and restarts the clock.
//
// The dataplane calls this the moment traffic can actually flow. A limiter
// built before the XDP program is attached would otherwise spend the several
// seconds of link bounce quietly accruing credit for packets nothing could
// have sent.
func (l *Limiter) Reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.last = l.now()
	l.tokenP, l.tokenB = 0, 0
}

// Acquire asks for permission to send up to maxPackets packets, each estimated
// to cost wireBytes bytes on the wire. It returns a Grant and, when the grant
// is empty, how long the caller should wait before asking again.
//
// The estimate only has to be close: [Limiter.Settle] reconciles the bit
// bucket against the real sizes afterwards, so variable-size traffic (IMIX,
// PCAP replay) still converges on the requested bit rate.
func (l *Limiter) Acquire(maxPackets, wireBytes int) (Grant, time.Duration) {
	if l.fast.Load() {
		return Grant{Packets: maxPackets}, 0
	}
	if maxPackets <= 0 {
		return Grant{}, MinWait
	}
	if wireBytes < 1 {
		wireBytes = 1
	}
	bitsEach := float64(wireBytes) * 8

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.paused.Load() {
		l.last = l.now()
		return Grant{}, MaxWait
	}
	l.accrueLocked()

	// Wait until there is a batch worth sending. Handing out one or two
	// packets at a time would spend more time on ring bookkeeping and kicks
	// than on packets, and measurably undershoots the requested rate.
	need := l.minGrantLocked(maxPackets, bitsEach)

	// Trim any credit beyond what this batch could actually use. Without this
	// a bucket idle since construction — a run waiting out the several-second
	// link bounce that native XDP causes — would open with a burst of
	// everything it banked while nothing could be transmitted anyway.
	if hi := max(l.capP, float64(need)); l.tokenP > hi {
		l.tokenP = hi
	}
	if hi := max(l.capB, float64(need)*bitsEach); l.tokenB > hi {
		l.tokenB = hi
	}

	if l.pps > 0 && l.tokenP < float64(need) {
		return Grant{}, l.waitForLocked(float64(need)-l.tokenP, l.pps, 0, 0)
	}
	if l.bps > 0 && l.tokenB < float64(need)*bitsEach {
		return Grant{}, l.waitForLocked(0, 0, float64(need)*bitsEach-l.tokenB, l.bps)
	}

	n := maxPackets
	if l.pps > 0 {
		n = min(n, int(l.tokenP))
	}
	if l.bps > 0 {
		n = min(n, int(l.tokenB/bitsEach))
	}
	if n <= 0 {
		return Grant{}, MinWait
	}

	l.tokenP -= float64(n)
	charged := float64(0)
	if l.bps > 0 {
		charged = float64(n) * bitsEach
		l.tokenB -= charged
	}
	return Grant{Packets: n, chargedBits: charged}, 0
}

// minGrantLocked is the smallest batch worth releasing: roughly a
// millisecond's worth of the configured rate, never more than the caller's
// batch size and never less than one packet.
//
// The millisecond bound is what keeps both ends honest. At 1 Mpps it means
// full 256-packet batches, so the transmit loop is efficient enough to hit the
// rate; at 1 kpps it drops to a single packet, so a slow run still ticks along
// smoothly instead of arriving in clumps.
func (l *Limiter) minGrantLocked(maxPackets int, bitsEach float64) int {
	perMs := float64(maxPackets)
	if l.pps > 0 {
		perMs = min(perMs, l.pps/1000)
	}
	if l.bps > 0 && bitsEach > 0 {
		perMs = min(perMs, l.bps/1000/bitsEach)
	}
	return min(max(int(perMs), 1), min(maxPackets, l.batch))
}

// Settle reconciles a grant against what was actually transmitted: sent is how
// many of the granted packets went out, and sentWireBytes their true total
// on-the-wire size. Unsent packets are refunded and any difference between the
// estimate and reality is corrected, which can leave a bucket in debt — that
// debt is repaid by the next accrual, so the long-run rate stays exact.
//
// Callers may skip Settle when the grant was fully used and the estimate was
// exact, which is the fixed-size case.
func (l *Limiter) Settle(g Grant, sent int, sentWireBytes uint64) {
	if g.Packets == 0 {
		return
	}
	if l.fast.Load() {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if unsent := g.Packets - sent; unsent > 0 {
		l.tokenP += float64(unsent)
		if l.tokenP > l.capP {
			l.tokenP = l.capP
		}
	}
	// Give back the whole estimate and charge what was really used. Refunds
	// are capped, but the correction is not: overspending must be repaid.
	l.tokenB += g.chargedBits
	if l.tokenB > l.capB {
		l.tokenB = l.capB
	}
	l.tokenB -= float64(sentWireBytes) * 8
}

// accrueLocked adds the credit earned since the last call. The caller must
// hold the mutex.
func (l *Limiter) accrueLocked() {
	now := l.now()
	dt := now.Sub(l.last)
	l.last = now
	if dt <= 0 {
		return
	}
	secs := dt.Seconds()
	if l.pps > 0 {
		if l.tokenP += l.pps * secs; l.tokenP > l.capP {
			l.tokenP = l.capP
		}
	}
	if l.bps > 0 {
		if l.tokenB += l.bps * secs; l.tokenB > l.capB {
			l.tokenB = l.capB
		}
	}
}

// waitForLocked returns how long to sleep until the given shortfalls are made
// up, clamped so a worker neither spins nor sleeps through a rate change.
func (l *Limiter) waitForLocked(needP, rateP, needB, rateB float64) time.Duration {
	var secs float64
	if rateP > 0 && needP > 0 {
		secs = needP / rateP
	}
	if rateB > 0 && needB > 0 {
		if s := needB / rateB; s > secs {
			secs = s
		}
	}
	d := time.Duration(secs * float64(time.Second))
	return min(max(d, MinWait), MaxWait)
}
