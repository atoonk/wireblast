package dataplane

import (
	"github.com/atoonk/packetio"
	pioafxdp "github.com/atoonk/packetio/afxdp"

	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	afxdp "github.com/atoonk/go-afxdp"

	"github.com/atoonk/wireblast/internal/config"
	"github.com/atoonk/wireblast/internal/discovery"
	"github.com/atoonk/wireblast/internal/generator"
	"github.com/atoonk/wireblast/internal/rate"
	"github.com/atoonk/wireblast/internal/stats"
)

// Transmit-loop tuning.
const (
	// txBatch is how many packets a worker builds per SendFunc call. Large
	// enough to amortise the ring bookkeeping and the rate limiter's mutex,
	// small enough that a rate change or a stop is noticed promptly.
	txBatch = 256

	// jumboTxBatch is txBatch for the multi-buffer path, which stages packets
	// in a buffer of batch x maxFrame bytes per queue. At a 9018-byte MTU the
	// full txBatch would be 2.3 MiB a queue, so use a smaller batch: jumbo
	// packet rates are two orders of magnitude below minimum-size rates, and
	// even one queue saturating 100G only needs a few tens of thousands of
	// batches a second.
	jumboTxBatch = 32

	// rxPollTimeout bounds a blocking receive so cancellation is seen quickly.
	rxPollTimeout = 200 * time.Millisecond

	// linkWait is how long to wait for carrier after attaching. Native XDP
	// reinitialises the driver's rings, and a 10G PHY can take several seconds
	// to renegotiate afterwards.
	linkWait = 20 * time.Second

	// defaultNumFrames is the UMEM depth per queue. This is per socket, so it
	// multiplies by the queue count; 4096 x 2048B is 8 MiB a queue, which
	// keeps a 12-queue run inside 100 MiB.
	defaultNumFrames = 4096
	// defaultRingSize is the depth of all four rings.
	defaultRingSize = 2048
)

// Info describes how the fleet ended up running, for the dashboard and the
// startup banner.
type Info struct {
	Interface string
	Driver    string
	// Backend is the packet-I/O backend this run resolved to, "afxdp" or
	// "mlx5". BackendWhy says why, when the choice was made rather than
	// asked for; Sizing says the same for the queue count.
	Backend    string
	BackendWhy string
	Sizing     string
	Queues     int
	// PerWorker is how many transmit queues one worker drives.
	PerWorker int
	XDPMode   string // "native", "generic", ...
	ZeroCopy  bool
	// NativeAttemptError is the exact error from a failed native attach or
	// bind when the run continued successfully in generic XDP mode.
	NativeAttemptError string
	Filter             string
	FrameSize          int
	NumFrames          int
	// MultiBuffer is true when packets are chained across several UMEM frames,
	// which is how jumbo frames are carried. Worth showing: it is also why a
	// jumbo run may report copy rather than zero-copy.
	MultiBuffer bool
	// Tuning is what the library did to the interface's NAPI settings to make
	// the receive path keep up, e.g. "defer=2 flush=200ms", or "untuned". These
	// are host settings the library restores on close; worth showing.
	Tuning string
	// Pattern and PacketSizes describe the traffic, e.g. "udp" and
	// "fixed 64-byte frames".
	Pattern     string
	PacketSizes string
	// LinkWait is how long the interface actually took to come back after the
	// XDP attach. The library polls for carrier rather than sleeping a fixed
	// amount, so this is the driver's real renegotiation time. Zero when the
	// attachment was reused and no wait was needed.
	LinkWait time.Duration
	// Reused is true when this run inherited an XDP program that was already
	// attached, and so started instantly.
	Reused bool
}

// String renders Info as the single line printed at startup.
// Workers is how many goroutines drive this run's transmit queues.
func (i Info) Workers() int {
	if i.PerWorker < 2 {
		return i.Queues
	}
	return (i.Queues + i.PerWorker - 1) / i.PerWorker
}

func (i Info) String() string {
	zc := "copy"
	if i.ZeroCopy {
		zc = "zero-copy"
	}
	var s string
	if i.Backend == "mlx5" {
		// Direct Verbs has no XDP program and no copy mode to report; what
		// matters instead is how the queues are shared between workers.
		s = fmt.Sprintf("%s: %d queue(s) over %d worker(s), mlx5 Direct Verbs",
			i.Interface, i.Queues, i.Workers())
	} else {
		s = fmt.Sprintf("%s: %d queue(s), %s, %s XDP", i.Interface, i.Queues, zc, i.XDPMode)
	}
	if i.BackendWhy != "" {
		s += " (" + i.BackendWhy + ")"
	}
	if i.Sizing != "" {
		s += ", " + i.Sizing
	}
	if i.MultiBuffer {
		s += ", multi-buffer"
	}
	if i.Driver != "" && i.Backend != "mlx5" {
		s += ", driver " + i.Driver
	}
	if i.Filter != "" {
		s += ", rx filter " + i.Filter
	}
	if i.Tuning != "" && i.Tuning != "untuned" {
		s += ", napi " + i.Tuning
	}
	return s
}

// Runner owns an AF_XDP run end to end: it opens the fleet, drives one
// transmit goroutine (and optionally one receive goroutine) per queue, and
// tears everything down cleanly.
//
// Exactly one goroutine owns each socket's transmit side and at most one owns
// its receive side, which is the concurrency contract go-afxdp requires.
type Runner struct {
	cfg  *config.Config
	res  *discovery.Resolved
	plan FilterPlan

	limiter   *rate.Limiter
	collector *stats.Collector

	fleet *afxdp.Fleet
	// dev is the datapath's view of the fleet: the transmit and receive loops
	// go through packetio so the same code runs over either backend.
	dev  packetio.Device
	info Info

	queues int

	// io is the resolved backend, "afxdp" or "mlx5" — cfg.IO after "auto" has
	// been decided. perWorker is how many transmit queues one worker drives.
	io        string
	perWorker int
	numFrames int
	frameSize int
	maxFrame  int
	// multiBuffer is set when the largest packet does not fit one UMEM frame
	// and has to be chained across several. See multiBufferFor.
	multiBuffer bool

	// frames is the loaded PCAP, nil for generated traffic.
	frames generator.FrameSource

	// session, when set, owns the fleet and keeps it attached between runs.
	// When nil this Runner owns its own fleet and detaches on the way out.
	session *Session

	// kernelBase is the kernel's counters as they stood when this run started.
	// A reused fleet carries the previous run's totals, so they are subtracted
	// out rather than reported as though this run had caused them.
	kernelBase stats.Kernel

	// Set by Start, consumed by Stop and Wait.
	runCtx context.Context
	stop   context.CancelFunc
	wg     sync.WaitGroup

	mu      sync.Mutex
	started bool
	closed  bool

	// txDone counts transmit workers that have finished on their own, which is
	// how a one-pass PCAP replay ends the run.
	txActive atomic.Int32

	fatal atomic.Pointer[error]
	// logf receives rate-limited dataplane errors. Never called from a hot
	// path more than once a second per queue.
	logf func(format string, args ...any)
}

// Options configures a Runner.
type Options struct {
	// Frames is the loaded capture for --mode pcap.
	Frames generator.FrameSource
	// Logf receives occasional dataplane messages. Optional.
	Logf func(format string, args ...any)
	// NumFrames and FrameSize override the UMEM geometry. Zero means default.
	NumFrames int
	FrameSize int
	// Session keeps the XDP program attached across runs. Set it for an
	// interactive session; leave it nil for a one-shot run.
	Session *Session
}

// New prepares a run. It resolves the queue count, builds the filter plan and
// sizes the UMEM, but attaches nothing: call [Runner.Preflight] and then
// [Runner.Run].
func New(cfg *config.Config, res *discovery.Resolved, opts Options) (*Runner, error) {
	if res == nil {
		return nil, errors.New("dataplane: addressing has not been resolved")
	}
	plan, err := DefaultFilterBuilder{}.Plan(cfg, res)
	if err != nil {
		return nil, err
	}

	io, ioWhy := chooseBackend(cfg, res, plan)
	if io == "mlx5" && plan.HardwareUnsupported != "" {
		return nil, fmt.Errorf("--io mlx5 cannot run --rx-mode %s: %s", cfg.RxMode, plan.HardwareUnsupported)
	}
	if io != "mlx5" && cfg.QueuesPerWorker > 1 {
		return nil, fmt.Errorf("--queues-per-worker %d needs the mlx5 backend, and this run uses AF_XDP (%s)",
			cfg.QueuesPerWorker, orUnknown(ioWhy))
	}

	r := &Runner{
		cfg:       cfg,
		res:       res,
		plan:      plan,
		io:        io,
		queues:    1,
		frames:    opts.Frames,
		session:   opts.Session,
		numFrames: orDefault(opts.NumFrames, defaultNumFrames),
		logf:      opts.Logf,
	}
	if r.logf == nil {
		r.logf = func(string, ...any) {}
	}

	// Build one generator up front: it validates the configuration and tells
	// us the largest frame, which sizes the UMEM and, on mlx5, decides the
	// queue count. A receive-only run has none, and sizes its frames for the
	// largest thing it might be sent.
	sizes := "not transmitting"
	if cfg.Transmits() {
		gens, err := r.buildGenerators()
		if err != nil {
			return nil, err
		}
		for _, g := range gens {
			r.maxFrame = max(r.maxFrame, g.MaxFrameLen())
		}
		sizes = gens[0].Describe()
	} else if mtu := res.Link.MTU; mtu > 0 {
		// Size the frames for the largest thing that could arrive: a full-MTU
		// packet behind an Ethernet header and a VLAN tag.
		r.maxFrame = mtu + 18
	}
	r.frameSize = orDefault(opts.FrameSize, frameSizeFor(r.maxFrame, res.Link.Driver))
	r.multiBuffer = multiBufferFor(r.maxFrame, r.frameSize)

	// Now that the frame size is known, size the run: how many queues, and
	// how many one worker drives. Build the generators again at that count,
	// so a configuration that cannot be striped across them fails here rather
	// than at Start.
	// maxFrame is bytes written, which excludes the FCS the NIC appends; line
	// rate counts the whole frame, and so does --packet-size.
	queues, perWorker, sizeWhy := autoQueues(io, cfg, res.Link, r.maxFrame+config.FCSLen, r.plan.Receives())
	r.queues, r.perWorker = queues, perWorker
	if cfg.Transmits() {
		if _, err := r.buildGenerators(); err != nil {
			return nil, err
		}
	}

	r.limiter = rate.New(cfg.PPS, cfg.BPS, rate.WithBatch(txBatch))
	statsOpts := []stats.Option{}
	if !cfg.Transmits() {
		statsOpts = append(statsOpts, stats.WithoutTransmit())
	}
	r.collector = stats.New(queues, cfg.Duration, r.kernelStats, statsOpts...)
	r.info = Info{
		Interface:   res.Link.Name,
		Driver:      res.Link.Driver,
		Backend:     io,
		BackendWhy:  ioWhy,
		Sizing:      sizeWhy,
		Queues:      queues,
		PerWorker:   perWorker,
		Filter:      plan.Summary,
		FrameSize:   r.frameSize,
		NumFrames:   r.numFrames,
		Pattern:     string(cfg.Mode),
		PacketSizes: sizes,
		MultiBuffer: r.multiBuffer,
	}
	return r, nil
}

func orDefault(v, def int) int {
	if v > 0 {
		return v
	}
	return def
}

// frameSizeFor picks a UMEM frame size. 2048 is the library default and covers
// everything up to a standard Ethernet frame; anything larger gets a full page.
//
// A page is the ceiling, not a preference. An aligned-chunk UMEM must satisfy
// XDP_UMEM_MIN_CHUNK_SIZE (2048) <= chunk_size <= PAGE_SIZE, and go-afxdp never
// sets XDP_UMEM_UNALIGNED_CHUNK_FLAG, so asking for more makes XDP_UMEM_REG
// fail with a bare EINVAL. Frames therefore do not grow to fit a jumbo packet.
// Packets bigger than one frame span several, which is what multiBufferFor
// below decides.
//
// AWS ENA's zero-copy datapath needs page-sized (4096) frames; with the default
// 2048 the bind silently falls back to native copy. So floor at 4096 on ena,
// which keeps our own UMEM accounting (memlock preflight, banner) consistent
// with what the driver actually binds. Scoped to ena; other drivers keep the
// smaller, more cache-friendly frames.
func frameSizeFor(maxFrame int, driver string) int {
	size := 2048
	if maxFrame > size || driver == "ena" {
		size = 4096
	}
	// Every Linux architecture pages at 4 KiB or more, so this never bites in
	// practice. It is here so the kernel's ceiling is expressed in the code
	// rather than assumed.
	if page := os.Getpagesize(); size > page {
		size = page
	}
	return size
}

// multiBufferFor reports whether packets have to span several UMEM frames.
//
// This is the jumbo path: the socket binds with XDP_USE_SG and the XDP program
// loads with BPF_F_XDP_HAS_FRAGS, so a packet arrives as a chain of descriptors
// instead of being dropped for not fitting. It costs zero-copy on any device
// reporting xdp-zc-max-segs = 1, and the transmit side has to build through a
// staging buffer, so it stays off unless the traffic actually needs it.
func multiBufferFor(maxFrame, frameSize int) bool {
	return maxFrame > frameSize
}

// maxTxSegs is how many UMEM frames one transmitted packet may span. It mirrors
// the limit go-afxdp enforces, which in turn comes from the kernel building an
// skb of at most CONFIG_MAX_SKB_FRAGS + 1 buffers. Kept here so preflight can
// reject an impossible size with an explanation instead of letting the transmit
// loop fail on every batch.
const maxTxSegs = 18

// framesPerPacket is how many UMEM frames the largest packet occupies.
func framesPerPacket(maxFrame, frameSize int) int {
	if maxFrame <= 0 || frameSize <= 0 {
		return 1
	}
	return (maxFrame + frameSize - 1) / frameSize
}

// buildGenerators makes one generator per queue.
func (r *Runner) buildGenerators() ([]generator.Generator, error) {
	var srcMAC, dstMAC [6]byte
	copy(srcMAC[:], r.res.SrcMAC)
	copy(dstMAC[:], r.res.DstMAC)

	gens := make([]generator.Generator, r.queues)
	for q := range gens {
		g, err := generator.New(generator.Spec{
			Cfg: r.cfg, SrcMAC: srcMAC, DstMAC: dstMAC,
			SrcIP: r.res.SrcIP, Dst: r.res.Dst,
			Queue: q, Queues: r.queues, Frames: r.frames,
		})
		if err != nil {
			return nil, err
		}
		gens[q] = g
	}
	return gens, nil
}

// Preflight runs every safety check, before anything is attached.
func (r *Runner) Preflight(src discovery.Source) *Preflight {
	links, _ := src.Links()
	// Lifting our own soft limit to the hard limit costs nothing and is not a
	// change to the host, so do it before measuring.
	_, _ = RaiseMemlock()
	return RunPreflight(PreflightInput{
		Cfg: r.cfg, Res: r.res, Plan: r.plan,
		Env:         HostEnvironment(src),
		Backend:     r.io,
		Queues:      r.queues,
		MaxFrameLen: r.maxFrame,
		NumFrames:   r.numFrames,
		FrameSize:   r.frameSize,
		MultiBuffer: r.multiBuffer,
		AllLinks:    links,
	})
}

// Plan returns the filter that will be installed.
func (r *Runner) Plan() FilterPlan { return r.plan }

// Info returns how the run is configured, filled in with what the kernel
// actually granted once [Runner.Run] has opened the fleet.
func (r *Runner) Info() Info {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.info
}

// Queues is how many queues the run will use.
func (r *Runner) Queues() int { return r.queues }

// Stats returns the latest published snapshot.
func (r *Runner) Stats() *stats.Snapshot { return r.collector.Snapshot() }

// Collector exposes the stats collector, for a front end that wants to reset
// the interval counters.
func (r *Runner) Collector() *stats.Collector { return r.collector }

// Rate returns the configured packet and bit rates, 0 meaning unlimited.
func (r *Runner) Rate() (pps, bps uint64) { return r.limiter.Rate() }

// SetRate changes the rate while the run is in flight.
func (r *Runner) SetRate(pps, bps uint64) { r.limiter.SetRate(pps, bps) }

// AdjustRate scales both limits, for the +/- hotkeys. An unlimited limit stays
// unlimited, so which constraint is binding does not change.
func (r *Runner) AdjustRate(factor float64) (pps, bps uint64) { return r.limiter.Scale(factor) }

// Paused reports whether transmission is currently paused.
func (r *Runner) Paused() bool { return r.limiter.Paused() }

// SetPaused stops or resumes transmission. Receiving and the dashboard keep
// going either way.
func (r *Runner) SetPaused(p bool) {
	r.limiter.SetPaused(p)
	if p {
		r.collector.SetState(stats.StatePaused)
	} else {
		r.collector.SetState(stats.StateRunning)
	}
}

// Start attaches the XDP program, waits for the link, and spawns the workers.
// It returns as soon as traffic is flowing, so a caller can display what the
// kernel actually granted (see [Runner.Info]) before waiting.
//
// Every Start must be paired with a [Runner.Wait], which is what tears
// everything down.
func (r *Runner) Start(ctx context.Context) error {
	if err := r.open(); err != nil {
		return err
	}

	// Native XDP attach bounces the link on many drivers. Wait for carrier
	// before starting the clock, or the first seconds of the run go nowhere.
	//
	// This polls for carrier rather than sleeping a fixed amount, so a driver
	// that comes back quickly costs nothing; linkWait is only the ceiling.
	// A reused attachment never bounced anything, so there is nothing to wait
	// for — which is the entire point of keeping it.
	if r.fleet != nil && r.res.Link.IsPhysical() && !r.info.Reused {
		began := time.Now()
		up := r.fleet.WaitLinkUp(linkWait)
		r.mu.Lock()
		r.info.LinkWait = time.Since(began)
		r.mu.Unlock()
		if !up {
			r.logf("warning: %s did not come up within %s; transmitting anyway",
				r.res.Link.Name, linkWait)
		}
	}

	// The link is back and traffic can flow, so both clocks start here — not
	// before the attach, whose bounce would otherwise be counted as part of
	// the requested duration and would bank rate credit for packets that
	// could not have gone anywhere.
	r.collector.MarkStart()
	r.limiter.Reset()

	var gens []generator.Generator
	if r.cfg.Transmits() {
		var err error
		if gens, err = r.buildGenerators(); err != nil {
			r.close()
			return err
		}
	}

	// runCtx stops the workers. It is cancelled by the duration timer, by the
	// caller's ctx, by Stop, or when every transmit worker has run out of
	// packets.
	runCtx, stop := context.WithCancel(ctx)
	r.stop = stop

	r.collector.SetState(stats.StateRunning)
	r.collector.Sample()

	r.txActive.Store(int32(len(gens)))
	perWorker := r.perWorker
	if perWorker < 1 {
		perWorker = 1
	}
	nq := r.dev.NumTxQueues()
	if nq > r.queues {
		nq = r.queues
	}

	// txActive counts workers, not queues: a group that finishes is one
	// generator set exhausted, and the run ends when the last group does.
	if perWorker > 1 {
		r.txActive.Store(int32((len(gens) + perWorker - 1) / perWorker))
	}
	for first := 0; first < nq; first += perWorker {
		last := first + perWorker
		if last > nq {
			last = nq
		}
		if first < len(gens) {
			if last > len(gens) {
				last = len(gens)
			}
			qs := make([]packetio.TxQueue, 0, last-first)
			for q := first; q < last; q++ {
				qs = append(qs, r.dev.TxQueue(q))
			}
			r.wg.Add(1)
			go func(first int, qs []packetio.TxQueue, gs []generator.Generator) {
				defer r.wg.Done()
				if len(qs) == 1 {
					r.txLoop(runCtx, first, qs[0], gs[0])
				} else {
					r.txLoopMulti(runCtx, first, qs, gs)
				}
				if r.txActive.Add(-1) == 0 {
					// Every generator is exhausted — a one-pass replay is done.
					stop()
				}
			}(first, qs, gens[first:last])
		}
	}

	if r.plan.Receives() {
		for q := 0; q < r.dev.NumRxQueues() && q < r.queues; q++ {
			r.wg.Add(1)
			go func(q int, rx packetio.RxQueue) {
				defer r.wg.Done()
				r.rxLoop(runCtx, q, rx)
			}(q, r.dev.RxQueue(q))
		}
	}

	// The stats collector runs alongside and publishes a final snapshot when
	// the run ends.
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		r.collector.Run(runCtx, 250*time.Millisecond)
	}()

	// The duration clock starts now, after the link came back, so a run
	// measures time actually spent transmitting.
	if r.cfg.Duration > 0 {
		r.wg.Add(1)
		go func() {
			defer r.wg.Done()
			t := time.NewTimer(r.cfg.Duration)
			defer t.Stop()
			select {
			case <-runCtx.Done():
			case <-t.C:
				stop()
			}
		}()
	}
	r.runCtx = runCtx
	return nil
}

// Stop asks the run to wind down. [Runner.Wait] then returns once everything
// has drained.
func (r *Runner) Stop() {
	if r.stop != nil {
		r.collector.SetState(stats.StateStopping)
		r.stop()
	}
}

// Wait blocks until the run ends, then stops the workers, drains the transmit
// rings, detaches the XDP program and closes the sockets.
//
// It always tears down what Start created — whether the run ended normally, on
// a signal, or on an error.
func (r *Runner) Wait() error {
	defer r.close()

	<-r.runCtx.Done()
	r.collector.SetState(stats.StateStopping)
	r.stop()
	r.wg.Wait()

	// Let the kernel finish whatever is still on the transmit rings, so the
	// final counts include packets that were in flight at the stop.
	r.drain()
	r.collector.SetState(stats.StateComplete)
	r.collector.Sample()

	if p := r.fatal.Load(); p != nil {
		return *p
	}
	return nil
}

// Run is Start followed by Wait: it transmits until the duration expires or
// ctx is cancelled, then shuts everything down cleanly.
func (r *Runner) Run(ctx context.Context) error {
	if err := r.Start(ctx); err != nil {
		return err
	}
	return r.Wait()
}

// fleetKey is what this run needs from an AF_XDP attachment. A session can
// hand back an already-attached fleet only when every part of it matches.
func (r *Runner) fleetKey() fleetKey {
	o := r.umemOptions()
	return fleetKey{
		iface:       r.res.Link.Name,
		queues:      r.queues,
		filter:      r.plan.Summary,
		numFrames:   o.NumFrames,
		frameSize:   o.FrameSize,
		receives:    r.plan.Receives(),
		multiBuffer: r.multiBuffer,
	}
}

// umemOptions sizes the UMEM and the four rings for this run.
//
// The split matters. A transmit-only run never receives, so almost the whole
// frame pool goes to transmit — but the fill ring must still be backed by the
// receive pool, so the receive rings shrink to match rather than the transmit
// pool growing without limit. When a receive mode is on, both directions get a
// fair share.
func (r *Runner) umemOptions() afxdp.Options {
	o := afxdp.Options{
		NumFrames:              r.numFrames,
		FrameSize:              r.frameSize,
		TxRingNumDescs:         defaultRingSize,
		CompletionRingNumDescs: defaultRingSize,
	}
	switch {
	case !r.cfg.Transmits():
		// Nothing is transmitted, so hand almost everything to the receive
		// side and keep only a token transmit pool.
		o.TxFrames = 64
		o.FillRingNumDescs = defaultRingSize
		o.RxRingNumDescs = defaultRingSize
	case r.plan.Receives():
		o.TxFrames = r.numFrames / 2
		o.FillRingNumDescs = defaultRingSize
		o.RxRingNumDescs = defaultRingSize
	default:
		const idleRx = 256
		o.TxFrames = r.numFrames - idleRx
		o.FillRingNumDescs = idleRx
		o.RxRingNumDescs = idleRx
	}
	return o
}

// open attaches the XDP program and binds the sockets.
func (r *Runner) open() error {
	if err := r.attach(); err != nil {
		return err
	}
	// Baseline the kernel's counters once the fleet is in place, and do it
	// with the lock released: readKernel takes the same mutex, and a Go mutex
	// is not reentrant — taking it twice deadlocks the whole run.
	if k, err := r.readKernel(); err == nil {
		r.kernelBase = k
	}
	return nil
}

// attach opens the fleet, or borrows the session's already-attached one, and
// records what the kernel granted.
func (r *Runner) attach() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.started {
		return errors.New("dataplane: already started")
	}

	openMode := func(mode afxdp.Option) func() (*afxdp.Fleet, error) {
		return func() (*afxdp.Fleet, error) {
			opts := []afxdp.Option{
				// WithOptions replaces the whole struct, so it must come first;
				// the options after it layer on top.
				afxdp.WithOptions(r.umemOptions()),
				afxdp.WithFilter(r.plan.Matches...),
				afxdp.WithQueues(r.queues),
				// Without need-wakeup a starved driver spins in ksoftirqd instead
				// of parking, burning cores while forwarding nothing.
				afxdp.WithNeedWakeup(),
			}
			if r.multiBuffer {
				// Packets bigger than a frame have to chain across several. This
				// also lets the program attach at a jumbo MTU on drivers that
				// otherwise cap XDP to a single buffer.
				opts = append(opts, afxdp.WithMultiBuffer())
			}
			if r.plan.KeepManagement {
				// Spare ARP, ND, SSH and DNS from the match-all redirect so the box
				// stays reachable while everything else is captured.
				opts = append(opts, afxdp.WithKeepManagement())
			}
			opts = append(opts, mode)
			return afxdp.Open(r.res.Link.Name, opts...)
		}
	}
	var nativeAttemptError error
	open := func() (*afxdp.Fleet, error) {
		result, err := openAFXDPNativeFirst(
			openMode(afxdp.WithDriverMode()),
			openMode(afxdp.WithGenericMode()),
			r.logf,
		)
		nativeAttemptError = result.nativeAttemptError
		return result.fleet, err
	}

	if r.io == "mlx5" {
		// Direct Verbs: no program to attach, no filter, and nothing to reuse
		// between runs, so none of the fleet machinery below applies. The
		// frame region is the backend's to size -- it knows how many hardware
		// rings sit behind each queue -- unless the user pinned a UMEM depth.
		frames := 0
		if r.numFrames != defaultNumFrames {
			frames = nextPow2(r.queues * r.numFrames)
		}
		dev, steering, err := openMLX5(r.res.Link.Name, r.queues, r.frameSize, frames,
			r.plan.Steering, !r.plan.Receives())
		if err != nil {
			return err
		}
		r.dev = dev
		r.started = true
		if steering != "" {
			// What the card was actually told, so the startup line shows the
			// rule and not just the intent.
			r.info.Filter = steering
		}
		r.info.Queues = dev.NumTxQueues()
		r.info.FrameSize = r.frameSize
		r.info.NumFrames = frames
		return nil
	}

	var (
		fleet  *afxdp.Fleet
		reused bool
		err    error
	)
	if r.session != nil {
		fleet, reused, err = r.session.Fleet(r.fleetKey(), open)
	} else {
		fleet, err = open()
	}
	if err != nil {
		return fmt.Errorf("open AF_XDP on %s: %w", r.res.Link.Name, err)
	}
	r.fleet = fleet
	r.dev = pioafxdp.NewDevice(fleet)
	r.started = true
	r.info.Reused = reused
	if nativeAttemptError != nil {
		r.info.NativeAttemptError = nativeAttemptError.Error()
	}

	if info, err := fleet.Info(); err == nil {
		r.info.Queues = info.NumQueues
		r.info.XDPMode = info.XDPMode
		r.info.ZeroCopy = info.ZeroCopy
		r.info.FrameSize = info.FrameSize
		r.info.NumFrames = info.NumFrames
		if info.Driver != "" {
			r.info.Driver = info.Driver
		}
		if info.Filter != "" {
			r.info.Filter = info.Filter
		}
		r.info.Tuning = info.Tuning
	}
	return nil
}

// openAFXDPNativeFirst makes the library's mode fallback visible without
// teaching Wireblast anything about individual drivers. The native opener
// still selects zero-copy first and native copy second. Generic mode is tried
// only after the same attach or bind failures for which go-afxdp's automatic
// mode would continue; validation and setup errors are returned immediately.
func openAFXDPNativeFirst(
	native, generic func() (*afxdp.Fleet, error),
	logf func(string, ...any),
) (afxdpOpenResult, error) {
	fleet, nativeErr := native()
	if nativeErr == nil {
		return afxdpOpenResult{fleet: fleet}, nil
	}
	result := afxdpOpenResult{nativeAttemptError: nativeErr}
	if !nativeFailureCanFallback(nativeErr) {
		return result, nativeErr
	}
	logf("native AF_XDP attempt failed: %v; trying generic XDP copy mode", nativeErr)

	fleet, genericErr := generic()
	if genericErr == nil {
		result.fleet = fleet
		return result, nil
	}
	return result, errors.Join(
		fmt.Errorf("native AF_XDP: %w", nativeErr),
		fmt.Errorf("generic XDP copy mode: %w", genericErr),
	)
}

type afxdpOpenResult struct {
	fleet              *afxdp.Fleet
	nativeAttemptError error
}

// nativeFailureCanFallback mirrors go-afxdp v0.11.0's mode loop conservatively.
// Its forced-native Open call wraps exhausted attach and bind attempts in this
// form; errors returned before that loop are not mode-specific and must not be
// retried as generic XDP.
func nativeFailureCanFallback(err error) bool {
	msg := err.Error()
	if !strings.HasPrefix(msg, "afxdp: could not open ") {
		return false
	}
	return strings.Contains(msg, ": native attach:") || strings.Contains(msg, ": native bind:")
}

// close releases this run's hold on the fleet.
//
// When a session owns the fleet the XDP program deliberately stays attached,
// so the next run starts instantly; the session detaches it when the program
// exits. Only a Runner that opened its own fleet closes it here.
func (r *Runner) close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || (r.fleet == nil && r.dev == nil) {
		return
	}
	r.closed = true
	if r.fleet == nil {
		// A backend that owns no fleet: the device is the whole thing.
		dev := r.dev
		r.dev = nil
		if dev != nil {
			_ = dev.Close()
		}
		return
	}
	fleet := r.fleet
	r.fleet = nil
	r.dev = nil
	if r.session != nil {
		return // still attached, and still the session's to close
	}
	if err := fleet.Close(); err != nil {
		r.logf("closing AF_XDP: %v", err)
	}
}

// drain gives the kernel a moment to finish sending what is already queued and
// reclaims the completions, so the final statistics are not short.
func (r *Runner) drain() {
	r.mu.Lock()
	dev := r.dev
	r.mu.Unlock()
	if dev == nil {
		return
	}
	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		pending := 0
		for q := 0; q < dev.NumTxQueues(); q++ {
			tx := dev.TxQueue(q)
			tx.Complete(tx.NumCompleted())
			pending += tx.NumInFlight()
		}
		if pending == 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// kernelStats adapts the library's counters to the stats package's shape.
// kernelStats reports what this run has caused, with the counters from any
// previous run on the same fleet subtracted out.
func (r *Runner) kernelStats() (stats.Kernel, error) {
	k, err := r.readKernel()
	if err != nil {
		return stats.Kernel{}, err
	}
	return subtractKernel(k, r.kernelBase), nil
}

// readKernel reads the raw cumulative counters for the open fleet.
func (r *Runner) readKernel() (stats.Kernel, error) {
	r.mu.Lock()
	fleet := r.fleet
	r.mu.Unlock()
	if fleet == nil {
		return stats.Kernel{}, nil
	}
	fs, err := fleet.Stats()
	if err != nil {
		return stats.Kernel{}, err
	}
	k := stats.Kernel{
		Queues:          fs.Queues,
		RxPackets:       fs.RxPackets,
		TxPackets:       fs.TxPackets,
		RxDropped:       fs.RxDropped,
		RxRingFull:      fs.RxRingFull,
		RxFillRingEmpty: fs.RxFillRingEmpty,
		RxInvalidDescs:  fs.RxInvalidDescs,
		TxInvalidDescs:  fs.TxInvalidDescs,
		TxRingEmpty:     fs.TxRingEmpty,
		PerQueue:        make([]stats.KernelQueue, 0, len(fs.PerQueue)),
	}
	for q, s := range fs.PerQueue {
		k.PerQueue = append(k.PerQueue, stats.KernelQueue{
			Queue:           q,
			RxPackets:       s.Received,
			TxPackets:       s.Transmitted,
			RxDropped:       s.KernelStats.Rx_dropped,
			RxRingFull:      s.KernelStats.Rx_ring_full,
			RxFillRingEmpty: s.KernelStats.Rx_fill_ring_empty_descs,
			RxInvalidDescs:  s.KernelStats.Rx_invalid_descs,
			TxInvalidDescs:  s.KernelStats.Tx_invalid_descs,
			TxRingEmpty:     s.KernelStats.Tx_ring_empty_descs,
		})
	}
	return k, nil
}

// setFatal records the first unrecoverable dataplane error.
func (r *Runner) setFatal(err error) {
	r.fatal.CompareAndSwap(nil, &err)
}

// closedSocket reports whether an error just means the socket went away during
// shutdown, which is not worth reporting.
func closedSocket(err error) bool {
	return errors.Is(err, net.ErrClosed)
}

// subtractKernel returns a minus b, per counter, so a run on a reused fleet
// reports its own drops and errors rather than inheriting the previous run's.
//
// Counters only ever climb, but a fresh attach resets them to zero while the
// baseline still holds the old totals; clamping at zero keeps that transition
// from producing nonsense.
func subtractKernel(a, b stats.Kernel) stats.Kernel {
	return a.Since(b)
}

// nextPow2 rounds up to a power of two, which is what the frame region wants.
func nextPow2(n int) int {
	p := 1
	for p < n {
		p <<= 1
	}
	return p
}
