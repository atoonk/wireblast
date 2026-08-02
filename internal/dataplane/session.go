package dataplane

import (
	"sync"

	afxdp "github.com/atoonk/go-afxdp"
)

// fleetKey is everything about a run that the AF_XDP attachment itself depends
// on.
//
// Two runs with the same key can share one open fleet. Anything else needs a
// fresh attach — and on a native-XDP driver that costs a link bounce of several
// seconds, so the comparison is worth getting exactly right. Erring towards
// reuse would silently run a test against the wrong XDP program; erring towards
// reattaching only costs time.
type fleetKey struct {
	iface  string
	queues int
	// filter is the installed XDP program, identified by its description.
	// Every parameter that changes the program — the receive mode, its ports,
	// its CIDRs — changes this string.
	filter string
	// The UMEM geometry, which is fixed at bind time.
	numFrames int
	frameSize int
	// receives changes the frame split between the transmit and receive pools
	// and the ring depths, so it is part of the bind too.
	receives bool
}

// Session keeps an AF_XDP fleet attached across several runs.
//
// Without it, every rerun detaches the XDP program and attaches it again,
// which reinitialises the driver's queues and drops carrier for the better
// part of ten seconds on a 10G NIC. Since almost nothing people change between
// runs — the rate, the duration, the flow count, the packet contents — has any
// bearing on the attachment, that wait is nearly always avoidable.
//
// A Session is owned by the interactive front end and closed when it exits.
// The one-shot --no-tui path does not use one: it runs once and leaves.
type Session struct {
	mu    sync.Mutex
	key   fleetKey
	fleet *afxdp.Fleet
	held  bool
}

// NewSession returns an empty session. Nothing is attached until the first run
// asks for a fleet.
func NewSession() *Session { return &Session{} }

// Fleet returns a fleet matching key, reusing the one already attached when it
// matches and opening a new one otherwise. It reports whether the fleet was
// reused, which is how the caller knows it can skip waiting for the link.
//
// open is only called when a new attach is genuinely needed.
func (s *Session) Fleet(key fleetKey, open func() (*afxdp.Fleet, error)) (*afxdp.Fleet, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.held && s.key == key {
		return s.fleet, true, nil
	}
	// The attachment has to change, so the old one goes first — two XDP
	// programs cannot share an interface, and the driver would refuse.
	s.closeLocked()

	fleet, err := open()
	if err != nil {
		return nil, false, err
	}
	s.key, s.fleet, s.held = key, fleet, true
	return fleet, false, nil
}

// Close detaches whatever is currently held. It is safe to call more than once.
func (s *Session) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closeLocked()
}

func (s *Session) closeLocked() error {
	if !s.held {
		return nil
	}
	s.held = false
	fleet := s.fleet
	s.fleet = nil
	if fleet == nil {
		return nil
	}
	return fleet.Close()
}

// Attached reports whether the session currently holds an open fleet.
func (s *Session) Attached() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.held
}
