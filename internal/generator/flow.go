// Package generator turns a configuration into a stream of packets.
//
// Every traffic pattern implements the same small [Generator] interface, so
// the dataplane's transmit loop is identical whether it is sending UDP, TCP
// SYNs, an IMIX or a PCAP replay. Each queue gets its own Generator instance,
// owned by that queue's transmit goroutine alone, so nothing here locks and
// nothing allocates after construction.
package generator

import (
	"encoding/binary"
	"net/netip"
)

// Flow is one flow's tuple. The other tuple components — IP protocol and VLAN
// ID — are fixed for a run and live in the packet template.
type Flow struct {
	SrcIP   [4]byte
	DstIP   [4]byte
	SrcPort uint16
	DstPort uint16
}

// FlowSpec describes the deterministic flow space a run walks.
//
// Flow n is a pure function of n: the same configuration always produces the
// same tuples in the same order, whatever the queue count, which is what makes
// a test reproducible and a capture comparable between runs.
type FlowSpec struct {
	SrcIP netip.Addr   // fixed for every flow
	Dst   netip.Prefix // /32 for a single destination; wider to cycle
	// SrcPort is the first source port; flow n uses SrcPort+n.
	SrcPort uint16
	// DstPort is the destination port. It is fixed unless VaryDstPort is set,
	// because the usual test points many flows at one server port.
	DstPort     uint16
	VaryDstPort bool
	// Flows is how many distinct flows exist. Must be at least 1.
	Flows int
	// Scatter walks the flow space in a scrambled order instead of counting
	// through it. The set of flows is identical either way, and the order is
	// still completely deterministic — it just stops consecutive packets
	// carrying consecutive ports, which some receivers hash badly.
	Scatter bool
}

// At returns the tuple for flow n. n is taken modulo Flows, so callers may
// pass a freely incrementing counter.
func (s FlowSpec) At(n int) Flow {
	flows := s.Flows
	if flows < 1 {
		flows = 1
	}
	n = ((n % flows) + flows) % flows // tolerate a negative n
	if s.Scatter {
		n = scatter(n, flows)
	}

	f := Flow{
		SrcIP:   s.SrcIP.As4(),
		DstIP:   nthUsable(s.Dst, n),
		SrcPort: portAt(s.SrcPort, n),
		DstPort: s.DstPort,
	}
	if s.VaryDstPort {
		f.DstPort = portAt(s.DstPort, n)
	}
	return f
}

// portAt returns the port for flow n, counting up from start.
//
// The 16-bit space wraps, which is fine — but port 0 is never a sensible
// source or destination, so it is skipped. Two flows out of 65536 therefore
// share port 1; that is the whole cost of wrapping safely.
func portAt(start uint16, n int) uint16 {
	p := uint16(uint32(start) + uint32(uint32(n)&0xffff))
	if p == 0 {
		return 1
	}
	return p
}

// nthUsable returns the n-th usable address in a prefix, cycling.
//
// For an ordinary IPv4 subnet (/30 and shorter) the network and broadcast
// addresses are skipped: sending to them is either dropped or, worse, flooded
// to every host in the subnet. A /31 (RFC 3021 point-to-point link) and a /32
// have no such reserved addresses, so both of their addresses are usable.
func nthUsable(p netip.Prefix, n int) [4]byte {
	if !p.Addr().Is4() {
		return [4]byte{}
	}
	base := p.Masked().Addr().As4()
	network := binary.BigEndian.Uint32(base[:])
	bits := p.Bits()

	var usable, offset uint32
	if bits >= 31 {
		usable = uint32(1) << (32 - bits) // 1 for /32, 2 for /31
	} else {
		usable = (uint32(1) << (32 - bits)) - 2
		offset = 1 // start after the network address
	}
	addr := network + offset + uint32(n)%usable

	var out [4]byte
	binary.BigEndian.PutUint32(out[:], addr)
	return out
}

// UsableAddresses reports how many destination addresses a prefix contributes,
// following the same network/broadcast rules as nthUsable. It is used to tell
// the user how many distinct destinations a CIDR really provides.
func UsableAddresses(p netip.Prefix) uint32 {
	if !p.Addr().Is4() {
		return 0
	}
	if p.Bits() >= 31 {
		return uint32(1) << (32 - p.Bits())
	}
	return (uint32(1) << (32 - p.Bits())) - 2
}

// queueCursor walks a queue's share of the flow space.
//
// Queue q of Q starts at flow q and steps by Q, so the queues together cover
// every flow exactly once per cycle and no two queues send the same flow at
// the same time. When there are fewer flows than queues — the common
// flows=1 case — the modulo folds them back onto the same flows, so every
// queue stays busy at full rate rather than sitting idle.
type queueCursor struct {
	idx   int
	step  int
	flows int
}

func newQueueCursor(queue, queues, flows int) queueCursor {
	if queues < 1 {
		queues = 1
	}
	if flows < 1 {
		flows = 1
	}
	return queueCursor{idx: queue % flows, step: queues, flows: flows}
}

// next returns the current flow index and advances the cursor.
func (c *queueCursor) next() int {
	i := c.idx
	c.idx += c.step
	if c.idx >= c.flows {
		c.idx %= c.flows
	}
	return i
}

// scatter permutes [0, flows) deterministically.
//
// Multiplying by a step coprime to flows is a bijection over the range, so
// every flow is still visited exactly once per cycle — the order is simply
// spread out instead of consecutive. It needs no table and no state, which
// matters because this runs per packet.
func scatter(n, flows int) int {
	if flows < 3 {
		return n
	}
	return (n * scatterStride(flows)) % flows
}

// scatterStride picks the multiplier. Starting near the golden ratio of the
// range gives a well-spread walk; stepping to the first coprime value keeps it
// a bijection.
func scatterStride(flows int) int {
	s := int(float64(flows) * 0.6180339887)
	if s < 2 {
		s = 2
	}
	if s%2 == 0 {
		s++
	}
	for range flows {
		if gcd(s, flows) == 1 {
			return s
		}
		if s += 2; s >= flows {
			s = 1
		}
	}
	return 1
}

func gcd(a, b int) int {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}
