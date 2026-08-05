package generator

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/atoonk/wireblast/internal/config"
	"github.com/atoonk/wireblast/internal/packet"
	"github.com/atoonk/wireblast/internal/stats"
)

// FrameSource supplies the frames of a loaded capture. It is an interface so
// the generator can be tested without touching a file, and so the PCAP reader
// stays in its own package.
type FrameSource interface {
	// Len is how many frames the capture holds.
	Len() int
	// Frame returns the i-th frame's bytes and the gap since the frame before
	// it (zero for the first). The returned slice must not be modified.
	Frame(i int) (data []byte, gap time.Duration)
	// MaxLen and MeanLen are the largest and mean frame lengths in bytes.
	MaxLen() int
	MeanLen() int
	// Describe summarises the capture for the review screen.
	Describe() string
	// Warnings lists anything about the capture worth telling the user before
	// replaying it, such as packets truncated by the capture's snaplen.
	Warnings() []string
}

// Finite is implemented by generators that can run out of packets — currently
// only a one-pass PCAP replay. The transmit loop asks how many packets are
// still available so it never requests a batch it cannot fill, and stops when
// nothing is left.
type Finite interface {
	// Remaining returns how many packets are left, or -1 when unbounded.
	Remaining() int
}

// pcapGen replays a capture. Frames are copied out of the loaded store
// verbatim, with an optional MAC rewrite, and nothing is allocated per packet.
//
// Queue assignment is deliberately simple. Looping replay runs on every queue,
// each cycling the whole capture independently, so throughput scales with
// queues while packet order within a queue is exactly the capture's order. A
// one-pass replay runs on queue 0 only, so the capture goes out exactly once,
// in order — which is the whole point of asking for one pass.
type pcapGen struct {
	src    FrameSource
	idx    int
	loop   bool
	oneUse bool // one-pass: stop after a single cycle

	overrideMACs   bool
	srcMAC, dstMAC [6]byte
	vlan           uint16

	pace     bool // preserve the capture's original inter-packet gaps
	nextGap  time.Duration
	avgWire  int
	maxFrame int
	describe string
}

func newPCAPGen(s Spec) (Generator, error) {
	cfg := s.Cfg
	if s.Frames == nil || s.Frames.Len() == 0 {
		return nil, fmt.Errorf("generator: pcap mode needs a loaded capture")
	}
	// One-pass replay belongs to queue 0 alone, so the capture is transmitted
	// exactly once rather than once per queue.
	if !cfg.PCAPLoop && s.Queue != 0 {
		return &emptyGen{describe: s.Frames.Describe()}, nil
	}

	g := &pcapGen{
		src:      s.Frames,
		loop:     cfg.PCAPLoop,
		oneUse:   !cfg.PCAPLoop,
		vlan:     uint16(cfg.VLAN),
		pace:     cfg.PCAPTiming == config.PcapOriginal,
		avgWire:  s.Frames.MeanLen() + wireOverhead,
		maxFrame: s.Frames.MaxLen(),
		describe: s.Frames.Describe(),
	}
	// MAC override is opt-in: a replay preserves the captured addresses unless
	// the user explicitly supplies one.
	if cfg.SrcMAC != "" || cfg.DstMAC != "" {
		g.overrideMACs = true
		g.srcMAC, g.dstMAC = s.SrcMAC, s.DstMAC
	}
	if g.pace {
		_, g.nextGap = g.src.Frame(0)
		// Only a replay that honours the capture's timing is a Pacer. Wrapping
		// it in a distinct type is what makes the transmit loop's gen.(Pacer)
		// check mean "actually paces", not merely "is a PCAP replay". A rate-
		// timed replay returns the bare generator, which is not a Pacer, so it
		// goes down the batched path like every other generator. Without this
		// split a rate-timed replay would still be sent one packet at a time,
		// and under a rate limit the per-packet lock traffic collapses the rate.
		return pacedPCAP{g}, nil
	}
	return g, nil
}

// pacedPCAP is a replay honouring the capture's own inter-packet gaps. It is
// the only generator that implements [Pacer]; see newPCAPGen for why the two
// timing modes are different types.
type pacedPCAP struct{ *pcapGen }

// Delay implements [Pacer]: the gap the capture recorded before the next frame.
func (g pacedPCAP) Delay() time.Duration { return g.nextGap }

func (g *pcapGen) Next(frame []byte) (int, stats.Class) {
	if g.oneUse && g.idx >= g.src.Len() {
		return 0, stats.ClassOther
	}
	data, _ := g.src.Frame(g.idx % g.src.Len())
	n := copy(frame, data)
	if g.overrideMACs && n >= 12 {
		copy(frame[0:6], g.dstMAC[:])
		copy(frame[6:12], g.srcMAC[:])
	}

	g.idx++
	if g.pace {
		if g.oneUse && g.idx >= g.src.Len() {
			g.nextGap = 0
		} else {
			_, g.nextGap = g.src.Frame(g.idx % g.src.Len())
		}
	}
	return n, classify(data)
}

// Remaining implements [Finite] for a one-pass replay.
func (g *pcapGen) Remaining() int {
	if !g.oneUse {
		return -1
	}
	if n := g.src.Len() - g.idx; n > 0 {
		return n
	}
	return 0
}

func (g *pcapGen) AvgWireBytes() int { return g.avgWire }
func (g *pcapGen) MaxFrameLen() int  { return g.maxFrame }
func (g *pcapGen) Describe() string  { return g.describe }

// emptyGen is the generator handed to queues that have no work: the queues
// beyond queue 0 during a one-pass PCAP replay.
type emptyGen struct{ describe string }

func (g *emptyGen) Next([]byte) (int, stats.Class) { return 0, stats.ClassOther }
func (g *emptyGen) AvgWireBytes() int              { return 64 }
func (g *emptyGen) MaxFrameLen() int               { return 0 }
func (g *emptyGen) Remaining() int                 { return 0 }
func (g *emptyGen) Describe() string               { return g.describe }

// classify inspects just enough of a frame to bucket it for statistics: the
// EtherType, one optional 802.1Q tag, and the IPv4 protocol byte. It reads
// fixed offsets and never allocates.
func classify(frame []byte) stats.Class {
	off := 12
	if len(frame) < off+2 {
		return stats.ClassOther
	}
	et := binary.BigEndian.Uint16(frame[off:])
	if et == packet.EtherTypeVLAN {
		off += 4
		if len(frame) < off+2 {
			return stats.ClassOther
		}
		et = binary.BigEndian.Uint16(frame[off:])
	}
	ip := off + 2 // start of the IP header
	switch et {
	case packet.EtherTypeIPv4:
		if len(frame) < ip+10 {
			return stats.ClassOther
		}
		return classifyProto(frame[ip+9]) // IPv4 protocol field
	case packet.EtherTypeIPv6:
		if len(frame) < ip+7 {
			return stats.ClassOther
		}
		// Next Header at +6. If it is an IPv6 extension header rather than the
		// L4 protocol itself, this counts as Other; the receive path does not
		// walk the extension-header chain.
		return classifyProto(frame[ip+6])
	}
	return stats.ClassOther
}

func classifyProto(proto byte) stats.Class {
	switch proto {
	case packet.ProtoUDP:
		return stats.ClassUDP
	case packet.ProtoTCP:
		return stats.ClassTCP
	}
	return stats.ClassOther
}

// Classify reports the protocol bucket of a received frame. The receive loop
// uses it, and it is the same code path the PCAP generator uses on transmit so
// both directions count the same way.
func Classify(frame []byte) stats.Class { return classify(frame) }
