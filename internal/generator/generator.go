package generator

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/atoonk/wireblast/internal/config"
	"github.com/atoonk/wireblast/internal/packet"
	"github.com/atoonk/wireblast/internal/stats"
)

// Generator produces the packets one queue transmits.
//
// A Generator is owned by exactly one transmit goroutine. Implementations must
// not allocate in Next: the whole point is that a 10 Gbit/s run does no
// per-packet memory work.
type Generator interface {
	// Next writes the next packet into frame and returns how many bytes it
	// wrote — the Ethernet frame length excluding the FCS the NIC appends —
	// along with the protocol class for statistics.
	Next(frame []byte) (int, stats.Class)

	// AvgWireBytes is the mean on-the-wire size of a packet, including the 20
	// bytes of preamble, start-frame delimiter and interframe gap. The rate
	// limiter charges this per packet up front and reconciles against the real
	// sizes afterwards, so it only has to be a good estimate.
	AvgWireBytes() int

	// MaxFrameLen is the largest frame this generator can emit, so the
	// dataplane can check it fits in a UMEM frame before attaching anything.
	MaxFrameLen() int

	// Describe is a short human-readable summary of the packet-size behaviour,
	// e.g. "fixed 64-byte frames" or "IMIX 7:4:1 (64/594/1518B)".
	Describe() string
}

// Pacer is implemented by generators that carry their own timing, currently
// only PCAP replay preserving a capture's original inter-packet gaps. When a
// Generator also implements Pacer the transmit loop sends one packet at a time
// and waits the returned delay in between, obeying whichever of the pacer and
// the rate limiter is slower.
type Pacer interface {
	// Delay is how long to wait before producing the next packet.
	Delay() time.Duration
}

// wireOverhead is the on-the-wire framing a frame costs beyond the bytes we
// write: 7 preamble + 1 start-frame delimiter + 4 FCS + 12 interframe gap.
const wireOverhead = 24

// Spec is everything the factory needs to build a queue's generator. The
// addressing is already resolved: discovery has picked the source address and
// the next-hop MAC before this point.
type Spec struct {
	Cfg    *config.Config
	SrcMAC [6]byte
	DstMAC [6]byte
	SrcIP  netip.Addr
	Dst    netip.Prefix

	// Queue and Queues place this generator in the flow space.
	Queue, Queues int

	// Frames is the PCAP replay source, required for config.ModePCAP.
	Frames FrameSource
}

// New builds the generator for one queue.
func New(s Spec) (Generator, error) {
	if s.Queues < 1 {
		s.Queues = 1
	}
	switch s.Cfg.Mode {
	case config.ModeUDP:
		return newFlowGen(s, packet.ProtoUDP, nil)
	case config.ModeTCPSYN:
		return newFlowGen(s, packet.ProtoTCP, nil)
	case config.ModeIMIX:
		return newFlowGen(s, packet.ProtoUDP, DefaultIMIX)
	case config.ModeRaw:
		return newRawGen(s)
	case config.ModePCAP:
		return newPCAPGen(s)
	case config.ModeReceive:
		return nil, fmt.Errorf("generator: %q transmits nothing, so it has no generator", s.Cfg.Mode)
	}
	return nil, fmt.Errorf("generator: unsupported mode %q", s.Cfg.Mode)
}

// flowGen generates IPv4 UDP or TCP packets across a deterministic flow space,
// optionally varying the frame size through a size mix (IMIX).
type flowGen struct {
	tmpl   *packet.Template
	spec   FlowSpec
	cursor queueCursor
	class  stats.Class

	// sizes is the expanded frame-size cycle, nil for fixed-size traffic.
	sizes   []int
	sizeIdx int

	avgWire  int
	maxFrame int
	describe string
}

func newFlowGen(s Spec, proto uint8, mix []MixEntry) (*flowGen, error) {
	cfg := s.Cfg
	if !s.SrcIP.IsValid() || !s.Dst.IsValid() {
		return nil, fmt.Errorf("generator: source and destination addresses must be set")
	}
	if s.SrcIP.Is4() != s.Dst.Addr().Is4() {
		return nil, fmt.Errorf("generator: source %s and destination %s are different address families",
			s.SrcIP, s.Dst)
	}

	g := &flowGen{
		spec: FlowSpec{
			SrcIP:       s.SrcIP,
			Dst:         s.Dst,
			SrcPort:     cfg.SrcPort,
			DstPort:     cfg.DstPort,
			VaryDstPort: cfg.VaryDstPort,
			Flows:       max(cfg.Flows, 1),
			Scatter:     cfg.FlowOrder == config.FlowRandom,
		},
		cursor: newQueueCursor(s.Queue, s.Queues, max(cfg.Flows, 1)),
	}
	switch proto {
	case packet.ProtoUDP:
		g.class = stats.ClassUDP
	case packet.ProtoTCP:
		g.class = stats.ClassTCP
	}

	// Frame sizes. config.PacketSize counts the FCS; the template holds the
	// bytes we actually write, which is four fewer.
	frameLen := config.FrameBytes(cfg.PacketSize)
	maxFrame := frameLen
	if mix != nil {
		// Raise any mix entry below the smallest frame this family and tagging
		// can actually put on the wire, so the frames built, the sizes reported
		// and the bytes on the wire all agree. Two floors combine: a tagged frame
		// cannot go below 68 (the NIC pads anything smaller), and an IPv6 frame
		// needs 20 more header bytes than IPv4. The mix drives the size entirely
		// here, so --packet-size plays no part (it is not even range-checked).
		minTotal := config.MinPacketSize
		hdr := packet.EthHeaderLen + packet.IPv4HeaderLen + packet.UDPHeaderLen + config.FCSLen
		if !s.SrcIP.Is4() {
			hdr += packet.IPv6HeaderLen - packet.IPv4HeaderLen
		}
		if cfg.VLAN != 0 {
			minTotal += config.VLANTagLen
			hdr += config.VLANTagLen
		}
		minTotal = max(minTotal, hdr)

		effMix := make([]MixEntry, len(mix))
		for i, e := range mix {
			if e.Size < minTotal {
				e.Size = minTotal
			}
			effMix[i] = e
		}
		sizes, err := ExpandMix(effMix)
		if err != nil {
			return nil, err
		}
		g.sizes = make([]int, len(sizes))
		maxFrame = 0
		for i, total := range sizes {
			g.sizes[i] = config.FrameBytes(total)
			maxFrame = max(maxFrame, g.sizes[i])
		}
		frameLen = g.sizes[0]
		g.describe = DescribeMix(effMix)
	} else {
		g.describe = fmt.Sprintf("fixed %d-byte frames", cfg.PacketSize)
	}

	first := g.spec.At(g.cursor.idx)
	tmpl, err := packet.Build(packet.Spec{
		SrcMAC: s.SrcMAC, DstMAC: s.DstMAC,
		VLAN:        uint16(cfg.VLAN),
		SrcIP:       s.SrcIP,
		DstIP:       first.DstIP,
		Proto:       proto,
		SrcPort:     first.SrcPort,
		DstPort:     first.DstPort,
		FrameLen:    frameLen,
		Cap:         maxFrame,
		PayloadByte: byte(cfg.PayloadByte),
	})
	if err != nil {
		return nil, err
	}
	g.tmpl = tmpl
	g.maxFrame = maxFrame

	// The rate limiter's per-packet estimate: exact for fixed sizes, the mean
	// for a mix (Settle corrects the difference afterwards).
	if g.sizes != nil {
		total := 0
		for _, n := range g.sizes {
			total += n + wireOverhead
		}
		g.avgWire = total / len(g.sizes)
	} else {
		g.avgWire = frameLen + wireOverhead
	}
	return g, nil
}

func (g *flowGen) Next(frame []byte) (int, stats.Class) {
	f := g.spec.At(g.cursor.next())
	g.tmpl.SetSrcIP(f.SrcIP)
	g.tmpl.SetDstIP(f.DstIP)
	g.tmpl.SetSrcPort(f.SrcPort)
	g.tmpl.SetDstPort(f.DstPort)

	if g.sizes != nil {
		// SetFrameLen only fails for a length outside the template's capacity,
		// which the constructor already sized for; ignore it here rather than
		// branch on an impossible error in the hot path.
		_ = g.tmpl.SetFrameLen(g.sizes[g.sizeIdx])
		if g.sizeIdx++; g.sizeIdx == len(g.sizes) {
			g.sizeIdx = 0
		}
	}
	return g.tmpl.WriteTo(frame), g.class
}

func (g *flowGen) AvgWireBytes() int { return g.avgWire }
func (g *flowGen) MaxFrameLen() int  { return g.maxFrame }
func (g *flowGen) Describe() string  { return g.describe }

// rawGen emits a fixed Ethernet frame with a chosen EtherType and payload
// pattern. There is nothing to vary, so it is the cheapest generator there is.
type rawGen struct {
	tmpl     *packet.Template
	frameLen int
	describe string
}

func newRawGen(s Spec) (*rawGen, error) {
	cfg := s.Cfg
	frameLen := config.FrameBytes(cfg.PacketSize)
	tmpl, err := packet.Build(packet.Spec{
		SrcMAC: s.SrcMAC, DstMAC: s.DstMAC,
		VLAN:        uint16(cfg.VLAN),
		EtherType:   uint16(cfg.EtherType),
		FrameLen:    frameLen,
		PayloadByte: byte(cfg.PayloadByte),
	})
	if err != nil {
		return nil, err
	}
	return &rawGen{
		tmpl:     tmpl,
		frameLen: frameLen,
		describe: fmt.Sprintf("fixed %d-byte frames, EtherType 0x%04x", cfg.PacketSize, cfg.EtherType),
	}, nil
}

func (g *rawGen) Next(frame []byte) (int, stats.Class) {
	return g.tmpl.WriteTo(frame), stats.ClassOther
}

func (g *rawGen) AvgWireBytes() int { return g.frameLen + wireOverhead }
func (g *rawGen) MaxFrameLen() int  { return g.frameLen }
func (g *rawGen) Describe() string  { return g.describe }
