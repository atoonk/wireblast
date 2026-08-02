package generator

import (
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"

	"github.com/atoonk/wireblast/internal/config"
	"github.com/atoonk/wireblast/internal/packet"
	"github.com/atoonk/wireblast/internal/stats"
)

var (
	testSrcMAC = [6]byte{0x3c, 0xec, 0xef, 0xb4, 0xc4, 0x3e}
	testDstMAC = [6]byte{0x3c, 0xec, 0xef, 0xb4, 0xc2, 0xdc}
)

func spec(t *testing.T, mut func(*config.Config)) Spec {
	t.Helper()
	cfg := config.Default()
	cfg.Interface = "eth0"
	cfg.SrcIP = "192.168.0.99"
	cfg.DstIP = "192.168.0.2"
	if mut != nil {
		mut(&cfg)
	}
	dst, err := config.ParseDst(cfg.DstIP)
	if err != nil {
		t.Fatalf("bad dst in test config: %v", err)
	}
	return Spec{
		Cfg: &cfg, SrcMAC: testSrcMAC, DstMAC: testDstMAC,
		SrcIP: netip.MustParseAddr(cfg.SrcIP), Dst: dst,
		Queue: 0, Queues: 1,
	}
}

// tuple pulls the flow tuple back out of a generated frame, so tests assert on
// what really went on the wire rather than on internal state.
type tuple struct {
	vlan             uint16
	proto            uint8
	srcIP, dstIP     [4]byte
	srcPort, dstPort uint16
	frameLen         int
}

func parse(t *testing.T, frame []byte, n int) tuple {
	t.Helper()
	frame = frame[:n]
	out := tuple{frameLen: n}
	off := 12
	if binary.BigEndian.Uint16(frame[off:]) == packet.EtherTypeVLAN {
		out.vlan = binary.BigEndian.Uint16(frame[14:]) & 0x0fff
		off += 4
	}
	if et := binary.BigEndian.Uint16(frame[off:]); et != packet.EtherTypeIPv4 {
		t.Fatalf("EtherType %#04x is not IPv4", et)
	}
	ip := off + 2
	out.proto = frame[ip+9]
	copy(out.srcIP[:], frame[ip+12:])
	copy(out.dstIP[:], frame[ip+16:])
	l4 := ip + 20
	out.srcPort = binary.BigEndian.Uint16(frame[l4:])
	out.dstPort = binary.BigEndian.Uint16(frame[l4+2:])
	return out
}

func TestUDPGeneratorSingleFlow(t *testing.T) {
	g, err := New(spec(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, 2048)
	first := tuple{}
	for i := range 10 {
		n, class := g.Next(frame)
		if class != stats.ClassUDP {
			t.Fatalf("class = %v, want UDP", class)
		}
		if n != 60 {
			t.Fatalf("frame length = %d, want 60 (a 64-byte frame minus the FCS)", n)
		}
		got := parse(t, frame, n)
		if got.proto != packet.ProtoUDP {
			t.Fatalf("IP protocol = %d, want %d", got.proto, packet.ProtoUDP)
		}
		if i == 0 {
			first = got
			continue
		}
		if got != first {
			t.Fatalf("packet %d changed the tuple of a single flow:\n got %+v\nwant %+v", i, got, first)
		}
	}
	if g.AvgWireBytes() != 84 {
		t.Errorf("AvgWireBytes = %d, want 84 (a 64-byte frame plus 20 of framing)", g.AvgWireBytes())
	}
	if g.MaxFrameLen() != 60 {
		t.Errorf("MaxFrameLen = %d, want 60", g.MaxFrameLen())
	}
}

func TestUDPGeneratorManyFlows(t *testing.T) {
	g, err := New(spec(t, func(c *config.Config) {
		c.Flows = 1000
		c.DstIP = "10.0.0.0/24"
		c.SrcPort = 2000
		c.DstPort = 9000
	}))
	if err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, 2048)
	seen := map[tuple]int{}
	for range 1000 {
		n, _ := g.Next(frame)
		seen[parse(t, frame, n)]++
	}
	if len(seen) != 1000 {
		t.Fatalf("1000 packets produced %d distinct tuples, want 1000", len(seen))
	}
	// Every destination must be a usable host in the /24, never .0 or .255.
	for tup := range seen {
		if tup.dstIP[3] == 0 || tup.dstIP[3] == 255 {
			t.Errorf("destination %v is a network or broadcast address", netip.AddrFrom4(tup.dstIP))
		}
		if tup.dstPort != 9000 {
			t.Errorf("destination port = %d, want the fixed 9000", tup.dstPort)
		}
	}
	// The next cycle must repeat exactly the same tuples.
	for range 1000 {
		n, _ := g.Next(frame)
		if _, ok := seen[parse(t, frame, n)]; !ok {
			t.Fatal("the second cycle produced a tuple the first did not")
		}
	}
}

// The generator must be a pure function of its configuration: two runs of the
// same config produce byte-identical packets in the same order.
func TestGenerationIsDeterministic(t *testing.T) {
	mk := func() Generator {
		g, err := New(spec(t, func(c *config.Config) {
			c.Flows = 37
			c.DstIP = "10.1.0.0/22"
			c.PacketSize = 128
		}))
		if err != nil {
			t.Fatal(err)
		}
		return g
	}
	a, b := mk(), mk()
	fa, fb := make([]byte, 2048), make([]byte, 2048)
	for i := range 500 {
		na, _ := a.Next(fa)
		nb, _ := b.Next(fb)
		if na != nb || string(fa[:na]) != string(fb[:nb]) {
			t.Fatalf("packet %d differs between two identical runs", i)
		}
	}
}

// Spreading the same flow space over more queues must not change the set of
// flows, only which queue carries each one.
func TestFlowSpaceIsIndependentOfQueueCount(t *testing.T) {
	collect := func(queues int) map[tuple]bool {
		out := map[tuple]bool{}
		frame := make([]byte, 2048)
		for q := range queues {
			s := spec(t, func(c *config.Config) {
				c.Flows = 120
				c.DstIP = "10.0.0.0/24"
			})
			s.Queue, s.Queues = q, queues
			g, err := New(s)
			if err != nil {
				t.Fatal(err)
			}
			for range 120 / queues {
				n, _ := g.Next(frame)
				out[parse(t, frame, n)] = true
			}
		}
		return out
	}
	want := collect(1)
	if len(want) != 120 {
		t.Fatalf("one queue produced %d flows, want 120", len(want))
	}
	for _, queues := range []int{2, 3, 4, 8, 12} {
		got := collect(queues)
		if len(got) != len(want) {
			t.Errorf("queues=%d produced %d flows, want %d", queues, len(got), len(want))
			continue
		}
		for tup := range want {
			if !got[tup] {
				t.Errorf("queues=%d is missing a flow the single-queue run produced", queues)
				break
			}
		}
	}
}

func TestTCPSYNGenerator(t *testing.T) {
	g, err := New(spec(t, func(c *config.Config) {
		c.Mode = config.ModeTCPSYN
		c.Flows = 50
		c.DstPort = 80
	}))
	if err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, 2048)
	seen := map[uint16]bool{}
	for range 50 {
		n, class := g.Next(frame)
		if class != stats.ClassTCP {
			t.Fatalf("class = %v, want TCP", class)
		}
		got := parse(t, frame, n)
		if got.proto != packet.ProtoTCP {
			t.Fatalf("IP protocol = %d, want %d", got.proto, packet.ProtoTCP)
		}
		if got.dstPort != 80 {
			t.Errorf("destination port = %d, want 80", got.dstPort)
		}
		seen[got.srcPort] = true

		// Only the SYN flag, and a valid checksum over the whole segment.
		flags := frame[34+13]
		if flags != 0x02 {
			t.Errorf("TCP flags = %#02x, want 0x02 (SYN only)", flags)
		}
		if !tcpChecksumValid(frame[:n]) {
			t.Fatal("TCP checksum is wrong")
		}
	}
	if len(seen) != 50 {
		t.Errorf("50 flows produced %d distinct source ports, want 50", len(seen))
	}
}

// tcpChecksumValid recomputes the checksum of an untagged IPv4/TCP frame the
// long way — literal pseudo-header bytes prepended to the segment — so it
// shares no code with the incremental implementation under test.
func tcpChecksumValid(frame []byte) bool {
	l4 := frame[34:]
	buf := make([]byte, 0, 12+len(l4))
	buf = append(buf, frame[26:34]...) // source and destination addresses
	buf = append(buf, 0, packet.ProtoTCP)
	buf = binary.BigEndian.AppendUint16(buf, uint16(len(l4)))
	buf = append(buf, l4...)

	got := binary.BigEndian.Uint16(buf[12+16:])
	binary.BigEndian.PutUint16(buf[12+16:], 0)
	return got == packet.Checksum(buf)
}

func TestVLANGeneration(t *testing.T) {
	g, err := New(spec(t, func(c *config.Config) {
		c.VLAN = 2131
		c.Flows = 4
	}))
	if err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, 2048)
	for range 4 {
		n, _ := g.Next(frame)
		got := parse(t, frame, n)
		if got.vlan != 2131 {
			t.Fatalf("VLAN = %d, want 2131", got.vlan)
		}
		// The tag lives inside --packet-size, so the frame length is unchanged.
		if n != 60 {
			t.Fatalf("tagged frame length = %d, want 60", n)
		}
	}
}

func TestIMIXGenerator(t *testing.T) {
	g, err := New(spec(t, func(c *config.Config) { c.Mode = config.ModeIMIX }))
	if err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, 2048)
	counts := map[int]int{}
	const cycles = 100
	for range cycles * 12 {
		n, class := g.Next(frame)
		if class != stats.ClassUDP {
			t.Fatalf("IMIX class = %v, want UDP", class)
		}
		counts[n+config.FCSLen]++ // back to total frame size
	}
	want := map[int]int{64: 7 * cycles, 594: 4 * cycles, 1518: 1 * cycles}
	for size, n := range want {
		if counts[size] != n {
			t.Errorf("%d-byte frames: got %d, want %d", size, counts[size], n)
		}
	}
	if len(counts) != 3 {
		t.Errorf("IMIX produced %d distinct sizes, want 3: %v", len(counts), counts)
	}
	// The estimate the rate limiter uses should be the mean wire size.
	if got, want := g.AvgWireBytes(), int(MeanSize(DefaultIMIX))+wireOverhead-config.FCSLen; got < want-2 || got > want+2 {
		t.Errorf("AvgWireBytes = %d, want about %d", got, want)
	}
	if g.MaxFrameLen() != 1514 {
		t.Errorf("MaxFrameLen = %d, want 1514", g.MaxFrameLen())
	}
}

// On a tagged link the smallest IMIX frame cannot be 64: the NIC pads anything
// below 68, so the generator must emit 68 and count it as 68, or every rate it
// reports is short of what is really on the wire. Measured on ixgbe, tagged IMIX
// arrives at the receiver averaging 364 bytes, not 362.
func TestTaggedIMIXRaisesSmallFrameTo68(t *testing.T) {
	g, err := New(spec(t, func(c *config.Config) {
		c.Mode = config.ModeIMIX
		c.VLAN = 2131
	}))
	if err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, 2048)
	counts := map[int]int{}
	const cycles = 100
	for range cycles * 12 {
		n, _ := g.Next(frame)
		counts[n+config.FCSLen]++ // back to total frame size
	}
	// The 64-byte component is now 68; the others are unchanged.
	want := map[int]int{68: 7 * cycles, 594: 4 * cycles, 1518: 1 * cycles}
	for size, n := range want {
		if counts[size] != n {
			t.Errorf("%d-byte frames: got %d, want %d", size, counts[size], n)
		}
	}
	if counts[64] != 0 {
		t.Errorf("a tagged run still emitted %d 64-byte frames; the NIC would pad them", counts[64])
	}
	if len(counts) != 3 {
		t.Errorf("tagged IMIX produced %d distinct sizes, want 3: %v", len(counts), counts)
	}
	// Mean rises from 362 to about 364, matching the wire.
	if !strings.Contains(g.Describe(), "68/594/1518") || !strings.Contains(g.Describe(), "364B") {
		t.Errorf("describe = %q, want it to report the 68-byte floor and a 364B mean", g.Describe())
	}
}

// Untagged, the floor stays 64 — the clamp must not fire without a tag.
func TestUntaggedIMIXKeeps64ByteFrames(t *testing.T) {
	g, err := New(spec(t, func(c *config.Config) { c.Mode = config.ModeIMIX }))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(g.Describe(), "64/594/1518") {
		t.Errorf("describe = %q, want the untagged 64-byte floor", g.Describe())
	}
}

// IMIX frames must still carry correct headers at every size.
func TestIMIXFramesAreWellFormed(t *testing.T) {
	g, err := New(spec(t, func(c *config.Config) {
		c.Mode = config.ModeIMIX
		c.VLAN = 100
		c.Flows = 5
	}))
	if err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, 2048)
	for range 24 {
		n, _ := g.Next(frame)
		got := parse(t, frame, n)
		if got.vlan != 100 {
			t.Fatalf("VLAN = %d, want 100", got.vlan)
		}
		ipLen := int(binary.BigEndian.Uint16(frame[18+2:]))
		if want := n - 18; ipLen != want {
			t.Errorf("IP total length = %d, want %d for a %d-byte frame", ipLen, want, n)
		}
		udpLen := int(binary.BigEndian.Uint16(frame[38+4:]))
		if want := n - 38; udpLen != want {
			t.Errorf("UDP length = %d, want %d", udpLen, want)
		}
		hdr := make([]byte, 20)
		copy(hdr, frame[18:38])
		binary.BigEndian.PutUint16(hdr[10:], 0)
		if got, want := binary.BigEndian.Uint16(frame[18+10:]), packet.Checksum(hdr); got != want {
			t.Errorf("IPv4 checksum = %#04x, want %#04x", got, want)
		}
	}
}

func TestRawGenerator(t *testing.T) {
	g, err := New(spec(t, func(c *config.Config) {
		c.Mode = config.ModeRaw
		c.EtherType = 0x88b5
		c.PacketSize = 100
		c.PayloadByte = 0xa5
	}))
	if err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, 2048)
	n, class := g.Next(frame)
	if class != stats.ClassOther {
		t.Errorf("class = %v, want Other", class)
	}
	if n != 96 {
		t.Errorf("frame length = %d, want 96", n)
	}
	if et := binary.BigEndian.Uint16(frame[12:]); et != 0x88b5 {
		t.Errorf("EtherType = %#04x, want 0x88b5", et)
	}
	for i, v := range frame[14:n] {
		if v != 0xa5 {
			t.Fatalf("payload byte %d = %#02x, want 0xa5", i, v)
		}
	}
}

func TestNewRejectsUnknownMode(t *testing.T) {
	s := spec(t, func(c *config.Config) { c.Mode = "sctp" })
	if _, err := New(s); err == nil {
		t.Error("an unknown mode should fail to build a generator")
	}
}

func TestClassify(t *testing.T) {
	build := func(vlan int, proto uint8) []byte {
		cfg := config.Default()
		cfg.VLAN = vlan
		tmpl, err := packet.Build(packet.Spec{
			SrcIP: netip.MustParseAddr("10.0.0.1"), DstIP: netip.MustParseAddr("10.0.0.2"),
			Proto: proto, VLAN: uint16(vlan), FrameLen: 60,
		})
		if err != nil {
			t.Fatal(err)
		}
		return tmpl.Bytes()
	}
	if got := Classify(build(0, packet.ProtoUDP)); got != stats.ClassUDP {
		t.Errorf("untagged UDP classified as %v", got)
	}
	if got := Classify(build(0, packet.ProtoTCP)); got != stats.ClassTCP {
		t.Errorf("untagged TCP classified as %v", got)
	}
	// Classification must see through a single VLAN tag, or every tagged
	// packet would be counted as "other".
	if got := Classify(build(100, packet.ProtoUDP)); got != stats.ClassUDP {
		t.Errorf("tagged UDP classified as %v, want UDP", got)
	}
	if got := Classify(build(100, packet.ProtoTCP)); got != stats.ClassTCP {
		t.Errorf("tagged TCP classified as %v, want TCP", got)
	}
	// Runts and non-IP frames must be safe to classify.
	for _, b := range [][]byte{nil, {1, 2, 3}, make([]byte, 14), make([]byte, 20)} {
		if got := Classify(b); got != stats.ClassOther {
			t.Errorf("Classify(%d bytes) = %v, want Other", len(b), got)
		}
	}
	arp := make([]byte, 60)
	binary.BigEndian.PutUint16(arp[12:], 0x0806)
	if got := Classify(arp); got != stats.ClassOther {
		t.Errorf("ARP classified as %v, want Other", got)
	}
}

func BenchmarkUDPNext(b *testing.B) {
	cfg := config.Default()
	cfg.Flows = 1000
	cfg.DstIP = "10.0.0.0/16"
	dst, _ := config.ParseDst(cfg.DstIP)
	g, err := New(Spec{
		Cfg: &cfg, SrcMAC: testSrcMAC, DstMAC: testDstMAC,
		SrcIP: netip.MustParseAddr("192.168.0.99"), Dst: dst, Queues: 1,
	})
	if err != nil {
		b.Fatal(err)
	}
	frame := make([]byte, 2048)
	b.ReportAllocs()
	b.SetBytes(64)
	for b.Loop() {
		g.Next(frame)
	}
}

func BenchmarkTCPNext(b *testing.B) {
	cfg := config.Default()
	cfg.Mode = config.ModeTCPSYN
	cfg.Flows = 1000
	dst, _ := config.ParseDst("10.0.0.2")
	g, err := New(Spec{
		Cfg: &cfg, SrcMAC: testSrcMAC, DstMAC: testDstMAC,
		SrcIP: netip.MustParseAddr("192.168.0.99"), Dst: dst, Queues: 1,
	})
	if err != nil {
		b.Fatal(err)
	}
	frame := make([]byte, 2048)
	b.ReportAllocs()
	b.SetBytes(64)
	for b.Loop() {
		g.Next(frame)
	}
}

func BenchmarkIMIXNext(b *testing.B) {
	cfg := config.Default()
	cfg.Mode = config.ModeIMIX
	cfg.Flows = 1000
	dst, _ := config.ParseDst("10.0.0.2")
	g, err := New(Spec{
		Cfg: &cfg, SrcMAC: testSrcMAC, DstMAC: testDstMAC,
		SrcIP: netip.MustParseAddr("192.168.0.99"), Dst: dst, Queues: 1,
	})
	if err != nil {
		b.Fatal(err)
	}
	frame := make([]byte, 2048)
	b.ReportAllocs()
	for b.Loop() {
		g.Next(frame)
	}
}
