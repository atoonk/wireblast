package packet

import (
	"bytes"
	"encoding/binary"
	"math/rand/v2"
	"net"
	"net/netip"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

var (
	srcMAC = [6]byte{0x3c, 0xec, 0xef, 0xb4, 0xc4, 0x3e}
	dstMAC = [6]byte{0x3c, 0xec, 0xef, 0xb4, 0xc2, 0xdc}
	srcIP  = netip.MustParseAddr("192.168.0.99")
	dstIP  = netip.MustParseAddr("192.168.0.2")
)

func udpSpec(vlan uint16, size int) Spec {
	return Spec{
		SrcMAC: srcMAC, DstMAC: dstMAC, VLAN: vlan,
		SrcIP: srcIP, DstIP: dstIP, Proto: ProtoUDP,
		SrcPort: 1024, DstPort: 9000, FrameLen: size, PayloadByte: 0x5a,
	}
}

func tcpSpec(vlan uint16, size int) Spec {
	s := udpSpec(vlan, size)
	s.Proto = ProtoTCP
	return s
}

// oracle builds the same frame with gopacket's serializer, which computes
// lengths and checksums independently of our code.
func oracle(t *testing.T, s Spec) []byte {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr(s.SrcMAC[:]),
		DstMAC:       net.HardwareAddr(s.DstMAC[:]),
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version: 4, IHL: 5, TTL: 64,
		SrcIP: net.IP(asSlice(s.SrcIP)), DstIP: net.IP(asSlice(s.DstIP)),
	}
	stack := []gopacket.SerializableLayer{eth}
	if s.VLAN != 0 {
		eth.EthernetType = layers.EthernetTypeDot1Q
		stack = append(stack, &layers.Dot1Q{
			VLANIdentifier: s.VLAN,
			Type:           layers.EthernetTypeIPv4,
		})
	}
	stack = append(stack, ip)

	l2l3 := EthHeaderLen + IPv4HeaderLen
	if s.VLAN != 0 {
		l2l3 += VLANTagLen
	}
	var payloadLen int
	switch s.Proto {
	case ProtoUDP:
		ip.Protocol = layers.IPProtocolUDP
		udp := &layers.UDP{SrcPort: layers.UDPPort(s.SrcPort), DstPort: layers.UDPPort(s.DstPort)}
		if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
			t.Fatal(err)
		}
		stack = append(stack, udp)
		payloadLen = s.FrameLen - l2l3 - UDPHeaderLen
	case ProtoTCP:
		ip.Protocol = layers.IPProtocolTCP
		tcp := &layers.TCP{
			SrcPort: layers.TCPPort(s.SrcPort), DstPort: layers.TCPPort(s.DstPort),
			SYN: true, Window: 64240, DataOffset: 5,
		}
		if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
			t.Fatal(err)
		}
		stack = append(stack, tcp)
		payloadLen = s.FrameLen - l2l3 - TCPHeaderLen
	}
	payload := bytes.Repeat([]byte{s.PayloadByte}, payloadLen)
	stack = append(stack, gopacket.Payload(payload))

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, stack...); err != nil {
		t.Fatalf("gopacket serialize: %v", err)
	}
	return buf.Bytes()
}

func asSlice(a netip.Addr) []byte { b := a.As4(); return b[:] }

// TestBuildMatchesGopacket checks our frames byte-for-byte against gopacket's
// serializer, which is where the IPv4, UDP and TCP checksums are really
// verified.
func TestBuildMatchesGopacket(t *testing.T) {
	tests := []struct {
		name string
		spec Spec
	}{
		{"udp/64", udpSpec(0, 60)},
		{"udp/1514", udpSpec(0, 1514)},
		{"udp/vlan/64", udpSpec(2131, 60)},
		{"udp/vlan/1514", udpSpec(2131, 1514)},
		{"tcp/64", tcpSpec(0, 60)},
		{"tcp/vlan/64", tcpSpec(2131, 60)},
		{"tcp/594", tcpSpec(0, 590)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpl, err := Build(tt.spec)
			if err != nil {
				t.Fatalf("Build: %v", err)
			}
			got := tmpl.Bytes()
			want := oracle(t, tt.spec)
			if len(got) != len(want) {
				t.Fatalf("length %d, want %d", len(got), len(want))
			}
			if tt.spec.Proto == ProtoUDP {
				// We deliberately leave the optional IPv4 UDP checksum at
				// zero; blank it in the oracle before comparing.
				lay := tmpl.Layout()
				binary.BigEndian.PutUint16(want[lay.L4Off+6:], 0)
				if c := binary.BigEndian.Uint16(got[lay.L4Off+6:]); c != 0 {
					t.Errorf("UDP checksum = %#04x, want 0", c)
				}
			}
			if !bytes.Equal(got, want) {
				t.Errorf("frame differs from gopacket\n got %x\nwant %x", got, want)
			}
		})
	}
}

func TestVLANTagStructure(t *testing.T) {
	tmpl, err := Build(udpSpec(2131, 64))
	if err != nil {
		t.Fatal(err)
	}
	b := tmpl.Bytes()
	if tpid := binary.BigEndian.Uint16(b[12:]); tpid != EtherTypeVLAN {
		t.Errorf("TPID = %#04x, want %#04x", tpid, EtherTypeVLAN)
	}
	tci := binary.BigEndian.Uint16(b[14:])
	if vid := tci & 0x0fff; vid != 2131 {
		t.Errorf("VLAN ID = %d, want 2131", vid)
	}
	if pcp := tci >> 13; pcp != 0 {
		t.Errorf("PCP = %d, want 0", pcp)
	}
	if tci&0x1000 != 0 {
		t.Error("DEI bit should be clear")
	}
	if et := binary.BigEndian.Uint16(b[16:]); et != EtherTypeIPv4 {
		t.Errorf("inner EtherType = %#04x, want %#04x", et, EtherTypeIPv4)
	}
	if lay := tmpl.Layout(); lay.L3Off != 18 || !lay.HasVLAN {
		t.Errorf("layout L3Off = %d, HasVLAN = %v; want 18, true", lay.L3Off, lay.HasVLAN)
	}

	// An untagged frame must put the EtherType straight at offset 12.
	plain, _ := Build(udpSpec(0, 64))
	if et := binary.BigEndian.Uint16(plain.Bytes()[12:]); et != EtherTypeIPv4 {
		t.Errorf("untagged EtherType = %#04x, want %#04x", et, EtherTypeIPv4)
	}
	if plain.Layout().L3Off != 14 {
		t.Errorf("untagged L3Off = %d, want 14", plain.Layout().L3Off)
	}
}

// verify recomputes both checksums from scratch and compares them with what
// the incremental mutators left in the packet.
func verify(t *testing.T, tmpl *Template) {
	t.Helper()
	lay := tmpl.Layout()
	b := tmpl.Bytes()

	hdr := append([]byte(nil), b[lay.L3Off:lay.L3Off+IPv4HeaderLen]...)
	got := binary.BigEndian.Uint16(hdr[10:])
	binary.BigEndian.PutUint16(hdr[10:], 0)
	if want := Checksum(hdr); got != want {
		t.Fatalf("IPv4 checksum = %#04x, want %#04x (incremental update drifted)", got, want)
	}

	if lay.L4CksumOff >= 0 {
		l4 := append([]byte(nil), b[lay.L4Off:]...)
		got := binary.BigEndian.Uint16(l4[16:])
		binary.BigEndian.PutUint16(l4[16:], 0)
		var s4, d4 [4]byte
		copy(s4[:], b[lay.SrcIPOff:])
		copy(d4[:], b[lay.DstIPOff:])
		sum := PseudoHeaderSum(s4, d4, lay.Proto, len(l4))
		if want := ^foldSum(partialSum(l4, sum)); got != want {
			t.Fatalf("TCP checksum = %#04x, want %#04x (incremental update drifted)", got, want)
		}
	}
}

// TestIncrementalChecksumsStayCorrect hammers the mutators with random values
// and checks the incrementally maintained checksums against full recomputes.
func TestIncrementalChecksumsStayCorrect(t *testing.T) {
	for _, proto := range []uint8{ProtoUDP, ProtoTCP} {
		for _, vlan := range []uint16{0, 2131} {
			spec := udpSpec(vlan, 128)
			spec.Proto = proto
			tmpl, err := Build(spec)
			if err != nil {
				t.Fatal(err)
			}
			verify(t, tmpl)

			r := rand.New(rand.NewPCG(1, uint64(proto)<<16|uint64(vlan)))
			for i := 0; i < 2000; i++ {
				var s, d [4]byte
				binary.BigEndian.PutUint32(s[:], r.Uint32())
				binary.BigEndian.PutUint32(d[:], r.Uint32())
				tmpl.SetSrcIP(netip.AddrFrom4(s))
				tmpl.SetDstIP(netip.AddrFrom4(d))
				tmpl.SetSrcPort(uint16(r.Uint32()))
				tmpl.SetDstPort(uint16(r.Uint32()))
				verify(t, tmpl)
			}
		}
	}
}

// A field set back to the value it already had must not disturb the checksum.
func TestRedundantSetsAreNoOps(t *testing.T) {
	tmpl, err := Build(tcpSpec(0, 128))
	if err != nil {
		t.Fatal(err)
	}
	before := append([]byte(nil), tmpl.Bytes()...)
	tmpl.SetSrcIP(srcIP)
	tmpl.SetDstIP(dstIP)
	tmpl.SetSrcPort(1024)
	tmpl.SetDstPort(9000)
	if !bytes.Equal(before, tmpl.Bytes()) {
		t.Error("setting a field to its current value changed the frame")
	}
}

// SetFrameLen is how IMIX varies size; lengths and checksums must follow.
func TestSetFrameLen(t *testing.T) {
	spec := udpSpec(0, 60)
	spec.Cap = 1514
	tmpl, err := Build(spec)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{1514, 60, 590, 60, 1514} {
		if err := tmpl.SetFrameLen(n); err != nil {
			t.Fatalf("SetFrameLen(%d): %v", n, err)
		}
		if tmpl.Len() != n {
			t.Fatalf("Len() = %d, want %d", tmpl.Len(), n)
		}
		b := tmpl.Bytes()
		lay := tmpl.Layout()
		if got := binary.BigEndian.Uint16(b[lay.IPLenOff:]); int(got) != n-lay.L3Off {
			t.Errorf("IP total length = %d, want %d", got, n-lay.L3Off)
		}
		if got := binary.BigEndian.Uint16(b[lay.L4LenOff:]); int(got) != n-lay.L4Off {
			t.Errorf("UDP length = %d, want %d", got, n-lay.L4Off)
		}
		verify(t, tmpl)
	}

	if err := tmpl.SetFrameLen(20); err == nil {
		t.Error("a length below the header size must be rejected")
	}
	if err := tmpl.SetFrameLen(9000); err == nil {
		t.Error("a length beyond the template capacity must be rejected")
	}
}

// TCP is fixed-size in practice, but resizing must still leave it valid.
func TestSetFrameLenTCPKeepsChecksumValid(t *testing.T) {
	spec := tcpSpec(0, 60)
	spec.Cap = 1514
	tmpl, err := Build(spec)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{200, 1514, 60} {
		if err := tmpl.SetFrameLen(n); err != nil {
			t.Fatal(err)
		}
		verify(t, tmpl)
	}
}

func TestRawEthernet(t *testing.T) {
	tmpl, err := Build(Spec{
		SrcMAC: srcMAC, DstMAC: dstMAC, EtherType: 0x88b5,
		FrameLen: 60, PayloadByte: 0xa5,
	})
	if err != nil {
		t.Fatal(err)
	}
	b := tmpl.Bytes()
	if len(b) != 60 {
		t.Fatalf("length %d, want 60", len(b))
	}
	if !bytes.Equal(b[0:6], dstMAC[:]) || !bytes.Equal(b[6:12], srcMAC[:]) {
		t.Error("MAC addresses are in the wrong order or place")
	}
	if et := binary.BigEndian.Uint16(b[12:]); et != 0x88b5 {
		t.Errorf("EtherType = %#04x, want 0x88b5", et)
	}
	for i, v := range b[14:] {
		if v != 0xa5 {
			t.Fatalf("payload byte %d = %#02x, want 0xa5", i, v)
		}
	}
	// Mutators must be harmless no-ops on a frame with no IP header.
	tmpl.SetSrcIP(netip.AddrFrom4([4]byte{1, 2, 3, 4}))
	tmpl.SetSrcPort(1234)
	if !bytes.Equal(b, tmpl.Bytes()) {
		t.Error("IP mutators changed a raw Ethernet frame")
	}

	vt, err := Build(Spec{
		SrcMAC: srcMAC, DstMAC: dstMAC, EtherType: 0x88b5, VLAN: 100,
		FrameLen: 60, PayloadByte: 0xa5,
	})
	if err != nil {
		t.Fatal(err)
	}
	if et := binary.BigEndian.Uint16(vt.Bytes()[16:]); et != 0x88b5 {
		t.Errorf("tagged raw EtherType = %#04x, want 0x88b5", et)
	}
}

func TestBuildRejectsBadSpecs(t *testing.T) {
	bad := []struct {
		name string
		spec Spec
	}{
		{"ipv6 src", Spec{SrcIP: netip.MustParseAddr("2001:db8::1"), DstIP: dstIP, Proto: ProtoUDP, FrameLen: 60}},
		{"ipv6 dst", Spec{SrcIP: srcIP, DstIP: netip.MustParseAddr("2001:db8::1"), Proto: ProtoUDP, FrameLen: 60}},
		{"bad proto", Spec{SrcIP: srcIP, DstIP: dstIP, Proto: 47, FrameLen: 60}},
		{"too short udp", Spec{SrcIP: srcIP, DstIP: dstIP, Proto: ProtoUDP, FrameLen: 20}},
		{"too short tcp", Spec{SrcIP: srcIP, DstIP: dstIP, Proto: ProtoTCP, FrameLen: 40}},
		{"too short raw", Spec{EtherType: 0x88b5, FrameLen: 10}},
	}
	for _, tt := range bad {
		if _, err := Build(tt.spec); err == nil {
			t.Errorf("%s: Build should have failed", tt.name)
		}
	}
}

func TestWriteTo(t *testing.T) {
	tmpl, err := Build(udpSpec(0, 64))
	if err != nil {
		t.Fatal(err)
	}
	dst := make([]byte, 2048)
	n := tmpl.WriteTo(dst)
	if n != 64 {
		t.Fatalf("WriteTo wrote %d bytes, want 64", n)
	}
	if !bytes.Equal(dst[:n], tmpl.Bytes()) {
		t.Error("WriteTo produced different bytes than Bytes()")
	}
}

func BenchmarkBuildUDPFrame64(b *testing.B) {
	tmpl, err := Build(udpSpec(0, 60))
	if err != nil {
		b.Fatal(err)
	}
	frame := make([]byte, 2048)
	b.ReportAllocs()
	b.SetBytes(60)
	for b.Loop() {
		tmpl.WriteTo(frame)
	}
}

func BenchmarkBuildUDPFrame1514(b *testing.B) {
	tmpl, err := Build(udpSpec(0, 1514))
	if err != nil {
		b.Fatal(err)
	}
	frame := make([]byte, 2048)
	b.ReportAllocs()
	b.SetBytes(1514)
	for b.Loop() {
		tmpl.WriteTo(frame)
	}
}

func BenchmarkFlowMutationUDP(b *testing.B) {
	tmpl, _ := Build(udpSpec(0, 60))
	frame := make([]byte, 2048)
	var ip [4]byte
	b.ReportAllocs()
	i := uint32(0)
	for b.Loop() {
		i++
		binary.BigEndian.PutUint32(ip[:], i)
		tmpl.SetDstIP(netip.AddrFrom4(ip))
		tmpl.SetSrcPort(uint16(i))
		tmpl.WriteTo(frame)
	}
}

func BenchmarkFlowMutationTCP(b *testing.B) {
	tmpl, _ := Build(tcpSpec(0, 60))
	frame := make([]byte, 2048)
	var ip [4]byte
	b.ReportAllocs()
	i := uint32(0)
	for b.Loop() {
		i++
		binary.BigEndian.PutUint32(ip[:], i)
		tmpl.SetDstIP(netip.AddrFrom4(ip))
		tmpl.SetSrcPort(uint16(i))
		tmpl.WriteTo(frame)
	}
}

func BenchmarkChecksumReplaceU32(b *testing.B) {
	c := uint16(0x1234)
	old := [4]byte{10, 0, 0, 1}
	new := [4]byte{10, 0, 0, 2}
	b.ReportAllocs()
	for b.Loop() {
		c = ReplaceU32(c, old, new)
	}
	_ = c
}
