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
	src6 = netip.MustParseAddr("2001:db8::99")
	dst6 = netip.MustParseAddr("2001:db8::2")
)

func udp6Spec(vlan uint16, size int) Spec {
	return Spec{
		SrcMAC: srcMAC, DstMAC: dstMAC, VLAN: vlan,
		SrcIP: src6, DstIP: dst6, Proto: ProtoUDP,
		SrcPort: 1024, DstPort: 9000, FrameLen: size, PayloadByte: 0x5a,
	}
}

func tcp6Spec(vlan uint16, size int) Spec {
	s := udp6Spec(vlan, size)
	s.Proto = ProtoTCP
	return s
}

// oracle6 builds the same IPv6 frame with gopacket, which computes the payload
// length and the (mandatory) UDP/TCP checksum independently of our code.
func oracle6(t *testing.T, s Spec) []byte {
	t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr(s.SrcMAC[:]),
		DstMAC:       net.HardwareAddr(s.DstMAC[:]),
		EthernetType: layers.EthernetTypeIPv6,
	}
	ip := &layers.IPv6{
		Version: 6, HopLimit: 64,
		SrcIP: net.IP(s.SrcIP.AsSlice()), DstIP: net.IP(s.DstIP.AsSlice()),
	}
	stack := []gopacket.SerializableLayer{eth}
	if s.VLAN != 0 {
		eth.EthernetType = layers.EthernetTypeDot1Q
		stack = append(stack, &layers.Dot1Q{VLANIdentifier: s.VLAN, Type: layers.EthernetTypeIPv6})
	}
	stack = append(stack, ip)

	l2l3 := EthHeaderLen + IPv6HeaderLen
	if s.VLAN != 0 {
		l2l3 += VLANTagLen
	}
	var payloadLen int
	switch s.Proto {
	case ProtoUDP:
		ip.NextHeader = layers.IPProtocolUDP
		udp := &layers.UDP{SrcPort: layers.UDPPort(s.SrcPort), DstPort: layers.UDPPort(s.DstPort)}
		if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
			t.Fatal(err)
		}
		stack = append(stack, udp)
		payloadLen = s.FrameLen - l2l3 - UDPHeaderLen
	case ProtoTCP:
		ip.NextHeader = layers.IPProtocolTCP
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
	stack = append(stack, gopacket.Payload(bytes.Repeat([]byte{s.PayloadByte}, payloadLen)))

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, stack...); err != nil {
		t.Fatalf("gopacket serialize: %v", err)
	}
	return buf.Bytes()
}

// TestBuildMatchesGopacketIPv6 checks our IPv6 frames byte-for-byte against
// gopacket, which is where the 40-byte header, the payload length and the
// mandatory UDP/TCP checksum are really verified. Unlike IPv4, the UDP checksum
// is not zeroed, so the comparison is exact.
func TestBuildMatchesGopacketIPv6(t *testing.T) {
	tests := []struct {
		name string
		spec Spec
	}{
		{"udp6/min", udp6Spec(0, 62)}, // 14 + 40 + 8, no payload
		{"udp6/1514", udp6Spec(0, 1514)},
		{"udp6/vlan", udp6Spec(2131, 128)},
		{"tcp6/min", tcp6Spec(0, 74)}, // 14 + 40 + 20
		{"tcp6/vlan", tcp6Spec(2131, 128)},
		{"tcp6/594", tcp6Spec(0, 590)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpl, err := Build(tt.spec)
			if err != nil {
				t.Fatalf("Build: %v", err)
			}
			got, want := tmpl.Bytes(), oracle6(t, tt.spec)
			if !bytes.Equal(got, want) {
				t.Errorf("frame differs from gopacket\n got %x\nwant %x", got, want)
			}
			// EtherType and the no-header-checksum property.
			lay := tmpl.Layout()
			if !lay.Is6 || lay.IPCksumOff != -1 {
				t.Errorf("layout Is6=%v IPCksumOff=%d; want true, -1", lay.Is6, lay.IPCksumOff)
			}
			et := binary.BigEndian.Uint16(got[lay.L3Off-2:])
			if et != EtherTypeIPv6 {
				t.Errorf("inner EtherType = %#04x, want %#04x", et, EtherTypeIPv6)
			}
		})
	}
}

// verify6 recomputes the IPv6 L4 checksum from scratch and compares it with the
// incrementally maintained value, and enforces the never-zero UDP rule.
func verify6(t *testing.T, tmpl *Template) {
	t.Helper()
	lay := tmpl.Layout()
	if lay.L4CksumOff < 0 {
		return
	}
	b := tmpl.Bytes()
	l4 := append([]byte(nil), b[lay.L4Off:]...)
	off := lay.L4CksumOff - lay.L4Off
	got := binary.BigEndian.Uint16(l4[off:])
	binary.BigEndian.PutUint16(l4[off:], 0)

	var s16, d16 [16]byte
	copy(s16[:], b[lay.SrcIPOff:])
	copy(d16[:], b[lay.DstIPOff:])
	want := ^foldSum(partialSum(l4, PseudoHeaderSum6(s16, d16, lay.Proto, len(l4))))
	if want == 0 && lay.Proto == ProtoUDP {
		want = 0xffff
	}
	if got != want {
		t.Fatalf("IPv6 L4 checksum = %#04x, want %#04x (incremental update drifted)", got, want)
	}
	if lay.Proto == ProtoUDP && got == 0 {
		t.Fatal("an IPv6 UDP checksum must never be transmitted as zero")
	}
}

// TestIPv6IncrementalChecksums hammers the mutators with random 128-bit
// addresses, ports and frame sizes, checking the incrementally maintained UDP
// and TCP checksums against full recomputes.
func TestIPv6IncrementalChecksums(t *testing.T) {
	for _, proto := range []uint8{ProtoUDP, ProtoTCP} {
		for _, vlan := range []uint16{0, 2131} {
			spec := udp6Spec(vlan, 400)
			spec.Proto = proto
			spec.Cap = 1514
			tmpl, err := Build(spec)
			if err != nil {
				t.Fatal(err)
			}
			verify6(t, tmpl)

			r := rand.New(rand.NewPCG(2, uint64(proto)<<16|uint64(vlan)))
			for i := 0; i < 2000; i++ {
				var s, d [16]byte
				binary.BigEndian.PutUint64(s[0:], r.Uint64())
				binary.BigEndian.PutUint64(s[8:], r.Uint64())
				binary.BigEndian.PutUint64(d[0:], r.Uint64())
				binary.BigEndian.PutUint64(d[8:], r.Uint64())
				tmpl.SetSrcIP(netip.AddrFrom16(s))
				tmpl.SetDstIP(netip.AddrFrom16(d))
				tmpl.SetSrcPort(uint16(r.Uint32()))
				tmpl.SetDstPort(uint16(r.Uint32()))
				// Vary the size occasionally, the IMIX-over-IPv6 path.
				if i%7 == 0 {
					_ = tmpl.SetFrameLen(62 + int(r.Uint32()%1000))
				}
				verify6(t, tmpl)
			}
		}
	}
}
