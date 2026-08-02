package packet

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// IP protocol numbers Wireblast generates.
const (
	ProtoTCP = 6
	ProtoUDP = 17
)

// EtherTypes used by the builders.
const (
	EtherTypeIPv4 = 0x0800
	EtherTypeIPv6 = 0x86DD
	EtherTypeVLAN = 0x8100
)

// Header sizes, in bytes.
const (
	EthHeaderLen  = 14
	VLANTagLen    = 4
	IPv4HeaderLen = 20
	IPv6HeaderLen = 40
	UDPHeaderLen  = 8
	TCPHeaderLen  = 20
)

// Layout records where each mutable field sits in a built frame. Offsets shift
// by VLANTagLen when a tag is present, which is why nothing downstream
// hardcodes them.
type Layout struct {
	HasVLAN bool
	HasIP   bool
	Is6     bool // IPv6 rather than IPv4

	L3Off int // start of the IP header (or of the raw payload)
	L4Off int // start of the UDP/TCP header

	SrcIPOff   int
	DstIPOff   int
	IPCksumOff int
	IPLenOff   int

	SrcPortOff int
	DstPortOff int
	L4LenOff   int // UDP length field; -1 for TCP
	L4CksumOff int // -1 when there is no L4 checksum to maintain

	HeaderLen int   // total header bytes before the payload
	Proto     uint8 // 0 for raw Ethernet
}

// Spec describes the frame to build. FrameLen and Cap are in bytes actually
// written to the wire, i.e. excluding the FCS the NIC appends.
type Spec struct {
	SrcMAC, DstMAC [6]byte
	VLAN           uint16 // 0 means untagged
	PCP            uint8  // 802.1p priority, 0-7

	SrcIP, DstIP     netip.Addr // IPv4; ignored when EtherType is set
	Proto            uint8      // ProtoUDP or ProtoTCP
	SrcPort, DstPort uint16
	TTL              uint8

	// EtherType, when non-zero, builds a raw Ethernet frame with this type
	// and no IP headers at all.
	EtherType uint16

	FrameLen    int // bytes written for each packet
	Cap         int // buffer capacity; >= FrameLen, for later SetFrameLen calls
	PayloadByte byte
}

// Template is a prebuilt frame plus the bookkeeping needed to change a flow
// field and repair the checksums without rescanning the packet.
//
// A Template is owned by exactly one transmit goroutine. It is not safe for
// concurrent use, and does not need to be: each queue builds its own.
type Template struct {
	buf []byte
	lay Layout

	srcIP, dstIP     netip.Addr
	srcPort, dstPort uint16
	frameLen         int
	payloadByte      byte
}

// Build constructs a Template from a Spec.
func Build(s Spec) (*Template, error) {
	if s.Cap < s.FrameLen {
		s.Cap = s.FrameLen
	}
	if s.EtherType != 0 {
		return buildRaw(s)
	}
	if s.SrcIP.Is6() || s.DstIP.Is6() {
		return buildIPv6(s)
	}
	return buildIPv4(s)
}

// buildRaw makes an Ethernet frame with a fixed EtherType and payload pattern.
func buildRaw(s Spec) (*Template, error) {
	lay := ethLayout(s.VLAN != 0)
	if s.FrameLen < lay.L3Off {
		return nil, fmt.Errorf("packet: frame length %d is smaller than the %d-byte Ethernet header",
			s.FrameLen, lay.L3Off)
	}
	lay.HeaderLen = lay.L3Off
	lay.L4Off, lay.SrcIPOff, lay.DstIPOff = -1, -1, -1
	lay.IPCksumOff, lay.IPLenOff = -1, -1
	lay.SrcPortOff, lay.DstPortOff, lay.L4LenOff, lay.L4CksumOff = -1, -1, -1, -1

	t := &Template{buf: make([]byte, s.Cap), lay: lay, frameLen: s.FrameLen, payloadByte: s.PayloadByte}
	writeEthernet(t.buf, s, s.EtherType)
	fill(t.buf[lay.HeaderLen:], s.PayloadByte)
	return t, nil
}

// buildIPv4 makes an Ethernet + optional 802.1Q + IPv4 + UDP/TCP frame.
func buildIPv4(s Spec) (*Template, error) {
	if !s.SrcIP.Is4() || !s.DstIP.Is4() {
		return nil, fmt.Errorf("packet: src %s and dst %s must both be IPv4", s.SrcIP, s.DstIP)
	}
	if s.Proto != ProtoUDP && s.Proto != ProtoTCP {
		return nil, fmt.Errorf("packet: unsupported IP protocol %d (want %d UDP or %d TCP)",
			s.Proto, ProtoUDP, ProtoTCP)
	}

	lay := ethLayout(s.VLAN != 0)
	lay.HasIP = true
	lay.L4Off = lay.L3Off + IPv4HeaderLen
	lay.IPLenOff = lay.L3Off + 2
	lay.IPCksumOff = lay.L3Off + 10
	lay.SrcIPOff = lay.L3Off + 12
	lay.DstIPOff = lay.L3Off + 16
	lay.SrcPortOff = lay.L4Off
	lay.DstPortOff = lay.L4Off + 2
	lay.Proto = s.Proto

	switch s.Proto {
	case ProtoUDP:
		lay.HeaderLen = lay.L4Off + UDPHeaderLen
		lay.L4LenOff = lay.L4Off + 4
		// The IPv4 UDP checksum is optional and left at zero, which is what
		// lets a flow's ports change with no L4 recompute at all.
		lay.L4CksumOff = -1
	case ProtoTCP:
		lay.HeaderLen = lay.L4Off + TCPHeaderLen
		lay.L4LenOff = -1
		lay.L4CksumOff = lay.L4Off + 16
	}

	if s.FrameLen < lay.HeaderLen {
		return nil, fmt.Errorf("packet: frame length %d is smaller than the %d-byte header",
			s.FrameLen, lay.HeaderLen)
	}
	if s.Cap < lay.HeaderLen {
		s.Cap = lay.HeaderLen
	}

	t := &Template{
		buf:         make([]byte, s.Cap),
		lay:         lay,
		srcIP:       s.SrcIP.Unmap(),
		dstIP:       s.DstIP.Unmap(),
		srcPort:     s.SrcPort,
		dstPort:     s.DstPort,
		frameLen:    s.FrameLen,
		payloadByte: s.PayloadByte,
	}
	b := t.buf

	writeEthernet(b, s, EtherTypeIPv4)

	// IPv4 header. ID stays 0 and DF is not set: these frames are never
	// fragmented and a generator has no use for a per-packet identifier.
	ttl := s.TTL
	if ttl == 0 {
		ttl = 64
	}
	s4, d4 := t.srcIP.As4(), t.dstIP.As4()
	ip := b[lay.L3Off:]
	ip[0] = 0x45 // version 4, IHL 5 (no options)
	ip[1] = 0    // DSCP/ECN
	binary.BigEndian.PutUint16(ip[2:], uint16(s.FrameLen-lay.L3Off))
	ip[8] = ttl
	ip[9] = s.Proto
	copy(ip[12:16], s4[:])
	copy(ip[16:20], d4[:])

	// L4 header.
	l4 := b[lay.L4Off:]
	binary.BigEndian.PutUint16(l4[0:], s.SrcPort)
	binary.BigEndian.PutUint16(l4[2:], s.DstPort)
	if s.Proto == ProtoUDP {
		binary.BigEndian.PutUint16(l4[4:], uint16(s.FrameLen-lay.L4Off))
	} else {
		// A bare SYN: sequence 0, no ack, data offset 5, window 64240.
		l4[12] = 5 << 4 // data offset, no options
		l4[13] = 0x02   // SYN
		binary.BigEndian.PutUint16(l4[14:], 64240)
	}

	fill(b[lay.HeaderLen:], s.PayloadByte)
	t.recomputeIPChecksum()
	t.recomputeL4Checksum()
	return t, nil
}

// buildIPv6 makes an Ethernet + optional 802.1Q + IPv6 + UDP/TCP frame.
//
// Two things differ from IPv4 and matter here. The IPv6 header has no checksum
// of its own, so there is nothing to maintain at L3. And the UDP checksum is
// mandatory over IPv6 (it may not be left at zero the way we do for IPv4), so
// L4CksumOff is set for UDP as well as TCP, and the port and address mutators
// maintain it incrementally.
func buildIPv6(s Spec) (*Template, error) {
	src, dst := s.SrcIP.Unmap(), s.DstIP.Unmap()
	if !src.Is6() || !dst.Is6() {
		return nil, fmt.Errorf("packet: src %s and dst %s must both be IPv6", s.SrcIP, s.DstIP)
	}
	if s.Proto != ProtoUDP && s.Proto != ProtoTCP {
		return nil, fmt.Errorf("packet: unsupported IP protocol %d (want %d UDP or %d TCP)",
			s.Proto, ProtoUDP, ProtoTCP)
	}

	lay := ethLayout(s.VLAN != 0)
	lay.HasIP = true
	lay.Is6 = true
	lay.L4Off = lay.L3Off + IPv6HeaderLen
	lay.IPLenOff = lay.L3Off + 4 // payload length (everything after the 40-byte header)
	lay.IPCksumOff = -1          // IPv6 has no header checksum
	lay.SrcIPOff = lay.L3Off + 8
	lay.DstIPOff = lay.L3Off + 24
	lay.SrcPortOff = lay.L4Off
	lay.DstPortOff = lay.L4Off + 2
	lay.Proto = s.Proto

	switch s.Proto {
	case ProtoUDP:
		lay.HeaderLen = lay.L4Off + UDPHeaderLen
		lay.L4LenOff = lay.L4Off + 4
		lay.L4CksumOff = lay.L4Off + 6 // mandatory over IPv6
	case ProtoTCP:
		lay.HeaderLen = lay.L4Off + TCPHeaderLen
		lay.L4LenOff = -1
		lay.L4CksumOff = lay.L4Off + 16
	}

	if s.FrameLen < lay.HeaderLen {
		return nil, fmt.Errorf("packet: frame length %d is smaller than the %d-byte header",
			s.FrameLen, lay.HeaderLen)
	}
	if s.Cap < lay.HeaderLen {
		s.Cap = lay.HeaderLen
	}

	t := &Template{
		buf:         make([]byte, s.Cap),
		lay:         lay,
		srcIP:       src,
		dstIP:       dst,
		srcPort:     s.SrcPort,
		dstPort:     s.DstPort,
		frameLen:    s.FrameLen,
		payloadByte: s.PayloadByte,
	}
	b := t.buf

	writeEthernet(b, s, EtherTypeIPv6)

	hop := s.TTL
	if hop == 0 {
		hop = 64
	}
	s16, d16 := src.As16(), dst.As16()
	ip := b[lay.L3Off:]
	ip[0] = 0x60 // version 6, traffic class 0
	ip[1], ip[2], ip[3] = 0, 0, 0
	binary.BigEndian.PutUint16(ip[4:], uint16(s.FrameLen-lay.L4Off)) // payload length
	ip[6] = s.Proto                                                  // next header
	ip[7] = hop
	copy(ip[8:24], s16[:])
	copy(ip[24:40], d16[:])

	l4 := b[lay.L4Off:]
	binary.BigEndian.PutUint16(l4[0:], s.SrcPort)
	binary.BigEndian.PutUint16(l4[2:], s.DstPort)
	if s.Proto == ProtoUDP {
		binary.BigEndian.PutUint16(l4[4:], uint16(s.FrameLen-lay.L4Off))
	} else {
		l4[12] = 5 << 4 // data offset, no options
		l4[13] = 0x02   // SYN
		binary.BigEndian.PutUint16(l4[14:], 64240)
	}

	fill(b[lay.HeaderLen:], s.PayloadByte)
	t.recomputeL4Checksum() // no IP checksum on IPv6
	return t, nil
}

func ethLayout(vlan bool) Layout {
	if vlan {
		return Layout{HasVLAN: true, L3Off: EthHeaderLen + VLANTagLen}
	}
	return Layout{L3Off: EthHeaderLen}
}

// writeEthernet lays down the MAC addresses, an optional 802.1Q tag, and the
// inner EtherType.
func writeEthernet(b []byte, s Spec, inner uint16) {
	copy(b[0:6], s.DstMAC[:])
	copy(b[6:12], s.SrcMAC[:])
	if s.VLAN != 0 {
		binary.BigEndian.PutUint16(b[12:], EtherTypeVLAN)
		// TCI: 3-bit PCP, 1-bit DEI (always 0), 12-bit VLAN ID.
		binary.BigEndian.PutUint16(b[14:], uint16(s.PCP&0x7)<<13|s.VLAN&0x0fff)
		binary.BigEndian.PutUint16(b[16:], inner)
		return
	}
	binary.BigEndian.PutUint16(b[12:], inner)
}

func fill(b []byte, v byte) {
	for i := range b {
		b[i] = v
	}
}

// Layout returns where each mutable field lives.
func (t *Template) Layout() Layout { return t.lay }

// Len returns the current frame length in bytes written (excluding the FCS).
func (t *Template) Len() int { return t.frameLen }

// Bytes returns the current frame. The slice aliases the Template's buffer and
// is only valid until the next mutation; do not retain it.
func (t *Template) Bytes() []byte { return t.buf[:t.frameLen] }

// WriteTo copies the current frame into dst and returns how many bytes it
// wrote. dst must be at least Len() bytes. This is the only per-packet copy on
// the transmit path, and it allocates nothing.
func (t *Template) WriteTo(dst []byte) int {
	return copy(dst, t.buf[:t.frameLen])
}

// SetSrcIP changes the source address, repairing the IPv4 header checksum (IPv6
// has none) and, wherever an L4 checksum is maintained, its pseudo-header part.
// It is a no-op for a non-IP template. The address family must match the one the
// template was built for.
func (t *Template) SetSrcIP(ip netip.Addr) {
	if !t.lay.HasIP || ip == t.srcIP {
		return
	}
	old := t.srcIP
	t.srcIP = ip
	t.writeAddr(t.lay.SrcIPOff, ip)
	if t.lay.Is6 {
		t.patchL4Checksum(func(c uint16) uint16 { return replaceAddr6(c, old, ip) })
		return
	}
	o, n := old.As4(), ip.As4()
	t.patchIPChecksum(func(c uint16) uint16 { return ReplaceU32(c, o, n) })
	t.patchL4Checksum(func(c uint16) uint16 { return ReplaceU32(c, o, n) })
}

// SetDstIP changes the destination address, repairing the same checksums.
func (t *Template) SetDstIP(ip netip.Addr) {
	if !t.lay.HasIP || ip == t.dstIP {
		return
	}
	old := t.dstIP
	t.dstIP = ip
	t.writeAddr(t.lay.DstIPOff, ip)
	if t.lay.Is6 {
		t.patchL4Checksum(func(c uint16) uint16 { return replaceAddr6(c, old, ip) })
		return
	}
	o, n := old.As4(), ip.As4()
	t.patchIPChecksum(func(c uint16) uint16 { return ReplaceU32(c, o, n) })
	t.patchL4Checksum(func(c uint16) uint16 { return ReplaceU32(c, o, n) })
}

// writeAddr copies an address into the buffer at off: 4 bytes for IPv4, 16 for
// IPv6, chosen by the template's family.
func (t *Template) writeAddr(off int, a netip.Addr) {
	if t.lay.Is6 {
		b := a.As16()
		copy(t.buf[off:], b[:])
		return
	}
	b := a.As4()
	copy(t.buf[off:], b[:])
}

// replaceAddr6 updates a checksum for a 128-bit address change, as four 32-bit
// incremental replacements (RFC 1624).
func replaceAddr6(c uint16, old, new netip.Addr) uint16 {
	o, n := old.As16(), new.As16()
	for i := 0; i < 16; i += 4 {
		c = ReplaceU32(c, [4]byte(o[i:i+4]), [4]byte(n[i:i+4]))
	}
	return c
}

// SetSrcPort changes the L4 source port. The IPv4 header checksum does not
// cover ports, so only the L4 checksum needs repairing — and for UDP, whose
// checksum is left at zero, not even that.
func (t *Template) SetSrcPort(p uint16) {
	if !t.lay.HasIP || p == t.srcPort {
		return
	}
	old := t.srcPort
	t.srcPort = p
	binary.BigEndian.PutUint16(t.buf[t.lay.SrcPortOff:], p)
	t.patchL4Checksum(func(c uint16) uint16 { return ReplaceU16(c, old, p) })
}

// SetDstPort changes the L4 destination port.
func (t *Template) SetDstPort(p uint16) {
	if !t.lay.HasIP || p == t.dstPort {
		return
	}
	old := t.dstPort
	t.dstPort = p
	binary.BigEndian.PutUint16(t.buf[t.lay.DstPortOff:], p)
	t.patchL4Checksum(func(c uint16) uint16 { return ReplaceU16(c, old, p) })
}

// SetFrameLen changes how many bytes the next packet occupies, updating the
// IPv4 total length and the UDP length. This is how IMIX varies frame size
// without rebuilding anything.
//
// For UDP the update is incremental and cheap. For TCP the length is part of
// the checksummed pseudo-header and changes which payload bytes are covered,
// so the L4 checksum is recomputed in full — TCP modes are fixed-size, so that
// never happens on a hot path.
func (t *Template) SetFrameLen(n int) error {
	if n == t.frameLen {
		return nil
	}
	if n < t.lay.HeaderLen {
		return fmt.Errorf("packet: frame length %d is smaller than the %d-byte header", n, t.lay.HeaderLen)
	}
	if n > len(t.buf) {
		return fmt.Errorf("packet: frame length %d exceeds the %d-byte template capacity", n, len(t.buf))
	}
	old := t.frameLen
	t.frameLen = n
	if !t.lay.HasIP {
		return nil
	}

	if t.lay.Is6 {
		// IPv6's length field is the payload length (everything after the fixed
		// 40-byte header), and there is no IP header checksum to repair.
		binary.BigEndian.PutUint16(t.buf[t.lay.IPLenOff:], uint16(n-t.lay.L4Off))
	} else {
		oldIPLen := uint16(old - t.lay.L3Off)
		newIPLen := uint16(n - t.lay.L3Off)
		binary.BigEndian.PutUint16(t.buf[t.lay.IPLenOff:], newIPLen)
		t.patchIPChecksum(func(c uint16) uint16 { return ReplaceU16(c, oldIPLen, newIPLen) })
	}

	if t.lay.L4LenOff >= 0 {
		binary.BigEndian.PutUint16(t.buf[t.lay.L4LenOff:], uint16(n-t.lay.L4Off))
	}
	// A size change moves both the pseudo-header length and which payload bytes
	// the checksum covers, so where an L4 checksum is maintained it is recomputed
	// in full. IPv4 UDP keeps its checksum at zero and skips this; IPv6 UDP must
	// not, so an IMIX over IPv6 pays this per size change.
	if t.lay.L4CksumOff >= 0 {
		t.recomputeL4Checksum()
	}
	return nil
}

func (t *Template) patchIPChecksum(f func(uint16) uint16) {
	if t.lay.IPCksumOff < 0 {
		return
	}
	cur := binary.BigEndian.Uint16(t.buf[t.lay.IPCksumOff:])
	binary.BigEndian.PutUint16(t.buf[t.lay.IPCksumOff:], f(cur))
}

func (t *Template) patchL4Checksum(f func(uint16) uint16) {
	if t.lay.L4CksumOff < 0 {
		return
	}
	cur := binary.BigEndian.Uint16(t.buf[t.lay.L4CksumOff:])
	binary.BigEndian.PutUint16(t.buf[t.lay.L4CksumOff:], f(cur))
}

// recomputeIPChecksum recalculates the IPv4 header checksum from scratch. Used
// at build time; the mutators patch it incrementally instead.
func (t *Template) recomputeIPChecksum() {
	if t.lay.IPCksumOff < 0 {
		return
	}
	hdr := t.buf[t.lay.L3Off : t.lay.L3Off+IPv4HeaderLen]
	binary.BigEndian.PutUint16(t.buf[t.lay.IPCksumOff:], 0)
	binary.BigEndian.PutUint16(t.buf[t.lay.IPCksumOff:], Checksum(hdr))
}

// recomputeL4Checksum recalculates the L4 checksum over the pseudo-header, the
// L4 header and the payload. It runs only where a checksum is maintained (TCP
// for both families, and UDP over IPv6); IPv4 UDP leaves L4CksumOff unset and
// keeps its checksum at zero.
func (t *Template) recomputeL4Checksum() {
	if t.lay.L4CksumOff < 0 {
		return
	}
	l4 := t.buf[t.lay.L4Off:t.frameLen]
	binary.BigEndian.PutUint16(t.buf[t.lay.L4CksumOff:], 0)
	var sum uint32
	if t.lay.Is6 {
		sum = PseudoHeaderSum6(t.srcIP.As16(), t.dstIP.As16(), t.lay.Proto, len(l4))
	} else {
		sum = PseudoHeaderSum(t.srcIP.As4(), t.dstIP.As4(), t.lay.Proto, len(l4))
	}
	sum = partialSum(l4, sum)
	c := ^foldSum(sum)
	// Over IPv6 a UDP checksum of zero is illegal (it means "no checksum"), so a
	// computed zero is transmitted as 0xFFFF instead (RFC 8200 section 8.1). TCP
	// has no such rule, and IPv4 UDP never reaches here.
	if c == 0 && t.lay.Is6 && t.lay.Proto == ProtoUDP {
		c = 0xffff
	}
	binary.BigEndian.PutUint16(t.buf[t.lay.L4CksumOff:], c)
}
