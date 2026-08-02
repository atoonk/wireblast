// Package packet builds the Ethernet, 802.1Q, IPv4, UDP and TCP headers
// Wireblast transmits.
//
// The design goal is a hot path that allocates nothing and recomputes nothing
// it does not have to. A [Template] is built once per queue; changing a flow
// rewrites only the fields that differ and repairs the checksums incrementally
// (RFC 1624), never by rescanning the header.
//
// Everything here is pure: no sockets, no system calls, no globals. The layout
// is computed from an offset rather than hardcoded constants, so an IPv6
// builder can be added later without disturbing the mutators.
package packet

import "encoding/binary"

// Checksum computes the 16-bit one's-complement checksum of b, as used by
// IPv4, UDP and TCP. An odd-length buffer is padded with a zero byte.
func Checksum(b []byte) uint16 {
	return ^foldSum(partialSum(b, 0))
}

// partialSum accumulates b into an unfolded 32-bit one's-complement sum. It is
// exported through [PseudoHeaderSum] and used to seed checksums that span more
// than one buffer.
func partialSum(b []byte, sum uint32) uint32 {
	for len(b) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	return sum
}

// foldSum folds a 32-bit accumulator down to 16 bits.
func foldSum(sum uint32) uint16 {
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return uint16(sum)
}

// PseudoHeaderSum returns the unfolded partial sum of the IPv4 pseudo-header
// used by UDP and TCP: source address, destination address, protocol number
// and L4 length.
func PseudoHeaderSum(srcIP, dstIP [4]byte, proto uint8, l4Len int) uint32 {
	sum := partialSum(srcIP[:], 0)
	sum = partialSum(dstIP[:], sum)
	sum += uint32(proto)
	sum += uint32(l4Len)
	return sum
}

// PseudoHeaderSum6 returns the unfolded partial sum of the IPv6 pseudo-header
// used by UDP and TCP (RFC 8200 section 8.1): the 128-bit source and
// destination addresses, a 32-bit upper-layer packet length, and the
// next-header value (the three bytes before it are zero and contribute nothing).
func PseudoHeaderSum6(srcIP, dstIP [16]byte, nextHdr uint8, l4Len int) uint32 {
	sum := partialSum(srcIP[:], 0)
	sum = partialSum(dstIP[:], sum)
	sum += uint32(l4Len)
	sum += uint32(nextHdr)
	return sum
}

// ReplaceU16 returns the checksum csum updated for a 16-bit header field whose
// value changed from old to new, without rescanning the packet.
//
// This is RFC 1624 equation 3, HC' = ~(~HC + ~m + m'), which is correct even
// when the intermediate sum would otherwise produce the negative-zero result
// that the naive RFC 1141 formula gets wrong.
func ReplaceU16(csum, old, new uint16) uint16 {
	sum := uint32(^csum) + uint32(^old) + uint32(new)
	return ^foldSum(sum)
}

// ReplaceU32 returns csum updated for a 32-bit field (an IPv4 address, say)
// that changed from old to new. It is two 16-bit replacements.
func ReplaceU32(csum uint16, old, new [4]byte) uint16 {
	csum = ReplaceU16(csum,
		binary.BigEndian.Uint16(old[0:2]), binary.BigEndian.Uint16(new[0:2]))
	return ReplaceU16(csum,
		binary.BigEndian.Uint16(old[2:4]), binary.BigEndian.Uint16(new[2:4]))
}
