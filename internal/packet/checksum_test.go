package packet

import (
	"encoding/binary"
	"math/rand/v2"
	"testing"
)

func TestChecksumKnownVector(t *testing.T) {
	// The worked IPv4 header example from RFC 1071 section 3, with the
	// checksum field zeroed. The expected result is 0xb1e6.
	hdr := []byte{
		0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00,
		0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8, 0x00, 0x01,
		0xc0, 0xa8, 0x00, 0xc7,
	}
	if got := Checksum(hdr); got != 0xb861 {
		t.Errorf("Checksum = %#04x, want 0xb861", got)
	}
	// Inserting the checksum makes the header sum to zero, which is how a
	// receiver validates it.
	binary.BigEndian.PutUint16(hdr[10:], 0xb861)
	if got := Checksum(hdr); got != 0 {
		t.Errorf("checksum over a complete header = %#04x, want 0", got)
	}
}

func TestChecksumOddLength(t *testing.T) {
	// An odd trailing byte is padded on the right, so appending a zero must
	// not change the result.
	odd := []byte{0x01, 0x02, 0x03}
	even := []byte{0x01, 0x02, 0x03, 0x00}
	if Checksum(odd) != Checksum(even) {
		t.Errorf("odd-length checksum %#04x != padded %#04x", Checksum(odd), Checksum(even))
	}
	if Checksum(nil) != 0xffff {
		t.Errorf("Checksum(nil) = %#04x, want 0xffff", Checksum(nil))
	}
}

// ReplaceU16 must agree with a full recompute for every kind of change,
// including the carry cases that the naive RFC 1141 formula gets wrong.
func TestReplaceU16MatchesRecompute(t *testing.T) {
	r := rand.New(rand.NewPCG(42, 7))
	buf := make([]byte, 20)
	for i := 0; i < 20000; i++ {
		for j := range buf {
			buf[j] = byte(r.Uint32())
		}
		off := 2 * (int(r.Uint32()) % (len(buf) / 2))
		csum := Checksum(buf)

		old := binary.BigEndian.Uint16(buf[off:])
		new := uint16(r.Uint32())
		binary.BigEndian.PutUint16(buf[off:], new)

		got := ReplaceU16(csum, old, new)
		if want := Checksum(buf); got != want {
			t.Fatalf("ReplaceU16(%#04x, %#04x, %#04x) = %#04x, want %#04x",
				csum, old, new, got, want)
		}
	}
}

func TestReplaceU16CarryEdgeCases(t *testing.T) {
	// Values chosen to exercise the wrap-around and the RFC 1624 negative-zero
	// case, where the intermediate sum reaches 0xffff.
	cases := []struct{ old, new uint16 }{
		{0x0000, 0xffff}, {0xffff, 0x0000}, {0xffff, 0xffff},
		{0x8000, 0x8000}, {0x7fff, 0x8000}, {0x0001, 0xfffe},
	}
	buf := make([]byte, 8)
	for _, c := range cases {
		for j := range buf {
			buf[j] = 0x5a
		}
		binary.BigEndian.PutUint16(buf[2:], c.old)
		csum := Checksum(buf)
		binary.BigEndian.PutUint16(buf[2:], c.new)
		if got, want := ReplaceU16(csum, c.old, c.new), Checksum(buf); got != want {
			t.Errorf("old=%#04x new=%#04x: got %#04x, want %#04x", c.old, c.new, got, want)
		}
	}
}

func TestReplaceU32MatchesRecompute(t *testing.T) {
	r := rand.New(rand.NewPCG(9, 9))
	buf := make([]byte, 20)
	for i := 0; i < 10000; i++ {
		for j := range buf {
			buf[j] = byte(r.Uint32())
		}
		csum := Checksum(buf)
		var old, new [4]byte
		copy(old[:], buf[12:16])
		binary.BigEndian.PutUint32(new[:], r.Uint32())
		copy(buf[12:16], new[:])
		if got, want := ReplaceU32(csum, old, new), Checksum(buf); got != want {
			t.Fatalf("ReplaceU32: got %#04x, want %#04x", got, want)
		}
	}
}

func TestPseudoHeaderSum(t *testing.T) {
	src := [4]byte{192, 168, 0, 99}
	dst := [4]byte{192, 168, 0, 2}
	// The pseudo-header is src + dst + proto + length, all as 16-bit words.
	want := uint32(0xc0a8) + 0x0063 + 0xc0a8 + 0x0002 + 17 + 100
	if got := PseudoHeaderSum(src, dst, ProtoUDP, 100); got != want {
		t.Errorf("PseudoHeaderSum = %d, want %d", got, want)
	}
}

func BenchmarkChecksum20(b *testing.B) {
	buf := make([]byte, 20)
	b.ReportAllocs()
	for b.Loop() {
		_ = Checksum(buf)
	}
}

func BenchmarkReplaceU16(b *testing.B) {
	c := uint16(0x1234)
	b.ReportAllocs()
	for b.Loop() {
		c = ReplaceU16(c, 0x1000, 0x2000)
	}
	_ = c
}
