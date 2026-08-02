package pcapfile

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

// frame builds a plausible Ethernet frame of the given length, tagged with a
// recognisable byte so tests can tell frames apart.
func frame(n int, marker byte) []byte {
	b := make([]byte, n)
	copy(b[0:6], []byte{0x02, 0, 0, 0, 0, 0x01})  // destination MAC
	copy(b[6:12], []byte{0x02, 0, 0, 0, 0, 0x02}) // source MAC
	binary.BigEndian.PutUint16(b[12:], 0x0800)    // IPv4
	if n > 14 {
		b[14] = 0x45
	}
	if n > 23 {
		b[23] = 17 // UDP
	}
	for i := 24; i < n; i++ {
		b[i] = marker
	}
	return b
}

type capPacket struct {
	data []byte
	at   time.Duration // offset from the start of the capture
	// origLen, when larger than len(data), marks the packet as truncated by
	// the capture's snaplen.
	origLen int
}

// writePcap writes a classic pcap file and returns its path.
func writePcap(t *testing.T, link layers.LinkType, pkts []capPacket) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.pcap")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65536, link); err != nil {
		t.Fatal(err)
	}
	base := time.Unix(1700000000, 0)
	for _, p := range pkts {
		orig := p.origLen
		if orig == 0 {
			orig = len(p.data)
		}
		ci := gopacket.CaptureInfo{
			Timestamp:     base.Add(p.at),
			CaptureLength: len(p.data),
			Length:        orig,
		}
		if err := w.WritePacket(ci, p.data); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

func writePcapng(t *testing.T, pkts []capPacket) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.pcapng")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	w, err := pcapgo.NewNgWriter(f, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatal(err)
	}
	base := time.Unix(1700000000, 0)
	for _, p := range pkts {
		ci := gopacket.CaptureInfo{
			Timestamp:     base.Add(p.at),
			CaptureLength: len(p.data),
			Length:        len(p.data),
		}
		if err := w.WritePacket(ci, p.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadEthernetCapture(t *testing.T) {
	path := writePcap(t, layers.LinkTypeEthernet, []capPacket{
		{data: frame(64, 0xa1), at: 0},
		{data: frame(1514, 0xa2), at: 10 * time.Millisecond},
		{data: frame(128, 0xa3), at: 25 * time.Millisecond},
	})

	f, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if f.Len() != 3 {
		t.Fatalf("Len = %d, want 3", f.Len())
	}
	if f.MinLen() != 64 || f.MaxLen() != 1514 {
		t.Errorf("size range = %d-%d, want 64-1514", f.MinLen(), f.MaxLen())
	}
	if want := (64 + 1514 + 128) / 3; f.MeanLen() != want {
		t.Errorf("MeanLen = %d, want %d", f.MeanLen(), want)
	}
	if f.Span() != 25*time.Millisecond {
		t.Errorf("Span = %v, want 25ms", f.Span())
	}
	if f.Bytes() != 64+1514+128 {
		t.Errorf("Bytes = %d, want %d", f.Bytes(), 64+1514+128)
	}

	// Frames come back byte-identical and in order.
	for i, want := range [][]byte{frame(64, 0xa1), frame(1514, 0xa2), frame(128, 0xa3)} {
		got, _ := f.Frame(i)
		if !bytes.Equal(got, want) {
			t.Errorf("frame %d does not match what was written", i)
		}
	}

	// The gaps are the capture's own inter-packet timing.
	for i, want := range []time.Duration{0, 10 * time.Millisecond, 15 * time.Millisecond} {
		if _, gap := f.Frame(i); gap != want {
			t.Errorf("gap before frame %d = %v, want %v", i, gap, want)
		}
	}

	desc := f.Describe()
	for _, want := range []string{"3 packets", "64-1514", "mean", "spanning"} {
		if !strings.Contains(desc, want) {
			t.Errorf("Describe = %q, missing %q", desc, want)
		}
	}
	if len(f.Warnings()) != 0 {
		t.Errorf("a clean capture should have no warnings, got %v", f.Warnings())
	}
}

func TestLoadPcapng(t *testing.T) {
	path := writePcapng(t, []capPacket{
		{data: frame(64, 0xb1), at: 0},
		{data: frame(300, 0xb2), at: 5 * time.Millisecond},
	})
	f, err := Load(path)
	if err != nil {
		t.Fatalf("Load pcapng: %v", err)
	}
	if f.Len() != 2 {
		t.Fatalf("Len = %d, want 2", f.Len())
	}
	if got, _ := f.Frame(1); len(got) != 300 {
		t.Errorf("second frame is %d bytes, want 300", len(got))
	}
}

// An unsupported link type must name itself, not fail obscurely.
func TestRejectsNonEthernetLinkTypes(t *testing.T) {
	for _, lt := range []layers.LinkType{layers.LinkTypeRaw, layers.LinkTypeLinuxSLL} {
		path := writePcap(t, lt, []capPacket{{data: frame(64, 1)}})
		_, err := Load(path)
		if err == nil {
			t.Errorf("link type %v should be rejected", lt)
			continue
		}
		for _, want := range []string{"link type", "Ethernet"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error for %v = %q, should mention %q", lt, err, want)
			}
		}
	}
}

func TestRejectsMalformedCaptures(t *testing.T) {
	dir := t.TempDir()

	t.Run("not a capture at all", func(t *testing.T) {
		path := filepath.Join(dir, "junk.bin")
		if err := os.WriteFile(path, []byte("this is not a pcap file at all"), 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := Load(path)
		if err == nil || !strings.Contains(err.Error(), "not a readable pcap") {
			t.Fatalf("error = %v, want a clear 'not a pcap' message", err)
		}
	})

	t.Run("missing file", func(t *testing.T) {
		if _, err := Load(filepath.Join(dir, "nope.pcap")); err == nil {
			t.Fatal("a missing file should fail")
		}
	})

	t.Run("empty capture", func(t *testing.T) {
		path := writePcap(t, layers.LinkTypeEthernet, nil)
		_, err := Load(path)
		if err == nil || !strings.Contains(err.Error(), "no packets") {
			t.Fatalf("error = %v, want a 'no packets' message", err)
		}
	})

	t.Run("runt frame", func(t *testing.T) {
		path := writePcap(t, layers.LinkTypeEthernet, []capPacket{
			{data: frame(64, 1)},
			{data: make([]byte, 6)}, // too short to be Ethernet
		})
		_, err := Load(path)
		if err == nil {
			t.Fatal("a 6-byte record should be rejected")
		}
		// The message must say which packet, so a big capture is debuggable.
		for _, want := range []string{"packet 2", "too short"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error = %q, should mention %q", err, want)
			}
		}
	})

	t.Run("oversized frame", func(t *testing.T) {
		path := writePcap(t, layers.LinkTypeEthernet, []capPacket{
			{data: frame(MaxFrame+1, 1)},
		})
		_, err := Load(path)
		if err == nil || !strings.Contains(err.Error(), "larger than") {
			t.Fatalf("error = %v, want a size-limit message", err)
		}
	})
}

// Frames cut short by the capture's snaplen still replay, but the user is told.
func TestTruncatedFramesAreReported(t *testing.T) {
	path := writePcap(t, layers.LinkTypeEthernet, []capPacket{
		{data: frame(64, 1)},
		{data: frame(64, 2), origLen: 1514}, // captured 64 of a 1514-byte packet
	})
	f, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if f.Truncated() != 1 {
		t.Errorf("Truncated = %d, want 1", f.Truncated())
	}
	warns := strings.Join(f.Warnings(), " ")
	for _, want := range []string{"truncated", "snapshot length"} {
		if !strings.Contains(warns, want) {
			t.Errorf("warnings = %q, should mention %q", warns, want)
		}
	}
	if !strings.Contains(f.Describe(), "truncated") {
		t.Errorf("Describe should mention truncation: %q", f.Describe())
	}
}

// A capture whose clock goes backwards must not produce a negative delay.
func TestOutOfOrderTimestampsGiveNoNegativeGaps(t *testing.T) {
	path := writePcap(t, layers.LinkTypeEthernet, []capPacket{
		{data: frame(64, 1), at: 100 * time.Millisecond},
		{data: frame(64, 2), at: 50 * time.Millisecond}, // earlier than the one before
		{data: frame(64, 3), at: 150 * time.Millisecond},
	})
	f, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := range f.Len() {
		if _, gap := f.Frame(i); gap < 0 {
			t.Errorf("frame %d has a negative gap %v", i, gap)
		}
	}
	if _, gap := f.Frame(1); gap != 0 {
		t.Errorf("a backwards timestamp should give a zero gap, got %v", gap)
	}
}

// The whole file is read before anything else happens, so an unusable capture
// costs an error message and not a bounced link.
func TestValidationHappensAtLoadTime(t *testing.T) {
	path := writePcap(t, layers.LinkTypeEthernet, []capPacket{
		{data: frame(64, 1)},
		{data: make([]byte, 3)},
	})
	if _, err := Load(path); err == nil {
		t.Fatal("Load must reject the capture up front, not at transmit time")
	}
}

func BenchmarkFrameLookup(b *testing.B) {
	dir := b.TempDir()
	path := filepath.Join(dir, "bench.pcap")
	f, _ := os.Create(path)
	w := pcapgo.NewWriter(f)
	_ = w.WriteFileHeader(65536, layers.LinkTypeEthernet)
	base := time.Unix(1700000000, 0)
	for i := range 1000 {
		data := frame(64+i%1000, byte(i))
		_ = w.WritePacket(gopacket.CaptureInfo{
			Timestamp:     base.Add(time.Duration(i) * time.Microsecond),
			CaptureLength: len(data), Length: len(data),
		}, data)
	}
	f.Close()

	cap, err := Load(path)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	i := 0
	for b.Loop() {
		i++
		_, _ = cap.Frame(i % cap.Len())
	}
}
