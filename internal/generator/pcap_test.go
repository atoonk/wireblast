package generator

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"github.com/atoonk/wireblast/internal/config"
	"github.com/atoonk/wireblast/internal/stats"
)

// fakeFrames is a FrameSource built in memory, so replay can be tested without
// a file on disk.
type fakeFrames struct {
	frames [][]byte
	gaps   []time.Duration
}

func (f *fakeFrames) Len() int { return len(f.frames) }
func (f *fakeFrames) Frame(i int) ([]byte, time.Duration) {
	return f.frames[i], f.gaps[i]
}
func (f *fakeFrames) MaxLen() int {
	n := 0
	for _, fr := range f.frames {
		n = max(n, len(fr))
	}
	return n
}
func (f *fakeFrames) MeanLen() int {
	n := 0
	for _, fr := range f.frames {
		n += len(fr)
	}
	return n / len(f.frames)
}
func (f *fakeFrames) Describe() string {
	return fmt.Sprintf("test capture: %d packets", len(f.frames))
}
func (f *fakeFrames) Warnings() []string { return nil }

// ethFrame builds an Ethernet frame with recognisable MACs and a marker byte.
func ethFrame(n int, marker byte, proto uint8) []byte {
	b := make([]byte, n)
	copy(b[0:6], []byte{0x0a, 0, 0, 0, 0, 0x01})
	copy(b[6:12], []byte{0x0a, 0, 0, 0, 0, 0x02})
	binary.BigEndian.PutUint16(b[12:], 0x0800)
	b[14] = 0x45
	b[23] = proto
	for i := 24; i < n; i++ {
		b[i] = marker
	}
	return b
}

func threeFrames() *fakeFrames {
	return &fakeFrames{
		frames: [][]byte{
			ethFrame(64, 0xa1, 17),
			ethFrame(128, 0xa2, 6),
			ethFrame(256, 0xa3, 1),
		},
		gaps: []time.Duration{0, 10 * time.Millisecond, 20 * time.Millisecond},
	}
}

func pcapSpec(t *testing.T, queue, queues int, mut func(*config.Config)) Spec {
	t.Helper()
	cfg := config.Default()
	cfg.Interface = "eth0"
	cfg.Mode = config.ModePCAP
	cfg.PCAPFile = "test.pcap"
	if mut != nil {
		mut(&cfg)
	}
	return Spec{
		Cfg: &cfg, SrcMAC: testSrcMAC, DstMAC: testDstMAC,
		Queue: queue, Queues: queues, Frames: threeFrames(),
	}
}

// Looping replay cycles the capture in order, forever.
func TestPCAPReplayLoops(t *testing.T) {
	g, err := New(pcapSpec(t, 0, 1, nil))
	if err != nil {
		t.Fatal(err)
	}
	src := threeFrames()
	buf := make([]byte, 2048)
	for i := range 9 { // three full cycles
		n, class := g.Next(buf)
		want, _ := src.Frame(i % 3)
		if n != len(want) {
			t.Fatalf("packet %d is %d bytes, want %d", i, n, len(want))
		}
		if !bytes.Equal(buf[:n], want) {
			t.Fatalf("packet %d does not match the capture", i)
		}
		// The class comes from the replayed packet, not from the mode.
		wantClass := []stats.Class{stats.ClassUDP, stats.ClassTCP, stats.ClassOther}[i%3]
		if class != wantClass {
			t.Errorf("packet %d classified as %v, want %v", i, class, wantClass)
		}
	}
	// A looping replay never runs out.
	if f, ok := g.(Finite); ok && f.Remaining() >= 0 {
		t.Errorf("a looping replay should be unbounded, Remaining = %d", f.Remaining())
	}
}

// One-pass replay sends the capture exactly once, in order, and then stops.
func TestPCAPOnePassSendsTheCaptureOnce(t *testing.T) {
	g, err := New(pcapSpec(t, 0, 1, func(c *config.Config) { c.PCAPLoop = false }))
	if err != nil {
		t.Fatal(err)
	}
	fin, ok := g.(Finite)
	if !ok {
		t.Fatal("a one-pass replay must report how much is left")
	}
	if fin.Remaining() != 3 {
		t.Fatalf("Remaining = %d, want 3", fin.Remaining())
	}

	buf := make([]byte, 2048)
	src := threeFrames()
	for i := range 3 {
		n, _ := g.Next(buf)
		want, _ := src.Frame(i)
		if !bytes.Equal(buf[:n], want) {
			t.Fatalf("packet %d does not match the capture", i)
		}
		if got, want := fin.Remaining(), 3-i-1; got != want {
			t.Errorf("after packet %d, Remaining = %d, want %d", i, got, want)
		}
	}
	if fin.Remaining() != 0 {
		t.Errorf("Remaining = %d after the whole capture, want 0", fin.Remaining())
	}
	// Asking for more must produce nothing rather than an empty frame.
	if n, _ := g.Next(buf); n != 0 {
		t.Errorf("a finished one-pass replay produced %d bytes, want 0", n)
	}
}

// Spread over queues, a one-pass replay must still send exactly one copy — so
// only queue 0 does the work.
func TestPCAPOnePassRunsOnOneQueue(t *testing.T) {
	total := 0
	buf := make([]byte, 2048)
	for q := range 4 {
		g, err := New(pcapSpec(t, q, 4, func(c *config.Config) { c.PCAPLoop = false }))
		if err != nil {
			t.Fatal(err)
		}
		fin, ok := g.(Finite)
		if !ok {
			t.Fatalf("queue %d: generator must be finite in one-pass mode", q)
		}
		for fin.Remaining() != 0 {
			if n, _ := g.Next(buf); n > 0 {
				total++
			}
		}
		if q > 0 && total != 3 {
			t.Errorf("queue %d sent packets; a one-pass replay belongs to queue 0 alone", q)
		}
	}
	if total != 3 {
		t.Errorf("a one-pass replay across 4 queues sent %d packets, want exactly 3", total)
	}
}

// Looping replay runs on every queue, so throughput scales.
func TestPCAPLoopRunsOnEveryQueue(t *testing.T) {
	buf := make([]byte, 2048)
	for q := range 4 {
		g, err := New(pcapSpec(t, q, 4, nil))
		if err != nil {
			t.Fatal(err)
		}
		if n, _ := g.Next(buf); n == 0 {
			t.Errorf("queue %d produced nothing; a looping replay should run everywhere", q)
		}
	}
}

// By default the capture's own addresses are preserved.
func TestPCAPPreservesMACsByDefault(t *testing.T) {
	g, err := New(pcapSpec(t, 0, 1, nil))
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	n, _ := g.Next(buf)
	orig, _ := threeFrames().Frame(0)
	if !bytes.Equal(buf[:12], orig[:12]) {
		t.Errorf("MACs were rewritten without being asked: %x, want %x", buf[:12], orig[:12])
	}
	_ = n
}

// ...and are rewritten only when the user supplies one.
func TestPCAPMACOverride(t *testing.T) {
	s := pcapSpec(t, 0, 1, func(c *config.Config) {
		c.DstMAC = "aa:bb:cc:dd:ee:ff"
	})
	g, err := New(s)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	g.Next(buf)
	if !bytes.Equal(buf[0:6], testDstMAC[:]) {
		t.Errorf("destination MAC = %x, want the override %x", buf[0:6], testDstMAC)
	}
	if !bytes.Equal(buf[6:12], testSrcMAC[:]) {
		t.Errorf("source MAC = %x, want the override %x", buf[6:12], testSrcMAC)
	}
	// The rest of the packet is untouched.
	orig, _ := threeFrames().Frame(0)
	if !bytes.Equal(buf[12:64], orig[12:64]) {
		t.Error("the MAC override changed bytes beyond the addresses")
	}
}

// With original timing the generator paces itself from the capture's gaps.
func TestPCAPOriginalTimingPaces(t *testing.T) {
	g, err := New(pcapSpec(t, 0, 1, func(c *config.Config) {
		c.PCAPTiming = config.PcapOriginal
	}))
	if err != nil {
		t.Fatal(err)
	}
	pacer, ok := g.(Pacer)
	if !ok {
		t.Fatal("original timing must make the generator a Pacer")
	}

	buf := make([]byte, 2048)
	// The delay reported before each packet is the capture's own gap, and the
	// cycle repeats when the replay loops.
	want := []time.Duration{0, 10 * time.Millisecond, 20 * time.Millisecond, 0, 10 * time.Millisecond}
	for i, w := range want {
		if got := pacer.Delay(); got != w {
			t.Errorf("delay before packet %d = %v, want %v", i, got, w)
		}
		g.Next(buf)
	}
}

// In rate mode the capture's timing is ignored; the limiters govern instead.
func TestPCAPRateTimingIsNotAPacer(t *testing.T) {
	g, err := New(pcapSpec(t, 0, 1, func(c *config.Config) {
		c.PCAPTiming = config.PcapRate
	}))
	if err != nil {
		t.Fatal(err)
	}
	if p, ok := g.(Pacer); ok && p.Delay() != 0 {
		t.Errorf("rate timing should impose no delay, got %v", p.Delay())
	}
}

func TestPCAPSizingAndDescription(t *testing.T) {
	g, err := New(pcapSpec(t, 0, 1, nil))
	if err != nil {
		t.Fatal(err)
	}
	if g.MaxFrameLen() != 256 {
		t.Errorf("MaxFrameLen = %d, want 256 (the largest frame)", g.MaxFrameLen())
	}
	// The limiter's estimate is the mean frame plus the wire framing.
	if want := (64+128+256)/3 + wireOverhead; g.AvgWireBytes() != want {
		t.Errorf("AvgWireBytes = %d, want %d", g.AvgWireBytes(), want)
	}
	if g.Describe() == "" {
		t.Error("the capture should describe itself for the review screen")
	}
}

func TestPCAPNeedsACapture(t *testing.T) {
	s := pcapSpec(t, 0, 1, nil)
	s.Frames = nil
	if _, err := New(s); err == nil {
		t.Error("pcap mode without a loaded capture should fail")
	}
	s.Frames = &fakeFrames{}
	if _, err := New(s); err == nil {
		t.Error("an empty capture should fail")
	}
}

func BenchmarkPCAPNext(b *testing.B) {
	cfg := config.Default()
	cfg.Mode = config.ModePCAP
	cfg.PCAPFile = "x.pcap"
	g, err := New(Spec{
		Cfg: &cfg, SrcMAC: testSrcMAC, DstMAC: testDstMAC,
		Queues: 1, Frames: threeFrames(),
	})
	if err != nil {
		b.Fatal(err)
	}
	buf := make([]byte, 2048)
	b.ReportAllocs()
	for b.Loop() {
		g.Next(buf)
	}
}
