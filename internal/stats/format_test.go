package stats

import (
	"strings"
	"testing"
	"time"
)

func TestCount(t *testing.T) {
	tests := []struct {
		in   uint64
		want string
	}{
		{0, "0"},
		{7, "7"},
		{9999, "9999"},
		{10_000, "10 k"},
		{1_234_000, "1.23 M"},
		{14_880_000, "14.88 M"},
		{2_500_000_000, "2.5 G"},
		{3_000_000_000_000, "3 T"},
	}
	for _, tt := range tests {
		if got := Count(tt.in); got != tt.want {
			t.Errorf("Count(%d) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestPPSAndBits(t *testing.T) {
	if got := PPS(14_880_000); got != "14.88 Mpps" {
		t.Errorf("PPS = %q, want 14.88 Mpps", got)
	}
	if got := PPS(1500); got != "1.5 kpps" {
		t.Errorf("PPS = %q, want 1.5 kpps", got)
	}
	if got := PPS(12); got != "12 pps" {
		t.Errorf("PPS = %q, want 12 pps", got)
	}
	if got := Bits(9.87e9); got != "9.87 Gbit/s" {
		t.Errorf("Bits = %q, want 9.87 Gbit/s", got)
	}
	if got := Bits(100e6); got != "100 Mbit/s" {
		t.Errorf("Bits = %q, want 100 Mbit/s", got)
	}
}

func TestBytesAndDuration(t *testing.T) {
	if got := Bytes(999); got != "999 B" {
		t.Errorf("Bytes = %q, want 999 B", got)
	}
	if got := Bytes(3_210_000_000); got != "3.21 GB" {
		t.Errorf("Bytes = %q, want 3.21 GB", got)
	}
	tests := []struct {
		in   time.Duration
		want string
	}{
		{0, "0:00"},
		{-time.Second, "0:00"},
		{30 * time.Second, "0:30"},
		{90 * time.Second, "1:30"},
		{3661 * time.Second, "1:01:01"},
	}
	for _, tt := range tests {
		if got := Duration(tt.in); got != tt.want {
			t.Errorf("Duration(%v) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestSnapshotLine(t *testing.T) {
	c := New(1, 30*time.Second, nil)
	c.Queue(0).AddTx(1000, 60_000, ClassUDP)
	c.Queue(0).AddRx(60, ClassUDP)
	s := c.Sample()

	line := s.Line()
	// Both bit rates must be named, in the vocabulary T-Rex uses. An
	// unlabelled pair is what made these numbers confusing in the first place.
	for _, want := range []string{"tx", "pkts", "L1", "L2", "avg"} {
		if !strings.Contains(line, want) {
			t.Errorf("Line() = %q, missing %q", line, want)
		}
	}
	if strings.Contains(line, "\n") {
		t.Errorf("Line() must be a single line, got %q", line)
	}

	c.SetState(StatePaused)
	if !strings.Contains(c.Sample().Line(), "[paused]") {
		t.Error("a paused run should say so on its status line")
	}
}

func TestSnapshotSummary(t *testing.T) {
	c := New(1, 0, func() (Kernel, error) {
		return Kernel{RxDropped: 5, PerQueue: []KernelQueue{{Queue: 0, RxDropped: 5}}}, nil
	})
	c.Queue(0).AddTx(700, 700*60, ClassUDP)
	c.Queue(0).AddTx(100, 100*590, ClassTCP)
	c.Queue(0).AddRx(64, ClassOther)
	c.ResetInterval() // must not affect the summary
	s := c.Sample()

	sum := s.Summary()
	for _, want := range []string{"ran for", "tx:", "L1", "L2", "udp", "tcp", "rx:", "drops", "queue 0"} {
		if !strings.Contains(sum, want) {
			t.Errorf("Summary() missing %q:\n%s", want, sum)
		}
	}
	// The summary reports lifetime totals, so an interval reset is invisible.
	if !strings.Contains(sum, "800") {
		t.Errorf("Summary() should report the 800 lifetime packets:\n%s", sum)
	}
	if strings.HasSuffix(sum, "\n") {
		t.Error("Summary() should not end with a newline")
	}
}
