package tui

import (
	"strings"
	"testing"
)

// runes is a convenience for asserting on individual cells.
func runes(s string) []rune { return []rune(s) }

func TestSparklineScalesToPeak(t *testing.T) {
	got := sparkline([]float64{0, 1, 2, 3, 4, 5, 6, 7, 8}, 8)
	r := runes(got)
	if len(r) != 9 {
		t.Fatalf("got %d cells, want one per value", len(r))
	}
	// Zero is its own mark; the rest climb to the tallest block.
	if r[0] != sparkZero {
		t.Errorf("zero rendered as %q, want %q", r[0], sparkZero)
	}
	if r[8] != sparkBlocks[len(sparkBlocks)-1] {
		t.Errorf("the peak rendered as %q, want the tallest block", r[8])
	}
	// Monotonic input must give monotonically non-decreasing heights.
	for i := 2; i < len(r); i++ {
		if height(r[i]) < height(r[i-1]) {
			t.Errorf("cell %d (%q) is shorter than cell %d (%q) for rising input",
				i, r[i], i-1, r[i-1])
		}
	}
}

// height maps a rendered rune back to its band, for assertions.
func height(r rune) int {
	if r == sparkZero {
		return 0
	}
	for i, b := range sparkBlocks {
		if b == r {
			return i + 1
		}
	}
	return -1
}

// A trickle must not disappear next to a burst — that is the difference
// between "idle" and "barely working", and it is exactly what you look at a
// graph to find out.
func TestSparklineKeepsSmallValuesVisible(t *testing.T) {
	got := runes(sparkline([]float64{0, 1, 1_000_000}, 1_000_000))
	if got[0] != sparkZero {
		t.Errorf("zero should render as %q, got %q", sparkZero, got[0])
	}
	if got[1] == sparkZero {
		t.Error("a tiny non-zero value rendered as the zero mark; it must stay visible")
	}
	if height(got[1]) < 1 {
		t.Errorf("a tiny value rendered as %q, want at least the lowest block", got[1])
	}
}

func TestSparklineEdgeCases(t *testing.T) {
	if got := sparkline(nil, 100); got != "" {
		t.Errorf("no values should render as empty, got %q", got)
	}
	if got := sparkline([]float64{}, 100); got != "" {
		t.Errorf("an empty slice should render as empty, got %q", got)
	}

	// Every value zero: a flat row of the zero mark, and no division by peak.
	got := sparkline([]float64{0, 0, 0}, 0)
	if got != strings.Repeat(string(sparkZero), 3) {
		t.Errorf("an all-zero series rendered as %q", got)
	}

	// Non-zero values with an unknown scale must not panic or vanish.
	got = sparkline([]float64{5, 10}, 0)
	if len([]rune(got)) != 2 {
		t.Fatalf("got %q, want two cells", got)
	}
	for _, r := range got {
		if height(r) < 0 {
			t.Errorf("unexpected rune %q with a zero peak", r)
		}
	}

	// A single value at the peak.
	if got := sparkline([]float64{42}, 42); runes(got)[0] != sparkBlocks[len(sparkBlocks)-1] {
		t.Errorf("a lone peak value rendered as %q, want the tallest block", got)
	}

	// Values above the stated peak clamp to the top rather than panicking.
	if got := sparkline([]float64{200}, 100); runes(got)[0] != sparkBlocks[len(sparkBlocks)-1] {
		t.Errorf("an over-peak value rendered as %q, want the tallest block", got)
	}

	// Negative values are treated as zero, not as an index below the array.
	if got := sparkline([]float64{-5}, 100); runes(got)[0] != sparkZero {
		t.Errorf("a negative value rendered as %q, want the zero mark", got)
	}
}

// Two series drawn on a shared peak must stay comparable: half the traffic has
// to look like half the traffic.
func TestSharedPeakKeepsSeriesComparable(t *testing.T) {
	tx := []float64{100, 100, 100, 100}
	rx := []float64{50, 50, 50, 50}
	peak := peakOf(tx, rx)
	if peak != 100 {
		t.Fatalf("peakOf = %v, want 100", peak)
	}

	txLine := runes(sparkline(tx, peak))
	rxLine := runes(sparkline(rx, peak))
	if height(txLine[0]) <= height(rxLine[0]) {
		t.Errorf("TX at %v should draw taller than RX at %v (%q vs %q)",
			tx[0], rx[0], txLine[0], rxLine[0])
	}
	// Scaled independently these two would render identically despite one
	// carrying twice the traffic. That is precisely the bug the shared scale
	// exists to prevent, so assert it is what would have happened.
	if sparkline(tx, peakOf(tx)) != sparkline(rx, peakOf(rx)) {
		t.Error("expected independent scaling to hide the difference; " +
			"if it no longer does, this test is no longer testing anything")
	}
}

func TestPeakOf(t *testing.T) {
	if got := peakOf(); got != 0 {
		t.Errorf("peakOf() = %v, want 0", got)
	}
	if got := peakOf(nil, nil); got != 0 {
		t.Errorf("peakOf(nil, nil) = %v, want 0", got)
	}
	if got := peakOf([]float64{1, 9, 3}, []float64{4, 2}); got != 9 {
		t.Errorf("peakOf = %v, want 9", got)
	}
	if got := peakOf([]float64{1, 2}, []float64{50}); got != 50 {
		t.Errorf("the peak must span every series, got %v", got)
	}
}

func TestLastN(t *testing.T) {
	s := []int{1, 2, 3, 4, 5}
	if got := lastN(s, 2); len(got) != 2 || got[0] != 4 || got[1] != 5 {
		t.Errorf("lastN(s, 2) = %v, want [4 5]", got)
	}
	if got := lastN(s, 10); len(got) != 5 {
		t.Errorf("asking for more than there is should give all of it, got %v", got)
	}
	if got := lastN(s, 0); got != nil {
		t.Errorf("lastN(s, 0) = %v, want nil", got)
	}
	if got := lastN([]int(nil), 3); got != nil {
		t.Errorf("lastN(nil, 3) = %v, want nil", got)
	}
}

func BenchmarkSparkline(b *testing.B) {
	vals := make([]float64, 120)
	for i := range vals {
		vals[i] = float64(i * 1000)
	}
	b.ReportAllocs()
	for b.Loop() {
		_ = sparkline(vals, 120000)
	}
}
