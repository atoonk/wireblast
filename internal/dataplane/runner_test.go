package dataplane

import "testing"

// frameSizeFor picks the UMEM frame size. The one subtlety is AWS ENA, whose
// zero-copy bind needs page-sized (4096) frames: a standard frame must be
// floored to 4096 there, while every other driver keeps the smaller 2048.
func TestFrameSizeForENA(t *testing.T) {
	tests := []struct {
		driver   string
		maxFrame int
		want     int
	}{
		{"ena", 1518, 4096},   // the fix: a standard frame is floored to a page on ena
		{"ixgbe", 1518, 2048}, // other drivers keep the smaller frame
		{"", 1518, 2048},      // unknown driver behaves like non-ena
		{"ena", 3018, 4096},   // already 4096, the floor is a no-op
		{"ena", 9018, 16384},  // jumbo is unaffected by the floor
		{"mlx5_core", 9018, 16384},
		{"ena", 64, 4096}, // a tiny frame still gets a page on ena
	}
	for _, tt := range tests {
		if got := frameSizeFor(tt.maxFrame, tt.driver); got != tt.want {
			t.Errorf("frameSizeFor(%d, %q) = %d, want %d", tt.maxFrame, tt.driver, got, tt.want)
		}
	}
}
