package tui

import "strings"

// sparkBlocks are the eight heights a sparkline can draw, lowest first.
//
// Block characters rather than braille: braille packs two columns per cell but
// renders inconsistently across fonts, and a graph nobody can read is worse
// than a narrower one.
var sparkBlocks = []rune{'▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'}

// sparkZero is drawn where a value is exactly zero, so "nothing happened" is
// visibly different from "a trickle" — the lowest block would otherwise mean
// both.
const sparkZero = '·'

// sparkline renders values as a single row of block characters, scaled so that
// peak reaches full height.
//
// The scale is passed in rather than taken from the values so that two
// sparklines can share it. Drawing transmit and receive on their own scales
// would make a receiver taking a tenth of the traffic look identical to one
// keeping up, which is worse than showing no graph at all.
//
// A non-zero value never renders as empty: anything above zero gets at least
// the lowest block, so a slow trickle stays visible next to a burst.
func sparkline(values []float64, peak float64) string {
	if len(values) == 0 {
		return ""
	}
	var b strings.Builder
	b.Grow(len(values) * 3) // block runes are three bytes

	for _, v := range values {
		switch {
		case v <= 0:
			b.WriteRune(sparkZero)
		case peak <= 0:
			// Every value is zero or the scale is not yet known; keep the row
			// flat rather than dividing by it.
			b.WriteRune(sparkBlocks[0])
		default:
			// Map (0, peak] onto the eight blocks. The ceiling-style rounding
			// is deliberate: it is the reason a value just above zero still
			// shows up.
			i := int(v / peak * float64(len(sparkBlocks)))
			if v > 0 && i < 1 {
				i = 1
			}
			b.WriteRune(sparkBlocks[min(i, len(sparkBlocks))-1])
		}
	}
	return b.String()
}

// lastN returns the final n elements of s, or all of it when it is shorter.
func lastN[T any](s []T, n int) []T {
	if n <= 0 || len(s) == 0 {
		return nil
	}
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

// peakOf is the largest value in a set of series, which is the scale they
// should share.
func peakOf(series ...[]float64) float64 {
	peak := 0.0
	for _, s := range series {
		for _, v := range s {
			peak = max(peak, v)
		}
	}
	return peak
}
