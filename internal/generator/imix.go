package generator

import (
	"fmt"
	"strings"
)

// MixEntry is one frame size in a size distribution and how often it occurs
// relative to the others.
type MixEntry struct {
	// Size is the total Ethernet frame size in bytes, including the 4-byte
	// FCS — the same units as --packet-size.
	Size int
	// Weight is how many packets of this size appear per cycle.
	Weight int
}

// DefaultIMIX is the "simple IMIX", the conventional Internet mix used by
// almost every traffic generator: seven small frames, four medium, one large,
// in a 7:4:1 ratio.
//
// The sizes are the classic ones — a 64-byte frame (40-byte IP packet, the
// size of a bare TCP ack), a 594-byte frame (576-byte IP packet, the old
// minimum reassembly buffer), and a 1518-byte frame (1500-byte IP packet, a
// full Ethernet MTU). The mean is 361.8 bytes of Ethernet frame, which is the
// familiar ~340-byte IMIX average measured at IP level plus the 18 bytes of
// Ethernet header and FCS wrapped around it.
//
// The distribution is a plain table so another mix can be dropped in without
// touching the generator.
var DefaultIMIX = []MixEntry{
	{Size: 64, Weight: 7},
	{Size: 594, Weight: 4},
	{Size: 1518, Weight: 1},
}

// ExpandMix turns a weighted size distribution into the exact, repeating
// sequence of frame sizes a generator cycles through. The returned slice has
// one entry per unit of weight, so DefaultIMIX yields 12 sizes containing
// exactly seven 64s, four 594s and one 1518.
//
// The order is smooth rather than grouped: instead of emitting all the small
// frames and then all the large ones, it interleaves them with a deterministic
// weighted round-robin (the same "smooth" scheduling nginx uses). That keeps
// the instantaneous bit rate close to the average rather than pulsing once per
// cycle, and it is fully reproducible.
func ExpandMix(mix []MixEntry) ([]int, error) {
	total := 0
	for _, e := range mix {
		if e.Size <= 0 {
			return nil, fmt.Errorf("generator: mix entry has a non-positive size %d", e.Size)
		}
		if e.Weight <= 0 {
			return nil, fmt.Errorf("generator: mix entry for %d-byte frames has a non-positive weight %d",
				e.Size, e.Weight)
		}
		total += e.Weight
	}
	if total == 0 {
		return nil, fmt.Errorf("generator: empty size mix")
	}

	credit := make([]int, len(mix))
	out := make([]int, 0, total)
	for range total {
		best := 0
		for i := range mix {
			credit[i] += mix[i].Weight
			if credit[i] > credit[best] {
				best = i
			}
		}
		out = append(out, mix[best].Size)
		credit[best] -= total
	}
	return out, nil
}

// MeanSize returns the average total frame size of a mix, in bytes.
func MeanSize(mix []MixEntry) float64 {
	var bytes, weight int
	for _, e := range mix {
		bytes += e.Size * e.Weight
		weight += e.Weight
	}
	if weight == 0 {
		return 0
	}
	return float64(bytes) / float64(weight)
}

// DescribeMix renders a mix for the review screen and the dashboard, e.g.
// "IMIX 7:4:1 (64/594/1518B), mean 362B".
func DescribeMix(mix []MixEntry) string {
	var ratio, sizes []string
	for _, e := range mix {
		ratio = append(ratio, fmt.Sprint(e.Weight))
		sizes = append(sizes, fmt.Sprint(e.Size))
	}
	return fmt.Sprintf("IMIX %s (%sB), mean %.0fB",
		strings.Join(ratio, ":"), strings.Join(sizes, "/"), MeanSize(mix))
}
