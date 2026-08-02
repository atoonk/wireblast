package generator

import (
	"strings"
	"testing"
)

// The documented IMIX is 7:4:1 over 64/594/1518-byte frames; the expansion
// must contain exactly that, in exactly 12 packets.
func TestDefaultIMIXDistribution(t *testing.T) {
	sizes, err := ExpandMix(DefaultIMIX)
	if err != nil {
		t.Fatal(err)
	}
	if len(sizes) != 12 {
		t.Fatalf("cycle length = %d, want 12", len(sizes))
	}
	counts := map[int]int{}
	for _, s := range sizes {
		counts[s]++
	}
	want := map[int]int{64: 7, 594: 4, 1518: 1}
	for size, n := range want {
		if counts[size] != n {
			t.Errorf("%d-byte frames per cycle = %d, want %d", size, counts[size], n)
		}
	}
	if len(counts) != 3 {
		t.Errorf("cycle contains %d distinct sizes, want 3", len(counts))
	}
}

func TestDefaultIMIXMeanSize(t *testing.T) {
	// (7*64 + 4*594 + 1*1518) / 12 = 4342/12 ≈ 361.83
	if got, want := MeanSize(DefaultIMIX), 4342.0/12; got != want {
		t.Errorf("MeanSize = %v, want %v", got, want)
	}
}

// The expansion must interleave sizes rather than emit them in blocks, so the
// instantaneous rate stays near the average instead of pulsing once a cycle.
func TestExpandMixIsSmooth(t *testing.T) {
	sizes, err := ExpandMix(DefaultIMIX)
	if err != nil {
		t.Fatal(err)
	}
	// A grouped expansion would put all seven 64s next to each other. Assert
	// no run of the same size is longer than 2.
	run, longest := 1, 1
	for i := 1; i < len(sizes); i++ {
		if sizes[i] == sizes[i-1] {
			run++
		} else {
			run = 1
		}
		longest = max(longest, run)
	}
	if longest > 2 {
		t.Errorf("longest run of identical sizes = %d, want at most 2: %v", longest, sizes)
	}
}

// The expansion is fully deterministic: the same mix always gives the same
// order, so two runs produce comparable captures.
func TestExpandMixIsDeterministic(t *testing.T) {
	a, _ := ExpandMix(DefaultIMIX)
	b, _ := ExpandMix(DefaultIMIX)
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("expansion differs between calls at index %d", i)
		}
	}
}

// The mix is a plain table so other distributions can be dropped in.
func TestExpandCustomMix(t *testing.T) {
	sizes, err := ExpandMix([]MixEntry{{Size: 128, Weight: 1}, {Size: 1024, Weight: 1}})
	if err != nil {
		t.Fatal(err)
	}
	if len(sizes) != 2 {
		t.Fatalf("cycle length = %d, want 2", len(sizes))
	}
	if sizes[0] == sizes[1] {
		t.Errorf("a 1:1 mix should alternate, got %v", sizes)
	}

	// A single-entry mix degenerates to fixed-size traffic.
	one, err := ExpandMix([]MixEntry{{Size: 512, Weight: 3}})
	if err != nil {
		t.Fatal(err)
	}
	if len(one) != 3 || one[0] != 512 || one[2] != 512 {
		t.Errorf("single-entry mix = %v, want three 512s", one)
	}
}

func TestExpandMixRejectsBadInput(t *testing.T) {
	bad := [][]MixEntry{
		nil,
		{},
		{{Size: 0, Weight: 1}},
		{{Size: -64, Weight: 1}},
		{{Size: 64, Weight: 0}},
		{{Size: 64, Weight: -2}},
	}
	for _, mix := range bad {
		if _, err := ExpandMix(mix); err == nil {
			t.Errorf("ExpandMix(%v) should have failed", mix)
		}
	}
}

func TestDescribeMix(t *testing.T) {
	got := DescribeMix(DefaultIMIX)
	for _, want := range []string{"7:4:1", "64/594/1518", "mean"} {
		if !strings.Contains(got, want) {
			t.Errorf("DescribeMix = %q, missing %q", got, want)
		}
	}
}
