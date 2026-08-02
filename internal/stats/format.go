package stats

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Count renders a packet or byte count compactly: 1234 -> "1.23 k",
// 14880000 -> "14.88 M". Small values are printed exactly, because "sent 7
// packets" should say 7.
func Count(v uint64) string {
	switch {
	case v >= 1e12:
		return trim(float64(v)/1e12) + " T"
	case v >= 1e9:
		return trim(float64(v)/1e9) + " G"
	case v >= 1e6:
		return trim(float64(v)/1e6) + " M"
	case v >= 1e4:
		return trim(float64(v)/1e3) + " k"
	default:
		return strconv.FormatUint(v, 10)
	}
}

// PPS renders a packet rate, e.g. "1.49 Mpps".
func PPS(v float64) string {
	switch {
	case v >= 1e6:
		return trim(v/1e6) + " Mpps"
	case v >= 1e3:
		return trim(v/1e3) + " kpps"
	default:
		return trim(v) + " pps"
	}
}

// Bits renders a bit rate, e.g. "9.87 Gbit/s".
func Bits(v float64) string {
	switch {
	case v >= 1e9:
		return trim(v/1e9) + " Gbit/s"
	case v >= 1e6:
		return trim(v/1e6) + " Mbit/s"
	case v >= 1e3:
		return trim(v/1e3) + " kbit/s"
	default:
		return trim(v) + " bit/s"
	}
}

// Bytes renders a byte total, e.g. "3.21 GB".
func Bytes(v uint64) string {
	switch {
	case v >= 1e12:
		return trim(float64(v)/1e12) + " TB"
	case v >= 1e9:
		return trim(float64(v)/1e9) + " GB"
	case v >= 1e6:
		return trim(float64(v)/1e6) + " MB"
	case v >= 1e3:
		return trim(float64(v)/1e3) + " kB"
	default:
		return strconv.FormatUint(v, 10) + " B"
	}
}

// Duration renders an elapsed or remaining time as m:ss or h:mm:ss.
func Duration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	d = d.Round(time.Second)
	h := int(d / time.Hour)
	m := int(d/time.Minute) % 60
	s := int(d/time.Second) % 60
	if h > 0 {
		return fmt.Sprintf("%d:%02d:%02d", h, m, s)
	}
	return fmt.Sprintf("%d:%02d", m, s)
}

func trim(v float64) string {
	s := strconv.FormatFloat(v, 'f', 2, 64)
	if strings.Contains(s, ".") {
		s = strings.TrimRight(s, "0")
		s = strings.TrimSuffix(s, ".")
	}
	return s
}

func formatQueueProblem(queue int, what string, n uint64) string {
	return fmt.Sprintf("queue %d: %s (%s)", queue, what, Count(n))
}

// Line renders a snapshot as the single status line the --no-tui runner prints
// once a second. Both bit rates appear, named L1 and L2 as T-Rex names them:
// for small frames they differ by a third, and only L1 is link utilisation.
func (s *Snapshot) Line() string {
	var b strings.Builder
	fmt.Fprintf(&b, "[%s]", Duration(s.Elapsed))

	if s.Transmits {
		fmt.Fprintf(&b, " tx %s pkts  %s  L1 %s  L2 %s",
			Count(s.TX.Packets),
			PPS(s.TXRate.PPS),
			Bits(s.TXRate.WireBPS),
			Bits(s.TXRate.FrameBPS))
		if avg := s.TX.AvgFrame(); avg > 0 {
			fmt.Fprintf(&b, "  avg %.0fB", avg)
		}
	}
	if !s.Transmits || s.RX.Packets > 0 || s.RX.Drops > 0 {
		if s.Transmits {
			b.WriteString(" |")
		}
		fmt.Fprintf(&b, " rx %s pkts  %s  L1 %s  L2 %s",
			Count(s.RX.Packets), PPS(s.RXRate.PPS),
			Bits(s.RXRate.WireBPS), Bits(s.RXRate.FrameBPS))
		if avg := s.RX.AvgFrame(); avg > 0 {
			fmt.Fprintf(&b, "  avg %.0fB", avg)
		}
		if s.RX.Drops > 0 {
			fmt.Fprintf(&b, "  drops %s", Count(s.RX.Drops))
		}
	}
	if s.TX.Errors > 0 {
		fmt.Fprintf(&b, "  tx_errors %s", Count(s.TX.Errors))
	}
	if s.State == StatePaused {
		b.WriteString("  [paused]")
	}
	return b.String()
}

// Summary renders the final report printed when a run ends. It reports
// lifetime totals, which an interval reset never touches.
func (s *Snapshot) Summary() string {
	var b strings.Builder
	dur := s.Elapsed.Seconds()
	fmt.Fprintf(&b, "ran for %s\n", Duration(s.Elapsed))
	if !s.Transmits {
		return strings.TrimRight(b.String()+s.rxSummary(dur), "\n")
	}
	fmt.Fprintf(&b, "  tx: %s packets, %s", Count(s.TotalTX.Packets), Bytes(s.TotalTX.Bytes))
	if dur > 0 {
		fmt.Fprintf(&b, ", %s, L1 %s, L2 %s",
			PPS(float64(s.TotalTX.Packets)/dur),
			Bits((float64(s.TotalTX.Bytes)+float64(s.TotalTX.Packets)*wireOverheadPerFrame)*8/dur),
			Bits(float64(s.TotalTX.Bytes)*8/dur))
	}
	if avg := s.TotalTX.AvgFrame(); avg > 0 {
		fmt.Fprintf(&b, ", avg frame %.0fB", avg)
	}
	b.WriteString("\n")
	if s.TotalTX.UDP > 0 || s.TotalTX.TCP > 0 || s.TotalTX.Other > 0 {
		fmt.Fprintf(&b, "      udp %s, tcp %s, other %s\n",
			Count(s.TotalTX.UDP), Count(s.TotalTX.TCP), Count(s.TotalTX.Other))
	}
	if s.TotalTX.Errors > 0 {
		fmt.Fprintf(&b, "      errors %s\n", Count(s.TotalTX.Errors))
	}
	b.WriteString(s.rxSummary(dur))
	// The summary is a lifetime report (like the drop count above), so it lists
	// problems since the run started, not since the last on-screen reset.
	for _, p := range problems(s.Kernel, Kernel{}) {
		fmt.Fprintf(&b, "  ! %s\n", p)
	}
	return strings.TrimRight(b.String(), "\n")
}

// rxSummary renders the receive half of the final report.
func (s *Snapshot) rxSummary(dur float64) string {
	if s.TotalRX.Packets == 0 && s.TotalRX.Drops == 0 && s.Transmits {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "  rx: %s packets, %s", Count(s.TotalRX.Packets), Bytes(s.TotalRX.Bytes))
	if dur > 0 {
		fmt.Fprintf(&b, ", %s, L1 %s, L2 %s",
			PPS(float64(s.TotalRX.Packets)/dur),
			Bits((float64(s.TotalRX.Bytes)+float64(s.TotalRX.Packets)*wireOverheadPerFrame)*8/dur),
			Bits(float64(s.TotalRX.Bytes)*8/dur))
	}
	if avg := s.TotalRX.AvgFrame(); avg > 0 {
		fmt.Fprintf(&b, ", avg frame %.0fB", avg)
	}
	b.WriteString("\n")
	if s.TotalRX.UDP > 0 || s.TotalRX.TCP > 0 || s.TotalRX.Other > 0 {
		fmt.Fprintf(&b, "      udp %s, tcp %s, other %s\n",
			Count(s.TotalRX.UDP), Count(s.TotalRX.TCP), Count(s.TotalRX.Other))
	}
	if s.TotalRX.Drops > 0 {
		fmt.Fprintf(&b, "      drops %s\n", Count(s.TotalRX.Drops))
	}
	return b.String()
}
