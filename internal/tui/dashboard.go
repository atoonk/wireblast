package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/atoonk/wireblast/internal/config"
	"github.com/atoonk/wireblast/internal/stats"
)

// viewDashboard is the live display: two columns of counters, the run's
// settings above them, and the hotkeys below.
//
// It only reads the snapshot the collector publishes — no counting, parsing or
// locking happens here, and none of it is on the packet path.
func (m model) viewDashboard() string {
	s := m.runner.Stats()

	var b strings.Builder
	b.WriteString(m.dashHeader(s) + "\n")
	b.WriteString(m.dashColumns(s) + "\n")
	if g := m.dashGraph(s); g != "" {
		b.WriteString(g + "\n")
	}
	b.WriteString(m.dashFooter(s))
	return b.String()
}

// graphRows is how many terminal rows the graph block occupies: a heading, a
// row per direction, and a blank line.
func (m model) graphRows() int {
	rows := 2 // heading + trailing blank
	if m.cfg.Transmits() {
		rows++
	}
	if m.rxEnabled() {
		rows++
	}
	return rows
}

// dashGraph draws the recent history as sparklines, one row per direction.
//
// Both rows share a single scale. Scaled separately, a receiver taking a tenth
// of the traffic would look identical to one keeping up — which is worse than
// showing no graph at all.
func (m model) dashGraph(s *stats.Snapshot) string {
	if m.graph == graphOff || len(s.History) == 0 {
		return ""
	}
	// A cramped terminal should lose the graph, not the footer.
	if m.height > 0 && m.height < dashboardRows+m.graphRows() {
		return ""
	}

	// The block is indented two columns; inside it a "TX " label, two spaces
	// and a right-hand column for the current value.
	const indent, labelW, valueW = 2, 3, 14
	width := m.blockWidth() - indent - labelW - valueW - 2
	if width < 8 {
		return ""
	}

	points := lastN(s.History, width)
	tx := make([]float64, len(points))
	rx := make([]float64, len(points))
	for i, p := range points {
		tx[i], rx[i] = m.graphValue(p.TX), m.graphValue(p.RX)
	}

	// Only the directions this run actually uses contribute to the scale, or a
	// receive-only run would be measured against a flat zero transmit series.
	var series [][]float64
	if m.cfg.Transmits() {
		series = append(series, tx)
	}
	if m.rxEnabled() {
		series = append(series, rx)
	}
	peak := peakOf(series...)

	var b strings.Builder
	head := fmt.Sprintf("%s · last %ds", m.graphLabel(), len(points))
	tail := "peak " + m.graphFormat(peak)
	pad := max(m.blockWidth()-indent-len(head)-len(tail), 1)
	fmt.Fprintf(&b, "%s%s%s%s\n", strings.Repeat(" ", indent),
		styleLabel.Render(head), strings.Repeat(" ", pad), styleFaint.Render(tail))

	// Early in a run there is less history than there is room for it. Pad on
	// the left so the newest sample always sits against the value column: the
	// "now" edge stays put and the line grows backwards into the space, rather
	// than the whole graph crawling rightwards as the run goes on.
	lead := strings.Repeat(" ", max(width-len(points), 0))

	row := func(name string, vals []float64, cur float64, style lipgloss.Style) {
		fmt.Fprintf(&b, "%s%s %s%s  %s\n", strings.Repeat(" ", indent),
			styleLabel.Render(name), lead,
			style.Render(sparkline(vals, peak)),
			styleValue.Render(m.graphFormat(cur)))
	}
	if m.cfg.Transmits() {
		row("TX", tx, m.graphValue(s.TXRate), styleSparkTX)
	}
	if m.rxEnabled() {
		row("RX", rx, m.graphValue(s.RXRate), styleSparkRX)
	}
	return strings.TrimRight(b.String(), "\n")
}

// graphValue picks the metric the graph is currently showing.
func (m model) graphValue(r stats.Rates) float64 {
	if m.graph == graphBits {
		return r.WireBPS
	}
	return r.PPS
}

func (m model) graphFormat(v float64) string {
	if m.graph == graphBits {
		return stats.Bits(v)
	}
	return stats.PPS(v)
}

func (m model) graphLabel() string {
	if m.graph == graphBits {
		return "bits/sec (L1)"
	}
	return "packets/sec"
}

func (m model) dashHeader(s *stats.Snapshot) string {
	i := m.runner.Info()
	var b strings.Builder

	state := styleOK.Render("running")
	switch s.State {
	case stats.StatePaused:
		state = styleWarn.Render("paused")
	case stats.StateStopping:
		state = styleWarn.Render("stopping")
	case stats.StateComplete:
		state = styleHint.Render("complete")
	}

	b.WriteString(styleTitle.Render("Wireblast") + "  " + state)

	// Elapsed and remaining.
	timing := stats.Duration(s.Elapsed)
	if s.Remaining > 0 {
		timing += styleFaint.Render(" / -" + stats.Duration(s.Remaining))
	} else if m.cfg.Duration == 0 {
		timing += styleFaint.Render(" (no limit)")
	}
	b.WriteString("   " + styleLabel.Render("elapsed ") + styleValue.Render(timing) + "\n")

	zc := "copy"
	if i.ZeroCopy {
		zc = "zero-copy"
	}
	line := func(k, v string) {
		fmt.Fprintf(&b, "  %s %s\n", styleLabel.Render(fmt.Sprintf("%-10s", k)), v)
	}
	iface := fmt.Sprintf("%s · %d queue(s) · %s XDP · %s",
		driverOr(i.Driver), i.Queues, i.XDPMode, zc)
	if i.Tuning != "" && i.Tuning != "untuned" {
		iface += " · napi " + i.Tuning
	}
	switch {
	case i.Reused:
		iface += " · XDP already attached"
	case i.LinkWait > 0:
		iface += fmt.Sprintf(" · link back in %.1fs", i.LinkWait.Seconds())
	}
	line("interface", fmt.Sprintf("%s  %s", i.Interface, styleFaint.Render(iface)))
	line("pattern", fmt.Sprintf("%s  %s", i.Pattern, styleFaint.Render(i.PacketSizes)))
	line("rx filter", i.Filter)

	// A run that transmits nothing has no configured rate; the RX column
	// already shows what is arriving.
	if !m.cfg.Transmits() {
		return b.String()
	}

	// Configured rate versus what is actually going out.
	pps, bps := m.runner.Rate()
	cfgRate := "unlimited (line rate)"
	switch {
	case pps != 0 && bps != 0:
		cfgRate = config.FormatPPS(pps) + " + " + config.FormatBPS(bps)
	case pps != 0:
		cfgRate = config.FormatPPS(pps)
	case bps != 0:
		cfgRate = config.FormatBPS(bps)
	}
	line("rate", fmt.Sprintf("%s %s  %s %s",
		styleFaint.Render("set"), cfgRate,
		styleFaint.Render("actual"), styleValue.Render(stats.PPS(s.TXRate.PPS))))
	return b.String()
}

// Dashboard geometry. The counter columns grow with the terminal, within
// limits: never below what fits an 80-column window, never so wide that a
// value drifts unreadably far from its label.
const (
	minBoxWidth = 34
	maxBoxWidth = 52
	// columnGap is the space between the two counter columns.
	columnGap = 2
)

// boxWidth is how wide each counter column is drawn.
//
// m.width is 0 until the first window-size message arrives, so the minimum
// doubles as the starting layout rather than a zero-width box on frame one.
func (m model) boxWidth() int {
	if m.width <= 0 {
		return minBoxWidth
	}
	return min(max((m.width-columnGap-2)/2, minBoxWidth), maxBoxWidth)
}

// blockWidth is the full width of the dashboard body: both columns and the gap
// between them. The graph spans exactly this, so it lines up with the boxes.
func (m model) blockWidth() int { return m.boxWidth()*2 + columnGap }

// dashColumns renders the TX and RX counters side by side.
func (m model) dashColumns(s *stats.Snapshot) string {
	w := m.boxWidth()
	tx := counterBlock("TX", s.TX, s.TXRate, false, w)
	rx := counterBlock("RX", s.RX, s.RXRate, true, w)

	if !m.cfg.Transmits() {
		tx = idleBlock("TX", "not transmitting\n\nThis run only receives.\nNothing is put on the wire.", w)
	}
	if !m.rxEnabled() {
		rx = idleBlock("RX", "receiving is off\n\nThis run is transmit-only,\nso every packet the\ninterface receives still\ngoes to the kernel.\n\nTurn it on with the\nreceive mode setting.", w)
	}
	return lipgloss.JoinHorizontal(lipgloss.Top, tx, strings.Repeat(" ", columnGap), rx)
}

// idleBlock renders a column for a direction this run does not use, explaining
// why rather than showing a wall of zeroes.
func idleBlock(name, why string, width int) string {
	return styleBox.Width(width).Render(styleHeader.Render(name) + "\n" + styleFaint.Render(why))
}

func (m model) rxEnabled() bool { return m.cfg.RxMode != config.RxNone }

// doneSummary restates what was just run, so the answer to "what did I
// actually send?" is on screen rather than scrolled away.
func (m model) doneSummary() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s", m.cfg.Mode)
	if m.cfg.UsesIPStack() {
		fmt.Fprintf(&b, " → %s", m.cfg.DstIP)
		if m.cfg.Flows == 1 {
			b.WriteString(", 1 flow")
		} else {
			fmt.Fprintf(&b, ", %d flows", m.cfg.Flows)
		}
	}
	if m.cfg.VLAN != 0 {
		fmt.Fprintf(&b, ", vlan %d", m.cfg.VLAN)
	}
	if m.cfg.Transmits() {
		fmt.Fprintf(&b, ", %s", config.FormatPPS(m.cfg.PPS))
	}
	if m.cfg.RxMode != config.RxNone {
		fmt.Fprintf(&b, ", rx %s", m.cfg.RxMode)
	}
	return b.String()
}

// counterBlock is one direction's column.
//
// Values are right-aligned to the column's inner edge, so on a wide terminal
// the numbers line up in a readable table instead of trailing off after a
// fixed-width label.
func counterBlock(name string, t stats.Totals, r stats.Rates, isRx bool, width int) string {
	// The box style adds a border and one column of padding on each side.
	inner := max(width-4, 20)

	var b strings.Builder
	b.WriteString(styleHeader.Render(name) + "\n")

	pair := func(label, value string, ls, vs lipgloss.Style) {
		pad := max(inner-len(label)-len(value), 1)
		fmt.Fprintf(&b, "%s%s%s\n", ls.Render(label), strings.Repeat(" ", pad), vs.Render(value))
	}
	row := func(k, v string) { pair(k, v, styleLabel, styleValue) }
	// The rates come first: they are the numbers you actually watch. Totals
	// are context, and sit underneath.
	row("Packets/sec", stats.PPS(r.PPS))
	// Both bit rates, under the names the field uses. L1 is the frame plus its
	// preamble, start-frame delimiter and interframe gap, and is what link
	// utilisation means; L2 is the frame itself. For 64-byte frames they
	// differ by 31%, so leaving either unlabelled invites the wrong reading.
	row("Bits/sec  L1", stats.Bits(r.WireBPS))
	pair("Bits/sec  L2", stats.Bits(r.FrameBPS), styleLabel, styleFaint)

	b.WriteString(styleFaint.Render(strings.Repeat("─", inner)) + "\n")

	row("Packets", stats.Count(t.Packets))
	row("Bytes", stats.Bytes(t.Bytes))
	row("Avg frame", fmt.Sprintf("%.0f B", t.AvgFrame()))
	row("UDP", stats.Count(t.UDP))
	row("TCP", stats.Count(t.TCP))
	row("Other", stats.Count(t.Other))

	label, n := "Errors", t.Errors
	if isRx {
		label, n = "Drops/errors", t.Drops
	}
	style := styleValue
	if n > 0 {
		style = styleWarn
	}
	pair(label, stats.Count(n), styleLabel, style)

	return styleBox.Width(width).Render(strings.TrimRight(b.String(), "\n"))
}

func (m model) dashFooter(s *stats.Snapshot) string {
	var b strings.Builder

	// Anything a queue is unhappy about. The per-queue lines are hidden by
	// default (a NIC with many queues dropping would otherwise fill the screen)
	// and revealed with 'w'; a one-line summary keeps them discoverable.
	if n := len(s.Problems); n > 0 {
		if m.showProblems {
			for _, p := range s.Problems {
				b.WriteString(styleWarn.Render("  ! "+p) + "\n")
			}
		} else {
			noun := "queue"
			if n > 1 {
				noun = "queues"
			}
			b.WriteString(styleWarn.Render(fmt.Sprintf("  ! %d %s dropping or stalling", n, noun)) +
				styleFaint.Render("  (w to show)") + "\n")
		}
	}
	if !s.IntervalSince.IsZero() && s.TotalTX.Packets != s.TX.Packets {
		b.WriteString(styleFaint.Render(fmt.Sprintf(
			"  counters reset · lifetime tx %s packets", stats.Count(s.TotalTX.Packets))) + "\n")
	}

	if s.State == stats.StateComplete {
		b.WriteString("\n" + styleOK.Render("  Run complete.") + "  " +
			styleHint.Render(m.doneSummary()) + "\n\n")
		b.WriteString(footer(
			keyHint("r", "run it again"),
			keyHint("e", "edit settings"),
			keyHint("p", "change pattern"),
			keyHint("g", m.graphHint()),
			keyHint("q", "quit"),
		))
		return b.String()
	}
	if s.State == stats.StateStopping {
		b.WriteString("\n" + styleHint.Render("  Stopping: draining the transmit rings and detaching XDP...") + "\n\n")
		return b.String()
	}

	pauseLabel := "pause"
	if s.State == stats.StatePaused {
		pauseLabel = "resume"
	}
	hints := []string{
		keyHint("space", pauseLabel),
		keyHint("+/-", "rate ±10%"),
		keyHint("g", m.graphHint()),
		keyHint("r", "reset counters"),
	}
	if len(s.Problems) > 0 {
		label := "show drops"
		if m.showProblems {
			label = "hide drops"
		}
		hints = append(hints, keyHint("w", label))
	}
	hints = append(hints, keyHint("?", "help"), keyHint("q", "stop and quit"))
	b.WriteString("\n" + footer(hints...))
	return b.String()
}

// graphHint names what pressing g will switch to, rather than what is already
// on screen.
func (m model) graphHint() string {
	switch m.graph {
	case graphPackets:
		return "graph: bits"
	case graphBits:
		return "graph: off"
	default:
		return "graph: packets"
	}
}
