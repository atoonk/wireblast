package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/atoonk/wireblast/internal/config"
	"github.com/atoonk/wireblast/internal/discovery"
)

// View renders the current stage.
func (m model) View() string {
	if m.showHelp {
		return m.viewHelp()
	}
	switch m.stage {
	case stageInterface:
		return m.viewInterface()
	case stagePattern:
		return m.viewPattern()
	case stageFields:
		return m.viewFields()
	case stagePreparing:
		return m.viewBusy("Working out the addressing",
			"Looking up routes and resolving the next hop. If the destination has to answer "+
				"ARP this takes a moment.", nil)
	case stageReview:
		return m.viewReview()
	case stageStarting:
		return m.viewBusy("Starting", startingDetail(m.busyElapsed()), startingSteps(m.busyElapsed()))
	case stageRunning, stageDone:
		return m.viewDashboard()
	case stageError:
		return m.viewError()
	}
	return ""
}

func (m model) viewError() string {
	var b strings.Builder
	b.WriteString(styleTitle.Render("Wireblast") + "\n\n")
	b.WriteString(styleDanger.Render("Cannot continue") + "\n\n")
	if m.err != nil {
		b.WriteString(m.err.Error() + "\n")
	}
	b.WriteString("\n" + footer(keyHint("any key", "quit")))
	return b.String()
}

// spinnerFrames is the waiting indicator. Braille dots read as motion at a
// glance without drawing attention to themselves.
var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// busyElapsed is how long the current wait has lasted.
func (m model) busyElapsed() time.Duration {
	if m.busySince.IsZero() {
		return 0
	}
	return time.Since(m.busySince)
}

// viewBusy is the screen shown while something slow is happening. It always
// moves, always says how long it has been going, and — where the steps are
// known — shows which one is in progress, because a static screen during a
// ten-second link bounce is indistinguishable from a hang.
func (m model) viewBusy(what, detail string, steps []busyStep) string {
	var b strings.Builder
	b.WriteString(styleTitle.Render("Wireblast") + "\n\n")

	spin := styleCursor.Render(spinnerFrames[m.busyFrame%len(spinnerFrames)])
	elapsed := ""
	if e := m.busyElapsed(); e >= time.Second {
		elapsed = styleFaint.Render(fmt.Sprintf("  %.0fs", e.Seconds()))
	}
	b.WriteString(spin + " " + styleValue.Render(what) + elapsed + "\n\n")

	for _, st := range steps {
		mark, style := "·", styleFaint
		switch {
		case st.done:
			mark, style = "✓", styleOK
		case st.active:
			mark, style = spinnerFrames[m.busyFrame%len(spinnerFrames)], styleValue
		}
		fmt.Fprintf(&b, "  %s %s\n", style.Render(mark), style.Render(st.label))
	}
	if len(steps) > 0 {
		b.WriteString("\n")
	}

	b.WriteString(styleHint.Render(wrapIndent(detail, 0, m.textWidth())) + "\n\n")
	b.WriteString(footer(keyHint("esc", "cancel")))
	return b.String()
}

// busyStep is one stage of a multi-part wait.
type busyStep struct {
	label  string
	done   bool
	active bool
}

// startingSteps turns elapsed time into a rough sense of progress. The
// timings are approximate on purpose: the point is to show that something is
// still happening, not to promise a schedule.
func startingSteps(e time.Duration) []busyStep {
	attached := e > 1500*time.Millisecond
	return []busyStep{
		{label: "Attaching the XDP program", done: attached, active: !attached},
		{label: "Waiting for the link to come back up", active: attached},
	}
}

func startingDetail(e time.Duration) string {
	if e > 20*time.Second {
		return "This is taking longer than usual. Some drivers renegotiate slowly; " +
			"press esc to give up."
	}
	return "Native XDP reinitialises the driver's queues, so the link drops carrier for a " +
		"few seconds before traffic can flow. This is normal, and the run's clock does not " +
		"start until it is back."
}

// viewInterface is the first thing a new user sees: a list of interfaces they
// can actually use, with enough detail to recognise the right one.
func (m model) viewInterface() string {
	var b strings.Builder
	b.WriteString(title(1, wizardSteps, "Interface") + "\n\n")
	b.WriteString(styleHint.Render("Which interface should Wireblast transmit from?") + "\n\n")

	// A busy host can have twenty virtual devices, so the list scrolls rather
	// than running off the bottom of the terminal.
	start, end := window(m.linkIdx, len(m.links), m.rowsFor(2, 8))
	if start > 0 {
		b.WriteString(styleFaint.Render("   ↑ "+itoa(start)+" more above") + "\n")
	}
	for i := start; i < end; i++ {
		l := m.links[i]
		cursor := "  "
		// Pad before styling: ANSI escapes count as characters to Sprintf and
		// would throw the column alignment off on the selected row.
		name := fmt.Sprintf("%-14s", l.Name)
		if i == m.linkIdx {
			cursor = styleCursor.Render("> ")
			name = styleSelected.Render(name)
		}
		fmt.Fprintf(&b, "%s%s %s\n", cursor, name, styleHint.Render(m.linkSummary(l)))
		fmt.Fprintf(&b, "    %s\n", styleFaint.Render(m.linkDetail(l)))
	}
	if end < len(m.links) {
		b.WriteString(styleFaint.Render("   ↓ "+itoa(len(m.links)-end)+" more below") + "\n")
	}

	b.WriteString("\n")
	if l := m.currentLink(); m.hasDef && l.Index == m.defRoute {
		b.WriteString(styleWarn.Render("! "+l.Name+" carries this machine's default route. "+
			"Traffic you generate here competes with the host's own.") + "\n\n")
	}
	b.WriteString(footer(
		keyHint("↑/↓", "select"),
		keyHint("enter", "continue"),
		keyHint("q", "quit"),
	))
	return b.String()
}

func (m model) linkSummary(l discovery.Link) string {
	state := "no carrier"
	if l.Carrier {
		state = "up"
	}
	driver := l.Driver
	if driver == "" {
		driver = "virtual"
	}
	s := fmt.Sprintf("%s · %s · mtu %d", state, driver, l.MTU)
	if m.hasDef && l.Index == m.defRoute {
		s += " · default route"
	}
	return s
}

func (m model) linkDetail(l discovery.Link) string {
	addrs := "no IPv4 address"
	if v4 := l.IPv4(); len(v4) > 0 {
		parts := make([]string, len(v4))
		for i, p := range v4 {
			parts[i] = p.String()
		}
		addrs = strings.Join(parts, ", ")
	}
	return fmt.Sprintf("%s · %s · %d queues", l.MAC, addrs, l.RxQueues)
}

func (m model) viewPattern() string {
	var b strings.Builder
	b.WriteString(title(2, wizardSteps, "Traffic pattern") + "\n\n")
	b.WriteString(styleHint.Render("What kind of traffic do you want to send?") + "\n\n")

	for i, mo := range config.Modes {
		cursor := "  "
		// Pad before styling, or the escape sequences count toward the width.
		label := fmt.Sprintf("%-10s", mo)
		if i == m.modeIdx {
			cursor = styleCursor.Render("> ")
			label = styleSelected.Render(label)
		}
		fmt.Fprintf(&b, "%s%s %s\n", cursor, label, styleHint.Render(describeMode(mo)))
	}

	b.WriteString("\n" + footer(
		keyHint("↑/↓", "select"),
		keyHint("enter", "continue"),
		keyHint("esc", "back"),
	))
	return b.String()
}

func describeMode(m config.Mode) string {
	switch m {
	case config.ModeUDP:
		return "one or many deterministic UDP flows"
	case config.ModeTCPSYN:
		return "stateless TCP SYNs, no handshake, no connection state"
	case config.ModeIMIX:
		return "the classic 7:4:1 mix of 64, 594 and 1518-byte frames"
	case config.ModeRaw:
		return "a fixed EtherType and payload pattern"
	case config.ModePCAP:
		return "replay an Ethernet capture file"
	}
	return ""
}

// viewFields renders the dynamic form. Only the fields that matter for the
// chosen pattern and receive mode are present at all.
func (m model) viewFields() string {
	var b strings.Builder
	b.WriteString(title(3, wizardSteps, "Settings: "+string(m.cfg.Mode)) + "\n\n")

	// Keep the focused field on screen on a short terminal.
	start, end := m.fieldWindow()
	if start > 0 {
		b.WriteString(styleFaint.Render("   ↑ "+itoa(start)+" more above") + "\n")
	}

	for i := start; i < end; i++ {
		f := m.fields[i]
		cursor := "  "
		label := styleLabel.Render(fmt.Sprintf("%-22s", f.label))
		if i == m.fieldIdx {
			cursor = styleCursor.Render("> ")
			label = styleSelected.Render(fmt.Sprintf("%-22s", f.label))
		}

		var value string
		switch f.kind {
		case fieldChoice:
			value = m.renderChoice(f, m.inputs[i].Value(), i == m.fieldIdx)
		default:
			if i == m.fieldIdx {
				value = m.inputs[i].View()
			} else {
				v := m.inputs[i].Value()
				if v == "" {
					v = styleFaint.Render("(auto)")
				}
				value = v
			}
		}
		fmt.Fprintf(&b, "%s%s %s\n", cursor, label, value)

		if err, bad := m.fieldErrs[f.key]; bad {
			fmt.Fprintf(&b, "    %s\n", styleDanger.Render("✗ "+err))
		} else if i == m.fieldIdx && f.help != "" {
			fmt.Fprintf(&b, "    %s\n", styleFaint.Render(f.help))
		}
	}
	if end < len(m.fields) {
		b.WriteString(styleFaint.Render("   ↓ "+itoa(len(m.fields)-end)+" more below") + "\n")
	}

	if err, bad := m.fieldErrs[""]; bad {
		b.WriteString("\n" + styleDanger.Render("Cannot continue:") + "\n")
		// Wrap: these messages explain what to do about the problem, and a
		// truncated explanation is worse than none.
		b.WriteString(styleDanger.Render(wrapIndent(err, 2, m.textWidth())) + "\n")
	}

	b.WriteString("\n")
	hints := []string{keyHint("↑/↓", "move"), keyHint("enter", "review"), keyHint("esc", "back")}
	if m.fieldIdx < len(m.fields) && m.fields[m.fieldIdx].kind == fieldChoice {
		hints = append([]string{keyHint("←/→", "change")}, hints...)
	}
	b.WriteString(footer(hints...))
	return b.String()
}

// renderChoice draws an enum as its options with the current one marked, so
// there is nothing to guess and nothing to mistype.
func (m model) renderChoice(f field, cur string, focused bool) string {
	parts := make([]string, 0, len(f.choices))
	for _, c := range f.choices {
		switch {
		case c == cur && focused:
			parts = append(parts, styleSelected.Render("["+c+"]"))
		case c == cur:
			parts = append(parts, styleValue.Render("["+c+"]"))
		default:
			parts = append(parts, styleFaint.Render(" "+c+" "))
		}
	}
	return strings.Join(parts, " ")
}

// rowsFor is how many list entries fit on screen when each takes linesEach
// terminal rows, leaving chrome rows for the banner and footer.
func (m model) rowsFor(linesEach, chrome int) int {
	if m.height <= 0 {
		return 8
	}
	return max((m.height-chrome)/linesEach, 3)
}

// window is the slice of a list to show so that the cursor stays visible.
func window(cursor, total, rows int) (start, end int) {
	if total <= rows {
		return 0, total
	}
	start = max(cursor-rows/2, 0)
	end = min(start+rows, total)
	return max(end-rows, 0), end
}

// fieldWindow is the slice of fields that fits on screen, always containing
// the focused one. Each field takes two lines: the value, plus its help or
// error.
func (m model) fieldWindow() (start, end int) {
	return window(m.fieldIdx, len(m.fields), m.rowsFor(2, 10))
}

// viewReview is the last stop before anything touches the interface. It states
// what will happen, where every value came from, and what it will cost.
func (m model) viewReview() string {
	p := m.prepared
	if p == nil {
		return m.viewBusy("Preparing", "", nil)
	}
	r := p.Resolved
	info := p.Runner.Info()

	var b strings.Builder
	b.WriteString(title(4, wizardSteps, "Review") + "\n\n")

	row := func(k, v string) {
		fmt.Fprintf(&b, "  %s %s\n", styleLabel.Render(fmt.Sprintf("%-16s", k)), v)
	}

	row("Interface", fmt.Sprintf("%s (%s, %d queue(s))",
		r.Link.Name, driverOr(r.Link.Driver), p.Runner.Queues()))
	row("Receive mode", string(m.cfg.RxMode)+"  "+styleFaint.Render("("+info.Filter+")"))
	if m.cfg.UsesIPStack() {
		row("Source", fmt.Sprintf("%s  %s", r.SrcIP, styleFaint.Render(r.SrcMAC.String())))
		row("Destination", fmt.Sprintf("%s  port %d", r.Dst, m.cfg.DstPort))
		row("Next hop", fmt.Sprintf("%s  %s", macOr(r.DstMAC), styleFaint.Render("("+nextHopDesc(r)+")")))
		row("Flows", itoa(m.cfg.Flows))
	} else if r.DstMAC != nil {
		row("Destination", r.DstMAC.String())
	}
	row("Pattern", string(m.cfg.Mode)+"  "+styleFaint.Render(info.PacketSizes))
	// A run that transmits nothing has no frames to tag and no rate to limit.
	if m.cfg.Transmits() {
		if m.cfg.VLAN != 0 {
			row("VLAN", fmt.Sprintf("802.1Q id %d", m.cfg.VLAN))
		} else {
			row("VLAN", styleFaint.Render("untagged"))
		}
		row("Rate", rateDesc(m.cfg))
	}
	row("Duration", durationDesc(m.cfg))

	b.WriteString("\n  " + styleLabel.Render("Receive") + "\n")
	b.WriteString(wrapIndent(p.Plan.Redirects, 4, m.textWidth()) + "\n")
	for _, l := range p.Plan.Limitations {
		b.WriteString(styleFaint.Render(wrapIndent("· "+l, 4, m.textWidth())) + "\n")
	}
	for _, n := range r.Notes {
		b.WriteString(styleFaint.Render(wrapIndent("· "+n, 4, m.textWidth())) + "\n")
	}
	if p.Frames != nil {
		for _, w := range p.Frames.Warnings() {
			b.WriteString(styleWarn.Render(wrapIndent("! "+w, 4, m.textWidth())) + "\n")
		}
	}

	// Warnings, then anything that requires a decision. The filter's own
	// description is already above, so a check that just repeats it is shown
	// as a heading rather than printed twice.
	shown := p.Plan.Redirects
	for _, c := range p.Preflight.Warnings() {
		b.WriteString("\n" + styleWarn.Render("  ! "+c.Title) + "\n")
		if c.Detail != shown {
			b.WriteString(styleWarn.Render(wrapIndent(c.Detail, 4, m.textWidth())) + "\n")
		}
	}
	danger := p.Preflight.Dangerous()
	for _, c := range danger {
		b.WriteString("\n" + styleDanger.Render("  ⚠ "+strings.ToUpper(c.Title)) + "\n")
		if c.Detail != shown {
			b.WriteString(styleDanger.Render(wrapIndent(c.Detail, 4, m.textWidth())) + "\n")
		}
		if c.Fix != "" {
			b.WriteString(styleHint.Render(wrapIndent(c.Fix, 4, m.textWidth())) + "\n")
		}
	}

	b.WriteString("\n")
	if len(danger) > 0 && !m.confirmed {
		b.WriteString(styleDanger.Render("  This run needs an explicit confirmation. Type 'yes' to continue.") + "\n")
		b.WriteString("  " + m.confirmInput.View() + "\n\n")
		b.WriteString(footer(keyHint("enter", "confirm"), keyHint("esc", "back to settings")))
		return b.String()
	}
	b.WriteString(footer(
		keyHint("enter", "start"),
		keyHint("esc", "back to settings"),
		keyHint("q", "quit"),
	))
	return b.String()
}

// textWidth is how wide prose may be, leaving a comfortable margin.
func (m model) textWidth() int {
	if m.width <= 0 {
		return 76
	}
	return min(m.width-4, 100)
}

// wrapIndent word-wraps text so no line exceeds width columns in total, and
// indents every line by indent spaces. Explicit newlines are kept.
func wrapIndent(s string, indent, width int) string {
	pad := strings.Repeat(" ", indent)
	// Never wrap so hard that a line has room for almost nothing.
	limit := max(width, indent+20)

	var out []string
	for _, para := range strings.Split(s, "\n") {
		line := pad
		for _, word := range strings.Fields(para) {
			if line == pad {
				line += word
				continue
			}
			if len(line)+1+len(word) > limit {
				out = append(out, line)
				line = pad + word
				continue
			}
			line += " " + word
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

func (m model) viewHelp() string {
	var b strings.Builder
	b.WriteString(styleTitle.Render("Wireblast keys") + "\n\n")

	section := func(name string, rows [][2]string) {
		b.WriteString(styleHeader.Render(name) + "\n")
		for _, r := range rows {
			fmt.Fprintf(&b, "  %s  %s\n", styleKey.Render(fmt.Sprintf("%-8s", r[0])), styleHint.Render(r[1]))
		}
		b.WriteString("\n")
	}

	section("Wizard", [][2]string{
		{"↑ ↓", "move between items"},
		{"← →", "change a choice"},
		{"enter", "continue"},
		{"esc", "go back"},
		{"q", "quit"},
	})
	section("While running", [][2]string{
		{"space", "pause or resume transmitting"},
		{"+", "increase the rate by 10%"},
		{"-", "decrease the rate by 10%"},
		{"g", "graph: packets/sec, then bits/sec, then off"},
		{"r", "reset the visible counters (lifetime totals are kept)"},
		{"q", "stop and quit cleanly"},
		{"ctrl+c", "the same as q"},
	})

	b.WriteString(styleHeader.Render("Bit rates") + "\n")
	for _, r := range [][2]string{
		{"L1", "the frame plus its physical framing: 7-byte preamble, 1-byte " +
			"start-frame delimiter and 12-byte interframe gap. This is link " +
			"utilisation: 10G line rate means 10 Gbit/s of L1, and --bps is " +
			"measured in it."},
		{"L2", "the Ethernet frame itself, including its 4-byte FCS."},
	} {
		fmt.Fprintf(&b, "  %s  %s\n", styleKey.Render(r[0]),
			strings.TrimLeft(styleHint.Render(wrapIndent(r[1], 6, m.textWidth())), " "))
	}
	b.WriteString(styleHint.Render(wrapIndent(
		"bwm-ng, iftop, nload and `ip -s link` read the kernel's counters, which "+
			"exclude the FCS, so they read a little under L2: about 6% at 64-byte "+
			"frames, 1% at IMIX. All three numbers are correct; they measure "+
			"different things.", 2, m.textWidth())) + "\n\n")

	b.WriteString(styleHeader.Render("Good to know") + "\n")
	for _, s := range []string{
		"--packet-size is the whole Ethernet frame, including the 4-byte FCS.",
		"Rates are aggregate across every queue, not per queue.",
		"Transmit-only is the default: nothing is taken away from the kernel.",
		"The two graph rows share one scale, so TX and RX can be compared directly.",
		"The XDP program stays attached between runs, so 'r' restarts instantly. " +
			"It is reattached only if you change the interface, queue count or " +
			"receive mode, and detached when you quit.",
	} {
		b.WriteString(styleHint.Render(wrapIndent("· "+s, 2, m.textWidth())) + "\n")
	}

	b.WriteString("\n" + footer(keyHint("any key", "back")))
	return b.String()
}

// Small formatting helpers shared with the review screen.

func driverOr(d string) string {
	if d == "" {
		return "virtual"
	}
	return d
}

func macOr(m fmt.Stringer) string {
	if m == nil {
		return styleFaint.Render("(none)")
	}
	return m.String()
}

func nextHopDesc(r *discovery.Resolved) string {
	if r.MACSource == "" {
		return "unresolved"
	}
	if r.NextHop.IsValid() && !r.OnLink {
		return fmt.Sprintf("via %s, %s", r.NextHop, r.MACSource)
	}
	return string(r.MACSource)
}

func rateDesc(cfg *config.Config) string {
	switch {
	case cfg.PPS == 0 && cfg.BPS == 0:
		return styleWarn.Render("unlimited, line rate")
	case cfg.BPS == 0:
		return config.FormatPPS(cfg.PPS) + styleFaint.Render(" (aggregate)")
	case cfg.PPS == 0:
		return config.FormatBPS(cfg.BPS) + styleFaint.Render(" L1 (aggregate)")
	}
	return fmt.Sprintf("%s and %s%s", config.FormatPPS(cfg.PPS), config.FormatBPS(cfg.BPS),
		styleFaint.Render(" L1, whichever binds first"))
}

func durationDesc(cfg *config.Config) string {
	if cfg.Duration == 0 {
		return "until you stop it"
	}
	return cfg.Duration.String()
}
