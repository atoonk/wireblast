// Package tui is Wireblast's interactive front end: a short wizard that gets a
// run configured, and a live dashboard while it transmits.
//
// It contains no packet-generation or AF_XDP logic at all. Everything it does
// goes through the same config.Config, validation and dataplane.Runner the
// --no-tui path uses, so the two front ends cannot drift apart.
package tui

import "github.com/charmbracelet/lipgloss"

// The palette is deliberately small and sticks to the terminal's own ANSI
// colours, so Wireblast looks right on whatever theme the user already has
// rather than fighting it.
var (
	colAccent = lipgloss.AdaptiveColor{Light: "27", Dark: "39"}   // blue
	colOK     = lipgloss.AdaptiveColor{Light: "28", Dark: "42"}   // green
	colWarn   = lipgloss.AdaptiveColor{Light: "130", Dark: "214"} // amber
	colDanger = lipgloss.AdaptiveColor{Light: "160", Dark: "203"} // red
	colMuted  = lipgloss.AdaptiveColor{Light: "244", Dark: "245"} // grey
	colFaint  = lipgloss.AdaptiveColor{Light: "250", Dark: "240"} // fainter grey
)

var (
	styleTitle = lipgloss.NewStyle().Bold(true).Foreground(colAccent)
	styleHint  = lipgloss.NewStyle().Foreground(colMuted)
	styleFaint = lipgloss.NewStyle().Foreground(colFaint)
	styleLabel = lipgloss.NewStyle().Foreground(colMuted)
	styleValue = lipgloss.NewStyle().Bold(true)

	styleSelected = lipgloss.NewStyle().Bold(true).Foreground(colAccent)
	styleCursor   = lipgloss.NewStyle().Foreground(colAccent)

	styleOK     = lipgloss.NewStyle().Foreground(colOK)
	styleWarn   = lipgloss.NewStyle().Foreground(colWarn)
	styleDanger = lipgloss.NewStyle().Bold(true).Foreground(colDanger)

	styleHeader = lipgloss.NewStyle().Bold(true).Foreground(colAccent).
			BorderStyle(lipgloss.NormalBorder()).BorderBottom(true).BorderForeground(colFaint)

	styleBox = lipgloss.NewStyle().
			BorderStyle(lipgloss.RoundedBorder()).BorderForeground(colFaint).
			Padding(0, 1)

	styleKey = lipgloss.NewStyle().Bold(true).Foreground(colAccent)

	// The two sparkline rows are coloured so they read as a pair rather than
	// as two unrelated lines of punctuation.
	styleSparkTX = lipgloss.NewStyle().Foreground(colAccent)
	styleSparkRX = lipgloss.NewStyle().Foreground(colOK)
)

// levelStyle picks the colour for a preflight finding.
func levelStyle(danger, warn bool) lipgloss.Style {
	switch {
	case danger:
		return styleDanger
	case warn:
		return styleWarn
	}
	return styleHint
}

// title renders the banner shown at the top of every wizard stage.
func title(step, of int, name string) string {
	return styleTitle.Render("Wireblast") + styleHint.Render(
		"  ·  step "+itoa(step)+" of "+itoa(of)+"  ·  "+name)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// keyHint renders a "key action" pair for the footer.
func keyHint(key, action string) string {
	return styleKey.Render(key) + styleHint.Render(" "+action)
}

// footer joins key hints into the help line at the bottom of a stage.
func footer(pairs ...string) string {
	out := ""
	for i, p := range pairs {
		if i > 0 {
			out += styleFaint.Render("  ·  ")
		}
		out += p
	}
	return out
}
