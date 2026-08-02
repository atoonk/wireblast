package tui

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/atoonk/wireblast/internal/config"
	"github.com/atoonk/wireblast/internal/discovery"
	"github.com/atoonk/wireblast/internal/stats"
)

// fakeSource is a scripted discovery.Source so the wizard can be driven
// without touching the machine's real network configuration.
type fakeSource struct {
	links  []discovery.Link
	routes []discovery.Route
	neighs map[int][]discovery.Neighbor
}

func mustMAC(s string) net.HardwareAddr {
	m, err := net.ParseMAC(s)
	if err != nil {
		panic(err)
	}
	return m
}

func bench() *fakeSource {
	return &fakeSource{
		links: []discovery.Link{
			{
				Name: "eth0", Index: 2, MAC: mustMAC("aa:bb:cc:00:00:01"), MTU: 1500,
				Up: true, Carrier: true, Driver: "ixgbe", RxQueues: 8,
				Addrs: []netip.Prefix{netip.MustParsePrefix("192.0.2.10/24")},
			},
			{
				Name: "eth1", Index: 3, MAC: mustMAC("aa:bb:cc:00:00:02"), MTU: 9000,
				Up: true, Carrier: true, Driver: "ixgbe", RxQueues: 4,
				Addrs: []netip.Prefix{netip.MustParsePrefix("10.0.0.1/24")},
			},
		},
		routes: []discovery.Route{
			{Dst: netip.MustParsePrefix("0.0.0.0/0"), Gateway: netip.MustParseAddr("192.0.2.1"), LinkIndex: 2},
			{Dst: netip.MustParsePrefix("192.0.2.0/24"), LinkIndex: 2},
			{Dst: netip.MustParsePrefix("10.0.0.0/24"), LinkIndex: 3},
		},
		neighs: map[int][]discovery.Neighbor{
			2: {{IP: netip.MustParseAddr("192.0.2.1"), MAC: mustMAC("de:ad:be:ef:00:01"), LinkIndex: 2, Reachable: true}},
			3: {{IP: netip.MustParseAddr("10.0.0.9"), MAC: mustMAC("de:ad:be:ef:00:09"), LinkIndex: 3, Reachable: true}},
		},
	}
}

func (f *fakeSource) Links() ([]discovery.Link, error)   { return f.links, nil }
func (f *fakeSource) Routes() ([]discovery.Route, error) { return f.routes, nil }
func (f *fakeSource) Neighbors(i int) ([]discovery.Neighbor, error) {
	return f.neighs[i], nil
}
func (f *fakeSource) Probe(discovery.Link, netip.Addr, time.Duration) error {
	return errors.New("no answer")
}

// press feeds one keystroke to the model, exactly as bubbletea would.
func press(t *testing.T, m model, key string) model {
	t.Helper()
	var msg tea.KeyMsg
	switch key {
	case "enter":
		msg = tea.KeyMsg{Type: tea.KeyEnter}
	case "esc":
		msg = tea.KeyMsg{Type: tea.KeyEsc}
	case "up":
		msg = tea.KeyMsg{Type: tea.KeyUp}
	case "down":
		msg = tea.KeyMsg{Type: tea.KeyDown}
	case "left":
		msg = tea.KeyMsg{Type: tea.KeyLeft}
	case "right":
		msg = tea.KeyMsg{Type: tea.KeyRight}
	case "space":
		msg = tea.KeyMsg{Type: tea.KeySpace, Runes: []rune{' '}}
	case "backspace":
		msg = tea.KeyMsg{Type: tea.KeyBackspace}
	case "ctrl+c":
		msg = tea.KeyMsg{Type: tea.KeyCtrlC}
	default:
		msg = tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(key)}
	}
	next, _ := m.Update(msg)
	return next.(model)
}

// typeText sends a string one rune at a time.
func typeText(t *testing.T, m model, s string) model {
	t.Helper()
	for _, r := range s {
		m = press(t, m, string(r))
	}
	return m
}

// clearField empties the focused text input.
func clearField(t *testing.T, m model) model {
	t.Helper()
	for range 80 {
		m = press(t, m, "backspace")
	}
	return m
}

func newTestModel(t *testing.T, mut func(*config.Config)) model {
	t.Helper()
	t.Setenv("WIREBLAST_HOME", t.TempDir())
	cfg := config.Default()
	if mut != nil {
		mut(&cfg)
	}
	m := newModel(context.Background(), &cfg, bench())
	m.width, m.height = 100, 60
	return m
}

// focusOn moves the cursor to a named field.
func focusOn(t *testing.T, m model, key string) model {
	t.Helper()
	for i, f := range m.fields {
		if f.key == key {
			m.fieldIdx = i
			m.focusField(i)
			return m
		}
	}
	t.Fatalf("no field %q in %v", key, fieldKeys(m))
	return m
}

func fieldKeys(m model) []string {
	out := make([]string, len(m.fields))
	for i, f := range m.fields {
		out[i] = f.key
	}
	return out
}

func hasField(m model, key string) bool {
	for _, f := range m.fields {
		if f.key == key {
			return true
		}
	}
	return false
}

// Running with no flags at all must land on a usable interface list.
func TestOpensOnInterfaceSelection(t *testing.T) {
	m := newTestModel(t, nil)
	if m.stage != stageInterface {
		t.Fatalf("stage = %v, want the interface list", m.stage)
	}
	view := m.View()
	for _, want := range []string{"eth0", "eth1", "ixgbe", "192.0.2.10/24", "queues", "enter"} {
		if !strings.Contains(view, want) {
			t.Errorf("interface list is missing %q:\n%s", want, view)
		}
	}
}

// Selecting an interface must fill in its MAC and an address, which is the
// whole point of not making the user type them.
func TestSelectingInterfacePopulatesSourceAddressing(t *testing.T) {
	m := newTestModel(t, nil)
	if m.cfg.Interface != "eth0" {
		t.Fatalf("Interface = %q, want eth0", m.cfg.Interface)
	}
	if m.cfg.SrcIP != "192.0.2.10" {
		t.Errorf("SrcIP = %q, want eth0's address", m.cfg.SrcIP)
	}

	// Moving to the other interface recomputes the dependent defaults.
	m = press(t, m, "down")
	if m.cfg.Interface != "eth1" {
		t.Fatalf("Interface = %q, want eth1", m.cfg.Interface)
	}
	if m.cfg.SrcIP != "10.0.0.1" {
		t.Errorf("SrcIP = %q, want eth1's address after switching", m.cfg.SrcIP)
	}
}

// A --src-ip on the command line is a deliberate choice and must survive a
// change of interface.
func TestExplicitSourceIPSurvivesInterfaceChange(t *testing.T) {
	m := newTestModel(t, func(c *config.Config) { c.SrcIP = "203.0.113.7" })
	m = press(t, m, "down")
	if m.cfg.SrcIP != "203.0.113.7" {
		t.Errorf("SrcIP = %q, want the value given on the command line", m.cfg.SrcIP)
	}
}

// Flags must prepopulate the wizard, not be ignored by it.
func TestFlagsPrepopulateTheWizard(t *testing.T) {
	m := newTestModel(t, func(c *config.Config) {
		c.Interface = "eth1"
		c.Mode = config.ModeTCPSYN
		c.DstIP = "10.0.0.9"
		c.Flows = 250
		c.PacketSize = 128
		c.VLAN = 100
		c.PPS = 2_000_000
	})
	if m.cfg.Interface != "eth1" || m.links[m.linkIdx].Name != "eth1" {
		t.Errorf("--interface eth1 did not select that row (selected %q)", m.links[m.linkIdx].Name)
	}
	if config.Modes[m.modeIdx] != config.ModeTCPSYN {
		t.Errorf("--mode tcp-syn did not select that pattern")
	}

	m = press(t, m, "enter") // interface -> pattern
	m = press(t, m, "enter") // pattern -> fields
	if m.stage != stageFields {
		t.Fatalf("stage = %v, want the settings form", m.stage)
	}
	want := map[string]string{
		"dst-ip": "10.0.0.9", "flows": "250", "packet-size": "128",
		"vlan": "100", "pps": "2Mpps",
	}
	for key, val := range want {
		m2 := focusOn(t, m, key)
		if got := m2.inputs[m2.fieldIdx].Value(); got != val {
			t.Errorf("field %s = %q, want %q", key, got, val)
		}
	}
}

// The form must only show the fields the chosen pattern actually uses.
func TestFormIsDynamicPerMode(t *testing.T) {
	tests := []struct {
		mode    config.Mode
		present []string
		absent  []string
	}{
		{config.ModeUDP,
			[]string{"dst-ip", "src-port", "dst-port", "flows", "packet-size", "vlan", "pps"},
			[]string{"pcap", "ethertype"}},
		{config.ModeTCPSYN,
			[]string{"dst-ip", "flows", "packet-size"},
			[]string{"pcap", "ethertype"}},
		{config.ModeIMIX,
			[]string{"dst-ip", "flows"},
			[]string{"packet-size", "pcap", "ethertype"}}, // IMIX sets its own sizes
		{config.ModeRaw,
			[]string{"ethertype", "dst-mac", "packet-size"},
			[]string{"dst-ip", "flows", "src-port", "pcap"}},
		{config.ModePCAP,
			[]string{"pcap", "pcap-timing", "pcap-loop"},
			[]string{"dst-ip", "flows", "packet-size", "src-port"}},
	}
	for _, tt := range tests {
		t.Run(string(tt.mode), func(t *testing.T) {
			m := newTestModel(t, func(c *config.Config) { c.Mode = tt.mode })
			m = press(t, m, "enter")
			m = press(t, m, "enter")
			for _, k := range tt.present {
				if !hasField(m, k) {
					t.Errorf("%s should show the %s field; got %v", tt.mode, k, fieldKeys(m))
				}
			}
			for _, k := range tt.absent {
				if hasField(m, k) {
					t.Errorf("%s should not show the %s field; got %v", tt.mode, k, fieldKeys(m))
				}
			}
		})
	}
}

// Changing the receive mode must add and remove the fields that go with it.
func TestReceiveModeRevealsItsFields(t *testing.T) {
	m := newTestModel(t, nil)
	m = press(t, m, "enter")
	m = press(t, m, "enter")
	m = focusOn(t, m, "rx-mode")

	if hasField(m, "rx-port") || hasField(m, "rx-cidr") {
		t.Fatal("transmit-only should show no receive fields")
	}

	// none -> generated-flow -> udp-port
	m = press(t, m, "right")
	m = press(t, m, "right")
	if m.cfg.RxMode != config.RxUDPPort {
		t.Fatalf("RxMode = %q, want udp-port", m.cfg.RxMode)
	}
	if !hasField(m, "rx-port") {
		t.Errorf("udp-port mode should reveal the port field; got %v", fieldKeys(m))
	}
	if hasField(m, "rx-cidr") {
		t.Error("udp-port mode should not show the CIDR field")
	}

	// ...on to cidr, which swaps one for the other.
	m = press(t, m, "right")
	m = press(t, m, "right")
	if m.cfg.RxMode != config.RxCIDR {
		t.Fatalf("RxMode = %q, want cidr", m.cfg.RxMode)
	}
	if !hasField(m, "rx-cidr") || hasField(m, "rx-port") {
		t.Errorf("cidr mode should show only the CIDR field; got %v", fieldKeys(m))
	}
}

// Choice fields cycle, so an enum can never be mistyped.
func TestChoiceFieldsCycleBothWays(t *testing.T) {
	m := newTestModel(t, nil)
	m = press(t, m, "enter")
	m = press(t, m, "enter")
	m = focusOn(t, m, "rx-mode")

	if m.cfg.RxMode != config.RxNone {
		t.Fatalf("starting RxMode = %q, want none", m.cfg.RxMode)
	}
	m = press(t, m, "left") // wraps to the last option
	if m.cfg.RxMode != config.RxAll {
		t.Errorf("stepping back from the first option gave %q, want all", m.cfg.RxMode)
	}
	m = press(t, m, "right")
	if m.cfg.RxMode != config.RxNone {
		t.Errorf("stepping forward again gave %q, want none", m.cfg.RxMode)
	}
}

// Typing a bad value must be caught and explained where it was typed.
func TestInlineValidation(t *testing.T) {
	m := newTestModel(t, nil)
	m = press(t, m, "enter")
	m = press(t, m, "enter")

	m = focusOn(t, m, "vlan")
	m = clearField(t, m)
	m = typeText(t, m, "9999")
	if m.fieldErrs["vlan"] == "" {
		t.Fatal("VLAN 9999 should be reported as invalid")
	}
	if !strings.Contains(m.View(), "1-4094") {
		t.Errorf("the error should say what is allowed:\n%s", m.View())
	}

	// Correcting it clears the error.
	m = clearField(t, m)
	m = typeText(t, m, "100")
	if m.fieldErrs["vlan"] != "" {
		t.Errorf("VLAN 100 is valid but still reports %q", m.fieldErrs["vlan"])
	}
	if m.cfg.VLAN != 100 {
		t.Errorf("cfg.VLAN = %d, want 100", m.cfg.VLAN)
	}
}

// Enter on the form must not advance while a required value is missing.
func TestCannotContinueWithoutADestination(t *testing.T) {
	m := newTestModel(t, nil)
	m = press(t, m, "enter")
	m = press(t, m, "enter")

	m = press(t, m, "enter") // no destination yet
	if m.stage != stageFields {
		t.Fatalf("stage = %v, want to stay on the form", m.stage)
	}
	if !strings.Contains(m.View(), "--dst-ip") {
		t.Errorf("the form should explain what is missing:\n%s", m.View())
	}
}

// The wizard and the CLI must run the same validation.
func TestWizardUsesTheSameValidation(t *testing.T) {
	m := newTestModel(t, nil)
	m = press(t, m, "enter")
	m = press(t, m, "enter")

	// An invalid VLAN is refused by config.Validate, exactly as it would be
	// for --no-tui.
	m = focusOn(t, m, "vlan")
	m = clearField(t, m)
	m = typeText(t, m, "5000")
	m = press(t, m, "enter")
	if m.stage != stageFields {
		t.Fatalf("stage = %v, want to be held on the form", m.stage)
	}
	if !strings.Contains(m.View(), "1-4094") {
		t.Errorf("the validation message should be shown:\n%s", m.View())
	}
}

// --allow-match-all is the non-interactive stand-in for a person reading the
// review screen and typing "yes". The wizard always shows that screen, so
// selecting match-all there must not dead-end on a flag the user cannot pass.
func TestWizardCanReachMatchAll(t *testing.T) {
	m := newTestModel(t, func(c *config.Config) {
		c.Interface = "eth1"
		c.DstIP = "10.0.0.9"
	})
	m = press(t, m, "enter")
	m = press(t, m, "enter")
	m = focusOn(t, m, "rx-mode")
	for range len(config.RxModes) - 1 {
		m = press(t, m, "right")
	}
	if m.cfg.RxMode != config.RxAll {
		t.Fatalf("RxMode = %q, want all", m.cfg.RxMode)
	}
	if !m.cfg.AllowMatchAll {
		t.Fatal("choosing match-all in the wizard should grant the acknowledgement")
	}

	// It must now get as far as the review screen...
	m = press(t, m, "enter")
	if m.stage != stagePreparing {
		t.Fatalf("stage = %v, want to be preparing; errors: %v", m.stage, m.fieldErrs)
	}
	next, _ := m.Update(m.prepare()())
	m = next.(model)
	if m.stage != stageReview {
		t.Fatalf("stage = %v, want the review screen; errors: %v", m.stage, m.fieldErrs)
	}

	// ...where it is still gated behind a typed confirmation.
	if !m.needsConfirm() {
		t.Fatal("match-all must still require an explicit confirmation")
	}
	view := m.View()
	for _, want := range []string{"EVERYTHING", "yes"} {
		if !strings.Contains(view, want) {
			t.Errorf("the confirmation should spell out %q:\n%s", want, view)
		}
	}
	m = press(t, m, "enter") // bare enter is not enough
	if m.confirmed {
		t.Fatal("match-all started without the typed confirmation")
	}

	// Backing away from match-all withdraws the acknowledgement.
	m = press(t, m, "esc")
	m = focusOn(t, m, "rx-mode")
	m = press(t, m, "left")
	if m.cfg.RxMode == config.RxAll {
		t.Fatal("expected to have moved off match-all")
	}
	if m.cfg.AllowMatchAll {
		t.Error("moving off match-all should withdraw the acknowledgement")
	}
}

func TestNavigationBackAndForth(t *testing.T) {
	m := newTestModel(t, nil)
	m = press(t, m, "enter")
	if m.stage != stagePattern {
		t.Fatalf("stage = %v, want the pattern list", m.stage)
	}
	m = press(t, m, "esc")
	if m.stage != stageInterface {
		t.Fatalf("esc from the pattern list gave %v, want the interface list", m.stage)
	}
	m = press(t, m, "enter")
	m = press(t, m, "down") // pick tcp-syn
	m = press(t, m, "enter")
	if m.cfg.Mode != config.ModeTCPSYN {
		t.Fatalf("Mode = %q, want tcp-syn", m.cfg.Mode)
	}
	m = press(t, m, "esc")
	if m.stage != stagePattern {
		t.Fatalf("esc from the form gave %v, want the pattern list", m.stage)
	}
}

func TestHelpOverlay(t *testing.T) {
	m := newTestModel(t, nil)
	m = press(t, m, "?")
	if !m.showHelp {
		t.Fatal("? should open the help overlay")
	}
	view := m.View()
	for _, want := range []string{"space", "pause", "+", "reset", "FCS", "aggregate"} {
		if !strings.Contains(view, want) {
			t.Errorf("help is missing %q:\n%s", want, view)
		}
	}
	m = press(t, m, "x")
	if m.showHelp {
		t.Error("any key should close the help overlay")
	}
}

func TestQuitFromTheWizard(t *testing.T) {
	for _, key := range []string{"q", "ctrl+c"} {
		cfg := config.Default()
		m := newModel(context.Background(), &cfg, bench())
		_, cmd := m.Update(tea.KeyMsg{Type: keyType(key), Runes: keyRunes(key)})
		if cmd == nil {
			t.Fatalf("%s should quit", key)
		}
		if msg := cmd(); msg == nil {
			t.Fatalf("%s produced no message", key)
		}
	}
}

func keyType(k string) tea.KeyType {
	if k == "ctrl+c" {
		return tea.KeyCtrlC
	}
	return tea.KeyRunes
}

func keyRunes(k string) []rune {
	if k == "ctrl+c" {
		return nil
	}
	return []rune(k)
}

// A host with nothing usable must say so plainly rather than showing an empty
// list.
func TestNoUsableInterfaces(t *testing.T) {
	cfg := config.Default()
	m := newModel(context.Background(), &cfg, &fakeSource{})
	if m.stage != stageError {
		t.Fatalf("stage = %v, want the error screen", m.stage)
	}
	if !strings.Contains(m.View(), "no usable network interfaces") {
		t.Errorf("view should explain the problem:\n%s", m.View())
	}
	if m.finish() == nil {
		t.Error("finish should report the error so the exit code is non-zero")
	}
}

// The review screen has to state every fact the spec asks for before anything
// is attached.
func TestReviewScreenShowsTheWholePlan(t *testing.T) {
	m := newTestModel(t, func(c *config.Config) {
		c.Interface = "eth1"
		c.DstIP = "10.0.0.9"
		c.VLAN = 100
		c.PacketSize = 68 // a tagged frame cannot be smaller
		c.Flows = 64
		c.Duration = 30 * time.Second
	})
	m = press(t, m, "enter")
	m = press(t, m, "enter")
	m = press(t, m, "enter") // -> preparing

	if m.stage != stagePreparing {
		t.Fatalf("stage = %v, want preparing", m.stage)
	}
	// Run the preparation the way bubbletea would, then feed back the result.
	msg := m.prepare()()
	next, _ := m.Update(msg)
	m = next.(model)
	if m.stage != stageReview {
		t.Fatalf("stage = %v, want the review screen; errors: %v", m.stage, m.fieldErrs)
	}

	view := m.View()
	for _, want := range []string{
		"Interface", "eth1", "ixgbe",
		"Receive mode", "none",
		"Source", "10.0.0.1",
		"Destination", "10.0.0.9",
		"Next hop", "de:ad:be:ef:00:09",
		"Flows", "64",
		"Pattern", "udp",
		"VLAN", "802.1Q id 100",
		"Rate", "100kpps",
		"Duration", "30s",
		"Nothing.", // what the receive filter takes from the kernel
		"enter", "start",
	} {
		if !strings.Contains(view, want) {
			t.Errorf("review screen is missing %q:\n%s", want, view)
		}
	}

	// Escape returns to editing rather than starting anything.
	m = press(t, m, "esc")
	if m.stage != stageFields {
		t.Errorf("esc from review gave %v, want the settings form", m.stage)
	}
}

// A destination that cannot be resolved must send the user back to the form
// with the explanation, not dead-end on a blank screen.
func TestUnresolvableDestinationReturnsToTheForm(t *testing.T) {
	m := newTestModel(t, func(c *config.Config) {
		c.Interface = "eth1"
		c.DstIP = "10.0.0.77" // on-link, but nothing answers ARP
	})
	m = press(t, m, "enter")
	m = press(t, m, "enter")
	m = press(t, m, "enter")

	next, _ := m.Update(m.prepare()())
	m = next.(model)
	if m.stage != stageFields {
		t.Fatalf("stage = %v, want to be back on the form", m.stage)
	}
	view := m.View()
	for _, want := range []string{"10.0.0.77", "ARP", "--dst-mac"} {
		if !strings.Contains(view, want) {
			t.Errorf("the explanation should mention %q:\n%s", want, view)
		}
	}
}

// A dangerous run must require the word "yes", and nothing shorter.
func TestDangerousRunRequiresTypedConfirmation(t *testing.T) {
	m := newTestModel(t, func(c *config.Config) {
		c.Interface = "eth0" // owns the default route in the fixture
		c.DstIP = "192.0.2.1"
		c.PPS = 0 // unlimited on the default-route interface: dangerous
		c.BPS = 0
	})
	m = press(t, m, "enter")
	m = press(t, m, "enter")
	m = press(t, m, "enter")
	next, _ := m.Update(m.prepare()())
	m = next.(model)

	if m.stage != stageReview {
		t.Fatalf("stage = %v, want review; errors %v", m.stage, m.fieldErrs)
	}
	if !m.needsConfirm() {
		t.Fatal("an unlimited run on the default-route interface should need confirmation")
	}
	view := m.View()
	for _, want := range []string{"explicit confirmation", "yes", "unlimited"} {
		if !strings.Contains(strings.ToLower(view), strings.ToLower(want)) {
			t.Errorf("the confirmation prompt is missing %q:\n%s", want, view)
		}
	}

	// Enter alone does not start it.
	m = press(t, m, "enter")
	if m.confirmed || m.stage != stageReview {
		t.Fatal("bare enter must not start a dangerous run")
	}
	// Neither does anything other than "yes".
	m = typeText(t, m, "no")
	m = press(t, m, "enter")
	if m.confirmed {
		t.Fatal("typing 'no' must not start a dangerous run")
	}
}

func TestWindowSizeIsTracked(t *testing.T) {
	m := newTestModel(t, nil)
	next, _ := m.Update(tea.WindowSizeMsg{Width: 120, Height: 40})
	m = next.(model)
	if m.width != 120 || m.height != 40 {
		t.Errorf("size = %dx%d, want 120x40", m.width, m.height)
	}
}

// A short terminal must scroll the form rather than truncating it.
func TestFormScrollsOnAShortTerminal(t *testing.T) {
	m := newTestModel(t, nil)
	m = press(t, m, "enter")
	m = press(t, m, "enter")
	m.height = 20

	start, end := m.fieldWindow()
	if end-start >= len(m.fields) {
		t.Skip("the form already fits")
	}
	// The focused field must always be inside the visible window.
	for i := range m.fields {
		m.fieldIdx = i
		start, end = m.fieldWindow()
		if i < start || i >= end {
			t.Fatalf("field %d is outside the visible window [%d,%d)", i, start, end)
		}
	}
	if !strings.Contains(m.View(), "more") {
		t.Error("a scrolled form should say there is more off-screen")
	}
}

func TestWrapIndent(t *testing.T) {
	const indent, width = 2, 30
	got := wrapIndent("one two three four five six seven eight nine ten", indent, width)
	for _, line := range strings.Split(got, "\n") {
		if !strings.HasPrefix(line, "  ") {
			t.Errorf("every line should be indented: %q", line)
		}
		if len(line) > width {
			t.Errorf("line is %d columns, over the %d limit: %q", len(line), width, line)
		}
	}
	if !strings.Contains(got, "\n") {
		t.Error("the text should have wrapped")
	}
	// Explicit newlines are preserved.
	if n := strings.Count(wrapIndent("a\nb", 0, 40), "\n"); n != 1 {
		t.Errorf("explicit newlines should survive, got %d", n)
	}
}

// A finished run is usually the start of the next one. Quitting must not be
// the only thing you can do.
func TestPostRunMenu(t *testing.T) {
	m := newTestModel(t, func(c *config.Config) {
		c.Interface = "eth1"
		c.DstIP = "10.0.0.9"
	})
	m.stage = stageDone

	// "Run it again" goes straight back to the traffic, without a second trip
	// through the review screen.
	m.stage = stageDone
	if again := press(t, m, "r"); !again.cfg.SkipWizard {
		t.Error("r should rerun immediately rather than asking for another review")
	}

	// Each option leads somewhere useful rather than exiting.
	for _, tt := range []struct {
		key  string
		want stage
	}{
		{"r", stagePreparing}, // run it again
		{"e", stageFields},    // change a setting
		{"p", stagePattern},   // change the traffic pattern
	} {
		m.stage = stageDone
		next := press(t, m, tt.key)
		if next.stage != tt.want {
			t.Errorf("%q from the finished screen gave stage %v, want %v", tt.key, next.stage, tt.want)
		}
		if next.runner != nil {
			t.Errorf("%q should drop the finished run's runner; a rerun needs a fresh one", tt.key)
		}
	}

	// ...and q still quits.
	m.stage = stageDone
	if _, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")}); cmd == nil {
		t.Error("q should quit from the finished screen")
	}
}

// The finished screen has to say what was just run, or "was that one flow or
// two? was it even UDP?" has no answer on screen.
func TestPostRunSummaryNamesTheRun(t *testing.T) {
	m := newTestModel(t, func(c *config.Config) {
		c.Interface = "eth1"
		c.Mode = config.ModeTCPSYN
		c.DstIP = "10.0.0.9"
		c.Flows = 64
		c.VLAN = 2131
		c.PPS = 500_000
	})
	got := m.doneSummary()
	for _, want := range []string{"tcp-syn", "10.0.0.9", "64 flows", "vlan 2131", "500kpps"} {
		if !strings.Contains(got, want) {
			t.Errorf("doneSummary = %q, missing %q", got, want)
		}
	}
	// One flow reads as "1 flow", not "1 flows".
	m.cfg.Flows = 1
	if !strings.Contains(m.doneSummary(), "1 flow,") && !strings.HasSuffix(m.doneSummary(), "1 flow") {
		if strings.Contains(m.doneSummary(), "1 flows") {
			t.Errorf("doneSummary = %q, want singular", m.doneSummary())
		}
	}
}

// Receive-only is a pattern like any other, and hides everything about
// transmitting.
func TestReceiveOnlyModeInTheWizard(t *testing.T) {
	m := newTestModel(t, func(c *config.Config) { c.Mode = config.ModeReceive })
	m = press(t, m, "enter")
	m = press(t, m, "enter")

	for _, absent := range []string{
		"dst-ip", "dst-mac", "src-mac", "flows", "packet-size", "src-port", "pps", "bps", "vlan",
	} {
		if hasField(m, absent) {
			t.Errorf("receive-only should not show %s; got %v", absent, fieldKeys(m))
		}
	}
	for _, present := range []string{"queues", "duration", "rx-mode"} {
		if !hasField(m, present) {
			t.Errorf("receive-only should show %s; got %v", present, fieldKeys(m))
		}
	}

	// It cannot start without something to receive.
	m = press(t, m, "enter")
	if m.stage != stageFields {
		t.Fatalf("stage = %v, want to be held on the form", m.stage)
	}
	if !strings.Contains(m.View(), "--rx-mode") {
		t.Errorf("it should explain that a receive mode is required:\n%s", m.View())
	}

	// With one chosen, it proceeds.
	m = focusOn(t, m, "rx-mode")
	m = press(t, m, "right") // none -> generated-flow (not valid here) ...
	m = press(t, m, "right") // ... -> udp-port
	m = focusOn(t, m, "rx-port")
	m = typeText(t, m, "9000")
	m = press(t, m, "enter")
	if m.stage != stagePreparing {
		t.Fatalf("stage = %v, want to proceed; errors %v", m.stage, m.fieldErrs)
	}
}

// --start means "I have already said what I want": go straight to the traffic
// and show the dashboard, no wizard.
func TestSkipWizardStartsImmediately(t *testing.T) {
	m := newTestModel(t, func(c *config.Config) {
		c.Interface = "eth1"
		c.DstIP = "10.0.0.9"
		c.SkipWizard = true
	})
	if m.stage != stagePreparing {
		t.Fatalf("stage = %v, want to be preparing already", m.stage)
	}
	if m.Init() == nil {
		t.Fatal("Init should kick off the preparation")
	}

	// Once resolved, it starts rather than showing the review screen.
	next, cmd := m.Update(m.prepare()())
	m = next.(model)
	if m.stage != stageStarting {
		t.Fatalf("stage = %v, want to be starting; errors: %v", m.stage, m.fieldErrs)
	}
	if cmd == nil {
		t.Fatal("it should have issued the start command")
	}
	// Only the first run skips the wizard; after that the menu is in charge.
	if m.cfg.SkipWizard {
		t.Error("the skip should be consumed, so a rerun still gets a review")
	}
}

// ...but it never skips a confirmation. Those exist precisely for the case
// where someone is in a hurry.
func TestSkipWizardStillConfirmsDangerousRuns(t *testing.T) {
	m := newTestModel(t, func(c *config.Config) {
		c.Interface = "eth0" // owns the default route in the fixture
		c.DstIP = "192.0.2.1"
		c.PPS, c.BPS = 0, 0 // unlimited
		c.SkipWizard = true
	})
	next, _ := m.Update(m.prepare()())
	m = next.(model)
	if m.stage != stageReview {
		t.Fatalf("stage = %v, want the review screen for a dangerous run", m.stage)
	}
	if !m.needsConfirm() {
		t.Fatal("this run should still need a typed confirmation")
	}
}

// A --start with a configuration that cannot run should explain itself in the
// wizard rather than dying at the prompt.
func TestSkipWizardFallsBackToTheFormWhenInvalid(t *testing.T) {
	m := newTestModel(t, func(c *config.Config) {
		c.Interface = "eth1"
		c.DstIP = "" // nothing to send to
		c.SkipWizard = true
	})
	if m.stage != stageFields {
		t.Fatalf("stage = %v, want the settings form", m.stage)
	}
	if !strings.Contains(m.View(), "--dst-ip") {
		t.Errorf("the reason should be on screen:\n%s", m.View())
	}
}

// The match-all acknowledgement must be granted however the mode arrives — by
// cycling the field or straight off the command line — because the wizard
// always shows the review screen that is the real gate.
func TestMatchAllFromAFlagIsNotADeadEnd(t *testing.T) {
	m := newTestModel(t, func(c *config.Config) {
		c.Interface = "eth1"
		c.Mode = config.ModeReceive
		c.RxMode = config.RxAll // as --rx-mode all would leave it
		c.SkipWizard = true
	})
	if !m.cfg.AllowMatchAll {
		t.Fatal("arriving with --rx-mode all should grant the acknowledgement")
	}
	if m.stage != stagePreparing {
		t.Fatalf("stage = %v, want to be preparing; errors: %v", m.stage, m.fieldErrs)
	}

	// It still stops at the review screen for a typed confirmation.
	next, _ := m.Update(m.prepare()())
	m = next.(model)
	if m.stage != stageReview {
		t.Fatalf("stage = %v, want the review screen", m.stage)
	}
	if !m.needsConfirm() {
		t.Error("match-all must still be confirmed")
	}
}

// --yes is the command-line form of typing the confirmation, so a scripted
// --start does not stop for a keystroke.
func TestYesSkipsTheConfirmationInTheTUI(t *testing.T) {
	mk := func(assumeYes bool) model {
		return newTestModel(t, func(c *config.Config) {
			c.Interface = "eth1"
			c.Mode = config.ModeReceive
			c.RxMode = config.RxAll
			c.AllowMatchAll = true
			c.AssumeYes = assumeYes
			c.SkipWizard = true
		})
	}

	// Without it, the review screen still demands a typed yes.
	m := mk(false)
	next, _ := m.Update(m.prepare()())
	m = next.(model)
	if m.stage != stageReview || !m.needsConfirm() {
		t.Fatalf("without --yes this should stop at the review screen; stage=%v", m.stage)
	}

	// With it, the run starts.
	m = mk(true)
	next, cmd := m.Update(m.prepare()())
	m = next.(model)
	if m.needsConfirm() {
		t.Error("--yes should answer the confirmation")
	}
	if m.stage != stageStarting {
		t.Fatalf("stage = %v, want to be starting", m.stage)
	}
	if cmd == nil {
		t.Error("it should have issued the start command")
	}
}

// --yes must not be a way around the match-all guard: that is what
// --allow-match-all is for, and validation refuses without it.
func TestYesAloneStillCannotReachMatchAll(t *testing.T) {
	c := config.Default()
	c.Interface = "eth1"
	c.DstIP = "10.0.0.9"
	c.RxMode = config.RxAll
	c.AssumeYes = true // but no --allow-match-all
	if err := c.Validate(); err == nil {
		t.Fatal("--yes alone must not permit --rx-mode all")
	} else if !strings.Contains(err.Error(), "--allow-match-all") {
		t.Errorf("the error should name the flag that is required: %v", err)
	}
}

// g cycles packets -> bits -> off -> packets, and nothing else moves with it.
func TestGraphToggleCycles(t *testing.T) {
	m := newTestModel(t, nil)
	if m.graph != graphPackets {
		t.Fatalf("the graph should start on packets/sec, got %v", m.graph)
	}
	m.stage = stageRunning

	want := []graphMode{graphBits, graphOff, graphPackets, graphBits}
	for i, w := range want {
		m = press(t, m, "g")
		if m.graph != w {
			t.Fatalf("press %d: graph = %v, want %v", i+1, m.graph, w)
		}
	}

	// The footer names what the key will do next, not what is on screen.
	m.graph = graphPackets
	if got := m.graphHint(); !strings.Contains(got, "bits") {
		t.Errorf("hint on packets = %q, should offer bits", got)
	}
	m.graph = graphBits
	if got := m.graphHint(); !strings.Contains(got, "off") {
		t.Errorf("hint on bits = %q, should offer off", got)
	}
	m.graph = graphOff
	if got := m.graphHint(); !strings.Contains(got, "packets") {
		t.Errorf("hint on off = %q, should offer packets", got)
	}
}

// The finished screen keeps the graph reachable, so the shape of a run can be
// inspected after it ends.
func TestGraphToggleWorksOnTheFinishedScreen(t *testing.T) {
	m := newTestModel(t, nil)
	m.stage = stageDone
	m = press(t, m, "g")
	if m.graph != graphBits {
		t.Errorf("g on the finished screen gave %v, want bits", m.graph)
	}
	if m.stage != stageDone {
		t.Errorf("g should not leave the finished screen, went to %v", m.stage)
	}
}

// history builds a snapshot with n seconds of history at a fixed rate.
func historySnapshot(n int, txPPS, rxPPS float64) *stats.Snapshot {
	s := &stats.Snapshot{
		Transmits: true,
		TXRate:    stats.Rates{PPS: txPPS, WireBPS: txPPS * 84 * 8},
		RXRate:    stats.Rates{PPS: rxPPS, WireBPS: rxPPS * 84 * 8},
	}
	base := time.Unix(1700000000, 0)
	for i := range n {
		s.History = append(s.History, stats.HistoryPoint{
			At: base.Add(time.Duration(i) * time.Second),
			TX: stats.Rates{PPS: txPPS, WireBPS: txPPS * 84 * 8},
			RX: stats.Rates{PPS: rxPPS, WireBPS: rxPPS * 84 * 8},
		})
	}
	return s
}

func TestGraphRendersBothDirections(t *testing.T) {
	m := newTestModel(t, func(c *config.Config) {
		c.RxMode = config.RxUDPPort
		c.RxPorts = []uint16{9000}
	})
	m.width, m.height = 120, 44

	got := m.dashGraph(historySnapshot(40, 400_000, 200_000))
	if got == "" {
		t.Fatal("expected a graph")
	}
	for _, want := range []string{"packets/sec", "last ", "peak", "TX", "RX"} {
		if !strings.Contains(got, want) {
			t.Errorf("graph is missing %q:\n%s", want, got)
		}
	}
	// Half the rate must draw shorter, which is the shared scale working.
	lines := strings.Split(strings.TrimRight(got, "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected a heading and two rows, got %d lines:\n%s", len(lines), got)
	}

	// Switching metric changes the heading and the units.
	m.graph = graphBits
	got = m.dashGraph(historySnapshot(40, 400_000, 200_000))
	if !strings.Contains(got, "bits/sec") {
		t.Errorf("bits mode should say so:\n%s", got)
	}
	if !strings.Contains(got, "bit/s") {
		t.Errorf("bits mode should format values in bits:\n%s", got)
	}
}

func TestGraphHiddenWhenOff(t *testing.T) {
	m := newTestModel(t, nil)
	m.width, m.height = 120, 44
	m.graph = graphOff
	if got := m.dashGraph(historySnapshot(40, 400_000, 0)); got != "" {
		t.Errorf("the graph should be hidden when off, got:\n%s", got)
	}
}

func TestGraphNeedsHistory(t *testing.T) {
	m := newTestModel(t, nil)
	m.width, m.height = 120, 44
	if got := m.dashGraph(&stats.Snapshot{Transmits: true}); got != "" {
		t.Errorf("no history should draw nothing, got:\n%s", got)
	}
}

// A short terminal loses the graph, not the footer.
func TestGraphHiddenOnAShortTerminal(t *testing.T) {
	m := newTestModel(t, nil)
	m.width, m.height = 120, 20
	if got := m.dashGraph(historySnapshot(40, 400_000, 0)); got != "" {
		t.Errorf("a 20-row terminal has no room for the graph, got:\n%s", got)
	}
	m.height = 44
	if got := m.dashGraph(historySnapshot(40, 400_000, 0)); got == "" {
		t.Error("a 44-row terminal has room and should draw it")
	}
}

// Only the directions a run actually uses get a row, and only they set the
// scale — otherwise a receive-only run would be measured against a flat zero.
func TestGraphShowsOnlyActiveDirections(t *testing.T) {
	// Transmit only.
	m := newTestModel(t, nil)
	m.width, m.height = 120, 44
	got := m.dashGraph(historySnapshot(30, 400_000, 0))
	if strings.Contains(got, "RX") {
		t.Errorf("a transmit-only run should have no RX row:\n%s", got)
	}
	if !strings.Contains(got, "TX") {
		t.Errorf("a transmit-only run should have a TX row:\n%s", got)
	}

	// Receive only.
	m = newTestModel(t, func(c *config.Config) {
		c.Mode = config.ModeReceive
		c.RxMode = config.RxUDPPort
		c.RxPorts = []uint16{9000}
	})
	m.width, m.height = 120, 44
	s := historySnapshot(30, 0, 250_000)
	s.Transmits = false
	got = m.dashGraph(s)
	if strings.Contains(got, "TX") {
		t.Errorf("a receive-only run should have no TX row:\n%s", got)
	}
	if !strings.Contains(got, "RX") {
		t.Errorf("a receive-only run should have an RX row:\n%s", got)
	}
	// The peak must come from the RX series, not from the absent TX one.
	if !strings.Contains(got, "peak 250 kpps") {
		t.Errorf("the scale should come from the active direction:\n%s", got)
	}
}

// The counter columns grow with the terminal, within limits.
func TestBoxWidthAdapts(t *testing.T) {
	tests := []struct {
		termWidth int
		want      int
	}{
		{0, minBoxWidth},   // before the first window-size message
		{80, 38},           // an 80-column terminal genuinely fits two 38s
		{120, 52},          // (120-4)/2 = 58, capped at the maximum
		{200, maxBoxWidth}, // very wide: values must not drift from labels
		{40, minBoxWidth},  // narrower than the floor: hold it and overflow
	}
	for _, tt := range tests {
		m := newTestModel(t, nil)
		m.width = tt.termWidth
		got := m.boxWidth()
		want := min(tt.want, maxBoxWidth)
		if got != want {
			t.Errorf("terminal %d columns: boxWidth = %d, want %d", tt.termWidth, got, want)
		}
		if got < minBoxWidth || got > maxBoxWidth {
			t.Errorf("terminal %d columns: boxWidth %d is outside [%d,%d]",
				tt.termWidth, got, minBoxWidth, maxBoxWidth)
		}
		// Two columns and the gap must fit the terminal.
		if tt.termWidth >= 80 && m.blockWidth() > tt.termWidth {
			t.Errorf("terminal %d columns: block of %d does not fit",
				tt.termWidth, m.blockWidth())
		}
	}
}

// The counter columns must name both bit rates. An unlabelled pair is what
// made these numbers confusing, and a silent no-match while refactoring the
// layout is exactly how the labels went missing once already.
func TestCounterColumnsNameBothBitRates(t *testing.T) {
	got := counterBlock("TX", stats.Totals{Packets: 1000, Bytes: 68000},
		stats.Rates{PPS: 1000, FrameBPS: 544000, WireBPS: 704000}, false, 52)
	for _, want := range []string{"Bits/sec  L1", "Bits/sec  L2"} {
		if !strings.Contains(got, want) {
			t.Errorf("the counter column should carry %q:\n%s", want, got)
		}
	}
	// The old homemade vocabulary must be gone.
	for _, gone := range []string{"frame only", "wire"} {
		if strings.Contains(got, gone) {
			t.Errorf("the column still says %q; it should use L1/L2:\n%s", gone, got)
		}
	}
}

// The per-queue drop/stall lines are hidden by default and toggled with 'w'.
func TestToggleProblemsKey(t *testing.T) {
	var m model
	if m.showProblems {
		t.Fatal("per-queue drop lines should be hidden by default")
	}
	next, _ := m.keyRunning("w")
	if !next.(model).showProblems {
		t.Error("w should reveal the per-queue drop lines")
	}
	back, _ := next.(model).keyRunning("w")
	if back.(model).showProblems {
		t.Error("w again should hide them")
	}
}
