package tui

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/atoonk/wireblast/internal/app"
	"github.com/atoonk/wireblast/internal/config"
	"github.com/atoonk/wireblast/internal/dataplane"
	"github.com/atoonk/wireblast/internal/discovery"
	"github.com/atoonk/wireblast/internal/prefs"
)

// stage is where the wizard has got to.
type stage int

const (
	stageInterface stage = iota
	stagePattern
	stageFields
	stagePreparing
	stageReview
	stageStarting
	stageRunning
	stageDone
	stageError
)

// wizardSteps is how many stages the user clicks through, for the
// "step N of M" banner.
const wizardSteps = 4

// graphMode is which metric the dashboard's sparklines show, or off.
type graphMode int

const (
	graphPackets graphMode = iota
	graphBits
	graphOff
)

// next cycles packets -> bits -> off -> packets.
func (g graphMode) next() graphMode { return (g + 1) % 3 }

// dashboardRows is how many rows the dashboard needs without the graph: the
// header, the counter boxes and the footer. Used to decide whether a short
// terminal has room for the graph at all.
const dashboardRows = 22

// refreshInterval is how often the dashboard repaints. The collector samples
// four times a second, so this keeps the display current without spending any
// more time formatting than it has to.
const refreshInterval = 250 * time.Millisecond

// Messages carrying the results of work done off the UI goroutine.
type (
	preparedMsg struct {
		prepared *app.Prepared
		err      error
	}
	startedMsg  struct{ err error }
	finishedMsg struct{ err error }
	tickMsg     time.Time
	// busyTickMsg animates the waiting screens. Attaching native XDP bounces
	// the link for several seconds, and a frozen screen for that long looks
	// like a hang.
	busyTickMsg time.Time
)

// busySpin is how often the waiting indicator advances.
const busySpin = 100 * time.Millisecond

// model is the whole interactive front end.
//
// It holds no packet or AF_XDP state of its own: the configuration is the same
// config.Config the CLI builds, and the run is a dataplane.Runner it starts and
// then only observes.
type model struct {
	ctx context.Context
	cfg *config.Config
	src discovery.Source

	stage stage
	err   error

	// Interface selection.
	links    []discovery.Link
	linkIdx  int
	defRoute int
	hasDef   bool

	// Pattern selection.
	modeIdx int

	// The dynamic form.
	fields    []field
	inputs    []textinput.Model
	fieldIdx  int
	fieldErrs map[string]string
	// edited records fields the user has typed into, so recomputed defaults
	// never overwrite a deliberate choice.
	edited map[string]bool

	// Review and run.
	prepared  *app.Prepared
	runner    *dataplane.Runner
	confirmed bool
	// confirmInput collects the typed "yes" for a dangerous run.
	confirmInput textinput.Model

	// store remembers settings between sessions.
	store *prefs.Store

	// session keeps the XDP program attached from one run to the next, so
	// rerunning does not pay for another link bounce. It is detached when the
	// program exits.
	session *dataplane.Session

	// busyFrame animates the waiting indicator; busySince is when the current
	// wait began, so the screen can say how long it has been going.
	busyFrame int
	busySince time.Time

	// graph is which metric the dashboard's sparklines show. It is a display
	// preference, not part of the run, so it is deliberately not remembered
	// between sessions.
	graph graphMode

	showHelp bool
	// showProblems reveals the per-queue drop/stall lines, which are hidden by
	// default so a NIC with many busy queues doesn't fill the dashboard with
	// them. Toggled with 'w'.
	showProblems bool
	width        int
	height       int
}

// Run opens the wizard, and then the dashboard once a run starts.
//
// cfg arrives already populated from the command line, so every flag the user
// passed shows up as the starting value of the matching field.
func Run(ctx context.Context, cfg *config.Config) error {
	m := newModel(ctx, cfg, discovery.NewSource())
	// The XDP program is held across runs and comes off here, whatever
	// happens to the program above — a clean quit, an error, or a panic.
	defer func() {
		if err := m.session.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "wireblast: detaching XDP: %v\n", err)
		}
	}()
	p := tea.NewProgram(m,
		tea.WithContext(ctx),
		tea.WithAltScreen(),
		// Wireblast installs its own signal handling in main, so a run can be
		// drained and the XDP program detached before exit; bubbletea must not
		// race it by quitting first.
		tea.WithoutSignalHandler(),
	)
	final, err := p.Run()
	if err != nil && !errors.Is(err, tea.ErrProgramKilled) && !errors.Is(err, context.Canceled) {
		return err
	}
	// The terminal is restored by now, so the summary and any error can be
	// printed as ordinary output.
	if fm, ok := final.(model); ok {
		return fm.finish()
	}
	return nil
}

func newModel(ctx context.Context, cfg *config.Config, src discovery.Source) model {
	ci := textinput.New()
	ci.Prompt = "> "
	ci.CharLimit = 8
	ci.Width = 10

	m := model{
		ctx:          ctx,
		cfg:          cfg,
		src:          src,
		store:        prefs.New(),
		session:      dataplane.NewSession(),
		fieldErrs:    map[string]string{},
		edited:       map[string]bool{},
		confirmInput: ci,
	}
	m.defRoute, m.hasDef = discovery.DefaultRouteLink(src)

	links, err := discovery.Interfaces(src)
	if err != nil {
		m.stage, m.err = stageError, err
		return m
	}
	if len(links) == 0 {
		m.stage = stageError
		m.err = errors.New("no usable network interfaces found.\n" +
			"Wireblast needs an interface that is up, is not loopback, has a hardware " +
			"address and exposes receive queues.")
		return m
	}
	m.links = links

	// Flags prepopulate the wizard: --interface selects the row rather than
	// making the user find it again, and every other flag becomes the starting
	// value of its field.
	for i, l := range links {
		if l.Name == cfg.Interface {
			m.linkIdx = i
			break
		}
	}
	for i, mo := range config.Modes {
		if mo == cfg.Mode {
			m.modeIdx = i
		}
	}
	// Anything already set on the command line counts as deliberate.
	for _, k := range presetKeys(cfg) {
		m.edited[k] = true
	}

	// --allow-match-all is the non-interactive stand-in for a person reading
	// the review screen and typing "yes". This session always shows that
	// screen, so grant it here however the mode arrived — chosen in the form
	// or passed as a flag. The confirmation itself is not skipped.
	if cfg.RxMode == config.RxAll {
		cfg.AllowMatchAll = true
	}

	m.applyInterface()

	// --start goes straight to the traffic. If the configuration is not
	// actually runnable, fall into the wizard with the reason shown rather
	// than failing at the prompt.
	if cfg.SkipWizard {
		if err := cfg.Validate(); err != nil {
			m.stage = stageFields
			m.fieldErrs[""] = err.Error()
		} else {
			m.stage = stagePreparing
		}
	}
	return m
}

// presetKeys lists the fields a command line has already filled in, so
// switching interfaces does not overwrite them.
func presetKeys(cfg *config.Config) []string {
	var out []string
	if cfg.SrcMAC != "" {
		out = append(out, "src-mac")
	}
	if cfg.SrcIP != "" {
		out = append(out, "src-ip")
	}
	return out
}

func (m model) Init() tea.Cmd {
	if m.stage == stagePreparing {
		return tea.Batch(textinput.Blink, m.prepare(), busyTick())
	}
	return textinput.Blink
}

// busy marks the start of a waiting stage and returns the command that keeps
// its indicator moving.
func (m *model) busy(st stage) tea.Cmd {
	m.stage = st
	m.busySince = time.Now()
	m.busyFrame = 0
	return busyTick()
}

func busyTick() tea.Cmd {
	return tea.Tick(busySpin, func(t time.Time) tea.Msg { return busyTickMsg(t) })
}

// waiting reports whether the current stage is one the user is waiting through.
func (m model) waiting() bool {
	return m.stage == stagePreparing || m.stage == stageStarting
}

// finish reports whatever the program ended with, after the terminal has been
// restored: a fatal error, or the run's summary.
func (m model) finish() error {
	if m.err != nil {
		return m.err
	}
	if m.runner != nil {
		fmt.Println(m.runner.Stats().Summary())
	}
	return nil
}

func (m *model) currentLink() discovery.Link {
	if m.linkIdx < len(m.links) {
		return m.links[m.linkIdx]
	}
	return discovery.Link{}
}

// applyInterface records the selected interface and recomputes the defaults
// that depend on it, so moving the cursor to a different NIC updates the
// source addressing instead of leaving the previous card's details behind.
func (m *model) applyInterface() {
	l := m.currentLink()
	m.cfg.Interface = l.Name

	// The source MAC follows the interface unless the user typed one.
	if !m.edited["src-mac"] {
		m.cfg.SrcMAC = ""
	}
	// So does the source address, preferring one on the destination's subnet.
	if !m.edited["src-ip"] && m.cfg.UsesIPStack() {
		m.cfg.SrcIP = ""
		l3 := l
		if m.cfg.VLAN != 0 {
			if vl, ok := discovery.VLANLink(m.src, l, m.cfg.VLAN); ok {
				l3 = vl
			}
		}
		if cands := discovery.SourceCandidates(l3, m.destPrefix()); len(cands) > 0 {
			m.cfg.SrcIP = cands[0].String()
		}
	}
	m.rebuildFields()
}

// destPrefix is the configured destination, or the zero prefix when it is not
// usable yet.
func (m *model) destPrefix() netip.Prefix {
	if m.cfg.DstIP == "" {
		return netip.Prefix{}
	}
	got, err := config.ParseDst(m.cfg.DstIP)
	if err != nil {
		return netip.Prefix{}
	}
	return got
}

// newInput makes a text input for one field.
func newInput(value string) textinput.Model {
	ti := textinput.New()
	ti.Prompt = ""
	ti.CharLimit = 64
	ti.Width = 34
	ti.SetValue(value)
	return ti
}

// rebuildFields regenerates the form for the current configuration.
func (m *model) rebuildFields() {
	m.fields = visibleFields(m.cfg)
	m.inputs = make([]textinput.Model, len(m.fields))
	for i, f := range m.fields {
		m.inputs[i] = newInput(f.get(m.cfg))
	}
	if m.fieldIdx >= len(m.fields) {
		m.fieldIdx = max(len(m.fields)-1, 0)
	}
	m.focusField(m.fieldIdx)
}

func (m *model) focusField(i int) {
	for j := range m.inputs {
		m.inputs[j].Blur()
	}
	if i >= 0 && i < len(m.inputs) && m.fields[i].kind == fieldText {
		m.inputs[i].Focus()
		m.inputs[i].SetCursor(len(m.inputs[i].Value()))
	}
}

// commitFields writes every field back into the configuration, collecting the
// ones that would not parse. It reports whether everything was accepted.
func (m *model) commitFields() bool {
	m.fieldErrs = map[string]string{}
	ok := true
	for i, f := range m.fields {
		if err := f.set(m.cfg, m.inputs[i].Value()); err != nil {
			m.fieldErrs[f.key] = err.Error()
			ok = false
		}
	}
	return ok
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil

	case preparedMsg:
		if msg.err != nil {
			// Resolution or preflight said no. Go back to the form with the
			// explanation attached rather than dead-ending.
			m.prepared = nil
			m.stage = stageFields
			m.fieldErrs = map[string]string{"": msg.err.Error()}
			return m, nil
		}
		m.prepared = msg.prepared
		m.confirmed = false
		m.confirmInput.SetValue("")
		if m.needsConfirmPrepared(msg.prepared) {
			// Something here needs a person to agree to it. That is exactly
			// what the review screen is for, so --start does not skip it.
			m.confirmInput.Focus()
			m.stage = stageReview
			return m, nil
		}
		if m.cfg.SkipWizard {
			m.cfg.SkipWizard = false // only the first run skips it
			cmd := m.start()
			return m, tea.Batch(cmd, m.busy(stageStarting))
		}
		m.stage = stageReview
		return m, nil

	case startedMsg:
		if msg.err != nil {
			m.err = msg.err
			return m, tea.Quit
		}
		m.stage = stageRunning
		return m, tea.Batch(m.waitForFinish(), tick())

	case finishedMsg:
		if msg.err != nil && !errors.Is(msg.err, context.Canceled) {
			m.err = msg.err
		}
		m.stage = stageDone
		return m, nil

	case tickMsg:
		if m.stage == stageRunning {
			return m, tick()
		}
		return m, nil

	case busyTickMsg:
		if !m.waiting() {
			return m, nil
		}
		m.busyFrame++
		return m, busyTick()

	case tea.KeyMsg:
		return m.handleKey(msg)
	}

	// Anything else goes to the focused text input (cursor blink, paste).
	if m.stage == stageFields && m.fieldIdx < len(m.inputs) {
		var cmd tea.Cmd
		m.inputs[m.fieldIdx], cmd = m.inputs[m.fieldIdx].Update(msg)
		return m, cmd
	}
	if m.stage == stageReview && m.needsConfirm() {
		var cmd tea.Cmd
		m.confirmInput, cmd = m.confirmInput.Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()

	// Ctrl-C always means stop, wherever we are.
	if key == "ctrl+c" {
		return m.stopOrQuit()
	}
	if m.showHelp {
		m.showHelp = false
		return m, nil
	}

	switch m.stage {
	case stageInterface:
		return m.keyInterface(key)
	case stagePattern:
		return m.keyPattern(key)
	case stageFields:
		return m.keyFields(msg, key)
	case stageReview:
		return m.keyReview(msg, key)
	case stageRunning:
		return m.keyRunning(key)
	case stageDone:
		return m.keyDone(key)
	case stageError:
		return m, tea.Quit
	case stagePreparing, stageStarting:
		if key == "esc" || key == "q" {
			return m.stopOrQuit()
		}
	}
	return m, nil
}

// stopOrQuit ends a running test cleanly, or quits outright if none is
// running. It never kills the dataplane from under itself: Stop only asks, and
// the run's own shutdown drains the rings and detaches the XDP program before
// the finished message arrives.
func (m model) stopOrQuit() (tea.Model, tea.Cmd) {
	if m.stage == stageRunning && m.runner != nil {
		m.runner.Stop()
		return m, nil
	}
	return m, tea.Quit
}

func (m model) keyInterface(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "up", "k":
		if m.linkIdx > 0 {
			m.linkIdx--
			m.applyInterface()
		}
	case "down", "j":
		if m.linkIdx < len(m.links)-1 {
			m.linkIdx++
			m.applyInterface()
		}
	case "enter":
		m.applyInterface()
		m.stage = stagePattern
	case "q":
		return m, tea.Quit
	case "?":
		m.showHelp = true
	}
	return m, nil
}

func (m model) keyPattern(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "up", "k":
		if m.modeIdx > 0 {
			m.modeIdx--
		}
	case "down", "j":
		if m.modeIdx < len(config.Modes)-1 {
			m.modeIdx++
		}
	case "enter":
		m.cfg.Mode = config.Modes[m.modeIdx]
		m.fieldIdx = 0
		m.rebuildFields()
		m.stage = stageFields
	case "esc":
		m.stage = stageInterface
	case "q":
		return m, tea.Quit
	case "?":
		m.showHelp = true
	}
	return m, nil
}

func (m model) keyFields(msg tea.KeyMsg, key string) (tea.Model, tea.Cmd) {
	switch key {
	case "esc":
		m.stage = stagePattern
		return m, nil
	case "up", "shift+tab":
		if m.fieldIdx > 0 {
			m.fieldIdx--
			m.focusField(m.fieldIdx)
		}
		return m, nil
	case "down", "tab":
		if m.fieldIdx < len(m.fields)-1 {
			m.fieldIdx++
			m.focusField(m.fieldIdx)
		}
		return m, nil
	case "enter":
		if !m.commitFields() {
			return m, nil
		}
		if err := m.cfg.Validate(); err != nil {
			m.fieldErrs[""] = err.Error()
			return m, nil
		}
		delete(m.fieldErrs, "")
		return m, tea.Batch(m.prepare(), m.busy(stagePreparing))
	}

	if m.fieldIdx >= len(m.fields) {
		return m, nil
	}
	f := m.fields[m.fieldIdx]

	// A choice field cycles rather than accepting typed text, so an enum can
	// never be misspelled.
	if f.kind == fieldChoice {
		switch key {
		case "left", "h":
			m.setChoice(nextChoice(f.choices, m.inputs[m.fieldIdx].Value(), -1))
		case "right", "l", " ":
			m.setChoice(nextChoice(f.choices, m.inputs[m.fieldIdx].Value(), +1))
		case "?":
			m.showHelp = true
		}
		return m, nil
	}

	var cmd tea.Cmd
	before := m.inputs[m.fieldIdx].Value()
	m.inputs[m.fieldIdx], cmd = m.inputs[m.fieldIdx].Update(msg)
	if m.inputs[m.fieldIdx].Value() != before {
		m.edited[f.key] = true
		// Validate as the user types so mistakes are visible immediately,
		// without blocking anything.
		if err := f.set(m.cfg, m.inputs[m.fieldIdx].Value()); err != nil {
			m.fieldErrs[f.key] = err.Error()
		} else {
			delete(m.fieldErrs, f.key)
			// A VLAN change moves where addressing is looked up, so the
			// suggested source address may no longer be right.
			if f.key == "vlan" && !m.edited["src-ip"] {
				m.applyInterface()
			}
			m.refreshVisible()
		}
	}
	return m, cmd
}

// setChoice applies a cycled enum value and refreshes the form, since a
// receive-mode change adds or removes the fields that go with it.
func (m *model) setChoice(v string) {
	f := m.fields[m.fieldIdx]
	m.inputs[m.fieldIdx].SetValue(v)
	if err := f.set(m.cfg, v); err != nil {
		m.fieldErrs[f.key] = err.Error()
		return
	}
	delete(m.fieldErrs, f.key)
	m.edited[f.key] = true
	m.refreshVisible()
}

// refreshVisible rebuilds the form when the set of relevant fields changes,
// keeping the cursor and anything already typed.
func (m *model) refreshVisible() {
	want := visibleFields(m.cfg)
	if sameFields(want, m.fields) {
		return
	}
	key := ""
	if m.fieldIdx < len(m.fields) {
		key = m.fields[m.fieldIdx].key
	}
	typed := make(map[string]string, len(m.fields))
	for i, f := range m.fields {
		typed[f.key] = m.inputs[i].Value()
	}

	m.fields = want
	m.inputs = make([]textinput.Model, len(want))
	for i, f := range want {
		v, ok := typed[f.key]
		if !ok {
			v = f.get(m.cfg)
		}
		m.inputs[i] = newInput(v)
		if f.key == key {
			m.fieldIdx = i
		}
	}
	if m.fieldIdx >= len(m.fields) {
		m.fieldIdx = max(len(m.fields)-1, 0)
	}
	m.focusField(m.fieldIdx)
}

func sameFields(a, b []field) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].key != b[i].key {
			return false
		}
	}
	return true
}

func (m model) keyReview(msg tea.KeyMsg, key string) (tea.Model, tea.Cmd) {
	// A dangerous run has to be typed out in full. This is deliberately not
	// satisfiable with a single keystroke, and --yes does not reach it either.
	if m.needsConfirm() && !m.confirmed {
		switch key {
		case "esc":
			m.confirmInput.SetValue("")
			m.stage = stageFields
			return m, nil
		case "enter":
			if strings.EqualFold(strings.TrimSpace(m.confirmInput.Value()), "yes") {
				m.confirmed = true
				cmd := m.start()
				return m, tea.Batch(cmd, m.busy(stageStarting))
			}
			return m, nil
		case "?":
			m.showHelp = true
			return m, nil
		}
		var cmd tea.Cmd
		m.confirmInput, cmd = m.confirmInput.Update(msg)
		return m, cmd
	}

	switch key {
	case "enter":
		cmd := m.start()
		return m, tea.Batch(cmd, m.busy(stageStarting))
	case "esc":
		m.stage = stageFields
	case "q":
		return m, tea.Quit
	case "?":
		m.showHelp = true
	}
	return m, nil
}

// keyDone drives the menu shown once a run has finished. Quitting is one
// option among several rather than the only one: the usual next step is
// another run, often with one thing changed.
func (m model) keyDone(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "r":
		// The finished runner's fleet is closed, so a rerun needs a fresh one.
		// Preparing again also re-resolves the next hop, which is what you
		// want if the far end has moved in the meantime.
		//
		// "Run it again" means exactly that: straight back to the traffic. The
		// review screen was already read once, and anything that genuinely
		// needs agreeing to will still stop and ask.
		m.runner = nil
		m.prepared = nil
		m.confirmed = false
		m.cfg.SkipWizard = true
		return m, tea.Batch(m.prepare(), m.busy(stagePreparing))
	case "e":
		m.runner = nil
		m.prepared = nil
		m.confirmed = false
		m.rebuildFields()
		m.stage = stageFields
		return m, nil
	case "p":
		m.runner = nil
		m.prepared = nil
		m.confirmed = false
		m.stage = stagePattern
		return m, nil
	case "g":
		// The shape of a finished run is worth looking at too.
		m.graph = m.graph.next()
	case "q", "esc":
		return m, tea.Quit
	case "?":
		m.showHelp = true
	}
	return m, nil
}

func (m model) keyRunning(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "q":
		return m.stopOrQuit()
	case " ":
		// Pausing stops transmission only. The dashboard and the receive side
		// keep updating, which is the point: you can watch return traffic
		// drain while nothing is being sent.
		m.runner.SetPaused(!m.runner.Paused())
	case "+", "=":
		m.runner.AdjustRate(1.1)
	case "-", "_":
		m.runner.AdjustRate(1 / 1.1)
	case "r":
		m.runner.Collector().ResetInterval()
	case "g":
		m.graph = m.graph.next()
	case "w":
		m.showProblems = !m.showProblems
	case "?":
		m.showHelp = true
	}
	return m, nil
}

// needsConfirm reports whether the prepared run has a finding that requires a
// typed confirmation before it may start.
func (m model) needsConfirm() bool { return m.needsConfirmPrepared(m.prepared) }

func (m model) needsConfirmPrepared(p *app.Prepared) bool {
	if p == nil || !p.Preflight.NeedsConfirmation() {
		return false
	}
	// --yes is the command-line form of typing the confirmation, and it means
	// the same thing here as it does for --no-tui: a run that was set up
	// deliberately, by someone who has read the warnings, should not stop for
	// a keystroke. Match-all still needs --allow-match-all, which validation
	// enforces before any of this is reached.
	return !m.cfg.AssumeYes
}

// prepare resolves addressing and runs the preflight checks off the UI
// goroutine — ARP resolution can take a second and a half, and the interface
// has to stay responsive.
func (m model) prepare() tea.Cmd {
	cfg := m.cfg
	src := m.src
	session := m.session
	return func() tea.Msg {
		p, err := app.Prepare(cfg, app.PrepareOptions{Source: src, Session: session})
		return preparedMsg{prepared: p, err: err}
	}
}

// start attaches the XDP program and begins transmitting. It can block for
// several seconds while a bounced link renegotiates, so it too runs off the UI
// goroutine.
func (m *model) start() tea.Cmd {
	runner := m.prepared.Runner
	m.runner = runner
	ctx := m.ctx
	// Remember this configuration so the next session starts from it. A
	// failure here is not worth interrupting a run for.
	_ = m.store.Save(m.cfg)
	return func() tea.Msg {
		return startedMsg{err: runner.Start(ctx)}
	}
}

// waitForFinish reports when the run has drained and detached.
func (m model) waitForFinish() tea.Cmd {
	runner := m.runner
	return func() tea.Msg {
		return finishedMsg{err: runner.Wait()}
	}
}

func tick() tea.Cmd {
	return tea.Tick(refreshInterval, func(t time.Time) tea.Msg { return tickMsg(t) })
}
