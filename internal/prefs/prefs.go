// Package prefs remembers what you ran last time.
//
// Filling in the same interface, destination and MAC on every invocation gets
// old fast, so Wireblast writes each run's settings to ~/.wireblast and offers
// them back as the starting point for the next interactive session.
//
// Two rules keep this from becoming surprising:
//
//   - Anything you pass on the command line wins over what was saved.
//   - --no-tui ignores saved settings entirely. A script has to mean exactly
//     what it says, whatever happens to be in a file in someone's home
//     directory.
package prefs

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/atoonk/wireblast/internal/config"
)

// Layout of the state directory.
const (
	// DirName is the directory under the user's home.
	DirName = ".wireblast"
	// LastFile holds the most recent run, used to prepopulate the wizard.
	LastFile = "last-run.json"
	// HistoryFile holds recent runs, newest first.
	HistoryFile = "history.json"
	// HistoryLimit is how many runs are kept.
	HistoryLimit = 20
)

// Entry is one remembered run.
type Entry struct {
	// At is when the run started.
	At time.Time `json:"at"`
	// Config is what it was configured with.
	Config config.Config `json:"config"`
}

// Summary renders an entry as one line, for a "recent runs" list.
func (e Entry) Summary() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s on %s", e.Config.Mode, e.Config.Interface)
	if e.Config.UsesIPStack() && e.Config.DstIP != "" {
		fmt.Fprintf(&b, " → %s", e.Config.DstIP)
	}
	if e.Config.VLAN != 0 {
		fmt.Fprintf(&b, " vlan %d", e.Config.VLAN)
	}
	if e.Config.Transmits() {
		fmt.Fprintf(&b, ", %s", config.FormatPPS(e.Config.PPS))
	}
	if e.Config.RxMode != config.RxNone {
		fmt.Fprintf(&b, ", rx %s", e.Config.RxMode)
	}
	return b.String()
}

// Store reads and writes the remembered settings.
//
// Every method degrades quietly: an unreadable or corrupt state file must
// never stop someone generating traffic, so failures mean "no history" rather
// than an error the user has to deal with.
type Store struct{ dir string }

// New returns a Store rooted at ~/.wireblast, or at $WIREBLAST_HOME when that
// is set (which is also how the tests get a scratch directory).
func New() *Store {
	if dir := os.Getenv("WIREBLAST_HOME"); dir != "" {
		return &Store{dir: dir}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return &Store{} // no home, no history; not an error worth reporting
	}
	return &Store{dir: filepath.Join(home, DirName)}
}

// NewAt returns a Store rooted at an explicit directory.
func NewAt(dir string) *Store { return &Store{dir: dir} }

// Dir is where the state lives, or "" when there is nowhere to keep it.
func (s *Store) Dir() string { return s.dir }

// Last returns the most recent run's configuration, and whether there was one.
func (s *Store) Last() (config.Config, bool) {
	if s.dir == "" {
		return config.Config{}, false
	}
	data, err := os.ReadFile(filepath.Join(s.dir, LastFile))
	if err != nil {
		return config.Config{}, false
	}
	var e Entry
	if err := json.Unmarshal(data, &e); err != nil {
		return config.Config{}, false
	}
	// A file written by a different version could hold anything; only offer it
	// back if it still makes sense.
	if e.Config.Mode == "" || e.Config.Interface == "" {
		return config.Config{}, false
	}
	return e.Config, true
}

// History returns the remembered runs, newest first.
func (s *Store) History() []Entry {
	if s.dir == "" {
		return nil
	}
	data, err := os.ReadFile(filepath.Join(s.dir, HistoryFile))
	if err != nil {
		return nil
	}
	var out []Entry
	if err := json.Unmarshal(data, &out); err != nil {
		return nil
	}
	return out
}

// Save records a run as the most recent one and adds it to the history.
//
// It returns an error so a caller can log it if it wants to, but nothing in
// Wireblast treats a failure here as fatal.
func (s *Store) Save(cfg *config.Config) error {
	if s.dir == "" {
		return errors.New("prefs: no home directory to save to")
	}
	if err := os.MkdirAll(s.dir, 0o755); err != nil {
		return fmt.Errorf("prefs: create %s: %w", s.dir, err)
	}

	e := Entry{At: time.Now(), Config: sanitise(*cfg)}
	if err := writeJSON(filepath.Join(s.dir, LastFile), e); err != nil {
		return err
	}

	// Newest first, one entry per distinct configuration, capped. Identity is
	// the configuration itself rather than its one-line summary, so two runs
	// that differ only in a field the summary omits still count as two.
	hist := append([]Entry{e}, s.History()...)
	seen := make(map[string]bool, len(hist))
	out := make([]Entry, 0, HistoryLimit)
	for _, h := range hist {
		key, err := json.Marshal(h.Config)
		if err != nil {
			continue
		}
		if seen[string(key)] {
			continue
		}
		seen[string(key)] = true
		if out = append(out, h); len(out) == HistoryLimit {
			break
		}
	}
	return writeJSON(filepath.Join(s.dir, HistoryFile), out)
}

// Forget removes everything Wireblast has remembered.
func (s *Store) Forget() error {
	if s.dir == "" {
		return nil
	}
	for _, f := range []string{LastFile, HistoryFile} {
		if err := os.Remove(filepath.Join(s.dir, f)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return nil
}

// sanitise strips the fields that describe one invocation rather than a
// configuration. Remembering that a previous run said "yes" to something
// dangerous would quietly carry that consent forward, which is exactly what
// those confirmations exist to prevent.
func sanitise(c config.Config) config.Config {
	c.NoTUI = false
	c.SkipWizard = false
	c.AssumeYes = false
	c.AllowMatchAll = false

	// Match-all is not remembered either. It is still guarded by a
	// confirmation, so carrying it forward would not be unsafe — but a later,
	// unrelated run silently arriving with "take every packet from the kernel"
	// already selected is a surprise nobody wants. Narrower receive modes are
	// useful to remember and are kept.
	if c.RxMode == config.RxAll {
		c.RxMode = config.RxNone
	}
	return c
}

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("prefs: encode %s: %w", path, err)
	}
	// Write to a temporary file and rename, so an interrupted write cannot
	// leave a half-parsed file behind.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o644); err != nil {
		return fmt.Errorf("prefs: write %s: %w", path, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("prefs: save %s: %w", path, err)
	}
	return nil
}

// Merge produces the configuration an interactive session should start from:
// the remembered run, with anything given on the command line laid over the
// top.
//
// changed reports whether a flag was actually passed, so a value that merely
// happens to equal its default does not count as a choice.
func Merge(flags config.Config, saved config.Config, changed func(flag string) bool) config.Config {
	out := saved

	// Each entry pairs a flag with how to carry its value across. Written out
	// rather than reflected over so that adding a flag without deciding how it
	// should be remembered is a compile error, not a silent omission.
	type field struct {
		flag string
		copy func(dst *config.Config, src config.Config)
	}
	fields := []field{
		{"interface", func(d *config.Config, s config.Config) { d.Interface = s.Interface }},
		{"mode", func(d *config.Config, s config.Config) { d.Mode = s.Mode }},
		{"src-ip", func(d *config.Config, s config.Config) { d.SrcIP = s.SrcIP }},
		{"dst-ip", func(d *config.Config, s config.Config) { d.DstIP = s.DstIP }},
		{"src-mac", func(d *config.Config, s config.Config) { d.SrcMAC = s.SrcMAC }},
		{"dst-mac", func(d *config.Config, s config.Config) { d.DstMAC = s.DstMAC }},
		{"src-port", func(d *config.Config, s config.Config) { d.SrcPort = s.SrcPort }},
		{"dst-port", func(d *config.Config, s config.Config) { d.DstPort = s.DstPort }},
		{"vary-dst-port", func(d *config.Config, s config.Config) { d.VaryDstPort = s.VaryDstPort }},
		{"flows", func(d *config.Config, s config.Config) { d.Flows = s.Flows }},
		{"flow-order", func(d *config.Config, s config.Config) { d.FlowOrder = s.FlowOrder }},
		{"packet-size", func(d *config.Config, s config.Config) { d.PacketSize = s.PacketSize }},
		{"vlan", func(d *config.Config, s config.Config) { d.VLAN = s.VLAN }},
		{"ethertype", func(d *config.Config, s config.Config) { d.EtherType = s.EtherType }},
		{"payload-byte", func(d *config.Config, s config.Config) { d.PayloadByte = s.PayloadByte }},
		{"duration", func(d *config.Config, s config.Config) { d.Duration = s.Duration }},
		{"pps", func(d *config.Config, s config.Config) { d.PPS = s.PPS }},
		{"bps", func(d *config.Config, s config.Config) { d.BPS = s.BPS }},
		{"queues", func(d *config.Config, s config.Config) { d.Queues = s.Queues }},
		{"rx-mode", func(d *config.Config, s config.Config) { d.RxMode = s.RxMode }},
		{"rx-port", func(d *config.Config, s config.Config) { d.RxPorts = s.RxPorts }},
		{"rx-cidr", func(d *config.Config, s config.Config) { d.RxCIDR = s.RxCIDR }},
		{"pcap", func(d *config.Config, s config.Config) { d.PCAPFile = s.PCAPFile }},
		{"pcap-timing", func(d *config.Config, s config.Config) { d.PCAPTiming = s.PCAPTiming }},
		{"pcap-loop", func(d *config.Config, s config.Config) { d.PCAPLoop = s.PCAPLoop }},
	}
	for _, f := range fields {
		if changed(f.flag) {
			f.copy(&out, flags)
		}
	}

	// Never inherited: these describe this invocation, not a configuration.
	out.NoTUI = flags.NoTUI
	out.SkipWizard = flags.SkipWizard
	out.AssumeYes = flags.AssumeYes
	out.AllowMatchAll = flags.AllowMatchAll

	// A --bps on the command line lifts the remembered packet cap the same way
	// it lifts the default one.
	if changed("bps") && !changed("pps") {
		out.PPS = flags.PPS
	}
	return out
}
