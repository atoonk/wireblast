package prefs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/atoonk/wireblast/internal/config"
)

func sample() config.Config {
	c := config.Default()
	c.Interface = "eth1"
	c.Mode = config.ModeTCPSYN
	c.DstIP = "192.0.2.10"
	c.DstMAC = "aa:bb:cc:dd:ee:ff"
	c.VLAN = 2131
	c.Flows = 500
	c.PPS = 2_000_000
	return c
}

func TestSaveAndLoad(t *testing.T) {
	s := NewAt(t.TempDir())
	if _, ok := s.Last(); ok {
		t.Fatal("a fresh store should remember nothing")
	}

	want := sample()
	if err := s.Save(&want); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, ok := s.Last()
	if !ok {
		t.Fatal("Last should return the run that was just saved")
	}
	if got.Interface != "eth1" || got.Mode != config.ModeTCPSYN || got.DstIP != "192.0.2.10" ||
		got.VLAN != 2131 || got.Flows != 500 || got.PPS != 2_000_000 {
		t.Errorf("the remembered settings do not match what was saved: %+v", got)
	}
}

// Consent is per-invocation. Remembering a "yes" would quietly carry it into
// the next run, which is exactly what those confirmations exist to prevent.
func TestConsentIsNeverRemembered(t *testing.T) {
	s := NewAt(t.TempDir())
	c := sample()
	c.RxMode = config.RxAll
	c.AllowMatchAll = true
	c.AssumeYes = true
	c.NoTUI = true
	if err := s.Save(&c); err != nil {
		t.Fatal(err)
	}

	got, _ := s.Last()
	if got.AllowMatchAll {
		t.Error("--allow-match-all must not be remembered")
	}
	if got.AssumeYes {
		t.Error("--yes must not be remembered")
	}
	if got.NoTUI {
		t.Error("--no-tui must not be remembered")
	}
	// Match-all is not remembered at all: a later, unrelated run should not
	// arrive with "take every packet from the kernel" already selected.
	if got.RxMode == config.RxAll {
		t.Error("--rx-mode all must not be carried into the next run")
	}
}

// Narrower receive modes are genuinely useful to remember, and are kept.
func TestNarrowReceiveModesAreRemembered(t *testing.T) {
	s := NewAt(t.TempDir())
	c := sample()
	c.RxMode = config.RxUDPPort
	c.RxPorts = []uint16{9000}
	if err := s.Save(&c); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Last()
	if got.RxMode != config.RxUDPPort {
		t.Errorf("RxMode = %q, want udp-port remembered", got.RxMode)
	}
	if len(got.RxPorts) != 1 || got.RxPorts[0] != 9000 {
		t.Errorf("RxPorts = %v, want [9000]", got.RxPorts)
	}
}

func TestHistory(t *testing.T) {
	s := NewAt(t.TempDir())
	for i, dst := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"} {
		c := sample()
		c.DstIP = dst
		if err := s.Save(&c); err != nil {
			t.Fatalf("save %d: %v", i, err)
		}
	}
	h := s.History()
	if len(h) != 3 {
		t.Fatalf("history has %d entries, want 3", len(h))
	}
	// Newest first.
	if !strings.Contains(h[0].Summary(), "192.0.2.3") {
		t.Errorf("the newest run should be first, got %q", h[0].Summary())
	}
	if h[0].At.IsZero() {
		t.Error("entries should be timestamped")
	}
	// The last saved run is also the most recent history entry.
	last, _ := s.Last()
	if last.DstIP != "192.0.2.3" {
		t.Errorf("Last = %q, want the newest", last.DstIP)
	}
}

// Running the same test repeatedly should not fill the history with copies.
func TestHistoryDeduplicates(t *testing.T) {
	s := NewAt(t.TempDir())
	c := sample()
	for range 5 {
		if err := s.Save(&c); err != nil {
			t.Fatal(err)
		}
	}
	if h := s.History(); len(h) != 1 {
		t.Errorf("history has %d entries for five identical runs, want 1", len(h))
	}
}

func TestHistoryIsCapped(t *testing.T) {
	s := NewAt(t.TempDir())
	for i := range HistoryLimit + 10 {
		c := sample()
		c.DstPort = uint16(9000 + i)
		if err := s.Save(&c); err != nil {
			t.Fatal(err)
		}
	}
	if h := s.History(); len(h) != HistoryLimit {
		t.Errorf("history holds %d entries, want the %d cap", len(h), HistoryLimit)
	}
}

func TestForget(t *testing.T) {
	dir := t.TempDir()
	s := NewAt(dir)
	c := sample()
	if err := s.Save(&c); err != nil {
		t.Fatal(err)
	}
	if err := s.Forget(); err != nil {
		t.Fatalf("Forget: %v", err)
	}
	if _, ok := s.Last(); ok {
		t.Error("Forget should have removed the remembered run")
	}
	if len(s.History()) != 0 {
		t.Error("Forget should have removed the history")
	}
	// Forgetting twice is not an error.
	if err := s.Forget(); err != nil {
		t.Errorf("a second Forget should be a no-op, got %v", err)
	}
}

// A corrupt or foreign state file must never stop someone generating traffic.
func TestCorruptStateIsIgnored(t *testing.T) {
	dir := t.TempDir()
	s := NewAt(dir)
	for _, content := range []string{"", "{", "not json at all", `{"config":{}}`} {
		if err := os.WriteFile(filepath.Join(dir, LastFile), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, ok := s.Last(); ok {
			t.Errorf("a state file of %q should be ignored, not offered back", content)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, HistoryFile), []byte("garbage"), 0o644); err != nil {
		t.Fatal(err)
	}
	if len(s.History()) != 0 {
		t.Error("a corrupt history file should read as empty")
	}
}

// With no home directory there is nowhere to keep state; that is not an error
// anyone should see.
func TestNoHomeDirectory(t *testing.T) {
	s := NewAt("")
	if _, ok := s.Last(); ok {
		t.Error("Last should report nothing")
	}
	if s.History() != nil {
		t.Error("History should be empty")
	}
	if err := s.Forget(); err != nil {
		t.Errorf("Forget should be a no-op, got %v", err)
	}
	c := sample()
	if err := s.Save(&c); err == nil {
		t.Error("Save should report that there is nowhere to save")
	}
}

func TestNewUsesEnvironmentOverride(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("WIREBLAST_HOME", dir)
	if got := New().Dir(); got != dir {
		t.Errorf("Dir = %q, want the override %q", got, dir)
	}
}

// Merge is the precedence rule: saved settings are the starting point, the
// command line wins wherever it says anything.
func TestMerge(t *testing.T) {
	saved := sample()

	flags := config.Default()
	flags.Interface = "eth9"
	flags.DstIP = "10.0.0.1"
	changed := func(f string) bool { return f == "interface" || f == "dst-ip" }

	got := Merge(flags, saved, changed)
	if got.Interface != "eth9" || got.DstIP != "10.0.0.1" {
		t.Errorf("the command line should win: interface=%q dst-ip=%q", got.Interface, got.DstIP)
	}
	// Everything not given on the command line comes from the saved run.
	if got.Mode != config.ModeTCPSYN {
		t.Errorf("Mode = %q, want the remembered tcp-syn", got.Mode)
	}
	if got.VLAN != 2131 || got.Flows != 500 || got.PPS != 2_000_000 {
		t.Errorf("remembered settings were lost: vlan=%d flows=%d pps=%d",
			got.VLAN, got.Flows, got.PPS)
	}
	if got.DstMAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("DstMAC = %q, want the remembered value", got.DstMAC)
	}
}

func TestMergeNeverInheritsConsent(t *testing.T) {
	saved := sample()
	saved.AllowMatchAll = true
	saved.AssumeYes = true
	saved.NoTUI = true

	flags := config.Default()
	got := Merge(flags, saved, func(string) bool { return false })
	if got.AllowMatchAll || got.AssumeYes || got.NoTUI {
		t.Errorf("consent flags must come from this invocation only: %+v", got)
	}
}

// A --bps on the command line has to lift a remembered packet cap, or the new
// bit rate would be silently throttled by the old pps.
func TestMergeBPSLiftsRememberedPacketCap(t *testing.T) {
	saved := sample() // pps 2M
	flags := config.Default()
	flags.BPS = 5e9
	flags.PPS = 0

	got := Merge(flags, saved, func(f string) bool { return f == "bps" })
	if got.BPS != 5e9 {
		t.Errorf("BPS = %d, want 5e9", got.BPS)
	}
	if got.PPS != 0 {
		t.Errorf("PPS = %d, want 0 — a remembered cap must not throttle a new --bps", got.PPS)
	}

	// ...unless the packet rate was given too.
	flags.PPS = 1_000_000
	got = Merge(flags, saved, func(f string) bool { return f == "bps" || f == "pps" })
	if got.PPS != 1_000_000 || got.BPS != 5e9 {
		t.Errorf("both given: pps=%d bps=%d, want 1000000/5e9", got.PPS, got.BPS)
	}
}

// Every field the wizard can edit must survive a save/load round trip, or a
// user would silently lose settings between sessions.
func TestEveryFieldRoundTrips(t *testing.T) {
	s := NewAt(t.TempDir())
	c := config.Config{
		Interface: "eth7", Mode: config.ModeIMIX,
		SrcIP: "10.1.1.1", DstIP: "10.2.2.0/24",
		SrcMAC: "02:00:00:00:00:01", DstMAC: "02:00:00:00:00:02",
		SrcPort: 1234, DstPort: 5678, VaryDstPort: true,
		Flows: 777, FlowOrder: config.FlowRandom,
		PacketSize: 512, VLAN: 100, EtherType: 0x1234, PayloadByte: 0x7f,
		Duration: 90 * time.Second, PPS: 123456, BPS: 7e9, Queues: 3,
		RxMode: config.RxUDPPort, RxPorts: []uint16{53, 5353}, RxCIDR: "10.0.0.0/8",
		PCAPFile: "/tmp/x.pcap", PCAPTiming: config.PcapOriginal, PCAPLoop: false,
	}
	if err := s.Save(&c); err != nil {
		t.Fatal(err)
	}
	got, ok := s.Last()
	if !ok {
		t.Fatal("nothing was remembered")
	}

	want := c // the consent fields are stripped, and were never set here
	if got.Interface != want.Interface || got.Mode != want.Mode ||
		got.SrcIP != want.SrcIP || got.DstIP != want.DstIP ||
		got.SrcMAC != want.SrcMAC || got.DstMAC != want.DstMAC ||
		got.SrcPort != want.SrcPort || got.DstPort != want.DstPort ||
		got.VaryDstPort != want.VaryDstPort || got.Flows != want.Flows ||
		got.FlowOrder != want.FlowOrder || got.PacketSize != want.PacketSize ||
		got.VLAN != want.VLAN || got.EtherType != want.EtherType ||
		got.PayloadByte != want.PayloadByte || got.Duration != want.Duration ||
		got.PPS != want.PPS || got.BPS != want.BPS || got.Queues != want.Queues ||
		got.RxMode != want.RxMode || got.RxCIDR != want.RxCIDR ||
		got.PCAPFile != want.PCAPFile || got.PCAPTiming != want.PCAPTiming ||
		got.PCAPLoop != want.PCAPLoop {
		t.Errorf("a field was lost in the round trip:\n got %+v\nwant %+v", got, want)
	}
	if len(got.RxPorts) != 2 || got.RxPorts[0] != 53 || got.RxPorts[1] != 5353 {
		t.Errorf("RxPorts = %v, want [53 5353]", got.RxPorts)
	}
}

func TestSummary(t *testing.T) {
	c := sample()
	c.RxMode = config.RxUDPPort
	got := Entry{At: time.Now(), Config: c}.Summary()
	for _, want := range []string{"tcp-syn", "eth1", "192.0.2.10", "vlan 2131", "rx udp-port"} {
		if !strings.Contains(got, want) {
			t.Errorf("Summary = %q, missing %q", got, want)
		}
	}

	// A receive-only run has no rate or destination worth showing.
	rc := config.Default()
	rc.Interface = "eth0"
	rc.Mode = config.ModeReceive
	rc.RxMode = config.RxAll
	if got := (Entry{Config: rc}).Summary(); !strings.Contains(got, "receive") {
		t.Errorf("Summary = %q, should name the mode", got)
	}
}
