package cli

import (
	"bytes"
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/atoonk/wireblast/internal/config"
)

// parse runs the root command with args and returns the Config that reached
// the run function.
func parse(t *testing.T, args ...string) (*config.Config, error) {
	t.Helper()
	// Point the remembered-settings store at a scratch directory so these
	// tests never see (or disturb) real saved state.
	t.Setenv("WIREBLAST_HOME", t.TempDir())
	var got *config.Config
	cmd := NewRootCommand("test", func(_ context.Context, cfg *config.Config) error {
		got = cfg
		return nil
	})
	cmd.SetArgs(args)
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	err := cmd.Execute()
	return got, err
}

func TestNoFlagsGivesDefaults(t *testing.T) {
	got, err := parse(t)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if want := config.Default(); !reflect.DeepEqual(*got, want) {
		t.Errorf("running with no flags changed the defaults:\n got %+v\nwant %+v", *got, want)
	}
	if got.NoTUI {
		t.Error("no-tui must default to false so a bare `wireblast` opens the wizard")
	}
}

// The spec's worked example must parse into exactly the intended run.
func TestFullNonInteractiveExample(t *testing.T) {
	got, err := parse(t,
		"--interface", "eth1",
		"--mode", "udp",
		"--dst-ip", "192.0.2.10",
		"--dst-port", "9000",
		"--flows", "1000",
		"--packet-size", "64",
		"--pps", "1000000",
		"--duration", "30s",
		"--no-tui",
	)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if got.Interface != "eth1" || got.Mode != config.ModeUDP || got.DstIP != "192.0.2.10" ||
		got.DstPort != 9000 || got.Flows != 1000 || got.PacketSize != 64 ||
		got.PPS != 1_000_000 || got.Duration != 30*time.Second || !got.NoTUI {
		t.Fatalf("parsed config does not match the flags: %+v", *got)
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("a fully specified run must validate: %v", err)
	}
}

func TestRateFlags(t *testing.T) {
	tests := []struct {
		args    []string
		pps     uint64
		bps     uint64
		wantErr bool
	}{
		{[]string{}, config.DefaultPPS, 0, false},
		{[]string{"--pps", "1M"}, 1_000_000, 0, false},
		{[]string{"--pps", "unlimited"}, 0, 0, false},
		{[]string{"--pps", "0"}, 0, 0, false},
		// Asking for a bit rate lifts the default packet cap, or --bps 10G
		// would silently run at the 100 kpps default.
		{[]string{"--bps", "10G"}, 0, 10e9, false},
		{[]string{"--pps", "2M", "--bps", "1G"}, 2_000_000, 1e9, false},
		{[]string{"--pps", "fast"}, 0, 0, true},
		{[]string{"--bps", "?"}, 0, 0, true},
	}
	for _, tt := range tests {
		got, err := parse(t, tt.args...)
		if (err != nil) != tt.wantErr {
			t.Errorf("parse(%v) error = %v, wantErr %v", tt.args, err, tt.wantErr)
			continue
		}
		if err != nil {
			continue
		}
		if got.PPS != tt.pps || got.BPS != tt.bps {
			t.Errorf("parse(%v): pps=%d bps=%d, want pps=%d bps=%d", tt.args, got.PPS, got.BPS, tt.pps, tt.bps)
		}
	}
}

// Unlimited must be reachable from the CLI, and must be an explicit request.
func TestUnlimitedIsExplicit(t *testing.T) {
	got, _ := parse(t)
	if got.PPS == 0 {
		t.Fatal("a run with no --pps must not be unlimited")
	}
	got, _ = parse(t, "--pps", "unlimited")
	if got.RateLimited() {
		t.Fatal("--pps unlimited must clear the packet limit")
	}
	got, _ = parse(t, "--pps", "unlimited", "--bps", "unlimited")
	if got.RateLimited() {
		t.Fatal("both limits unlimited means line rate")
	}
}

func TestRxPortFlag(t *testing.T) {
	got, err := parse(t, "--rx-mode", "udp-port", "--rx-port", "53,5353")
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(got.RxPorts) != 2 || got.RxPorts[0] != 53 || got.RxPorts[1] != 5353 {
		t.Fatalf("--rx-port parsed as %v", got.RxPorts)
	}
	got, err = parse(t, "--rx-port", "80", "--rx-port", "443")
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(got.RxPorts) != 2 {
		t.Fatalf("repeated --rx-port parsed as %v", got.RxPorts)
	}
	if _, err := parse(t, "--rx-port", "nope"); err == nil {
		t.Error("--rx-port nope should fail")
	}
}

func TestEtherTypeFlag(t *testing.T) {
	got, err := parse(t, "--mode", "raw", "--ethertype", "0x0800")
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if got.EtherType != 0x0800 {
		t.Errorf("EtherType = 0x%04x, want 0x0800", got.EtherType)
	}
	if got, _ := parse(t, "--ethertype", "2048"); got.EtherType != 2048 {
		t.Errorf("decimal EtherType = %d, want 2048", got.EtherType)
	}
	if _, err := parse(t, "--ethertype", "0x1ffff"); err == nil {
		t.Error("out-of-range EtherType should fail")
	}
}

func TestEnumsAreCaseInsensitive(t *testing.T) {
	got, err := parse(t, "--mode", "TCP-SYN", "--rx-mode", "None", "--pcap-timing", "ORIGINAL")
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if got.Mode != config.ModeTCPSYN || got.RxMode != config.RxNone || got.PCAPTiming != config.PcapOriginal {
		t.Errorf("enums not normalised: mode=%q rx=%q timing=%q", got.Mode, got.RxMode, got.PCAPTiming)
	}
}

// Passing --pcap without --mode is an obvious intent; honour it.
func TestPcapFileImpliesPcapMode(t *testing.T) {
	got, err := parse(t, "--pcap", "capture.pcap")
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if got.Mode != config.ModePCAP {
		t.Errorf("--pcap alone gave mode %q, want pcap", got.Mode)
	}
	// ...but an explicit --mode always wins.
	got, _ = parse(t, "--pcap", "capture.pcap", "--mode", "udp")
	if got.Mode != config.ModeUDP {
		t.Errorf("explicit --mode udp was overridden, got %q", got.Mode)
	}
}

// Every TUI-editable field must have a flag: guard the list explicitly.
func TestEveryConfigFieldHasAFlag(t *testing.T) {
	cmd := NewRootCommand("test", func(context.Context, *config.Config) error { return nil })
	want := []string{
		"interface", "mode", "src-ip", "dst-ip", "src-mac", "dst-mac",
		"src-port", "dst-port", "vary-dst-port", "flows", "flow-order",
		"packet-size", "vlan", "ethertype", "payload-byte",
		"duration", "pps", "bps", "queues",
		"rx-mode", "rx-port", "rx-cidr",
		"pcap", "pcap-timing", "pcap-loop",
		"no-tui", "start", "yes", "allow-match-all", "forget",
	}
	for _, name := range want {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("missing --%s flag", name)
		}
	}
}

func TestUnknownFlagAndArgsRejected(t *testing.T) {
	if _, err := parse(t, "--nope"); err == nil {
		t.Error("unknown flag should fail")
	}
	if _, err := parse(t, "extra-arg"); err == nil {
		t.Error("positional args should be rejected")
	}
}

// The default packet rate is a guard against accidental line rate. Choosing a
// bit rate is an explicit rate choice, so the guard must step aside — but
// asking for both must honour both.
func TestBPSLiftsTheDefaultPacketCap(t *testing.T) {
	got, _ := parse(t, "--bps", "1G")
	if got.PPS != 0 {
		t.Errorf("--bps alone left pps at %d; it must not cap the requested bit rate", got.PPS)
	}
	if got.BPS != 1e9 {
		t.Errorf("BPS = %d, want 1e9", got.BPS)
	}

	got, _ = parse(t, "--bps", "1G", "--pps", "500k")
	if got.PPS != 500_000 || got.BPS != 1e9 {
		t.Errorf("both limits given: pps=%d bps=%d, want 500000/1e9", got.PPS, got.BPS)
	}
}
