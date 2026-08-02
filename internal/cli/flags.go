// Package cli builds Wireblast's Cobra command and translates flags into the
// central config.Config.
//
// Every field the TUI wizard can edit has a flag here, and every flag lands in
// the same Config the wizard edits — so flags prepopulate the wizard, and
// --no-tui runs the identical configuration through the identical validation.
package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/atoonk/wireblast/internal/config"
	"github.com/atoonk/wireblast/internal/prefs"
)

// RunFunc is the entry point the root command hands the finished configuration
// to. It is injected so the flag layer can be tested without a dataplane.
type RunFunc func(ctx context.Context, cfg *config.Config) error

// options holds the raw string forms of flags that need custom parsing.
type options struct {
	pps      string
	bps      string
	rxPorts  []string
	etherHex string
	forget   bool
}

// NewRootCommand builds the `wireblast` command. Running it with no flags at
// all opens the interactive wizard; --no-tui runs straight from the flags.
func NewRootCommand(version string, run RunFunc) *cobra.Command {
	cfg := config.Default()
	var opt options

	cmd := &cobra.Command{
		Use:   "wireblast",
		Short: "A fast, easy-to-use AF_XDP traffic generator for Linux",
		Long: `Wireblast: the iPerf of packet generators.

Generate line-rate traffic from a Linux box using AF_XDP, without knowing
anything about AF_XDP. Run it with no flags for an interactive wizard, or
specify everything and add --no-tui for scripts.

  sudo wireblast
  sudo wireblast -i eth1 --dst-ip 192.0.2.10 --pps 1M --duration 30s --no-tui

Wireblast transmits only by default: it attaches an XDP program that redirects
nothing, so your SSH session and all other receive traffic keep flowing through
the kernel untouched. Receiving through AF_XDP is opt-in via --rx-mode.

--packet-size is the total Ethernet frame size in bytes INCLUDING the 4-byte
FCS, so --packet-size 64 means the classic 64-byte frame.

Bit rates are reported as L1 and L2, the same two T-Rex reports. L1 is the
frame plus its 20 bytes of preamble, start-frame delimiter and interframe gap,
and is what link utilisation means; L2 is the frame itself. --bps is measured
in L1, so --bps 10G means 10G line rate.`,
		Version:      version,
		SilenceUsage: true,
		// main prints errors itself, with the program's own prefix; without
		// this cobra prints them too and every failure appears twice.
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := applyOptions(cmd, &cfg, &opt); err != nil {
				return err
			}
			return run(cmd.Context(), &cfg)
		},
	}

	f := cmd.Flags()

	f.StringVarP(&cfg.Interface, "interface", "i", cfg.Interface,
		"network interface to transmit from (the physical NIC, not a VLAN sub-interface)")
	f.StringVarP((*string)(&cfg.Mode), "mode", "m", string(cfg.Mode),
		"traffic pattern: "+modeList())

	f.StringVar(&cfg.SrcIP, "src-ip", cfg.SrcIP,
		"source IPv4 address (default: an address of the selected interface)")
	f.StringVar(&cfg.DstIP, "dst-ip", cfg.DstIP,
		"destination IPv4 address or CIDR (a CIDR cycles destinations across flows)")
	f.StringVar(&cfg.SrcMAC, "src-mac", cfg.SrcMAC,
		"source MAC address (default: the selected interface's MAC)")
	f.StringVar(&cfg.DstMAC, "dst-mac", cfg.DstMAC,
		"next-hop MAC address (default: resolved from the neighbour and routing tables)")

	f.Uint16Var(&cfg.SrcPort, "src-port", cfg.SrcPort, "first source port; incremented per flow")
	f.Uint16Var(&cfg.DstPort, "dst-port", cfg.DstPort, "destination port (fixed unless --vary-dst-port)")
	f.BoolVar(&cfg.VaryDstPort, "vary-dst-port", cfg.VaryDstPort,
		"also increment the destination port per flow")
	f.IntVar(&cfg.Flows, "flows", cfg.Flows, "number of distinct flows to generate (1 = a single flow)")
	f.StringVar((*string)(&cfg.FlowOrder), "flow-order", string(cfg.FlowOrder),
		"order flows are walked in: sequential, random")

	f.IntVarP(&cfg.PacketSize, "packet-size", "s", cfg.PacketSize,
		"total Ethernet frame size in bytes, including the 4-byte FCS")
	f.IntVar(&cfg.VLAN, "vlan", cfg.VLAN, "802.1Q VLAN ID to tag frames with (1-4094; 0 = untagged)")
	f.StringVar(&opt.etherHex, "ethertype", "", "EtherType for --mode raw (e.g. 0x88b5)")
	f.IntVar(&cfg.PayloadByte, "payload-byte", cfg.PayloadByte,
		"repeating payload byte value for --mode raw")

	f.DurationVarP(&cfg.Duration, "duration", "d", cfg.Duration,
		"how long to transmit (0 = until stopped)")
	f.StringVar(&opt.pps, "pps", "",
		"packet rate limit, aggregate across queues (e.g. 1M, 500k, or 'unlimited')")
	f.StringVar(&opt.bps, "bps", "",
		"bit rate limit in L1 bits (frame plus preamble, SFD and interframe gap), "+
			"aggregate across queues (e.g. 10G, 2.5Gbps, or 'unlimited')")
	f.IntVar(&cfg.Queues, "queues", cfg.Queues, "number of NIC queues to transmit on (0 = all)")

	f.StringVar((*string)(&cfg.RxMode), "rx-mode", string(cfg.RxMode),
		"what to receive through AF_XDP: "+rxModeList())
	f.StringSliceVar(&opt.rxPorts, "rx-port", nil,
		"destination port(s) for --rx-mode udp-port/tcp-port (repeatable or comma-separated)")
	f.StringVar(&cfg.RxCIDR, "rx-cidr", cfg.RxCIDR, "source CIDR for --rx-mode cidr")

	f.StringVar(&cfg.PCAPFile, "pcap", cfg.PCAPFile, "Ethernet PCAP/PCAPNG file to replay (--mode pcap)")
	f.StringVar((*string)(&cfg.PCAPTiming), "pcap-timing", string(cfg.PCAPTiming),
		"pcap pacing: rate (use --pps/--bps) or original (preserve capture timing)")
	f.BoolVar(&cfg.PCAPLoop, "pcap-loop", cfg.PCAPLoop, "loop the capture until the duration expires")

	f.BoolVar(&cfg.NoTUI, "no-tui", cfg.NoTUI,
		"skip the wizard and dashboard; validate the flags and run, printing periodic statistics")
	f.BoolVar(&cfg.SkipWizard, "start", cfg.SkipWizard,
		"skip the wizard and start straight away, showing the live dashboard")
	f.BoolVarP(&cfg.AssumeYes, "yes", "y", cfg.AssumeYes,
		"skip ordinary confirmation prompts (does not bypass the --rx-mode all guard)")
	f.BoolVar(&cfg.AllowMatchAll, "allow-match-all", cfg.AllowMatchAll,
		"required acknowledgement for --rx-mode all, which takes EVERY packet from the kernel")
	f.BoolVar(&opt.forget, "forget", false,
		"discard the remembered settings from previous runs and start from the defaults")

	cmd.SetVersionTemplate("wireblast {{.Version}}\n")
	return cmd
}

// applyOptions folds the custom-parsed flags into cfg. It only overrides a
// Config field when the user actually set the flag, so defaults survive.
func applyOptions(cmd *cobra.Command, cfg *config.Config, opt *options) error {
	f := cmd.Flags()

	if f.Changed("pps") {
		v, err := config.ParsePPS(opt.pps)
		if err != nil {
			return fmt.Errorf("--pps: %w", err)
		}
		cfg.PPS = v
	}
	if f.Changed("bps") {
		v, err := config.ParseBPS(opt.bps)
		if err != nil {
			return fmt.Errorf("--bps: %w", err)
		}
		cfg.BPS = v
		// The default packet rate is a safety net against starting at line
		// rate by accident. Someone who asked for a bit rate has already made
		// that choice, so the net comes off — otherwise "--bps 1G" would
		// quietly run at the 100 kpps default instead.
		if !f.Changed("pps") {
			cfg.PPS = 0
		}
	}
	if f.Changed("ethertype") {
		v, err := parseEtherType(opt.etherHex)
		if err != nil {
			return fmt.Errorf("--ethertype: %w", err)
		}
		cfg.EtherType = v
	}
	if f.Changed("rx-port") {
		ports, err := config.ParsePorts(strings.Join(opt.rxPorts, ","))
		if err != nil {
			return fmt.Errorf("--rx-port: %w", err)
		}
		cfg.RxPorts = ports
	}

	cfg.Mode = config.Mode(strings.ToLower(strings.TrimSpace(string(cfg.Mode))))
	cfg.RxMode = config.RxMode(strings.ToLower(strings.TrimSpace(string(cfg.RxMode))))
	cfg.PCAPTiming = config.PcapTiming(strings.ToLower(strings.TrimSpace(string(cfg.PCAPTiming))))
	cfg.FlowOrder = config.FlowOrder(strings.ToLower(strings.TrimSpace(string(cfg.FlowOrder))))

	// Choosing --mode pcap without saying --rx-mode implies nothing about
	// receiving, but choosing --pcap without --mode is an easy slip to catch.
	if cfg.PCAPFile != "" && !f.Changed("mode") {
		cfg.Mode = config.ModePCAP
	}

	store := prefs.New()
	if opt.forget {
		_ = store.Forget()
		return nil
	}
	// An interactive session starts from what you ran last time, with anything
	// you typed on the command line laid over the top. --no-tui deliberately
	// does not: a script has to mean exactly what it says.
	if !cfg.NoTUI {
		if saved, ok := store.Last(); ok {
			*cfg = prefs.Merge(*cfg, saved, f.Changed)
		}
	}
	return nil
}

func parseEtherType(s string) (int, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	base := 10
	if strings.HasPrefix(s, "0x") {
		s, base = s[2:], 16
	}
	var v int
	if _, err := fmt.Sscanf(s, map[int]string{10: "%d", 16: "%x"}[base], &v); err != nil {
		return 0, fmt.Errorf("%q is not a number", s)
	}
	if v < 0 || v > 0xffff {
		return 0, fmt.Errorf("0x%x is out of range", v)
	}
	return v, nil
}

func modeList() string {
	parts := make([]string, len(config.Modes))
	for i, m := range config.Modes {
		parts[i] = string(m)
	}
	return strings.Join(parts, ", ")
}

func rxModeList() string {
	parts := make([]string, len(config.RxModes))
	for i, m := range config.RxModes {
		parts[i] = string(m)
	}
	return strings.Join(parts, ", ")
}
