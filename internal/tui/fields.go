package tui

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/atoonk/wireblast/internal/config"
)

// fieldKind decides how a field is edited.
type fieldKind int

const (
	// fieldText is a free-text value edited with a cursor.
	fieldText fieldKind = iota
	// fieldChoice cycles through a fixed set with the left and right arrows,
	// so there is no way to type an invalid enum.
	fieldChoice
)

// field is one editable configuration value.
//
// Each field knows how to read itself out of a Config and write itself back,
// and — importantly — when it is relevant at all. The form only renders fields
// whose show returns true, which is how choosing PCAP replay makes the flow
// and packet-size fields disappear instead of sitting there doing nothing.
type field struct {
	key     string
	label   string
	help    string
	kind    fieldKind
	choices []string

	// show reports whether this field applies to the current configuration.
	// nil means always.
	show func(*config.Config) bool

	get func(*config.Config) string
	set func(*config.Config, string) error
}

func (f field) visible(c *config.Config) bool { return f.show == nil || f.show(c) }

// usesIP is true for the modes that build IP packets.
func usesIP(c *config.Config) bool { return c.UsesIPStack() }

// allFields is the full catalogue, in the order the form presents them:
// addressing first, then the packet shape, then how fast and for how long, and
// finally the receive settings most people never touch.
var allFields = []field{
	{
		key: "src-mac", label: "Source MAC",
		help: "left blank, the interface's own MAC is used",
		show: func(c *config.Config) bool { return c.Transmits() },
		get:  func(c *config.Config) string { return c.SrcMAC },
		set: func(c *config.Config, v string) error {
			if v = strings.TrimSpace(v); v != "" {
				if _, err := config.ParseMAC(v); err != nil {
					return err
				}
			}
			c.SrcMAC = v
			return nil
		},
	},
	{
		key: "src-ip", label: "Source IP",
		help: "left blank, an address of the interface is used",
		show: func(c *config.Config) bool { return usesIP(c) },
		get:  func(c *config.Config) string { return c.SrcIP },
		set: func(c *config.Config, v string) error {
			if v = strings.TrimSpace(v); v != "" {
				if _, err := config.ParseHostIP(v); err != nil {
					return err
				}
			}
			c.SrcIP = v
			return nil
		},
	},
	{
		key: "dst-ip", label: "Destination IP or CIDR",
		help: "a CIDR cycles destinations across flows, e.g. 10.0.0.0/24",
		show: func(c *config.Config) bool { return usesIP(c) },
		get:  func(c *config.Config) string { return c.DstIP },
		set: func(c *config.Config, v string) error {
			if v = strings.TrimSpace(v); v != "" {
				if _, err := config.ParseDst(v); err != nil {
					return err
				}
			}
			c.DstIP = v
			return nil
		},
	},
	{
		key: "dst-mac", label: "Destination MAC",
		help: "left blank, the next hop is resolved from the neighbour and routing tables",
		show: func(c *config.Config) bool { return c.Transmits() },
		get:  func(c *config.Config) string { return c.DstMAC },
		set: func(c *config.Config, v string) error {
			if v = strings.TrimSpace(v); v != "" {
				if _, err := config.ParseMAC(v); err != nil {
					return err
				}
			}
			c.DstMAC = v
			return nil
		},
	},
	{
		key: "src-port", label: "Source port", help: "the first port; it increments per flow",
		show: func(c *config.Config) bool { return usesIP(c) },
		get:  func(c *config.Config) string { return strconv.Itoa(int(c.SrcPort)) },
		set:  func(c *config.Config, v string) error { return setPort(&c.SrcPort, v) },
	},
	{
		key: "dst-port", label: "Destination port", help: "fixed across flows",
		show: func(c *config.Config) bool { return usesIP(c) },
		get:  func(c *config.Config) string { return strconv.Itoa(int(c.DstPort)) },
		set:  func(c *config.Config, v string) error { return setPort(&c.DstPort, v) },
	},
	{
		key: "flows", label: "Flows", help: "1 is a single flow; each flow keeps a stable tuple",
		show: func(c *config.Config) bool { return usesIP(c) },
		get:  func(c *config.Config) string { return strconv.Itoa(c.Flows) },
		set: func(c *config.Config, v string) error {
			n, err := strconv.Atoi(strings.TrimSpace(v))
			if err != nil || n < 1 {
				return fmt.Errorf("must be a whole number of 1 or more")
			}
			c.Flows = n
			return nil
		},
	},
	{
		key: "packet-size", label: "Packet size",
		help: "total Ethernet frame bytes, including the 4-byte FCS",
		show: func(c *config.Config) bool {
			return c.Transmits() && c.Mode != config.ModeIMIX && c.Mode != config.ModePCAP
		},
		get: func(c *config.Config) string { return strconv.Itoa(c.PacketSize) },
		set: func(c *config.Config, v string) error {
			n, err := strconv.Atoi(strings.TrimSpace(v))
			if err != nil {
				return fmt.Errorf("must be a whole number")
			}
			if n < config.MinPacketSize || n > config.MaxPacketSize {
				return fmt.Errorf("must be between %d and %d", config.MinPacketSize, config.MaxPacketSize)
			}
			c.PacketSize = n
			return nil
		},
	},
	{
		key: "ethertype", label: "EtherType", help: "hex, e.g. 0x88b5",
		show: func(c *config.Config) bool { return c.Mode == config.ModeRaw },
		get:  func(c *config.Config) string { return fmt.Sprintf("0x%04x", c.EtherType) },
		set: func(c *config.Config, v string) error {
			n, err := strconv.ParseUint(strings.TrimPrefix(strings.TrimSpace(strings.ToLower(v)), "0x"), 16, 32)
			if err != nil || n < 0x0600 || n > 0xffff {
				return fmt.Errorf("must be hex between 0x0600 and 0xffff")
			}
			c.EtherType = int(n)
			return nil
		},
	},
	{
		key: "pcap", label: "Capture file", help: "an Ethernet .pcap or .pcapng file",
		show: func(c *config.Config) bool { return c.Mode == config.ModePCAP },
		get:  func(c *config.Config) string { return c.PCAPFile },
		set:  func(c *config.Config, v string) error { c.PCAPFile = strings.TrimSpace(v); return nil },
	},
	{
		key: "pcap-timing", label: "Capture timing", kind: fieldChoice,
		choices: []string{string(config.PcapRate), string(config.PcapOriginal)},
		help:    "rate uses the limits below; original preserves the capture's own gaps",
		show:    func(c *config.Config) bool { return c.Mode == config.ModePCAP },
		get:     func(c *config.Config) string { return string(c.PCAPTiming) },
		set:     func(c *config.Config, v string) error { c.PCAPTiming = config.PcapTiming(v); return nil },
	},
	{
		key: "pcap-loop", label: "Loop the capture", kind: fieldChoice,
		choices: []string{"yes", "no"},
		help:    "no replays it once and stops",
		show:    func(c *config.Config) bool { return c.Mode == config.ModePCAP },
		get:     func(c *config.Config) string { return yesNo(c.PCAPLoop) },
		set:     func(c *config.Config, v string) error { c.PCAPLoop = v == "yes"; return nil },
	},
	{
		key: "vlan", label: "VLAN ID", help: "0 sends untagged frames; 1-4094 adds an 802.1Q tag",
		// The tag is something Wireblast writes, so it means nothing to a run
		// that writes nothing. Receive filters see through one tag anyway.
		show: func(c *config.Config) bool { return c.Transmits() },
		get:  func(c *config.Config) string { return strconv.Itoa(c.VLAN) },
		set: func(c *config.Config, v string) error {
			n, err := strconv.Atoi(strings.TrimSpace(v))
			if err != nil || n < 0 || (n != 0 && (n < 1 || n > 4094)) {
				return fmt.Errorf("must be 0 (untagged) or 1-4094")
			}
			c.VLAN = n
			return nil
		},
	},
	{
		key: "pps", label: "Packet rate",
		help: "aggregate across all queues, e.g. 1M or 500k; 'unlimited' for line rate",
		show: func(c *config.Config) bool { return c.Transmits() },
		get:  func(c *config.Config) string { return config.FormatPPS(c.PPS) },
		set: func(c *config.Config, v string) error {
			n, err := config.ParsePPS(v)
			if err != nil {
				return err
			}
			c.PPS = n
			return nil
		},
	},
	{
		key: "bps", label: "Bit rate",
		help: "on-the-wire bits, aggregate, e.g. 10G; 'unlimited' for no bit limit",
		show: func(c *config.Config) bool { return c.Transmits() },
		get:  func(c *config.Config) string { return config.FormatBPS(c.BPS) },
		set: func(c *config.Config, v string) error {
			n, err := config.ParseBPS(v)
			if err != nil {
				return err
			}
			c.BPS = n
			return nil
		},
	},
	{
		key: "duration", label: "Duration", help: "e.g. 30s, 5m; 0 runs until you stop it",
		get: func(c *config.Config) string { return c.Duration.String() },
		set: func(c *config.Config, v string) error {
			d, err := time.ParseDuration(strings.TrimSpace(v))
			if err != nil || d < 0 {
				return fmt.Errorf("must be a duration like 30s or 5m")
			}
			c.Duration = d
			return nil
		},
	},
	{
		key: "queues", label: "Queues", help: "0 uses every queue on the interface",
		get: func(c *config.Config) string { return strconv.Itoa(c.Queues) },
		set: func(c *config.Config, v string) error {
			n, err := strconv.Atoi(strings.TrimSpace(v))
			if err != nil || n < 0 {
				return fmt.Errorf("must be 0 or more")
			}
			c.Queues = n
			return nil
		},
	},
	{
		key: "rx-mode", label: "Receive mode", kind: fieldChoice,
		choices: rxModeChoices(),
		help:    "none transmits only and leaves the kernel's traffic alone; anything else takes packets from it",
		get:     func(c *config.Config) string { return string(c.RxMode) },
		set: func(c *config.Config, v string) error {
			c.RxMode = config.RxMode(v)
			// --allow-match-all is the non-interactive stand-in for a human
			// reading the review screen and typing "yes". In the wizard that
			// screen is always shown, so selecting the mode here grants the
			// acknowledgement and the review screen remains the real gate.
			c.AllowMatchAll = c.RxMode == config.RxAll
			return nil
		},
	},
	{
		key: "rx-port", label: "Receive ports", help: "comma-separated destination ports to capture",
		show: func(c *config.Config) bool { return c.RxMode == config.RxUDPPort || c.RxMode == config.RxTCPPort },
		get:  func(c *config.Config) string { return joinPorts(c.RxPorts) },
		set: func(c *config.Config, v string) error {
			if strings.TrimSpace(v) == "" {
				c.RxPorts = nil
				return nil
			}
			p, err := config.ParsePorts(v)
			if err != nil {
				return err
			}
			c.RxPorts = p
			return nil
		},
	},
	{
		key: "rx-cidr", label: "Receive from CIDR", help: "capture traffic sourced from this range",
		show: func(c *config.Config) bool { return c.RxMode == config.RxCIDR },
		get:  func(c *config.Config) string { return c.RxCIDR },
		set:  func(c *config.Config, v string) error { c.RxCIDR = strings.TrimSpace(v); return nil },
	},
}

// visibleFields is the form for the current configuration.
func visibleFields(c *config.Config) []field {
	out := make([]field, 0, len(allFields))
	for _, f := range allFields {
		if f.visible(c) {
			out = append(out, f)
		}
	}
	return out
}

func setPort(dst *uint16, v string) error {
	n, err := strconv.ParseUint(strings.TrimSpace(v), 10, 16)
	if err != nil {
		return fmt.Errorf("must be a port number, 0-65535")
	}
	*dst = uint16(n)
	return nil
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func joinPorts(ports []uint16) string {
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = strconv.Itoa(int(p))
	}
	return strings.Join(parts, ",")
}

func rxModeChoices() []string {
	out := make([]string, len(config.RxModes))
	for i, m := range config.RxModes {
		out[i] = string(m)
	}
	return out
}

// nextChoice returns the value after cur in choices, wrapping. delta of -1
// steps backwards.
func nextChoice(choices []string, cur string, delta int) string {
	if len(choices) == 0 {
		return cur
	}
	idx := 0
	for i, c := range choices {
		if c == cur {
			idx = i
			break
		}
	}
	idx = (idx + delta + len(choices)) % len(choices)
	return choices[idx]
}
