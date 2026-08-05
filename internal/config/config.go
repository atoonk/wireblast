// Package config holds Wireblast's single, central configuration model.
//
// One Config is shared by the CLI, the TUI wizard, validation and the runtime
// engine: Cobra flags populate it, the wizard edits it, Validate checks it, and
// the dataplane consumes it. Nothing downstream reinterprets a user's input.
package config

import (
	"errors"
	"fmt"
	"net/netip"
	"time"
)

// Mode is the traffic pattern to generate.
type Mode string

const (
	ModeUDP    Mode = "udp"     // stateless UDP flows
	ModeTCPSYN Mode = "tcp-syn" // stateless TCP SYN flows (no handshake, no state)
	ModeIMIX   Mode = "imix"    // UDP flows using the classic IMIX size distribution
	ModeRaw    Mode = "raw"     // fixed EtherType + payload pattern
	ModePCAP   Mode = "pcap"    // replay an Ethernet PCAP file
	// ModeReceive transmits nothing at all. It turns Wireblast into the other
	// end of a test: point one machine's traffic at it and watch what arrives.
	ModeReceive Mode = "receive"
)

// Modes lists every traffic pattern, in menu order.
var Modes = []Mode{ModeUDP, ModeTCPSYN, ModeIMIX, ModeRaw, ModePCAP, ModeReceive}

// Describe returns a one-line explanation for the wizard and CLI help.
func (m Mode) Describe() string {
	switch m {
	case ModeUDP:
		return "UDP flows: the default; one or many deterministic UDP flows"
	case ModeTCPSYN:
		return "TCP SYN flows: stateless SYN flood; no handshake or connection state"
	case ModeIMIX:
		return "IMIX: mixed frame sizes using the classic 7:4:1 distribution"
	case ModeRaw:
		return "Raw Ethernet: fixed EtherType and payload pattern"
	case ModePCAP:
		return "PCAP replay: replay an Ethernet capture file"
	case ModeReceive:
		return "Receive only: transmit nothing and count what arrives"
	}
	return string(m)
}

// RxMode selects what (if anything) is redirected out of the kernel network
// stack and into Wireblast's AF_XDP sockets. The default is RxNone: transmit
// only, nothing is taken from the kernel.
type RxMode string

const (
	RxNone          RxMode = "none"           // transmit only (default, safe)
	RxGeneratedFlow RxMode = "generated-flow" // likely return traffic for this test
	RxUDPPort       RxMode = "udp-port"       // UDP to specific destination ports
	RxTCPPort       RxMode = "tcp-port"       // TCP to specific destination ports
	RxCIDR          RxMode = "cidr"           // traffic sourced from a CIDR
	// RxKeepManagement takes everything except the traffic that keeps the box
	// reachable: SSH and DNS to and from this host, plus ARP and IPv6 ND. It is
	// the safe way to capture broadly on the interface you are logged in over.
	RxKeepManagement RxMode = "keep-management"
	RxAll            RxMode = "all" // everything, dangerous
)

// RxModes lists every receive mode, in menu order.
var RxModes = []RxMode{RxNone, RxGeneratedFlow, RxUDPPort, RxTCPPort, RxCIDR, RxKeepManagement, RxAll}

// PcapTiming selects how PCAP replay is paced.
type PcapTiming string

const (
	// PcapRate ignores the capture's timestamps and paces with --pps/--bps.
	PcapRate PcapTiming = "rate"
	// PcapOriginal preserves the capture's relative inter-packet gaps.
	PcapOriginal PcapTiming = "original"
)

// FlowOrder selects how flows are walked. Sequential is the required, default
// and fully deterministic behaviour.
type FlowOrder string

const (
	FlowSequential FlowOrder = "sequential"
	FlowRandom     FlowOrder = "random"
)

// Frame-size limits, in total Ethernet frame bytes including the 4-byte FCS.
// See the package docs on PacketSize for exactly what that means.
const (
	// MinPacketSize is the smallest legal Ethernet frame: 60 bytes of
	// header+payload plus the 4-byte FCS the NIC appends.
	MinPacketSize = 64
	// MaxPacketSize is a generous jumbo ceiling. The real limit is the
	// interface MTU and the AF_XDP frame capacity, both checked at preflight
	// where those numbers are known.
	MaxPacketSize = 9018
	// FCSLen is the Ethernet frame check sequence the NIC appends for us. It
	// is part of PacketSize but never written into a UMEM frame.
	FCSLen = 4
	// VLANTagLen is the size of an 802.1Q tag.
	VLANTagLen = 4
	// WireOverhead is the per-frame on-the-wire framing not present in the
	// frame itself: 7-byte preamble + 1-byte start-frame delimiter + 12-byte
	// interframe gap. Wire bytes = PacketSize + WireOverhead.
	WireOverhead = 20
)

// DefaultPPS is the rate the wizard and the CLI start from when the user does
// not ask for one. Deliberately conservative: an accidental run should not
// saturate a link. Unlimited is available but must be requested.
const DefaultPPS = 100_000

// Config is the complete description of a Wireblast run.
//
// Address and MAC fields are kept as strings because that is what a user types
// and what the TUI edits; Validate parses them and reports precise errors, and
// Resolve turns them into the typed values the dataplane uses.
type Config struct {
	// Interface is the NIC to transmit from. AF_XDP binds to the physical
	// device, so this is the parent NIC (e.g. eth0), not a VLAN sub-interface;
	// use VLAN to emit tagged frames.
	Interface string

	Mode Mode

	// Addressing. DstIP accepts a single address or a CIDR.
	SrcIP  string
	DstIP  string
	SrcMAC string
	DstMAC string

	// Ports and flows.
	SrcPort     uint16
	DstPort     uint16
	VaryDstPort bool
	Flows       int
	FlowOrder   FlowOrder

	// PacketSize is the total Ethernet frame size in bytes INCLUDING the
	// 4-byte FCS — the number packet-generator people mean by "64-byte
	// packets". Wireblast writes PacketSize-FCSLen bytes into each frame and
	// the NIC appends the FCS. Ignored in pcap mode, and overridden per packet
	// in imix mode.
	PacketSize int

	// VLAN is an 802.1Q VLAN ID (1-4094), or 0 for untagged. A tag adds 4
	// bytes of header inside PacketSize.
	VLAN int

	// Raw-mode fields.
	EtherType   int // EtherType for ModeRaw
	PayloadByte int // repeating payload byte for ModeRaw

	// Run control.
	Duration time.Duration // 0 means run until stopped
	PPS      uint64        // packets/sec, 0 means unlimited
	BPS      uint64        // on-the-wire bits/sec, 0 means unlimited
	Queues   int           // 0 means all available queues

	// Receive behaviour.
	RxMode  RxMode
	RxPorts []uint16
	RxCIDR  string

	// PCAP replay.
	PCAPFile   string
	PCAPTiming PcapTiming
	PCAPLoop   bool

	// Front-end and confirmation.
	NoTUI bool
	// SkipWizard starts the run immediately and goes straight to the live
	// dashboard, using whatever the flags and remembered settings supply. The
	// wizard is skipped, but the safety confirmations are not.
	SkipWizard    bool
	AssumeYes     bool
	AllowMatchAll bool
}

// Default returns the configuration Wireblast starts from before any flag or
// wizard input is applied.
func Default() Config {
	return Config{
		Mode:        ModeUDP,
		SrcPort:     1024,
		DstPort:     9000,
		Flows:       1,
		FlowOrder:   FlowSequential,
		PacketSize:  64,
		EtherType:   0x88b5, // IEEE 802 local experimental EtherType 1
		PayloadByte: 0x5a,
		Duration:    30 * time.Second,
		PPS:         DefaultPPS,
		RxMode:      RxNone,
		PCAPTiming:  PcapRate,
		PCAPLoop:    true,
	}
}

// RateLimited reports whether any rate limit is in force. When false the run
// transmits as fast as the NIC allows.
func (c *Config) RateLimited() bool { return c.PPS != 0 || c.BPS != 0 }

// UsesIPStack reports whether the mode builds IP packets, i.e. whether the
// IP addressing, port and flow fields are meaningful.
func (c *Config) UsesIPStack() bool {
	return c.Mode == ModeUDP || c.Mode == ModeTCPSYN || c.Mode == ModeIMIX
}

// UsesFlows reports whether the mode walks a flow table.
func (c *Config) UsesFlows() bool { return c.UsesIPStack() }

// Transmits reports whether the run puts any packets on the wire. Only
// ModeReceive does not.
func (c *Config) Transmits() bool { return c.Mode != ModeReceive }

// FrameBytes is the number of bytes Wireblast writes into a UMEM frame for a
// given total frame size, i.e. everything except the FCS the NIC appends.
func FrameBytes(packetSize int) int { return packetSize - FCSLen }

// WireBits is the number of bits a frame of the given total size occupies on
// the wire, including preamble, start-frame delimiter and interframe gap. This
// is the unit --bps is measured in.
func WireBits(packetSize int) uint64 { return uint64(packetSize+WireOverhead) * 8 }

// Validate checks the configuration for syntactic and cross-field errors
// without touching the system. It reports every problem it finds, joined, so a
// form can show them all at once.
//
// It does not check anything that needs the machine (interface existence, MTU,
// privileges, routing); those are preflight's job.
func (c *Config) Validate() error {
	var errs []error
	bad := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	if c.Interface == "" {
		bad("--interface is required (run without --no-tui to pick one from a list)")
	}

	if !validMode(c.Mode) {
		bad("--mode %q is not one of %s", c.Mode, joinModes())
	}
	if c.FlowOrder != FlowSequential && c.FlowOrder != FlowRandom {
		bad("--flow-order %q is not one of sequential, random", c.FlowOrder)
	}

	if c.VLAN != 0 && (c.VLAN < 1 || c.VLAN > 4094) {
		bad("--vlan %d is out of range; use 1-4094, or 0 for untagged", c.VLAN)
	}

	if c.Mode == ModeReceive && c.RxMode == RxNone {
		bad("--mode receive transmits nothing, so with --rx-mode none it would do nothing at " +
			"all. Choose what to receive: --rx-mode generated-flow, udp-port, tcp-port, cidr, " +
			"keep-management or all")
	}

	// PCAP takes its sizes from the capture and IMIX from its own distribution,
	// so --packet-size is not a knob in either mode and is not range-checked.
	if c.Transmits() && c.Mode != ModePCAP && c.Mode != ModeIMIX {
		// The floor is the larger of the Ethernet minimum and what this mode's
		// headers actually need, so one message covers both.
		lo := max(c.minFrame(), c.headerBytes())
		if c.PacketSize < lo || c.PacketSize > MaxPacketSize {
			why := ""
			if c.VLAN != 0 && lo == MinPacketSize+VLANTagLen && c.PacketSize < lo {
				// Worth spelling out: the NIC pads anything shorter, so the
				// frame on the wire would not be the size that was asked for,
				// and every rate Wireblast reported would be short by the
				// difference.
				why = ". The 64-byte Ethernet minimum applies to the untagged " +
					"frame, so a tagged one starts at 68: the NIC pads anything " +
					"smaller, and the reported rates would not match the wire"
			}
			bad("--packet-size %d is out of range for --mode %s%s; use %d-%d "+
				"(total Ethernet frame bytes, including the 4-byte FCS)%s",
				c.PacketSize, c.Mode, vlanNote(c.VLAN), lo, MaxPacketSize, why)
		}
	}

	if c.UsesFlows() {
		if c.Flows < 1 {
			bad("--flows %d is invalid; use 1 or more (1 means a single flow)", c.Flows)
		}
		var src netip.Addr
		if c.SrcIP != "" {
			a, err := parseHostIP(c.SrcIP)
			if err != nil {
				bad("--src-ip %q is not an IP address", c.SrcIP)
			}
			src = a
		}
		if c.DstIP == "" {
			bad("--dst-ip is required for --mode %s (an IPv4 or IPv6 address or CIDR)", c.Mode)
		} else if dst, err := ParseDst(c.DstIP); err != nil {
			bad("--dst-ip %q is not an IP address or CIDR: %v", c.DstIP, err)
		} else if src.IsValid() && src.Is4() != dst.Addr().Is4() {
			bad("--src-ip %s and --dst-ip %s are different address families; "+
				"use the same family for both", c.SrcIP, c.DstIP)
		}
	}

	if c.Mode == ModeRaw && (c.EtherType < 0x0600 || c.EtherType > 0xffff) {
		bad("--ethertype 0x%04x is invalid; use 0x0600-0xffff", c.EtherType)
	}

	// PayloadByte fills the frame body; it is a single byte, so a value outside
	// 0-255 would silently truncate rather than do what was asked.
	if c.PayloadByte < 0 || c.PayloadByte > 255 {
		bad("--payload-byte %d is out of range; use 0-255", c.PayloadByte)
	}

	if c.SrcMAC != "" {
		if _, err := ParseMAC(c.SrcMAC); err != nil {
			bad("--src-mac %q is not a MAC address", c.SrcMAC)
		}
	}
	if c.DstMAC != "" {
		mac, err := ParseMAC(c.DstMAC)
		if err != nil {
			bad("--dst-mac %q is not a MAC address", c.DstMAC)
		} else if isBroadcast(mac) {
			bad("--dst-mac ff:ff:ff:ff:ff:ff floods every port in the broadcast domain; " +
				"give the real next-hop MAC, or let Wireblast resolve it")
		}
	}

	if c.Mode == ModePCAP {
		if c.PCAPFile == "" {
			bad("--pcap is required for --mode pcap (the path to a .pcap or .pcapng file)")
		}
		if c.PCAPTiming != PcapRate && c.PCAPTiming != PcapOriginal {
			bad("--pcap-timing %q is not one of rate, original", c.PCAPTiming)
		}
	}

	if c.Duration < 0 {
		bad("--duration must not be negative (0 means run until stopped)")
	}
	if c.Queues < 0 {
		bad("--queues must not be negative (0 means all available queues)")
	}

	errs = append(errs, c.validateRx()...)
	return errors.Join(errs...)
}

func (c *Config) validateRx() []error {
	var errs []error
	bad := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	switch c.RxMode {
	case RxNone:
	case RxGeneratedFlow:
		if !c.UsesIPStack() {
			bad("--rx-mode generated-flow needs generated IP traffic; it cannot infer a "+
				"return filter for --mode %s. Use --rx-mode udp-port, tcp-port or cidr instead", c.Mode)
		}
		if c.SrcIP == "" {
			bad("--rx-mode generated-flow needs a source IP to match return traffic against; " +
				"set --src-ip or pick an interface address in the wizard")
		}
	case RxUDPPort, RxTCPPort:
		if len(c.RxPorts) == 0 {
			bad("--rx-mode %s needs at least one --rx-port", c.RxMode)
		}
		for _, p := range c.RxPorts {
			if p == 0 {
				bad("--rx-port 0 is not a valid port")
			}
		}
	case RxCIDR:
		if c.RxCIDR == "" {
			bad("--rx-mode cidr needs --rx-cidr")
		} else if p, err := netip.ParsePrefix(c.RxCIDR); err != nil {
			bad("--rx-cidr %q is not a CIDR: %v", c.RxCIDR, err)
		} else if p.Bits() == 0 && !c.AllowMatchAll {
			// A /0 matches every source address, i.e. every packet: the same
			// blast radius as --rx-mode all. Gate it behind the same
			// --allow-match-all flag so --yes cannot quietly strand the box.
			bad("--rx-cidr %s matches every packet on %s, the same as --rx-mode all, taking SSH, "+
				"DNS and everything else with it. Pass --allow-match-all if that is really what "+
				"you want, or narrow the CIDR", c.RxCIDR, c.Interface)
		}
	case RxKeepManagement:
		// Nothing extra to require. It takes everything except the traffic that
		// keeps the box reachable, so it needs no ports or CIDRs, and unlike
		// --rx-mode all it does not need --allow-match-all because it cannot
		// strand you.
	case RxAll:
		if !c.AllowMatchAll {
			bad("--rx-mode all redirects EVERY packet on %s away from the kernel, taking SSH, DNS "+
				"and all other traffic on this interface with it. Pass --allow-match-all if "+
				"that is really what you want, or --rx-mode keep-management to take everything "+
				"except SSH and DNS", c.Interface)
		}
	default:
		bad("--rx-mode %q is not one of %s", c.RxMode, joinRxModes())
	}
	return errs
}

// minFrame is the smallest frame that can go on the wire unpadded.
//
// The 64-byte Ethernet minimum is measured on the untagged frame, so adding an
// 802.1Q tag raises it to 68. Sending less means the NIC pads the frame and the
// size on the wire is not the size that was asked for — measured on ixgbe:
// --packet-size 64 --vlan N leaves as 68 bytes.
func (c *Config) minFrame() int {
	if c.VLAN != 0 {
		return MinPacketSize + VLANTagLen
	}
	return MinPacketSize
}

// headerBytes is the total frame size consumed by this mode's headers alone,
// including the FCS — i.e. the smallest frame that can hold them with a
// zero-length payload. The IP header is 20 bytes for IPv4, 40 for IPv6.
func (c *Config) headerBytes() int {
	l2 := 14
	if c.VLAN != 0 {
		l2 += 4
	}
	switch c.Mode {
	case ModeUDP, ModeIMIX:
		return l2 + c.ipHeaderLen() + 8 + FCSLen
	case ModeTCPSYN:
		return l2 + c.ipHeaderLen() + 20 + FCSLen
	default:
		return l2 + FCSLen
	}
}

// ipHeaderLen is the L3 header size for this run's address family.
func (c *Config) ipHeaderLen() int {
	if c.IsIPv6() {
		return 40
	}
	return 20
}

// IsIPv6 reports whether the run's addressing is IPv6, inferred from the
// destination (or, failing that, the source). Malformed input reads as IPv4,
// which is harmless: the address validation reports the real error separately.
func (c *Config) IsIPv6() bool {
	if p, err := ParseDst(c.DstIP); err == nil {
		return p.Addr().Is6()
	}
	if a, err := ParseHostIP(c.SrcIP); err == nil {
		return a.Is6()
	}
	return false
}

func vlanNote(vlan int) string {
	if vlan == 0 {
		return ""
	}
	return " with a VLAN tag"
}

func validMode(m Mode) bool {
	for _, v := range Modes {
		if v == m {
			return true
		}
	}
	return false
}

func joinModes() string {
	s := ""
	for i, m := range Modes {
		if i > 0 {
			s += ", "
		}
		s += string(m)
	}
	return s
}

func joinRxModes() string {
	s := ""
	for i, m := range RxModes {
		if i > 0 {
			s += ", "
		}
		s += string(m)
	}
	return s
}
