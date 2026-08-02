package config

import (
	"strings"
	"testing"
	"time"
)

// valid returns a Config that passes Validate, as a base for negative tests.
func valid() Config {
	c := Default()
	c.Interface = "eth0"
	c.DstIP = "192.0.2.10"
	c.SrcIP = "192.0.2.1"
	return c
}

func TestDefaults(t *testing.T) {
	c := Default()
	if c.Mode != ModeUDP {
		t.Errorf("default mode = %q, want udp", c.Mode)
	}
	if c.Duration != 30*time.Second {
		t.Errorf("default duration = %v, want 30s", c.Duration)
	}
	if c.PPS != DefaultPPS {
		t.Errorf("default pps = %d, want %d (never unlimited by accident)", c.PPS, DefaultPPS)
	}
	if c.BPS != 0 {
		t.Errorf("default bps = %d, want 0 (no bit limit)", c.BPS)
	}
	if c.RxMode != RxNone {
		t.Errorf("default rx-mode = %q, want none — transmit only is the safe default", c.RxMode)
	}
	if c.Flows != 1 {
		t.Errorf("default flows = %d, want 1", c.Flows)
	}
	if c.PacketSize != 64 {
		t.Errorf("default packet-size = %d, want 64", c.PacketSize)
	}
	if c.VLAN != 0 {
		t.Errorf("default vlan = %d, want 0 (disabled)", c.VLAN)
	}
	if c.Queues != 0 {
		t.Errorf("default queues = %d, want 0 (all)", c.Queues)
	}
	if c.FlowOrder != FlowSequential {
		t.Errorf("default flow-order = %q, want sequential", c.FlowOrder)
	}
	v := valid()
	if err := v.Validate(); err != nil {
		t.Fatalf("baseline config should validate: %v", err)
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name string
		mut  func(*Config)
		want string // substring the error must contain; "" means must succeed
	}{
		{"ok", func(c *Config) {}, ""},
		{"no interface", func(c *Config) { c.Interface = "" }, "--interface is required"},
		{"bad mode", func(c *Config) { c.Mode = "quic" }, "--mode \"quic\""},
		{"bad flow order", func(c *Config) { c.FlowOrder = "shuffle" }, "--flow-order"},

		{"vlan low", func(c *Config) { c.VLAN = -1 }, "--vlan -1"},
		{"vlan zero ok", func(c *Config) { c.VLAN = 0 }, ""},
		{"vlan 1 ok", func(c *Config) { c.VLAN, c.PacketSize = 1, 68 }, ""},
		{"vlan 4094 ok", func(c *Config) { c.VLAN, c.PacketSize = 4094, 68 }, ""},
		{"vlan 4095", func(c *Config) { c.VLAN = 4095 }, "--vlan 4095"},

		{"size small", func(c *Config) { c.PacketSize = 63 }, "--packet-size 63"},
		{"size 64 ok", func(c *Config) { c.PacketSize = 64 }, ""},
		{"size huge", func(c *Config) { c.PacketSize = 9019 }, "--packet-size 9019"},
		// A tagged frame starts at 68, not 64: the Ethernet minimum is measured
		// on the untagged frame. Measured on ixgbe, asking for 64 with a tag
		// puts 68 bytes on the wire.
		{"tagged 64 is padded", func(c *Config) {
			c.VLAN, c.PacketSize = 100, 64
		}, "use 68-9018"},
		{"tagged 67 is padded", func(c *Config) {
			c.VLAN, c.PacketSize = 100, 67
		}, "use 68-9018"},
		{"tagged 68 ok", func(c *Config) {
			c.VLAN, c.PacketSize = 100, 68
		}, ""},
		{"tcp+vlan at 68 ok", func(c *Config) {
			c.Mode, c.VLAN, c.PacketSize = ModeTCPSYN, 100, 68
		}, ""},

		{"flows zero", func(c *Config) { c.Flows = 0 }, "--flows 0"},
		{"no dst", func(c *Config) { c.DstIP = "" }, "--dst-ip is required"},
		{"bad dst", func(c *Config) { c.DstIP = "not-an-ip" }, "--dst-ip"},
		{"dst cidr ok", func(c *Config) { c.DstIP = "10.0.0.0/24" }, ""},
		{"ipv6 ok", func(c *Config) {
			c.SrcIP, c.DstIP, c.PacketSize = "2001:db8::1", "2001:db8::2", 66
		}, ""},
		{"ipv6 cidr ok", func(c *Config) {
			c.SrcIP, c.DstIP, c.PacketSize = "2001:db8::1", "2001:db8::/64", 66
		}, ""},
		{"mixed family rejected", func(c *Config) { c.DstIP = "2001:db8::1" }, "different address families"},
		{"ipv6 needs a bigger minimum frame", func(c *Config) {
			c.SrcIP, c.DstIP, c.PacketSize = "2001:db8::1", "2001:db8::2", 64
		}, "use 66-9018"},
		{"bad src", func(c *Config) { c.SrcIP = "300.1.1.1" }, "--src-ip"},

		{"bad src mac", func(c *Config) { c.SrcMAC = "zz:zz" }, "--src-mac"},
		{"bad dst mac", func(c *Config) { c.DstMAC = "1:2:3" }, "--dst-mac"},
		{"dst mac ok", func(c *Config) { c.DstMAC = "aa:bb:cc:dd:ee:ff" }, ""},
		{"broadcast dst mac", func(c *Config) { c.DstMAC = "ff:ff:ff:ff:ff:ff" }, "broadcast domain"},

		{"raw ethertype low", func(c *Config) { c.Mode, c.EtherType = ModeRaw, 0x05ff }, "--ethertype"},
		{"raw ok", func(c *Config) { c.Mode = ModeRaw }, ""},

		{"payload byte high", func(c *Config) { c.PayloadByte = 999 }, "--payload-byte"},
		{"payload byte negative", func(c *Config) { c.PayloadByte = -1 }, "--payload-byte"},
		{"payload byte 255 ok", func(c *Config) { c.PayloadByte = 255 }, ""},

		{"pcap needs file", func(c *Config) { c.Mode = ModePCAP }, "--pcap is required"},
		{"pcap ok", func(c *Config) { c.Mode, c.PCAPFile = ModePCAP, "x.pcap" }, ""},
		{"pcap bad timing", func(c *Config) {
			c.Mode, c.PCAPFile, c.PCAPTiming = ModePCAP, "x.pcap", "asap"
		}, "--pcap-timing"},
		{"pcap ignores packet size", func(c *Config) {
			c.Mode, c.PCAPFile, c.PacketSize = ModePCAP, "x.pcap", 0
		}, ""},
		// IMIX draws its sizes from the distribution, so --packet-size is not a
		// knob and must not be range-checked — not even against the tagged
		// minimum, which used to reject the default 64 under a VLAN tag.
		{"imix ignores packet size", func(c *Config) {
			c.Mode, c.PacketSize = ModeIMIX, 64
		}, ""},
		{"imix with vlan ignores packet size", func(c *Config) {
			c.Mode, c.VLAN, c.PacketSize = ModeIMIX, 2131, 64
		}, ""},

		{"negative duration", func(c *Config) { c.Duration = -time.Second }, "--duration"},
		{"zero duration ok", func(c *Config) { c.Duration = 0 }, ""},
		{"negative queues", func(c *Config) { c.Queues = -1 }, "--queues"},

		{"rx generated-flow ok", func(c *Config) { c.RxMode = RxGeneratedFlow }, ""},
		{"rx generated-flow needs src", func(c *Config) {
			c.RxMode, c.SrcIP = RxGeneratedFlow, ""
		}, "needs a source IP"},
		{"rx generated-flow wrong mode", func(c *Config) {
			c.RxMode, c.Mode, c.PCAPFile = RxGeneratedFlow, ModePCAP, "x.pcap"
		}, "cannot infer a return filter"},
		{"rx udp needs port", func(c *Config) { c.RxMode = RxUDPPort }, "needs at least one --rx-port"},
		{"rx udp ok", func(c *Config) { c.RxMode, c.RxPorts = RxUDPPort, []uint16{53} }, ""},
		{"rx cidr needs cidr", func(c *Config) { c.RxMode = RxCIDR }, "needs --rx-cidr"},
		{"rx cidr bad", func(c *Config) { c.RxMode, c.RxCIDR = RxCIDR, "10.0.0.1" }, "--rx-cidr"},
		{"rx cidr ok", func(c *Config) { c.RxMode, c.RxCIDR = RxCIDR, "10.0.0.0/8" }, ""},
		// A /0 cidr matches every packet, the same blast radius as --rx-mode all,
		// so it is gated by the same --allow-match-all flag rather than only a
		// soft warning that --yes bypasses.
		{"rx cidr /0 guarded", func(c *Config) { c.RxMode, c.RxCIDR = RxCIDR, "0.0.0.0/0" }, "--allow-match-all"},
		{"rx cidr ::/0 guarded", func(c *Config) { c.RxMode, c.RxCIDR = RxCIDR, "::/0" }, "--allow-match-all"},
		{"rx cidr /0 allowed", func(c *Config) { c.RxMode, c.RxCIDR, c.AllowMatchAll = RxCIDR, "0.0.0.0/0", true }, ""},
		{"rx all guarded", func(c *Config) { c.RxMode = RxAll }, "--allow-match-all"},
		{"rx all allowed", func(c *Config) { c.RxMode, c.AllowMatchAll = RxAll, true }, ""},
		// keep-management takes everything except SSH/DNS, so it cannot strand
		// the box and needs no acknowledgement, no ports, no CIDR.
		{"rx keep-management ok", func(c *Config) { c.RxMode = RxKeepManagement }, ""},
		{"rx keep-management needs no guard", func(c *Config) {
			c.RxMode, c.AllowMatchAll = RxKeepManagement, false
		}, ""},
		{"receive with keep-management ok", func(c *Config) {
			c.Mode, c.RxMode = ModeReceive, RxKeepManagement
		}, ""},
		{"rx unknown", func(c *Config) { c.RxMode = "sniff" }, "--rx-mode"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := valid()
			tt.mut(&c)
			err := (&c).Validate()
			switch {
			case tt.want == "" && err != nil:
				t.Fatalf("Validate() = %v, want nil", err)
			case tt.want != "" && err == nil:
				t.Fatalf("Validate() = nil, want an error containing %q", tt.want)
			case tt.want != "" && !strings.Contains(err.Error(), tt.want):
				t.Fatalf("Validate() = %v, want an error containing %q", err, tt.want)
			}
		})
	}
}

// --yes must not be a way around the match-all guard.
func TestAssumeYesDoesNotBypassMatchAll(t *testing.T) {
	c := valid()
	c.RxMode = RxAll
	c.AssumeYes = true
	if err := c.Validate(); err == nil {
		t.Fatal("--yes must not bypass the rx-mode=all guard; --allow-match-all is required")
	}
}

func TestValidateReportsEveryProblem(t *testing.T) {
	c := valid()
	c.Interface = ""
	c.Flows = 0
	c.VLAN = 9999
	err := c.Validate()
	if err == nil {
		t.Fatal("want errors")
	}
	for _, want := range []string{"--interface", "--flows", "--vlan"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing mention of %s", err, want)
		}
	}
}

func TestFrameAndWireBytes(t *testing.T) {
	// packet-size 64 means 64 bytes on the wire including FCS: we write 60.
	if got := FrameBytes(64); got != 60 {
		t.Errorf("FrameBytes(64) = %d, want 60", got)
	}
	// ...and it occupies 84 bytes of wire time (64 + preamble/SFD/IFG).
	if got := WireBits(64); got != 84*8 {
		t.Errorf("WireBits(64) = %d, want %d", got, 84*8)
	}
	if got := WireBits(1518); got != 1538*8 {
		t.Errorf("WireBits(1518) = %d, want %d", got, 1538*8)
	}
}

func TestRateLimitedAndModeHelpers(t *testing.T) {
	c := Default()
	if !c.RateLimited() {
		t.Error("default config must be rate limited")
	}
	c.PPS, c.BPS = 0, 0
	if c.RateLimited() {
		t.Error("pps=0 bps=0 means unlimited")
	}
	c.BPS = 1
	if !c.RateLimited() {
		t.Error("a bps limit alone is still rate limited")
	}

	for _, m := range []Mode{ModeUDP, ModeTCPSYN, ModeIMIX} {
		c.Mode = m
		if !c.UsesIPStack() || !c.UsesFlows() {
			t.Errorf("%s should use the IP stack and flows", m)
		}
	}
	for _, m := range []Mode{ModeRaw, ModePCAP} {
		c.Mode = m
		if c.UsesIPStack() {
			t.Errorf("%s should not use the IP stack", m)
		}
	}
}

// The 64-byte Ethernet minimum is measured on the untagged frame, so a tagged
// one cannot be smaller than 68. Anything less is padded by the NIC, which
// would make every rate Wireblast reports short of what is really on the wire.
//
// Measured on ixgbe against the receiver's kernel counters: --packet-size 64,
// 66 and 68 with a VLAN tag all left the NIC as 68-byte frames.
func TestTaggedFramesStartAt68(t *testing.T) {
	for _, size := range []int{64, 65, 66, 67} {
		c := valid()
		c.VLAN = 2131
		c.PacketSize = size
		err := c.Validate()
		if err == nil {
			t.Errorf("--packet-size %d with a VLAN tag should be refused; the NIC pads it", size)
			continue
		}
		for _, want := range []string{"68", "untagged", "pads"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("size %d: the message should explain %q:\n%v", size, want, err)
			}
		}
	}

	// 68 and up are exactly what they say.
	for _, size := range []int{68, 69, 128, 1522} {
		c := valid()
		c.VLAN = 2131
		c.PacketSize = size
		if err := c.Validate(); err != nil {
			t.Errorf("--packet-size %d with a VLAN tag should be fine: %v", size, err)
		}
	}

	// Untagged, 64 is still the floor.
	c := valid()
	c.PacketSize = 64
	if err := c.Validate(); err != nil {
		t.Errorf("untagged 64 must stay valid: %v", err)
	}
	c.PacketSize = 63
	if err := c.Validate(); err == nil {
		t.Error("untagged 63 should still be refused")
	}
}
