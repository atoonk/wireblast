package dataplane

import (
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/atoonk/wireblast/internal/config"
	"github.com/atoonk/wireblast/internal/discovery"
)

// plan is a helper so tests can call the builder inside an `if` without Go
// mistaking the composite literal for the condition.
func plan(cfg *config.Config, r *discovery.Resolved) (FilterPlan, error) {
	return DefaultFilterBuilder{}.Plan(cfg, r)
}

func resolved() *discovery.Resolved {
	return &discovery.Resolved{
		Link: discovery.Link{
			Name: "eth0", Index: 2, MTU: 1500, Driver: "ixgbe", RxQueues: 8,
			MAC: net.HardwareAddr{0xaa, 0, 0, 0, 0, 1}, Up: true, Carrier: true,
			Addrs: []netip.Prefix{netip.MustParsePrefix("192.0.2.10/24")},
		},
		SrcIP: netip.MustParseAddr("192.0.2.10"),
		Dst:   netip.MustParsePrefix("192.0.2.99/32"),
	}
}

func cfgFor(mut func(*config.Config)) *config.Config {
	c := config.Default()
	c.Interface = "eth0"
	c.DstIP = "192.0.2.99"
	c.SrcIP = "192.0.2.10"
	if mut != nil {
		mut(&c)
	}
	return &c
}

// Transmit-only must install a filter that redirects nothing, so the kernel
// keeps every packet it would have had.
func TestTransmitOnlyRedirectsNothing(t *testing.T) {
	p, err := plan(cfgFor(nil), resolved())
	if err != nil {
		t.Fatal(err)
	}
	if p.Receives() {
		t.Error("transmit-only must not receive")
	}
	if p.Dangerous {
		t.Error("transmit-only is not dangerous")
	}
	if len(p.Matches) != 1 {
		t.Fatalf("want exactly one match (MatchNone), got %d", len(p.Matches))
	}
	for _, want := range []string{"Nothing", "kernel"} {
		if !strings.Contains(p.Redirects, want) {
			t.Errorf("description %q should mention %q", p.Redirects, want)
		}
	}
}

// The generated-flow filter is an IP-pair match and nothing more. Saying so is
// the point: go-afxdp's only built-in AND is source-and-destination CIDR, so
// claiming a 5-tuple match would be a lie.
func TestGeneratedFlowIsHonestAboutItsLimits(t *testing.T) {
	cfg := cfgFor(func(c *config.Config) { c.RxMode = config.RxGeneratedFlow })
	p, err := plan(cfg, resolved())
	if err != nil {
		t.Fatal(err)
	}
	if !p.Receives() {
		t.Fatal("generated-flow must receive")
	}
	// The filter matches the return direction: from our destination, to us.
	for _, want := range []string{"192.0.2.99/32", "192.0.2.10/32"} {
		if !strings.Contains(p.Summary, want) {
			t.Errorf("summary %q should mention %q", p.Summary, want)
		}
	}
	limits := strings.Join(p.Limitations, " ")
	for _, want := range []string{"IP pair only", "not ports", "IPv4 only"} {
		if !strings.Contains(limits, want) {
			t.Errorf("the limitations should say %q; got %q", want, limits)
		}
	}
	if strings.Contains(strings.ToLower(p.Redirects), "port") &&
		!strings.Contains(strings.ToLower(p.Limitations[0]), "port") {
		t.Error("the description must not imply a port match")
	}
}

func TestGeneratedFlowNeedsResolvedAddresses(t *testing.T) {
	cfg := cfgFor(func(c *config.Config) { c.RxMode = config.RxGeneratedFlow })
	if _, err := plan(cfg, nil); err == nil {
		t.Error("generated-flow without resolved addressing should fail")
	}
	r := resolved()
	r.Dst = netip.Prefix{}
	if _, err := plan(cfg, r); err == nil {
		t.Error("generated-flow without a destination should fail")
	}
}

func TestPortFilters(t *testing.T) {
	for _, proto := range []config.RxMode{config.RxUDPPort, config.RxTCPPort} {
		cfg := cfgFor(func(c *config.Config) {
			c.RxMode = proto
			c.RxPorts = []uint16{9000, 9001}
		})
		p, err := plan(cfg, resolved())
		if err != nil {
			t.Fatalf("%s: %v", proto, err)
		}
		if !strings.Contains(p.Summary, "9000,9001") {
			t.Errorf("%s summary = %q, should list the ports", proto, p.Summary)
		}
		// Destination port only — a reply to our source port is not matched,
		// and the UI has to say so.
		limits := strings.Join(p.Limitations, " ")
		if !strings.Contains(limits, "Destination port only") {
			t.Errorf("%s should note it matches destination ports only: %q", proto, limits)
		}
	}

	// Redirecting a port people depend on earns a warning.
	cfg := cfgFor(func(c *config.Config) {
		c.RxMode = config.RxUDPPort
		c.RxPorts = []uint16{53}
	})
	p, _ := plan(cfg, resolved())
	if !strings.Contains(strings.Join(p.Warnings, " "), "DNS") {
		t.Errorf("redirecting UDP/53 should warn about DNS: %v", p.Warnings)
	}

	if _, err := plan(cfgFor(func(c *config.Config) {
		c.RxMode = config.RxUDPPort
	}), resolved()); err == nil {
		t.Error("a port filter with no ports should fail")
	}
}

func TestCIDRFilter(t *testing.T) {
	cfg := cfgFor(func(c *config.Config) {
		c.RxMode = config.RxCIDR
		c.RxCIDR = "10.0.0.0/8"
	})
	p, err := plan(cfg, resolved())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(p.Summary, "10.0.0.0/8") {
		t.Errorf("summary = %q, should name the CIDR", p.Summary)
	}
	if !strings.Contains(p.Redirects, "SOURCE") {
		t.Errorf("the description should say it matches the source address: %q", p.Redirects)
	}
	if !strings.Contains(strings.Join(p.Warnings, " "), "SSH") {
		t.Errorf("a CIDR filter should warn about losing SSH: %v", p.Warnings)
	}
}

// Match-all is gated behind an explicit acknowledgement, and says exactly what
// it will do.
func TestMatchAllIsGatedAndBlunt(t *testing.T) {
	cfg := cfgFor(func(c *config.Config) { c.RxMode = config.RxAll })
	if _, err := plan(cfg, resolved()); err == nil {
		t.Fatal("match-all without --allow-match-all should fail")
	} else if !strings.Contains(err.Error(), "--allow-match-all") {
		t.Errorf("the error should name the flag: %v", err)
	}

	cfg.AllowMatchAll = true
	p, err := plan(cfg, resolved())
	if err != nil {
		t.Fatal(err)
	}
	if !p.Dangerous {
		t.Error("match-all must be marked dangerous")
	}
	for _, want := range []string{"EVERYTHING", "SSH", "DNS", "ARP"} {
		if !strings.Contains(p.Redirects, want) {
			t.Errorf("the description should spell out %q: %q", want, p.Redirects)
		}
	}
	if len(p.Warnings) == 0 {
		t.Error("match-all should carry warnings")
	}
}

func TestUnknownReceiveMode(t *testing.T) {
	cfg := cfgFor(func(c *config.Config) { c.RxMode = "sniff-everything" })
	if _, err := plan(cfg, resolved()); err == nil {
		t.Error("an unknown receive mode should fail")
	}
}

// Every mode that receives must describe, in words, what stops reaching the
// kernel — that is the promise the safety model rests on.
func TestEveryReceivingModeExplainsItself(t *testing.T) {
	modes := []struct {
		mode config.RxMode
		mut  func(*config.Config)
	}{
		{config.RxGeneratedFlow, nil},
		{config.RxUDPPort, func(c *config.Config) { c.RxPorts = []uint16{9000} }},
		{config.RxTCPPort, func(c *config.Config) { c.RxPorts = []uint16{80} }},
		{config.RxCIDR, func(c *config.Config) { c.RxCIDR = "10.0.0.0/8" }},
		{config.RxAll, func(c *config.Config) { c.AllowMatchAll = true }},
	}
	for _, tt := range modes {
		cfg := cfgFor(func(c *config.Config) {
			c.RxMode = tt.mode
			if tt.mut != nil {
				tt.mut(c)
			}
		})
		p, err := plan(cfg, resolved())
		if err != nil {
			t.Fatalf("%s: %v", tt.mode, err)
		}
		if !p.Receives() {
			t.Errorf("%s should count as receiving", tt.mode)
		}
		if len(p.Redirects) < 40 {
			t.Errorf("%s: the description is too terse to be useful: %q", tt.mode, p.Redirects)
		}
		if !strings.Contains(p.Redirects, "kernel") {
			t.Errorf("%s: the description should say what the kernel loses: %q", tt.mode, p.Redirects)
		}
		if len(p.Matches) == 0 {
			t.Errorf("%s: no matches were built", tt.mode)
		}
	}
}
