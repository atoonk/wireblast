package dataplane

import (
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/atoonk/wireblast/internal/config"
	"github.com/atoonk/wireblast/internal/discovery"
)

func resolved6() *discovery.Resolved {
	return &discovery.Resolved{
		Link: discovery.Link{
			Name: "eth0", Index: 2, MTU: 1500, Driver: "mlx5", RxQueues: 8,
			MAC: net.HardwareAddr{0xaa, 0, 0, 0, 0, 1}, Up: true, Carrier: true,
			Addrs: []netip.Prefix{netip.MustParsePrefix("2001:db8::10/64")},
		},
		SrcIP: netip.MustParseAddr("2001:db8::10"),
		Dst:   netip.MustParsePrefix("2001:db8::99/128"),
	}
}

// generated-flow works for IPv6 (the address matchers are family-aware); the
// host filters must be /128, and the description must not claim IPv4.
func TestGeneratedFlowIPv6(t *testing.T) {
	cfg := cfgFor(func(c *config.Config) {
		c.SrcIP, c.DstIP, c.RxMode = "2001:db8::10", "2001:db8::99", config.RxGeneratedFlow
	})
	p, err := plan(cfg, resolved6())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(p.Summary, "/128") {
		t.Errorf("an IPv6 flow filter should use /128 hosts: %q", p.Summary)
	}
	if strings.Contains(p.Redirects, "IPv4") || !strings.Contains(p.Redirects, "IPv6") {
		t.Errorf("the description should say IPv6, not IPv4: %q", p.Redirects)
	}
	limits := strings.Join(p.Limitations, " ")
	if strings.Contains(limits, "IPv4 only") {
		t.Errorf("generated-flow must not claim IPv4-only for an IPv6 run: %q", limits)
	}
}

// Phase A: the port matchers are IPv4-only in go-afxdp, so an IPv6 udp-port /
// tcp-port run must fail with a clear pointer to the modes that do work.
func TestPortModesRejectIPv6(t *testing.T) {
	for _, mode := range []config.RxMode{config.RxUDPPort, config.RxTCPPort} {
		cfg := cfgFor(func(c *config.Config) {
			c.SrcIP, c.DstIP = "2001:db8::10", "2001:db8::99"
			c.RxMode, c.RxPorts = mode, []uint16{9000}
		})
		_, err := plan(cfg, resolved6())
		if err == nil {
			t.Errorf("%s should be rejected for an IPv6 run", mode)
			continue
		}
		for _, want := range []string{"IPv6", "cidr", "generated-flow"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%s error should mention %q: %v", mode, want, err)
			}
		}
	}
}
