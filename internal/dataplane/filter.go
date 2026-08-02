// Package dataplane owns everything AF_XDP: opening the fleet, the per-queue
// transmit and receive loops, and the safety checks that run before an XDP
// program is attached to a live interface.
//
// It is the only package that imports go-afxdp. Everything above it —
// configuration, the TUI, the CLI — deals in plain Go types.
package dataplane

import (
	"fmt"
	"strings"

	afxdp "github.com/atoonk/go-afxdp"

	"github.com/atoonk/wireblast/internal/config"
	"github.com/atoonk/wireblast/internal/discovery"
)

// FilterPlan is the XDP filter a run will install, together with a plain
// description of what it takes away from the kernel.
//
// Receiving through AF_XDP means those packets stop reaching the normal
// network stack. That is a big enough deal that Wireblast always states, in
// words, exactly what will be redirected before it attaches anything.
type FilterPlan struct {
	// Matches is what gets handed to afxdp.WithFilter.
	Matches []afxdp.Match

	// Summary is the short form for the dashboard, e.g. "udp/9000".
	Summary string
	// Redirects describes in plain language what leaves the kernel stack.
	Redirects string
	// Limitations are honest notes about what the filter does NOT do, so the
	// UI never claims more precision than the filter really has.
	Limitations []string
	// Warnings are things the user should think about before saying yes.
	Warnings []string
	// Dangerous marks the match-all filter, which needs an extra confirmation
	// on top of any --yes.
	Dangerous bool
}

// FilterBuilder turns a receive mode into an XDP filter.
//
// It is an interface on purpose. go-afxdp's matches currently combine with OR
// and have no way to express "everything except", so a narrow filter is
// sometimes impossible; if the library grows exclusion filters, a new builder
// can be dropped in here without touching the rest of Wireblast.
type FilterBuilder interface {
	Plan(cfg *config.Config, res *discovery.Resolved) (FilterPlan, error)
}

// DefaultFilterBuilder maps Wireblast's receive modes onto the matches
// go-afxdp provides today.
type DefaultFilterBuilder struct{}

// Plan builds the filter for a run.
func (DefaultFilterBuilder) Plan(cfg *config.Config, res *discovery.Resolved) (FilterPlan, error) {
	switch cfg.RxMode {
	case config.RxNone:
		return planNone(cfg), nil
	case config.RxGeneratedFlow:
		return planGeneratedFlow(cfg, res)
	case config.RxUDPPort:
		return planPorts(cfg, "udp")
	case config.RxTCPPort:
		return planPorts(cfg, "tcp")
	case config.RxCIDR:
		return planCIDR(cfg)
	case config.RxAll:
		return planAll(cfg)
	}
	return FilterPlan{}, fmt.Errorf("unknown receive mode %q", cfg.RxMode)
}

func planNone(cfg *config.Config) FilterPlan {
	return FilterPlan{
		Matches:   []afxdp.Match{afxdp.MatchNone()},
		Summary:   "none (transmit only)",
		Redirects: "Nothing. Every packet " + cfg.Interface + " receives continues up the kernel network stack exactly as before.",
	}
}

func planGeneratedFlow(cfg *config.Config, res *discovery.Resolved) (FilterPlan, error) {
	if res == nil || !res.SrcIP.IsValid() || !res.Dst.IsValid() {
		return FilterPlan{}, fmt.Errorf(
			"--rx-mode generated-flow needs the run's source and destination addresses to be resolved first")
	}
	src := netipPrefixString(res.SrcIP)
	dst := res.Dst.String()

	// go-afxdp's only built-in AND is MatchFlow(srcCIDR, dstCIDR), so the
	// narrowest expressible filter for return traffic is the reversed IP pair.
	// Ports are genuinely not part of it, and the UI says so rather than
	// implying a full 5-tuple match.
	return FilterPlan{
		Matches: []afxdp.Match{afxdp.MatchFlow(dst, src)},
		Summary: fmt.Sprintf("src %s & dst %s", dst, src),
		Redirects: fmt.Sprintf(
			"IPv4 packets coming from %s and addressed to %s. Those stop reaching the kernel "+
				"on %s; everything else is untouched.", dst, src, cfg.Interface),
		Limitations: []string{
			"This matches the IP pair only, not ports. go-afxdp can AND a source and " +
				"destination CIDR together, but cannot also require a port, so any protocol " +
				"between those two addresses is redirected, not just this test's traffic.",
			"IPv4 only.",
		},
	}, nil
}

func planPorts(cfg *config.Config, proto string) (FilterPlan, error) {
	if len(cfg.RxPorts) == 0 {
		return FilterPlan{}, fmt.Errorf("--rx-mode %s-port needs at least one --rx-port", proto)
	}
	var m afxdp.Match
	if proto == "udp" {
		m = afxdp.MatchUDPPort(cfg.RxPorts...)
	} else {
		m = afxdp.MatchTCPPort(cfg.RxPorts...)
	}
	list := portList(cfg.RxPorts)
	return FilterPlan{
		Matches: []afxdp.Match{m},
		Summary: proto + "/" + list,
		Redirects: fmt.Sprintf(
			"IPv4 %s packets whose DESTINATION port is %s. Those stop reaching the kernel on %s.",
			strings.ToUpper(proto), list, cfg.Interface),
		Limitations: []string{
			"Destination port only: replies to a port Wireblast chose as its source are not matched.",
			"IPv4 only.",
		},
		Warnings: portWarnings(cfg.RxPorts, proto),
	}, nil
}

func planCIDR(cfg *config.Config) (FilterPlan, error) {
	if cfg.RxCIDR == "" {
		return FilterPlan{}, fmt.Errorf("--rx-mode cidr needs --rx-cidr")
	}
	return FilterPlan{
		Matches: []afxdp.Match{afxdp.MatchSrcIP(cfg.RxCIDR)},
		Summary: "src " + cfg.RxCIDR,
		Redirects: fmt.Sprintf(
			"Every packet with a SOURCE address inside %s, whatever the protocol or port. "+
				"Those stop reaching the kernel on %s.", cfg.RxCIDR, cfg.Interface),
		Limitations: []string{
			"Source address only. Traffic Wireblast sends toward that range is unaffected; " +
				"traffic coming back from it is redirected in full.",
		},
		Warnings: []string{
			"If your SSH client or DNS resolver is inside " + cfg.RxCIDR +
				" and reachable over " + cfg.Interface + ", you will lose it.",
		},
	}, nil
}

func planAll(cfg *config.Config) (FilterPlan, error) {
	if !cfg.AllowMatchAll {
		return FilterPlan{}, fmt.Errorf(
			"--rx-mode all requires --allow-match-all: it redirects EVERY packet on %s away "+
				"from the kernel", cfg.Interface)
	}
	return FilterPlan{
		Matches:   []afxdp.Match{afxdp.MatchAll()},
		Summary:   "all",
		Dangerous: true,
		Redirects: fmt.Sprintf(
			"EVERYTHING. Every single packet %s receives is taken by Wireblast and never "+
				"reaches the kernel: SSH, DNS, ARP, the lot.", cfg.Interface),
		Warnings: []string{
			"If you are logged in over " + cfg.Interface + ", this session will freeze the " +
				"moment the program attaches, and stay frozen until the run ends.",
			"ARP replies are redirected too, so the host will lose its neighbour entries on " +
				"this interface.",
		},
	}, nil
}

// portWarnings flags ports whose redirection would break something the user
// probably depends on.
func portWarnings(ports []uint16, proto string) []string {
	var out []string
	known := map[uint16]string{
		22: "SSH", 53: "DNS", 123: "NTP", 179: "BGP", 443: "HTTPS", 67: "DHCP", 68: "DHCP",
	}
	for _, p := range ports {
		if name, ok := known[p]; ok {
			out = append(out, fmt.Sprintf(
				"%s port %d is %s: redirecting it takes %s traffic away from the kernel on this interface.",
				strings.ToUpper(proto), p, name, name))
		}
	}
	return out
}

func portList(ports []uint16) string {
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = fmt.Sprint(p)
	}
	return strings.Join(parts, ",")
}

// netipPrefixString renders a single address as a host prefix, which is the
// form go-afxdp's CIDR matchers expect.
func netipPrefixString(a interface{ String() string }) string {
	return a.String() + "/32"
}

// Receives reports whether a plan takes any traffic from the kernel at all.
func (p FilterPlan) Receives() bool {
	return p.Summary != "" && !strings.HasPrefix(p.Summary, "none")
}
