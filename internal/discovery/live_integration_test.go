//go:build integration

// These tests read the real network configuration of the machine they run on.
// They need no root and change nothing, but their results depend on the host,
// so they are excluded from `go test ./...` and only run with:
//
//	go test -tags integration ./internal/discovery/ -v

package discovery

import (
	"os"
	"strconv"
	"testing"

	"github.com/atoonk/wireblast/internal/config"
)

func TestLiveInterfaces(t *testing.T) {
	s := NewSource()
	links, err := Interfaces(s)
	if err != nil {
		t.Fatal(err)
	}
	if len(links) == 0 {
		t.Fatal("no usable interfaces found on this host")
	}
	defIdx, hasDefault := DefaultRouteLink(s)
	for _, l := range links {
		marker := ""
		if hasDefault && l.Index == defIdx {
			marker = "  [default route]"
		}
		t.Logf("%-10s idx=%-3d mac=%s mtu=%d driver=%-10s queues=%-3d carrier=%v addrs=%v%s",
			l.Name, l.Index, l.MAC, l.MTU, l.Driver, l.RxQueues, l.Carrier, l.Addrs, marker)
	}
}

func TestLiveRoutes(t *testing.T) {
	routes, err := NewSource().Routes()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range routes {
		t.Logf("dst=%-20s gw=%-16s link=%d metric=%d", r.Dst, r.Gateway, r.LinkIndex, r.Priority)
	}
}

// TestLiveResolve exercises the whole resolution path against this host. Point
// it at something real with the environment:
//
//	WB_IFACE=eno2 WB_VLAN=2131 WB_DST=192.168.0.2 go test -tags integration ...
func TestLiveResolve(t *testing.T) {
	iface := os.Getenv("WB_IFACE")
	dst := os.Getenv("WB_DST")
	if iface == "" || dst == "" {
		t.Skip("set WB_IFACE and WB_DST to exercise resolution")
	}
	cfg := config.Default()
	cfg.Interface = iface
	cfg.DstIP = dst
	cfg.SrcIP = os.Getenv("WB_SRC")
	cfg.DstMAC = os.Getenv("WB_DSTMAC")
	if v := os.Getenv("WB_VLAN"); v != "" {
		vlan, err := strconv.Atoi(v)
		if err != nil {
			t.Fatalf("bad WB_VLAN %q: %v", v, err)
		}
		cfg.VLAN = vlan
	}

	r, err := Resolve(NewSource(), &cfg, Options{})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	t.Logf("bind %s (L3 %s)", r.Link.Name, r.L3Link.Name)
	t.Logf("src %s / %s", r.SrcIP, r.SrcMAC)
	t.Logf("dst %s via %s -> %s (%s, on-link=%v)", r.Dst, r.NextHop, r.DstMAC, r.MACSource, r.OnLink)
	for _, n := range r.Notes {
		t.Logf("note: %s", n)
	}
}
