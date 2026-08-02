package discovery

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// netlinkSource is the real [Source], reading from netlink and sysfs.
type netlinkSource struct{}

// NewSource returns a Source backed by the running kernel.
func NewSource() Source { return netlinkSource{} }

func (netlinkSource) Links() ([]Link, error) {
	links, err := netlink.LinkList()
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}
	out := make([]Link, 0, len(links))
	for _, l := range links {
		a := l.Attrs()
		nl := Link{
			Name:     a.Name,
			Index:    a.Index,
			MAC:      a.HardwareAddr,
			MTU:      a.MTU,
			Up:       a.Flags&net.FlagUp != 0,
			Carrier:  a.OperState == netlink.OperUp || a.OperState == netlink.OperUnknown,
			Loopback: a.Flags&net.FlagLoopback != 0,
			Driver:   driverOf(a.Name),
			RxQueues: countRxQueues(a.Name),
		}
		if v, ok := l.(*netlink.Vlan); ok {
			nl.VLANID = v.VlanId
			nl.ParentIndex = a.ParentIndex
		}
		nl.Addrs = addrsOf(l)
		out = append(out, nl)
	}
	return out, nil
}

func addrsOf(l netlink.Link) []netip.Prefix {
	addrs, err := netlink.AddrList(l, netlink.FAMILY_ALL)
	if err != nil {
		return nil
	}
	var out []netip.Prefix
	for _, a := range addrs {
		ip, ok := netip.AddrFromSlice(a.IP)
		if !ok {
			continue
		}
		ip = ip.Unmap()
		// Link-local addresses are never a useful source for generated
		// traffic, and showing them just clutters the interface list.
		if ip.IsLinkLocalUnicast() {
			continue
		}
		ones, _ := a.Mask.Size()
		out = append(out, netip.PrefixFrom(ip, ones))
	}
	return out
}

// driverOf reports the kernel driver bound to an interface, or "" for virtual
// devices that have none.
func driverOf(name string) string {
	dest, err := os.Readlink(filepath.Join("/sys/class/net", name, "device", "driver"))
	if err != nil {
		return ""
	}
	return filepath.Base(dest)
}

// countRxQueues counts the receive queues in sysfs — the same source go-afxdp
// uses to decide how many sockets to bind.
func countRxQueues(name string) int {
	entries, err := os.ReadDir(filepath.Join("/sys/class/net", name, "queues"))
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "rx-") {
			n++
		}
	}
	return n
}

func (netlinkSource) Routes() ([]Route, error) {
	rts, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		return nil, fmt.Errorf("list routes: %w", err)
	}
	out := make([]Route, 0, len(rts))
	for _, r := range rts {
		route := Route{LinkIndex: r.LinkIndex, Priority: r.Priority}
		if r.Dst != nil {
			ip, ok := netip.AddrFromSlice(r.Dst.IP)
			if !ok {
				continue
			}
			ones, _ := r.Dst.Mask.Size()
			route.Dst = netip.PrefixFrom(ip.Unmap(), ones).Masked()
		} else {
			// A nil destination is the default route.
			route.Dst = netip.PrefixFrom(netip.IPv4Unspecified(), 0)
		}
		if r.Gw != nil {
			if gw, ok := netip.AddrFromSlice(r.Gw); ok {
				route.Gateway = gw.Unmap()
			}
		}
		if r.Src != nil {
			if src, ok := netip.AddrFromSlice(r.Src); ok {
				route.Src = src.Unmap()
			}
		}
		out = append(out, route)
	}
	return out, nil
}

func (netlinkSource) Neighbors(linkIndex int) ([]Neighbor, error) {
	neighs, err := netlink.NeighList(linkIndex, netlink.FAMILY_V4)
	if err != nil {
		return nil, fmt.Errorf("list neighbours: %w", err)
	}
	out := make([]Neighbor, 0, len(neighs))
	for _, n := range neighs {
		ip, ok := netip.AddrFromSlice(n.IP)
		if !ok {
			continue
		}
		out = append(out, Neighbor{
			IP:        ip.Unmap(),
			MAC:       n.HardwareAddr,
			LinkIndex: n.LinkIndex,
			// Anything but INCOMPLETE, FAILED or NONE has a MAC worth using.
			// STALE in particular is a perfectly good answer: the kernel will
			// revalidate it, and we only need the address.
			Reachable: n.State&(netlink.NUD_REACHABLE|netlink.NUD_STALE|netlink.NUD_PERMANENT|
				netlink.NUD_DELAY|netlink.NUD_PROBE) != 0,
		})
	}
	return out, nil
}

// Probe provokes ARP resolution by sending a single UDP datagram to the
// discard port out of the given interface, then waiting for the kernel's
// neighbour state machine to fill in the answer.
//
// This is a read-only nudge: it adds nothing to the routing table, changes no
// interface configuration, and the datagram itself is discarded by any host
// that receives it.
func (s netlinkSource) Probe(link Link, dst netip.Addr, timeout time.Duration) error {
	if !dst.Is4() {
		return fmt.Errorf("probe: %s is not IPv4", dst)
	}
	d := net.Dialer{
		Timeout: timeout,
		Control: func(_, _ string, c syscall.RawConn) error {
			var serr error
			if err := c.Control(func(fd uintptr) {
				// Pin the datagram to this interface so the probe leaves
				// through the VLAN or NIC the user actually chose, whatever
				// the routing table would otherwise prefer.
				serr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, link.Name)
			}); err != nil {
				return err
			}
			return serr
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Port 9 is discard (RFC 863): a packet sent there is meant to be thrown
	// away, which is exactly what we want from a probe.
	conn, err := d.DialContext(ctx, "udp4", net.JoinHostPort(dst.String(), "9"))
	if err != nil {
		return fmt.Errorf("probe %s on %s: %w", dst, link.Name, err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte{0}); err != nil {
		return fmt.Errorf("probe %s on %s: %w", dst, link.Name, err)
	}

	// Poll the neighbour table rather than sleeping the whole timeout, so a
	// LAN that answers in a millisecond does not cost a second and a half.
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, ok := neighborMAC(s, link.Index, dst); ok {
			return nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	return fmt.Errorf("probe %s on %s: no answer within %s", dst, link.Name, timeout)
}
