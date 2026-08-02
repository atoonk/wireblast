package dataplane

import (
	"fmt"
	"net/netip"
	"os"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/atoonk/wireblast/internal/config"
	"github.com/atoonk/wireblast/internal/discovery"
)

// Level is how serious a preflight finding is.
type Level int

const (
	// LevelInfo is worth knowing but needs no decision.
	LevelInfo Level = iota
	// LevelWarn is something the user should see before starting.
	LevelWarn
	// LevelDanger could cut the user off from the machine. It requires an
	// explicit confirmation that --yes does not provide.
	LevelDanger
	// LevelFatal cannot be continued past.
	LevelFatal
)

func (l Level) String() string {
	switch l {
	case LevelInfo:
		return "info"
	case LevelWarn:
		return "warning"
	case LevelDanger:
		return "DANGER"
	case LevelFatal:
		return "error"
	}
	return "unknown"
}

// Check is one preflight finding.
type Check struct {
	Level  Level
	Title  string
	Detail string
	// Fix is a command the user could run. Wireblast only ever suggests these:
	// it never reconfigures the host itself.
	Fix string
}

// Preflight is the result of every check run before an XDP program is
// attached.
type Preflight struct {
	Checks []Check
}

// Fatal returns the checks that make the run impossible.
func (p *Preflight) Fatal() []Check { return p.at(LevelFatal) }

// Dangerous returns the checks that need an explicit confirmation.
func (p *Preflight) Dangerous() []Check { return p.at(LevelDanger) }

// Warnings returns the advisory checks.
func (p *Preflight) Warnings() []Check { return p.at(LevelWarn) }

func (p *Preflight) at(l Level) []Check {
	var out []Check
	for _, c := range p.Checks {
		if c.Level == l {
			out = append(out, c)
		}
	}
	return out
}

// OK reports whether the run may proceed at all.
func (p *Preflight) OK() bool { return len(p.Fatal()) == 0 }

// NeedsConfirmation reports whether a human has to say yes before starting,
// regardless of --yes.
func (p *Preflight) NeedsConfirmation() bool { return len(p.Dangerous()) > 0 }

// Err renders the fatal checks as a single error, or nil when there are none.
func (p *Preflight) Err() error {
	fatal := p.Fatal()
	if len(fatal) == 0 {
		return nil
	}
	var b strings.Builder
	for i, c := range fatal {
		if i > 0 {
			b.WriteString("\n")
		}
		b.WriteString(c.Title)
		if c.Detail != "" {
			b.WriteString(": " + c.Detail)
		}
		if c.Fix != "" {
			b.WriteString("\n  " + c.Fix)
		}
	}
	return fmt.Errorf("%s", b.String())
}

// Environment is the host state preflight inspects, injected so the checks can
// be unit-tested without root, a real NIC or a real SSH session.
type Environment struct {
	// Euid is the effective user ID; 0 means root.
	Euid int
	// HasNetRaw reports whether the process holds CAP_NET_RAW.
	HasNetRaw bool
	// MemlockCur and MemlockMax are the RLIMIT_MEMLOCK soft and hard limits in
	// bytes. MemlockUnlimited short-circuits both.
	MemlockCur       uint64
	MemlockMax       uint64
	MemlockUnlimited bool
	// SSHConnection is the value of $SSH_CONNECTION, if any.
	SSHConnection string
	// DefaultRouteLink is the interface index owning the default route.
	DefaultRouteLink int
	HasDefaultRoute  bool
}

// HostEnvironment reads the real environment.
func HostEnvironment(src discovery.Source) Environment {
	env := Environment{
		Euid:          os.Geteuid(),
		HasNetRaw:     hasCapNetRaw(),
		SSHConnection: os.Getenv("SSH_CONNECTION"),
	}
	var rl unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &rl); err == nil {
		env.MemlockCur, env.MemlockMax = rl.Cur, rl.Max
		env.MemlockUnlimited = rl.Cur == unix.RLIM_INFINITY
	}
	env.DefaultRouteLink, env.HasDefaultRoute = discovery.DefaultRouteLink(src)
	return env
}

// hasCapNetRaw reports whether the process has CAP_NET_RAW in its effective
// set. AF_XDP needs it (or root) to create sockets and load the XDP program.
func hasCapNetRaw() bool {
	const capNetRaw = 13
	var hdr unix.CapUserHeader
	var data [2]unix.CapUserData
	hdr.Version = unix.LINUX_CAPABILITY_VERSION_3
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return false
	}
	return data[0].Effective&(1<<capNetRaw) != 0
}

// MemoryNeeded estimates the locked memory a run will need: one UMEM per
// queue, plus slack for the rings and BPF maps.
func MemoryNeeded(queues, numFrames, frameSize int) uint64 {
	umem := uint64(queues) * uint64(numFrames) * uint64(frameSize)
	// The four rings per socket and the BPF maps are small next to the UMEM,
	// but the kernel accounts for them too; 25% plus 16 MiB is comfortable.
	return umem + umem/4 + 16<<20
}

// RaiseMemlock tries to lift this process's RLIMIT_MEMLOCK soft limit to the
// hard limit. That is a change to Wireblast's own process, not to the host, so
// it is done automatically; anything beyond it is the user's call.
func RaiseMemlock() (uint64, error) {
	var rl unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &rl); err != nil {
		return 0, err
	}
	if rl.Cur == rl.Max {
		return rl.Cur, nil
	}
	raised := unix.Rlimit{Cur: rl.Max, Max: rl.Max}
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &raised); err != nil {
		return rl.Cur, err
	}
	return rl.Max, nil
}

// PreflightInput is everything the checks need to make their decisions.
type PreflightInput struct {
	Cfg    *config.Config
	Res    *discovery.Resolved
	Plan   FilterPlan
	Env    Environment
	Queues int
	// MaxFrameLen is the largest frame the generator will emit, in bytes
	// written (excluding the FCS).
	MaxFrameLen int
	NumFrames   int
	FrameSize   int
	// AllLinks is every interface on the host, used to place the SSH session.
	AllLinks []discovery.Link
}

// RunPreflight performs every check that must happen before an XDP program
// touches the interface.
//
// It reads and reports; it never changes the host. Where a change would help,
// it prints the command for the user to run.
func RunPreflight(in PreflightInput) *Preflight {
	p := &Preflight{}
	add := func(l Level, title, detail, fix string) {
		p.Checks = append(p.Checks, Check{Level: l, Title: title, Detail: detail, Fix: fix})
	}

	// Privileges.
	if in.Env.Euid != 0 && !in.Env.HasNetRaw {
		add(LevelFatal, "insufficient privileges",
			"AF_XDP needs to create raw sockets and load an XDP program, which requires "+
				"root or CAP_NET_RAW.",
			"Run with sudo, or grant the capability:\n"+
				"  sudo setcap cap_net_raw,cap_bpf,cap_sys_resource+ep $(command -v wireblast)")
	}

	// Locked memory. The UMEM is locked pages, and the default 8 MiB limit on
	// many distributions is nowhere near enough for a multi-queue run.
	if !in.Env.MemlockUnlimited {
		need := MemoryNeeded(in.Queues, in.NumFrames, in.FrameSize)
		if in.Env.MemlockCur < need {
			detail := fmt.Sprintf(
				"this run needs about %s of locked memory (%d queues x %d frames x %d bytes), "+
					"but the limit is %s.",
				humanBytes(need), in.Queues, in.NumFrames, in.FrameSize, humanBytes(in.Env.MemlockCur))
			fix := fmt.Sprintf("Raise it for this shell:\n  ulimit -l %d\n"+
				"or permanently in /etc/security/limits.conf:\n"+
				"  * hard memlock unlimited\n  * soft memlock unlimited\n"+
				"Alternatively use fewer queues (--queues %d).",
				need/1024, maxQueuesFor(in.Env.MemlockCur, in.NumFrames, in.FrameSize))
			add(LevelFatal, "locked-memory limit too low", detail, fix)
		}
	}

	// Frame size against the interface MTU and the UMEM frame capacity.
	if in.MaxFrameLen > in.FrameSize {
		add(LevelFatal, "packets are larger than an AF_XDP frame",
			fmt.Sprintf("the largest packet is %d bytes but each UMEM frame holds %d.",
				in.MaxFrameLen, in.FrameSize),
			"Use a smaller --packet-size, or a capture with smaller packets.")
	}
	// The MTU bounds what may be *sent*. A run that transmits nothing is not
	// constrained by it — it just has to have frames big enough to receive
	// into, which the frame-capacity check above already covers.
	if mtu := in.Res.Link.MTU; mtu > 0 && in.Cfg.Transmits() {
		l2 := 14
		if in.Cfg.VLAN != 0 {
			l2 += 4
		}
		if payload := in.MaxFrameLen - l2; payload > mtu {
			add(LevelFatal, "packets are larger than the interface MTU",
				fmt.Sprintf("%s has an MTU of %d, but the largest packet carries %d bytes above "+
					"the Ethernet header.", in.Res.Link.Name, mtu, payload),
				fmt.Sprintf("Use --packet-size %d or smaller, or raise the MTU yourself with "+
					"`sudo ip link set %s mtu %d`.", mtu+l2+config.FCSLen, in.Res.Link.Name, payload))
		}
	}

	// The default route.
	onDefaultRoute := in.Env.HasDefaultRoute && in.Env.DefaultRouteLink == in.Res.Link.Index
	if onDefaultRoute {
		add(LevelWarn, "this interface owns the default route",
			fmt.Sprintf("%s is how this machine reaches the rest of the world. Saturating it "+
				"will starve the host's own traffic.", in.Res.Link.Name), "")
	}

	// The SSH session.
	if peer, ok := sshPeer(in.Env.SSHConnection); ok {
		if sameLink(in, peer) {
			add(LevelDanger, "your SSH session runs over this interface",
				fmt.Sprintf("$SSH_CONNECTION says you are connected from %s, and that traffic "+
					"uses %s, the interface this run will transmit from. A line-rate run can "+
					"stall your own session.", peer, in.Res.Link.Name), "")
		} else {
			add(LevelInfo, "SSH session is on another interface",
				fmt.Sprintf("your session from %s does not use %s, so it should survive the run.",
					peer, in.Res.Link.Name), "")
		}
	}

	// Native XDP bounces the link on many drivers.
	if in.Res.Link.IsPhysical() {
		add(LevelInfo, "the link may bounce when XDP attaches",
			fmt.Sprintf("attaching native XDP reinitialises the driver's queues, which drops "+
				"carrier on %s (%s) for a few seconds while it renegotiates. Wireblast waits for "+
				"the link before it starts the clock.", in.Res.Link.Name, in.Res.Link.Driver), "")
	}

	// Unlimited rate on an interface that matters.
	if !in.Cfg.RateLimited() && onDefaultRoute {
		add(LevelDanger, "unlimited rate on the default-route interface",
			fmt.Sprintf("this run will transmit as fast as %s can, on the interface carrying "+
				"this machine's default route.", in.Res.Link.Name),
			"Set a rate with --pps or --bps, or pick a different interface.")
	}

	// Whatever the receive filter takes from the kernel.
	if in.Plan.Receives() {
		lvl := LevelWarn
		if in.Plan.Dangerous {
			lvl = LevelDanger
		}
		add(lvl, "receive mode takes traffic from the kernel", in.Plan.Redirects, "")
		for _, w := range in.Plan.Warnings {
			add(LevelDanger, "receive filter warning", w, "")
		}
	}
	return p
}

// sshPeer extracts the client address from $SSH_CONNECTION, whose format is
// "<client ip> <client port> <server ip> <server port>".
func sshPeer(v string) (netip.Addr, bool) {
	f := strings.Fields(v)
	if len(f) < 1 {
		return netip.Addr{}, false
	}
	a, err := netip.ParseAddr(f[0])
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

// sshServerAddr extracts the local address of the SSH session.
func sshServerAddr(v string) (netip.Addr, bool) {
	f := strings.Fields(v)
	if len(f) < 3 {
		return netip.Addr{}, false
	}
	a, err := netip.ParseAddr(f[2])
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

// sameLink reports whether the SSH session travels over the interface this run
// will transmit from.
//
// The reliable signal is the session's own local address: whichever interface
// owns it is the one carrying the session. Only when that address cannot be
// placed does it fall back to the default-route heuristic, which is right
// whenever the client is somewhere out on the network.
func sameLink(in PreflightInput, peer netip.Addr) bool {
	if local, ok := sshServerAddr(in.Env.SSHConnection); ok {
		if linkHasAddr(in.Res.Link, local) || linkHasAddr(in.Res.L3Link, local) {
			return true
		}
		for _, l := range in.AllLinks {
			if linkHasAddr(l, local) {
				// The session terminates on a different interface, so this run
				// cannot disturb it.
				return false
			}
		}
	}
	// The local address told us nothing. If the client is off-link and this
	// interface is how the machine reaches everything, the session goes
	// through it.
	if in.Env.HasDefaultRoute && in.Env.DefaultRouteLink == in.Res.Link.Index {
		for _, p := range in.Res.Link.Addrs {
			if p.Contains(peer) {
				return true // the client is on this very subnet
			}
		}
		return true
	}
	return false
}

func linkHasAddr(l discovery.Link, a netip.Addr) bool {
	for _, p := range l.Addrs {
		if p.Addr() == a {
			return true
		}
	}
	return false
}

// maxQueuesFor is how many queues would fit inside a locked-memory limit,
// always at least 1 so the suggestion is runnable.
func maxQueuesFor(limit uint64, numFrames, frameSize int) int {
	per := uint64(numFrames) * uint64(frameSize)
	if per == 0 {
		return 1
	}
	// Leave the same slack MemoryNeeded assumes.
	usable := limit
	if usable > 16<<20 {
		usable -= 16 << 20
	} else {
		return 1
	}
	n := int(usable * 4 / 5 / per)
	return max(n, 1)
}

func humanBytes(v uint64) string {
	switch {
	case v >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(v)/(1<<30))
	case v >= 1<<20:
		return fmt.Sprintf("%.0f MiB", float64(v)/(1<<20))
	case v >= 1<<10:
		return fmt.Sprintf("%.0f KiB", float64(v)/(1<<10))
	}
	return fmt.Sprintf("%d B", v)
}
