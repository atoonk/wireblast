package dataplane

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/atoonk/wireblast/internal/config"
	"github.com/atoonk/wireblast/internal/discovery"
)

// rootEnv is a permissive environment: root, plenty of locked memory, no SSH.
func rootEnv() Environment {
	return Environment{
		Euid:             0,
		HasNetRaw:        true,
		MemlockCur:       1 << 30,
		MemlockMax:       1 << 30,
		DefaultRouteLink: 99, // some other interface
		HasDefaultRoute:  true,
	}
}

func input(mut func(*PreflightInput)) PreflightInput {
	in := PreflightInput{
		Cfg:         cfgFor(nil),
		Res:         resolved(),
		Env:         rootEnv(),
		Queues:      8,
		MaxFrameLen: 60,
		NumFrames:   4096,
		FrameSize:   2048,
	}
	in.Plan, _ = plan(in.Cfg, in.Res)
	if mut != nil {
		mut(&in)
	}
	return in
}

// find returns the first check whose title contains substr.
func find(p *Preflight, substr string) *Check {
	for i := range p.Checks {
		if strings.Contains(p.Checks[i].Title, substr) {
			return &p.Checks[i]
		}
	}
	return nil
}

func TestCleanRunHasNothingBlocking(t *testing.T) {
	p := RunPreflight(input(nil))
	if !p.OK() {
		t.Fatalf("a plain transmit-only run should be allowed: %v", p.Err())
	}
	if p.NeedsConfirmation() {
		t.Errorf("nothing here needs confirming: %v", p.Dangerous())
	}
	if p.Err() != nil {
		t.Errorf("Err = %v, want nil", p.Err())
	}
}

func TestPrivilegesAreRequired(t *testing.T) {
	p := RunPreflight(input(func(in *PreflightInput) {
		in.Env.Euid = 1000
		in.Env.HasNetRaw = false
	}))
	if p.OK() {
		t.Fatal("an unprivileged run must be refused")
	}
	c := find(p, "privileges")
	if c == nil {
		t.Fatal("no privileges check was reported")
	}
	for _, want := range []string{"CAP_NET_RAW", "sudo", "setcap"} {
		if !strings.Contains(c.Detail+c.Fix, want) {
			t.Errorf("the privileges message should mention %q:\n%s\n%s", want, c.Detail, c.Fix)
		}
	}

	// CAP_NET_RAW alone is enough; root is not required.
	p = RunPreflight(input(func(in *PreflightInput) {
		in.Env.Euid = 1000
		in.Env.HasNetRaw = true
	}))
	if !p.OK() {
		t.Errorf("CAP_NET_RAW should be sufficient: %v", p.Err())
	}
}

// The default 8 MiB memlock limit on many distributions is nowhere near enough
// for a multi-queue UMEM, and the error has to say how to fix it.
func TestMemlockLimit(t *testing.T) {
	p := RunPreflight(input(func(in *PreflightInput) {
		in.Env.MemlockCur = 8 << 20 // the common default
		in.Queues = 12
	}))
	if p.OK() {
		t.Fatal("8 MiB of locked memory is not enough for 12 queues")
	}
	c := find(p, "locked-memory")
	if c == nil {
		t.Fatal("no memlock check was reported")
	}
	for _, want := range []string{"ulimit -l", "limits.conf", "--queues"} {
		if !strings.Contains(c.Fix, want) {
			t.Errorf("the fix should mention %q:\n%s", want, c.Fix)
		}
	}
	if !strings.Contains(c.Detail, "12 queues") {
		t.Errorf("the detail should show the arithmetic: %s", c.Detail)
	}

	// An unlimited limit is never a problem.
	p = RunPreflight(input(func(in *PreflightInput) {
		in.Env.MemlockCur = 0
		in.Env.MemlockUnlimited = true
		in.Queues = 12
	}))
	if find(p, "locked-memory") != nil {
		t.Error("unlimited memlock should raise nothing")
	}
}

func TestMemoryNeededScalesWithQueues(t *testing.T) {
	one := MemoryNeeded(1, 4096, 2048)
	twelve := MemoryNeeded(12, 4096, 2048)
	if twelve <= one {
		t.Error("more queues must need more memory — the UMEM is per socket")
	}
	// Each queue is 8 MiB of UMEM, so twelve is at least 96 MiB.
	if twelve < 96<<20 {
		t.Errorf("12 queues x 8 MiB should need at least 96 MiB, got %d", twelve)
	}
}

func TestFrameSizeAndMTUChecks(t *testing.T) {
	// A packet larger than a UMEM frame cannot be transmitted at all.
	p := RunPreflight(input(func(in *PreflightInput) {
		in.MaxFrameLen = 4000
		in.FrameSize = 2048
	}))
	if p.OK() {
		t.Fatal("a packet larger than the UMEM frame must be refused")
	}
	if find(p, "larger than an AF_XDP frame") == nil {
		t.Error("the frame-capacity check did not fire")
	}

	// A packet larger than the MTU is refused, with the interface's own number
	// in the message.
	p = RunPreflight(input(func(in *PreflightInput) {
		in.MaxFrameLen = 1600 // 1586 bytes above the Ethernet header
		in.FrameSize = 2048
	}))
	if p.OK() {
		t.Fatal("a packet larger than the MTU must be refused")
	}
	c := find(p, "MTU")
	if c == nil {
		t.Fatal("the MTU check did not fire")
	}
	if !strings.Contains(c.Detail, "1500") {
		t.Errorf("the message should quote the interface's MTU: %s", c.Detail)
	}
	// Wireblast suggests the command but never runs it.
	if !strings.Contains(c.Fix, "ip link set") {
		t.Errorf("the fix should suggest the command: %s", c.Fix)
	}

	// The MTU bounds what rides above the Ethernet header, and an 802.1Q tag
	// is part of that header — a tagged frame carrying a full 1500-byte
	// payload is 1518 bytes written (1522 on the wire) and is perfectly legal.
	p = RunPreflight(input(func(in *PreflightInput) {
		in.Cfg = cfgFor(func(c *config.Config) { c.VLAN = 100 })
		in.MaxFrameLen = 1518
		in.FrameSize = 2048
	}))
	if !p.OK() {
		t.Errorf("a tagged frame at exactly the MTU should be allowed: %v", p.Err())
	}
	// One byte more genuinely does exceed it.
	p = RunPreflight(input(func(in *PreflightInput) {
		in.Cfg = cfgFor(func(c *config.Config) { c.VLAN = 100 })
		in.MaxFrameLen = 1519
		in.FrameSize = 2048
	}))
	if p.OK() {
		t.Error("a tagged frame one byte over the MTU should be refused")
	}
	// ...and untagged, the equivalent limit is four bytes lower.
	p = RunPreflight(input(func(in *PreflightInput) {
		in.MaxFrameLen = 1515
		in.FrameSize = 2048
	}))
	if p.OK() {
		t.Error("an untagged frame one byte over the MTU should be refused")
	}
}

func TestDefaultRouteWarning(t *testing.T) {
	p := RunPreflight(input(func(in *PreflightInput) {
		in.Env.DefaultRouteLink = in.Res.Link.Index
	}))
	if !p.OK() {
		t.Fatal("owning the default route is a warning, not a refusal")
	}
	c := find(p, "default route")
	if c == nil {
		t.Fatal("no default-route warning")
	}
	if c.Level != LevelWarn {
		t.Errorf("level = %v, want a warning", c.Level)
	}
}

// Blasting at line rate out of the interface the machine reaches the world
// through needs a human to say yes.
func TestUnlimitedRateOnDefaultRouteIsDangerous(t *testing.T) {
	p := RunPreflight(input(func(in *PreflightInput) {
		in.Env.DefaultRouteLink = in.Res.Link.Index
		in.Cfg = cfgFor(func(c *config.Config) { c.PPS, c.BPS = 0, 0 })
	}))
	if !p.NeedsConfirmation() {
		t.Fatal("unlimited rate on the default-route interface should need confirmation")
	}
	if find(p, "unlimited rate") == nil {
		t.Error("the unlimited-rate check did not fire")
	}

	// A rate-limited run on the same interface is only a warning.
	p = RunPreflight(input(func(in *PreflightInput) {
		in.Env.DefaultRouteLink = in.Res.Link.Index
	}))
	if find(p, "unlimited rate") != nil {
		t.Error("a rate-limited run should not trigger the unlimited-rate check")
	}
}

// The SSH check is the one that saves people from locking themselves out.
func TestSSHSessionDetection(t *testing.T) {
	t.Run("session on this interface", func(t *testing.T) {
		p := RunPreflight(input(func(in *PreflightInput) {
			// The session terminates on this interface's own address.
			in.Env.SSHConnection = "203.0.113.5 54321 192.0.2.10 22"
		}))
		c := find(p, "SSH session runs over this interface")
		if c == nil {
			t.Fatal("an SSH session on this interface should be flagged")
		}
		if c.Level != LevelDanger {
			t.Errorf("level = %v, want danger", c.Level)
		}
		if !p.NeedsConfirmation() {
			t.Error("it should require confirmation")
		}
	})

	t.Run("session on another interface", func(t *testing.T) {
		other := discovery.Link{
			Name: "eth9", Index: 9,
			Addrs: []netip.Prefix{netip.MustParsePrefix("198.51.100.4/24")},
		}
		p := RunPreflight(input(func(in *PreflightInput) {
			in.Env.SSHConnection = "203.0.113.5 54321 198.51.100.4 22"
			in.AllLinks = []discovery.Link{in.Res.Link, other}
		}))
		if find(p, "SSH session runs over this interface") != nil {
			t.Error("a session on a different interface must not be flagged as dangerous")
		}
		if find(p, "another interface") == nil {
			t.Error("it should still be mentioned, reassuringly")
		}
	})

	t.Run("no ssh session", func(t *testing.T) {
		p := RunPreflight(input(nil))
		if find(p, "SSH") != nil {
			t.Error("no SSH session means no SSH check")
		}
	})

	t.Run("unparseable", func(t *testing.T) {
		p := RunPreflight(input(func(in *PreflightInput) {
			in.Env.SSHConnection = "garbage"
		}))
		if find(p, "SSH") != nil {
			t.Error("an unparseable SSH_CONNECTION should be ignored, not guessed at")
		}
	})
}

// Native XDP bounces the link, and a user watching a dead interface for ten
// seconds deserves to have been told.
func TestLinkBounceIsMentionedForPhysicalNICs(t *testing.T) {
	p := RunPreflight(input(nil))
	c := find(p, "bounce")
	if c == nil {
		t.Fatal("a physical NIC should carry the link-bounce note")
	}
	if c.Level != LevelInfo {
		t.Errorf("level = %v, want info", c.Level)
	}

	// A virtual device has no PHY to renegotiate.
	p = RunPreflight(input(func(in *PreflightInput) {
		in.Res.Link.Driver = ""
	}))
	if find(p, "bounce") != nil {
		t.Error("a virtual device should not warn about a link bounce")
	}
}

func TestReceiveModeSurfacesInPreflight(t *testing.T) {
	in := input(func(in *PreflightInput) {
		in.Cfg = cfgFor(func(c *config.Config) {
			c.RxMode = config.RxAll
			c.AllowMatchAll = true
		})
	})
	in.Plan, _ = plan(in.Cfg, in.Res)
	p := RunPreflight(in)

	if !p.NeedsConfirmation() {
		t.Fatal("match-all must require confirmation")
	}
	c := find(p, "receive mode takes traffic")
	if c == nil {
		t.Fatal("the receive mode was not surfaced")
	}
	if c.Level != LevelDanger {
		t.Errorf("match-all should be dangerous, got %v", c.Level)
	}
	if !strings.Contains(c.Detail, "EVERYTHING") {
		t.Errorf("the detail should be the filter's own description: %s", c.Detail)
	}
}

func TestErrCollectsEveryFatalFinding(t *testing.T) {
	p := RunPreflight(input(func(in *PreflightInput) {
		in.Env.Euid = 1000
		in.Env.HasNetRaw = false
		in.Env.MemlockCur = 1 << 20
		in.MaxFrameLen = 9000
		in.FrameSize = 2048
	}))
	err := p.Err()
	if err == nil {
		t.Fatal("want an error")
	}
	for _, want := range []string{"privileges", "locked-memory", "AF_XDP frame"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("Err should mention %q:\n%v", want, err)
		}
	}
}

func TestLevelString(t *testing.T) {
	for lvl, want := range map[Level]string{
		LevelInfo: "info", LevelWarn: "warning", LevelDanger: "DANGER", LevelFatal: "error",
	} {
		if got := lvl.String(); got != want {
			t.Errorf("Level(%d).String() = %q, want %q", lvl, got, want)
		}
	}
}

// A run that transmits nothing cannot exceed the MTU, so the transmit-side
// size checks must not fire on it.
func TestReceiveOnlyIsNotBoundByTheTransmitMTU(t *testing.T) {
	p := RunPreflight(input(func(in *PreflightInput) {
		in.Cfg = cfgFor(func(c *config.Config) {
			c.Mode = config.ModeReceive
			c.RxMode = config.RxAll
			c.AllowMatchAll = true
		})
		// Frames sized to receive a full-MTU packet behind a VLAN tag, which
		// is larger than anything this interface may transmit.
		in.MaxFrameLen = in.Res.Link.MTU + 18
		in.FrameSize = 2048
	}))
	if c := find(p, "MTU"); c != nil {
		t.Errorf("a receive-only run should not be checked against the transmit MTU: %s", c.Detail)
	}
	// It is still checked against what a UMEM frame can hold.
	p = RunPreflight(input(func(in *PreflightInput) {
		in.Cfg = cfgFor(func(c *config.Config) {
			c.Mode = config.ModeReceive
			c.RxMode = config.RxAll
			c.AllowMatchAll = true
		})
		in.MaxFrameLen = 4000
		in.FrameSize = 2048
	}))
	if find(p, "larger than an AF_XDP frame") == nil {
		t.Error("a frame too big for the UMEM should still be caught")
	}
}
