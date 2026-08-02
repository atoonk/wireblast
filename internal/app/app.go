// Package app wires the pieces together: it takes a validated configuration,
// resolves addressing, runs the safety checks and drives the dataplane.
//
// Both front ends go through here, so a run started from the wizard and one
// started with --no-tui are the same run, validated the same way.
package app

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/atoonk/wireblast/internal/config"
	"github.com/atoonk/wireblast/internal/dataplane"
	"github.com/atoonk/wireblast/internal/discovery"
	"github.com/atoonk/wireblast/internal/generator"
	"github.com/atoonk/wireblast/internal/pcapfile"
	"github.com/atoonk/wireblast/internal/stats"
)

// Prepare turns a configuration into a ready-to-start Runner, doing every step
// that must happen before an XDP program is attached: validation, PCAP
// loading, address and next-hop resolution, and the preflight checks.
//
// It returns the runner, the preflight result and the resolved addressing so a
// front end can show a review screen. Nothing has touched the interface yet.
type Prepared struct {
	Runner    *dataplane.Runner
	Resolved  *discovery.Resolved
	Preflight *dataplane.Preflight
	Plan      dataplane.FilterPlan
	Frames    generator.FrameSource
}

// PrepareOptions tunes preparation.
type PrepareOptions struct {
	// Source overrides system discovery; nil uses the real kernel.
	Source discovery.Source
	// Logf receives dataplane messages during the run.
	Logf func(format string, args ...any)
	// Session keeps the XDP program attached between runs. An interactive
	// session passes one so a rerun does not pay the attach cost again; the
	// one-shot --no-tui path leaves it nil.
	Session *dataplane.Session
}

// Prepare validates and resolves everything a run needs.
func Prepare(cfg *config.Config, opts PrepareOptions) (*Prepared, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	src := opts.Source
	if src == nil {
		src = discovery.NewSource()
	}

	// Read and check the capture before anything else touches the NIC: a
	// broken file should never cost you a link bounce.
	var frames generator.FrameSource
	if cfg.Mode == config.ModePCAP {
		f, err := pcapfile.Load(cfg.PCAPFile)
		if err != nil {
			return nil, err
		}
		frames = f
	}

	res, err := discovery.Resolve(src, cfg, discovery.Options{})
	if err != nil {
		return nil, err
	}

	runner, err := dataplane.New(cfg, res, dataplane.Options{
		Frames: frames, Logf: opts.Logf, Session: opts.Session,
	})
	if err != nil {
		return nil, err
	}
	return &Prepared{
		Runner:    runner,
		Resolved:  res,
		Preflight: runner.Preflight(src),
		Plan:      runner.Plan(),
		Frames:    frames,
	}, nil
}

// RunNonInteractive validates the flags, prints what it is about to do, and
// transmits — printing a statistics line every second and a summary at the
// end. This is the shape scripts and CI use.
func RunNonInteractive(ctx context.Context, cfg *config.Config, out io.Writer) error {
	logf := func(format string, args ...any) {
		fmt.Fprintf(out, "wireblast: "+format+"\n", args...)
	}
	p, err := Prepare(cfg, PrepareOptions{Logf: logf})
	if err != nil {
		return err
	}

	if err := p.Preflight.Err(); err != nil {
		return err
	}
	printPlan(out, cfg, p)

	// Dangerous findings need a human, and --yes deliberately does not cover
	// them. The one exception is the match-all filter, which has its own
	// explicit --allow-match-all gate checked during validation.
	if danger := p.Preflight.Dangerous(); len(danger) > 0 {
		if err := confirmDanger(out, cfg, danger); err != nil {
			return err
		}
	}

	// Attaching native XDP bounces the link, which can take ten seconds on a
	// 10G NIC. Show that something is happening rather than going silent.
	stopWait := progress(out, fmt.Sprintf("attaching XDP to %s and waiting for the link",
		p.Resolved.Link.Name))
	err = p.Runner.Start(ctx)
	stopWait()
	if err != nil {
		return err
	}

	// Only now does Info describe what the kernel actually granted — the XDP
	// attach mode and whether zero-copy was available.
	info := p.Runner.Info()
	if info.LinkWait > 0 {
		fmt.Fprintf(out, "link came back after %.1fs\n", info.LinkWait.Seconds())
	}
	if info.Reused {
		fmt.Fprintln(out, "reused the attached XDP program; no link bounce")
	}
	fmt.Fprintf(out, "started: %s\n", info)
	if cfg.Duration > 0 {
		fmt.Fprintf(out, "running for %s (Ctrl-C to stop early)\n\n", cfg.Duration)
	} else {
		fmt.Fprintf(out, "running until stopped (Ctrl-C)\n\n")
	}

	// Print a status line every second while the run proceeds.
	reportCtx, stopReport := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		report(reportCtx, p.Runner, out)
	}()

	runErr := p.Runner.Wait()
	stopReport()
	<-done

	fmt.Fprintf(out, "\n%s\n", p.Runner.Stats().Summary())
	if runErr != nil && !errors.Is(runErr, context.Canceled) {
		return runErr
	}
	return nil
}

// progress prints a growing line of dots while something slow happens, and
// returns the function that finishes it off. On anything that is not a
// terminal it prints one plain line, so log files do not fill up with dots.
func progress(out io.Writer, what string) func() {
	f, isFile := out.(*os.File)
	if !isFile || !isTerminal(f) {
		fmt.Fprintf(out, "\n%s...\n", what)
		return func() {}
	}

	fmt.Fprintf(out, "\n%s", what)
	done := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		t := time.NewTicker(500 * time.Millisecond)
		defer t.Stop()
		start := time.Now()
		for {
			select {
			case <-done:
				fmt.Fprintf(out, " (%.0fs)\n", time.Since(start).Seconds())
				return
			case <-t.C:
				fmt.Fprint(out, ".")
			}
		}
	}()
	return func() { close(done); <-finished }
}

// report prints one status line a second until the run ends.
func report(ctx context.Context, r *dataplane.Runner, out io.Writer) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s := r.Stats()
			if s.State == stats.StateStarting {
				continue
			}
			fmt.Fprintln(out, s.Line())
		}
	}
}

// printPlan describes the run in plain language before it starts. It is the
// noninteractive equivalent of the wizard's review screen, and deliberately
// includes the same facts.
func printPlan(out io.Writer, cfg *config.Config, p *Prepared) {
	r, info := p.Resolved, p.Runner.Info()
	fmt.Fprintf(out, "interface     %s (%s, %d queue(s))\n", r.Link.Name, driverOr(r.Link.Driver), p.Runner.Queues())
	fmt.Fprintf(out, "pattern       %s  %s\n", cfg.Mode, info.PacketSizes)

	if cfg.UsesIPStack() {
		fmt.Fprintf(out, "source        %s / %s\n", r.SrcIP, r.SrcMAC)
		fmt.Fprintf(out, "destination   %s port %d\n", r.Dst, cfg.DstPort)
		fmt.Fprintf(out, "next hop      %s (%s)\n", macOr(r.DstMAC), nextHopDesc(r))
		fmt.Fprintf(out, "flows         %d\n", cfg.Flows)
	} else if r.DstMAC != nil {
		fmt.Fprintf(out, "destination   %s\n", r.DstMAC)
	}
	if cfg.Transmits() {
		if cfg.VLAN != 0 {
			fmt.Fprintf(out, "vlan          802.1Q id %d\n", cfg.VLAN)
		} else {
			fmt.Fprintf(out, "vlan          untagged\n")
		}
		fmt.Fprintf(out, "rate          %s\n", rateDesc(cfg))
	}
	fmt.Fprintf(out, "duration      %s\n", durationDesc(cfg))
	fmt.Fprintf(out, "receive       %s\n", p.Plan.Redirects)
	for _, l := range p.Plan.Limitations {
		fmt.Fprintf(out, "              note: %s\n", l)
	}
	for _, n := range r.Notes {
		fmt.Fprintf(out, "              %s\n", n)
	}
	if p.Frames != nil {
		fmt.Fprintf(out, "capture       %s\n", p.Frames.Describe())
		for _, w := range p.Frames.Warnings() {
			fmt.Fprintf(out, "              note: %s\n", w)
		}
	}
	for _, c := range p.Preflight.Warnings() {
		if c.Detail == p.Plan.Redirects {
			fmt.Fprintf(out, "\nwarning: %s\n", c.Title) // already described above
			continue
		}
		fmt.Fprintf(out, "\nwarning: %s\n  %s\n", c.Title, c.Detail)
		if c.Fix != "" {
			fmt.Fprintf(out, "  %s\n", indent(c.Fix))
		}
	}
}

// confirmDanger requires a human to type yes before a run that could cut the
// user off from the machine. --yes does not satisfy it.
func confirmDanger(out io.Writer, cfg *config.Config, danger []dataplane.Check) error {
	fmt.Fprintln(out)
	for _, c := range danger {
		fmt.Fprintf(out, "DANGER: %s\n  %s\n", c.Title, c.Detail)
		if c.Fix != "" {
			fmt.Fprintf(out, "  %s\n", indent(c.Fix))
		}
	}
	// --yes is the command-line form of typing the confirmation, so a script
	// can run something dangerous on purpose. It is not a way around the
	// match-all guard: validation has already required --allow-match-all for
	// that, so reaching here with --rx-mode all means both were given.
	if cfg.AssumeYes {
		fmt.Fprintln(out, "\nproceeding: --yes was given.")
		return nil
	}
	if !isTerminal(os.Stdin) {
		return fmt.Errorf("this run needs an explicit confirmation but there is no terminal to " +
			"ask on. Re-run it interactively, or pass --yes together with --allow-match-all if " +
			"you have read the warnings above")
	}
	fmt.Fprint(out, "\nType 'yes' to continue: ")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return fmt.Errorf("cancelled")
	}
	if strings.TrimSpace(strings.ToLower(line)) != "yes" {
		return errors.New("cancelled")
	}
	return nil
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func driverOr(d string) string {
	if d == "" {
		return "virtual"
	}
	return d
}

func macOr(m fmt.Stringer) string {
	if m == nil {
		return "(none)"
	}
	return m.String()
}

func nextHopDesc(r *discovery.Resolved) string {
	if r.MACSource == "" {
		return "unresolved"
	}
	if r.NextHop.IsValid() && !r.OnLink {
		return fmt.Sprintf("%s, %s", r.NextHop, r.MACSource)
	}
	return string(r.MACSource)
}

func rateDesc(cfg *config.Config) string {
	switch {
	case cfg.PPS == 0 && cfg.BPS == 0:
		return "unlimited (line rate)"
	case cfg.BPS == 0:
		return config.FormatPPS(cfg.PPS) + " (aggregate across queues)"
	case cfg.PPS == 0:
		return config.FormatBPS(cfg.BPS) + " L1 (aggregate across queues)"
	}
	return fmt.Sprintf("%s and %s L1, whichever binds first",
		config.FormatPPS(cfg.PPS), config.FormatBPS(cfg.BPS))
}

func durationDesc(cfg *config.Config) string {
	if cfg.Duration == 0 {
		return "until stopped"
	}
	return cfg.Duration.String()
}

func indent(s string) string { return strings.ReplaceAll(s, "\n", "\n  ") }
