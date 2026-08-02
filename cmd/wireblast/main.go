// Command wireblast is a fast, easy-to-use AF_XDP traffic generator for Linux.
//
// Run it with no arguments for an interactive wizard, or specify everything on
// the command line and add --no-tui for scripts:
//
//	sudo wireblast
//	sudo wireblast -i eth1 --dst-ip 192.0.2.10 --pps 1M --duration 30s --no-tui
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/atoonk/wireblast/internal/app"
	"github.com/atoonk/wireblast/internal/cli"
	"github.com/atoonk/wireblast/internal/config"
	"github.com/atoonk/wireblast/internal/tui"
)

// version is overridden at build time with -ldflags "-X main.version=..."
var version = "dev"

func main() {
	// Stop cleanly on the first Ctrl-C or SIGTERM; the second exits immediately,
	// so a wedged run can still be killed without reaching for another shell.
	//
	// One channel counts both: the first signal cancels the context (graceful
	// drain and detach), the second forces the exit. Registering it once, up
	// front, means there is no window in which a signal can be lost, and the
	// buffer of two holds both even if this goroutine is slow to run.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sig := make(chan os.Signal, 2)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sig)
	go func() {
		<-sig
		cancel()
		<-sig
		fmt.Fprintln(os.Stderr, "\nwireblast: second signal, exiting now")
		os.Exit(130)
	}()

	cmd := cli.NewRootCommand(version, run)
	if err := cmd.ExecuteContext(ctx); err != nil {
		if errors.Is(err, context.Canceled) {
			os.Exit(0)
		}
		fmt.Fprintf(os.Stderr, "wireblast: %v\n", err)
		os.Exit(1)
	}
}

// run is the single entry point both front ends go through. This is the only
// place in the program that decides between the wizard and the scripted path,
// and the only place that exits the process.
func run(ctx context.Context, cfg *config.Config) error {
	if cfg.NoTUI {
		return app.RunNonInteractive(ctx, cfg, os.Stdout)
	}
	return tui.Run(ctx, cfg)
}
