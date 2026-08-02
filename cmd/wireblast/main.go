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
	// Stop cleanly on Ctrl-C and SIGTERM. The second signal exits immediately,
	// so a wedged run can still be killed without reaching for another shell.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
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
