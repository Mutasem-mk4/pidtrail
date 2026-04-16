package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/pidtrail/pidtrail/internal/config"
	"github.com/pidtrail/pidtrail/internal/output"
	"github.com/pidtrail/pidtrail/internal/trace"
	"github.com/pidtrail/pidtrail/internal/version"
)

func Run(ctx context.Context, args []string) int {
	cfg, err := config.Parse(args, os.Stderr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		fmt.Fprintln(os.Stderr, config.UsageText())
		return 2
	}
	if cfg.Version {
		fmt.Fprintln(os.Stdout, version.String())
		return 0
	}

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	if cfg.Duration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cfg.Duration+time.Second)
		defer cancel()
	}

	out, err := output.NewManager(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "output setup failed: %v\n", err)
		return 1
	}
	defer func() {
		if closeErr := out.Close(); closeErr != nil {
			fmt.Fprintf(os.Stderr, "output close failed: %v\n", closeErr)
		}
	}()

	backend := trace.New()
	if cfg.Diagnose {
		events, err := backend.Diagnose(ctx, cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "diagnostics failed: %v\n", err)
			return 1
		}
		for _, ev := range events {
			if err := out.Write(ev); err != nil {
				fmt.Fprintf(os.Stderr, "write failed: %v\n", err)
				return 1
			}
		}
		return 0
	}

	sink := make(chan trace.Event, 128)
	errCh := make(chan error, 1)
	go func() {
		errCh <- backend.Run(ctx, cfg, sink)
	}()

	for {
		select {
		case <-ctx.Done():
			return 0
		case err := <-errCh:
			if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
				fmt.Fprintf(os.Stderr, "%v\n", err)
				return 1
			}
			return 0
		case ev, ok := <-sink:
			if !ok {
				return 0
			}
			if err := out.Write(ev); err != nil {
				fmt.Fprintf(os.Stderr, "write failed: %v\n", err)
				return 1
			}
		}
	}
}
