//go:build !linux

package stub

import (
	"context"
	"fmt"

	"github.com/pidtrail/pidtrail/internal/config"
	"github.com/pidtrail/pidtrail/internal/event"
)

type Backend struct{}

func New() *Backend {
	return &Backend{}
}

func (b *Backend) Run(ctx context.Context, cfg config.Options, sink chan<- event.Event) error {
	defer close(sink)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case sink <- event.NewDiagnostic("runtime tracing is supported on Linux only; this host can run control-plane tests but not live process/file/network capture"):
	}
	return fmt.Errorf("pidtrail: live tracing is unsupported on this platform")
}

func (b *Backend) Diagnose(ctx context.Context, cfg config.Options) ([]event.Event, error) {
	return []event.Event{
		event.NewDiagnostic("platform: unsupported"),
		event.NewDiagnostic("live tracing requires Linux with tracing privileges"),
		event.NewDiagnostic("the supported capture surface is process, file, and network metadata"),
	}, nil
}
