package trace

import (
	"context"

	"github.com/pidtrail/pidtrail/internal/config"
	"github.com/pidtrail/pidtrail/internal/event"
)

type Event = event.Event

type Backend interface {
	Run(context.Context, config.Options, chan<- event.Event) error
	Diagnose(context.Context, config.Options) ([]event.Event, error)
}
