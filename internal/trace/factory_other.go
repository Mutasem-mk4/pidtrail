//go:build !linux

package trace

import (
	"github.com/pidtrail/pidtrail/internal/trace/stub"
)

func New() Backend {
	return stub.New()
}
