//go:build linux

package trace

import (
	"github.com/pidtrail/pidtrail/internal/trace/linux"
)

func New() Backend {
	return linux.New()
}
