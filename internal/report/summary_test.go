package report

import (
	"testing"
	"time"

	"github.com/pidtrail/pidtrail/internal/event"
)

func TestCollectorSummary(t *testing.T) {
	c := NewCollector()
	now := time.Now().UTC()
	c.Add(event.Event{
		Time:      now,
		Kind:      event.KindProcess,
		Operation: "exec",
		PID:       10,
		Path:      "/usr/bin/curl",
	})
	c.Add(event.Event{
		Time:      now.Add(time.Second),
		Kind:      event.KindFile,
		Operation: "open",
		PID:       10,
		Path:      "/etc/ssl/certs/ca-certificates.crt",
	})
	c.Add(event.Event{
		Time:      now.Add(2 * time.Second),
		Kind:      event.KindNetwork,
		Operation: "connect",
		PID:       10,
		Direction: event.DirectionOutbound,
		DstAddr:   "1.1.1.1:443",
	})

	summary := c.Summary()
	if summary.TotalEvents != 3 {
		t.Fatalf("unexpected total events: %d", summary.TotalEvents)
	}
	if summary.ByKind["process"] != 1 || summary.ByKind["file"] != 1 || summary.ByKind["network"] != 1 {
		t.Fatalf("unexpected by-kind counts: %#v", summary.ByKind)
	}
	if len(summary.Execs) != 1 || len(summary.Files) != 1 || len(summary.Remotes) != 1 {
		t.Fatalf("unexpected summary detail: %#v", summary)
	}
}
