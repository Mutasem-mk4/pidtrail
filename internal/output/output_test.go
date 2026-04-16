package output

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pidtrail/pidtrail/internal/config"
	"github.com/pidtrail/pidtrail/internal/event"
)

func TestManagerReportBundle(t *testing.T) {
	dir := t.TempDir()
	mgr, err := NewManager(config.Options{
		ReportDir: dir,
		Quiet:     true,
	})
	if err != nil {
		t.Fatalf("new manager failed: %v", err)
	}

	now := time.Unix(1_700_000_000, 0).UTC()
	if err := mgr.Write(event.Event{
		Time:      now,
		Kind:      event.KindProcess,
		Operation: "exec",
		PID:       1234,
		Path:      "/usr/bin/curl",
	}); err != nil {
		t.Fatalf("write process event failed: %v", err)
	}
	if err := mgr.Write(event.Event{
		Time:      now.Add(time.Second),
		Kind:      event.KindFile,
		Operation: "open",
		PID:       1234,
		Path:      "/etc/hosts",
	}); err != nil {
		t.Fatalf("write file event failed: %v", err)
	}
	if err := mgr.Write(event.Event{
		Time:      now.Add(2 * time.Second),
		Kind:      event.KindNetwork,
		Operation: "connect",
		PID:       1234,
		Direction: event.DirectionOutbound,
		DstAddr:   "127.0.0.1:18080",
	}); err != nil {
		t.Fatalf("write network event failed: %v", err)
	}
	if err := mgr.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}

	eventsRaw, err := os.ReadFile(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		t.Fatalf("read events.jsonl failed: %v", err)
	}
	if !strings.Contains(string(eventsRaw), `"kind":"process"`) {
		t.Fatalf("events.jsonl missing process event: %s", eventsRaw)
	}
	if !strings.Contains(string(eventsRaw), `"kind":"network"`) {
		t.Fatalf("events.jsonl missing network event: %s", eventsRaw)
	}

	summaryRaw, err := os.ReadFile(filepath.Join(dir, "summary.json"))
	if err != nil {
		t.Fatalf("read summary.json failed: %v", err)
	}
	summaryText := string(summaryRaw)
	if !strings.Contains(summaryText, `"total_events": 3`) {
		t.Fatalf("summary.json missing total event count: %s", summaryText)
	}
	if !strings.Contains(summaryText, `"connect": 1`) {
		t.Fatalf("summary.json missing connect count: %s", summaryText)
	}
}
