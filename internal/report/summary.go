package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/pidtrail/pidtrail/internal/event"
)

type Summary struct {
	StartedAt   time.Time      `json:"started_at"`
	EndedAt     time.Time      `json:"ended_at"`
	TotalEvents int            `json:"total_events"`
	ByKind      map[string]int `json:"by_kind"`
	ByOperation map[string]int `json:"by_operation"`
	PIDs        []int          `json:"pids,omitempty"`
	Execs       []string       `json:"execs,omitempty"`
	Files       []string       `json:"files,omitempty"`
	Remotes     []string       `json:"remotes,omitempty"`
}

type Collector struct {
	started time.Time
	ended   time.Time
	total   int
	byKind  map[string]int
	byOp    map[string]int
	pids    map[int]struct{}
	execs   map[string]struct{}
	files   map[string]struct{}
	remotes map[string]struct{}
}

func NewCollector() *Collector {
	return &Collector{
		byKind:  make(map[string]int),
		byOp:    make(map[string]int),
		pids:    make(map[int]struct{}),
		execs:   make(map[string]struct{}),
		files:   make(map[string]struct{}),
		remotes: make(map[string]struct{}),
	}
}

func (c *Collector) Add(ev event.Event) {
	if c.total == 0 || ev.Time.Before(c.started) {
		c.started = ev.Time
	}
	if ev.Time.After(c.ended) {
		c.ended = ev.Time
	}
	c.total++
	c.byKind[string(ev.Kind)]++
	if ev.Operation != "" {
		c.byOp[ev.Operation]++
	}
	if ev.PID > 0 {
		c.pids[ev.PID] = struct{}{}
	}
	if ev.Kind == event.KindProcess && ev.Operation == "exec" && ev.Path != "" {
		c.execs[ev.Path] = struct{}{}
	}
	if ev.Kind == event.KindFile && ev.Path != "" {
		c.files[ev.Path] = struct{}{}
	}
	if ev.Kind == event.KindNetwork {
		switch {
		case ev.Direction == event.DirectionOutbound && ev.DstAddr != "":
			c.remotes[ev.DstAddr] = struct{}{}
		case ev.Direction == event.DirectionInbound && ev.SrcAddr != "":
			c.remotes[ev.SrcAddr] = struct{}{}
		}
	}
}

func (c *Collector) Summary() Summary {
	return Summary{
		StartedAt:   c.started,
		EndedAt:     c.ended,
		TotalEvents: c.total,
		ByKind:      cloneMap(c.byKind),
		ByOperation: cloneMap(c.byOp),
		PIDs:        sortedInts(c.pids),
		Execs:       sortedStrings(c.execs),
		Files:       sortedStrings(c.files),
		Remotes:     sortedStrings(c.remotes),
	}
}

func (c *Collector) WriteSummary(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(c.Summary())
}

func cloneMap(in map[string]int) map[string]int {
	out := make(map[string]int, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func sortedInts(in map[int]struct{}) []int {
	out := make([]int, 0, len(in))
	for k := range in {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}

func sortedStrings(in map[string]struct{}) []string {
	out := make([]string, 0, len(in))
	for k := range in {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
