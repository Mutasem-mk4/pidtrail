package config

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"time"
)

type Options struct {
	PID              int
	Process          string
	Command          []string
	Duration         time.Duration
	JSONPath         string
	JSONLPath        string
	ReportDir        string
	Quiet            bool
	Diagnose         bool
	Version          bool
	RequireRootCheck bool
}

func Parse(args []string, stderr io.Writer) (Options, error) {
	var cfg Options
	cfg.RequireRootCheck = true

	flags := flag.NewFlagSet("pidtrail", flag.ContinueOnError)
	flags.SetOutput(stderr)

	flags.IntVar(&cfg.PID, "pid", 0, "trace a specific PID")
	flags.StringVar(&cfg.Process, "process", "", "trace processes whose comm matches exactly")
	flags.DurationVar(&cfg.Duration, "duration", 0, "optional trace duration, for example 30s")
	flags.StringVar(&cfg.JSONPath, "json", "", "write JSON output to a file")
	flags.StringVar(&cfg.JSONLPath, "jsonl", "", "write JSONL output to a file")
	flags.StringVar(&cfg.ReportDir, "report-dir", "", "write a report bundle with events.jsonl and summary.json")
	flags.BoolVar(&cfg.Quiet, "quiet", false, "disable terminal event output")
	flags.BoolVar(&cfg.Diagnose, "diagnose", false, "run capability checks and exit")
	flags.BoolVar(&cfg.Version, "version", false, "print version and exit")

	if err := flags.Parse(args); err != nil {
		return Options{}, err
	}
	cfg.Command = append(cfg.Command, flags.Args()...)
	if cfg.Version {
		return cfg, nil
	}
	scopeCount := 0
	if cfg.PID > 0 {
		scopeCount++
	}
	if cfg.Process != "" {
		scopeCount++
	}
	if len(cfg.Command) > 0 {
		scopeCount++
	}
	if scopeCount == 0 {
		return Options{}, errors.New("one of --pid, --process, or a command after -- is required")
	}
	if scopeCount > 1 {
		return Options{}, errors.New("use exactly one scope selector: --pid, --process, or a command after --")
	}
	if cfg.PID < 0 {
		return Options{}, errors.New("--pid must be > 0")
	}
	if cfg.JSONPath != "" && cfg.JSONLPath != "" {
		return Options{}, errors.New("use either --json or --jsonl, not both")
	}
	if cfg.ReportDir != "" && cfg.JSONPath != "" {
		return Options{}, fmt.Errorf("use --report-dir with --jsonl or by itself, not with --json")
	}
	return cfg, nil
}

func UsageText() string {
	return `Usage:
  pidtrail --pid 1234 [options]
  pidtrail --process curl [options]
  pidtrail [options] -- /path/to/command arg1 arg2

Options:
  --json PATH           export collected events as JSON
  --jsonl PATH          stream events as JSONL
  --report-dir DIR      write a report bundle
  --diagnose            report runtime support status and exit`
}
