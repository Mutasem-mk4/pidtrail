package output

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pidtrail/pidtrail/internal/config"
	"github.com/pidtrail/pidtrail/internal/event"
	"github.com/pidtrail/pidtrail/internal/report"
)

type Manager struct {
	cfg        config.Options
	jsonFile   *os.File
	jsonlFile  *os.File
	jsonl      *bufio.Writer
	events     []event.Event
	report     *report.Collector
	reportPath string
}

func NewManager(cfg config.Options) (*Manager, error) {
	mgr := &Manager{cfg: cfg}
	if cfg.ReportDir != "" {
		if err := os.MkdirAll(cfg.ReportDir, 0o755); err != nil {
			return nil, err
		}
		mgr.report = report.NewCollector()
		mgr.reportPath = filepath.Join(cfg.ReportDir, "summary.json")
		if cfg.JSONLPath == "" {
			cfg.JSONLPath = filepath.Join(cfg.ReportDir, "events.jsonl")
			mgr.cfg.JSONLPath = cfg.JSONLPath
		}
	}
	if cfg.JSONLPath != "" {
		f, err := os.Create(cfg.JSONLPath)
		if err != nil {
			return nil, err
		}
		mgr.jsonlFile = f
		mgr.jsonl = bufio.NewWriter(f)
	}
	if cfg.JSONPath != "" {
		f, err := os.Create(cfg.JSONPath)
		if err != nil {
			return nil, err
		}
		mgr.jsonFile = f
	}
	return mgr, nil
}

func (m *Manager) Close() error {
	if m.cfg.JSONLPath != "" && m.jsonl != nil {
		if err := m.jsonl.Flush(); err != nil {
			if m.jsonlFile != nil {
				_ = m.jsonlFile.Close()
			}
			return err
		}
	}
	if m.cfg.JSONPath != "" && m.jsonFile != nil {
		enc := json.NewEncoder(m.jsonFile)
		enc.SetIndent("", "  ")
		if err := enc.Encode(m.events); err != nil {
			_ = m.jsonFile.Close()
			return err
		}
	}
	if m.jsonFile != nil {
		if err := m.jsonFile.Close(); err != nil {
			return err
		}
	}
	if m.jsonlFile != nil {
		if err := m.jsonlFile.Close(); err != nil {
			return err
		}
	}
	if m.report != nil {
		return m.report.WriteSummary(m.reportPath)
	}
	return nil
}

func (m *Manager) Write(ev event.Event) error {
	if !m.cfg.Quiet {
		fmt.Fprintln(os.Stdout, renderTerminal(ev))
	}
	if m.cfg.JSONLPath != "" && m.jsonl != nil {
		line, err := json.Marshal(ev)
		if err != nil {
			return err
		}
		if _, err := m.jsonl.Write(append(line, '\n')); err != nil {
			return err
		}
	}
	if m.cfg.JSONPath != "" {
		m.events = append(m.events, ev)
	}
	if m.report != nil {
		m.report.Add(ev)
	}
	return nil
}

func renderTerminal(ev event.Event) string {
	var b strings.Builder
	b.WriteString(ev.Time.UTC().Format("2006-01-02T15:04:05.000Z"))
	b.WriteString(" ")
	b.WriteString(string(ev.Kind))
	if ev.Comm != "" || ev.PID != 0 {
		b.WriteString(" pid=")
		b.WriteString(fmt.Sprintf("%d", ev.PID))
		if ev.Comm != "" {
			b.WriteString(" comm=")
			b.WriteString(ev.Comm)
		}
	}
	if ev.Direction != "" && ev.Direction != event.DirectionUnknown {
		b.WriteString(" dir=")
		b.WriteString(string(ev.Direction))
	}
	if ev.Operation != "" {
		b.WriteString(" op=")
		b.WriteString(ev.Operation)
	}
	if ev.SrcAddr != "" || ev.DstAddr != "" {
		if ev.SrcAddr != "" {
			b.WriteString(" src=")
			b.WriteString(ev.SrcAddr)
		}
		if ev.DstAddr != "" {
			b.WriteString(" dst=")
			b.WriteString(ev.DstAddr)
		}
	}
	switch ev.Kind {
	case event.KindDiagnostic:
		if ev.Message != "" {
			b.WriteString(" ")
			b.WriteString(ev.Message)
		}
	default:
		if ev.ChildPID > 0 {
			b.WriteString(" child=")
			b.WriteString(fmt.Sprintf("%d", ev.ChildPID))
		}
		if ev.ExitCode != 0 {
			b.WriteString(" exit=")
			b.WriteString(fmt.Sprintf("%d", ev.ExitCode))
		}
		if ev.FD > 0 {
			b.WriteString(" fd=")
			b.WriteString(fmt.Sprintf("%d", ev.FD))
		}
		if ev.Path != "" {
			b.WriteString(" path=")
			b.WriteString(strconvQuote(ev.Path))
		}
		if ev.Message != "" {
			b.WriteString(" ")
			b.WriteString(ev.Message)
		}
	}
	return b.String()
}

func strconvQuote(value string) string {
	quoted, err := json.Marshal(value)
	if err != nil {
		return `""`
	}
	return string(quoted)
}
