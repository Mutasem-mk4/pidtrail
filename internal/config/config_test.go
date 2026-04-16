package config

import (
	"bytes"
	"testing"
)

func TestParseRequiresScope(t *testing.T) {
	_, err := Parse(nil, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected scope validation error")
	}
}

func TestParseCommandScope(t *testing.T) {
	cfg, err := Parse([]string{"--report-dir", "out", "--", "/usr/bin/curl", "https://example.com"}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if len(cfg.Command) != 2 {
		t.Fatalf("unexpected command slice: %#v", cfg.Command)
	}
	if cfg.ReportDir != "out" {
		t.Fatalf("unexpected report dir: %q", cfg.ReportDir)
	}
}

func TestParseRejectsMultipleScopes(t *testing.T) {
	_, err := Parse([]string{"--pid", "42", "--process", "curl"}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected multiple-scope validation error")
	}
}
