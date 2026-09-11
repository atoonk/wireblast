package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/atoonk/wireblast/internal/config"
	"github.com/atoonk/wireblast/internal/stats"
)

func TestOpenStatsOutputDisabled(t *testing.T) {
	cfg := config.Default()
	out, err := openStatsOutput(&cfg)
	if err != nil {
		t.Fatalf("openStatsOutput: %v", err)
	}
	if out != nil {
		t.Fatal("disabled stats output should return nil")
	}
}

func TestOpenStatsOutputRefusesToOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run.csv")
	if err := os.WriteFile(path, []byte("keep me"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.StatsFile = path
	cfg.StatsFormat = config.StatsCSV

	if _, err := openStatsOutput(&cfg); err == nil {
		t.Fatal("opening an existing stats file should fail")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "keep me" {
		t.Fatalf("existing file changed to %q", got)
	}
}

func TestStatsOutputCreatesAndFlushesAStream(t *testing.T) {
	path := filepath.Join(t.TempDir(), "run.csv")
	cfg := config.Default()
	cfg.StatsFile = path
	cfg.StatsFormat = config.StatsCSV
	out, err := openStatsOutput(&cfg)
	if err != nil {
		t.Fatalf("openStatsOutput: %v", err)
	}
	s := &stats.Snapshot{
		At:    time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC),
		State: stats.StateRunning,
	}
	if err := out.Sample(s); err != nil {
		t.Fatalf("Sample: %v", err)
	}

	// A sample must be visible before Close so a preempted process leaves data.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "schema_version") || !strings.Contains(string(data), "sample") {
		t.Fatalf("stream was not flushed after Sample:\n%s", data)
	}
	if err := out.Final(s); err != nil {
		t.Fatalf("Final: %v", err)
	}
	if err := out.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}
