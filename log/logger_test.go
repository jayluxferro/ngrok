package log

// Tests for the one place a log level is set from user input (LogTo, called
// with the -log-level flag value): an unrecognized level name used to fall
// back to DEBUG in silence, so a typo'd "-log-level=WARN" configured exactly
// the noisiest level while looking like a quieter one. The house rule is
// fail-loudly; these tests pin the loud failure and the accepted set -- the
// four names both CLIs document (client/cli.go, server/cli.go).

import (
	"strings"
	"testing"

	log4go "github.com/alecthomas/log4go"
)

// rootLevel reads the level of the filter LogTo installs, under the same lock
// the production readers use -- the logger is process-wide state, and the
// guard exists so it is never read unlocked, tests included.
func rootLevel(t *testing.T) (log4go.Level, bool) {
	t.Helper()

	rootMu.RLock()
	defer rootMu.RUnlock()

	filter, ok := root["log"]
	if !ok {
		return 0, false
	}

	return filter.Level, true
}

// TestLogToRejectsUnknownLevel pins the fix: every unrecognized spelling --
// including the near-misses and the case variants of valid names -- is a
// startup error that names the offending level and the accepted set, rather
// than a quiet DEBUG.
func TestLogToRejectsUnknownLevel(t *testing.T) {
	for _, level := range []string{"WARN", "warning", "Debug", "INFO ", "verbose", ""} {
		err := LogTo("stdout", level, "text")
		if err == nil {
			t.Errorf("LogTo level %q: expected an error, got none (the silent DEBUG fall-back is back)", level)
			continue
		}
		// The error names the level the operator passed...
		if !strings.Contains(err.Error(), "\""+level+"\"") {
			t.Errorf("LogTo level %q: error should name the offending level, got: %v", level, err)
		}
		// ...and the accepted set, so the fix needs no documentation lookup.
		if !strings.Contains(err.Error(), "DEBUG, INFO, WARNING, ERROR") {
			t.Errorf("LogTo level %q: error should name the accepted set, got: %v", level, err)
		}
	}
}

// TestLogToAcceptsEachDocumentedLevel pins the other half: each accepted name
// really sets its level on the filter the logger reads, and no accepted name
// drifted into another.
func TestLogToAcceptsEachDocumentedLevel(t *testing.T) {
	for _, tt := range []struct {
		name  string
		level log4go.Level
	}{
		{"DEBUG", log4go.DEBUG},
		{"INFO", log4go.INFO},
		{"WARNING", log4go.WARNING},
		{"ERROR", log4go.ERROR},
	} {
		if err := LogTo("stdout", tt.name, "text"); err != nil {
			t.Errorf("LogTo(%q): expected the documented level to be accepted, got: %v", tt.name, err)
			continue
		}

		got, ok := rootLevel(t)
		if !ok {
			t.Fatalf("LogTo(%q): no filter named \"log\" installed", tt.name)
		}
		if got != tt.level {
			t.Errorf("LogTo(%q) installed level %v, want %v", tt.name, got, tt.level)
		}
	}
}

// TestLogToRejectedLevelLeavesLoggerUntouched pins the failure's hygiene: a
// refused call mutates nothing, so the level in force when the bad one
// arrived survives it. (LogTo validates before it touches the writer state
// or the format flag; this is that promise, observed.)
func TestLogToRejectedLevelLeavesLoggerUntouched(t *testing.T) {
	if err := LogTo("stdout", "INFO", "text"); err != nil {
		t.Fatalf("setting up: LogTo(INFO) failed: %v", err)
	}

	if err := LogTo("stdout", "WARN", "text"); err == nil {
		t.Fatal("setting up: expected the bad level to be refused")
	}

	if got, ok := rootLevel(t); !ok || got != log4go.INFO {
		t.Fatalf("after a refused LogTo, installed level = %v (present: %v), want INFO untouched", got, ok)
	}
}
