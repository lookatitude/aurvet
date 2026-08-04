package main

import (
	"bytes"
	"strings"
	"testing"
)

// Spec §14: the exit code is the machine-readable result. Automation branches on
// it, so each class is pinned here rather than left to the switch's shape.
func TestRunExitCodes(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want int
	}{
		{"doctor succeeds", []string{"doctor"}, exitClean},
		{"doctor under offline-root succeeds", []string{"-offline-root", "/mnt/target", "doctor"}, exitClean},
		{"no command is a usage error", nil, exitUsage},
		{"unknown command is a usage error", []string{"rummage"}, exitUsage},
		{"unknown flag is a usage error", []string{"-nope", "doctor"}, exitUsage},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if got := run(tc.args, &stdout, &stderr); got != tc.want {
				t.Errorf("run(%q) = %d, want %d\nstderr: %s", tc.args, got, tc.want, stderr.String())
			}
		})
	}
}

// doctor must write its report to stdout, not stderr: it is data, and callers
// pipe it.
func TestDoctorWritesReportToStdout(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-offline-root", "/mnt/target", "doctor"}, &stdout, &stderr); code != exitClean {
		t.Fatalf("run = %d, stderr: %s", code, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "/mnt/target/var/lib/pacman/local") {
		t.Errorf("doctor output missing rooted db_path:\n%s", out)
	}
	if stderr.Len() != 0 {
		t.Errorf("doctor wrote to stderr: %s", stderr.String())
	}
	// Provenance is the point of doctor; a bare value dump is not enough.
	if !strings.Contains(out, "(derived)") {
		t.Errorf("doctor output missing provenance:\n%s", out)
	}
}
