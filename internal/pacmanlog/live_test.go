// internal/pacmanlog/live_test.go
//
// Measurement against the live log, behind an env gate like the other
// AURVET_LIVE_* tests. Every number asserted here was measured independently of
// this reader (awk/grep over /var/log/pacman.log) before the reader existed, so
// a disagreement is a bug in the reader or drift on the machine -- not a
// tautology.
package pacmanlog

import (
	"os"
	"testing"
	"time"
)

func TestLiveReferenceLog(t *testing.T) {
	if os.Getenv("AURVET_LIVE_PACMANLOG") != "1" {
		t.Skip("set AURVET_LIVE_PACMANLOG=1 to measure against /var/log/pacman.log")
	}
	const path = "/var/log/pacman.log"
	if _, err := os.Stat(path); err != nil {
		t.Skipf("no live log: %v", err)
	}
	r, err := Read(Config{Path: path})
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	t.Logf("files=%v lines=%d alpm=%d pacman=%d scriptlet=%d unparsed=%d offsets=%v "+
		"entries=%d foreign=%d foreignRoots=%v earliest=%s latest=%s gaps=%d",
		paths(r.Files), r.LinesRead, r.ALPMLines, r.PacmanLines, r.ScriptletLines, r.Unparsed,
		r.Offsets, len(r.Entries), len(r.Foreign), r.ForeignRoots, r.EarliestString(),
		r.Latest.Format(TimeLayout), len(r.Gaps))
	for _, g := range r.Gaps {
		t.Logf("gap %s %s: %s", g.RuleID, g.Subject, g.Reason)
	}

	// Measured independently: 16,840 lines, 11,298 [ALPM], 1,683 [PACMAN],
	// 3,859 [ALPM-SCRIPTLET], exactly two offsets (+0000 on 10,498 lines,
	// +0100 on 6,342), 15 invocations naming another root, no rotated siblings,
	// earliest line 2025-11-11T00:50:40+0000.
	if r.LinesRead != 16840 {
		t.Errorf("LinesRead = %d, want 16840", r.LinesRead)
	}
	if r.ALPMLines != 11298 {
		t.Errorf("ALPMLines = %d, want 11298", r.ALPMLines)
	}
	if r.PacmanLines != 1683 {
		t.Errorf("PacmanLines = %d, want 1683", r.PacmanLines)
	}
	if r.ScriptletLines != 3859 {
		t.Errorf("ScriptletLines = %d, want 3859", r.ScriptletLines)
	}
	if len(r.Offsets) != 2 || r.Offsets[0] != "+0000" || r.Offsets[1] != "+0100" {
		t.Errorf("Offsets = %v, want [+0000 +0100] (the DST boundary in one file)", r.Offsets)
	}
	if got, want := r.EarliestString(), "2025-11-11T00:50:40+0000"; got != want {
		t.Errorf("EarliestString = %q, want %q", got, want)
	}
	if len(r.Files) != 1 {
		t.Errorf("read %d files; the reference machine has NO rotated siblings", len(r.Files))
	}
	if r.ForeignRoots["/mnt"] == 0 {
		t.Errorf("no transactions attributed to /mnt; the installer ran 15 invocations with -r /mnt")
	}
	// The installer's /mnt transactions are the archinstall run, so this root's
	// own coverage begins later than the log does. Report, do not assert: it is
	// a property of this machine's history, not of the reader.
	if len(r.Entries) > 0 {
		t.Logf("first transaction attributed to /: %s %s %s",
			r.Entries[0].Time.Format(TimeLayout), r.Entries[0].Op, r.Entries[0].Pkg)
	}
	// Independent cross-check on the transaction total: grep counts 1,915
	// installed + 5,126 upgraded + 505 removed + 81 reinstalled + 1 downgraded =
	// 7,628 package transactions, which must equal this root's plus the other
	// root's. It is the assertion that catches a verb this reader silently drops.
	if got := len(r.Entries) + len(r.Foreign); got != 7628 {
		t.Errorf("transactions = %d (%d here + %d elsewhere), want 7628",
			got, len(r.Entries), len(r.Foreign))
	}
	if r.Unparsed != 0 {
		t.Errorf("Unparsed = %d on the live log; every line of it should parse", r.Unparsed)
	}

	// Coverage against a baseline window one day inside the log: covered.
	inside := r.Earliest.Add(24 * time.Hour)
	if !r.CoversWindow(inside) {
		t.Errorf("CoversWindow(%s) = false inside the log's own span", inside)
	}
	// And one day before it: not covered, as a gap and not as criticals.
	before := r.Earliest.Add(-24 * time.Hour)
	r2, err := Read(Config{Path: path, BaselineStart: before})
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if r2.CoversWindow(before) {
		t.Error("CoversWindow said a window starting before the log's first line is covered")
	}
	if r2.MaxSeverityIsCritical() {
		t.Error("a window the log does not cover produced a critical")
	}
	var window int
	for _, g := range r2.Gaps {
		if g.RuleID == RuleWindowNotCovered {
			window++
		}
	}
	if window != 1 {
		t.Errorf("%d window gaps, want exactly 1 for the whole shortfall", window)
	}
}
