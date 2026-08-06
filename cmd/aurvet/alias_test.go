package main

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// The two spellings spec §14 uses and the binary did not.
//
// §14 names `aurvet baseline ... show` and a TOP-LEVEL `aurvet diff`. The binary
// had `baseline status` and `baseline diff`. Rather than leave the spec wrong,
// both spellings dispatch to one implementation: §1 names `diff` as one of the
// four verbs the product is ("scan compares live state to expectation, diff to
// recorded state"), so a user who read the spec types `aurvet diff`, and a user
// who learned the tool types `aurvet baseline diff`. Neither should get exit 2.
// ---------------------------------------------------------------------------

// An offline root is used throughout: config.Resolve puts the state directory
// inside it, so these run against an empty chain in a temp dir and never read
// this machine's own baseline.

func TestBaselineShowIsBaselineStatus(t *testing.T) {
	root := t.TempDir()
	statusCode, statusOut, statusErr := scanOut(t, "baseline", "status", "-offline-root", root)
	showCode, showOut, showErr := scanOut(t, "baseline", "show", "-offline-root", root)
	if statusCode != showCode {
		t.Errorf("`baseline show` = %d, `baseline status` = %d", showCode, statusCode)
	}
	if showOut != statusOut || showErr != statusErr {
		t.Errorf("the two spellings do not produce the same output\nshow:\n%s%s\nstatus:\n%s%s",
			showOut, showErr, statusOut, statusErr)
	}
	if strings.Contains(showErr, "unknown baseline subcommand") {
		t.Errorf("`baseline show` is not dispatched:\n%s", showErr)
	}
}

func TestTopLevelDiffIsBaselineDiff(t *testing.T) {
	root := t.TempDir()
	subCode, subOut, subErr := scanOut(t, "baseline", "diff", "-offline-root", root)
	topCode, topOut, topErr := scanOut(t, "diff", "-offline-root", root)
	if topCode != subCode {
		t.Errorf("`aurvet diff` = %d, `aurvet baseline diff` = %d", topCode, subCode)
	}
	if topOut != subOut || topErr != subErr {
		t.Errorf("the two spellings do not produce the same output\ntop:\n%s%s\nsub:\n%s%s",
			topOut, topErr, subOut, subErr)
	}
	if strings.Contains(topErr, "unknown command") {
		t.Errorf("`aurvet diff` is not dispatched:\n%s", topErr)
	}
	// Both must reach the real refusal rather than a usage error: there is no
	// chain in the temp root, and "nothing to diff against is not the same as no
	// drift" is the answer.
	if !strings.Contains(topErr, "nothing to diff against") {
		t.Errorf("`aurvet diff` did not reach baselineDiff:\n%s", topErr)
	}
	if topCode != exitIncomplete {
		t.Errorf("exit = %d, want %d", topCode, exitIncomplete)
	}
}

// An unknown subcommand after `diff` must still be an error rather than being
// silently swallowed by the translation to `baseline diff`.
func TestTopLevelDiffRejectsTrailingArguments(t *testing.T) {
	code, stdout, stderr := scanOut(t, "diff", "nonsense", "-offline-root", t.TempDir())
	if code != exitUsage {
		t.Fatalf("exit = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitUsage, stdout, stderr)
	}
}
