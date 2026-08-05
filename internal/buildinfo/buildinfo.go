// Package buildinfo carries the version identity injected into the binary at
// link time.
//
// Both variables are set with -ldflags -X at build time and are deliberately
// EMPTY by default. Nothing here invents a fallback: a binary that was not
// built by the release pipeline must say so, because aurvet's output is
// evidence in a security investigation and an unfalsifiable version string is
// worse than an absent one. A reader who sees "not injected" knows to go and
// establish provenance; a reader who sees "dev" or "0.0.0" believes they
// already have it.
//
// Injection is a single merged -ldflags string (spec §16). Two -ldflags flags
// mean the second replaces the first and one -X silently vanishes, and an
// inherited GOFLAGS -ldflags is *replaced* rather than merged by a
// command-line one -- which is how naive version injection turns a static
// binary into a dynamically-linked one. The canonical invocation lives in the
// Makefile; TestBinaryIsStaticallyLinked in cmd/aurvet guards the consequence.
package buildinfo

// Version is the release version (e.g. "0.0.1"), injected at link time.
// Empty means this binary was not built by the release pipeline.
var Version = ""

// Commit is the full git commit SHA, injected at link time. Empty means this
// binary was not built by the release pipeline. The full SHA is injected
// rather than an abbreviation so the value is unambiguous; String abbreviates
// for display only.
var Commit = ""

// notInjected is the exact phrase callers and tests match on. Kept as a
// constant so the wording cannot drift apart from the tests that assert it.
const notInjected = "not injected"

// commitDisplayLen is how much of the SHA String shows. 12 is git's own
// core.abbrev ceiling for large repositories and is unambiguous in practice.
const commitDisplayLen = 12

// String renders the build identity for `aurvet version`.
//
// Partial injection is reported as not-injected rather than as a partial
// success: a build where one -X landed and the other was typo'd has unknown
// provenance, and describing it as identified would be the same mistake as a
// fake default.
func String() string {
	switch {
	case Version == "" && Commit == "":
		return "aurvet (version " + notInjected + "; not a release build)"
	case Version == "":
		return "aurvet (version " + notInjected + "; commit " + shortCommit() + ")"
	case Commit == "":
		return "aurvet " + Version + " (commit " + notInjected + ")"
	default:
		return "aurvet " + Version + " (commit " + shortCommit() + ")"
	}
}

func shortCommit() string {
	if len(Commit) > commitDisplayLen {
		return Commit[:commitDisplayLen]
	}
	return Commit
}
