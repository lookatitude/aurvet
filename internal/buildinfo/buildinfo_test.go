package buildinfo

import (
	"strings"
	"testing"
)

// Version and Commit are injected at link time and are empty in an ordinary
// `go build`. Empty must render as *explicitly not injected*, never as a
// plausible-looking value. aurvet's output is evidence in a security
// investigation: "aurvet 0.0.0" or "aurvet dev" in a report tells a reader
// something false with total confidence, whereas an explicit "not injected"
// tells them to go find out. This is the whole reason the zero value is "" and
// not "dev".
func TestStringSaysWhenNotInjected(t *testing.T) {
	defer restore(Version, Commit)
	Version, Commit = "", ""

	got := String()
	if !strings.Contains(got, "not injected") {
		t.Errorf("String() = %q, want it to state the build was not injected", got)
	}
	// Guard against a future edit substituting a fake default. None of these
	// may appear when nothing was injected.
	for _, fake := range []string{"0.0.0", "v0.0.0", "dev", "unknown", "(devel)"} {
		if strings.Contains(got, fake) {
			t.Errorf("String() = %q contains placeholder %q that reads like a real value", got, fake)
		}
	}
}

func TestStringReportsInjectedValues(t *testing.T) {
	defer restore(Version, Commit)
	Version, Commit = "0.0.1", "0123456789abcdef0123456789abcdef01234567"

	got := String()
	if !strings.Contains(got, "0.0.1") {
		t.Errorf("String() = %q, want it to contain the injected version", got)
	}
	if !strings.Contains(got, "0123456") {
		t.Errorf("String() = %q, want it to contain the injected commit", got)
	}
	if strings.Contains(got, "not injected") {
		t.Errorf("String() = %q claims not-injected despite both values being set", got)
	}
}

// A half-injected build is a real failure mode: one -X lands and the other is
// typo'd. It must not read as fully identified.
func TestStringHandlesPartialInjection(t *testing.T) {
	defer restore(Version, Commit)

	Version, Commit = "0.0.1", ""
	if got := String(); !strings.Contains(got, "not injected") {
		t.Errorf("version-only build: String() = %q, want the missing commit flagged", got)
	}

	Version, Commit = "", "0123456789abcdef"
	if got := String(); !strings.Contains(got, "not injected") {
		t.Errorf("commit-only build: String() = %q, want the missing version flagged", got)
	}
}

func restore(v, c string) { Version, Commit = v, c }
