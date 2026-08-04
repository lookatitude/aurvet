package aur

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// Acceptance tests for the provenance tier, written from
// docs/interface-contracts-p1a.md rather than from http.go, and driven by the
// captured cgit pages in testdata/aur/cgit rather than hand-written HTML.
//
// They exist as an independent cross-check: the lane's own suite was written by
// the same agents that wrote the implementation, and the second adversarial
// re-attack never ran. These pin P1-A success criteria 2 and 3 directly -- a
// tombstoned package is critical, a package absent without a tombstone is not --
// plus the two regressions that cost the most if they ever return: hyphen-
// compounded malware nouns going undetected, and a real package name containing
// a malware word being accused.
func serveFixture(t *testing.T, path string) *HTTP {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(b)
	}))
	t.Cleanup(srv.Close)
	return NewHTTP(srv.URL, srv.Client())
}

func TestOrchRealTombstoneIsCritical(t *testing.T) {
	c := serveFixture(t, "../../testdata/aur/cgit/log-tombstoned-librewolf-fix-bin.html")
	present, msg, err := c.Tombstone(context.Background(), "librewolf-fix-bin")
	if err != nil || !present {
		t.Fatalf("present=%v msg=%q err=%v; want present with no error", present, msg, err)
	}
	if !IsMalwareRemoval(msg) {
		t.Errorf("IsMalwareRemoval(%q) = false; the real 2025 tombstone must reach critical", msg)
	}
}

func TestOrchRealPresentPackageIsNotFlagged(t *testing.T) {
	c := serveFixture(t, "../../testdata/aur/cgit/log-present-yay.html")
	present, msg, err := c.Tombstone(context.Background(), "yay")
	if present || err != nil {
		t.Errorf("live 50-commit package: present=%v msg=%q err=%v; want clean", present, msg, err)
	}
}

func TestOrch404PageIsNotACleanBill(t *testing.T) {
	c := serveFixture(t, "../../testdata/aur/cgit/log-404-nonexistent-branch.html")
	present, _, err := c.Tombstone(context.Background(), "nope")
	if err == nil {
		t.Errorf("non-cgit body: err=nil present=%v; absence of a log table must be an error, not 'no tombstone'", present)
	}
}

// R1: the hyphen guard must not silently discard compounded malware nouns.
func TestOrchHyphenCompoundsStillMalware(t *testing.T) {
	for _, s := range []string{
		"removed: trojan-dropper in the prebuilt binary",
		"history removed due to a malware-laden prebuilt binary",
		"removed: trojan-infected upstream tarball",
		"removed the backdoor-laced install hook",
		"removed: info-stealer in the vendored binary",
	} {
		if !IsMalwareRemoval(s) {
			t.Errorf("false assurance: IsMalwareRemoval(%q) = false", s)
		}
	}
}

// F6: real AUR package names containing malware words are administrative.
func TestOrchPackageNamesAreNotMalware(t *testing.T) {
	for _, s := range []string{
		"history removed due to merge into security-misc",
		"removed due to rename to arch-security-tools",
		"removed due to rename to malware-analysis-toolkit",
		"history removed due to merge into clamav-unofficial-sigs-malware-expert",
	} {
		if IsMalwareRemoval(s) {
			t.Errorf("false accusation: IsMalwareRemoval(%q) = true", s)
		}
	}
}

// R4: an ordinary commit mentioning malware, newest row of a live history,
// must not be adjudicated as a tombstone.
func TestOrchOrdinaryNewestCommitIsNotATombstone(t *testing.T) {
	b, err := os.ReadFile("../../testdata/aur/cgit/log-present-yay.html")
	if err != nil {
		t.Fatal(err)
	}
	page := strings.Replace(string(b), ">merge<", ">removed malware samples from the git history<", 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(page))
	}))
	defer srv.Close()
	present, msg, err := NewHTTP(srv.URL, srv.Client()).Tombstone(context.Background(), "malware-analysis-toolkit")
	if present && err == nil && IsMalwareRemoval(msg) {
		t.Errorf("false accusation: live 50-commit package reported as a malware tombstone (msg=%q)", msg)
	}
	t.Logf("live-history-with-malware-word: present=%v msg=%q err=%v", present, msg, err)
}
