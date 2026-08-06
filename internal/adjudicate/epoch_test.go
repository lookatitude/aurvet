// internal/adjudicate/epoch_test.go
package adjudicate

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

const goldenPath = fixtures + "/epochs.golden.json"

type goldenFile struct {
	SchemaVersion int                   `json:"schema_version"`
	History       map[string][]goldenAt `json:"history"`
}

type goldenAt struct {
	Epoch  int    `json:"epoch"`
	Digest string `json:"semantics_digest"`
}

// This is the "a test that fails is strong" half of task 8. A rule author who
// changes what a rule MATCHES ON changes its declared inputs, which changes the
// semantics digest, which no longer equals the recorded golden — so the change
// cannot land without editing this fixture, and editing it means appending a new
// epoch. A comment asking nicely would not survive a year of refactors.
//
// Note what this test is NOT relied upon for: staleness itself is enforced by
// comparing a record's semantics_digest against the live registry, so an author
// who changes inputs and forgets to bump the epoch still invalidates every
// bound suppression (TestChangedSemanticsWithoutAnEpochBumpIsStillStale). This
// fixture exists so the forgetting is visible, not so that safety depends on
// remembering.
func TestBuiltInEpochsMatchTheGoldenHistory(t *testing.T) {
	blob, err := os.ReadFile(filepath.Clean(goldenPath))
	if err != nil {
		t.Fatal(err)
	}
	var g goldenFile
	if err := json.Unmarshal(blob, &g); err != nil {
		t.Fatal(err)
	}
	if g.SchemaVersion != EpochGoldenSchema {
		t.Fatalf("golden schema_version = %d, want %d", g.SchemaVersion, EpochGoldenSchema)
	}

	decls := BuiltIn().All()
	if len(decls) == 0 {
		t.Fatal("the built-in epoch registry is empty")
	}
	if len(g.History) != len(decls) {
		t.Fatalf("golden covers %d rules, the registry declares %d: every declared rule needs a "+
			"history entry, and a removed rule must be removed from both", len(g.History), len(decls))
	}

	for _, s := range decls {
		hist, ok := g.History[s.RuleID]
		if !ok {
			t.Fatalf("rule %q has no epoch history; add {\"epoch\":1,\"semantics_digest\":...} to %s",
				s.RuleID, goldenPath)
		}
		if len(hist) != s.Epoch {
			t.Fatalf("rule %q is at epoch %d but its history has %d entries: an epoch is a step in "+
				"an append-only history, so epoch N needs exactly N entries", s.RuleID, s.Epoch, len(hist))
		}
		seen := map[string]bool{}
		for i, h := range hist {
			if h.Epoch != i+1 {
				t.Fatalf("rule %q history[%d] is epoch %d; epochs run 1..N with no gaps",
					s.RuleID, i, h.Epoch)
			}
			if seen[h.Digest] {
				t.Fatalf("rule %q reuses semantics digest %s across epochs: an epoch bump that does "+
					"not change matching semantics only invalidates suppressions for nothing",
					s.RuleID, h.Digest)
			}
			seen[h.Digest] = true
		}
		want := hist[len(hist)-1]
		got, err := s.Digest()
		if err != nil {
			t.Fatal(err)
		}
		if got != want.Digest {
			t.Fatalf("rule %q: matching inputs changed (digest %s, golden %s at epoch %d).\n"+
				"A change to matching SEMANTICS must bump fingerprint_epoch: set Epoch to %d in "+
				"epoch.go and append {\"epoch\":%d,\"semantics_digest\":%q} to %s. If the change was "+
				"cosmetic (severity, wording), it does not belong in Inputs at all.",
				s.RuleID, got, want.Digest, want.Epoch, s.Epoch+1, s.Epoch+1, got, goldenPath)
		}
	}
}

// Digest must ignore the order of the declared inputs (reordering a list is not
// a semantic change) and must ignore the epoch (or a bump would be
// indistinguishable from a semantics change, and the two carry different
// meanings for the operator).
func TestSemanticsDigestIgnoresInputOrderAndEpoch(t *testing.T) {
	a := Semantics{RuleID: "x", Epoch: 1, Inputs: []string{"beta", "alpha"}}
	b := Semantics{RuleID: "x", Epoch: 9, Inputs: []string{"alpha", "beta"}}
	da, err := a.Digest()
	if err != nil {
		t.Fatal(err)
	}
	db, err := b.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if da != db {
		t.Fatal("input order or epoch changed the semantics digest")
	}
	c := Semantics{RuleID: "y", Epoch: 1, Inputs: []string{"alpha", "beta"}}
	dc, err := c.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if dc == da {
		t.Fatal("two different rules share a semantics digest")
	}
	// A rule with no declared inputs has nothing to pin, so it is refused
	// rather than digested into a comfortable-looking constant.
	if _, err := (Semantics{RuleID: "z", Epoch: 1}).Digest(); err == nil {
		t.Fatal("a rule with no declared matching inputs was digested")
	}
}

func TestRegistryRefusesMalformedDeclarations(t *testing.T) {
	good := Semantics{RuleID: "x", Epoch: 1, Inputs: []string{"a"}}
	cases := map[string][]Semantics{
		"duplicate rule": {good, good},
		"empty rule id":  {{RuleID: "", Epoch: 1, Inputs: []string{"a"}}},
		"zero epoch":     {{RuleID: "x", Epoch: 0, Inputs: []string{"a"}}},
		"no inputs":      {{RuleID: "x", Epoch: 1}},
		"empty input":    {{RuleID: "x", Epoch: 1, Inputs: []string{""}}},
	}
	for name, decls := range cases {
		if _, err := NewRegistry(decls...); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
}

// TestScanReachableRulesAreDeclared pins the interaction between fingerprint
// epochs (P4 task 8) and bootstrap refusal (P4 task 7), which is easy to break
// from either side.
//
// `baseline init` refuses to write while unresolved criticals exist and requires
// each to be adjudicated with a recorded reason. But an undeclared rule cannot be
// adjudicated at all -- by design, since the registry fails closed. Put together,
// a SCAN-reachable rule with no declared epoch is a critical the operator is
// instructed to adjudicate and then refused permission to adjudicate, and
// bootstrap can never complete on a machine that produces one.
//
// The list is scan-reachable rules only. `review`/`install` rules (pkgbuild-*)
// are deliberately absent: they cannot block `baseline init`, which runs a scan.
// Adding a scan rule without an epoch declaration fails here rather than
// deadlocking a user's bootstrap.
func TestScanReachableRulesAreDeclared(t *testing.T) {
	reg := BuiltIn()
	scanReachable := []string{
		// P1-A / P1-B
		"aur-absent", "aur-orphaned", "aur-provenance", "aur-submitter-mismatch",
		"aur-tombstone", "integrity-coverage", "integrity-digest-mismatch",
		"integrity-link-target", "integrity-missing", "integrity-unowned-setuid",
		"hook-coverage", "local-db", "sync-coverage",
		// P1-C surfaces
		"unit-execstart-unowned", "unit-coverage",
		"wants-link-unowned-target", "wants-coverage",
		"hook-suppressed", "hook-unowned", "hook-dirs",
		"surface-preload-unowned", "surface-generator-unowned",
		"surface-profiled-unowned", "surface-autostart-unowned-exec",
		"surface-misc-coverage",
		// P1-C correlation -- the only rule in that phase reaching critical
		"correlated-cluster", "correlate-coverage",
		// P4 drift. Not raised by `scan` itself but by `baseline diff`/`verify`,
		// which is the same deadlock for the same reason: an operator told to
		// adjudicate a drift critical and then refused permission to. It is
		// listed here rather than in a second list because the property being
		// pinned is identical, and a rule that reaches an operator as a critical
		// is what matters -- not which subcommand printed it.
		"baseline-drift",
	}
	if missing := reg.Undeclared(scanReachable); len(missing) > 0 {
		t.Errorf("scan-reachable rules with no fingerprint epoch: %v\n"+
			"each is a critical `baseline init` would demand be adjudicated and then refuse to adjudicate; "+
			"declare it in builtIn and add its history entry to testdata/adjudicate/epochs.golden.json",
			missing)
	}
}
