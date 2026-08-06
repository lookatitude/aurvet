// Flag parity.
//
// completions_test.go keeps the SUBCOMMAND lists honest. Flags had no such
// guard, and it cost exactly what you would expect: `-tier` -- the flag that
// decides how much of each file aurvet actually verifies -- shipped in the
// binary and appeared in none of the three completion files nor the man page.
// Nothing noticed, because a flag missing from a completion looks like "no
// match" and a flag missing from a man page looks like a flag that does not
// exist.
//
// The registered set is DERIVED from the binary, not copied here: the test
// builds cmd/aurvet, asks it for `-h`, and reads the flag list Go's flag
// package prints by walking the very FlagSet run() constructs (PrintDefaults is
// VisitAll). A hand-copied list in this file would be the same failure one
// level up -- two lists that drift together and then certify each other.
package completions

import (
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// notUserVisible lists flags that are deliberately absent from the completions
// and the man page, each with the reason. It exists so that a
// deliberately-hidden flag and an undocumented-by-accident one cannot look the
// same. It is empty: every flag aurvet registers today is one an operator is
// meant to be able to find.
var notUserVisible = map[string]string{}

// docFiles are the four places a flag must appear. The failure message names
// them all, because someone who has just added a flag needs the list, not a
// diagnosis.
var docFiles = []string{
	"completions/aurvet.bash",
	"completions/_aurvet",
	"completions/aurvet.fish",
	"man/aurvet.1.scd",
}

// flagDefault matches the lines flag.PrintDefaults emits: exactly two spaces, a
// dash, the flag name. Continuation lines are indented with four spaces and a
// tab, so a description that begins with a dash cannot be mistaken for a flag.
var flagDefault = regexp.MustCompile(`(?m)^  -([A-Za-z0-9][A-Za-z0-9._-]*)`)

// registeredFlags returns every flag cmd/aurvet registers, by building it and
// reading its own usage output.
//
// It fails rather than skips when the toolchain is unavailable: a skip here
// would let the gate pass while checking nothing, which is the failure mode this
// file exists to prevent (INV-3 applied to our own tooling).
func registeredFlags(t *testing.T) []string {
	t.Helper()

	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("no go toolchain on PATH to build cmd/aurvet with (%v); this test cannot "+
			"derive the registered flag set, and a skip here would let the gate pass while "+
			"checking nothing", err)
	}

	bin := filepath.Join(t.TempDir(), "aurvet")
	build := exec.Command(goBin, "build", "-mod=vendor", "-o", bin, "../cmd/aurvet")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build cmd/aurvet: %v\n%s", err, out)
	}

	// `-h` is handled by flag itself: every flag is registered before Parse
	// runs, so the usage text is the complete set. The command exits 2 (usage),
	// which is expected and not an error here.
	out, _ := exec.Command(bin, "-h").CombinedOutput()
	if len(out) == 0 {
		t.Fatal("aurvet -h printed nothing; cannot derive the registered flag set")
	}

	var flags []string
	for _, m := range flagDefault.FindAllStringSubmatch(string(out), -1) {
		flags = append(flags, m[1])
	}
	if len(flags) == 0 {
		t.Fatalf("extracted zero flags from `aurvet -h`; the extractor is broken and every "+
			"assertion below would be vacuous. Output was:\n%s", out)
	}
	sort.Strings(flags)
	return flags
}

var (
	bashFlagList = regexp.MustCompile(`(?s)_aurvet_flags=\(([^)]*)\)`)
	zshFlagEntry = regexp.MustCompile(`'-([A-Za-z0-9][A-Za-z0-9._-]*)[\[\]]`)
	fishFlagLong = regexp.MustCompile(`(?m)-l\s+([A-Za-z0-9][A-Za-z0-9._-]*)`)
	manFlagEntry = regexp.MustCompile(`(?m)^\*-([A-Za-z0-9][A-Za-z0-9._-]*)\*`)
)

// betweenFlags returns the text between the flag-block markers, so a flag name
// mentioned in prose elsewhere in the file cannot satisfy the assertion.
func betweenFlags(t *testing.T, path, body string) string {
	t.Helper()
	const begin, end = "AURVET_FLAGS_BEGIN", "AURVET_FLAGS_END"
	i := strings.Index(body, begin)
	j := strings.Index(body, end)
	if i < 0 || j < 0 || j < i {
		t.Fatalf("%s: missing the %s/%s markers the flag extractor keys on", path, begin, end)
	}
	return body[i+len(begin) : j]
}

// documentedFlags returns the flags one documentation file actually offers.
func documentedFlags(t *testing.T, where string) []string {
	t.Helper()
	var out []string
	switch where {
	case "bash":
		const p = "aurvet.bash"
		block := betweenFlags(t, p, read(t, p))
		m := bashFlagList.FindStringSubmatch(block)
		if m == nil {
			t.Fatalf("%s: could not find the _aurvet_flags=(...) array", p)
		}
		for _, f := range strings.Fields(m[1]) {
			out = append(out, strings.TrimLeft(f, "-"))
		}
	case "zsh":
		const p = "_aurvet"
		block := betweenFlags(t, p, read(t, p))
		for _, m := range zshFlagEntry.FindAllStringSubmatch(block, -1) {
			out = append(out, m[1])
		}
	case "fish":
		const p = "aurvet.fish"
		block := betweenFlags(t, p, read(t, p))
		for _, m := range fishFlagLong.FindAllStringSubmatch(block, -1) {
			out = append(out, m[1])
		}
	case "man":
		const p = "../man/aurvet.1.scd"
		body := read(t, p)
		i := strings.Index(body, "# FLAGS")
		if i < 0 {
			t.Fatalf("%s: no FLAGS section to check", p)
		}
		section := body[i+len("# FLAGS"):]
		if j := strings.Index(section, "\n# "); j >= 0 {
			section = section[:j]
		}
		for _, m := range manFlagEntry.FindAllStringSubmatch(section, -1) {
			out = append(out, m[1])
		}
	default:
		t.Fatalf("unknown documentation target %q", where)
	}
	if len(out) == 0 {
		t.Fatalf("%s: extracted zero flags; the extractor is broken and every assertion "+
			"below would be vacuous", where)
	}
	sort.Strings(out)
	return out
}

// TestEveryFlagIsDocumentedEverywhere is the deliverable. If it fails you have
// added a flag to cmd/aurvet and stopped there: the flag exists in the binary
// and does not exist for anyone who has to discover it.
func TestEveryFlagIsDocumentedEverywhere(t *testing.T) {
	registered := registeredFlags(t)

	for _, where := range []string{"bash", "zsh", "fish", "man"} {
		t.Run(where, func(t *testing.T) {
			got := documentedFlags(t, where)
			have := make(map[string]bool, len(got))
			for _, f := range got {
				have[f] = true
			}
			for _, f := range registered {
				if reason, hidden := notUserVisible[f]; hidden {
					if have[f] {
						t.Errorf("-%s is listed in notUserVisible (%s) but is documented in "+
							"%s; either document it properly or remove the exclusion", f, reason, where)
					}
					continue
				}
				if !have[f] {
					t.Errorf("-%s is registered by cmd/aurvet but is missing from %s.\n"+
						"A flag must be documented in all four places or an operator cannot find it:\n"+
						"  %s\n"+
						"If it is deliberately not user-visible, add it to notUserVisible in this file "+
						"with the reason -- an undocumented-by-accident flag and a deliberately-hidden "+
						"one must not look the same.",
						f, where, strings.Join(docFiles, "\n  "))
				}
			}

			// The other direction: a documented flag the binary does not
			// register is a lie with a longer half-life than a missing one,
			// because the user tries it and gets a usage error.
			reg := make(map[string]bool, len(registered))
			for _, f := range registered {
				reg[f] = true
			}
			for _, f := range got {
				if !reg[f] {
					t.Errorf("%s documents -%s, which cmd/aurvet does not register; remove it "+
						"or add the flag", where, f)
				}
			}
		})
	}
}

// TestTierValuesAreOfferedEverywhere pins the one flag whose VALUES are a
// contract of their own: -tier chooses how much verification happens, and an
// operator offered a tier name that ParseTier refuses gets a usage error at the
// worst possible moment (a systemd unit, a cron line). The names come from
// internal/check's ParseTier.
func TestTierValuesAreOfferedEverywhere(t *testing.T) {
	tiers := []string{"meta", "triage", "full", "paranoid"}
	for _, f := range []string{"aurvet.bash", "_aurvet", "aurvet.fish", "../man/aurvet.1.scd"} {
		body := read(t, f)
		for _, tier := range tiers {
			if !strings.Contains(body, tier) {
				t.Errorf("%s: does not mention the -tier value %q", f, tier)
			}
		}
	}
}
