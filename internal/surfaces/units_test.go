// internal/surfaces/units_test.go
package surfaces

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lookatitude/aurvet/internal/alpm"
	"github.com/lookatitude/aurvet/internal/finding"
	"github.com/lookatitude/aurvet/internal/fsx"
	"github.com/lookatitude/aurvet/internal/own"
)

// execRaws flattens the Exec values of one directive, in file order, so a test
// can assert both WHICH values were kept and in WHAT order -- ordering is part
// of the contract because systemd runs repeated ExecStart= in order.
func execRaws(u Unit, directive string) []string {
	var out []string
	for _, e := range u.Exec {
		if e.Directive == directive {
			out = append(out, e.Raw)
		}
	}
	return out
}

func execBins(u Unit, directive string) []string {
	var out []string
	for _, e := range u.Exec {
		if e.Directive == directive {
			out = append(out, e.Bin)
		}
	}
	return out
}

// TestParseUnitRepeatedAndPrefixedExecStart pins the two shapes the format
// really uses and a naive key=value parser gets wrong: ExecStart= repeats (a
// last-one-wins parser drops the earlier commands, and the earlier command is
// where a dropper would sit), and every value may carry systemd's prefix
// characters, which are not part of the path.
func TestParseUnitRepeatedAndPrefixedExecStart(t *testing.T) {
	data := []byte(`# comment
; also a comment
[Unit]
Description=fixture

[Service]
Type=oneshot
ExecStartPre=-/usr/bin/first --ignore-failure
ExecStart=@/usr/bin/second argv0-override
ExecStart=+/usr/bin/third
ExecStart=!!/usr/bin/fourth
ExecStart=-@/usr/bin/fifth
`)
	u, err := ParseUnit("fixture.service", data)
	if err != nil {
		t.Fatalf("ParseUnit: %v", err)
	}
	wantBins := []string{"/usr/bin/second", "/usr/bin/third", "/usr/bin/fourth", "/usr/bin/fifth"}
	got := execBins(u, "ExecStart")
	if strings.Join(got, ",") != strings.Join(wantBins, ",") {
		t.Errorf("ExecStart bins = %v, want %v", got, wantBins)
	}
	if pre := execBins(u, "ExecStartPre"); len(pre) != 1 || pre[0] != "/usr/bin/first" {
		t.Errorf("ExecStartPre bins = %v, want [/usr/bin/first]", pre)
	}
	for _, e := range u.Exec {
		if strings.ContainsAny(e.Bin, "-@+!") {
			t.Errorf("%s: Bin %q still carries a prefix character; the prefix is not part of the path",
				e.Directive, e.Bin)
		}
		if !e.Resolvable {
			t.Errorf("%s: %q reported unresolvable (%s), want a concrete path", e.Directive, e.Raw, e.Unresolvable)
		}
	}
	if u.Type != "oneshot" {
		t.Errorf("Type = %q, want oneshot", u.Type)
	}
}

// TestParseUnitLineContinuation covers the trailing-backslash continuation. A
// parser that does not join the lines sees "ExecStart=/usr/bin/tool" and misses
// the arguments -- and, worse, sees the continuation line as a bare line it
// silently discards.
func TestParseUnitLineContinuation(t *testing.T) {
	data := []byte("[Service]\n" +
		"ExecStart=/usr/bin/tool \\\n" +
		"    --flag one \\\n" +
		"    --flag two\n")
	u, err := ParseUnit("cont.service", data)
	if err != nil {
		t.Fatalf("ParseUnit: %v", err)
	}
	raws := execRaws(u, "ExecStart")
	if len(raws) != 1 {
		t.Fatalf("ExecStart values = %v, want exactly 1 joined value", raws)
	}
	want := "/usr/bin/tool --flag one --flag two"
	if raws[0] != want {
		t.Errorf("joined ExecStart = %q, want %q", raws[0], want)
	}
	if got := u.Exec[0].Args; len(got) != 5 {
		t.Errorf("Args = %v, want 5 tokens", got)
	}
}

// TestParseUnitEmptyValueResetsTheList is systemd's reset semantics. It matters
// in the suppression direction: a drop-in whose "ExecStart=" empties the list
// disables what the packaged unit ran, and a parser that appends instead of
// resetting reports a command that no longer executes.
func TestParseUnitEmptyValueResetsTheList(t *testing.T) {
	data := []byte("[Service]\nExecStart=/usr/bin/original\nExecStart=\nExecStart=/usr/bin/replacement\n")
	u, err := ParseUnit("reset.service", data)
	if err != nil {
		t.Fatalf("ParseUnit: %v", err)
	}
	bins := execBins(u, "ExecStart")
	if len(bins) != 1 || bins[0] != "/usr/bin/replacement" {
		t.Fatalf("ExecStart bins = %v, want [/usr/bin/replacement]", bins)
	}
	if !hasNote(u, "reset") {
		t.Errorf("a reset was applied but no note records it; notes = %v", u.Notes)
	}
}

// TestParseUnitWithoutExecStartReportsNothing guards the phantom the cruft
// fixture warns about: a .timer and a .socket have no ExecStart, and a parser
// that assumes one invents a subject.
func TestParseUnitWithoutExecStartReportsNothing(t *testing.T) {
	data := []byte("[Unit]\nDescription=t\n\n[Timer]\nOnCalendar=daily\nUnit=foo-sync.service\n\n[Install]\nWantedBy=timers.target\n")
	u, err := ParseUnit("foo.timer", data)
	if err != nil {
		t.Fatalf("ParseUnit: %v", err)
	}
	if len(u.Exec) != 0 {
		t.Errorf("Exec = %+v, want none: a timer activates a unit, it does not exec", u.Exec)
	}
	if len(u.WantedBy) != 1 || u.WantedBy[0] != "timers.target" {
		t.Errorf("WantedBy = %v, want [timers.target]", u.WantedBy)
	}
}

// TestParseUnitMarksShapesItCannotResolve is INV-6 at the parser level: a
// directive this parser cannot pin to one concrete file must say so, because a
// value silently mis-parsed is a check that silently goes quiet.
func TestParseUnitMarksShapesItCannotResolve(t *testing.T) {
	cases := []struct {
		name string
		line string
		want string // substring of Unresolvable
	}{
		{"specifier", "ExecStart=/usr/lib/%p/agent", "specifier"},
		{"variable", "ExecStart=${ROOTDIR}/agent", "variable"},
		{"relative", "ExecStart=agent --serve", "not absolute"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			u, err := ParseUnit("x.service", []byte("[Service]\n"+c.line+"\n"))
			if err != nil {
				t.Fatalf("ParseUnit: %v", err)
			}
			if len(u.Exec) != 1 {
				t.Fatalf("Exec = %+v, want 1 value", u.Exec)
			}
			e := u.Exec[0]
			if e.Resolvable {
				t.Fatalf("%q reported resolvable; it names no concrete file", c.line)
			}
			if !strings.Contains(e.Unresolvable, c.want) {
				t.Errorf("Unresolvable = %q, want it to mention %q", e.Unresolvable, c.want)
			}
		})
	}
}

// TestParseUnitRecordsIncludeAsUnparsed pins that the one directive which can
// pull in arbitrary other content is recorded rather than ignored.
func TestParseUnitRecordsIncludeAsUnparsed(t *testing.T) {
	u, err := ParseUnit("inc.service", []byte("[Service]\n.include /etc/systemd/hidden.conf\nExecStart=/usr/bin/tool\n"))
	if err != nil {
		t.Fatalf("ParseUnit: %v", err)
	}
	if !hasUnparsed(u, ".include") {
		t.Errorf("unparsed = %v, want one naming .include -- an unread include is a coverage gap, not a silence",
			u.Unparsed)
	}
}

func hasNote(u Unit, substr string) bool { return containsSubstr(u.Notes, substr) }

// hasUnparsed is deliberately a DIFFERENT question from hasNote. A note is
// something the parser modelled and carries as evidence (an applied reset); an
// unparsed entry is a shape it did not model, and only that becomes a coverage
// gap. Collapsing the two would either bury a real gap among notes or turn every
// modelled quirk into a spurious gap.
func hasUnparsed(u Unit, substr string) bool { return containsSubstr(u.Unparsed, substr) }

func containsSubstr(hay []string, substr string) bool {
	for _, n := range hay {
		if strings.Contains(n, substr) {
			return true
		}
	}
	return false
}

// unitTree materializes a unit directory at runtime. Runtime rather than
// checked in because the shapes that matter here -- an oversized file, a
// drop-in directory, a unit reached only through a symlink -- are either
// unstorable in git or noise in a shared fixture.
func unitTree(t *testing.T, files map[string]string, links map[string]string) *os.Root {
	t.Helper()
	tmp := t.TempDir()
	for rel, content := range files {
		p := filepath.Join(tmp, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for rel, target := range links {
		p := filepath.Join(tmp, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, p); err != nil {
			t.Fatal(err)
		}
	}
	root, err := os.OpenRoot(tmp)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	return root
}

// TestLoadUnitsAppliesDropIns is the attack this covers: a packaged unit is
// extended by an unowned foo.service.d/*.conf, so the unit file's own digest
// verifies and the added command lives in a file nobody looked at.
func TestLoadUnitsAppliesDropIns(t *testing.T) {
	root := unitTree(t, map[string]string{
		"usr/lib/systemd/system/foo.service":                 "[Service]\nExecStart=/usr/bin/foo\n",
		"usr/lib/systemd/system/foo.service.d/10-extra.conf": "[Service]\nExecStart=/usr/local/bin/extra\n",
		"usr/lib/systemd/system/bar.service":                 "[Service]\nExecStart=/usr/bin/bar\n",
		"usr/lib/systemd/system/bar.service.d/20-off.conf":   "[Service]\nExecStart=\n",
	}, nil)

	units, gaps := LoadUnits(fsx.Live(root), []string{"usr/lib/systemd/system"})
	if len(gaps) != 0 {
		t.Fatalf("unexpected gaps: %+v", gaps)
	}
	byName := map[string]Unit{}
	for _, u := range units {
		byName[u.Name] = u
	}
	foo, ok := byName["foo.service"]
	if !ok {
		t.Fatalf("foo.service not loaded; loaded %v", units)
	}
	if got := execBins(foo, "ExecStart"); len(got) != 2 || got[1] != "/usr/local/bin/extra" {
		t.Errorf("foo.service ExecStart bins = %v, want the drop-in command appended", got)
	}
	if len(foo.DropIns) != 1 || !strings.HasSuffix(foo.DropIns[0], "10-extra.conf") {
		t.Errorf("DropIns = %v, want the drop-in recorded as evidence", foo.DropIns)
	}
	bar := byName["bar.service"]
	if got := execBins(bar, "ExecStart"); len(got) != 0 {
		t.Errorf("bar.service ExecStart bins = %v, want none: the drop-in reset the list", got)
	}
}

// TestLoadUnitsUnreadableDirectoryIsAGap is INV-9. An absent unit directory is
// ordinary (/run/systemd/system does not exist in an offline root) and says
// nothing; anything else means the unit set is unknown, and an unknown unit set
// must not read as a clean one.
func TestLoadUnitsUnreadableDirectoryIsAGap(t *testing.T) {
	root := unitTree(t, map[string]string{
		"etc/systemd/system/keep.service": "[Service]\nExecStart=/usr/bin/keep\n",
		"usr/lib/systemd/system":          "not a directory\n",
	}, nil)

	units, gaps := LoadUnits(fsx.Live(root), []string{"etc/systemd/system", "usr/lib/systemd/system", "run/systemd/system"})
	if len(units) != 1 {
		t.Errorf("units = %v, want the one readable unit", units)
	}
	if len(gaps) != 1 {
		t.Fatalf("gaps = %+v, want exactly 1 (ENOTDIR); an ABSENT dir must not be a gap", gaps)
	}
	if gaps[0].Subject != "usr/lib/systemd/system" {
		t.Errorf("gap subject = %q, want usr/lib/systemd/system", gaps[0].Subject)
	}
}

// TestLoadUnitsOversizeFileIsAGapNotATruncation: a truncated parse is a parse
// that can miss the last ExecStart, which is indistinguishable from a unit that
// never had one.
func TestLoadUnitsOversizeFileIsAGapNotATruncation(t *testing.T) {
	big := "[Service]\n" + strings.Repeat("# padding\n", (maxUnitFileBytes/10)+1) + "ExecStart=/usr/bin/hidden\n"
	root := unitTree(t, map[string]string{"etc/systemd/system/big.service": big}, nil)

	units, gaps := LoadUnits(fsx.Live(root), []string{"etc/systemd/system"})
	if len(units) != 0 {
		t.Errorf("units = %v, want none: an oversize unit is refused, not truncated", units)
	}
	if len(gaps) != 1 || !strings.Contains(gaps[0].Reason, "larger") {
		t.Fatalf("gaps = %+v, want one naming the size limit", gaps)
	}
}

// TestLoadUnitsSymlinkedUnitOutsideTheSearchPathIsAGap: /etc/systemd/system
// entries are frequently symlinks, and a link into a directory this scan never
// reads leaves an ExecStart unexamined. Silence there is exactly what INV-9
// forbids.
func TestLoadUnitsSymlinkedUnitOutsideTheSearchPathIsAGap(t *testing.T) {
	root := unitTree(t,
		map[string]string{
			"usr/lib/systemd/system/in.service": "[Service]\nExecStart=/usr/bin/in\n",
			"opt/vendor/out.service":            "[Service]\nExecStart=/opt/vendor/out\n",
		},
		map[string]string{
			"etc/systemd/system/in.service":  "/usr/lib/systemd/system/in.service",
			"etc/systemd/system/out.service": "/opt/vendor/out.service",
		})

	units, gaps := LoadUnits(fsx.Live(root), []string{"usr/lib/systemd/system", "etc/systemd/system"})
	if len(units) != 1 || units[0].Name != "in.service" {
		t.Errorf("units = %v, want just in.service (parsed once, at its real location)", units)
	}
	if len(gaps) != 1 || !strings.Contains(gaps[0].Subject, "out.service") {
		t.Fatalf("gaps = %+v, want one for the unit linked out of the search path", gaps)
	}
}

// ownersFor builds the ownership oracle for a fixture root the way a real scan
// does: from that root's own local DB, resolving against that root.
func ownersFor(t *testing.T, name string) (*os.Root, *own.Owners) {
	t.Helper()
	dir := filepath.Join("..", "..", "testdata", "roots", name)
	pkgs, dbGaps, err := alpm.LoadLocalDB(filepath.Join(dir, "var", "lib", "pacman", "local"))
	if err != nil {
		t.Fatalf("LoadLocalDB(%s): %v", name, err)
	}
	if len(dbGaps) != 0 {
		t.Fatalf("%s: unreadable local DB entries %v", name, dbGaps)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	owners := own.IndexIn(fsx.Live(root), pkgs)
	if owners.Len() == 0 {
		t.Fatalf("%s: empty ownership index; every 'unowned' assertion would pass vacuously", name)
	}
	return root, owners
}

// TestUnitFindingsOnFixtureRoots is the INV-8 gate for this surface. stock must
// be silent while still having examined something; cruft's one hand-written unit
// is suspicious and never critical (it is a backup script, and the tool cannot
// tell that from malware); malicious names its inert marker.
//
// Rule and severity are asserted alongside the subject, not just the subject.
// Two rules now share this surface and they carry different weight: an unowned
// file that EXISTS is suspicious, while an unclaimed bare name in a directory
// only its owner can write is info. Collapsing them into a subject list would
// let either quietly become the other.
//
// stock's `ExecStartPre=-fooplymouth` and cruft's `ExecStop=sysutil_ioctl ...`
// are the two shapes measured on the reference system, where 8 unit-coverage
// gaps decomposed into 6 of the first and 2 of the second. Neither may produce a
// gap here: no expected-gap entry exists because the expected count is zero.
func TestUnitFindingsOnFixtureRoots(t *testing.T) {
	type want struct {
		rule    string
		subject string
		sev     finding.Severity
	}
	cases := []struct {
		root      string
		wantUnits int
		findings  []want
	}{
		// One unit, one `-`-prefixed bare command that resolves to nothing, and
		// nothing to say about it.
		{"stock", 1, nil},
		{"cruft", 20, []want{
			// The packaged unit with the unclaimed bare ExecStop. Every
			// search-path directory in this root is mode 0755, so planting the
			// name already needs the owner's privileges: info.
			{RuleUnitExecHijackable, "usr/lib/systemd/system/sysutil-modules.service", finding.SevInfo},
			// The hand-written admin unit running an unowned binary that is
			// really there.
			{RuleUnitExecUnowned, "etc/systemd/system/local-backup.service", finding.SevSuspicious},
		}},
		{"malicious", 2, []want{
			{RuleUnitExecUnowned, "etc/systemd/system/systemd-initd-inert.service", finding.SevSuspicious},
		}},
	}
	for _, c := range cases {
		t.Run(c.root, func(t *testing.T) {
			root, owners := ownersFor(t, c.root)
			units, gaps := LoadUnits(fsx.Live(root), DefaultUnitDirs)
			if len(gaps) != 0 {
				t.Errorf("%s: unexpected load gaps %+v", c.root, gaps)
			}
			if len(units) != c.wantUnits {
				t.Errorf("%s: loaded %d units, want %d (a rule that examined nothing is not a silent rule)",
					c.root, len(units), c.wantUnits)
			}
			findings, fgaps := UnitFindings(fsx.Live(root), units, owners)
			if len(fgaps) != 0 {
				t.Errorf("%s: unexpected ownership gaps %+v; the `-` prefix and an unfound bare command "+
					"are both determinate answers, not gaps", c.root, fgaps)
			}
			var got, wantLines []string
			for _, f := range findings {
				got = append(got, fmt.Sprintf("%s %s %v", f.RuleID, f.Subject, f.Severity))
				if f.Severity == finding.SevCritical {
					t.Errorf("%s: %s is critical; only a cluster may reach critical", c.root, f.Subject)
				}
				if f.Limits == "" {
					t.Errorf("%s: finding %s carries no Limits (INV-6)", c.root, f.Subject)
				}
			}
			for _, w := range c.findings {
				wantLines = append(wantLines, fmt.Sprintf("%s %s %v", w.rule, w.subject, w.sev))
			}
			if strings.Join(got, "\n") != strings.Join(wantLines, "\n") {
				t.Errorf("%s findings:\n got %v\nwant %v", c.root, got, wantLines)
			}
		})
	}
}

// TestUnitFindingsLimitsNameTheBlindSpot: the phase's honesty requirement is a
// property of the OUTPUT, not of the documentation. A user who reads only the
// finding must learn that a clean result was not earned.
func TestUnitFindingsLimitsNameTheBlindSpot(t *testing.T) {
	root, owners := ownersFor(t, "malicious")
	units, _ := LoadUnits(fsx.Live(root), DefaultUnitDirs)
	findings, _ := UnitFindings(fsx.Live(root), units, owners)
	if len(findings) == 0 {
		t.Fatal("no findings on the malicious root; nothing to inspect")
	}
	lim := strings.ToLower(findings[0].Limits)
	for _, want := range []string{"pkgdir", "silent"} {
		if !strings.Contains(lim, want) {
			t.Errorf("Limits does not mention %q: %q", want, findings[0].Limits)
		}
	}
}

// TestUnitFindingsUnresolvedOwnershipIsAGap: own.Unresolved must never become a
// finding. A symlink loop under the ExecStart path is a permission-shaped
// unknown, and reporting it as unowned invents a finding out of an unknown.
func TestUnitFindingsUnresolvedOwnershipIsAGap(t *testing.T) {
	tmp := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tmp, "usr/bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("loopb", filepath.Join(tmp, "usr/bin/loopa")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("loopa", filepath.Join(tmp, "usr/bin/loopb")); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(tmp)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	owners := own.IndexIn(fsx.Live(root), []alpm.Package{{Name: "coreutils", Files: []string{"usr/bin/true"}}})

	units := []Unit{{
		Path: "etc/systemd/system/loop.service",
		Name: "loop.service",
		Exec: []Exec{{Directive: "ExecStart", Raw: "/usr/bin/loopa", Bin: "/usr/bin/loopa", Resolvable: true}},
	}}
	findings, gaps := UnitFindings(fsx.Live(root), units, owners)
	if len(findings) != 0 {
		t.Errorf("findings = %+v, want none: an unresolvable path is a gap, not an accusation", findings)
	}
	if len(gaps) != 1 {
		t.Fatalf("gaps = %+v, want exactly 1", gaps)
	}
	if !strings.Contains(gaps[0].Reason, "loopa") {
		t.Errorf("gap reason %q does not name the path it could not resolve", gaps[0].Reason)
	}
}

// TestUnitFindingsUnresolvableExecValueIsAGap: a value carrying a specifier or a
// variable names no file, so ownership cannot be asked. That is a gap too --
// otherwise a unit whose ExecStart is "${X}/rat" reads as clean.
func TestUnitFindingsUnresolvableExecValueIsAGap(t *testing.T) {
	root, owners := ownersFor(t, "stock")
	units := []Unit{{
		Path: "etc/systemd/system/tmpl@.service",
		Name: "tmpl@.service",
		Exec: []Exec{{Directive: "ExecStart", Raw: "/usr/lib/%p/agent", Bin: "/usr/lib/%p/agent",
			Unresolvable: "value contains a systemd specifier, which this parser does not expand"}},
	}}
	findings, gaps := UnitFindings(fsx.Live(root), units, owners)
	if len(findings) != 0 {
		t.Errorf("findings = %+v, want none", findings)
	}
	if len(gaps) != 1 || !strings.Contains(gaps[0].Reason, "specifier") {
		t.Fatalf("gaps = %+v, want one naming the unexpanded specifier", gaps)
	}
}

// TestLoadUnitsIsPureOverTheRoot: INV-4. Two loads of the same root from
// different working directories must agree, and neither may consult an ambient
// path. Chdir is the cheapest way to prove no relative path leaks in.
func TestLoadUnitsIsPureOverTheRoot(t *testing.T) {
	dir, err := filepath.Abs(filepath.Join("..", "..", "testdata", "roots", "cruft"))
	if err != nil {
		t.Fatal(err)
	}
	load := func() []Unit {
		root, err := os.OpenRoot(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		units, gaps := LoadUnits(fsx.Live(root), DefaultUnitDirs)
		if len(gaps) != 0 {
			t.Fatalf("gaps: %+v", gaps)
		}
		return units
	}
	before := load()
	t.Chdir(t.TempDir())
	after := load()
	if len(before) != len(after) {
		t.Fatalf("unit count changed with the process CWD: %d then %d", len(before), len(after))
	}
	for i := range before {
		if before[i].Path != after[i].Path {
			t.Fatalf("unit %d differs: %q then %q", i, before[i].Path, after[i].Path)
		}
	}
}

// TestParseUnitRejectsNUL keeps the one input that makes a path mean two things.
func TestParseUnitRejectsNUL(t *testing.T) {
	_, err := ParseUnit("nul.service", []byte("[Service]\nExecStart=/usr/bin/a\x00b\n"))
	if !errors.Is(err, ErrUnparseable) {
		t.Errorf("err = %v, want ErrUnparseable", err)
	}
}

// TestUnitFindingsAbsentCommandIsInfoNotSuspicious is the reference system's
// dominant false positive: a PACKAGED unit naming a binary from a package that
// is not installed (systemd's quotaon-root.service names /usr/bin/quotaon, and
// quota-tools is optional). Nothing can run from a path holding no file, so the
// finding is kept -- never dropped -- and rated info.
func TestUnitFindingsAbsentCommandIsInfoNotSuspicious(t *testing.T) {
	root := unitTree(t, map[string]string{
		"usr/lib/systemd/system/absent.service":  "[Service]\nExecStart=/usr/bin/quotaon -ug /\n",
		"usr/lib/systemd/system/present.service": "[Service]\nExecStart=/usr/local/bin/really-here\n",
		"usr/local/bin/really-here":              "inert marker, not a payload\n",
	}, nil)
	owners := own.IndexIn(fsx.Live(root), []alpm.Package{{Name: "systemd", Files: []string{
		"usr/lib/systemd/system/absent.service", "usr/lib/systemd/system/present.service",
	}}})

	units, gaps := LoadUnits(fsx.Live(root), []string{"usr/lib/systemd/system"})
	if len(gaps) != 0 {
		t.Fatalf("gaps = %+v, want none", gaps)
	}
	findings, fgaps := UnitFindings(fsx.Live(root), units, owners)
	if len(fgaps) != 0 {
		t.Fatalf("ownership gaps = %+v, want none", fgaps)
	}
	sev := map[string]finding.Severity{}
	for _, f := range findings {
		sev[f.Subject] = f.Severity
	}
	if got, ok := sev["usr/lib/systemd/system/absent.service"]; !ok || got != finding.SevInfo {
		t.Errorf("absent command reported as %v (reported at all=%v), want info and NOT dropped", got, ok)
	}
	if got := sev["usr/lib/systemd/system/present.service"]; got != finding.SevSuspicious {
		t.Errorf("existing unowned command reported as %v, want suspicious", got)
	}
}

// TestUnitFindingsResolvesBareCommandAgainstTheSearchPath: systemd's own units
// really do say `ExecStart=ldconfig -X`. Treating that as an unattributable value
// produced ~80 coverage gaps on the reference system, which under INV-3 makes
// every live run incomplete and buries the gaps that mean something.
//
// The walk stops at the first PRESENT candidate, not the first owned one: a name
// planted in /usr/local/bin shadows the packaged /usr/bin copy, and stopping at
// the owned one would report the packaged file and miss the shadow entirely.
func TestUnitFindingsResolvesBareCommandAgainstTheSearchPath(t *testing.T) {
	root := unitTree(t, map[string]string{
		"usr/lib/systemd/system/bare.service":   "[Service]\nExecStart=ldconfig -X\n",
		"usr/lib/systemd/system/shadow.service": "[Service]\nExecStart=helper --run\n",
		"usr/bin/ldconfig":                      "inert\n",
		"usr/bin/helper":                        "inert\n",
		"usr/local/bin/helper":                  "inert marker, not a payload\n",
	}, nil)
	owners := own.IndexIn(fsx.Live(root), []alpm.Package{{Name: "glibc", Files: []string{
		"usr/bin/ldconfig", "usr/bin/helper",
	}}})

	units, _ := LoadUnits(fsx.Live(root), []string{"usr/lib/systemd/system"})
	findings, gaps := UnitFindings(fsx.Live(root), units, owners)
	if len(gaps) != 0 {
		t.Fatalf("gaps = %+v, want none: a bare name IS attributable once a root is in hand", gaps)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %+v, want exactly 1 (the shadowed helper)", findings)
	}
	f := findings[0]
	if f.Subject != "usr/lib/systemd/system/shadow.service" {
		t.Errorf("subject = %q, want the unit whose bare name resolves to the unowned shadow", f.Subject)
	}
	if !strings.Contains(f.Summary, "/usr/local/bin/helper") {
		t.Errorf("summary = %q, want it to name /usr/local/bin/helper -- the file that would actually run",
			f.Summary)
	}
}

// TestUnitFindingsUnfoundBareCommandIsAHijackableFinding: a bare name that
// resolves to nothing is NOT a coverage gap. The check ran and got a determinate
// answer -- systemd will resolve the name at runtime against a search path in
// which nothing holds it -- and that answer is a hole an attacker can fill. The
// unit file's own digest still verifies afterwards, because the unit was never
// modified; the only thing that changed is a file appearing in a directory.
func TestUnitFindingsUnfoundBareCommandIsAHijackableFinding(t *testing.T) {
	root := unitTree(t, map[string]string{
		"usr/lib/systemd/system/nowhere.service": "[Service]\nExecStop=nowhere-at-all --run\n",
		"usr/bin/keep":                           "inert\n",
	}, nil)
	owners := own.IndexIn(fsx.Live(root), []alpm.Package{{Name: "systemd", Files: []string{
		"usr/lib/systemd/system/nowhere.service", "usr/bin/keep",
	}}})
	units, _ := LoadUnits(fsx.Live(root), []string{"usr/lib/systemd/system"})
	findings, gaps := UnitFindings(fsx.Live(root), units, owners)
	if len(gaps) != 0 {
		t.Errorf("gaps = %+v, want none: an unfound bare command is a determinate answer, not an "+
			"inability to look", gaps)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %+v, want exactly 1", findings)
	}
	f := findings[0]
	if f.RuleID != RuleUnitExecHijackable {
		t.Errorf("rule = %q, want %q", f.RuleID, RuleUnitExecHijackable)
	}
	if f.Subject != "usr/lib/systemd/system/nowhere.service" {
		t.Errorf("subject = %q, want the unit holding the directive", f.Subject)
	}
	// Every search-path directory in this tree is 0755 and owned by the test
	// user, so nothing but that user can plant the name: visible, not alarming.
	if f.Severity != finding.SevInfo {
		t.Errorf("severity = %v, want info when no search-path directory is writable by a "+
			"non-owner", f.Severity)
	}
	ev := strings.Join(f.Evidence, "\n")
	for _, want := range []string{
		"ExecStop",             // the directive
		"nowhere-at-all",       // the bare name
		"usr/local/sbin",       // the search path consulted, in order
		"usr/bin",              // the directory that would win
		"would be found first", // ...said as such
	} {
		if !strings.Contains(ev, want) {
			t.Errorf("evidence does not mention %q:\n%s", want, ev)
		}
	}
	if !strings.Contains(strings.ToLower(f.Limits), "runtime") {
		t.Errorf("Limits does not say resolution happens at runtime (INV-6): %q", f.Limits)
	}
}

// TestUnitFindingsHijackableWinnerIsTheFirstDirectoryTHATEXISTS: the search path
// is consulted in order, and a directory absent from the root cannot receive a
// file without also being created. Naming the first entry unconditionally would
// tell an operator to inspect a directory that is not there.
func TestUnitFindingsHijackableWinnerIsTheFirstDirectoryTHATEXISTS(t *testing.T) {
	root := unitTree(t, map[string]string{
		"usr/lib/systemd/system/hole.service": "[Service]\nExecStart=absent-helper\n",
		"usr/local/bin/other":                 "inert\n",
		"usr/bin/other":                       "inert\n",
	}, nil)
	owners := own.IndexIn(fsx.Live(root), []alpm.Package{{Name: "systemd", Files: []string{
		"usr/lib/systemd/system/hole.service",
	}}})
	units, _ := LoadUnits(fsx.Live(root), []string{"usr/lib/systemd/system"})
	findings, _ := UnitFindings(fsx.Live(root), units, owners)
	if len(findings) != 1 {
		t.Fatalf("findings = %+v, want exactly 1", findings)
	}
	ev := strings.Join(findings[0].Evidence, "\n")
	if !strings.Contains(ev, "usr/local/bin/absent-helper") {
		t.Errorf("evidence does not name usr/local/bin as the winner (usr/local/sbin does not exist "+
			"in this root):\n%s", ev)
	}
}

// TestUnitFindingsHijackableIsSuspiciousWhenTheWinnerIsGroupOrWorldWritable is
// the severity argument made from the evidence rather than from a prior. A
// root-only-writable directory needs root to plant the file, and an attacker who
// already has root does not need this hole; a directory a non-root user can
// write is a privilege boundary this hole crosses.
func TestUnitFindingsHijackableIsSuspiciousWhenTheWinnerIsGroupOrWorldWritable(t *testing.T) {
	root := unitTree(t, map[string]string{
		"usr/lib/systemd/system/hole.service": "[Service]\nExecStart=absent-helper\n",
		"usr/local/bin/other":                 "inert\n",
	}, nil)
	owners := own.IndexIn(fsx.Live(root), []alpm.Package{{Name: "systemd", Files: []string{
		"usr/lib/systemd/system/hole.service",
	}}})
	// git cannot store this mode, so it is a runtime chmod (see the fixture
	// READMEs); 0777 is what a careless `install -d` or an unpacked tarball
	// leaves behind.
	if err := os.Chmod(filepath.Join(root.Name(), "usr/local/bin"), 0o777); err != nil {
		t.Fatal(err)
	}
	units, _ := LoadUnits(fsx.Live(root), []string{"usr/lib/systemd/system"})
	findings, _ := UnitFindings(fsx.Live(root), units, owners)
	if len(findings) != 1 {
		t.Fatalf("findings = %+v, want exactly 1", findings)
	}
	if findings[0].Severity != finding.SevSuspicious {
		t.Errorf("severity = %v, want suspicious: a non-root user can plant the name in the "+
			"directory that wins", findings[0].Severity)
	}
	if !containsSubstr(findings[0].Evidence, "writable") {
		t.Errorf("evidence does not say the winning directory is writable: %v", findings[0].Evidence)
	}
}

// TestUnitFindingsOptionalPrefixOnAnAbsentBareCommandIsSilent: six of the eight
// unit-coverage gaps measured on the reference system were
// `ExecStartPre=-plymouth --wait quit` in systemd's own units. The `-` is the
// unit author saying the command may be absent and its failure is ignored. The
// check RAN and got a determinate answer; reporting that as "could not be
// examined" is false, and INV-9 cuts both ways.
func TestUnitFindingsOptionalPrefixOnAnAbsentBareCommandIsSilent(t *testing.T) {
	root := unitTree(t, map[string]string{
		"usr/lib/systemd/system/rescue.service": "[Service]\nExecStartPre=-plymouth --wait quit\n" +
			"ExecStart=/usr/bin/rescue\n",
		"usr/bin/rescue": "inert\n",
	}, nil)
	owners := own.IndexIn(fsx.Live(root), []alpm.Package{{Name: "systemd", Files: []string{
		"usr/lib/systemd/system/rescue.service", "usr/bin/rescue",
	}}})
	units, _ := LoadUnits(fsx.Live(root), []string{"usr/lib/systemd/system"})
	findings, gaps := UnitFindings(fsx.Live(root), units, owners)
	if len(findings) != 0 || len(gaps) != 0 {
		t.Fatalf("findings = %+v, gaps = %+v; want neither for a documented optional dependency "+
			"that is absent", findings, gaps)
	}
}

// TestUnitFindingsOptionalPrefixIsNotAFreePass: `-` says "failure is ignored",
// not "this command is uninteresting". A command that DOES resolve is subject to
// the ordinary ownership verdict, or an attacker gets an exemption for the price
// of one character.
func TestUnitFindingsOptionalPrefixIsNotAFreePass(t *testing.T) {
	root := unitTree(t, map[string]string{
		"usr/lib/systemd/system/abs.service":  "[Service]\nExecStartPre=-/usr/local/bin/evil-inert\n",
		"usr/lib/systemd/system/bare.service": "[Service]\nExecStartPre=-evil-inert-bare\n",
		"usr/local/bin/evil-inert":            "inert marker, not a payload\n",
		"usr/local/bin/evil-inert-bare":       "inert marker, not a payload\n",
	}, nil)
	owners := own.IndexIn(fsx.Live(root), []alpm.Package{{Name: "systemd", Files: []string{
		"usr/lib/systemd/system/abs.service", "usr/lib/systemd/system/bare.service",
	}}})
	units, _ := LoadUnits(fsx.Live(root), []string{"usr/lib/systemd/system"})
	findings, gaps := UnitFindings(fsx.Live(root), units, owners)
	if len(gaps) != 0 {
		t.Errorf("gaps = %+v, want none", gaps)
	}
	if len(findings) != 2 {
		t.Fatalf("findings = %+v, want 2: both the absolute and the bare `-` command resolve to an "+
			"unowned file and both are ordinary unowned-ExecStart findings", findings)
	}
	for _, f := range findings {
		if f.RuleID != RuleUnitExecUnowned {
			t.Errorf("%s: rule = %q, want %q", f.Subject, f.RuleID, RuleUnitExecUnowned)
		}
		if f.Severity != finding.SevSuspicious {
			t.Errorf("%s: severity = %v, want suspicious", f.Subject, f.Severity)
		}
	}
}
