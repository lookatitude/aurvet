// internal/repro/repro_test.go
//
// The attacks first, and here an "attack" is the operator's own machine leaking
// into a public issue. Every test in the first block plants something that must
// not travel and then asserts it is absent from every byte of the bundle.
package repro

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lookatitude/aurvet/internal/alpm"
	"github.com/lookatitude/aurvet/internal/finding"
)

const secret = "hunter2-CORRECT-HORSE-BATTERY-STAPLE"

func at(t *testing.T) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339, "2026-08-06T09:00:00+02:00")
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// plantedRoot is a fixture root carrying the shapes that must not escape: a file
// whose whole content is a secret, a unit whose Environment= is a secret, a
// comment nobody should read, a home path in an argument, and a secret in an
// ExecStart ARGUMENT.
//
// That last one is here because it is the shape that actually leaked. The
// original fixture planted secrets only in the places the directive allowlist
// already dropped -- Environment=, EnvironmentFile=, a comment, etc/shadow -- so
// the absence test passed by construction while `ExecStart=... --token <secret>`
// was published verbatim. A redaction fixture has to plant inside the directives
// that are KEPT, or it only ever proves the easy half.
//
// The ld.so.preload line is here for the opposite reason: after arguments stopped
// being emitted at all, it is one of the few remaining shapes where a home path
// in content is genuinely REDACTED rather than dropped, so it keeps
// TestHomePathsInContentAreRedacted testing something.
func plantedRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	write := func(rel, body string, mode os.FileMode) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
	}
	write("etc/shadow", "root:"+secret+":20000:0:99999:7:::\n", 0o600)
	write("etc/systemd/system/leaky.service", strings.Join([]string{
		"# written by ops on the " + secret + " box",
		"[Unit]",
		"Description=backup of " + secret,
		"[Service]",
		"Type=oneshot",
		"Environment=API_TOKEN=" + secret,
		"EnvironmentFile=/etc/leaky.env",
		"User=deploy",
		"ExecStart=/usr/local/bin/backup --to /home/miguelp/Projects/employer/dumps --token " + secret,
		"[Install]",
		"WantedBy=multi-user.target",
	}, "\n")+"\n", 0o644)
	write("etc/leaky.env", "API_TOKEN="+secret+"\n", 0o600)
	write("usr/local/bin/backup", "#!/bin/sh\necho "+secret+"\n", 0o755)
	write("etc/ld.so.preload", "/home/miguelp/Projects/employer/lib/hook.so\n", 0o644)
	return root
}

func plantedPackages() []alpm.Package {
	return []alpm.Package{{
		Name: "systemd", Version: "257.2-1", Base: "systemd", Validation: "pgp",
		Packager:    "Miguel P <miguel@example.invalid>",
		InstallDate: time.Unix(1700000000, 0).UTC(),
		Files:       []string{"etc/", "etc/systemd/", "etc/systemd/system/", "etc/shadow"},
		Backup:      map[string]string{"etc/shadow": "d41d8cd98f00b204e9800998ecf8427e"},
	}}
}

// theFinding names both a parsed surface and, in its evidence, three paths whose
// contents are none of a maintainer's business.
func theFinding() finding.Finding {
	return finding.Finding{
		RuleID: "unit-execstart-unowned", SubjectKind: "systemd-unit",
		Subject: "etc/systemd/system/leaky.service", Severity: finding.SevSuspicious,
		Summary: "unit leaky.service runs /usr/local/bin/backup, which no installed package owns",
		Evidence: []string{
			"ExecStart = /usr/local/bin/backup --to /home/miguelp/Projects/employer/dumps",
			"/usr/local/bin/backup is owned by no installed package",
			"the unit also reads /etc/leaky.env and the host's /etc/shadow",
			"etc/ld.so.preload names a shared object outside any package",
		},
		Limits: "a hand-written administrator unit is indistinguishable from a planted one",
	}
}

func build(t *testing.T, root string, f finding.Finding) (string, Report) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "bundle")
	rep, err := Build(dir, Input{
		Root: root, Finding: f, FindingID: "deadbeefdeadbeefdeadbeefdeadbeef",
		Packages: plantedPackages(), Version: "aurvet test", Now: at(t),
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return dir, rep
}

// everyByte returns every byte of every file in the bundle, including the
// README, the manifest, the file names themselves and the symlink targets. A
// redaction test that reads only the "interesting" files is a redaction test
// that passes while the secret sits in the manifest.
func everyByte(t *testing.T, dir string) string {
	t.Helper()
	var b strings.Builder
	err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		b.WriteString(p + "\n")
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			target, rerr := os.Readlink(p)
			if rerr != nil {
				return rerr
			}
			b.WriteString(target + "\n")
		case info.Mode().IsRegular():
			raw, rerr := os.ReadFile(p)
			if rerr != nil {
				return rerr
			}
			b.Write(raw)
			b.WriteString("\n")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if b.Len() == 0 {
		t.Fatal("the bundle is empty; every assertion below would be vacuous")
	}
	return b.String()
}

// -- attack 1: the secret ------------------------------------------------------

// A fixture reproducing a finding on /etc/shadow must not carry /etc/shadow's
// contents. Neither must it carry a unit's Environment=, its comments, or the
// contents of anything else it happens to name.
func TestNoPlantedSecretSurvivesIntoTheBundle(t *testing.T) {
	root := plantedRoot(t)
	dir, rep := build(t, root, theFinding())
	all := everyByte(t, dir)

	if strings.Contains(all, secret) {
		t.Fatalf("the planted secret is in the bundle. It appears in:\n%s",
			whereIn(t, dir, secret))
	}
	// The bundle really did carry the files -- otherwise absence proves nothing.
	for _, want := range []string{
		"etc/systemd/system/leaky.service", "usr/local/bin/backup", "etc/leaky.env", "etc/shadow",
	} {
		if !hasEntry(rep, want) {
			t.Errorf("the bundle does not carry %s, so this test proves nothing about it", want)
		}
	}
	// And the directive the check reads DID survive, or the bundle is useless.
	unit, err := os.ReadFile(filepath.Join(dir, "etc/systemd/system/leaky.service"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(unit), "ExecStart=/usr/local/bin/backup") {
		t.Fatalf("the ExecStart the finding is about did not survive:\n%s", unit)
	}
	for _, gone := range []string{"Environment", "EnvironmentFile", "User=", "Description", "#"} {
		if strings.Contains(string(unit), gone) {
			t.Errorf("the rebuilt unit still carries %q:\n%s", gone, unit)
		}
	}
	// The program survived and its ARGUMENTS did not. Asserted on the kept line
	// itself rather than only through the secret's absence above, so a future edit
	// that reinstates arguments fails here with a message that says what it did.
	if strings.Contains(string(unit), "--to") || strings.Contains(string(unit), "--token") {
		t.Errorf("the rebuilt unit carries command ARGUMENTS; an argument is uninspected free "+
			"text from the reporter's machine and no rule reads past Exec.Bin:\n%s", unit)
	}
	// Files whose format no check parses are zero-byte placeholders.
	for _, rel := range []string{"etc/shadow", "etc/leaky.env", "usr/local/bin/backup"} {
		st, serr := os.Stat(filepath.Join(dir, rel))
		if serr != nil {
			t.Fatal(serr)
		}
		if st.Size() != 0 {
			t.Errorf("%s is %d bytes; a file no check parses must be a zero-byte placeholder",
				rel, st.Size())
		}
	}
}

// The operator's own name and address on a locally built package must not travel
// either. %PACKAGER% is never written, rather than filtered out afterwards.
func TestSynthesisedPackageEntriesCarryNoPackager(t *testing.T) {
	root := plantedRoot(t)
	dir, rep := build(t, root, theFinding())
	all := everyByte(t, dir)
	for _, leak := range []string{"Miguel P", "miguel@example.invalid"} {
		if strings.Contains(all, leak) {
			t.Errorf("%q is in the bundle:\n%s", leak, whereIn(t, dir, leak))
		}
	}
	if len(rep.Packages) != 1 {
		t.Fatalf("the bundle rebuilt %d package entries, want 1", len(rep.Packages))
	}
	desc, err := os.ReadFile(filepath.Join(dir, "var/lib/pacman/local/systemd-257.2-1/desc"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(desc), "PACKAGER") {
		t.Errorf("the synthesised desc carries a %%PACKAGER%% field:\n%s", desc)
	}
	for _, want := range []string{"%NAME%", "systemd", "%VERSION%", "257.2-1", "%INSTALLDATE%"} {
		if !strings.Contains(string(desc), want) {
			t.Errorf("the synthesised desc is missing %q:\n%s", want, desc)
		}
	}
}

// -- attack 2: the home directory layout --------------------------------------

// The reference machine's live scan reports a unit pointing at
// /home/<user>/Projects/<employer>/..., which is a directory layout nobody
// should have to publish to report a false positive.
func TestHomePathsInContentAreRedacted(t *testing.T) {
	root := plantedRoot(t)
	dir, rep := build(t, root, theFinding())
	all := everyByte(t, dir)

	for _, leak := range []string{"/home/miguelp", "Projects/employer", "dumps"} {
		if strings.Contains(all, leak) {
			t.Errorf("%q survived into the bundle:\n%s", leak, whereIn(t, dir, leak))
		}
	}
	// The canary that the fixture still exercises the redaction, read from an
	// emitted CONTENT file rather than from every byte.
	//
	// It used to read everyByte, and that made it tautological: README.md contains
	// the sentence documenting the placeholder, so the string was always present
	// and the check passed even with redaction switched off entirely. A canary that
	// cannot fail is worse than none -- it reads like coverage.
	preload, err := os.ReadFile(filepath.Join(dir, "etc/ld.so.preload"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(preload), "/home/redacted/redacted") {
		t.Errorf("nothing was redacted in emitted content; the fixture no longer exercises "+
			"redactHome:\n%s", preload)
	}
	// This finding's ExecStart PROGRAM is not under /home, so withholding an
	// argument must not downgrade the verdict.
	if !rep.Reproduction.Reproduces {
		t.Errorf("redacting an ARGUMENT downgraded the reproduction verdict: %s",
			rep.Reproduction.Why)
	}
	// A subject under /home is a different matter: it is the finding, so it is
	// published, and the report says so loudly rather than quietly.
	if len(rep.HomePaths) != 0 {
		t.Errorf("nothing here is a home subject, yet HomePaths is %v", rep.HomePaths)
	}
}

// When the PROGRAM a finding is about lies under /home, redacting it changes the
// finding -- so the bundle says it does not reproduce rather than shipping a
// fixture that quietly produces something else.
func TestAHomeEntryPointDowngradesTheReproductionVerdict(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "etc/systemd/system/personal.service")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	body := "[Service]\nExecStart=/home/miguelp/bin/agent --daemon\n[Install]\nWantedBy=default.target\n"
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	f := theFinding()
	f.Subject = "etc/systemd/system/personal.service"
	f.Evidence = []string{"ExecStart = /home/miguelp/bin/agent --daemon (from personal.service)"}

	dir := filepath.Join(t.TempDir(), "bundle")
	rep, err := Build(dir, Input{Root: root, Finding: f, FindingID: "x", Now: at(t)})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Reproduction.Reproduces {
		t.Fatal("a bundle whose entry point was redacted claims it still reproduces the finding")
	}
	if rep.RedactedEntryPoint != "/home/miguelp/bin/agent" {
		t.Fatalf("the report does not tell the OPERATOR which program was redacted: %q",
			rep.RedactedEntryPoint)
	}
	// ...and it is absent from the bundle itself, because the bundle is the part
	// that gets published. A "why" field that spelled the path out would undo the
	// redaction it is explaining.
	if strings.Contains(everyByte(t, dir), "/home/miguelp") {
		t.Fatalf("the home entry point is still in the bundle:\n%s",
			whereIn(t, dir, "/home/miguelp"))
	}
}

// -- attack 3: a bundle that claims to reproduce and does not -----------------

// Classify's default is "not guaranteed". A rule added later must inherit an
// honest label, never a promise: a maintainer who runs a bundle, sees nothing
// and closes the report is the failure this table exists to prevent.
func TestAnUnclassifiedRuleIsNotClaimedToReproduce(t *testing.T) {
	got := Classify("some-rule-invented-next-quarter")
	if got.Reproduces {
		t.Fatal("an unclassified rule is claimed to reproduce")
	}
	if !strings.Contains(got.Why, "not in this build's reproduction table") {
		t.Fatalf("the label does not say why: %q", got.Why)
	}
	// The classes that genuinely cannot reproduce say what they would need.
	for _, rule := range []string{
		"integrity-digest-mismatch", "aur-orphaned", "baseline-drift", "correlated-cluster",
	} {
		c := Classify(rule)
		if c.Reproduces {
			t.Errorf("%s is claimed to reproduce from a bundle", rule)
		}
		if len(c.Why) < 40 {
			t.Errorf("%s: the reason is too thin to act on: %q", rule, c.Why)
		}
	}
	// And every rule in the reproducible set is absent from the other table, so
	// the two cannot both answer.
	for rule := range reproducible {
		if _, both := notReproducible[rule]; both {
			t.Errorf("%s is in both tables; the answer depends on lookup order", rule)
		}
		if !Classify(rule).Reproduces {
			t.Errorf("%s is in the reproducible set but Classify says otherwise", rule)
		}
	}
}

// -- attack 4: a bundle that is not self-contained ----------------------------

func TestBuildRefusesAPopulatedDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("mine"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Build(dir, Input{Root: plantedRoot(t), Finding: theFinding(), Now: at(t)})
	if err == nil {
		t.Fatal("Build wrote into a directory that already had contents")
	}
	if !strings.Contains(err.Error(), "self-contained") {
		t.Fatalf("the refusal does not say why: %v", err)
	}
}

// A path the builder MEANT to include and could not is a gap, never silence
// (INV-9): otherwise a maintainer debugs the wrong absence.
//
// An unresolvable token inside an EVIDENCE line is not one, and the asymmetry is
// deliberate. Evidence quotes command lines, glob triggers ("Target=
// usr/lib/modules/*/vmlinuz") and prose, so a path-shaped token that is not
// there is usually not a path. Gapping each of those would fill a healthy bundle
// with gaps and teach its reader to skip them -- which is how a real gap goes
// unread.
func TestAMissingSubjectIsAGapAndAMissingEvidenceTokenIsNot(t *testing.T) {
	root := plantedRoot(t)

	f := theFinding()
	f.Subject = "etc/systemd/system/never-existed.service"
	_, rep := build(t, root, f)
	if !hasGapAbout(rep, "never-existed") {
		t.Fatalf("a missing SUBJECT produced no gap: %+v", rep.Gaps)
	}

	g := theFinding()
	g.Evidence = append(g.Evidence, "Trigger: Target=usr/lib/modules/*/vmlinuz")
	_, rep2 := build(t, root, g)
	if hasGapAbout(rep2, "usr/lib/modules") {
		t.Fatalf("a glob quoted in an evidence line became a coverage gap: %+v", rep2.Gaps)
	}
	if len(rep2.Gaps) != 0 {
		t.Fatalf("a healthy bundle raised gaps: %+v", rep2.Gaps)
	}
}

func hasGapAbout(rep Report, needle string) bool {
	for _, g := range rep.Gaps {
		if strings.Contains(g.Subject, needle) {
			return true
		}
	}
	return false
}

// -- the documents -------------------------------------------------------------

// The operator is about to attach this to a public issue, so the README must
// state what is in it rather than leaving them to infer it.
func TestTheReadmeStatesWhatTheBundleContains(t *testing.T) {
	root := plantedRoot(t)
	dir, _ := build(t, root, theFinding())
	raw, err := os.ReadFile(filepath.Join(dir, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	for _, want := range []string{
		"No file's own bytes were copied",
		"zero-byte placeholder",
		"%PACKAGER%",
		"/home/redacted/redacted",
		"aurvet scan --offline-root",
		"| path | disposition | bytes | note |",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("README.md does not state %q", want)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "MANIFEST.json")); err != nil {
		t.Fatalf("no machine-readable manifest: %v", err)
	}
}

// -- helpers -------------------------------------------------------------------

func hasEntry(rep Report, path string) bool {
	for _, e := range rep.Files {
		if e.Path == path {
			return true
		}
	}
	return false
}

// whereIn names the files a leaked string appears in, so a failure is a fix
// rather than a search.
func whereIn(t *testing.T, dir, needle string) string {
	t.Helper()
	var hits []string
	_ = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || !info.Mode().IsRegular() {
			return nil
		}
		raw, rerr := os.ReadFile(p)
		if rerr == nil && strings.Contains(string(raw), needle) {
			hits = append(hits, "  "+p)
		}
		if strings.Contains(p, needle) {
			hits = append(hits, "  (in the path) "+p)
		}
		return nil
	})
	if len(hits) == 0 {
		return "  (in a path name or a symlink target)"
	}
	return strings.Join(hits, "\n")
}
