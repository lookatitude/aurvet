// internal/correlate/correlate_test.go
package correlate

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/lookatitude/aurvet/internal/alpm"
	"github.com/lookatitude/aurvet/internal/finding"
	"github.com/lookatitude/aurvet/internal/fsx"
	"github.com/lookatitude/aurvet/internal/own"
	"github.com/lookatitude/aurvet/internal/surfaces"
)

// fixtureSyncNames is the repository-name oracle for each committed root.
//
// It is stated per root rather than derived, because "which packages are
// foreign" is the single input that decides whether attribution can happen at
// all, and a test that derived it from the same local DB it is testing would
// assert nothing. cruft deliberately carries ONE foreign package (deskx, a
// plausible AUR desktop build): a benign root with no foreign package at all
// would pass every "no critical" assertion below for the wrong reason.
var fixtureSyncNames = map[string]map[string]bool{
	"stock": {"foo-bin": true, "foo-lib": true, "zlib": true},
	"cruft": {
		"systemd": true, "kmod": true, "netbar": true, "printbaz": true,
		"sysutil": true, "foo-daemon": true,
		// deskx: absent on purpose -> foreign.
	},
	"malicious": {"systemd": true, "kmod": true},
	// librewolf-fix-bin: absent on purpose -> foreign.
}

// fixtureConfig loads one committed root from testdata/roots.
func fixtureConfig(t *testing.T, dir, name string) (*os.Root, Config) {
	t.Helper()
	pkgs, dbGaps, err := alpm.LoadLocalDB(filepath.Join(dir, "var", "lib", "pacman", "local"))
	if err != nil {
		t.Fatalf("LoadLocalDB(%s): %v", dir, err)
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
	sync := fixtureSyncNames[name]
	if len(sync) == 0 {
		t.Fatalf("no sync-name oracle for root %q", name)
	}
	// Non-vacuity: cruft and malicious must each have a foreign package, or
	// "no critical cluster" and "attributed to librewolf-fix-bin" both stop
	// meaning anything.
	foreign := 0
	for _, p := range pkgs {
		if !sync[p.Name] {
			foreign++
		}
	}
	if name != "stock" && foreign == 0 {
		t.Fatalf("%s: no foreign packages; attribution has nothing to choose between", name)
	}
	return root, Config{Owners: owners, Pkgs: pkgs, SyncNames: sync}
}

func fixture(t *testing.T, name string) (*os.Root, Config) {
	t.Helper()
	return fixtureConfig(t, filepath.Join("..", "..", "testdata", "roots", name), name)
}

// copyFixture copies a committed root into t.TempDir(), preserving symlinks
// verbatim. It exists because git does not preserve mtimes, so the temporal key
// cannot be exercised from a checked-in tree at all -- and because INV-5 forbids
// writing under a scanned root. Nothing under testdata/ is ever modified: the
// copy is written, the original is only read.
func copyFixture(t *testing.T, name string) string {
	t.Helper()
	src := filepath.Join("..", "..", "testdata", "roots", name)
	dst := t.TempDir()
	err := filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		out := filepath.Join(dst, rel)
		switch {
		case d.IsDir():
			return os.MkdirAll(out, 0o755)
		case d.Type()&os.ModeSymlink != 0:
			target, rerr := os.Readlink(p)
			if rerr != nil {
				return rerr
			}
			return os.Symlink(target, out)
		default:
			data, rerr := os.ReadFile(p)
			if rerr != nil {
				return rerr
			}
			return os.WriteFile(out, data, 0o644)
		}
	})
	if err != nil {
		t.Fatalf("copy %s: %v", name, err)
	}
	return dst
}

// setMtime stamps one file in a copied root. Seconds are given as a Unix time so
// the test states the same clock %INSTALLDATE% is recorded on.
func setMtime(t *testing.T, dir, rel string, unixSec int64) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(rel))
	ts := time.Unix(unixSec, 0)
	if err := os.Chtimes(p, ts, ts); err != nil {
		t.Fatalf("chtimes %s: %v", rel, err)
	}
}

// The malicious root's recorded install date, and the paths its scriptlet
// planted. The offsets are deliberately non-zero: a planted file's mtime is set
// when the scriptlet runs, which is near but not equal to the moment pacman
// writes %INSTALLDATE%. Equal timestamps would let a window of one nanosecond
// pass, and the window would then be untested.
const maliciousInstallDate int64 = 1770099000

var maliciousPlanted = map[string]int64{
	"usr/lib/systemd/inert-marker-initd":             maliciousInstallDate + 60,
	"usr/lib/systemd/libinert-marker-preload.so":     maliciousInstallDate + 62,
	"etc/systemd/system/systemd-initd-inert.service": maliciousInstallDate + 61,
	"etc/pacman.d/hooks/60-depmod.hook":              maliciousInstallDate + 63,
}

// maliciousWithMtimes is the malicious root copied out and stamped, which is the
// only form in which the temporal key can be exercised.
func maliciousWithMtimes(t *testing.T) (*os.Root, Config) {
	t.Helper()
	dir := copyFixture(t, "malicious")
	for rel, sec := range maliciousPlanted {
		setMtime(t, dir, rel, sec)
	}
	return fixtureConfig(t, dir, "malicious")
}

func factPaths(facts []Fact) []string {
	out := make([]string, 0, len(facts))
	for _, f := range facts {
		out = append(out, f.Family+":"+f.Path)
	}
	sort.Strings(out)
	return out
}

func clusterPaths(c Cluster) []string {
	out := make([]string, 0, len(c.Facts))
	for _, f := range c.Facts {
		out = append(out, f.Path)
	}
	sort.Strings(out)
	return out
}

func hasPath(c Cluster, want string) bool {
	for _, f := range c.Facts {
		if f.Path == want || f.Target == want {
			return true
		}
	}
	return false
}

func criticals(res finding.Result) []finding.Finding {
	var out []finding.Finding
	for _, f := range res.Findings {
		if f.Severity == finding.SevCritical {
			out = append(out, f)
		}
	}
	return out
}

// TestFactsOnFixtureRootsAreNeverCritical is the asymmetry this package exists
// to create: every surface check rates its own findings suspicious at most, so
// any critical in the output must have come from a cluster.
func TestFactsOnFixtureRootsAreNeverCritical(t *testing.T) {
	for _, name := range []string{"stock", "cruft", "malicious"} {
		t.Run(name, func(t *testing.T) {
			root, cfg := fixture(t, name)
			_, res := Facts(fsx.Live(root), cfg)
			for _, f := range res.Findings {
				if f.Severity == finding.SevCritical {
					t.Errorf("%s: surface check %s rated %s critical on its own; only a cluster may",
						name, f.RuleID, f.Subject)
				}
			}
		})
	}
}

// TestFactCountsOnFixtureRoots pins that facts are actually being derived. A
// correlation engine handed zero facts satisfies every "no critical" assertion
// in this file trivially, which is the exact failure the INV-8 gate exists to
// catch.
func TestFactCountsOnFixtureRoots(t *testing.T) {
	cases := []struct {
		name  string
		facts []string
	}{
		{"stock", nil},
		{"cruft", []string{
			"enablement-link:etc/systemd/system/multi-user.target.wants/local-backup.service",
			"pacman-hook:etc/pacman.d/hooks/60-depmod.hook",
			"pacman-hook:etc/pacman.d/hooks/99-local-mkinitcpio.hook",
			"pacman-hook:usr/local/share/pacman-hooks/10-local-report.hook",
			"shell-profile:etc/profile.d/local-path.sh",
			"unit-execstart:etc/systemd/system/local-backup.service",
			"xdg-autostart:home/alice/.config/autostart/nextcloud.desktop",
		}},
		{"malicious", []string{
			"enablement-link:etc/systemd/system/multi-user.target.wants/systemd-initd-inert.service",
			"ld-so-preload:usr/lib/systemd/libinert-marker-preload.so",
			"pacman-hook:etc/pacman.d/hooks/60-depmod.hook",
			"unit-execstart:etc/systemd/system/systemd-initd-inert.service",
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root, cfg := fixture(t, c.name)
			facts, _ := Facts(fsx.Live(root), cfg)
			got := factPaths(facts)
			if strings.Join(got, "\n") != strings.Join(c.facts, "\n") {
				t.Errorf("%s facts:\n got %v\nwant %v", c.name, got, c.facts)
			}
		})
	}
}

// TestStockRootHasNoCluster: nothing to correlate, and nothing invented.
func TestStockRootHasNoCluster(t *testing.T) {
	root, cfg := fixture(t, "stock")
	res := Correlate(fsx.Live(root), cfg)
	for _, f := range res.Findings {
		if f.RuleID == RuleCluster {
			t.Errorf("stock: cluster finding %+v", f)
		}
	}
	if len(res.Gaps) != 0 {
		t.Errorf("stock: gaps %+v, want none", res.Gaps)
	}
}

// TestCruftClusterStaysSuspicious is the false-positive half of the gate, and
// the hardest case in the corpus: cruft's hand-written unit IS enabled through a
// *.wants link and DOES run an unowned binary, so two families really do
// correlate onto one subject. It must still not be critical, because every path
// involved is in administrator territory -- /etc/systemd/system for the unit,
// /usr/local/bin for the program it runs -- which is where local software is
// supposed to live.
func TestCruftClusterStaysSuspicious(t *testing.T) {
	root, cfg := fixture(t, "cruft")
	facts, _ := Facts(fsx.Live(root), cfg)
	clusters, gaps := Clusters(fsx.Live(root), cfg, facts)
	if len(clusters) != 1 {
		t.Fatalf("cruft: %d clusters, want 1 (the hand-written unit and its enablement link): %+v",
			len(clusters), clusters)
	}
	c := clusters[0]
	if c.Severity != finding.SevSuspicious {
		t.Errorf("cruft cluster severity = %v, want suspicious; every member is in administrator "+
			"territory: %+v", c.Severity, c)
	}
	if len(c.Masquerade) != 0 {
		t.Errorf("cruft cluster claims a masquerade at %v; /etc/systemd/system and /usr/local are "+
			"where local software belongs", c.Masquerade)
	}
	want := []string{
		"etc/systemd/system/local-backup.service",
		"etc/systemd/system/multi-user.target.wants/local-backup.service",
	}
	if strings.Join(clusterPaths(c), ",") != strings.Join(want, ",") {
		t.Errorf("cruft cluster members = %v, want %v", clusterPaths(c), want)
	}
	if len(gaps) != 0 {
		t.Errorf("cruft: gaps %+v; the timestamps were readable and simply did not match, which is an "+
			"answer and not an inability", gaps)
	}
}

// TestCruftSurvivesAnAdversarialTimestamp is the false positive this rule is
// most likely to produce in real life: an administrator installs an AUR package
// and hand-writes a unit in the same session, so the unit's mtime lands inside
// the package's install window. The temporal key then fires -- and the cluster
// must STILL not be critical, because nothing in it is planted in a package's
// own directory.
func TestCruftSurvivesAnAdversarialTimestamp(t *testing.T) {
	dir := copyFixture(t, "cruft")
	// deskx is the foreign package in this root; 1770000700 is its
	// %INSTALLDATE%.
	setMtime(t, dir, "etc/systemd/system/local-backup.service", 1770000700+30)
	setMtime(t, dir, "usr/local/bin/hand-built-tool", 1770000700+31)
	root, cfg := fixtureConfig(t, dir, "cruft")

	facts, _ := Facts(fsx.Live(root), cfg)
	clusters, _ := Clusters(fsx.Live(root), cfg, facts)
	if len(clusters) != 1 {
		t.Fatalf("cruft: %d clusters, want 1: %+v", len(clusters), clusters)
	}
	c := clusters[0]
	if len(c.Candidates) == 0 {
		t.Fatal("the temporal key did not fire at all, so this test is not exercising what it claims")
	}
	if c.Severity == finding.SevCritical {
		t.Errorf("cruft cluster reached critical on a timestamp coincidence: %+v", c)
	}
}

// TestMaliciousClusterIsCriticalWithTheTemporalKey is the acceptance half of the
// phase gate, and it closes the four items the fixture lane deferred here:
//
//  1. the facts cluster onto ONE subject, librewolf-fix-bin;
//  2. the cluster reaches SevCritical while NO individual finding does;
//  3. the temporal key, which needs a t.TempDir() copy because git does not
//     preserve mtimes;
//  4. the Limits text states what the cluster cannot see (INV-6).
func TestMaliciousClusterIsCriticalWithTheTemporalKey(t *testing.T) {
	root, cfg := maliciousWithMtimes(t)
	facts, surfaceRes := Facts(fsx.Live(root), cfg)

	// Half 2, first direction: no individual fact is critical.
	for _, f := range surfaceRes.Findings {
		if f.Severity == finding.SevCritical {
			t.Errorf("individual finding reached critical: %s on %s -- a correlation engine that rates "+
				"single facts critical has not correlated anything", f.RuleID, f.Subject)
		}
	}
	for _, f := range facts {
		if f.Severity == finding.SevCritical {
			t.Errorf("fact %s is critical before correlation", f.Path)
		}
	}

	clusters, gaps := Clusters(fsx.Live(root), cfg, facts)
	var crit []Cluster
	for _, c := range clusters {
		if c.Severity == finding.SevCritical {
			crit = append(crit, c)
		}
	}
	if len(crit) != 1 {
		t.Fatalf("%d critical clusters, want exactly 1; clusters=%+v gaps=%+v", len(crit), clusters, gaps)
	}
	c := crit[0]

	// Half 1: one subject, and it is the package.
	if c.Subject != "librewolf-fix-bin" {
		t.Errorf("cluster subject = %q, want librewolf-fix-bin (the right count reached through the "+
			"wrong subject is not attribution)", c.Subject)
	}
	if c.SubjectKind != "package" {
		t.Errorf("cluster subject kind = %q, want package", c.SubjectKind)
	}

	// The three facts the fixture is built from, plus the shared directory that
	// merges two of them.
	for _, want := range []string{
		"etc/systemd/system/multi-user.target.wants/systemd-initd-inert.service",
		"etc/systemd/system/systemd-initd-inert.service",
		"usr/lib/systemd/inert-marker-initd",
		"usr/lib/systemd/libinert-marker-preload.so",
	} {
		if !hasPath(c, want) {
			t.Errorf("cluster does not include %s; members=%v", want, clusterPaths(c))
		}
	}
	if len(c.Families) < 3 {
		t.Errorf("cluster spans %v, want at least three families", c.Families)
	}
	if len(c.Masquerade) == 0 {
		t.Error("cluster records no masquerade; the unowned payload in the package-owned " +
			"usr/lib/systemd is the whole shape")
	}

	// Half 3: the temporal key, with the number in the evidence.
	var temporal bool
	for _, cand := range c.Candidates {
		if cand.Pkg != "librewolf-fix-bin" {
			continue
		}
		if !cand.Foreign {
			t.Error("librewolf-fix-bin is not marked foreign; the temporal key must be restricted to " +
				"packages the repositories do not offer")
		}
		if !cand.HasScriptlet {
			t.Error("the install scriptlet was not detected; it is the recorded mechanism by which a " +
				"file lands outside a package's own file list")
		}
		for _, k := range cand.Keys {
			if strings.Contains(k, "temporal") {
				temporal = true
			}
		}
	}
	if !temporal {
		t.Errorf("no temporal attribution key on the cluster: %+v", c.Candidates)
	}

	// Half 2, second direction: the cluster, and only the cluster, is critical.
	res := Correlate(fsx.Live(root), cfg)
	cs := criticals(res)
	if len(cs) != 1 || cs[0].RuleID != RuleCluster {
		t.Fatalf("criticals in the full result = %+v, want exactly one %s", cs, RuleCluster)
	}

	// Half 4: INV-6 in the finding text, not only in documentation.
	//
	// The last three terms cover the escalation rule's own blind spot rather than
	// the phase's: because critical REQUIRES a masquerade, a cluster confined to
	// administrator territory is capped at suspicious no matter how many families
	// it spans. That matters most for exactly the threat this tool exists for --
	// an AUR build runs as the user and needs no package-owned directory to
	// persist -- so a reader who is not told about the cap will read a suspicious
	// user-level cluster as weaker evidence than it is.
	lim := strings.ToLower(cs[0].Limits)
	for _, want := range []string{"pkgdir", "silent", "sloppy", "mtree", "masquerade", "home", "aur"} {
		if !strings.Contains(lim, want) {
			t.Errorf("cluster Limits does not mention %q: %q", want, cs[0].Limits)
		}
	}
	if len(cs[0].Evidence) == 0 {
		t.Error("cluster finding carries no evidence")
	}
}

// TestMaliciousTreeWithoutMtimesStaysSuspicious is the checked-in tree, where
// every mtime is the checkout's. The facts still cluster -- the joins do not
// depend on time -- but attribution fails, and an unattributed cluster is not
// critical. This is deliberate and is stated in the Limits: whoever planted the
// files could have rewritten their mtimes, and doing so costs them this rating
// and not the cluster.
func TestMaliciousTreeWithoutMtimesStaysSuspicious(t *testing.T) {
	root, cfg := fixture(t, "malicious")
	facts, _ := Facts(fsx.Live(root), cfg)
	clusters, _ := Clusters(fsx.Live(root), cfg, facts)
	if len(clusters) == 0 {
		t.Fatal("no cluster at all; the joins must not depend on timestamps")
	}
	for _, c := range clusters {
		if c.Severity == finding.SevCritical {
			t.Errorf("cluster reached critical with no attribution key: %+v", c)
		}
	}
}

// TestBreakingEachKeyStopsTheCritical proves the correlation is load-bearing:
// remove one key at a time from the shape that IS critical and the critical must
// disappear. A rule that survives every one of these was never using them.
func TestBreakingEachKeyStopsTheCritical(t *testing.T) {
	cases := []struct {
		name    string
		break_  func(*Config)
		wantGap bool
	}{
		{
			// The foreign/native split. Without a repository oracle no package
			// can be called foreign, which is a coverage gap and not a licence
			// to attribute the cluster to whatever is nearest (INV-3).
			name:    "repository name set unknown",
			break_:  func(c *Config) { c.SyncNames = nil },
			wantGap: true,
		},
		{
			// The temporal key. The planted files' mtimes are 60-63 s from the
			// recorded install date, so a one-second window cannot reach them.
			name:   "temporal window too tight to reach the planted mtimes",
			break_: func(c *Config) { c.Window = time.Second },
			// Not a gap: the timestamps were read and did not match. That is an
			// answer, and an answer is never a coverage shortfall.
			wantGap: false,
		},
		{
			// The masquerade. Strip systemd's ownership of usr/lib/systemd and
			// the payload sits in an unowned directory -- indistinguishable from
			// a local tree, which is what /usr/local and /opt are.
			name: "the payload's directory is no longer package-owned",
			break_: func(c *Config) {
				c.Owners = ownersWithout(c, "usr/lib/systemd")
			},
			wantGap: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root, cfg := maliciousWithMtimes(t)
			// Sanity: unbroken, this configuration is critical.
			facts, _ := Facts(fsx.Live(root), cfg)
			base, _ := Clusters(fsx.Live(root), cfg, facts)
			if !anyCritical(base) {
				t.Fatalf("the unbroken configuration is not critical, so breaking a key proves nothing: %+v", base)
			}

			tc.break_(&cfg)
			facts, _ = Facts(fsx.Live(root), cfg)
			clusters, gaps := Clusters(fsx.Live(root), cfg, facts)
			if anyCritical(clusters) {
				t.Errorf("still critical with %q broken: %+v", tc.name, clusters)
			}
			if tc.wantGap && len(gaps) == 0 {
				t.Errorf("no coverage gap after %q; a cluster that could not be evaluated must say so "+
					"(INV-3, INV-9) rather than quietly reading as suspicious", tc.name)
			}
		})
	}
}

func anyCritical(cs []Cluster) bool {
	for _, c := range cs {
		if c.Severity == finding.SevCritical {
			return true
		}
	}
	return false
}

// ownersWithout rebuilds the ownership oracle with one recorded path removed, so
// a test can withdraw a single fact about the world without editing a fixture.
func ownersWithout(cfg *Config, drop string) *own.Owners {
	pkgs := make([]alpm.Package, 0, len(cfg.Pkgs))
	for _, p := range cfg.Pkgs {
		q := p
		q.Files = nil
		for _, f := range p.Files {
			if strings.Trim(f, "/") == strings.Trim(drop, "/") {
				continue
			}
			q.Files = append(q.Files, f)
		}
		pkgs = append(pkgs, q)
	}
	cfg.Pkgs = pkgs
	return own.IndexIn(fsx.Source{}, pkgs)
}

// TestSingleFactIsNeverACluster: one unowned file is one unowned file. Restating
// it as a cluster would double every count in the report and inflate the one
// rating this package is allowed to hand out.
func TestSingleFactIsNeverACluster(t *testing.T) {
	root, cfg := maliciousWithMtimes(t)
	facts, _ := Facts(fsx.Live(root), cfg)
	var one []Fact
	for _, f := range facts {
		if f.Family == FamilyUnitExec {
			one = append(one, f)
		}
	}
	if len(one) != 1 {
		t.Fatalf("expected exactly one unit fact, got %d", len(one))
	}
	clusters, _ := Clusters(fsx.Live(root), cfg, one)
	if len(clusters) != 0 {
		t.Errorf("a single fact produced %d clusters: %+v", len(clusters), clusters)
	}
}

// TestUnreadableMemberTimeIsAGapNotADrop is INV-9 at the exact point it is
// easiest to violate: a member whose timestamp cannot be read must not be
// quietly dropped from the cluster, because dropping it is how a correlated
// critical becomes a correlated suspicious with nobody noticing.
func TestUnreadableMemberTimeIsAGapNotADrop(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores the permission bits this test depends on")
	}
	dir := copyFixture(t, "malicious")
	// Only the two planted binaries are stamped, and both are then made
	// unreadable. The unit file is deliberately left alone: it must stay
	// PARSEABLE (an unreadable unit is a different shortfall, already gapped by
	// internal/surfaces) and its own mtime -- the checkout's -- matches no
	// install date, so the temporal key's only possible input is the two files
	// whose mtimes cannot be read.
	for _, rel := range []string{
		"usr/lib/systemd/inert-marker-initd",
		"usr/lib/systemd/libinert-marker-preload.so",
	} {
		setMtime(t, dir, rel, maliciousPlanted[rel])
		p := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.Chmod(p, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(p, 0o644) })
	}
	root, cfg := fixtureConfig(t, dir, "malicious")

	facts, _ := Facts(fsx.Live(root), cfg)
	clusters, gaps := Clusters(fsx.Live(root), cfg, facts)
	if anyCritical(clusters) {
		t.Errorf("critical from facts whose timestamps could not be read: %+v", clusters)
	}
	if len(gaps) == 0 {
		t.Fatalf("no gap for unreadable member timestamps; clusters=%+v", clusters)
	}
	var named bool
	for _, g := range gaps {
		if g.RuleID == RuleCoverage && strings.Contains(g.Reason, "mtime") {
			named = true
		}
	}
	if !named {
		t.Errorf("no %s gap naming the unreadable timestamp: %+v", RuleCoverage, gaps)
	}
	// And the facts are still in the cluster, not dropped.
	for _, c := range clusters {
		for _, f := range c.Facts {
			if !f.TimeKnown && f.TimeErr == nil {
				t.Errorf("member %s has no time and no reason for it", f.Path)
			}
		}
	}
}

// TestPathNameAttributionNeedsNoTimestamps covers the second strong key on its
// own: the roadmap's "match the directory or the filename stem against foreign
// package names". A stem match attributes with no clock involved at all, which
// matters because mtimes are the one input the person who planted the files
// could have rewritten.
func TestPathNameAttributionNeedsNoTimestamps(t *testing.T) {
	dir := t.TempDir()
	write := func(rel, body string) {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, rel)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, rel), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("etc/systemd/system/agent.service", "[Service]\nExecStart=/usr/lib/mailer/mailertool\n")
	write("usr/lib/mailer/mailertool", "inert\n")
	write("usr/lib/mailer/libinert.so", "inert\n")
	write("etc/ld.so.preload", "/usr/lib/mailer/libinert.so\n")
	write("etc/passwd", "root:x:0:0::/root:/usr/bin/nologin\n")

	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })

	pkgs := []alpm.Package{
		{Name: "systemd", Version: "1-1", Files: []string{"etc/systemd/", "etc/systemd/system/"}},
		// The foreign package. usr/lib/mailer/ is its own directory and IS
		// package-owned, so the files planted in it are unowned inside an owned
		// directory outside administrator territory.
		{Name: "mailertool-bin", Version: "2-1", Files: []string{"usr/lib/", "usr/lib/mailer/"}},
	}
	cfg := Config{
		Owners:    own.IndexIn(fsx.Live(root), pkgs),
		Pkgs:      pkgs,
		SyncNames: map[string]bool{"systemd": true},
		UnitDirs:  []string{"etc/systemd/system"},
	}
	facts, _ := Facts(fsx.Live(root), cfg)
	if len(facts) != 2 {
		t.Fatalf("facts = %v, want the unit and the preload entry", factPaths(facts))
	}
	clusters, _ := Clusters(fsx.Live(root), cfg, facts)
	if len(clusters) != 1 {
		t.Fatalf("clusters = %+v, want 1 joined by the shared package-owned directory", clusters)
	}
	c := clusters[0]
	if c.Severity != finding.SevCritical {
		t.Fatalf("severity = %v, want critical: a stem match on a foreign package name is a strong key: %+v",
			c.Severity, c)
	}
	if c.Subject != "mailertool-bin" {
		t.Errorf("subject = %q, want mailertool-bin", c.Subject)
	}
	var named bool
	for _, cand := range c.Candidates {
		for _, k := range cand.Keys {
			if strings.Contains(k, "path") {
				named = true
			}
		}
	}
	if !named {
		t.Errorf("no path-attribution key recorded: %+v", c.Candidates)
	}
}

// TestPathNameAttributionRefusesShortAndInexactMatches: the stem key is exact
// equality after a normalisation this file states, and nothing looser. A prefix
// or substring match would attribute half the filesystem to any package called
// "bin" or "lib".
func TestPathNameAttributionRefusesShortAndInexactMatches(t *testing.T) {
	cases := []struct {
		token, pkg string
		want       bool
	}{
		{"mailertool", "mailertool-bin", true},
		{"mailertool", "mailertool-git", true},
		{"MailerTool", "mailertool", true},
		{"mailertool2", "mailertool", false},
		{"mailer", "mailertool", false},
		{"bin", "bin", false}, // below the length floor
		{"tool", "tool", false},
		{"toolkit", "toolkit", true},
	}
	for _, c := range cases {
		if got := nameMatches(c.token, c.pkg); got != c.want {
			t.Errorf("nameMatches(%q, %q) = %v, want %v", c.token, c.pkg, got, c.want)
		}
	}
}

// TestTemporalWindowSitsInTheMeasuredBand pins the relationship rather than the
// literal: the window must be wide enough not to split one real transaction and
// narrow enough not to fuse two. Both numbers are measured on the reference
// system and are recorded next to DefaultWindow.
func TestTemporalWindowSitsInTheMeasuredBand(t *testing.T) {
	if DefaultWindow <= MeasuredMaxIntraTransactionStep {
		t.Errorf("DefaultWindow %v is at or below the largest step inside one measured transaction (%v); "+
			"a real cluster would split across two windows and neither half would reach two facts",
			DefaultWindow, MeasuredMaxIntraTransactionStep)
	}
	if DefaultWindow >= MeasuredMinInterTransactionGap {
		t.Errorf("DefaultWindow %v is at or above the smallest measured gap between two DIFFERENT "+
			"transactions (%v); two unrelated transactions would fuse into one fabricated incident",
			DefaultWindow, MeasuredMinInterTransactionGap)
	}
	// The stated preference: nearer the lower edge, because fabricating a
	// cluster costs more than missing one.
	mid := (MeasuredMaxIntraTransactionStep + MeasuredMinInterTransactionGap) / 2
	if DefaultWindow > mid {
		t.Errorf("DefaultWindow %v is in the upper half of the band (midpoint %v); this package prefers "+
			"missing a cluster to fabricating one, so the window belongs in the lower half", DefaultWindow, mid)
	}
}

// TestCorrelateIsPureOverTheRoot is INV-4, in both directions that matter here:
// the process working directory must not change the answer, and neither must the
// day the scan runs on -- there is no wall-clock input to change it with, and
// this test would notice one appearing because the fixture's timestamps are
// fixed while "now" is not.
func TestCorrelateIsPureOverTheRoot(t *testing.T) {
	dir := copyFixture(t, "malicious")
	for rel, sec := range maliciousPlanted {
		setMtime(t, dir, rel, sec)
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}
	run := func() string {
		pkgs, _, err := alpm.LoadLocalDB(filepath.Join(abs, "var", "lib", "pacman", "local"))
		if err != nil {
			t.Fatal(err)
		}
		root, err := os.OpenRoot(abs)
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		res := Correlate(fsx.Live(root), Config{
			Owners: owners(root, pkgs), Pkgs: pkgs, SyncNames: fixtureSyncNames["malicious"],
		})
		var b strings.Builder
		for _, f := range res.Findings {
			b.WriteString(f.RuleID + "|" + f.Subject + "|" + f.Severity.String() + "\n")
		}
		for _, g := range res.Gaps {
			b.WriteString("gap|" + g.RuleID + "|" + g.Subject + "\n")
		}
		return b.String()
	}
	before := run()
	t.Chdir(t.TempDir())
	after := run()
	if before != after {
		t.Errorf("output changed with the process working directory:\n%s\n---\n%s", before, after)
	}
	if !strings.Contains(before, RuleCluster+"|librewolf-fix-bin|critical") {
		t.Errorf("the run under test produced no critical cluster, so purity was asserted over nothing:\n%s",
			before)
	}
}

func owners(root *os.Root, pkgs []alpm.Package) *own.Owners { return own.IndexIn(fsx.Live(root), pkgs) }

// TestNilRootIsAGapNotSilence: no root, no evidence, and saying so is the only
// honest answer (INV-3 -- incomplete coverage outranks a clean verdict).
func TestNilRootIsAGapNotSilence(t *testing.T) {
	for _, c := range []struct {
		name string
		cfg  Config
	}{
		{"nil root", Config{Owners: own.Index(nil)}},
		{"nil owners", Config{}},
	} {
		t.Run(c.name, func(t *testing.T) {
			res := Correlate(fsx.Source{}, c.cfg)
			if len(res.Findings) != 0 {
				t.Errorf("findings from nothing: %+v", res.Findings)
			}
			if len(res.Gaps) == 0 {
				t.Error("no gap; an unexamined system must never read as a clean one")
			}
		})
	}
}

// TestAdminTerritoryList states, as a test, which paths are treated as
// administrator territory. The list decides whether a cruft-laden honest system
// can reach critical, so a silent addition to it is a silent loss of detection.
func TestAdminTerritoryList(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"etc/systemd/system/local.service", true},
		{"etc/systemd/system", true},
		{"etc/pacman.d/hooks/99-local.hook", true},
		{"etc/profile.d/local.sh", true},
		{"usr/local/bin/tool", true},
		{"opt/vendor/thing", true},
		{"home/alice/.config/autostart/x.desktop", true},
		{"/usr/local/lib/libhand.so", true},
		{"usr/lib/systemd/inert-marker-initd", false},
		{"usr/lib/systemd/system/foo.service", false},
		{"usr/bin/foo", false},
		{"etc/systemd/systemd-fake/x", false},
		{"usr/localish/bin/tool", false},
	}
	for _, c := range cases {
		if got := isAdminTerritory(c.path); got != c.want {
			t.Errorf("isAdminTerritory(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

// TestCorrelateLiveSystem measures the phase gate's remaining claim on the
// machine the roadmap's numbers were taken from: a correlated critical here
// would be a false positive, because there is no incident on this system.
func TestCorrelateLiveSystem(t *testing.T) {
	if os.Getenv("AURVET_LIVE_CORRELATE") != "1" {
		t.Skip("set AURVET_LIVE_CORRELATE=1 to measure against the live system")
	}
	root, err := os.OpenRoot("/")
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	pkgs, dbGaps, err := alpm.LoadLocalDB("/var/lib/pacman/local")
	if err != nil {
		t.Fatal(err)
	}
	sync, unreadable, err := alpm.LoadSyncNames("/var/lib/pacman/sync")
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{Owners: own.IndexIn(fsx.Live(root), pkgs), Pkgs: pkgs, SyncNames: sync}
	facts, surfaceRes := Facts(fsx.Live(root), cfg)
	clusters, gaps := Clusters(fsx.Live(root), cfg, facts)
	t.Logf("packages=%d db-gaps=%d sync-names=%d unreadable-sync=%v", len(pkgs), len(dbGaps), len(sync), unreadable)
	t.Logf("facts=%d surface-findings=%d surface-gaps=%d clusters=%d cluster-gaps=%d",
		len(facts), len(surfaceRes.Findings), len(surfaceRes.Gaps), len(clusters), len(gaps))
	for _, f := range facts {
		t.Logf("  fact %s %s -> %q time=%v known=%v", f.Family, f.Path, f.Target, f.Time, f.TimeKnown)
	}
	for _, c := range clusters {
		t.Logf("  cluster %s (%s) sev=%v families=%v members=%v masquerade=%v candidates=%d",
			c.Subject, c.SubjectKind, c.Severity, c.Families, clusterPaths(c), c.Masquerade, len(c.Candidates))
	}
	for _, c := range clusters {
		if c.Severity == finding.SevCritical {
			t.Errorf("correlated CRITICAL on the reference system, where there is no incident -- this is a "+
				"false positive and a bug in the engine, not a discovery: %+v", c)
		}
	}
	if len(sync) == 0 {
		t.Error("no sync names loaded; foreignness would be unknown and the measurement would prove nothing")
	}
}

// TestFactsMirrorTheSurfaceFindings guards the one place this package could
// drift from internal/surfaces: facts are derived from structured values, so a
// surface finding with no matching fact (or the reverse) would mean the two
// disagree about what is suspicious. Checked on the noisiest root.
func TestFactsMirrorTheSurfaceFindings(t *testing.T) {
	root, cfg := fixture(t, "cruft")
	facts, res := Facts(fsx.Live(root), cfg)
	suspicious := 0
	for _, f := range res.Findings {
		if f.Severity >= finding.SevSuspicious {
			suspicious++
		}
	}
	if suspicious != len(facts) {
		var got []string
		for _, f := range res.Findings {
			if f.Severity >= finding.SevSuspicious {
				got = append(got, f.RuleID+":"+f.Subject)
			}
		}
		sort.Strings(got)
		t.Errorf("%d suspicious surface findings but %d facts; they must not disagree about what is "+
			"suspicious.\nfindings=%v\nfacts=%v", suspicious, len(facts), got, factPaths(facts))
	}
	if _, ok := any(cfg.Misc).(surfaces.MiscConfig); !ok {
		t.Fatal("MiscConfig zero value must be usable")
	}
}
