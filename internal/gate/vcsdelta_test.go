// internal/gate/vcsdelta_test.go
package gate

import (
	"bytes"
	"compress/zlib"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lookatitude/aurvet/internal/vcs"
)

// --- what counts as a VCS source -------------------------------------------

// TestVCSKindFollowsMakepkg: makepkg decides a source is a VCS checkout from a
// proto+ prefix or a bare VCS scheme, NOT from a .git suffix. Getting this
// wrong in either direction is a real failure: over-matching sends the delta
// review at a tarball, under-matching leaves a -git package reviewed once and
// then never again.
func TestVCSKindFollowsMakepkg(t *testing.T) {
	cases := []struct {
		entry    string
		kind     string
		readable bool
	}{
		{"git+https://github.com/x/y.git", "git", true},
		{"git+https://github.com/x/y.git#branch=main", "git", true},
		{"y::git+ssh://git@github.com/x/y", "git", true},
		{"git://git.sv.gnu.org/x", "git", true},
		{"y::git://host/x", "git", true},
		{"GIT+HTTPS://host/x", "git", true},
		{"hg+https://host/x", "hg", false},
		{"svn+https://host/x", "svn", false},
		{"bzr+lp:x", "bzr", false},
		{"fossil+https://host/x", "fossil", false},
		// Not VCS sources: a .git suffix on a plain fetch is a tarball name,
		// and makepkg treats it as one.
		{"https://github.com/x/y/archive/v1.tar.gz", "", false},
		{"https://host/y.git", "", false},
		{"local.patch", "", false},
		{"y::https://host/y-1.0.tar.xz", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		kind, readable := VCSKind(c.entry)
		if kind != c.kind || readable != c.readable {
			t.Errorf("VCSKind(%q) = (%q, %v), want (%q, %v)", c.entry, kind, readable, c.kind, c.readable)
		}
	}
}

// --- the four outcomes ------------------------------------------------------

// TestUpToDateIsEmptyAndSaysSo: HEAD is the recorded commit. Nothing to review.
func TestUpToDateWhenHeadIsTheAnchor(t *testing.T) {
	repo := newFixture(t, filepath.Join(t.TempDir(), "clone"))
	c1 := repo.commit(t, "initial", nil)
	repo.setHead(t, "refs/heads/master", c1)

	d := ReviewDelta(Request{PkgBase: "foo-git", Dir: repo.work, Anchor: Anchor{Commit: c1}})
	if d.Status != DeltaUpToDate {
		t.Fatalf("Status = %q, want %q (gaps=%+v)", d.Status, DeltaUpToDate, d.Gaps)
	}
	if len(d.Commits) != 0 {
		t.Errorf("Commits = %+v, want none", d.Commits)
	}
	if len(d.Gaps) != 0 || len(d.Result().Findings) != 0 {
		t.Errorf("an up-to-date delta produced %d gaps and %d findings", len(d.Gaps), len(d.Result().Findings))
	}
	if !d.Reached {
		t.Error("Reached = false for an anchor that is HEAD")
	}
}

// TestNewCommitsAreListed: the range since the snapshot, newest first, with the
// subjects an operator reviews.
func TestNewCommitsSinceTheAnchorAreListed(t *testing.T) {
	repo := newFixture(t, filepath.Join(t.TempDir(), "clone"))
	c1 := repo.commit(t, "initial", nil)
	c2 := repo.commit(t, "add feature", []string{c1})
	c3 := repo.commit(t, "exfiltrate ~/.ssh", []string{c2})
	repo.setHead(t, "refs/heads/master", c3)

	d := ReviewDelta(Request{PkgBase: "foo-git", Dir: repo.work, Anchor: Anchor{Commit: c1}})
	if d.Status != DeltaAhead {
		t.Fatalf("Status = %q, want %q (gaps=%+v)", d.Status, DeltaAhead, d.Gaps)
	}
	if !d.Reached {
		t.Fatal("Reached = false although the anchor is in this history")
	}
	if len(d.Commits) != 2 {
		t.Fatalf("Commits = %d, want 2: %+v", len(d.Commits), d.Commits)
	}
	if d.Commits[0].Hash != c3 || d.Commits[1].Hash != c2 {
		t.Errorf("range is not newest-first: %s, %s", d.Commits[0].Hash, d.Commits[1].Hash)
	}
	if d.Head != c3 {
		t.Errorf("Head = %s, want %s", d.Head, c3)
	}
	text := strings.Join(d.Lines(), "\n")
	for _, want := range []string{"exfiltrate ~/.ssh", "add feature", c1[:12]} {
		if !strings.Contains(text, want) {
			t.Errorf("rendered delta omits %q:\n%s", want, text)
		}
	}
	// New upstream commits are review material, reported, never silent.
	r := d.Result()
	if len(r.Findings) != 1 || r.Findings[0].RuleID != RuleVCSNewCommits {
		t.Fatalf("Findings = %+v, want one %s", r.Findings, RuleVCSNewCommits)
	}
	if r.Findings[0].Limits == "" {
		t.Error("a VCS delta finding must state what it cannot prove (INV-6)")
	}
}

// TestForcePushIsNotRenderedAsUpToDate is the assertion the whole task exists
// for. The recorded commit is gone from the history -- a force-push, a swapped
// upstream, or a truncated clone -- and reached == false. Rendering that as "no
// changes" would tell the operator the opposite of the truth.
func TestForcePushIsNotRenderedAsUpToDate(t *testing.T) {
	repo := newFixture(t, filepath.Join(t.TempDir(), "clone"))
	c1 := repo.commit(t, "initial", nil)
	c2 := repo.commit(t, "rewritten history", []string{c1})
	repo.setHead(t, "refs/heads/master", c2)
	// An anchor that is a well-formed hash and not in this history at all.
	orphan := strings.Repeat("b", 40)

	d := ReviewDelta(Request{PkgBase: "foo-git", Dir: repo.work, Anchor: Anchor{Commit: orphan}, Max: 50})
	if d.Status != DeltaAnchorAbsent {
		t.Fatalf("Status = %q, want %q (reached=%v gaps=%+v)", d.Status, DeltaAnchorAbsent, d.Reached, d.Gaps)
	}
	if d.Reached {
		t.Fatal("Reached = true for a commit that is not in this history")
	}
	text := strings.Join(d.Lines(), "\n")
	if strings.Contains(strings.ToLower(text), "up to date") {
		t.Fatalf("a vanished anchor rendered as up to date:\n%s", text)
	}
	if !strings.Contains(text, orphan[:12]) {
		t.Errorf("rendering does not name the missing anchor:\n%s", text)
	}
	r := d.Result()
	if len(r.Findings) != 1 || r.Findings[0].RuleID != RuleVCSAnchorAbsent {
		t.Fatalf("Findings = %+v, want one %s", r.Findings, RuleVCSAnchorAbsent)
	}
	if r.Findings[0].Severity.String() != "suspicious" {
		t.Errorf("severity = %s, want suspicious", r.Findings[0].Severity)
	}
	if r.Findings[0].Limits == "" {
		t.Error("the finding must say it cannot distinguish force-push from a truncated clone")
	}
}

// TestCapReachedIsUndetermined: reached == false ALSO happens when the walk hit
// its own bound before it got to the anchor. That is not proof the anchor is
// gone, and reporting it as a force-push would be a false accusation -- so it
// is its own status, with a gap.
func TestCapReachedBeforeAnchorIsUndetermined(t *testing.T) {
	repo := newFixture(t, filepath.Join(t.TempDir(), "clone"))
	var head string
	var first string
	for i := 0; i < 6; i++ {
		var parents []string
		if head != "" {
			parents = []string{head}
		}
		head = repo.commit(t, fmt.Sprintf("commit %d", i), parents)
		if first == "" {
			first = head
		}
	}
	repo.setHead(t, "refs/heads/master", head)

	d := ReviewDelta(Request{PkgBase: "foo-git", Dir: repo.work, Anchor: Anchor{Commit: first}, Max: 2})
	if d.Status != DeltaUndetermined {
		t.Fatalf("Status = %q, want %q", d.Status, DeltaUndetermined)
	}
	if !d.Truncated {
		t.Error("Truncated = false although the walk stopped at its bound")
	}
	if len(d.Gaps) == 0 {
		t.Fatal("a truncated walk produced no coverage gap")
	}
	text := strings.Join(d.Lines(), "\n")
	if strings.Contains(strings.ToLower(text), "up to date") {
		t.Fatalf("a truncated walk rendered as up to date:\n%s", text)
	}
	// It must not be reported as a vanished anchor either: that is an
	// accusation, and this evidence does not support it.
	for _, f := range d.Result().Findings {
		if f.RuleID == RuleVCSAnchorAbsent {
			t.Fatalf("a bounded walk was reported as a missing anchor: %+v", f)
		}
	}
}

// TestReachedButBoundedStillReportsTheBound: the anchor was found, and the walk
// still stopped at Max, so the rendered list is not the whole range. Measured
// live: with Max=20 the yay clone reaches its anchor AND fills the bound, so a
// caller reading only the list would under-count what changed.
func TestReachedButBoundedStillReportsTheBound(t *testing.T) {
	repo := newFixture(t, filepath.Join(t.TempDir(), "clone"))
	var head, first string
	for i := 0; i < 5; i++ {
		var parents []string
		if head != "" {
			parents = []string{head}
		}
		head = repo.commit(t, fmt.Sprintf("bounded %d", i), parents)
		if first == "" {
			first = head
		}
	}
	repo.setHead(t, "refs/heads/master", head)

	// Max=4 with 4 commits since the first: the anchor IS reached and the bound
	// is exactly filled.
	d := ReviewDelta(Request{PkgBase: "foo-git", Dir: repo.work, Anchor: Anchor{Commit: first}, Max: 4})
	if d.Status != DeltaAhead || !d.Reached {
		t.Fatalf("Status = %q Reached = %v, want new-commits and reached", d.Status, d.Reached)
	}
	if !d.Truncated {
		t.Fatal("Truncated = false although the walk filled its bound")
	}
	var found bool
	for _, g := range d.Gaps {
		if g.RuleID == RuleVCSTruncated {
			found = true
		}
	}
	if !found {
		t.Fatalf("a bounded range reported no %s gap: %+v", RuleVCSTruncated, d.Gaps)
	}
	if !strings.Contains(strings.Join(d.Lines(), "\n"), "bounded at 4") {
		t.Errorf("rendering does not say the list is bounded:\n%s", strings.Join(d.Lines(), "\n"))
	}
}

// TestNoAnchorIsAGap: a -git package with no recorded snapshot cannot have a
// delta reviewed. That is a coverage gap (INV-9/INV-10), not "nothing changed".
func TestNoAnchorIsAGap(t *testing.T) {
	repo := newFixture(t, filepath.Join(t.TempDir(), "clone"))
	c1 := repo.commit(t, "initial", nil)
	repo.setHead(t, "refs/heads/master", c1)

	d := ReviewDelta(Request{PkgBase: "foo-git", Dir: repo.work})
	if d.Status != DeltaUnanchored {
		t.Fatalf("Status = %q, want %q", d.Status, DeltaUnanchored)
	}
	if len(d.Gaps) == 0 || d.Gaps[0].RuleID != RuleVCSNoAnchor {
		t.Fatalf("gaps = %+v, want %s", d.Gaps, RuleVCSNoAnchor)
	}
	if d.Head != c1 {
		t.Errorf("Head = %q; the current position is still worth reporting", d.Head)
	}
	if strings.Contains(strings.ToLower(strings.Join(d.Lines(), "\n")), "up to date") {
		t.Error("an unanchored package rendered as up to date")
	}
}

// TestMalformedAnchorIsAGapNotACrash: the anchor comes from a snapshot file,
// which is state on disk. Garbage in it must not be read as "up to date".
func TestMalformedAnchorIsAGap(t *testing.T) {
	repo := newFixture(t, filepath.Join(t.TempDir(), "clone"))
	c1 := repo.commit(t, "initial", nil)
	repo.setHead(t, "refs/heads/master", c1)

	for _, bad := range []string{"HEAD", "refs/heads/master", "zz", strings.Repeat("a", 39), "../../etc"} {
		d := ReviewDelta(Request{PkgBase: "foo-git", Dir: repo.work, Anchor: Anchor{Commit: bad}})
		if d.Status != DeltaUnreadable && d.Status != DeltaUnanchored {
			t.Errorf("anchor %q: Status = %q, want a gap status", bad, d.Status)
		}
		if len(d.Gaps) == 0 {
			t.Errorf("anchor %q produced no gap", bad)
		}
	}
}

// TestUnreadableRepositoryIsAGap: no clone, no delta. Not silence.
func TestUnreadableRepositoryIsAGap(t *testing.T) {
	d := ReviewDelta(Request{PkgBase: "foo-git", Dir: filepath.Join(t.TempDir(), "nope"), Anchor: Anchor{Commit: strings.Repeat("a", 40)}})
	if d.Status != DeltaUnreadable {
		t.Fatalf("Status = %q, want %q", d.Status, DeltaUnreadable)
	}
	if len(d.Gaps) == 0 || d.Gaps[0].RuleID != RuleVCSUnreadable {
		t.Fatalf("gaps = %+v, want %s", d.Gaps, RuleVCSUnreadable)
	}
	if d.Result().Complete() {
		t.Error("a delta that could not be read reports itself complete")
	}
}

// TestIncompleteHistoryKeepsWhatItRead: a missing parent object truncates the
// walk. The commits that WERE read are still worth showing, and the shortfall
// is a gap rather than a discarded result.
func TestIncompleteHistoryKeepsWhatItRead(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "clone")
	repo := newFixture(t, dir)
	c1 := repo.commit(t, "initial", nil)
	c2 := repo.commit(t, "second", []string{c1})
	c3 := repo.commit(t, "third", []string{c2})
	repo.setHead(t, "refs/heads/master", c3)
	// Remove c1's object: the walk can read c3 and c2 and then cannot follow.
	if err := os.Remove(filepath.Join(repo.git, "objects", c1[:2], c1[2:])); err != nil {
		t.Fatal(err)
	}

	d := ReviewDelta(Request{PkgBase: "foo-git", Dir: repo.work, Anchor: Anchor{Commit: strings.Repeat("c", 40)}, Max: 50})
	if len(d.Commits) == 0 {
		t.Fatal("an incomplete walk discarded the commits it did read")
	}
	if len(d.Gaps) == 0 {
		t.Fatal("an incomplete walk reported no coverage gap")
	}
	if d.Status == DeltaUpToDate || d.Status == DeltaAhead {
		t.Fatalf("Status = %q; an incomplete history cannot claim a complete range", d.Status)
	}
}

// TestRemoteChangeIsReported: the recipe can keep the same source line while
// the clone points somewhere else, which the recipe digest cannot see.
func TestRemoteChangeIsReported(t *testing.T) {
	repo := newFixture(t, filepath.Join(t.TempDir(), "clone"))
	c1 := repo.commit(t, "initial", nil)
	repo.setHead(t, "refs/heads/master", c1)
	repo.writeFile(t, "config", "[core]\n\trepositoryformatversion = 0\n"+
		"[remote \"origin\"]\n\turl = https://evil.example/foo.git\n")

	d := ReviewDelta(Request{PkgBase: "foo-git", Dir: repo.work,
		Anchor: Anchor{Commit: c1, Remote: "https://aur.archlinux.org/foo.git"}})
	if !d.RemoteChanged {
		t.Fatal("RemoteChanged = false although the origin URL differs from the recorded one")
	}
	if d.Remote != "https://evil.example/foo.git" {
		t.Errorf("Remote = %q", d.Remote)
	}
	var found bool
	for _, f := range d.Result().Findings {
		if f.RuleID == RuleVCSRemoteChanged {
			found = true
		}
	}
	if !found {
		t.Fatalf("no %s finding: %+v", RuleVCSRemoteChanged, d.Result().Findings)
	}
	if d.Status != DeltaUpToDate {
		t.Errorf("Status = %q; the commit range really is empty and that stays true", d.Status)
	}
	if strings.Contains(strings.ToLower(strings.Join(d.Lines(), "\n")), "nothing to review") {
		t.Error("a changed remote rendered as nothing to review")
	}
}

// --- the reason task 11 exists at all ---------------------------------------

// TestApprovedGitRecipeStillReportsNewCommits is the justification, written as
// one test: the PKGBUILD of a -git package does not change when upstream moves,
// so the approval store is silent -- and the delta review is not. Remove
// vcsdelta.go and this test is the thing that fails.
func TestApprovedGitRecipeStillReportsNewCommits(t *testing.T) {
	s, _ := liveStore(t)
	root, dir := recipeDir(t, map[string]string{
		"PKGBUILD": "pkgbase=foo-git\npkgver=r1\nsource=('foo::git+https://example.invalid/foo.git')\n",
	})
	r := mustDigest(t, root, RecipeRequest{PkgBase: "foo-git", Dir: dir})

	repo := newFixture(t, filepath.Join(t.TempDir(), "clone"))
	c1 := repo.commit(t, "initial", nil)
	repo.setHead(t, "refs/heads/master", c1)

	if _, err := s.Approve(r, ApproveOptions{By: "operator", VCS: &Anchor{Commit: c1}}); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	// Upstream moves. The recipe does not.
	c2 := repo.commit(t, "add a curl|sh to build()", []string{c1})
	repo.setHead(t, "refs/heads/master", c2)

	again := mustDigest(t, root, RecipeRequest{PkgBase: "foo-git", Dir: dir})
	if again.Digest != r.Digest {
		t.Fatalf("precondition failed: the recipe digest moved (%s -> %s)", r.Digest, again.Digest)
	}
	dec := s.Lookup(again.PkgBase, again.Digest)
	if !dec.Silent() {
		t.Fatalf("precondition failed: the approval store was not silent (%q)", dec.Status)
	}
	if dec.Approval == nil || dec.Approval.VCS == nil {
		t.Fatal("the approval carries no VCS anchor, so the delta has nothing to measure from")
	}

	d := ReviewDelta(Request{PkgBase: "foo-git", Dir: repo.work, Anchor: *dec.Approval.VCS})
	if d.Status != DeltaAhead || len(d.Commits) != 1 {
		t.Fatalf("Status = %q Commits = %d; an approved -git recipe must still surface the new upstream commit",
			d.Status, len(d.Commits))
	}
	if !strings.Contains(strings.Join(d.Lines(), "\n"), "curl|sh") {
		t.Errorf("the new commit's subject is not rendered:\n%s", strings.Join(d.Lines(), "\n"))
	}
}

// --- live measurement -------------------------------------------------------

// TestLiveVCSDelta runs the delta review against the real helper clones. It is
// skipped by default: it reads $HOME, which no unit test may depend on.
func TestLiveVCSDelta(t *testing.T) {
	if os.Getenv("AURVET_LIVE_GATE") != "1" {
		t.Skip("set AURVET_LIVE_GATE=1 to measure against the live helper caches")
	}
	home := os.Getenv("HOME")
	if home == "" {
		t.Skip("no HOME")
	}
	var dirs []string
	for _, cache := range []string{
		filepath.Join(home, ".cache/yay"),
		filepath.Join(home, ".cache/paru/clone"),
		filepath.Join(home, ".cache/pikaur/aur_repos"),
		filepath.Join(home, ".cache/aurutils/sync"),
	} {
		ents, err := os.ReadDir(cache)
		if err != nil {
			t.Logf("cache %s: %v (coverage gap, not silence)", cache, err)
			continue
		}
		for _, e := range ents {
			if e.IsDir() {
				dirs = append(dirs, filepath.Join(cache, e.Name()))
			}
		}
	}

	var vcsStyle, ranged, absent, gapped, uptodate int
	for _, dir := range dirs {
		base := filepath.Base(dir)
		// A -git style package by the shape of its own recipe: read the
		// PKGBUILD text and look for a VCS source entry.
		raw, err := os.ReadFile(filepath.Join(dir, "PKGBUILD"))
		if err != nil {
			t.Logf("%-40s no PKGBUILD: %v", base, err)
		}
		isVCS := false
		for _, tok := range strings.FieldsFunc(string(raw), func(r rune) bool {
			return r == '\'' || r == '"' || r == ' ' || r == '\t' || r == '\n' || r == '(' || r == ')'
		}) {
			if kind, _ := VCSKind(tok); kind != "" {
				isVCS = true
				break
			}
		}
		if isVCS {
			vcsStyle++
		}

		// Anchor on the second commit so every readable clone produces a real
		// range, which is what the numbers below measure.
		commits, err := vcs.Log(dir, 3)
		anchor := ""
		if err == nil && len(commits) > 1 {
			anchor = commits[1].Hash
		} else if err == nil && len(commits) == 1 {
			anchor = commits[0].Hash
		}
		d := ReviewDelta(Request{PkgBase: base, Dir: dir, Anchor: Anchor{Commit: anchor}, Max: 20})
		switch d.Status {
		case DeltaAhead:
			ranged++
		case DeltaUpToDate:
			uptodate++
		case DeltaAnchorAbsent:
			absent++
		default:
			gapped++
		}
		t.Logf("%-40s vcs=%-5v status=%-20s commits=%d gaps=%d", base, isVCS, d.Status, len(d.Commits), len(d.Gaps))
	}
	t.Logf("clones=%d vcs-style=%d range=%d up-to-date=%d anchor-absent=%d gap=%d",
		len(dirs), vcsStyle, ranged, uptodate, absent, gapped)

	// A genuinely absent anchor across the whole cache, measured once.
	var orphanAbsent, orphanOther int
	for _, dir := range dirs {
		d := ReviewDelta(Request{PkgBase: filepath.Base(dir), Dir: dir,
			Anchor: Anchor{Commit: strings.Repeat("d", 40)}, Max: 10_000})
		if d.Status == DeltaAnchorAbsent {
			orphanAbsent++
		} else {
			orphanOther++
			t.Logf("orphan anchor %-30s status=%s gaps=%d", filepath.Base(dir), d.Status, len(d.Gaps))
		}
	}
	t.Logf("orphan-anchor sweep: reached==false/absent=%d other=%d", orphanAbsent, orphanOther)
}

// --- fixture construction ---------------------------------------------------
//
// Repositories are built from the raw object format, never by running git: a
// fixture that shells out to git makes this suite depend on the binary decision
// D-1 exists to avoid.

type gitFixture struct {
	work string
	git  string
	tree string
}

func newFixture(t *testing.T, work string) *gitFixture {
	t.Helper()
	f := &gitFixture{work: work, git: filepath.Join(work, ".git")}
	for _, d := range []string{"objects", "refs/heads"} {
		if err := os.MkdirAll(filepath.Join(f.git, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	f.writeFile(t, "HEAD", "ref: refs/heads/master\n")
	f.writeFile(t, "config", "[core]\n\trepositoryformatversion = 0\n"+
		"[remote \"origin\"]\n\turl = https://aur.archlinux.org/foo.git\n")
	f.tree = f.writeLoose(t, "tree", nil)
	return f
}

func (f *gitFixture) writeFile(t *testing.T, rel, body string) {
	t.Helper()
	abs := filepath.Join(f.git, rel)
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(abs, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func (f *gitFixture) setHead(t *testing.T, ref, sha string) {
	t.Helper()
	f.writeFile(t, "HEAD", "ref: "+ref+"\n")
	f.writeFile(t, ref, sha+"\n")
}

var fixtureSeq int

func (f *gitFixture) commit(t *testing.T, msg string, parents []string) string {
	t.Helper()
	fixtureSeq++
	var b bytes.Buffer
	fmt.Fprintf(&b, "tree %s\n", f.tree)
	for _, p := range parents {
		fmt.Fprintf(&b, "parent %s\n", p)
	}
	when := 1785924000 + fixtureSeq*60
	fmt.Fprintf(&b, "author A U Thor <author@example.com> %d +0200\n", when)
	fmt.Fprintf(&b, "committer C O Mitter <committer@example.com> %d +0200\n", when)
	b.WriteString("\n")
	b.WriteString(msg)
	b.WriteString("\n")
	return f.writeLoose(t, "commit", b.Bytes())
}

func (f *gitFixture) writeLoose(t *testing.T, typ string, body []byte) string {
	t.Helper()
	h := sha1.New()
	fmt.Fprintf(h, "%s %d", typ, len(body))
	h.Write([]byte{0})
	h.Write(body)
	sha := hex.EncodeToString(h.Sum(nil))

	var raw bytes.Buffer
	fmt.Fprintf(&raw, "%s %d", typ, len(body))
	raw.WriteByte(0)
	raw.Write(body)

	var z bytes.Buffer
	w := zlib.NewWriter(&z)
	if _, err := w.Write(raw.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(f.git, "objects", sha[:2])
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, sha[2:]), z.Bytes(), 0o444); err != nil {
		t.Fatal(err)
	}
	return sha
}
