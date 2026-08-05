// internal/vcs/gitlog_test.go
package vcs

import (
	"bytes"
	"compress/zlib"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// --- the proof that matters: no exec, ever ---------------------------------

// TestPackageImportsNoExec is the structural half of decision D-1's proof. A
// comment saying "we do not exec" is not proof; an assertion over the package's
// own import graph is, and it fails the moment someone adds the import back.
//
// os/exec is the direct route, but syscall.Exec/ForkExec and golang.org/x/sys
// are the same capability under another name, so all three are refused.
func TestPackageImportsNoExec(t *testing.T) {
	banned := map[string]string{
		"os/exec":          "runs a binary",
		"syscall":          "Exec/ForkExec are the same capability under another name",
		"golang.org/x/sys": "unix.Exec is the same capability under another name",
	}
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parse package: %v", err)
	}
	seen := 0
	for _, pkg := range pkgs {
		for name, file := range pkg.Files {
			if strings.HasSuffix(name, "_test.go") {
				continue
			}
			seen++
			for _, imp := range file.Imports {
				p := strings.Trim(imp.Path.Value, `"`)
				if why, bad := banned[p]; bad {
					t.Errorf("%s imports %q (%s); decision D-1 forbids executing git against an "+
						"attacker-controlled repository", name, p, why)
				}
			}
		}
	}
	if seen == 0 {
		t.Fatal("parsed no non-test files; this assertion would pass vacuously")
	}
}

// TestHostileConfigIsNeverExecuted is the behavioural half. The repository is
// attacker-controlled: it carries a .git/config with core.pager,
// core.fsmonitor, core.sshCommand, core.hooksPath and an alias, all naming a
// command that creates a sentinel file, plus an executable hook. Every one of
// those is a documented way to make `git` -- even a read-only `git log` --
// execute a command out of the repository it is reading.
//
// The assertion is that the sentinel does not exist afterwards AND that the
// reader still produced the right answers: refusing to read is not the same as
// reading safely.
func TestHostileConfigIsNeverExecuted(t *testing.T) {
	dir := t.TempDir()
	sentinel := filepath.Join(dir, "sentinel")
	payload := "sh -c 'touch " + sentinel + "'"

	repo := newRepo(t, filepath.Join(dir, "clone"))
	head := repo.commit(t, "initial import", nil)
	repo.setHead(t, "refs/heads/master", head)
	repo.writeFile(t, "config", strings.Join([]string{
		"[core]",
		"\tpager = " + payload,
		"\tfsmonitor = " + payload,
		"\tsshCommand = " + payload,
		"\thooksPath = " + filepath.Join(dir, "clone", ".git", "hooks"),
		"\teditor = " + payload,
		"[alias]",
		"\tlog = !" + payload,
		"\thead = !" + payload,
		"[remote \"origin\"]",
		"\turl = https://aur.archlinux.org/evil.git",
		"\tproxy = " + payload,
		"[uploadpack]",
		"\tpackObjectsHook = " + payload,
		"",
	}, "\n"))
	for _, hook := range []string{"post-checkout", "pre-commit", "fsmonitor-watchman"} {
		repo.writeExec(t, "hooks/"+hook, "#!/bin/sh\ntouch "+sentinel+"\n")
	}

	gotHead, err := Head(repo.work)
	if err != nil {
		t.Fatalf("Head: %v", err)
	}
	if gotHead != head {
		t.Errorf("Head = %s, want %s", gotHead, head)
	}
	commits, err := Log(repo.work, 10)
	if err != nil {
		t.Fatalf("Log: %v", err)
	}
	if len(commits) != 1 || commits[0].Subject != "initial import" {
		t.Errorf("Log = %+v", commits)
	}
	remote, err := Remote(repo.work)
	if err != nil {
		t.Fatalf("Remote: %v", err)
	}
	if remote != "https://aur.archlinux.org/evil.git" {
		t.Errorf("Remote = %q", remote)
	}

	if _, err := os.Lstat(sentinel); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("sentinel %s exists: the repository's own configuration was executed (err=%v)", sentinel, err)
	}
}

// TestGitDirPointerFileIsRefused: a ".git" FILE names a git directory
// elsewhere. Following an attacker-supplied pointer out of the tree being
// inspected is not a read this package performs, so it is a refusal (and a
// coverage gap for the caller), not a traversal.
func TestGitDirPointerFileIsRefused(t *testing.T) {
	dir := t.TempDir()
	work := filepath.Join(dir, "clone")
	if err := os.MkdirAll(work, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, ".git"), []byte("gitdir: /etc\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Head(work)
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Head on a gitdir-pointer repo: err = %v, want ErrUnsupported", err)
	}
}

// TestSymlinkedHeadIsRefused: HEAD is read through the confined API, which
// refuses a symlink leaf unresolved. A HEAD symlinked at /etc/passwd must not
// be read at all.
func TestSymlinkedHeadIsRefused(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "outside")
	if err := os.WriteFile(target, []byte("ref: refs/heads/master\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	repo := newRepo(t, filepath.Join(dir, "clone"))
	if err := os.Remove(filepath.Join(repo.git, "HEAD")); err != nil && !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(repo.git, "HEAD")); err != nil {
		t.Fatal(err)
	}
	if _, err := Head(repo.work); err == nil {
		t.Fatal("Head followed a symlinked HEAD out of the repository")
	}
}

// --- HEAD resolution ------------------------------------------------------

func TestHeadFromLooseRef(t *testing.T) {
	repo := newRepo(t, filepath.Join(t.TempDir(), "clone"))
	sha := repo.commit(t, "one", nil)
	repo.setHead(t, "refs/heads/master", sha)

	got, err := Head(repo.work)
	if err != nil {
		t.Fatalf("Head: %v", err)
	}
	if got != sha {
		t.Errorf("Head = %s, want %s", got, sha)
	}
}

// TestHeadFromPackedRefs: every one of the 34 clones in the reference
// system's yay cache has a packed-refs file, and 34 of 34 resolve HEAD only
// through it after a fresh clone. Loose-refs-only support would report a
// coverage gap for the entire population.
func TestHeadFromPackedRefs(t *testing.T) {
	repo := newRepo(t, filepath.Join(t.TempDir(), "clone"))
	sha := repo.commit(t, "one", nil)
	repo.writeFile(t, "HEAD", "ref: refs/heads/master\n")
	repo.writeFile(t, "packed-refs", "# pack-refs with: peeled fully-peeled sorted \n"+
		sha+" refs/heads/master\n"+
		strings.Repeat("f", 40)+" refs/remotes/origin/master\n")

	got, err := Head(repo.work)
	if err != nil {
		t.Fatalf("Head: %v", err)
	}
	if got != sha {
		t.Errorf("Head = %s, want %s (packed-refs was not consulted)", got, sha)
	}
}

// TestLooseRefWinsOverPackedRef mirrors git's own precedence: a loose ref is
// newer than the packed copy. Getting this backwards reports a stale commit as
// the one that was built.
func TestLooseRefWinsOverPackedRef(t *testing.T) {
	repo := newRepo(t, filepath.Join(t.TempDir(), "clone"))
	old := repo.commit(t, "old", nil)
	newer := repo.commit(t, "new", []string{old})
	repo.writeFile(t, "HEAD", "ref: refs/heads/master\n")
	repo.writeFile(t, "packed-refs", old+" refs/heads/master\n")
	repo.writeFile(t, "refs/heads/master", newer+"\n")

	got, err := Head(repo.work)
	if err != nil {
		t.Fatalf("Head: %v", err)
	}
	if got != newer {
		t.Errorf("Head = %s, want the loose ref %s", got, newer)
	}
}

func TestHeadDetached(t *testing.T) {
	repo := newRepo(t, filepath.Join(t.TempDir(), "clone"))
	sha := repo.commit(t, "one", nil)
	repo.writeFile(t, "HEAD", sha+"\n")

	got, err := Head(repo.work)
	if err != nil {
		t.Fatalf("Head: %v", err)
	}
	if got != sha {
		t.Errorf("Head = %s, want %s", got, sha)
	}
}

func TestHeadBareRepo(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "bare.git")
	repo := newBareRepo(t, dir)
	sha := repo.commit(t, "one", nil)
	repo.setHead(t, "refs/heads/master", sha)

	got, err := Head(dir)
	if err != nil {
		t.Fatalf("Head on a bare repo: %v", err)
	}
	if got != sha {
		t.Errorf("Head = %s, want %s", got, sha)
	}
}

func TestHeadDanglingRef(t *testing.T) {
	repo := newRepo(t, filepath.Join(t.TempDir(), "clone"))
	repo.writeFile(t, "HEAD", "ref: refs/heads/master\n")

	_, err := Head(repo.work)
	if !errors.Is(err, ErrNoRef) {
		t.Fatalf("Head with an unborn branch: err = %v, want ErrNoRef", err)
	}
}

func TestHeadNotARepo(t *testing.T) {
	_, err := Head(t.TempDir())
	if !errors.Is(err, ErrNotRepo) {
		t.Fatalf("err = %v, want ErrNotRepo", err)
	}
}

// TestHeadRefLoopIsBounded: HEAD -> refs/a -> refs/b -> refs/a is a hang, and
// a hang outranks a panic. The chain is bounded and the bound is reported.
func TestHeadRefLoopIsBounded(t *testing.T) {
	repo := newRepo(t, filepath.Join(t.TempDir(), "clone"))
	repo.writeFile(t, "HEAD", "ref: refs/heads/a\n")
	repo.writeFile(t, "refs/heads/a", "ref: refs/heads/b\n")
	repo.writeFile(t, "refs/heads/b", "ref: refs/heads/a\n")

	done := make(chan error, 1)
	go func() { _, err := Head(repo.work); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, ErrLimit) {
			t.Fatalf("err = %v, want ErrLimit", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Head hung on a symref loop")
	}
}

// TestRefNameIsValidated: a ref name is a path this package then opens. "../"
// in it would be a traversal, and the confined API is the backstop, not the
// only check.
func TestRefNameIsValidated(t *testing.T) {
	repo := newRepo(t, filepath.Join(t.TempDir(), "clone"))
	for _, bad := range []string{
		"ref: ../../../../etc/passwd\n",
		"ref: /etc/passwd\n",
		"ref: refs/heads/../../etc/passwd\n",
		"ref: \n",
	} {
		repo.writeFile(t, "HEAD", bad)
		if _, err := Head(repo.work); err == nil {
			t.Errorf("Head accepted HEAD=%q", bad)
		}
	}
}

// --- commit reading, loose objects ----------------------------------------

func TestLogReadsLooseCommits(t *testing.T) {
	repo := newRepo(t, filepath.Join(t.TempDir(), "clone"))
	a := repo.commitAt(t, "first", nil, 0)
	b := repo.commitAt(t, "second\n\nwith a body\n", []string{a}, 60)
	repo.setHead(t, "refs/heads/master", b)

	commits, err := Log(repo.work, 10)
	if err != nil {
		t.Fatalf("Log: %v", err)
	}
	if len(commits) != 2 {
		t.Fatalf("commits = %d, want 2: %+v", len(commits), commits)
	}
	if commits[0].Hash != b || commits[1].Hash != a {
		t.Errorf("order = %s,%s want %s,%s", commits[0].Hash, commits[1].Hash, b, a)
	}
	c := commits[0]
	if c.Subject != "second" {
		t.Errorf("Subject = %q, want %q", c.Subject, "second")
	}
	if !strings.Contains(c.Message, "with a body") {
		t.Errorf("Message = %q", c.Message)
	}
	if c.Author.Name != "A U Thor" || c.Author.Email != "author@example.com" {
		t.Errorf("Author = %+v", c.Author)
	}
	if c.Committer.Name != "C O Mitter" {
		t.Errorf("Committer = %+v", c.Committer)
	}
	// The offset is explicit, not the local zone: the reference pacman.log
	// mixes two offsets and every timestamp in this project is parsed with the
	// one it was written with.
	if _, off := c.Author.When.Zone(); off != 2*3600 {
		t.Errorf("author offset = %d, want +7200", off)
	}
	if got := commits[1].Author.When.UTC().Format(time.RFC3339); got != "2026-08-05T10:00:00Z" {
		t.Errorf("oldest commit author time = %s, want 2026-08-05T10:00:00Z", got)
	}
	if got := c.Author.When.UTC().Format(time.RFC3339); got != "2026-08-05T10:01:00Z" {
		t.Errorf("author time = %s, want 2026-08-05T10:01:00Z", got)
	}
	if len(c.Parents) != 1 || c.Parents[0] != a {
		t.Errorf("Parents = %v", c.Parents)
	}
	if c.Tree == "" {
		t.Error("Tree not parsed")
	}
}

// TestLogNBound: n is attacker-adjacent (a commit count out of a config) and
// the history is attacker-controlled. Both ends are bounded.
func TestLogNBound(t *testing.T) {
	repo := newRepo(t, filepath.Join(t.TempDir(), "clone"))
	var prev string
	var shas []string
	for i := 0; i < 8; i++ {
		prev = repo.commit(t, fmt.Sprintf("c%d", i), parentsOf(prev))
		shas = append(shas, prev)
	}
	repo.setHead(t, "refs/heads/master", prev)

	commits, err := Log(repo.work, 3)
	if err != nil {
		t.Fatalf("Log: %v", err)
	}
	if len(commits) != 3 {
		t.Fatalf("commits = %d, want 3", len(commits))
	}
	if commits[0].Hash != shas[7] || commits[2].Hash != shas[5] {
		t.Errorf("wrong window: %s..%s", commits[0].Hash, commits[2].Hash)
	}

	if _, err := Log(repo.work, 0); !errors.Is(err, ErrLimit) {
		t.Errorf("Log(n=0): err = %v, want ErrLimit", err)
	}
	if _, err := Log(repo.work, -1); !errors.Is(err, ErrLimit) {
		t.Errorf("Log(n=-1): err = %v, want ErrLimit", err)
	}
	if _, err := Log(repo.work, 1<<30); !errors.Is(err, ErrLimit) {
		t.Errorf("Log(n=1<<30): err = %v, want ErrLimit", err)
	}
}

// TestLogStopsAtMissingParent: a shallow or truncated clone runs out of
// objects. That is a coverage gap for the commits not read, and the commits
// that WERE read are still returned -- refusing everything because the tenth
// object is missing would throw away nine facts.
func TestLogStopsAtMissingParent(t *testing.T) {
	repo := newRepo(t, filepath.Join(t.TempDir(), "clone"))
	missing := strings.Repeat("a", 40)
	sha := repo.commit(t, "only", []string{missing})
	repo.setHead(t, "refs/heads/master", sha)

	commits, err := Log(repo.work, 10)
	if !errors.Is(err, ErrIncomplete) {
		t.Fatalf("err = %v, want ErrIncomplete", err)
	}
	if len(commits) != 1 || commits[0].Hash != sha {
		t.Fatalf("commits = %+v, want the one readable commit", commits)
	}
	if !strings.Contains(err.Error(), missing) {
		t.Errorf("error must name the unreadable object, got %v", err)
	}
}

// TestObjectHashIsVerified: the object store is attacker-controlled, so an
// object's name is a claim about its content. A repository that maps a sha to
// something else would otherwise let the reader report a commit message,
// author and date that belong to a different object.
func TestObjectHashIsVerified(t *testing.T) {
	repo := newRepo(t, filepath.Join(t.TempDir(), "clone"))
	real := repo.commit(t, "honest", nil)
	lie := strings.Repeat("b", 40)
	// Store an honest-looking commit under a name that is not its hash.
	repo.writeLooseAt(t, lie, "commit", commitBody(t, repo.tree, nil, "forged", 0))
	repo.writeFile(t, "HEAD", lie+"\n")

	_, err := Log(repo.work, 10)
	if !errors.Is(err, ErrCorrupt) && !errors.Is(err, ErrIncomplete) {
		t.Fatalf("err = %v, want ErrCorrupt (or ErrIncomplete carrying it)", err)
	}
	if !strings.Contains(err.Error(), lie) {
		t.Errorf("error must name the object whose hash did not match: %v", err)
	}
	_ = real
}

// TestLooseObjectSizeBounded: an inflated-size claim in the object header, and
// the actual inflated stream, are both attacker-controlled. A zlib bomb in a
// .git/objects file must be a bounded refusal.
func TestLooseObjectSizeBounded(t *testing.T) {
	repo := newRepo(t, filepath.Join(t.TempDir(), "clone"))
	body := commitBody(t, repo.tree, nil, strings.Repeat("A", 200_000), 0)
	sha := repo.writeLoose(t, "commit", body)
	repo.writeFile(t, "HEAD", sha+"\n")

	r, err := Open(repo.work, Limits{MaxObjectBytes: 1024})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer r.Close()
	if _, err := r.Log("", 5); !errors.Is(err, ErrLimit) && !errors.Is(err, ErrIncomplete) {
		t.Fatalf("err = %v, want ErrLimit", err)
	}
}

// TestNonCommitAtHeadIsRefused: HEAD naming a blob is not a history.
func TestNonCommitAtHeadIsRefused(t *testing.T) {
	repo := newRepo(t, filepath.Join(t.TempDir(), "clone"))
	sha := repo.writeLoose(t, "blob", []byte("not a commit"))
	repo.writeFile(t, "HEAD", sha+"\n")

	if _, err := Log(repo.work, 5); !errors.Is(err, ErrIncomplete) && !errors.Is(err, ErrCorrupt) {
		t.Fatalf("err = %v, want a refusal", err)
	}
}

// TestGarbageObjectIsNotAPanic: the object file is not a zlib stream at all.
func TestGarbageObjectIsNotAPanic(t *testing.T) {
	repo := newRepo(t, filepath.Join(t.TempDir(), "clone"))
	sha := strings.Repeat("c", 40)
	if err := os.MkdirAll(filepath.Join(repo.git, "objects", sha[:2]), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo.git, "objects", sha[:2], sha[2:]),
		[]byte("\x00\x01\x02not zlib"), 0o644); err != nil {
		t.Fatal(err)
	}
	repo.writeFile(t, "HEAD", sha+"\n")

	if _, err := Log(repo.work, 5); err == nil {
		t.Fatal("garbage object read as a commit")
	}
}

// --- packfiles ------------------------------------------------------------

// TestLogReadsPackedCommits is the case that decides whether this reader is
// useful at all: `git clone` puts every object in a packfile, so all 34 clones
// in the reference system's yay cache have an EMPTY loose object store. A
// loose-only reader would report a coverage gap for 34 of 34.
func TestLogReadsPackedCommits(t *testing.T) {
	repo := newRepo(t, filepath.Join(t.TempDir(), "clone"))
	tree := repo.tree
	a := commitBody(t, tree, nil, "first", 0)
	shaA := fixtureID("commit", a)
	b := commitBody(t, tree, []string{shaA}, "second", 60)
	shaB := fixtureID("commit", b)

	repo.writePack(t, []packEntry{
		{typ: objCommit, data: a},
		{typ: objCommit, data: b},
	})
	repo.writeFile(t, "packed-refs", shaB+" refs/heads/master\n")
	repo.writeFile(t, "HEAD", "ref: refs/heads/master\n")

	commits, err := Log(repo.work, 10)
	if err != nil {
		t.Fatalf("Log over a packfile: %v", err)
	}
	if len(commits) != 2 || commits[0].Hash != shaB || commits[1].Hash != shaA {
		t.Fatalf("commits = %+v", commits)
	}
	if commits[0].Subject != "second" || commits[1].Subject != "first" {
		t.Errorf("subjects = %q,%q", commits[0].Subject, commits[1].Subject)
	}
}

// TestLogReadsDeltifiedCommits: git deltifies commits against each other, so a
// packfile reader that handles only whole objects reads the first commit and
// gaps on the rest. Both delta forms are exercised because a pack from a clone
// uses OFS_DELTA and one from a thin-pack fetch uses REF_DELTA.
func TestLogReadsDeltifiedCommits(t *testing.T) {
	repo := newRepo(t, filepath.Join(t.TempDir(), "clone"))
	tree := repo.tree
	base := commitBody(t, tree, nil, "base commit with a long enough subject to share a prefix", 0)
	shaBase := fixtureID("commit", base)
	mid := commitBody(t, tree, []string{shaBase}, "base commit with a long enough subject to share a prefix, mid", 60)
	shaMid := fixtureID("commit", mid)
	tip := commitBody(t, tree, []string{shaMid}, "base commit with a long enough subject to share a prefix, tip", 120)
	shaTip := fixtureID("commit", tip)

	repo.writePack(t, []packEntry{
		{typ: objCommit, data: base},
		{typ: objRefDelta, data: mid, baseSHA: shaBase},
		{typ: objOfsDelta, data: tip, baseIndex: 1},
	})
	repo.writeFile(t, "packed-refs", shaTip+" refs/heads/master\n")
	repo.writeFile(t, "HEAD", "ref: refs/heads/master\n")

	commits, err := Log(repo.work, 10)
	if err != nil {
		t.Fatalf("Log over deltified commits: %v", err)
	}
	if len(commits) != 3 {
		t.Fatalf("commits = %d, want 3: %+v", len(commits), commits)
	}
	if commits[0].Hash != shaTip || commits[1].Hash != shaMid || commits[2].Hash != shaBase {
		t.Errorf("hashes = %s %s %s", commits[0].Hash, commits[1].Hash, commits[2].Hash)
	}
	if !strings.HasSuffix(commits[0].Subject, "tip") {
		t.Errorf("delta reconstruction wrong: subject = %q", commits[0].Subject)
	}
}

// TestPackedObjectHashIsVerified: an idx that maps a sha to the wrong pack
// offset is the packed form of the forgery TestObjectHashIsVerified covers.
func TestPackedObjectHashIsVerified(t *testing.T) {
	repo := newRepo(t, filepath.Join(t.TempDir(), "clone"))
	body := commitBody(t, repo.tree, nil, "honest", 0)
	lie := strings.Repeat("d", 40)
	repo.writePack(t, []packEntry{{typ: objCommit, data: body, overrideSHA: lie}})
	repo.writeFile(t, "HEAD", lie+"\n")

	if _, err := Log(repo.work, 5); !errors.Is(err, ErrCorrupt) && !errors.Is(err, ErrIncomplete) {
		t.Fatalf("err = %v, want a hash-mismatch refusal", err)
	}
}

// TestDeltaChainDepthBounded: a self-referential or very long delta chain is a
// hang or an allocation, and both are denial of tool.
func TestDeltaChainDepthBounded(t *testing.T) {
	repo := newRepo(t, filepath.Join(t.TempDir(), "clone"))
	base := commitBody(t, repo.tree, nil, "base", 0)
	entries := []packEntry{{typ: objCommit, data: base}}
	prev := base
	for i := 0; i < 12; i++ {
		next := commitBody(t, repo.tree, []string{fixtureID("commit", prev)}, fmt.Sprintf("step %d", i), i*60)
		entries = append(entries, packEntry{typ: objOfsDelta, data: next, baseIndex: len(entries) - 1})
		prev = next
	}
	tip := fixtureID("commit", prev)
	repo.writePack(t, entries)
	repo.writeFile(t, "HEAD", tip+"\n")

	r, err := Open(repo.work, Limits{MaxDeltaDepth: 3})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer r.Close()
	if _, err := r.Log("", 5); !errors.Is(err, ErrLimit) && !errors.Is(err, ErrIncomplete) {
		t.Fatalf("err = %v, want ErrLimit for a chain deeper than the cap", err)
	}
}

// TestSelfReferentialOfsDeltaIsRefused: an OFS_DELTA whose base offset is its
// own offset is an infinite loop that a depth counter alone would not catch
// quickly enough to be obviously safe. It must be refused outright.
func TestSelfReferentialOfsDeltaIsRefused(t *testing.T) {
	repo := newRepo(t, filepath.Join(t.TempDir(), "clone"))
	body := commitBody(t, repo.tree, nil, "loop", 0)
	sha := fixtureID("commit", body)
	repo.writeSelfDeltaPack(t, sha)
	repo.writeFile(t, "HEAD", sha+"\n")

	done := make(chan error, 1)
	go func() { _, err := Log(repo.work, 5); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("self-referential delta produced a commit")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("hung on a self-referential delta")
	}
}

// TestUnsupportedIdxVersionIsAGap: idx v1 has no magic and a different layout.
// Guessing at it would mean reading offsets out of the wrong place; refusing is
// a coverage gap and is honest.
func TestUnsupportedIdxVersionIsAGap(t *testing.T) {
	repo := newRepo(t, filepath.Join(t.TempDir(), "clone"))
	sha := repo.commit(t, "loose copy", nil)
	pack := filepath.Join(repo.git, "objects", "pack")
	if err := os.MkdirAll(pack, 0o755); err != nil {
		t.Fatal(err)
	}
	// v1 idx: no magic, straight into the fanout table.
	if err := os.WriteFile(filepath.Join(pack, "pack-old.idx"), make([]byte, 256*4+24), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pack, "pack-old.pack"), []byte("PACK"), 0o644); err != nil {
		t.Fatal(err)
	}
	repo.writeFile(t, "HEAD", sha+"\n")

	r, err := Open(repo.work, Limits{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer r.Close()
	// The loose object still resolves; the unreadable index is reported.
	commits, err := r.Log("", 5)
	if err != nil {
		t.Fatalf("Log: %v", err)
	}
	if len(commits) != 1 {
		t.Fatalf("commits = %+v", commits)
	}
	gaps := r.Gaps()
	if len(gaps) == 0 {
		t.Fatal("an unreadable pack index produced no gap")
	}
	found := false
	for _, g := range gaps {
		if strings.Contains(g.Subject, "pack-old.idx") {
			found = true
		}
		if g.RuleID == "" || g.Reason == "" {
			t.Errorf("incomplete gap %+v", g)
		}
	}
	if !found {
		t.Errorf("gaps do not name the unreadable index: %+v", gaps)
	}
}

// TestAlternatesAreNotFollowed: objects/info/alternates names another object
// store, by absolute path, in the repository we do not trust.
func TestAlternatesAreNotFollowed(t *testing.T) {
	repo := newRepo(t, filepath.Join(t.TempDir(), "clone"))
	sha := repo.commit(t, "one", nil)
	repo.setHead(t, "refs/heads/master", sha)
	if err := os.MkdirAll(filepath.Join(repo.git, "objects", "info"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo.git, "objects", "info", "alternates"),
		[]byte("/etc\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	r, err := Open(repo.work, Limits{})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer r.Close()
	if _, err := r.Log("", 5); err != nil {
		t.Fatalf("Log: %v", err)
	}
	if len(r.Gaps()) == 0 {
		t.Error("an alternates file produced no gap; a caller cannot know objects were out of reach")
	}
}

// TestSHA256RepositoryIsRefused: hash verification is the reader's integrity
// check, and it is a SHA-1 check. A sha256 repository would fail every
// verification, which would read as corruption rather than as "this format is
// not supported".
func TestSHA256RepositoryIsRefused(t *testing.T) {
	repo := newRepo(t, filepath.Join(t.TempDir(), "clone"))
	repo.writeFile(t, "config", "[core]\n\trepositoryformatversion = 1\n[extensions]\n\tobjectformat = sha256\n")
	sha := repo.commit(t, "one", nil)
	repo.writeFile(t, "HEAD", sha+"\n")

	if _, err := Head(repo.work); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("err = %v, want ErrUnsupported for a sha256 repository", err)
	}
}

// --- LogSince, the VCS-delta primitive ------------------------------------

// TestLogSinceReportsTheRange is what P2 task 11 needs: for a -git package the
// recipe is stable while the source moves, so approving once would bless
// unbounded future commits.
func TestLogSinceReportsTheRange(t *testing.T) {
	repo := newRepo(t, filepath.Join(t.TempDir(), "clone"))
	var prev string
	var shas []string
	for i := 0; i < 5; i++ {
		prev = repo.commit(t, fmt.Sprintf("c%d", i), parentsOf(prev))
		shas = append(shas, prev)
	}
	repo.setHead(t, "refs/heads/master", prev)

	commits, reached, err := LogSince(repo.work, shas[1], 10)
	if err != nil {
		t.Fatalf("LogSince: %v", err)
	}
	if !reached {
		t.Error("reached = false although the recorded commit is in this history")
	}
	if len(commits) != 3 {
		t.Fatalf("commits = %d, want 3 (c4,c3,c2): %+v", len(commits), commits)
	}
	if commits[len(commits)-1].Hash != shas[2] {
		t.Errorf("range excludes the recorded commit itself; got oldest %s", commits[len(commits)-1].Hash)
	}

	// A recorded commit that is not in this history at all: the delta cannot be
	// computed and the caller must be able to tell that from an empty range.
	commits, reached, err = LogSince(repo.work, strings.Repeat("e", 40), 10)
	if err != nil {
		t.Fatalf("LogSince(unknown): %v", err)
	}
	if reached {
		t.Error("reached = true for a commit that is not in this history")
	}
	if len(commits) != 5 {
		t.Errorf("commits = %d, want the whole bounded history", len(commits))
	}

	// Already up to date is an empty range with reached = true, which must not
	// be confusable with the unknown-commit case above.
	commits, reached, err = LogSince(repo.work, prev, 10)
	if err != nil || !reached || len(commits) != 0 {
		t.Errorf("LogSince(head) = %+v, %v, %v; want empty, true, nil", commits, reached, err)
	}
}

// --- remotes --------------------------------------------------------------

func TestRemoteReadsOrigin(t *testing.T) {
	repo := newRepo(t, filepath.Join(t.TempDir(), "clone"))
	repo.writeFile(t, "config", strings.Join([]string{
		"[core]",
		"\trepositoryformatversion = 0",
		`[remote "upstream"]`,
		"\turl = https://example.invalid/other.git",
		`[remote "origin"]`,
		"\turl = https://aur.archlinux.org/hello.git",
		"\tfetch = +refs/heads/*:refs/remotes/origin/*",
		`[branch "master"]`,
		"\tremote = origin",
		"",
	}, "\n"))

	got, err := Remote(repo.work)
	if err != nil {
		t.Fatalf("Remote: %v", err)
	}
	if got != "https://aur.archlinux.org/hello.git" {
		t.Errorf("Remote = %q", got)
	}
	all, err := Remotes(repo.work)
	if err != nil {
		t.Fatalf("Remotes: %v", err)
	}
	if len(all) != 2 || all["upstream"] != "https://example.invalid/other.git" {
		t.Errorf("Remotes = %v", all)
	}
}

func TestRemoteAbsentIsNotAnEmptyString(t *testing.T) {
	repo := newRepo(t, filepath.Join(t.TempDir(), "clone"))
	repo.writeFile(t, "config", "[core]\n\tbare = false\n")

	got, err := Remote(repo.work)
	if !errors.Is(err, ErrNoRemote) {
		t.Fatalf("err = %v, want ErrNoRemote", err)
	}
	if got != "" {
		t.Errorf("Remote = %q with an error", got)
	}
}

// TestRemoteIncludeIsNotFollowed: git's [include] path= reads another file,
// which in an attacker-controlled repository is an arbitrary read. It is not
// followed, and the refusal is visible in the error so a caller does not read
// "no remote" as "no remote configured".
func TestRemoteIncludeIsNotFollowed(t *testing.T) {
	dir := t.TempDir()
	repo := newRepo(t, filepath.Join(dir, "clone"))
	secret := filepath.Join(dir, "secret.cfg")
	if err := os.WriteFile(secret, []byte("[remote \"origin\"]\n\turl = https://leaked.invalid/\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	repo.writeFile(t, "config", "[include]\n\tpath = "+secret+"\n")

	got, err := Remote(repo.work)
	if err == nil {
		t.Fatalf("Remote followed an include and returned %q", got)
	}
	if !strings.Contains(err.Error(), "include") {
		t.Errorf("error does not mention the unfollowed include: %v", err)
	}
}

// TestConfigSizeBounded: .git/config is attacker-written.
func TestConfigSizeBounded(t *testing.T) {
	repo := newRepo(t, filepath.Join(t.TempDir(), "clone"))
	repo.writeFile(t, "config", "[core]\n\tx = "+strings.Repeat("A", 100_000)+"\n")

	r, err := Open(repo.work, Limits{MaxConfigBytes: 1024})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer r.Close()
	if _, err := r.Remote(); !errors.Is(err, ErrLimit) {
		t.Fatalf("err = %v, want ErrLimit", err)
	}
}

// TestRemoteURLIsNotInterpreted: an ext:: URL or one naming a command is
// reported verbatim. This package's job is to report what the repository says,
// not to normalise it -- and certainly not to act on it.
func TestRemoteURLIsNotInterpreted(t *testing.T) {
	repo := newRepo(t, filepath.Join(t.TempDir(), "clone"))
	hostile := `ext::sh -c touch% /tmp/aurvet-sentinel`
	repo.writeFile(t, "config", "[remote \"origin\"]\n\turl = "+hostile+"\n")

	got, err := Remote(repo.work)
	if err != nil {
		t.Fatalf("Remote: %v", err)
	}
	if got != hostile {
		t.Errorf("Remote = %q, want the verbatim value %q", got, hostile)
	}
}

// --- purity ---------------------------------------------------------------

// TestReadersWriteNothing: INV-5. Under --offline-root every one of these runs
// against a mounted target that must not be modified, and a real `git` would
// happily write .git/index, a lock file or a fetched pack.
func TestReadersWriteNothing(t *testing.T) {
	repo := newRepo(t, filepath.Join(t.TempDir(), "clone"))
	sha := repo.commit(t, "one", nil)
	repo.setHead(t, "refs/heads/master", sha)
	repo.writeFile(t, "config", "[remote \"origin\"]\n\turl = https://aur.archlinux.org/x.git\n")

	before := treeSnapshot(t, repo.work)
	if _, err := Head(repo.work); err != nil {
		t.Fatal(err)
	}
	if _, err := Log(repo.work, 5); err != nil {
		t.Fatal(err)
	}
	if _, err := Remote(repo.work); err != nil {
		t.Fatal(err)
	}
	if after := treeSnapshot(t, repo.work); after != before {
		t.Errorf("a reader mutated the repository:\nbefore\n%s\nafter\n%s", before, after)
	}
}

// --- live measurement -----------------------------------------------------

// TestLiveHelperClones reads the real helper caches on the machine this runs
// on, through this package's own object reader. Skipped by default: it reads
// $HOME, which no unit test may depend on. AURVET_LIVE_VCS=1 reproduces the
// numbers in the P2 receipt.
func TestLiveHelperClones(t *testing.T) {
	if os.Getenv("AURVET_LIVE_VCS") != "1" {
		t.Skip("set AURVET_LIVE_VCS=1 to measure against the live system")
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
	t.Logf("clones found: %d", len(dirs))

	var okHead, okRemote, okLog, failed int
	for _, d := range dirs {
		head, err := Head(d)
		if err != nil {
			failed++
			t.Logf("HEAD  %-40s FAIL %v", filepath.Base(d), err)
			continue
		}
		okHead++
		if _, err := Remote(d); err == nil {
			okRemote++
		} else {
			t.Logf("REMOTE %-40s FAIL %v", filepath.Base(d), err)
		}
		commits, err := Log(d, 5)
		if err != nil {
			t.Logf("LOG   %-40s FAIL %v", filepath.Base(d), err)
			continue
		}
		okLog++
		if len(commits) > 0 && commits[0].Hash != head {
			t.Errorf("%s: Log[0] %s != Head %s", d, commits[0].Hash, head)
		}
		if len(commits) > 0 {
			t.Logf("ok    %-40s %s %-18s %s", filepath.Base(d), head[:12],
				commits[0].Author.When.Format("2006-01-02"), firstN(commits[0].Subject, 48))
		}
	}
	t.Logf("clones=%d head-ok=%d remote-ok=%d log-ok=%d head-failed=%d",
		len(dirs), okHead, okRemote, okLog, failed)
}

func firstN(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// --- fixture construction -------------------------------------------------
//
// Repositories are built here, by this file, from the raw object format. They
// are NOT built by running `git`: a test that shells out to git to make a
// fixture makes the test suite depend on the binary this package exists to
// avoid, and it would hide the one thing worth pinning -- that these bytes,
// exactly, are what the reader understands.

type fixture struct {
	work string // the working tree (or the git dir, for a bare repo)
	git  string // the git directory
	tree string // a tree object every commit points at
}

func newRepo(t *testing.T, work string) *fixture {
	t.Helper()
	f := &fixture{work: work, git: filepath.Join(work, ".git")}
	f.init(t)
	return f
}

func newBareRepo(t *testing.T, dir string) *fixture {
	t.Helper()
	f := &fixture{work: dir, git: dir}
	f.init(t)
	return f
}

func (f *fixture) init(t *testing.T) {
	t.Helper()
	for _, d := range []string{"objects", "refs/heads", "refs/tags"} {
		if err := os.MkdirAll(filepath.Join(f.git, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	f.writeFile(t, "HEAD", "ref: refs/heads/master\n")
	f.writeFile(t, "config", "[core]\n\trepositoryformatversion = 0\n")
	// An empty tree is a legal tree object and is all these commits need.
	f.tree = f.writeLoose(t, "tree", nil)
}

func (f *fixture) writeFile(t *testing.T, rel, body string) {
	t.Helper()
	abs := filepath.Join(f.git, rel)
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(abs, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) writeExec(t *testing.T, rel, body string) {
	t.Helper()
	f.writeFile(t, rel, body)
	if err := os.Chmod(filepath.Join(f.git, rel), 0o755); err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) setHead(t *testing.T, ref, sha string) {
	t.Helper()
	f.writeFile(t, "HEAD", "ref: "+ref+"\n")
	f.writeFile(t, ref, sha+"\n")
}

// fixtureEpoch is 2026-08-05T10:00:00Z, the instant every fixture commit is
// dated from. It is written with a +0200 offset so the explicit-offset parse is
// exercised: 12:00 local, 10:00 UTC.
const fixtureEpoch = 1785924000

// commit writes a loose commit object and returns its hash. minuteOffset keeps
// committer dates distinct and ascending so ordering assertions mean something.
var commitSeq int

func (f *fixture) commit(t *testing.T, msg string, parents []string) string {
	t.Helper()
	commitSeq++
	return f.writeLoose(t, "commit", commitBody(t, f.tree, parents, msg, commitSeq*60))
}

// commitAt is commit with an explicit second offset, for the tests that assert
// on a timestamp and therefore cannot depend on a package-level counter.
func (f *fixture) commitAt(t *testing.T, msg string, parents []string, secs int) string {
	t.Helper()
	return f.writeLoose(t, "commit", commitBody(t, f.tree, parents, msg, secs))
}

func parentsOf(sha string) []string {
	if sha == "" {
		return nil
	}
	return []string{sha}
}

// commitBody builds a commit object body byte for byte, including the +0200
// offset this project insists on parsing explicitly.
func commitBody(t *testing.T, tree string, parents []string, msg string, secs int) []byte {
	t.Helper()
	var b bytes.Buffer
	fmt.Fprintf(&b, "tree %s\n", tree)
	for _, p := range parents {
		fmt.Fprintf(&b, "parent %s\n", p)
	}
	// 2026-08-05T12:00:00+02:00 == 2026-08-05T10:00:00Z
	when := fixtureEpoch + secs
	fmt.Fprintf(&b, "author A U Thor <author@example.com> %d +0200\n", when)
	fmt.Fprintf(&b, "committer C O Mitter <committer@example.com> %d +0200\n", when)
	b.WriteString("gpgsig -----BEGIN PGP SIGNATURE-----\n \n bogus\n -----END PGP SIGNATURE-----\n")
	b.WriteString("\n")
	b.WriteString(msg)
	if !strings.HasSuffix(msg, "\n") {
		b.WriteString("\n")
	}
	return b.Bytes()
}

// fixtureID recomputes an object name the way the format defines it. It
// deliberately does NOT call the implementation's objectID: a fixture that
// derives its expected hashes from the code under test cannot detect that code
// hashing the wrong bytes.
func fixtureID(typ string, body []byte) string {
	h := sha1.New()
	fmt.Fprintf(h, "%s %d", typ, len(body))
	h.Write([]byte{0})
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}

func (f *fixture) writeLoose(t *testing.T, typ string, body []byte) string {
	t.Helper()
	sha := fixtureID(typ, body)
	f.writeLooseAt(t, sha, typ, body)
	return sha
}

// writeLooseAt stores an object under a caller-chosen name, which is how the
// hash-verification tests build a repository that lies about its own contents.
func (f *fixture) writeLooseAt(t *testing.T, sha, typ string, body []byte) {
	t.Helper()
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
	if err := os.WriteFile(filepath.Join(dir, sha[2:]), z.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

// --- pack construction ----------------------------------------------------

const (
	objCommit   = 1
	objOfsDelta = 6
	objRefDelta = 7
)

// packEntry describes one object to place in a packfile. data is always the
// FULL object body; the builder derives the delta encoding for the delta
// types, so a test never hand-writes delta bytes.
type packEntry struct {
	typ         byte
	data        []byte
	baseSHA     string // objRefDelta
	baseIndex   int    // objOfsDelta: index into the entry slice
	overrideSHA string // store under a name that is not the object's hash
}

func (f *fixture) writePack(t *testing.T, entries []packEntry) {
	t.Helper()

	var body bytes.Buffer
	body.WriteString("PACK")
	binary.Write(&body, binary.BigEndian, uint32(2))
	binary.Write(&body, binary.BigEndian, uint32(len(entries)))

	offsets := make([]int64, len(entries))
	shas := make([]string, len(entries))
	for i, e := range entries {
		offsets[i] = int64(body.Len())
		shas[i] = e.overrideSHA
		if shas[i] == "" {
			shas[i] = fixtureID("commit", e.data)
		}

		payload := e.data
		var extra []byte
		switch e.typ {
		case objRefDelta:
			raw, err := hex.DecodeString(e.baseSHA)
			if err != nil {
				t.Fatal(err)
			}
			extra = raw
			payload = encodeDelta(baseBodyOf(t, entries, e), e.data)
		case objOfsDelta:
			extra = encodeOfs(offsets[i] - offsets[e.baseIndex])
			payload = encodeDelta(entries[e.baseIndex].data, e.data)
		}
		body.Write(packObjHeader(e.typ, len(payload)))
		body.Write(extra)
		body.Write(zlibBytes(t, payload))
	}
	sum := sha1.Sum(body.Bytes())
	body.Write(sum[:])

	name := "pack-" + hex.EncodeToString(sum[:])
	dir := filepath.Join(f.git, "objects", "pack")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name+".pack"), body.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name+".idx"), buildIdx(t, shas, offsets, body.Bytes()), 0o644); err != nil {
		t.Fatal(err)
	}
}

// writeSelfDeltaPack builds a pack with a single OFS_DELTA whose base offset
// is its own offset -- a shape no honest packer produces.
func (f *fixture) writeSelfDeltaPack(t *testing.T, sha string) {
	t.Helper()
	var body bytes.Buffer
	body.WriteString("PACK")
	binary.Write(&body, binary.BigEndian, uint32(2))
	binary.Write(&body, binary.BigEndian, uint32(1))
	off := int64(body.Len())
	payload := encodeDelta([]byte("x"), []byte("x"))
	body.Write(packObjHeader(objOfsDelta, len(payload)))
	body.Write(encodeOfs(0)) // base offset == this object's own offset
	body.Write(zlibBytes(t, payload))
	sum := sha1.Sum(body.Bytes())
	body.Write(sum[:])

	name := "pack-" + hex.EncodeToString(sum[:])
	dir := filepath.Join(f.git, "objects", "pack")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name+".pack"), body.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name+".idx"),
		buildIdx(t, []string{sha}, []int64{off}, body.Bytes()), 0o644); err != nil {
		t.Fatal(err)
	}
}

func baseBodyOf(t *testing.T, entries []packEntry, e packEntry) []byte {
	t.Helper()
	for _, c := range entries {
		if fixtureID("commit", c.data) == e.baseSHA {
			return c.data
		}
	}
	t.Fatalf("no entry with sha %s to delta against", e.baseSHA)
	return nil
}

func packObjHeader(typ byte, size int) []byte {
	b := []byte{byte(typ<<4) | byte(size&0x0f)}
	size >>= 4
	for size > 0 {
		b[len(b)-1] |= 0x80
		b = append(b, byte(size&0x7f))
		size >>= 7
	}
	return b
}

// encodeOfs is git's own negative-offset encoding for OFS_DELTA.
func encodeOfs(off int64) []byte {
	buf := []byte{byte(off & 0x7f)}
	for off >>= 7; off > 0; off >>= 7 {
		off--
		buf = append(buf, byte(0x80|(off&0x7f)))
	}
	for i, j := 0, len(buf)-1; i < j; i, j = i+1, j-1 {
		buf[i], buf[j] = buf[j], buf[i]
	}
	return buf
}

// encodeDelta produces a git delta from base to target, using a copy
// instruction for the common prefix and inserts for the rest -- so the reader's
// handling of BOTH instruction forms is exercised rather than just inserts.
func encodeDelta(base, target []byte) []byte {
	var b bytes.Buffer
	b.Write(varint(len(base)))
	b.Write(varint(len(target)))

	n := 0
	for n < len(base) && n < len(target) && base[n] == target[n] {
		n++
	}
	if n > 16 {
		// copy: offset and size present, both little-endian, minimal bytes.
		b.WriteByte(0x80 | 0x01 | 0x02 | 0x10) // offset bytes 0,1; size byte 0
		b.WriteByte(0)                         // offset & 0xff
		b.WriteByte(0)                         // (offset >> 8) & 0xff
		if n > 0xffff {
			panic("fixture: prefix too long for this encoder")
		}
		copySize := n
		if copySize > 0xff {
			copySize = 0xff
		}
		b.WriteByte(byte(copySize))
		n = copySize
	} else {
		n = 0
	}
	for i := n; i < len(target); {
		chunk := len(target) - i
		if chunk > 127 {
			chunk = 127
		}
		b.WriteByte(byte(chunk))
		b.Write(target[i : i+chunk])
		i += chunk
	}
	return b.Bytes()
}

func varint(n int) []byte {
	var out []byte
	for {
		c := byte(n & 0x7f)
		n >>= 7
		if n > 0 {
			c |= 0x80
		}
		out = append(out, c)
		if n == 0 {
			return out
		}
	}
}

func zlibBytes(t *testing.T, p []byte) []byte {
	t.Helper()
	var z bytes.Buffer
	w := zlib.NewWriter(&z)
	if _, err := w.Write(p); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return z.Bytes()
}

// buildIdx writes a version-2 pack index: magic, version, 256-entry fanout,
// sorted object names, CRCs, 32-bit offsets, and the two trailing checksums.
func buildIdx(t *testing.T, shas []string, offsets []int64, pack []byte) []byte {
	t.Helper()
	type rec struct {
		raw []byte
		off int64
	}
	recs := make([]rec, 0, len(shas))
	for i, s := range shas {
		raw, err := hex.DecodeString(s)
		if err != nil || len(raw) != 20 {
			t.Fatalf("bad sha %q: %v", s, err)
		}
		recs = append(recs, rec{raw, offsets[i]})
	}
	sort.Slice(recs, func(i, j int) bool { return bytes.Compare(recs[i].raw, recs[j].raw) < 0 })

	var b bytes.Buffer
	b.Write([]byte{0xff, 0x74, 0x4f, 0x63})
	binary.Write(&b, binary.BigEndian, uint32(2))
	for i := 0; i < 256; i++ {
		n := 0
		for _, r := range recs {
			if int(r.raw[0]) <= i {
				n++
			}
		}
		binary.Write(&b, binary.BigEndian, uint32(n))
	}
	for _, r := range recs {
		b.Write(r.raw)
	}
	for range recs {
		// CRC32 is not verified by the reader -- the object hash is, which is
		// strictly stronger -- so the fixture leaves it zero deliberately.
		binary.Write(&b, binary.BigEndian, uint32(0))
	}
	for _, r := range recs {
		binary.Write(&b, binary.BigEndian, uint32(r.off))
	}
	packSum := pack[len(pack)-20:]
	b.Write(packSum)
	idxSum := sha1.Sum(b.Bytes())
	b.Write(idxSum[:])
	return b.Bytes()
}

// --- misc helpers ---------------------------------------------------------

func treeSnapshot(t *testing.T, base string) string {
	t.Helper()
	var b strings.Builder
	err := filepath.WalkDir(base, func(p string, de fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := de.Info()
		if err != nil {
			return err
		}
		fmt.Fprintf(&b, "%s %s", p, info.Mode())
		if !de.IsDir() {
			fmt.Fprintf(&b, " %d %s", info.Size(), info.ModTime().UTC().Format(time.RFC3339Nano))
		}
		b.WriteString("\n")
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	return b.String()
}
