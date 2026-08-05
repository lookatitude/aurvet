// internal/vcs/gitlog.go
//
// Package vcs reads a git repository's history by parsing the object store,
// and never by executing git.
//
// # Decision D-1, and why this file is 700 lines instead of 30
//
// The obvious implementation of Head/Log/Remote is three calls to git
// rev-parse, git log and git config. It is also unusable here. An AUR clone is
// attacker-controlled, and a git repository carries its own configuration and
// hooks: core.pager, core.fsmonitor, core.sshCommand, core.editor,
// core.hooksPath, uploadpack.packObjectsHook, remote.<n>.proxy and any
// alias.* are all values that make git EXECUTE A COMMAND OUT OF THE REPOSITORY
// IT IS READING, while doing nothing but reading. Pointing git at a hostile
// repository to find out whether that repository is hostile executes a binary
// against exactly the input this tool exists to warn about, which is INV-2's
// (parse, never execute) single hardest case in the project.
//
// Hardening the exec is not a boundary. `git -c core.pager=cat -c ...` is a
// denylist over someone else's configuration format -- a format that gains keys
// with every release -- and a denylist you do not control is not a boundary.
// The only defensible answer is to not run the program: read the bytes.
//
// The proof lives in the tests, not in this comment.
// TestPackageImportsNoExec asserts over this package's own import graph that
// os/exec, syscall and golang.org/x/sys are absent, and
// TestHostileConfigIsNeverExecuted runs all three entry points against a
// repository whose config and hooks would create a sentinel file, then asserts
// the sentinel does not exist.
//
// # Scope
//
// Deliberately narrow, exactly as much as provenance capture needs: HEAD, the
// commit graph reachable from it (author, committer, date, message, parents),
// and the configured remote URL. There is no index reader, no tree walk, no
// merge logic, no network. Anything outside that scope is a coverage gap
// (INV-9), never a guess.
//
// # What is implemented, and why packfiles are not optional
//
// Loose objects (zlib, stdlib compress/zlib) and packfiles (idx v2 + OFS_DELTA
// and REF_DELTA reconstruction). Packfile support looked like the part that
// could be deferred to a coverage gap until it was measured against the 34
// clones in the reference system's yay cache (2026-08-05): `git clone` writes
// every object into a packfile, so 19 of the 34 have a COMPLETELY EMPTY loose
// object store and the remaining 15 hold only the objects fetched since the
// clone. A loose-only reader therefore reads nothing at all in 19 of 34 and a
// partial history in the rest -- which is honest, and useless. Both stores are
// implemented; pack index v1 and sha256 repositories are not, and each is
// refused by name rather than misread.
//
// # Hostile input
//
// Every bound here exists because the bytes on the other side are chosen by
// someone else: object sizes, inflated sizes, delta chain depth, delta results,
// ref-name shape, ref-chain depth, packed-refs size, config size, commit count,
// parent count, message length. A hang outranks a panic (INV-3's spirit: the
// scan must finish and say what it could not do), so the self-referential delta
// and the symref loop are refused structurally rather than left to a timeout.
//
// An object's name is a CLAIM about its content, so every object materialized
// here is hashed and checked against the name it was requested under. Without
// that, a repository can hand this reader a commit message, author and date
// belonging to a different object -- and the whole point of provenance capture
// is that these fields are evidence.
//
// # Purity and confinement
//
// Read-only (INV-5): nothing here creates, writes or locks anything, which is
// also why a real `git` would be wrong under --offline-root (it writes
// .git/index and lock files as a side effect of reading). All I/O is confined
// to the repository directory through os.Root, and every file is opened with
// fsx.OpenConfined so a symlinked HEAD, ref or object is refused unresolved
// rather than followed out of the tree.
package vcs

import (
	"bytes"
	"compress/zlib"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lookatitude/aurvet/internal/finding"
	"github.com/lookatitude/aurvet/internal/fsx"
)

// The sentinels a caller switches on. None of them is a finding: a history this
// package could not read says nothing about whether the package is malicious,
// so every one of these is a coverage gap attributable to one repository
// (INV-9), and a caller that reports one must say what it could not prove
// (INV-6).
var (
	// ErrNotRepo means dir is not a git repository this package recognises.
	ErrNotRepo = errors.New("vcs: not a git repository")

	// ErrUnsupported means the repository uses a format this package
	// deliberately does not read: a .git file pointing at a git directory
	// elsewhere, a sha256 object format, a version-1 pack index. Refused by
	// name so the gap is specific.
	ErrUnsupported = errors.New("vcs: unsupported repository format")

	// ErrNoRef means a ref does not resolve -- an unborn branch, or a HEAD
	// naming a ref that is neither loose nor packed.
	ErrNoRef = errors.New("vcs: ref does not resolve")

	// ErrNoRemote means the configuration names no origin remote.
	ErrNoRemote = errors.New("vcs: no origin remote configured")

	// ErrLimit reports input that exceeded a bound rather than input that was
	// wrong. Everything an attacker sizes is bounded.
	ErrLimit = errors.New("vcs: input exceeds a bound")

	// ErrCorrupt reports an object whose content does not match the name it
	// was stored under, or a structurally impossible object or pack.
	ErrCorrupt = errors.New("vcs: object does not match its name")

	// ErrObjectMissing reports an object that is in neither the loose store
	// nor any readable pack -- the normal shape of a shallow clone.
	ErrObjectMissing = errors.New("vcs: object not found")

	// ErrIncomplete means the walk returned fewer commits than it was asked
	// for because the history could not be followed further. The commits that
	// WERE read are returned alongside it: refusing nine facts because the
	// tenth object is missing would be the wrong trade.
	ErrIncomplete = errors.New("vcs: history incomplete")
)

// Gap rule identifiers for the shortfalls that are not attributable to a
// single call -- an unreadable pack index still lets HEAD resolve out of the
// loose store, so it cannot be an error return.
const (
	// RuleObjectStore is an object store this package could not fully reach:
	// an unreadable or unsupported pack index, or an alternates file naming
	// another store that is deliberately not followed.
	RuleObjectStore = "vcs-object-store"
)

// SubjectRepo is the subject kind for gaps this package emits.
const SubjectRepo = "git-repository"

// Signature is one identity line from a commit.
//
// When carries the offset the commit was written with, never the local zone.
// Timestamps in this project are parsed with explicit offsets (spec §4: the
// reference pacman.log mixes two), and a provenance record whose dates were
// silently rewritten into the reader's zone is evidence about the reader.
type Signature struct {
	Name  string
	Email string
	When  time.Time
}

// Commit is one commit object, reduced to the fields provenance capture needs.
type Commit struct {
	Hash    string
	Tree    string
	Parents []string

	Author    Signature
	Committer Signature

	// Subject is the first line of the message, which is what review output
	// shows for a commit range.
	Subject string

	// Message is the full commit message, bounded by Limits.MaxMessageBytes.
	Message string

	// MessageTruncated reports that Message hit that bound. A truncated
	// message must not read as a short one.
	MessageTruncated bool
}

// Limits bounds everything the repository controls. Exported and copyable so a
// caller can tighten a bound and a test can prove each one fires on its own.
type Limits struct {
	// MaxObjectBytes caps one INFLATED object. Commit objects on the
	// reference system's clones are well under 4 KiB; the ceiling is what
	// makes buffering an object safe at all.
	MaxObjectBytes int64

	// MaxLooseBytes caps the COMPRESSED bytes read for one loose object,
	// before inflation, so a zlib bomb is bounded by what it cost to ship.
	MaxLooseBytes int64

	// MaxPackFiles caps the pack indexes opened for one repository.
	MaxPackFiles int

	// MaxIdxBytes caps one pack index file, which is read into memory.
	MaxIdxBytes int64

	// MaxIdxObjects caps the objects one index may claim.
	MaxIdxObjects int

	// MaxDeltaDepth caps a delta chain. git's own default pack depth is 50.
	MaxDeltaDepth int

	// MaxRefBytes caps HEAD and one loose ref file.
	MaxRefBytes int64

	// MaxRefNameBytes caps a ref name, which this package then uses as a path.
	MaxRefNameBytes int

	// MaxRefDepth caps a symref chain: HEAD -> refs/a -> refs/b. A loop is a
	// hang, and a hang outranks a panic.
	MaxRefDepth int

	// MaxPackedRefsBytes caps packed-refs.
	MaxPackedRefsBytes int64

	// MaxRefs caps the entries parsed out of packed-refs.
	MaxRefs int

	// MaxConfigBytes caps .git/config.
	MaxConfigBytes int64

	// MaxCommits caps a walk, and therefore caps n.
	MaxCommits int

	// MaxMessageBytes caps one retained commit message.
	MaxMessageBytes int

	// MaxParents caps a commit's parent list. Real octopus merges have a
	// handful; the cap stops a synthetic commit from making the frontier
	// unbounded.
	MaxParents int
}

// DefaultLimits returns bounds with headroom over the measured worst case
// rather than fitted to it.
//
// Measured over the 34 clones in the reference system's yay cache
// (2026-08-05, with this reader): largest packfile 577,037 B, largest pack
// index 60,432 B, most objects in one pack 2,120, longest history 565 commits,
// longest commit message 1,706 B, 35 packs across 34 clones (one clone has
// two). The caps below are two to four orders of magnitude above that, which is
// the point: they exist to bound a hostile repository, not to constrain a real
// one.
func DefaultLimits() Limits {
	return Limits{
		MaxObjectBytes:     16 << 20,
		MaxLooseBytes:      8 << 20,
		MaxPackFiles:       64,
		MaxIdxBytes:        64 << 20,
		MaxIdxObjects:      2_000_000,
		MaxDeltaDepth:      50,
		MaxRefBytes:        4 << 10,
		MaxRefNameBytes:    512,
		MaxRefDepth:        5,
		MaxPackedRefsBytes: 8 << 20,
		MaxRefs:            100_000,
		MaxConfigBytes:     1 << 20,
		MaxCommits:         10_000,
		MaxMessageBytes:    64 << 10,
		MaxParents:         256,
	}
}

// withDefaults fills unset fields so a caller can tighten one bound without
// restating the rest, and so the zero Limits means "the defaults".
func (l Limits) withDefaults() Limits {
	d := DefaultLimits()
	if l.MaxObjectBytes <= 0 {
		l.MaxObjectBytes = d.MaxObjectBytes
	}
	if l.MaxLooseBytes <= 0 {
		l.MaxLooseBytes = d.MaxLooseBytes
	}
	if l.MaxPackFiles <= 0 {
		l.MaxPackFiles = d.MaxPackFiles
	}
	if l.MaxIdxBytes <= 0 {
		l.MaxIdxBytes = d.MaxIdxBytes
	}
	if l.MaxIdxObjects <= 0 {
		l.MaxIdxObjects = d.MaxIdxObjects
	}
	if l.MaxDeltaDepth <= 0 {
		l.MaxDeltaDepth = d.MaxDeltaDepth
	}
	if l.MaxRefBytes <= 0 {
		l.MaxRefBytes = d.MaxRefBytes
	}
	if l.MaxRefNameBytes <= 0 {
		l.MaxRefNameBytes = d.MaxRefNameBytes
	}
	if l.MaxRefDepth <= 0 {
		l.MaxRefDepth = d.MaxRefDepth
	}
	if l.MaxPackedRefsBytes <= 0 {
		l.MaxPackedRefsBytes = d.MaxPackedRefsBytes
	}
	if l.MaxRefs <= 0 {
		l.MaxRefs = d.MaxRefs
	}
	if l.MaxConfigBytes <= 0 {
		l.MaxConfigBytes = d.MaxConfigBytes
	}
	if l.MaxCommits <= 0 {
		l.MaxCommits = d.MaxCommits
	}
	if l.MaxMessageBytes <= 0 {
		l.MaxMessageBytes = d.MaxMessageBytes
	}
	if l.MaxParents <= 0 {
		l.MaxParents = d.MaxParents
	}
	return l
}

// --- package-level entry points, the signatures P2 task 2 specifies --------

// Head returns the commit HEAD resolves to, as a 40-character hex sha.
func Head(dir string) (string, error) {
	r, err := Open(dir, Limits{})
	if err != nil {
		return "", err
	}
	defer r.Close()
	return r.Head()
}

// Log returns up to n commits reachable from HEAD, newest first.
//
// n is required and bounded: 0 and negative are refused rather than treated as
// "all", because "all" of an attacker-controlled history is not a quantity
// this tool agrees to read.
func Log(dir string, n int) ([]Commit, error) {
	r, err := Open(dir, Limits{})
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return r.Log("", n)
}

// Remote returns the origin remote's URL, verbatim.
//
// Verbatim is deliberate. A URL like "ext::sh -c ..." is reported exactly as
// the repository wrote it: this package reports what the repository says and
// never normalises it, and certainly never acts on it. Interpreting it is the
// caller's business, and the caller is a rule, not a subprocess.
func Remote(dir string) (string, error) {
	r, err := Open(dir, Limits{})
	if err != nil {
		return "", err
	}
	defer r.Close()
	return r.Remote()
}

// Remotes returns every configured remote name and URL.
//
// Remote reports origin only, because origin is the AUR remote every helper
// clone carries and provenance must name one URL rather than pick from a set.
// A caller that needs to see a second remote -- which is itself worth
// reporting, since an AUR clone with an extra remote is unusual -- asks here.
func Remotes(dir string) (map[string]string, error) {
	r, err := Open(dir, Limits{})
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return r.Remotes()
}

// LogSince returns the commits from HEAD back to (and excluding) stop, newest
// first, and whether stop was reached.
//
// This is the primitive the VCS delta review needs (P2 task 11): for a -git
// package the PKGBUILD is stable while the source moves, so an approval keyed
// on the recipe alone would bless every future commit. reached is the field
// that carries the honest answer -- reached == false with a full slice means
// the recorded commit is not in this history at all (a force-push, a different
// upstream, or a truncated clone), which is a different fact from an empty
// range with reached == true ("already up to date") and must never be
// presented as the same one.
func LogSince(dir, stop string, max int) (commits []Commit, reached bool, err error) {
	r, err := Open(dir, Limits{})
	if err != nil {
		return nil, false, err
	}
	defer r.Close()
	return r.LogSince("", stop, max)
}

// --- Repo -----------------------------------------------------------------

// Repo is an open repository. Callers that need non-default limits, or that
// want the coverage gaps the walk accumulated, use this instead of the
// package-level functions.
type Repo struct {
	dir  string
	root *os.Root
	// gitDir is the root-relative git directory: ".git" for a working tree,
	// "." for a bare repository.
	gitDir string
	lim    Limits

	cfg       map[string]string
	cfgErr    error
	cfgLoaded bool

	packs       []*packFile
	packsLoaded bool

	gaps []finding.Gap
}

// Open resolves dir as a repository. A zero Limits means DefaultLimits.
func Open(dir string, lim Limits) (*Repo, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotRepo, err)
	}
	r := &Repo{dir: dir, root: root, lim: lim.withDefaults()}

	fsys := root.FS()
	if st, err := fs.Stat(fsys, ".git"); err == nil {
		if st.IsDir() {
			r.gitDir = ".git"
		} else {
			// A ".git" FILE contains "gitdir: <path>" and names a git
			// directory somewhere else -- a worktree, a submodule, or whatever
			// path an attacker wrote there. Following it would read a store
			// outside the tree being inspected, so it is refused by name.
			root.Close()
			return nil, fmt.Errorf("%w: .git is a file naming a git directory elsewhere, which is not followed", ErrUnsupported)
		}
	} else if isBareLayout(fsys) {
		r.gitDir = "."
	} else {
		root.Close()
		return nil, fmt.Errorf("%w: %s has no .git directory and is not a bare repository", ErrNotRepo, dir)
	}
	return r, nil
}

// isBareLayout reports whether the root itself looks like a git directory:
// a HEAD file and an objects directory.
func isBareLayout(fsys fs.FS) bool {
	if st, err := fs.Stat(fsys, "HEAD"); err != nil || !st.Mode().IsRegular() {
		return false
	}
	st, err := fs.Stat(fsys, "objects")
	return err == nil && st.IsDir()
}

// Close releases the repository's file descriptors.
func (r *Repo) Close() error {
	for _, p := range r.packs {
		p.close()
	}
	r.packs = nil
	return r.root.Close()
}

// Gaps returns the coverage shortfalls accumulated so far: parts of the object
// store that could not be reached. They are not errors, because HEAD can
// resolve out of the loose store while a pack index is unreadable, and a
// caller must be told both things.
func (r *Repo) Gaps() []finding.Gap { return r.gaps }

func (r *Repo) gap(subject, reason string) {
	g := finding.Gap{RuleID: RuleObjectStore, Subject: subject, Reason: reason}
	for _, have := range r.gaps {
		if have == g {
			return
		}
	}
	r.gaps = append(r.gaps, g)
}

// gitPath joins a git-directory-relative path for the confined API.
func (r *Repo) gitPath(rel string) string {
	if r.gitDir == "." {
		return rel
	}
	return path.Join(r.gitDir, rel)
}

// readFile reads one file under the repository, bounded.
//
// Every read in this package goes through here, and therefore through
// fsx.OpenConfined: the leaf is opened with O_NOFOLLOW, so a HEAD, ref, config
// or object replaced by a symlink is refused unresolved rather than read from
// wherever it pointed.
func (r *Repo) readFile(rel string, max int64) ([]byte, error) {
	f, st, err := fsx.OpenConfined(r.root, rel)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if st.Size > max {
		return nil, fmt.Errorf("%w: %s is %d bytes, over the %d cap", ErrLimit, rel, st.Size, max)
	}
	// LimitReader rather than trusting the fstat size: the file can grow
	// between the fstat and the read, and the cap is the thing that has to
	// hold.
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("%w: %s exceeds the %d byte cap", ErrLimit, rel, max)
	}
	return data, nil
}

// --- HEAD and refs --------------------------------------------------------

// Head resolves HEAD to a commit hash.
func (r *Repo) Head() (string, error) {
	if err := r.checkFormat(); err != nil {
		return "", err
	}
	data, err := r.readFile(r.gitPath("HEAD"), r.lim.MaxRefBytes)
	if err != nil {
		return "", fmt.Errorf("%w: HEAD: %v", ErrNoRef, err)
	}
	return r.resolve(strings.TrimSpace(string(data)), 0)
}

// resolve turns the content of HEAD or a ref file into a hash, following
// symrefs to a bounded depth.
func (r *Repo) resolve(content string, depth int) (string, error) {
	if depth > r.lim.MaxRefDepth {
		return "", fmt.Errorf("%w: symref chain deeper than %d, which is a loop", ErrLimit, r.lim.MaxRefDepth)
	}
	if sha, ok := parseHash(content); ok {
		return sha, nil
	}
	name, ok := strings.CutPrefix(content, "ref: ")
	if !ok {
		return "", fmt.Errorf("%w: %q is neither a hash nor a symref", ErrNoRef, firstLine(content))
	}
	name = strings.TrimSpace(name)
	if err := r.validRefName(name); err != nil {
		return "", err
	}

	// Loose first, then packed -- git's own precedence, and the direction that
	// matters: a loose ref is newer than the packed copy, so reversing this
	// reports a stale commit as the one that was built.
	if data, err := r.readFile(r.gitPath(name), r.lim.MaxRefBytes); err == nil {
		return r.resolve(strings.TrimSpace(string(data)), depth+1)
	}
	if sha, ok, err := r.packedRef(name); err != nil {
		return "", err
	} else if ok {
		return sha, nil
	}
	return "", fmt.Errorf("%w: %s is neither a loose nor a packed ref", ErrNoRef, name)
}

// packedRef looks name up in packed-refs.
//
// Fresh clones keep every ref here: all 34 clones in the reference system's yay
// cache have a packed-refs file (and 34 of 34 also have a loose
// refs/heads/master, which is why the precedence above is load-bearing rather
// than academic), so treating packed-refs as optional would mean resolving
// nothing on a repository that has not been checked out.
func (r *Repo) packedRef(name string) (string, bool, error) {
	data, err := r.readFile(r.gitPath("packed-refs"), r.lim.MaxPackedRefsBytes)
	if err != nil {
		if errors.Is(err, ErrLimit) {
			return "", false, err
		}
		return "", false, nil
	}
	n := 0
	for _, line := range strings.Split(string(data), "\n") {
		if n++; n > r.lim.MaxRefs {
			return "", false, fmt.Errorf("%w: packed-refs holds more than %d refs", ErrLimit, r.lim.MaxRefs)
		}
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' || line[0] == '^' {
			// '^' lines are the peeled target of the preceding tag. This
			// package resolves commits, and a peeled line belongs to a tag we
			// did not ask for.
			continue
		}
		sha, rest, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		h, ok := parseHash(sha)
		if !ok {
			continue
		}
		if strings.TrimSpace(rest) == name {
			return h, true, nil
		}
	}
	return "", false, nil
}

// validRefName refuses a ref name before it becomes a path.
//
// fsx.OpenConfined is the backstop, not the only check: refusing here keeps the
// refusal attributable to the ref rather than to whatever errno the kernel
// produced, and requiring the refs/ prefix means a HEAD saying
// "ref: ../../../../etc/passwd" is rejected as what it is.
func (r *Repo) validRefName(name string) error {
	if name == "" {
		return fmt.Errorf("%w: empty ref name", ErrNoRef)
	}
	if len(name) > r.lim.MaxRefNameBytes {
		return fmt.Errorf("%w: ref name is %d bytes, over the %d cap", ErrLimit, len(name), r.lim.MaxRefNameBytes)
	}
	if !strings.HasPrefix(name, "refs/") {
		return fmt.Errorf("%w: ref name %q is not under refs/", ErrNoRef, name)
	}
	if strings.ContainsRune(name, 0) {
		return fmt.Errorf("%w: ref name contains NUL", ErrNoRef)
	}
	for _, c := range strings.Split(name, "/") {
		switch c {
		case "", ".", "..":
			return fmt.Errorf("%w: ref name %q has an empty, . or .. component", ErrNoRef, name)
		}
	}
	return nil
}

// parseHash accepts a 40-character hex sha, normalised to lower case.
func parseHash(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if len(s) != 40 {
		return "", false
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f':
			b.WriteByte(c)
		case c >= 'A' && c <= 'F':
			b.WriteByte(c + ('a' - 'A'))
		default:
			return "", false
		}
	}
	return b.String(), true
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 120 {
		s = s[:120]
	}
	return s
}

// --- configuration --------------------------------------------------------

// checkFormat refuses object formats whose hashes this reader cannot verify.
//
// Hash verification is this package's integrity check and it is a SHA-1 check.
// A sha256 repository would fail every verification, so without this the
// refusal would read as "corrupt" -- a wrong statement about the repository --
// instead of "unsupported", which is a true one.
func (r *Repo) checkFormat() error {
	cfg, err := r.config()
	if err != nil {
		// An unreadable or oversized config does not stop HEAD from
		// resolving, so it is a gap rather than a failure. sha1 is assumed,
		// and hash verification will report the consequence if that is wrong.
		r.gap(r.dir, fmt.Sprintf("configuration could not be read (%v); the object format is assumed to be sha1", err))
		return nil
	}
	if f := cfg["extensions.objectformat"]; f != "" && f != "sha1" {
		return fmt.Errorf("%w: object format %q; this reader verifies sha1 object names", ErrUnsupported, f)
	}
	return nil
}

// Remote returns the origin remote's URL.
func (r *Repo) Remote() (string, error) {
	cfg, err := r.config()
	if err != nil {
		return "", err
	}
	if url := cfg["remote.origin.url"]; url != "" {
		return url, nil
	}
	if cfg[cfgHasInclude] != "" {
		// An [include] or [includeIf] reads another file, by a path the
		// repository chose. In an attacker-controlled repository that is an
		// arbitrary read, so it is not followed -- and saying so is the
		// difference between "no remote configured" and "the remote may be in
		// a file I refused to open".
		return "", fmt.Errorf("%w: configuration has an include directive naming %q, which is not followed, "+
			"so a remote defined there was not read", ErrNoRemote, cfg[cfgHasInclude])
	}
	return "", fmt.Errorf("%w: %s", ErrNoRemote, r.dir)
}

// Remotes returns every configured remote's URL, keyed by remote name.
func (r *Repo) Remotes() (map[string]string, error) {
	cfg, err := r.config()
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for k, v := range cfg {
		if name, ok := strings.CutPrefix(k, "remote."); ok {
			if name, ok := strings.CutSuffix(name, ".url"); ok && name != "" {
				out[name] = v
			}
		}
	}
	return out, nil
}

// cfgHasInclude is the pseudo-key under which config records an unfollowed
// include directive. It is not a git key, and cannot collide with one: a real
// key always has a section prefix.
const cfgHasInclude = "\x00include"

// config parses .git/config once.
//
// This is an INI-ish parse of a documented format, and nothing in the result is
// ever executed or resolved -- not core.pager, not core.sshCommand, not an
// alias, not an include path. The parse exists to read one URL and one
// extension key.
func (r *Repo) config() (map[string]string, error) {
	if r.cfgLoaded {
		return r.cfg, r.cfgErr
	}
	r.cfgLoaded = true
	data, err := r.readFile(r.gitPath("config"), r.lim.MaxConfigBytes)
	if err != nil {
		if errors.Is(err, ErrLimit) {
			r.cfgErr = err
			return nil, err
		}
		// No config at all is legal (and common in a bare fixture): an empty
		// map, not an error, because the questions asked of it have honest
		// negative answers.
		r.cfg = map[string]string{}
		return r.cfg, nil
	}
	r.cfg = parseConfig(string(data))
	return r.cfg, nil
}

// parseConfig turns git config text into dotted keys: "remote.origin.url",
// "core.bare", "extensions.objectformat". Section and key names are lowercased
// (git treats them case-insensitively); a subsection name keeps its case, as
// git does.
func parseConfig(text string) map[string]string {
	out := map[string]string{}
	section := ""
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if line[0] == '[' {
			end := strings.IndexByte(line, ']')
			if end < 0 {
				continue
			}
			head := line[1:end]
			name, sub, hasSub := strings.Cut(head, " ")
			section = strings.ToLower(strings.TrimSpace(name))
			if hasSub {
				sub = strings.TrimSpace(sub)
				sub = strings.Trim(sub, `"`)
				if sub != "" {
					section += "." + sub
				}
			}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			// A valueless key is boolean true in git's grammar.
			key, value = line, "true"
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = trimConfigValue(value)
		if section == "" || key == "" {
			continue
		}
		full := section + "." + key
		if (section == "include" || strings.HasPrefix(section, "includeif")) && key == "path" {
			// Recorded, never followed. See Remote.
			out[cfgHasInclude] = value
			continue
		}
		if _, exists := out[full]; exists {
			// git's last-value-wins, which is what a caller reading
			// remote.origin.url would get from `git config`.
			out[full] = value
			continue
		}
		out[full] = value
	}
	return out
}

// trimConfigValue strips a trailing comment and surrounding quotes without
// interpreting anything. A value is evidence, not a command line: it is
// reported as written.
func trimConfigValue(v string) string {
	quoted := false
	end := len(v)
	for i := 0; i < len(v); i++ {
		switch v[i] {
		case '"':
			quoted = !quoted
		case '#', ';':
			if !quoted {
				end = i
				i = len(v)
			}
		}
	}
	v = strings.TrimSpace(v[:end])
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		v = v[1 : len(v)-1]
	}
	return v
}

// --- the commit walk ------------------------------------------------------

// Log returns up to n commits reachable from start (HEAD when start is empty),
// newest first.
func (r *Repo) Log(start string, n int) ([]Commit, error) {
	commits, _, err := r.walk(start, "", n)
	return commits, err
}

// LogSince returns the commits from start back to (excluding) stop.
func (r *Repo) LogSince(start, stop string, max int) ([]Commit, bool, error) {
	if stop != "" {
		if h, ok := parseHash(stop); ok {
			stop = h
		} else {
			return nil, false, fmt.Errorf("%w: stop %q is not a commit hash", ErrNoRef, firstLine(stop))
		}
	}
	return r.walk(start, stop, max)
}

// walk is the one traversal both entry points use.
//
// Ordering is committer date descending, ties broken by hash, which is git
// log's default (date) order.
//
// Stated limit (INV-6), and it is NOT hypothetical: this is not git's
// topological order, so where a history contains merges the SEQUENCE can differ
// from `git log` even though the set of commits within the bound is the same.
// Measured on the reference system, 8 of the 34 cached clones contain merge
// commits (50 in total, 31 of them in one package), so any caller rendering a
// commit range must present it as "the commits in this range" and not as "the
// order they were applied". Reproducing git's topological order would mean
// implementing its commit-graph traversal, which is well outside the narrow
// read this task is scoped to.
func (r *Repo) walk(start, stop string, n int) ([]Commit, bool, error) {
	if n <= 0 {
		return nil, false, fmt.Errorf("%w: n must be positive; %d is not a request for a bounded history", ErrLimit, n)
	}
	if n > r.lim.MaxCommits {
		return nil, false, fmt.Errorf("%w: n=%d over the %d cap", ErrLimit, n, r.lim.MaxCommits)
	}
	if err := r.checkFormat(); err != nil {
		return nil, false, err
	}
	// Enumerate the object store before walking, so a pack index that could not
	// be read, or an alternates file that was not followed, becomes a gap even
	// when the commits happened to resolve out of the loose store. Otherwise a
	// caller reading Gaps() would be told the store was fully reachable
	// because the one object it needed was.
	if err := r.loadPacks(); err != nil {
		return nil, false, err
	}

	head := start
	if head == "" {
		h, err := r.Head()
		if err != nil {
			return nil, false, err
		}
		head = h
	} else if h, ok := parseHash(head); ok {
		head = h
	} else {
		return nil, false, fmt.Errorf("%w: start %q is not a commit hash", ErrNoRef, firstLine(head))
	}

	if stop != "" && head == stop {
		// Already up to date. An empty range with reached == true, which is a
		// different fact from an unreachable stop commit.
		return nil, true, nil
	}

	visited := map[string]bool{head: true}
	frontier := []Commit{}
	var firstErr error

	push := func(sha string) {
		if visited[sha] || sha == stop {
			return
		}
		visited[sha] = true
		c, err := r.commit(sha)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			return
		}
		frontier = append(frontier, c)
	}

	first, err := r.commit(head)
	if err != nil {
		return nil, false, err
	}
	frontier = append(frontier, first)

	var out []Commit
	reached := false
	for len(out) < n && len(frontier) > 0 {
		sort.Slice(frontier, func(i, j int) bool {
			a, b := frontier[i], frontier[j]
			if !a.Committer.When.Equal(b.Committer.When) {
				return a.Committer.When.After(b.Committer.When)
			}
			return a.Hash < b.Hash
		})
		c := frontier[0]
		frontier = frontier[1:]
		out = append(out, c)
		for _, p := range c.Parents {
			if p == stop {
				reached = true
				continue
			}
			push(p)
		}
	}
	if firstErr != nil && len(out) < n {
		return out, reached, fmt.Errorf("%w: %v", ErrIncomplete, firstErr)
	}
	return out, reached, nil
}

// commit reads and parses one commit object.
func (r *Repo) commit(sha string) (Commit, error) {
	typ, data, err := r.object(sha)
	if err != nil {
		return Commit{}, err
	}
	if typ != "commit" {
		return Commit{}, fmt.Errorf("%w: object %s is a %s, not a commit", ErrCorrupt, sha, typ)
	}
	return r.parseCommit(sha, data)
}

// parseCommit reads the header lines this package needs and the message.
//
// Continuation lines (a leading space) belong to the preceding header and are
// skipped: gpgsig is multi-line and would otherwise be parsed as a sequence of
// unknown headers, or worse, as the start of the message.
func (r *Repo) parseCommit(sha string, data []byte) (Commit, error) {
	c := Commit{Hash: sha}
	rest := data
	for {
		line, tail, ok := cutLine(rest)
		if !ok {
			// No blank line: a commit with headers and no message.
			rest = nil
			break
		}
		rest = tail
		if len(line) == 0 {
			break
		}
		if line[0] == ' ' {
			continue // continuation of the previous header
		}
		key, value, _ := bytes.Cut(line, []byte(" "))
		switch string(key) {
		case "tree":
			if h, ok := parseHash(string(value)); ok {
				c.Tree = h
			}
		case "parent":
			if len(c.Parents) >= r.lim.MaxParents {
				return Commit{}, fmt.Errorf("%w: commit %s has more than %d parents", ErrLimit, sha, r.lim.MaxParents)
			}
			if h, ok := parseHash(string(value)); ok {
				c.Parents = append(c.Parents, h)
			}
		case "author":
			c.Author = parseSignature(string(value))
		case "committer":
			c.Committer = parseSignature(string(value))
		}
	}
	msg := rest
	if len(msg) > r.lim.MaxMessageBytes {
		msg = msg[:r.lim.MaxMessageBytes]
		c.MessageTruncated = true
	}
	c.Message = string(msg)
	c.Subject = strings.TrimRight(firstLine(c.Message), "\r")
	return c, nil
}

func cutLine(b []byte) (line, rest []byte, ok bool) {
	i := bytes.IndexByte(b, '\n')
	if i < 0 {
		return b, nil, false
	}
	return b[:i], b[i+1:], true
}

// parseSignature parses "Name <email> 1786032000 +0200".
//
// The offset is applied as a fixed zone, so When keeps the offset the commit
// was written with. A malformed line yields a zero When rather than an error:
// the reader's job is to report what is there, and a commit with an unparsable
// date is still a commit with an author and a message.
func parseSignature(s string) Signature {
	var sig Signature
	lt := strings.LastIndexByte(s, '<')
	gt := strings.LastIndexByte(s, '>')
	if lt >= 0 && gt > lt {
		sig.Name = strings.TrimSpace(s[:lt])
		sig.Email = s[lt+1 : gt]
		s = strings.TrimSpace(s[gt+1:])
	} else {
		sig.Name = strings.TrimSpace(s)
		return sig
	}
	epochStr, offStr, _ := strings.Cut(s, " ")
	epoch, err := strconv.ParseInt(strings.TrimSpace(epochStr), 10, 64)
	if err != nil {
		return sig
	}
	sig.When = time.Unix(epoch, 0).In(fixedZone(strings.TrimSpace(offStr)))
	return sig
}

// fixedZone turns "+0200" into a zone with that offset. An unparsable or
// absent offset becomes UTC, which is the only honest default: guessing the
// reader's local zone would attribute an offset to the commit that the commit
// never carried.
func fixedZone(off string) *time.Location {
	if len(off) != 5 || (off[0] != '+' && off[0] != '-') {
		return time.UTC
	}
	h, err1 := strconv.Atoi(off[1:3])
	m, err2 := strconv.Atoi(off[3:5])
	if err1 != nil || err2 != nil || h > 23 || m > 59 {
		return time.UTC
	}
	secs := h*3600 + m*60
	if off[0] == '-' {
		secs = -secs
	}
	return time.FixedZone(off, secs)
}

// --- the object store -----------------------------------------------------

// object returns the type and body of one object, from the loose store or from
// a pack, with its hash verified against sha.
func (r *Repo) object(sha string) (string, []byte, error) {
	typ, data, err := r.rawObject(sha, 0)
	if err != nil {
		return "", nil, err
	}
	if got := objectID(typ, data); got != sha {
		// An object's name is a claim about its content. A repository that can
		// break this claim can hand the reader an author, a date and a message
		// belonging to a different object -- and those fields are the evidence
		// this whole package exists to collect.
		return "", nil, fmt.Errorf("%w: object %s hashes to %s", ErrCorrupt, sha, got)
	}
	return typ, data, nil
}

func objectID(typ string, body []byte) string {
	h := sha1.New()
	fmt.Fprintf(h, "%s %d", typ, len(body))
	h.Write([]byte{0})
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}

// rawObject finds an object without verifying its hash. depth bounds delta
// chains that cross from a pack into another object.
func (r *Repo) rawObject(sha string, depth int) (string, []byte, error) {
	if depth > r.lim.MaxDeltaDepth {
		return "", nil, fmt.Errorf("%w: delta chain deeper than %d", ErrLimit, r.lim.MaxDeltaDepth)
	}
	if typ, data, err := r.looseObject(sha); err == nil {
		return typ, data, nil
	} else if !errors.Is(err, fs.ErrNotExist) && !errors.Is(err, fsx.ErrSymlink) && !errors.Is(err, fsx.ErrNotRegular) {
		return "", nil, err
	}

	if err := r.loadPacks(); err != nil {
		return "", nil, err
	}
	for _, p := range r.packs {
		off, ok := p.find(sha)
		if !ok {
			continue
		}
		return r.packObject(p, off, depth)
	}
	return "", nil, fmt.Errorf("%w: %s", ErrObjectMissing, sha)
}

// looseObject inflates .git/objects/ab/cdef... and splits its header.
func (r *Repo) looseObject(sha string) (string, []byte, error) {
	rel := r.gitPath(path.Join("objects", sha[:2], sha[2:]))
	f, st, err := fsx.OpenConfined(r.root, rel)
	if err != nil {
		return "", nil, err
	}
	defer f.Close()
	if st.Size > r.lim.MaxLooseBytes {
		return "", nil, fmt.Errorf("%w: loose object %s is %d compressed bytes, over the %d cap",
			ErrLimit, sha, st.Size, r.lim.MaxLooseBytes)
	}
	zr, err := zlib.NewReader(io.LimitReader(f, r.lim.MaxLooseBytes))
	if err != nil {
		return "", nil, fmt.Errorf("%w: loose object %s is not a zlib stream: %v", ErrCorrupt, sha, err)
	}
	defer zr.Close()

	raw, err := readCapped(zr, r.lim.MaxObjectBytes)
	if err != nil {
		return "", nil, fmt.Errorf("%s: %w", sha, err)
	}
	nul := bytes.IndexByte(raw, 0)
	if nul < 0 || nul > 64 {
		return "", nil, fmt.Errorf("%w: loose object %s has no type header", ErrCorrupt, sha)
	}
	typ, sizeStr, ok := strings.Cut(string(raw[:nul]), " ")
	if !ok {
		return "", nil, fmt.Errorf("%w: loose object %s header %q is malformed", ErrCorrupt, sha, raw[:nul])
	}
	size, err := strconv.ParseInt(sizeStr, 10, 64)
	body := raw[nul+1:]
	if err != nil || size != int64(len(body)) {
		return "", nil, fmt.Errorf("%w: loose object %s declares %q bytes and carries %d",
			ErrCorrupt, sha, sizeStr, len(body))
	}
	return typ, body, nil
}

// readCapped reads at most max bytes and reports the cap as ErrLimit rather
// than silently truncating -- a truncated object would hash to something else
// and be reported as corrupt, which is a different and wrong statement.
func readCapped(rd io.Reader, max int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(rd, max+1))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("%w: inflated object exceeds the %d byte cap", ErrLimit, max)
	}
	return data, nil
}

// --- packfiles ------------------------------------------------------------

// pack object type codes, from the packfile format.
const (
	packCommit   = 1
	packTree     = 2
	packBlob     = 3
	packTag      = 4
	packOfsDelta = 6
	packRefDelta = 7
)

// packFile is one pack and its index. The index is read into memory (bounded);
// the pack itself is read through ReadAt, so a large pack costs a descriptor
// rather than its size in memory.
type packFile struct {
	name string
	f    *os.File
	size int64

	// names is n*20 raw object ids, sorted, exactly as the index stores them,
	// so lookups are a binary search with no per-object allocation.
	names   []byte
	offsets []int64
	count   int
}

func (p *packFile) close() {
	if p.f != nil {
		p.f.Close()
	}
}

// find binary-searches the index for sha and returns its pack offset.
func (p *packFile) find(sha string) (int64, bool) {
	want, err := hex.DecodeString(sha)
	if err != nil || len(want) != 20 {
		return 0, false
	}
	lo, hi := 0, p.count-1
	for lo <= hi {
		mid := (lo + hi) / 2
		switch bytes.Compare(p.names[mid*20:mid*20+20], want) {
		case 0:
			return p.offsets[mid], true
		case -1:
			lo = mid + 1
		default:
			hi = mid - 1
		}
	}
	return 0, false
}

// loadPacks opens every readable pack index once.
//
// An index that cannot be read is a coverage gap and not a failure: the loose
// store may still answer the question, and reporting "no history" for a
// repository with one bad pack out of two would be a false statement.
func (r *Repo) loadPacks() error {
	if r.packsLoaded {
		return nil
	}
	r.packsLoaded = true

	// objects/info/alternates names another object store, by absolute path, in
	// a repository we do not trust. It is not followed, and the gap says the
	// objects it names were out of reach.
	if data, err := r.readFile(r.gitPath("objects/info/alternates"), r.lim.MaxRefBytes); err == nil && len(bytes.TrimSpace(data)) > 0 {
		r.gap(r.dir, "objects/info/alternates names another object store, which is deliberately not "+
			"followed; objects held only there were not read")
	}

	dir := r.gitPath("objects/pack")
	ents, err := fs.ReadDir(r.root.FS(), dir)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			r.gap(dir, fmt.Sprintf("pack directory could not be listed: %v; packed objects were not read", err))
		}
		return nil
	}
	for _, e := range ents {
		if !strings.HasSuffix(e.Name(), ".idx") {
			continue
		}
		if len(r.packs) >= r.lim.MaxPackFiles {
			r.gap(dir, fmt.Sprintf("more than %d pack indexes; the rest were not read", r.lim.MaxPackFiles))
			break
		}
		p, err := r.openPack(dir, e.Name())
		if err != nil {
			r.gap(path.Join(dir, e.Name()), fmt.Sprintf("pack index unusable: %v; the objects it holds were not read", err))
			continue
		}
		r.packs = append(r.packs, p)
	}
	return nil
}

// openPack parses one index-v2 file and opens its pack.
func (r *Repo) openPack(dir, idxName string) (*packFile, error) {
	idx, err := r.readFile(path.Join(dir, idxName), r.lim.MaxIdxBytes)
	if err != nil {
		return nil, err
	}
	if len(idx) < 8 {
		return nil, fmt.Errorf("%w: index is %d bytes", ErrCorrupt, len(idx))
	}
	if !bytes.Equal(idx[:4], []byte{0xff, 0x74, 0x4f, 0x63}) {
		// A v1 index has no magic and a different layout entirely. Guessing at
		// it would mean reading offsets from the wrong place, so it is refused
		// by name: an unreadable index is a coverage gap, a misread one is a
		// wrong answer.
		return nil, fmt.Errorf("%w: pack index is not version 2 (no v2 magic); v1 indexes are not read", ErrUnsupported)
	}
	if v := binary.BigEndian.Uint32(idx[4:8]); v != 2 {
		return nil, fmt.Errorf("%w: pack index version %d", ErrUnsupported, v)
	}
	const fanoutOff = 8
	if len(idx) < fanoutOff+256*4 {
		return nil, fmt.Errorf("%w: index truncated in the fanout table", ErrCorrupt)
	}
	count := int(binary.BigEndian.Uint32(idx[fanoutOff+255*4:]))
	if count < 0 || count > r.lim.MaxIdxObjects {
		return nil, fmt.Errorf("%w: index claims %d objects, over the %d cap", ErrLimit, count, r.lim.MaxIdxObjects)
	}
	namesOff := fanoutOff + 256*4
	crcOff := namesOff + count*20
	offsOff := crcOff + count*4
	largeOff := offsOff + count*4
	if len(idx) < largeOff+40 {
		return nil, fmt.Errorf("%w: index is %d bytes, too short for %d objects", ErrCorrupt, len(idx), count)
	}

	packName := strings.TrimSuffix(idxName, ".idx") + ".pack"
	f, st, err := fsx.OpenConfined(r.root, path.Join(dir, packName))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", packName, err)
	}

	p := &packFile{
		name:    packName,
		f:       f,
		size:    st.Size,
		names:   idx[namesOff:crcOff],
		count:   count,
		offsets: make([]int64, count),
	}
	for i := 0; i < count; i++ {
		v := binary.BigEndian.Uint32(idx[offsOff+i*4:])
		if v&0x8000_0000 == 0 {
			p.offsets[i] = int64(v)
			continue
		}
		// The high bit means "index into the 64-bit offset table", which is
		// how a pack over 2 GiB records its offsets.
		j := int(v & 0x7fff_ffff)
		if largeOff+j*8+8 > len(idx)-40 {
			p.close()
			return nil, fmt.Errorf("%w: large-offset index %d out of range", ErrCorrupt, j)
		}
		p.offsets[i] = int64(binary.BigEndian.Uint64(idx[largeOff+j*8:]))
	}
	for i, off := range p.offsets {
		if off < 12 || off >= p.size {
			p.close()
			return nil, fmt.Errorf("%w: object %d offset %d outside a %d byte pack", ErrCorrupt, i, off, p.size)
		}
	}
	return p, nil
}

// packObject reads the object at off in p, reconstructing deltas.
func (r *Repo) packObject(p *packFile, off int64, depth int) (string, []byte, error) {
	if depth > r.lim.MaxDeltaDepth {
		return "", nil, fmt.Errorf("%w: delta chain deeper than %d in %s", ErrLimit, r.lim.MaxDeltaDepth, p.name)
	}

	hdr := make([]byte, 32)
	n, err := p.f.ReadAt(hdr, off)
	if n == 0 && err != nil {
		return "", nil, fmt.Errorf("%w: read at %d in %s: %v", ErrCorrupt, off, p.name, err)
	}
	hdr = hdr[:n]

	typ, size, used, err := parsePackHeader(hdr)
	if err != nil {
		return "", nil, fmt.Errorf("%s at %d: %w", p.name, off, err)
	}
	if size > r.lim.MaxObjectBytes {
		return "", nil, fmt.Errorf("%w: packed object at %d declares %d bytes, over the %d cap",
			ErrLimit, off, size, r.lim.MaxObjectBytes)
	}

	var baseSHA string
	var baseOff int64 = -1
	switch typ {
	case packOfsDelta:
		delta, k, err := parseOfsDelta(hdr[used:])
		if err != nil {
			return "", nil, fmt.Errorf("%s at %d: %w", p.name, off, err)
		}
		used += k
		baseOff = off - delta
		if delta <= 0 || baseOff < 12 || baseOff >= off {
			// delta == 0 means the object is its own base: an infinite loop
			// that no honest packer produces. Refused structurally rather than
			// left to the depth counter, because a hang is worse than a panic.
			return "", nil, fmt.Errorf("%w: OFS_DELTA at %d names base offset %d", ErrCorrupt, off, baseOff)
		}
	case packRefDelta:
		if len(hdr) < used+20 {
			return "", nil, fmt.Errorf("%w: REF_DELTA at %d truncated", ErrCorrupt, off)
		}
		baseSHA = hex.EncodeToString(hdr[used : used+20])
		used += 20
	}

	dataOff := off + int64(used)
	if dataOff >= p.size {
		return "", nil, fmt.Errorf("%w: object at %d has no payload", ErrCorrupt, off)
	}
	zr, err := zlib.NewReader(io.NewSectionReader(p.f, dataOff, p.size-dataOff))
	if err != nil {
		return "", nil, fmt.Errorf("%w: object at %d in %s is not a zlib stream: %v", ErrCorrupt, off, p.name, err)
	}
	defer zr.Close()
	payload, err := readCapped(zr, r.lim.MaxObjectBytes)
	if err != nil {
		return "", nil, err
	}
	if int64(len(payload)) != size {
		return "", nil, fmt.Errorf("%w: object at %d declares %d bytes and inflates to %d",
			ErrCorrupt, off, size, len(payload))
	}

	switch typ {
	case packCommit:
		return "commit", payload, nil
	case packTree:
		return "tree", payload, nil
	case packBlob:
		return "blob", payload, nil
	case packTag:
		return "tag", payload, nil
	case packOfsDelta, packRefDelta:
		var baseTyp string
		var base []byte
		if baseOff >= 0 {
			baseTyp, base, err = r.packObject(p, baseOff, depth+1)
		} else {
			// A REF_DELTA base can live in another pack or in the loose store
			// (a thin pack from a fetch), so this goes back through the store.
			baseTyp, base, err = r.rawObject(baseSHA, depth+1)
		}
		if err != nil {
			return "", nil, err
		}
		out, err := r.applyDelta(base, payload)
		if err != nil {
			return "", nil, fmt.Errorf("%s at %d: %w", p.name, off, err)
		}
		return baseTyp, out, nil
	default:
		return "", nil, fmt.Errorf("%w: object at %d has type %d", ErrUnsupported, off, typ)
	}
}

// parsePackHeader reads the type/size varint that begins a packed object.
func parsePackHeader(b []byte) (typ int, size int64, used int, err error) {
	if len(b) == 0 {
		return 0, 0, 0, fmt.Errorf("%w: empty object header", ErrCorrupt)
	}
	c := b[0]
	typ = int((c >> 4) & 7)
	size = int64(c & 0x0f)
	shift := uint(4)
	used = 1
	for c&0x80 != 0 {
		if used >= len(b) {
			return 0, 0, 0, fmt.Errorf("%w: object header truncated", ErrCorrupt)
		}
		if shift > 56 {
			return 0, 0, 0, fmt.Errorf("%w: object size varint too long", ErrLimit)
		}
		c = b[used]
		used++
		size |= int64(c&0x7f) << shift
		shift += 7
	}
	return typ, size, used, nil
}

// parseOfsDelta reads git's negative-offset encoding.
func parseOfsDelta(b []byte) (int64, int, error) {
	if len(b) == 0 {
		return 0, 0, fmt.Errorf("%w: OFS_DELTA offset truncated", ErrCorrupt)
	}
	c := b[0]
	off := int64(c & 0x7f)
	used := 1
	for c&0x80 != 0 {
		if used >= len(b) {
			return 0, 0, fmt.Errorf("%w: OFS_DELTA offset truncated", ErrCorrupt)
		}
		if used > 9 {
			return 0, 0, fmt.Errorf("%w: OFS_DELTA offset varint too long", ErrLimit)
		}
		c = b[used]
		used++
		off = ((off + 1) << 7) | int64(c&0x7f)
	}
	return off, used, nil
}

// applyDelta reconstructs an object from a base and a git delta.
//
// Both sizes in the delta header are checked against reality: a delta that
// claims a base size the base does not have is applied to something other than
// what it was computed against, which produces a plausible-looking object that
// is not any object. The result cap is enforced as it is built, not afterwards,
// because the point of a cap is to stop before the memory is spent.
func (r *Repo) applyDelta(base, delta []byte) ([]byte, error) {
	baseSize, n, err := deltaVarint(delta, 0)
	if err != nil {
		return nil, err
	}
	resultSize, n, err := deltaVarint(delta, n)
	if err != nil {
		return nil, err
	}
	if baseSize != int64(len(base)) {
		return nil, fmt.Errorf("%w: delta expects a %d byte base, base is %d", ErrCorrupt, baseSize, len(base))
	}
	if resultSize > r.lim.MaxObjectBytes {
		return nil, fmt.Errorf("%w: delta result %d bytes, over the %d cap", ErrLimit, resultSize, r.lim.MaxObjectBytes)
	}

	out := make([]byte, 0, resultSize)
	for n < len(delta) {
		op := delta[n]
		n++
		switch {
		case op == 0:
			// A zero opcode is reserved and unused; git rejects it too.
			return nil, fmt.Errorf("%w: delta contains a zero opcode", ErrCorrupt)
		case op&0x80 != 0:
			// Copy from the base: a bitmask says which offset and size bytes
			// are present.
			var cpOff, cpSize int64
			for i := 0; i < 4; i++ {
				if op&(1<<uint(i)) != 0 {
					if n >= len(delta) {
						return nil, fmt.Errorf("%w: delta copy offset truncated", ErrCorrupt)
					}
					cpOff |= int64(delta[n]) << uint(8*i)
					n++
				}
			}
			for i := 0; i < 3; i++ {
				if op&(0x10<<uint(i)) != 0 {
					if n >= len(delta) {
						return nil, fmt.Errorf("%w: delta copy size truncated", ErrCorrupt)
					}
					cpSize |= int64(delta[n]) << uint(8*i)
					n++
				}
			}
			if cpSize == 0 {
				cpSize = 0x10000 // the format's documented special case
			}
			if cpOff < 0 || cpSize < 0 || cpOff+cpSize > int64(len(base)) {
				return nil, fmt.Errorf("%w: delta copies %d bytes at %d from a %d byte base",
					ErrCorrupt, cpSize, cpOff, len(base))
			}
			if int64(len(out))+cpSize > resultSize {
				return nil, fmt.Errorf("%w: delta result exceeds its declared %d bytes", ErrCorrupt, resultSize)
			}
			out = append(out, base[cpOff:cpOff+cpSize]...)
		default:
			// Insert: the opcode is the literal byte count.
			size := int(op)
			if n+size > len(delta) {
				return nil, fmt.Errorf("%w: delta insert of %d bytes truncated", ErrCorrupt, size)
			}
			if int64(len(out))+int64(size) > resultSize {
				return nil, fmt.Errorf("%w: delta result exceeds its declared %d bytes", ErrCorrupt, resultSize)
			}
			out = append(out, delta[n:n+size]...)
			n += size
		}
	}
	if int64(len(out)) != resultSize {
		return nil, fmt.Errorf("%w: delta produced %d bytes, declared %d", ErrCorrupt, len(out), resultSize)
	}
	return out, nil
}

// deltaVarint reads the little-endian varint the delta header uses (a
// different encoding from the pack object header's).
func deltaVarint(b []byte, i int) (int64, int, error) {
	var v int64
	var shift uint
	for {
		if i >= len(b) {
			return 0, i, fmt.Errorf("%w: delta header truncated", ErrCorrupt)
		}
		if shift > 56 {
			return 0, i, fmt.Errorf("%w: delta size varint too long", ErrLimit)
		}
		c := b[i]
		i++
		v |= int64(c&0x7f) << shift
		if c&0x80 == 0 {
			return v, i, nil
		}
		shift += 7
	}
}
