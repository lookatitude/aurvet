// internal/gate/approve.go
//
// Package gate is the pre-install review: it decides whether a recipe a human
// already approved is the recipe about to be built, and it shows what moved
// since that decision was taken.
//
// Two files carry that today. approve.go holds the approval store (P2 task 10);
// vcsdelta.go holds the VCS delta review (P2 task 11), which exists because the
// store alone cannot see a -git package's upstream moving underneath a stable
// recipe.
//
// Nothing here executes anything (INV-2). The inputs are an AUR clone and a git
// repository, both attacker-controlled; the outputs are evidence and coverage
// gaps.
//
// # What an approval is keyed on, and why it is both halves
//
// pkgbase + recipe digest. Neither half is sufficient and the failure modes are
// opposite: keyed on pkgbase alone the store blesses every future version of a
// recipe, which is the blank cheque this phase exists to refuse; keyed on the
// digest alone it loses the identity the decision belongs to, so approving one
// package silences an unrelated one that happens to ship the same bytes.
// pkgbase, never pkgname -- 433 of 1409 packages on the reference system are
// split, and a review decision is taken over one build, not one output package.
//
// # What the digest is taken over -- the judgement call, argued
//
// The digest covers the PKGBUILD **and every additional file the recipe names
// that ships beside it**: the install= scriptlet and any local source=() entry
// (patches, .desktop files, unit files, sysusers fragments). Those names are
// supplied by the caller (RecipeRequest.Aux) from the resolver's output; this
// package does not parse bash (INV-2 is not the reason -- the resolver already
// exists and duplicating it here would give the gate a second, divergent
// opinion about what a recipe contains).
//
// The alternative -- PKGBUILD only -- was rejected for one concrete reason: a
// .install scriptlet runs AS ROOT at install time, is not the file a reviewer's
// eye lands on, and can be changed without touching a byte of the PKGBUILD. An
// approval store that goes silent on that change approves precisely the payload
// path that is hardest to notice. The same argument holds, one step weaker, for
// a local patch: it is applied to the code that gets built. Both are part of
// the recipe in every sense a reviewer cares about, so both are in the digest.
//
// The scope limit is equally deliberate and is stated in output rather than in
// documentation (INV-6): the digest covers the files the recipe NAMES, so it
// says nothing about a remote source=() URL whose contents changed behind a
// stable URL. That is what the integrity array is for, what SKIP-on-fixed-URL
// is a rule about, and -- for VCS sources, where there is no checksum at all --
// what vcsdelta.go exists to cover. An approval is a statement about a recipe,
// never a statement about the internet.
//
// # Why a corrupt store is neither "clean" nor "nothing approved"
//
// Both of those readings hand an attacker something. Read as "everything is
// approved" it buys silence; read as "nothing is approved" it buys prompt
// fatigue, and the prompt an operator has learned to click through is not a
// control. So an unreadable, tampered, symlinked or future-format record yields
// StatusIndeterminate: not approved, not silent, and a coverage gap naming what
// could not be determined (INV-9).
package gate

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/lookatitude/aurvet/internal/config"
	"github.com/lookatitude/aurvet/internal/finding"
	"github.com/lookatitude/aurvet/internal/fsx"
)

// StoreFormat is the on-disk record version. A record carrying anything else is
// refused rather than interpreted: an older binary guessing at a newer record's
// meaning is exactly how a "silent when unchanged" store goes silent on
// something it never understood.
const StoreFormat = 1

// The sentinels a caller switches on.
var (
	// ErrBadPkgBase is a pkgbase this package refuses to use as an identity.
	// It comes from an attacker-controlled .SRCINFO, so it is validated before
	// it can influence a path or a record.
	ErrBadPkgBase = errors.New("gate: refused pkgbase")

	// ErrRecipeUnreadable means a file the recipe names could not be read in
	// full. There is no partial digest: a digest over the half that was
	// readable would claim coverage this tool does not have.
	ErrRecipeUnreadable = errors.New("gate: recipe file unreadable")

	// ErrOffline refuses a write under --offline-root (INV-5). The state
	// directory resolves INSIDE the tree being inspected in that mode, so an
	// approval written there would mutate the evidence.
	ErrOffline = errors.New("gate: refusing to write under --offline-root")

	// ErrStoreUnsafe is an approval store whose permissions or ownership mean
	// another account could have written it. An approval record is a human
	// decision; a forgeable one is decoration.
	ErrStoreUnsafe = errors.New("gate: approval store is not private")
)

// Gap rule identifiers. They are not collapsed into one "approval unavailable"
// because the remedies differ: a refused pkgbase is a finding about the
// package, an unsafe store is a finding about the machine, and a corrupt record
// is a finding about the store's integrity.
const (
	// RulePkgBaseRefused is a pkgbase that is not usable as an identity.
	RulePkgBaseRefused = "approval-pkgbase-refused"

	// RuleStoreUnreadable is a store directory or record that could not be
	// read -- permissions, or a record that is not a regular file.
	RuleStoreUnreadable = "approval-store-unreadable"

	// RuleStoreUnsafe is a store any other account could write.
	RuleStoreUnsafe = "approval-store-unsafe"

	// RuleRecordCorrupt is a record that parsed as garbage, named another
	// pkgbase, or carried an unknown format version.
	RuleRecordCorrupt = "approval-record-corrupt"
)

// SubjectApproval is the subject kind for the gaps this file emits.
const SubjectApproval = "approval"

// maxRecordBytes bounds one record read. Records are a few hundred bytes plus
// one manifest entry per recipe file; the cap is four orders of magnitude above
// that and exists so a planted file cannot be a memory budget.
const maxRecordBytes = 1 << 20

// maxRecipeFileBytes bounds one recipe file read for digesting. The largest
// PKGBUILD in the reference cache is under 16 KB; local patches are the
// unbounded member of the set, so the cap is generous and still finite.
const maxRecipeFileBytes = 64 << 20

// --- the recipe digest ------------------------------------------------------

// RecipeFile is one file the digest covers.
type RecipeFile struct {
	// Name is the recipe-relative file name, as the recipe wrote it.
	Name string `json:"name"`

	// SHA256 is the digest of the bytes read from the descriptor that was
	// opened once (fsx.OpenConfined), never of a path resolved twice.
	SHA256 string `json:"sha256"`

	// Bytes is the size read, reported so a manifest entry is auditable
	// without re-reading the file.
	Bytes int64 `json:"bytes"`
}

// Recipe is the digested form of one pkgbase's recipe: the identity, the file
// manifest, and the single digest the store keys on.
type Recipe struct {
	PkgBase string       `json:"pkgbase"`
	Files   []RecipeFile `json:"files"`
	Digest  string       `json:"digest"`
}

// RecipeRequest names what to digest.
//
// Aux is the caller's list of additional recipe-relative files: install= and
// every local source=() entry, which internal/pkgbuild already identifies
// (Source.Local, Source.Name). Order and duplicates do not matter -- the digest
// is over the file set, so a resolver that reorders its output does not
// invalidate an approval. A caller that passes no Aux gets a PKGBUILD-only
// digest, and Recipe.Files reports exactly that, so the narrower coverage is
// visible rather than assumed.
type RecipeRequest struct {
	PkgBase string
	// Dir is the root-relative directory holding the recipe.
	Dir string
	Aux []string
}

// digestPrefix domain-separates the manifest hash. Without it a digest computed
// here could collide with any other sha256 this project takes over similar
// text.
const digestPrefix = "aurvet-recipe-v1\n"

// DigestRecipe reads the recipe files and returns the manifest plus the digest
// the store keys on.
//
// It is a pure function of (root, req) (INV-4): no CWD, no $HOME, no ambient
// path. Every read goes through fsx.OpenConfined, so a symlink standing where a
// PKGBUILD was expected is refused rather than followed, a fifo cannot hang the
// gate, and no name in an attacker-written recipe can reach outside root.
//
// The encoding is length-prefixed per field, the same injectivity argument as
// finding.Fingerprint: no file name and no digest can shift a byte across a
// field boundary to collide with a different manifest.
func DigestRecipe(root *os.Root, req RecipeRequest) (Recipe, error) {
	if err := ValidPkgBase(req.PkgBase); err != nil {
		return Recipe{}, err
	}
	dir, err := safeRel(req.Dir)
	if err != nil {
		return Recipe{}, fmt.Errorf("%w: recipe directory %q: %v", ErrRecipeUnreadable, req.Dir, err)
	}

	names := []string{"PKGBUILD"}
	seen := map[string]bool{"PKGBUILD": true}
	for _, n := range req.Aux {
		if seen[n] {
			continue
		}
		seen[n] = true
		names = append(names, n)
	}

	files := make([]RecipeFile, 0, len(names))
	for _, name := range names {
		if err := safeName(name); err != nil {
			return Recipe{}, fmt.Errorf("%w: %q: %v", ErrRecipeUnreadable, name, err)
		}
		rf, err := digestOne(root, path.Join(dir, name), name)
		if err != nil {
			return Recipe{}, err
		}
		files = append(files, rf)
	}

	// Sort by name so the digest is over the file SET. Names are unique by
	// construction above, so the order is total.
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })

	h := sha256.New()
	h.Write([]byte(digestPrefix))
	for _, f := range files {
		fmt.Fprintf(h, "%d:%s%d:%s", len(f.Name), f.Name, len(f.SHA256), f.SHA256)
	}

	// PKGBUILD first in the manifest, then the rest alphabetically: the recipe
	// is what a reviewer reads first, and Files is rendered.
	sort.SliceStable(files, func(i, j int) bool { return files[i].Name == "PKGBUILD" && files[j].Name != "PKGBUILD" })

	return Recipe{
		PkgBase: req.PkgBase,
		Files:   files,
		Digest:  hex.EncodeToString(h.Sum(nil)),
	}, nil
}

func digestOne(root *os.Root, rel, name string) (RecipeFile, error) {
	f, st, err := fsx.OpenConfined(root, rel)
	if err != nil {
		return RecipeFile{}, fmt.Errorf("%w: %s: %v", ErrRecipeUnreadable, name, err)
	}
	defer f.Close()
	if st.Size > maxRecipeFileBytes {
		return RecipeFile{}, fmt.Errorf("%w: %s: %d bytes over the %d cap", ErrRecipeUnreadable, name, st.Size, int64(maxRecipeFileBytes))
	}
	sum, n, err := fsx.Digest(f, st)
	if err != nil {
		return RecipeFile{}, fmt.Errorf("%w: %s: %v", ErrRecipeUnreadable, name, err)
	}
	return RecipeFile{Name: name, SHA256: sum, Bytes: n}, nil
}

// safeRel accepts a root-relative directory and refuses anything that would be
// reinterpreted on the way to a syscall.
func safeRel(rel string) (string, error) {
	if rel == "" || rel == "." {
		return ".", nil
	}
	if strings.HasPrefix(rel, "/") || strings.ContainsRune(rel, 0) {
		return "", errors.New("must be relative and NUL-free")
	}
	for _, p := range strings.Split(strings.TrimPrefix(rel, "./"), "/") {
		switch p {
		case "", ".", "..":
			return "", errors.New("contains an empty, . or .. component")
		}
	}
	return strings.TrimPrefix(rel, "./"), nil
}

// safeName refuses a recipe-named file that is not a plain name inside the
// recipe directory. source=(../../etc/shadow) is a real shape and this is where
// it stops.
func safeName(name string) error {
	if name == "" {
		return errors.New("empty file name")
	}
	if strings.ContainsRune(name, 0) {
		return errors.New("contains NUL")
	}
	if strings.HasPrefix(name, "/") {
		return errors.New("absolute path")
	}
	for _, p := range strings.Split(name, "/") {
		switch p {
		case "", ".", "..":
			return errors.New("contains an empty, . or .. component")
		}
	}
	return nil
}

// --- pkgbase validation -----------------------------------------------------

// maxPkgBaseBytes is well above the longest real pkgbase (the reference
// system's longest is 27 bytes) and well below anything that could be a path
// problem.
const maxPkgBaseBytes = 128

// ValidPkgBase reports whether a pkgbase is usable as an identity.
//
// The permitted set is Arch's own package-name charset: alphanumerics plus
// @ . _ + -, not starting with a hyphen or a dot. Everything else is refused --
// traversal, absolute paths, NUL, newlines, spaces, shell metacharacters and
// 4 KB names -- and refused HERE, before the value reaches a path, a record or
// a report line.
//
// The refusal is deliberately an allowlist. A denylist of "../" and "/" would
// have to anticipate every encoding of the same idea; an allowlist has to be
// wrong only about the ecosystem, which is measurable and is asserted by a test
// over real AUR names.
func ValidPkgBase(s string) error {
	if s == "" {
		return fmt.Errorf("%w: empty", ErrBadPkgBase)
	}
	if len(s) > maxPkgBaseBytes {
		return fmt.Errorf("%w: %d bytes over the %d cap", ErrBadPkgBase, len(s), maxPkgBaseBytes)
	}
	if s[0] == '-' || s[0] == '.' {
		return fmt.Errorf("%w: %q starts with %q", ErrBadPkgBase, safeQuote(s), string(s[0]))
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '@' || c == '.' || c == '_' || c == '+' || c == '-':
		default:
			return fmt.Errorf("%w: %q contains a byte outside the package-name charset at offset %d", ErrBadPkgBase, safeQuote(s), i)
		}
	}
	return nil
}

// safeQuote renders an untrusted name for a message without letting it forge
// output: bounded, and with control bytes escaped by %q at the call site.
func safeQuote(s string) string {
	const max = 64
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}

// --- the store --------------------------------------------------------------

// Anchor is the upstream position an approval was taken at, carried so the VCS
// delta review has something to measure from when no snapshot exists. Defined
// in vcsdelta.go, where it is used.

// Approval is one recorded human decision. It is plain JSON on purpose: the
// record format has to be writable and auditable with the standard library and
// with a text editor, and no new module may enter for it.
type Approval struct {
	FormatVersion int          `json:"format_version"`
	PkgBase       string       `json:"pkgbase"`
	Digest        string       `json:"digest"`
	Files         []RecipeFile `json:"files"`
	ApprovedAt    time.Time    `json:"approved_at"`

	// By and Note record who took the decision and why, because an approval
	// nobody can audit is not a record of a human decision.
	By   string `json:"by,omitempty"`
	Note string `json:"note,omitempty"`

	// VCS is the upstream position at approval time, for -git packages whose
	// recipe digest cannot move even though the built source does.
	VCS *Anchor `json:"vcs,omitempty"`
}

// Status is the outcome of a lookup. Four values, and collapsing any two of
// them loses a distinction the operator needs.
type Status string

const (
	// StatusApproved: this exact recipe, for this pkgbase, was approved. The
	// only status that is silent.
	StatusApproved Status = "approved"

	// StatusChanged: this pkgbase was approved, at a different digest. The
	// review prompts and leads with a diff against Decision.Prior.
	StatusChanged Status = "recipe-changed"

	// StatusUnknown: no record. A first install is not a coverage gap -- there
	// is nothing this tool failed to read.
	StatusUnknown Status = "never-approved"

	// StatusIndeterminate: approval could not be determined. Never silent,
	// always accompanied by a Gap (INV-9).
	StatusIndeterminate Status = "could-not-determine"
)

// Decision is a lookup result.
type Decision struct {
	PkgBase string
	Digest  string
	Status  Status

	// Approval is the matching record, set only for StatusApproved.
	Approval *Approval

	// Prior is the superseded record, set only for StatusChanged, so review
	// output can diff the incoming recipe against the last approved one
	// instead of printing the whole file.
	Prior *Approval

	// Gaps is what could not be determined (INV-9).
	Gaps []finding.Gap

	// Limits states what this decision does not prove (INV-6).
	Limits string
}

// Silent reports whether the gate may say nothing. Exactly one status is
// silent, and the method exists so no caller re-derives that rule and gets it
// subtly wrong -- treating StatusIndeterminate as "nothing to say" is the
// fail-open this store is designed to prevent.
func (d Decision) Silent() bool { return d.Status == StatusApproved }

// Store is the on-disk approval store.
type Store struct {
	dir string

	// offline records that Config.Root is not "/", which makes every write a
	// refusal (INV-5).
	offline bool
}

// OpenStore resolves the store from an already-resolved Config. It performs no
// I/O and creates nothing: a read must never bring the store into existence,
// and under --offline-root creating a directory would already be a write to the
// inspected tree.
//
// The location comes from config.Resolve rather than from a path scheme
// invented here, so the SourceFallbackUnwritable case (an unprivileged live run
// with neither XDG_STATE_HOME nor HOME) surfaces as the write error doctor
// already explains, and a privileged run never follows a user-controlled path.
func OpenStore(cfg config.Config) (*Store, error) {
	if cfg.StateDir == "" {
		return nil, errors.New("gate: config has no state directory; call config.Resolve first")
	}
	if !filepath.IsAbs(cfg.StateDir) {
		return nil, fmt.Errorf("gate: state directory %q is not absolute", cfg.StateDir)
	}
	return &Store{
		dir:     filepath.Join(cfg.StateDir, "approvals"),
		offline: cfg.Root != "/",
	}, nil
}

// Dir is the store directory. Exported for doctor output and for tests.
func (s *Store) Dir() string { return s.dir }

// recordPath is the slot for one pkgbase.
//
// The file name is sha256(pkgbase), not the pkgbase. ValidPkgBase has already
// refused anything hostile, so this is defence in depth rather than the
// control -- but it is cheap defence in depth that removes attacker-chosen text
// from a path entirely, and it makes every slot a fixed 64-byte name regardless
// of what a .SRCINFO claims.
func (s *Store) recordPath(pkgbase string) string {
	sum := sha256.Sum256([]byte(pkgbase))
	return filepath.Join(s.dir, hex.EncodeToString(sum[:])+".json")
}

// Lookup answers whether this exact recipe was approved for this pkgbase.
//
// It never creates anything, and it never returns StatusApproved on evidence it
// could not fully verify.
func (s *Store) Lookup(pkgbase, digest string) Decision {
	d := Decision{PkgBase: pkgbase, Digest: digest}

	if err := ValidPkgBase(pkgbase); err != nil {
		d.Status = StatusIndeterminate
		d.Limits = "the package's own metadata names a pkgbase this tool refuses to use as an identity, so no approval can be looked up or recorded for it"
		d.Gaps = append(d.Gaps, finding.Gap{
			RuleID:  RulePkgBaseRefused,
			Subject: safeQuote(pkgbase),
			Reason:  err.Error(),
		})
		return d
	}

	if err := s.checkDirSafe(); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// No store yet is not a gap: nothing has ever been approved on
			// this machine and nothing failed to be read.
			d.Status = StatusUnknown
			d.Limits = unknownLimits
			return d
		}
		rule := RuleStoreUnreadable
		if errors.Is(err, ErrStoreUnsafe) {
			rule = RuleStoreUnsafe
		}
		d.Status = StatusIndeterminate
		d.Limits = "the approval store could not be trusted to answer, so this recipe is neither known-approved nor known-unapproved"
		d.Gaps = append(d.Gaps, finding.Gap{RuleID: rule, Subject: pkgbase, Reason: err.Error()})
		return d
	}

	a, err := s.read(pkgbase)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		d.Status = StatusUnknown
		d.Limits = unknownLimits
		return d
	case errors.Is(err, errCorrupt):
		d.Status = StatusIndeterminate
		d.Limits = "an approval record exists for this pkgbase and could not be read as one; it is not treated as approval"
		d.Gaps = append(d.Gaps, finding.Gap{RuleID: RuleRecordCorrupt, Subject: pkgbase, Reason: err.Error()})
		return d
	case err != nil:
		d.Status = StatusIndeterminate
		d.Limits = "the approval record could not be read, so this recipe is neither known-approved nor known-unapproved"
		d.Gaps = append(d.Gaps, finding.Gap{RuleID: RuleStoreUnreadable, Subject: pkgbase, Reason: err.Error()})
		return d
	}

	if a.Digest == digest {
		d.Status = StatusApproved
		d.Approval = a
		d.Limits = "approval covers the recipe files listed in the record; it says nothing about the contents fetched from remote sources at build time"
		return d
	}
	d.Status = StatusChanged
	d.Prior = a
	d.Limits = "the recipe changed since it was approved; only the named recipe files are compared, so an unchanged digest would still not cover remote source contents"
	return d
}

const unknownLimits = "no approval has ever been recorded for this pkgbase; that is an absence of a decision, not a decision"

// errCorrupt marks a record that exists and is not a record.
var errCorrupt = errors.New("gate: approval record is not a valid record")

// read loads and validates one record.
func (s *Store) read(pkgbase string) (*Approval, error) {
	p := s.recordPath(pkgbase)

	// Open the slot itself with O_NOFOLLOW: a record that is a symlink is not a
	// record this store wrote, and following it would let anyone who can create
	// a link in the state dir choose what the gate reads.
	fd, err := unix.Open(p, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		if err == unix.ELOOP {
			return nil, fmt.Errorf("%w: %s is a symlink", errCorrupt, p)
		}
		return nil, &fs.PathError{Op: "open", Path: p, Err: err}
	}
	f := os.NewFile(uintptr(fd), p)
	defer f.Close()

	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, &fs.PathError{Op: "fstat", Path: p, Err: err}
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, fmt.Errorf("%w: %s is not a regular file", errCorrupt, p)
	}
	if st.Size > maxRecordBytes {
		return nil, fmt.Errorf("%w: %s is %d bytes, over the %d cap", errCorrupt, p, st.Size, int64(maxRecordBytes))
	}

	raw := make([]byte, st.Size)
	if _, err := io.ReadFull(f, raw); err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return nil, &fs.PathError{Op: "read", Path: p, Err: err}
	}

	var a Approval
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&a); err != nil {
		return nil, fmt.Errorf("%w: %v", errCorrupt, err)
	}
	if a.FormatVersion != StoreFormat {
		return nil, fmt.Errorf("%w: format version %d, this build understands %d", errCorrupt, a.FormatVersion, StoreFormat)
	}
	if a.PkgBase != pkgbase {
		// The slot is derived from the pkgbase, so a record naming a different
		// one was not written by this store for this package.
		return nil, fmt.Errorf("%w: record in %s names pkgbase %q", errCorrupt, filepath.Base(p), safeQuote(a.PkgBase))
	}
	if a.Digest == "" {
		return nil, fmt.Errorf("%w: record carries no digest", errCorrupt)
	}
	return &a, nil
}

// ApproveOptions carries the parts of a decision that are not the recipe.
type ApproveOptions struct {
	By   string
	Note string

	// VCS records the upstream position reviewed, so a later run can show the
	// commit range since this decision even if the snapshot is gone.
	VCS *Anchor

	// Now exists so a test can pin the timestamp. Zero means time.Now().
	Now time.Time
}

// Approve records a human decision.
//
// This is the one deliberate write in this package, and it is confined to the
// state directory: never the clone, never anywhere the reviewed package can
// reach. Under --offline-root it is refused outright (INV-5).
//
// The write is temp + fsync + atomic rename, so a crash or a full disk leaves
// either the old record or the new one and never a half-parsed record that
// would read as corrupt on the next run.
func (s *Store) Approve(r Recipe, opts ApproveOptions) (Approval, error) {
	if err := ValidPkgBase(r.PkgBase); err != nil {
		return Approval{}, err
	}
	if r.Digest == "" {
		return Approval{}, errors.New("gate: refusing to approve an empty digest")
	}
	if s.offline {
		return Approval{}, fmt.Errorf("%w: %s", ErrOffline, s.dir)
	}
	if err := s.ensureDir(); err != nil {
		return Approval{}, err
	}

	when := opts.Now
	if when.IsZero() {
		when = time.Now().UTC()
	}
	a := Approval{
		FormatVersion: StoreFormat,
		PkgBase:       r.PkgBase,
		Digest:        r.Digest,
		Files:         r.Files,
		ApprovedAt:    when,
		By:            opts.By,
		Note:          opts.Note,
		VCS:           opts.VCS,
	}
	body, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return Approval{}, err
	}
	body = append(body, '\n')

	tmp, err := os.CreateTemp(s.dir, ".tmp-approval-*")
	if err != nil {
		return Approval{}, err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return Approval{}, err
	}
	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		return Approval{}, err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return Approval{}, err
	}
	if err := tmp.Close(); err != nil {
		return Approval{}, err
	}
	if err := os.Rename(tmpName, s.recordPath(r.PkgBase)); err != nil {
		return Approval{}, err
	}
	return a, nil
}

// Revoke removes a recorded approval. A store that can only grow cannot express
// "I was wrong", and the only alternative -- editing JSON by hand -- is how a
// store ends up corrupt.
func (s *Store) Revoke(pkgbase string) error {
	if err := ValidPkgBase(pkgbase); err != nil {
		return err
	}
	if s.offline {
		return fmt.Errorf("%w: %s", ErrOffline, s.dir)
	}
	err := os.Remove(s.recordPath(pkgbase))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

// ensureDir creates the store directory 0700 and refuses to use one that is not
// private.
func (s *Store) ensureDir() error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	return s.checkDirSafe()
}

// checkDirSafe refuses a store another account could write to, and reports a
// missing store as fs.ErrNotExist so the caller can tell "never approved
// anything" from "cannot be trusted".
//
// Ownership is checked as well as mode: a directory owned by someone else is
// theirs to chmod at any moment, so its current mode proves nothing.
func (s *Store) checkDirSafe() error {
	var st unix.Stat_t
	if err := unix.Lstat(s.dir, &st); err != nil {
		if err == unix.ENOENT {
			return fs.ErrNotExist
		}
		return &fs.PathError{Op: "lstat", Path: s.dir, Err: err}
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("%w: %s is not a directory", ErrStoreUnsafe, s.dir)
	}
	if st.Mode&(unix.S_IWGRP|unix.S_IWOTH) != 0 {
		return fmt.Errorf("%w: %s is mode %04o; group- or world-writable means an approval can be forged",
			ErrStoreUnsafe, s.dir, st.Mode&0o7777)
	}
	if euid := uint32(os.Geteuid()); st.Uid != euid && st.Uid != 0 {
		return fmt.Errorf("%w: %s is owned by uid %d, not %d or root", ErrStoreUnsafe, s.dir, st.Uid, euid)
	}
	// A readable directory is a precondition for every lookup; probe it here so
	// EACCES is reported as a store problem rather than as a missing record.
	f, err := os.Open(s.dir)
	if err != nil {
		return err
	}
	f.Close()
	return nil
}
