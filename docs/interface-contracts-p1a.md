# P1-A frozen interface contracts

Lane `interface-contracts` (architect). **Frozen 2026-08-04, before parallel work
begins.** Every signature below is a commitment between lanes: a lane may change
its own internals freely, but changing anything on this page requires the
orchestrator to re-freeze it and notify every dependent lane.

Task 1 shipped in `1ee1aa2`. Tasks 2–7 run in parallel across two fronts;
task 8 is the join.

## Ownership map — one package, one owner, no shared files

| Front | Team lead | Tasks | Owns exclusively |
|---|---|---|---|
| A | `lead-alpm` | 2, 3, 4, 5 | `internal/alpm/**`, `testdata/roots/**` |
| B | `lead-model` | 6, 7 | `internal/finding/**`, `internal/aur/**`, `testdata/aur/**` |
| — | orchestrator | integration | `go.mod`, `cmd/**`, `docs/**`, all git commits |

Fronts A and B share **no file**. Neither front imports the other: front A's
parsers and front B's model are independent, and `internal/check` (task 8, the
join) is the first package that imports both.

## Frozen signatures

### `internal/config` — shipped

```go
type Config struct {
	Root, DBPath, SyncPath, StateDir string
	Network                         bool
	MinSeverity                     string
}
type DoctorLine struct{ Key, Value, Source string }

func Resolve(root string, euid int) (Config, error)
func (c Config) Doctor() []DoctorLine
```

### `internal/alpm` — front A

```go
// Task 2. Multi-valued because %DEPENDS% and friends repeat.
func ParseDesc(r io.Reader) (map[string][]string, error)

// Task 3. %BACKUP% lives in `files`, not `desc`, and is "path\tmd5"-shaped —
// measured, not assumed: 0 occurrences in desc, 94 in files on the reference
// system. backup maps path -> md5.
func ParseFiles(r io.Reader) (paths []string, backup map[string]string, err error)

// Task 4. The []string return is unreadable DB entries: coverage gaps, never
// silently dropped (INV-9).
type Package struct {
	Name, Version, Base, Validation, Packager string
	InstallDate                               time.Time
	Files                                     []string
	Backup                                    map[string]string
}
func LoadLocalDB(dbPath string) ([]Package, []string, error)

// Task 5. The []string return is unreadable sync DB filenames: coverage gaps.
// Foreignness derives from sync-DB absence ONLY — never from %VALIDATION%,
// which `python-pkg_resources` disproves (foreign yet pgp-signed).
func LoadSyncNames(syncPath string) (map[string]bool, []string, error)
func IsForeign(p Package, syncNames map[string]bool) bool
```

### `internal/finding` — front B

```go
type Severity int
const (
	SevInfo Severity = iota
	SevSuspicious
	SevCritical
)
func (s Severity) String() string

type Finding struct {
	RuleID, SubjectKind, Subject string
	Severity                     Severity
	Summary                      string
	Evidence                     []string
	Limits                       string
}
type Gap struct{ RuleID, Subject, Reason string }
type Result struct {
	Findings []Finding
	Gaps     []Gap
}

// Stable across runs and across versions: it is what --since-last diffs on.
func Fingerprint(ruleID, subjectKind, subjectIdentity, scope string) string

func (r Result) Complete() bool      // len(Gaps) == 0
func (r Result) MaxSeverity() Severity
```

### `internal/aur` — front B

```go
type Pkg struct {
	Name, PackageBase, Maintainer, Submitter string
	FirstSubmitted, LastModified             int64
}

type Client interface {
	Info(ctx context.Context, bases []string) (map[string]Pkg, error)

	// Tombstone reports whether the cgit log records a removal commit, and the
	// matching message. `present == true` means A REMOVAL WAS DETECTED — it does
	// NOT mean malware. Severity comes solely from IsMalwareRemoval(message):
	// an administrative removal ("removed due to rename") is present-but-not-
	// malware and must land at SevSuspicious via `aur-absent`.
	Tombstone(ctx context.Context, base string) (bool, string, error)
}

type Fake struct {
	Known      map[string]Pkg
	Tombstones map[string]string
	Err        error
}

func NewHTTP(baseURL string, hc *http.Client) *HTTP
```

`baseURL` is a parameter, not a constant, so `http_test.go` drives a
`httptest.Server` and no test reaches the network.

### Consumed later (not built this round)

`check.Provenance(ctx, pkgs []alpm.Package, syncNames map[string]bool, cl aur.Client, network bool) finding.Result`
is the join. Both fronts must leave their outputs consumable by exactly that
call — that is the contract's whole purpose.

## Cross-cutting rules that outrank lane convenience

1. **A failure is a gap, never an absence.** An RPC error, a timeout, or
   `network == false` produces a `finding.Gap`. It must never produce a finding
   that says a package is missing from the AUR — that is false assurance
   inverted into a false accusation. (P1-A success criterion 4.)
2. **Coverage is reported, not inferred (INV-9).** Every function that can fail
   to read part of its input returns those subjects. Callers propagate them.
   Nothing is silently skipped.
3. **Only the tombstone earns `SevCritical`,** and only when the removal message
   matches the malware pattern. An administrative removal
   (`removed due to rename`) is `SevSuspicious` via `aur-absent`. Verified
   wording: `history removed due to malware`.
4. **No third-party dependencies in P1-A.** `golang.org/x/sys` is the only
   sanctioned dependency in the whole project and it enters at P1-B.
5. **Fixtures carry inert markers only** — no working payloads, no real C2
   addresses, no live URLs.
6. **Leads do not commit.** Git is serialized at the orchestrator so two fronts
   cannot race the index. A lead reports its lane green; the orchestrator
   verifies and commits.

## Open items carried into the task 8 join

Raised by the lanes themselves, resolved or assigned here rather than left for
the join lane to trip over.

| # | Item | Resolution |
|---|---|---|
| O-1 | The `stock` fixture root has no `var/lib/pacman/sync/`, so it cannot drive `IsForeign` end to end. | **Generate sync DBs at runtime in the test.** A committed gzipped tar is opaque to review, and a fixture nobody can read is a fixture nobody checks. Front A's path, front A's change. |
| O-2 | `LoadSyncNames` cannot distinguish "empty repo" from "sync DB I failed to parse". Zero names, zero gaps, nil error — and an empty `syncNames` makes `IsForeign` return true for **every installed package**, reported as complete coverage. | Real defect, deliberately unpatched: an empty repo is a legitimate state, so gapping every zero-name DB would manufacture false gaps. Adopt the lane's proposed rule — **gap when a `.db` parses to zero names but contained at least one tar entry** — and add the sentence to spec §5 before implementing. |
| O-3 | `LoadLocalDB` may emit two gap entries for one directory. | Not a defect. `gaps` is a list of *subjects that were not fully analysed*, not a count of packages. Callers must not treat `len(gaps)` as a package count. |
| O-4 | `LoadLocalDB`'s `[]string` gap channel would be better typed as `[]Gap{Subject, Reason}`. | Frozen for P1-A. Importing `finding.Gap` would couple front A to front B, which this contract forbids. Revisit when the fronts merge at task 8. |
| O-5 | `IsForeign(p Package, ...)` reads only `p.Name`; taking a `string` would make consulting `%VALIDATION%` structurally impossible rather than comment-enforced. | Frozen for P1-A — `check.Provenance` iterates `[]alpm.Package`. Worth doing at the next signature revision: it converts a rule we currently enforce by review into one the compiler enforces. |
| O-6 | `Fingerprint` cannot enforce its own version-independence contract; a caller passing `pkg-1.2.3-1` gets a version-bearing fingerprint silently, invalidating every `--since-last` suppression on upgrade. | Task 10 must pin it: fingerprint the same package across two synthetic versions and assert equality. A `SubjectID` named type with a rejecting constructor is the stronger fix and is deferred. |

## Process note: a headless lead cannot await its own specialists

A `claude -p` team lead is one-shot and cannot block on a child it spawned — both
leads correctly reported "waiting on task N" and exited before their last
specialist landed. The lead is therefore **resumed** (`resume.sh`, `--resume
<session-id>`) rather than relaunched, which preserves the specialist reports it
already read and the deviations it already authorised. A lead that must wait
inline has to do so in a *foreground* shell loop; a backgrounded wait returns
immediately and the lead exits.
