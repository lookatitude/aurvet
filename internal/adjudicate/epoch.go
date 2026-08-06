// internal/adjudicate/epoch.go
//
// Fingerprint epochs: the binding between a recorded judgement and the matching
// semantics it was made against (P4 task 8).
//
// # The failure this exists to prevent
//
// An operator adjudicates finding X as benign. Later, the rule that produced X
// changes what it matches. The old suppression is now bound to semantics that no
// longer exist, and there are two tempting behaviours, both wrong:
//
//   - silently persisting -- the suppression keeps matching under the new
//     semantics and now hides something nobody assessed;
//   - silently vanishing -- the suppression stops matching, the finding
//     reappears with no explanation, and the operator's recorded judgement is
//     lost.
//
// The correct third option is STALE: the judgement is preserved verbatim, it no
// longer suppresses anything, and the operator is told to re-adjudicate. Apply
// implements that; this file supplies what "the semantics moved" is measured
// against.
//
// # Two mechanisms, only one of which safety depends on
//
// A record carries both the epoch NUMBER and a SEMANTICS DIGEST over the rule's
// declared matching inputs, and a mismatch in either makes it stale.
//
// The digest is the enforcement. It is computed from data, so an author who
// changes what a rule matches on and forgets to bump the epoch STILL cannot keep
// an old suppression alive -- the digest moved, so every bound record reads
// stale. Nothing here depends on a human remembering.
//
// The epoch number is the explanation. "Epoch 2" is what an operator sees and
// what a changelog can describe; a bare digest change tells them only that
// something moved. TestBuiltInEpochsMatchTheGoldenHistory makes forgetting the
// bump a test failure with the exact edit spelled out, because a comment asking
// rule authors to remember is the weakest possible control.
//
// Severity and wording changes do not belong in Inputs and so do not bump the
// epoch (spec §12): re-alerting on every reworded summary would train operators
// to re-adjudicate without reading, which is the same as no adjudication at all.
package adjudicate

import (
	"errors"
	"fmt"
	"sort"

	"github.com/lookatitude/aurvet/internal/baseline"
)

// EpochGoldenSchema versions testdata/adjudicate/epochs.golden.json.
const EpochGoldenSchema = 1

// ErrEpoch reports a malformed epoch declaration or an undeclared rule.
var ErrEpoch = errors.New("adjudicate: fingerprint epoch")

// Semantics declares what one rule MATCHES ON, and at which epoch.
//
// Inputs names the inputs whose change alters which subjects the rule fires on:
// the data compared, the sets consulted, the thresholds applied. It is a
// declaration of record, not a copy of the values -- an entry reads "AUR RPC
// Maintainer field emptiness", never the current maintainer list.
//
// Inputs is deliberately NOT the rule's prose description. A reworded summary
// must not bump an epoch, and a widened pattern must. Anything in Inputs that
// does not change what the rule matches is a source of spurious staleness, and
// spurious staleness is how operators learn to re-adjudicate reflexively.
type Semantics struct {
	RuleID string
	Epoch  int
	Inputs []string
}

// Digest is the hex sha256 over the canonical form of the declaration.
//
// Two deliberate exclusions. The epoch NUMBER is not covered: a bump must be
// distinguishable from a semantics change, since the two mean different things
// to an operator reading a stale record. Input ORDER is not covered either --
// the list is sorted first -- because reordering a list is not a semantic
// change and must not invalidate anyone's judgement.
//
// A declaration with no inputs is refused rather than digested. "This rule
// matches on nothing" is never true, so an empty list means the author has not
// declared anything yet, and hashing it would produce a stable-looking constant
// that pins nothing at all.
func (s Semantics) Digest() (string, error) {
	if s.RuleID == "" {
		return "", fmt.Errorf("%w: a declaration with no rule id", ErrEpoch)
	}
	if len(s.Inputs) == 0 {
		return "", fmt.Errorf("%w: rule %q declares no matching inputs, so there is nothing to "+
			"pin an epoch against", ErrEpoch, s.RuleID)
	}
	inputs := make([]string, 0, len(s.Inputs))
	for _, in := range s.Inputs {
		if in == "" {
			return "", fmt.Errorf("%w: rule %q declares an empty matching input", ErrEpoch, s.RuleID)
		}
		inputs = append(inputs, in)
	}
	sort.Strings(inputs)
	d, err := baseline.Digest(struct {
		RuleID string   `json:"rule_id"`
		Inputs []string `json:"inputs"`
	}{RuleID: s.RuleID, Inputs: inputs})
	if err != nil {
		return "", err
	}
	return baseline.Hex(d[:]), nil
}

// Registry is the set of epoch declarations in force for one run.
//
// The zero value declares nothing, which is the correct default: with no
// declarations, no record can be confirmed current, so every record reads stale
// and nothing suppresses. Fail closed.
type Registry struct {
	byRule map[string]Semantics
}

// NewRegistry validates and freezes a set of declarations. A duplicate rule id,
// an epoch below 1 or an undeclared input list is an error rather than a
// last-writer-wins merge: two declarations for one rule means two answers to
// "are these semantics current", and the one that answers "yes" is the one an
// attacker wants.
func NewRegistry(decls ...Semantics) (Registry, error) {
	r := Registry{byRule: make(map[string]Semantics, len(decls))}
	for _, s := range decls {
		if s.Epoch < 1 {
			return Registry{}, fmt.Errorf("%w: rule %q declares epoch %d; epochs start at 1",
				ErrEpoch, s.RuleID, s.Epoch)
		}
		if _, err := s.Digest(); err != nil {
			return Registry{}, err
		}
		if _, dup := r.byRule[s.RuleID]; dup {
			return Registry{}, fmt.Errorf("%w: rule %q is declared twice", ErrEpoch, s.RuleID)
		}
		s.Inputs = append([]string(nil), s.Inputs...)
		r.byRule[s.RuleID] = s
	}
	return r, nil
}

// Lookup reports the declaration in force for a rule.
func (r Registry) Lookup(ruleID string) (Semantics, bool) {
	s, ok := r.byRule[ruleID]
	return s, ok
}

// All returns the declarations sorted by rule id.
func (r Registry) All() []Semantics {
	out := make([]Semantics, 0, len(r.byRule))
	for _, s := range r.byRule {
		out = append(out, Semantics{RuleID: s.RuleID, Epoch: s.Epoch,
			Inputs: append([]string(nil), s.Inputs...)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RuleID < out[j].RuleID })
	return out
}

// Len reports how many rules declare an epoch.
func (r Registry) Len() int { return len(r.byRule) }

// Undeclared returns, sorted, those rule ids that declare no epoch. A caller
// holding a finding list can report exactly which findings are not adjudicable
// yet, which is better than discovering it one refusal at a time.
func (r Registry) Undeclared(ruleIDs []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, id := range ruleIDs {
		if _, ok := r.byRule[id]; ok || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// builtIn is the declaration of record for the compiled rules whose findings can
// be adjudicated today.
//
// It is deliberately INCOMPLETE, and the incompleteness fails closed: a rule
// absent from this table cannot be adjudicated at all (New refuses, naming the
// file to edit), and a stored record naming an absent rule reads stale rather
// than active. So the cost of an omission is a visible refusal, never a silent
// suppression.
//
// Adding a rule here is one entry plus one line in
// testdata/adjudicate/epochs.golden.json. The longer-term shape is for each rule
// to declare its own epoch beside its own matching code and register it, which
// removes this second place to update; see the receipt's followups.
var builtIn = []Semantics{
	{RuleID: "aur-absent", Epoch: 1, Inputs: []string{
		"AUR RPC package presence for the pkgbase",
		"foreign-package classification from the local pacman db",
	}},
	{RuleID: "aur-orphaned", Epoch: 1, Inputs: []string{
		"AUR RPC Maintainer field emptiness",
	}},
	{RuleID: "aur-provenance", Epoch: 1, Inputs: []string{
		"provenance snapshot digest set (PKGBUILD, .SRCINFO, .BUILDINFO, git anchor)",
		"approval store record for the pkgbase",
	}},
	{RuleID: "aur-submitter-mismatch", Epoch: 1, Inputs: []string{
		"AUR RPC Submitter field",
		"AUR RPC Maintainer field",
	}},
	{RuleID: "aur-tombstone", Epoch: 1, Inputs: []string{
		"AUR RPC package presence for the pkgbase",
		"local install record for the package",
		"corroborating pacman.log transaction",
	}},
	{RuleID: "hook-coverage", Epoch: 1, Inputs: []string{
		"pacman hook directory search path",
		"hook files parsed versus hook files unparseable",
	}},
	{RuleID: "integrity-coverage", Epoch: 1, Inputs: []string{
		"packages with a readable mtree",
		"packages whose mtree could not be read",
	}},
	{RuleID: "integrity-digest-mismatch", Epoch: 1, Inputs: []string{
		"recorded mtree sha256 per packaged file",
		"observed file digest",
		"%BACKUP% exemption set",
		"pacman hook Exec output-literal exemption set",
		"exemption refusal for entries the package records as executable",
	}},
	{RuleID: "integrity-link-target", Epoch: 1, Inputs: []string{
		"recorded mtree link target",
		"observed symlink target",
	}},
	{RuleID: "integrity-missing", Epoch: 1, Inputs: []string{
		"recorded mtree entry per package",
		"presence of the recorded path on the filesystem",
	}},
	{RuleID: "integrity-unowned-setuid", Epoch: 1, Inputs: []string{
		"observed setuid and setgid mode bits",
		"alpm file-ownership index",
	}},
	{RuleID: "local-db", Epoch: 1, Inputs: []string{
		"local pacman db record parse outcome",
		"db.lck presence",
	}},
	// P1-C surfaces and correlation. These are declared because they are
	// SCAN-reachable, which makes them a precondition for P4 task 7 rather than a
	// nicety: `baseline init` refuses to write while unresolved criticals exist
	// and requires each to be adjudicated, so a scan-reachable rule with no
	// declared epoch is a critical the operator is told to adjudicate and then
	// refused permission to adjudicate. correlated-cluster is the one that makes
	// that concrete -- it is the only rule in P1-C that reaches critical at all.
	{RuleID: "correlated-cluster", Epoch: 1, Inputs: []string{
		"fact families contributing to the cluster",
		"strong-attribution candidates (temporal key, path-name key)",
		"masquerade set: members unowned inside a package-owned directory",
		"administrator-territory allowlist",
		"temporal window (DefaultWindow)",
	}},
	{RuleID: "correlate-coverage", Epoch: 1, Inputs: []string{
		"repository name set supplied to the correlator",
		"member mtime readability",
		"foreign-package %INSTALLDATE% availability",
	}},
	// Epoch 2: a bare command that resolves to nothing no longer reaches this
	// rule at all. It used to fall through to unit-coverage; it is now
	// unit-execstart-hijackable, and the `-` (ignore-failure) prefix on such a
	// command suppresses both. What this rule matches -- a command that DOES
	// resolve, including a `-`-prefixed one -- is unchanged in shape but no
	// longer shares an input with the unresolved case.
	{RuleID: "unit-execstart-unowned", Epoch: 2, Inputs: []string{
		"unit search path and drop-in resolution",
		"ExecStart command extraction and interpreter handling",
		"bare-command resolution against systemd's search path",
		"the `-` ignore-failure prefix, which does NOT exempt a command that resolves",
		"ownership verdict for the resolved command",
		"presence of the resolved command (absent is info, present is suspicious)",
	}},
	// Epoch 1: new rule. A bare command resolving to no file in systemd's search
	// path is a determinate answer, not an inability to look, so it is a finding
	// rather than the coverage gap it used to be.
	{RuleID: "unit-execstart-hijackable", Epoch: 1, Inputs: []string{
		"bare (non-path) Exec command extraction",
		"systemd's compiled-in search path and its order",
		"absence of the name from every search-path directory",
		"the `-` ignore-failure prefix, which suppresses this rule entirely",
		"the winning directory: first search-path entry present in the root",
		"the winning directory's permission bits (group- or world-writable is suspicious, else info)",
	}},
	// Epoch 2: two shapes left this rule. A bare command absent from the search
	// path is now a finding, and a `-`-prefixed absent bare command is neither a
	// gap nor a finding -- the unit's own author declared it optional. What
	// remains is what "the check could not run" should always have meant.
	{RuleID: "unit-coverage", Epoch: 2, Inputs: []string{
		"unit files parsed versus unit files unparseable",
		"unit directory readability",
		"Exec values naming no concrete file (specifier, variable, empty value)",
		"the `-` ignore-failure prefix on an unresolved bare command, which is not a gap",
		"unresolved bare commands, which are a finding rather than a gap",
	}},
	{RuleID: "wants-link-unowned-target", Epoch: 1, Inputs: []string{
		"enablement-link target resolution against the scanned root",
		"directory exclusion (behaviour 2)",
		"ownership verdict for the resolved target (behaviour 3)",
	}},
	{RuleID: "wants-coverage", Epoch: 1, Inputs: []string{
		"*.wants directory readability",
		"link targets whose ownership could not be determined",
	}},
	{RuleID: "hook-suppressed", Epoch: 1, Inputs: []string{
		"hook directory priority order",
		"same-name shadowing across directories",
		"/dev/null mask detection by link text",
		"ownership verdict for the winning hook file",
	}},
	{RuleID: "hook-unowned", Epoch: 1, Inputs: []string{
		"hook directory search path",
		"ownership verdict for the hook file",
		"whether the hook is itself shadowed (a hook pacman will not run)",
	}},
	{RuleID: "hook-dirs", Epoch: 1, Inputs: []string{
		"pacman.conf HookDir resolution, including Include expansion",
		"compiled-in system and admin hook directory defaults",
	}},
	{RuleID: "surface-preload-unowned", Epoch: 1, Inputs: []string{
		"ld.so.preload token extraction",
		"ownership verdict for each named object",
		"empty-file handling (an empty preload list is not a finding)",
	}},
	{RuleID: "surface-generator-unowned", Epoch: 1, Inputs: []string{
		"systemd generator directory set",
		"ownership verdict for each entry",
		"directory and owned-symlink-target exclusions",
	}},
	{RuleID: "surface-profiled-unowned", Epoch: 1, Inputs: []string{
		"profile.d directory set",
		"ownership verdict for each entry",
	}},
	{RuleID: "surface-autostart-unowned-exec", Epoch: 1, Inputs: []string{
		"system and per-user XDG autostart directory set",
		"per-user home enumeration from the target root's passwd",
		"Exec= program extraction and Hidden=true handling",
		"ownership verdict for the resolved program",
	}},
	{RuleID: "surface-misc-coverage", Epoch: 1, Inputs: []string{
		"passwd readability and parse outcome",
		"home directory readability (absent is not a gap, unreadable is)",
		"surface directory readability",
	}},
	{RuleID: "sync-coverage", Epoch: 1, Inputs: []string{
		"sync db presence per configured repository",
		"sync db freshness timestamp",
	}},
	// P4 drift. This is the third instance of the same cross-phase deadlock:
	// a critical from a rule that declares no epoch is one the operator is told
	// to adjudicate and then refused permission to adjudicate. Drift criticals
	// are the ones an operator is MOST likely to need to adjudicate -- an
	// expected out-of-band change is routine -- so leaving this undeclared
	// would have made the adjudication route useless exactly where it matters.
	// Declared here rather than in internal/baseline because baseline must not
	// import adjudicate (adjudicate imports baseline).
	{RuleID: "baseline-drift", Epoch: 1, Inputs: []string{
		"signed baseline manifest package set (name, version, mtree sha256)",
		"observed package set from the local pacman db",
		"pacman.log transaction set inside the log's coverage",
		"log coverage window versus the baseline's recorded earliest timestamp",
		"%INSTALLDATE% per package, where present",
	}},
}

// BuiltIn returns the compiled epoch declarations. It panics only on a
// programming error in the table above, which a test catches long before a
// release.
func BuiltIn() Registry {
	r, err := NewRegistry(builtIn...)
	if err != nil {
		panic("adjudicate: built-in epoch table is invalid: " + err.Error())
	}
	return r
}
