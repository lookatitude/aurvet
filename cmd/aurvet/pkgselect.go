// cmd/aurvet/pkgselect.go
//
// `--pkg N` (repeatable), spec §14's `[--pkg N]...`.
//
// An unknown name is exit 2 naming it, never an empty result: `--pkg zilb` that
// scanned nothing and exited 0 would be a false clean manufactured by a typo.
//
// The restriction lands on the ANALYSIS, between phase 1 and the analysers.
// Collection is NOT narrowed -- internal/collect takes no package filter -- so
// `--pkg` buys scope and not speed; narrowing the read needs a field in
// collect.Config, which is that package owner's call and not this lane's.
//
// The system-wide passes do not run under a restriction: the ownership oracle is
// then built from the named packages alone, so every other file on the system
// would read as owned by nobody and the checks keyed on that would accuse the
// whole filesystem. The scope line states the omission above the findings.
package main

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/lookatitude/aurvet/internal/alpm"
	"github.com/lookatitude/aurvet/internal/collect"
)

// errUnknownPackage is returned when --pkg names something the local database
// does not carry. runScan maps it to exit 2 (usage) rather than 3 (incomplete):
// nothing was left unexamined, the invocation was wrong.
var errUnknownPackage = errors.New("unknown package")

// pkgList is the repeatable --pkg flag. flag.Value rather than a comma-separated
// string because §14 spells it `[--pkg N]...` and because a package name may
// legitimately contain almost anything except a comma-free guarantee.
type pkgList []string

func (l *pkgList) String() string { return strings.Join(*l, ",") }

func (l *pkgList) Set(v string) error {
	v = strings.TrimSpace(v)
	if v == "" {
		return errors.New("an empty package name")
	}
	for _, existing := range *l {
		if existing == v {
			// Silently accepted duplicates would make the scope line lie about
			// how many packages were examined.
			return nil
		}
	}
	*l = append(*l, v)
	return nil
}

// restrictPackages reduces a loaded package set and phase 1's buffers to the
// named packages.
//
// Both halves have to be filtered together: d.pkgs is what the provenance sweep,
// the ownership oracle and the exemption derivation read, and raw.Packages is
// what verification parses mtrees from. Filtering one and not the other would
// verify packages nobody asked about, or ask about packages nothing verified.
func restrictPackages(d dbs, raw collect.Raw, only []string) (dbs, collect.Raw, error) {
	want := make(map[string]bool, len(only))
	for _, n := range only {
		want[n] = true
	}

	kept := make([]alpm.Package, 0, len(only))
	keepDir := make(map[string]bool, len(only))
	found := make(map[string]bool, len(only))
	for _, p := range d.pkgs {
		if !want[p.Name] {
			continue
		}
		found[p.Name] = true
		kept = append(kept, p)
		keepDir[p.Name+"-"+p.Version] = true
	}

	var missing []string
	for _, n := range only {
		if !found[n] {
			missing = append(missing, n)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return dbs{}, collect.Raw{}, fmt.Errorf("%w: %s is not installed on this root (--pkg takes "+
			"package names as the local database spells them; `pacman -Qq | grep` will find the one you "+
			"meant). Refusing to scan nothing and report it as clean",
			errUnknownPackage, strings.Join(missing, ", "))
	}

	d.pkgs = kept
	// The local-db and sync-coverage gaps stay: they describe the database this
	// restriction was applied to, and dropping them would hide a database that
	// could not be fully read behind a narrow question.
	pkgs := make([]collect.Package, 0, len(kept))
	for _, p := range raw.Packages {
		if keepDir[p.Dir] {
			pkgs = append(pkgs, p)
		}
	}
	raw.Packages = pkgs
	return d, raw, nil
}
