// internal/check/tier.go
//
// The four verification tiers, and the single confined pass over the filesystem
// that produces the observations integrity.go compares.
//
// The tiers exist because verifying every digest on the reference system means
// reading 19.8 GiB. That cost is worth paying by default -- `full` is the
// default and hashes everything covered by a recorded digest -- but a scheduled
// hourly run and an interactive triage want different bargains, and a tier the
// operator chooses is honest in a way that a silently sampled scan is not: the
// weaker tiers report their own blindness as coverage gaps rather than as
// silence (INV-3).
package check

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/lookatitude/aurvet/internal/fsx"
	"github.com/lookatitude/aurvet/internal/mtree"
	"github.com/lookatitude/aurvet/internal/safe"
	"golang.org/x/sys/unix"
)

// Tier selects how much work one verification pass does.
type Tier int

const (
	// TierMeta reads no file contents at all. Each recorded path is still
	// opened once, confined, and fstat'd -- so a missing file, a swapped
	// symlink and a fifo are all still established from a descriptor -- but
	// nothing is hashed. Every observation is mtime-assisted by construction.
	TierMeta Tier = iota

	// TierTriage hashes two populations: everything whose stat disagrees with
	// the record, and -- unconditionally, whatever stat says -- the
	// security-relevant subset. See Verify.
	TierTriage

	// TierFull hashes every path with a recorded digest, skipping only the
	// derived exemptions. This is the default.
	TierFull

	// TierParanoid additionally hashes the exempt paths, so the exemption set
	// itself can be audited rather than trusted.
	TierParanoid
)

// DefaultTier is the tier a scan runs at when the operator names none.
const DefaultTier = TierFull

// ErrUnknownTier reports an unrecognised tier name. An unknown tier is refused
// rather than silently defaulted: a typo in a systemd unit or a cron line must
// not quietly downgrade verification.
var ErrUnknownTier = errors.New("unknown verification tier")

// ParseTier maps a tier name to a Tier. The empty string is the default.
func ParseTier(s string) (Tier, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "":
		return DefaultTier, nil
	case "meta":
		return TierMeta, nil
	case "triage":
		return TierTriage, nil
	case "full":
		return TierFull, nil
	case "paranoid":
		return TierParanoid, nil
	}
	return DefaultTier, fmt.Errorf("%w: %q (want meta, triage, full or paranoid)", ErrUnknownTier, s)
}

func (t Tier) String() string {
	switch t {
	case TierMeta:
		return "meta"
	case TierTriage:
		return "triage"
	case TierFull:
		return "full"
	case TierParanoid:
		return "paranoid"
	}
	return "unknown"
}

// SecurityRelevant reports whether an entry is in the subset TierTriage hashes
// regardless of what stat says.
//
// The subset is derived from the record's own mode: anything executable, and
// anything carrying setuid, setgid or sticky. Those are the files whose contents
// decide what runs on the machine, which is exactly the population an attacker
// who can set mtime would want the prefilter to skip. Symlinks are included
// because comparing a link target costs a readlink and no read at all.
//
// Deliberately NOT part of the subset: everything under /etc. Configuration is
// the noisiest population on a real system (it is what %BACKUP% exists for), and
// pulling it in would spend the tier's whole budget on files whose difference
// says the least.
func SecurityRelevant(e mtree.Entry) bool {
	if e.Type == "link" {
		return true
	}
	return e.Mode&0o7111 != 0
}

// Verify performs one confined pass over the recorded entries and returns what
// it observed, keyed by the recorded path.
//
// Two properties are load-bearing and easy to lose:
//
//   - THE STAT COMES FROM THE DESCRIPTOR THAT WOULD BE HASHED. fsx.OpenConfined
//     opens once and fstats that fd; the triage prefilter then decides from that
//     stat. A prefilter that lstat'd the path and then opened it would reopen a
//     TOCTOU window fsx exists to close -- the attacker swaps the path between
//     the two resolutions and the scan reports on a file it never examined.
//   - THE SECURITY-RELEVANT SUBSET IS HASHED WHATEVER STAT SAYS. mtime and size
//     are writable by anyone who can write the file, so a prefilter that trusted
//     them to decide what to look at would be taking its instructions from the
//     attacker. Everything the prefilter DID decide is marked MtimeAssisted, so
//     no finding derived from it is ever presented as equally strong (INV-6).
//
// Verify is a pure function of (root, entries, exemptions): no ambient paths, no
// process state, no network (INV-4). It never resolves a symlink and never
// follows one; a link entry's target is read as a string and compared as one,
// because 4,145 legitimate targets on the reference system contain "..".
func (t Tier) Verify(root *os.Root, entries []mtree.Entry, ex Exemptions) map[string]Observed {
	obs := make(map[string]Observed, len(entries))
	for _, e := range entries {
		if e.Type == "dir" {
			continue
		}
		// Per-PATH containment (INV-9). One crafted record must cost one
		// coverage gap, not the rest of the scan: a tool that dies on the first
		// hostile input tells an attacker how to become invisible, because every
		// subject after the crash goes unexamined and the process that never
		// finished also never reported that it had not. The recover lives inside
		// safe.Run, at the top of the function that calls the closure, which is
		// the only place it works.
		var o Observed
		err, _ := safe.Run(e.Path, func() error {
			o = t.observe(root, e, ex)
			return nil
		})
		if err != nil {
			o = unreadable(Observed{Path: e.Path}, err)
		}
		obs[e.Path] = o
	}
	return obs
}

// beforeObserveForTest runs at the top of observe. Production leaves it nil;
// tier_test.go sets it to raise a panic from inside the observation of one
// specific path, which is the only way to prove containment works from outside.
var beforeObserveForTest func(path string)

// observe examines one entry.
func (t Tier) observe(root *os.Root, e mtree.Entry, ex Exemptions) Observed {
	if beforeObserveForTest != nil {
		beforeObserveForTest(e.Path)
	}
	o := Observed{Path: e.Path}

	if e.Type == "link" {
		target, err := fsx.ReadLinkConfined(root, e.Path)
		if err != nil {
			return unreadable(o, err)
		}
		o.Kind, o.Link = ObsLink, target
		return o
	}

	// An exempt path is not opened at all below paranoid: pacman rewrites it,
	// so reading it buys a known-useless answer at real I/O cost.
	if t != TierParanoid {
		if _, ok := ex.Applies(e); ok {
			o.Kind = ObsExempt
			return o
		}
	}

	f, st, err := fsx.OpenConfined(root, e.Path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			o.Kind = ObsMissing
			return o
		}
		return unreadable(o, err)
	}
	defer f.Close()

	o.Mode = uint32(st.Mode & 0o7777)
	o.Size = st.Size

	// The prefilter decision, taken from the fstat of the descriptor above and
	// from nothing else.
	hash, assisted := t.decide(e, st)
	o.MtimeAssisted = assisted
	if !hash {
		o.Kind = ObsMetadataOnly
		// Even a metadata-only observation owes the file the mutation check:
		// otherwise "size and mtime agreed" could be a statement about two
		// different generations of the file.
		if err := fsx.CheckUnchanged(f, st); err != nil {
			return unreadable(o, err)
		}
		return o
	}

	sum, _, err := fsx.Digest(f, st)
	if err != nil {
		// Includes fsx.ErrMutatedDuringScan: neither "matches" nor "does not
		// match", and reported as neither.
		return unreadable(o, err)
	}
	o.Kind, o.SHA256 = ObsHashed, sum
	return o
}

// decide reports whether to hash this entry, and whether stat participated in
// the decision.
func (t Tier) decide(e mtree.Entry, st unix.Stat_t) (hash, assisted bool) {
	switch t {
	case TierMeta:
		// Nothing is hashed, and every verdict rests on metadata.
		return false, true
	case TierTriage:
		if SecurityRelevant(e) {
			// Hashed whatever stat says, so no part of this verdict was
			// delegated to a field the attacker controls.
			return true, false
		}
		if statAgrees(e, st) {
			return false, true
		}
		return true, true
	default: // TierFull, TierParanoid
		return true, false
	}
}

// statAgrees reports whether the descriptor's own stat matches the record's size
// and mtime.
//
// mtime is compared at one-second granularity. mtree carries a fractional part
// (every one of the 461,601 time= values on the reference system does), but a
// package's recorded nanoseconds and the filesystem's are not reliably identical
// after a copy, and a prefilter that disagreed with every file would hash
// everything and stop being a tier. The imprecision is affordable precisely
// because it can only ever cause MORE hashing than necessary in the general
// case, and because the population where it could cause less -- the
// security-relevant subset -- is not subject to this test at all.
func statAgrees(e mtree.Entry, st unix.Stat_t) bool {
	if st.Size != e.Size {
		return false
	}
	return st.Mtim.Sec == int64(e.Time)
}

// unreadable attributes a refusal to the observation. Kind is set to
// ObsUnreadable so integrity.go turns it into a gap and never into a finding
// (INV-9): a file we could not examine is a hole in coverage, not an accusation.
func unreadable(o Observed, err error) Observed {
	o.Kind, o.Err = ObsUnreadable, err
	return o
}
