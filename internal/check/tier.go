// internal/check/tier.go
//
// The four verification tiers, and the translation of phase 1's evidence into
// the observations integrity.go compares.
//
// The tiers exist because verifying every digest on the reference system means
// reading 19.8 GiB. That cost is worth paying by default -- `full` is the
// default and hashes everything covered by a recorded digest -- but a scheduled
// hourly run and an interactive triage want different bargains, and a tier the
// operator chooses is honest in a way that a silently sampled scan is not: the
// weaker tiers report their own blindness as coverage gaps rather than as
// silence (INV-3).
//
// NOTHING IN THIS FILE PERFORMS I/O, and that is spec §11.1 rather than a style
// preference. A tier is a decision about how much to read, and after the
// capability drop this process can read nothing a normal user cannot, so the
// decision has to be made while the capability is held -- in internal/collect,
// from the paths the local database records. CollectPolicy is that decision
// travelling to phase 1; Observe is phase 1's answer coming back.
package check

import (
	"errors"
	"fmt"
	"strings"

	"github.com/lookatitude/aurvet/internal/collect"
	"github.com/lookatitude/aurvet/internal/mtree"
	"github.com/lookatitude/aurvet/internal/safe"
)

// Tier selects how much work one verification pass does.
type Tier int

const (
	// TierMeta reads no file contents at all. Each recorded path is still
	// opened once, confined, and fstat'd -- so a missing file, a swapped
	// symlink and a fifo are all still established from a descriptor -- but
	// nothing is hashed. Every observation is mtime-assisted by construction.
	TierMeta Tier = iota

	// TierTriage hashes the security-relevant subset and nothing else:
	// everything the DESCRIPTOR'S OWN MODE says decides what runs -- executable,
	// setuid, setgid, sticky -- plus everything under a watched path (unit
	// directories, pacman hook directories, profile.d, ld.so.preload). Symlink
	// targets come free from a readlink. Every other recorded path is opened,
	// fstat'd and left unread.
	//
	// The subset is decided in phase 1, from the fstat of the descriptor that
	// would be hashed, because after the capability drop this process cannot
	// read a root-only file at all. That makes it strictly stronger than keying
	// on the mode a package RECORDED: the recorded mode is what the package
	// claims, the descriptor's mode is what the kernel honours when something
	// executes the file, and a file made executable after installation is
	// exactly the case worth reading.
	//
	// WHAT TRIAGE CANNOT SEE, stated because it is a real weakening and §13's
	// own "triage is reassurance, not verification" is the reason it is
	// acceptable rather than an excuse for leaving it unsaid: a file OUTSIDE the
	// security-relevant subset whose contents changed while its size stayed the
	// same is not detected, whatever its mtime says. Only tier full hashes it.
	// This blindness is reported as an integrity-coverage gap on every run, so
	// it reaches the operator rather than only the reader of this comment.
	TierTriage

	// TierFull hashes every path with a recorded digest, skipping only the
	// derived exemptions. This is the default.
	TierFull

	// TierParanoid additionally compares the exempt paths, so the exemption set
	// itself can be audited rather than trusted, and adds the metadata-only
	// sweep of the watched trees that UnownedSUID needs. Spec §13 assigns both
	// the unowned walk and the SUID sweep to this tier and to no other, so
	// integrity-unowned-setuid CANNOT FIRE below it -- see UnownedSUID.
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

// CollectPolicy is the hashing policy this tier requires of phase 1.
//
// It exists because a tier's hash set MUST be decidable while the read
// capability is still held. After the drop the process holds nothing, so a
// phase-2 decision to read a root-only file is a decision that fails; a tier
// that made one would be strictly weaker than it looks, which is the
// manufactured confidence this project exists to avoid.
func (t Tier) CollectPolicy() collect.RecordedPolicy {
	switch t {
	case TierMeta:
		return collect.RecordedStat
	case TierTriage:
		return collect.RecordedSecurity
	default: // TierFull, TierParanoid
		return collect.RecordedAll
	}
}

// errRecordKind reports that the object standing at a recorded path is not the
// kind of thing a digest can be taken from.
var errRecordKind = errors.New("recorded path is not a regular file")

// beforeObserveForTest runs at the top of observe. Production leaves it nil;
// tier_test.go sets it to raise a panic from inside the observation of one
// specific path, which is the only way to prove containment works from outside.
var beforeObserveForTest func(path string)

// Observe joins one package's mtree records to the evidence phase 1 gathered and
// returns what was observed, keyed by the recorded path.
//
// It performs NO I/O. Everything it reports comes from the descriptor
// internal/collect opened once, confined, with O_NOFOLLOW, and fstat'd -- the
// digest, the mode, the size and the link target are all statements about that
// one descriptor rather than about a path resolved twice.
//
// A recorded path with no evidence is simply absent from the result. Integrity
// turns that into a coverage gap naming the package, which is the honest
// statement: the scan produced no observation, so nothing can be said.
//
// Observe is a pure function of (entries, files, exemptions): no ambient paths,
// no process state, no network (INV-4). It never resolves a symlink; a link
// entry's target is compared as a string, because 4,145 legitimate targets on
// the reference system contain "..".
func (t Tier) Observe(entries []mtree.Entry, files map[string]collect.File, ex Exemptions) map[string]Observed {
	obs := make(map[string]Observed, len(entries))
	for _, e := range entries {
		if e.Type == "dir" {
			continue
		}
		f, ok := files[e.Path]
		if !ok {
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
			o = t.observe(e, f, ex)
			return nil
		})
		if err != nil {
			o = unreadable(Observed{Path: e.Path}, err)
		}
		obs[e.Path] = o
	}
	return obs
}

// observe translates one file's evidence into an observation about one record.
func (t Tier) observe(e mtree.Entry, f collect.File, ex Exemptions) Observed {
	if beforeObserveForTest != nil {
		beforeObserveForTest(e.Path)
	}
	o := Observed{Path: e.Path}

	// An exempt path is compared at no tier below paranoid: pacman rewrites it,
	// so the answer is known useless. Phase 1 hashed it anyway -- exemptions are
	// derived from PARSED hooks and are not available while the capability is
	// held -- which costs 321 files and 1.3 MiB on the reference system and buys
	// the property that phase 1 hashes and phase 2 alone decides what a mismatch
	// means. A link is never exempt: comparing a target costs no read.
	if e.Type != "link" && t != TierParanoid {
		if _, ok := ex.Applies(e); ok {
			o.Kind = ObsExempt
			return o
		}
	}

	switch f.Kind {
	case collect.KindFile:
		o.Mode, o.Size = f.Mode, f.Size
		if f.SHA256 != "" {
			o.Kind, o.SHA256 = ObsHashed, f.SHA256
			return o
		}
		// Opened and fstat'd, never read. Any verdict resting on this rests on
		// size and mode, both of which anyone who can write the file can set.
		o.Kind, o.MtimeAssisted = ObsMetadataOnly, true
		return o

	case collect.KindLink:
		o.Kind, o.Link = ObsLink, f.Link
		return o

	case collect.KindAbsent:
		o.Kind = ObsMissing
		return o

	case collect.KindUnread:
		// The collector already raised a gap naming this subject; Gapped says
		// so, so Integrity states the one shortfall once instead of twice.
		o = unreadable(o, errors.New(f.Unread))
		o.Gapped = true
		return o
	}

	// KindDir or KindOther: a fifo, socket, device or directory stands where a
	// regular file was recorded. Refused after the fstat of the descriptor, so
	// this is a definite answer and not a guess -- but it is not a digest, and it
	// is not an accusation either.
	return unreadable(o, fmt.Errorf("%w: it is a %s", errRecordKind, f.Kind))
}

// unreadable attributes a refusal to the observation. Kind is set to
// ObsUnreadable so integrity.go turns it into a gap and never into a finding
// (INV-9): a file we could not examine is a hole in coverage, not an accusation.
func unreadable(o Observed, err error) Observed {
	o.Kind, o.Err = ObsUnreadable, err
	return o
}
