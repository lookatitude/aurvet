// internal/bundle/verify.go
//
// The whole verification pipeline, and the three fail-closed paths.
//
// # Order
//
//	root set present -> delegation signatures (2-of-3, distinct) -> parse
//	delegation -> retirement -> delegation window -> select online keys ->
//	bundle signature over RAW bytes -> canonicalise -> declarative admission ->
//	parse bundle -> anti-rollback floor -> prev_digest linkage -> indicator
//	count -> expiry
//
// Nothing below a step may assume anything a step above has not established.
// The single most important consequence: no JSON parser in this package ever
// sees a byte that a trusted key has not already vouched for.
//
// # The three fail-closed paths are different, deliberately
//
//	StateRefused      the document is not trustworthy. Do not use it. The
//	                  operator is told why.
//	StateExpired      the document is trustworthy but STALE. Indicators are
//	                  still consulted -- discarding them would make the tool
//	                  worse at exactly the moment its data is oldest -- but
//	                  coverage is incomplete and the run must never report
//	                  clean. This is INV-9's shape and exit 3's meaning.
//	StateUnavailable  there is no bundle. Not expired, not clean, not an error:
//	                  its own state (INV-10).
//
// None of the three may be rendered as "no indicator findings, so you are
// fine". A caller that prints a clean bill of health without consulting
// State.CoverageComplete is reporting clean for something it did not examine
// (INV-3).
//
// # Freeze
//
// An attacker who simply stops serving updates holds a client at a
// stale-but-valid bundle forever. No signature notices; the version floor does
// not notice (nothing went backwards); prev_digest does not notice (nothing was
// forked). What DOES notice, in order of reliability:
//
//  1. valid_until. This is the real bound. A freeze becomes an expiry within at
//     most one bundle lifetime, and expiry degrades coverage. It is why
//     valid_until is mandatory and why an infinite one is not spellable.
//  2. the delegation's own expiry, likewise.
//  3. the silence check below, which fires when nothing new has been ACCEPTED
//     for longer than MaxSilence even though checks have been happening. This
//     is a hint, not a detection: it cannot distinguish an attacker withholding
//     updates from a publisher who published nothing. It says so in the gap
//     text rather than implying more than it knows.
//
// What nothing here detects: a freeze shorter than the bundle's remaining
// validity. Inside that window a withheld update is indistinguishable from no
// update. The operator's control is out-of-band -- compare the bundle version
// printed by `--version` against the published one.
package bundle

import (
	"fmt"
	"time"

	"github.com/lookatitude/aurvet/internal/baseline"
	"github.com/lookatitude/aurvet/internal/finding"
)

// GapRule is the rule id every coverage gap from this package carries.
const GapRule = "bundle.coverage"

// DefaultMaxSilence is how long an unchanged bundle goes unremarked. Two weeks:
// long enough that a quiet fortnight from the publisher is not noise, short
// enough that a sustained freeze is visible well inside a typical valid_until.
const DefaultMaxSilence = 14 * 24 * time.Hour

// State is the bundle subsystem's coverage state.
type State int

const (
	// StateUnavailable: no bundle was supplied. INV-10.
	StateUnavailable State = iota

	// StateRefused: a bundle was supplied and is not trustworthy.
	StateRefused

	// StateExpired: trustworthy but past valid_until.
	StateExpired

	// StateActive: trustworthy and current.
	StateActive
)

func (s State) String() string {
	switch s {
	case StateActive:
		return "active"
	case StateExpired:
		return "expired"
	case StateRefused:
		return "refused"
	default:
		return "unavailable"
	}
}

// UsableIndicators reports whether the parsed indicators may be matched against.
// True for expired: stale data still finds known-bad things, and throwing it
// away would be a second failure on top of the staleness.
func (s State) UsableIndicators() bool { return s == StateActive || s == StateExpired }

// CoverageComplete reports whether indicator coverage was complete. False for
// every state but StateActive. A caller must consult this before saying
// anything resembling "clean".
func (s State) CoverageComplete() bool { return s == StateActive }

// Input is everything Verify is allowed to look at. Now is a parameter, never a
// clock read, so a verification is reproducible and testable at any instant.
type Input struct {
	Roots RootSet

	// DelegationRaw and DelegationSigs are the bytes as received. Verify does
	// not fetch and does not canonicalise before authenticating.
	DelegationRaw  []byte
	DelegationSigs [][]byte

	BundleRaw []byte
	BundleSig []byte

	// Floor is the root-only anti-rollback state. FloorPresent is false on a
	// first run; a false FloorPresent must come from FloorStore.Load reporting
	// absence, never from an error it swallowed.
	Floor        Floor
	FloorPresent bool

	Now time.Time

	// MaxSilence is the freeze hint's threshold. Zero means DefaultMaxSilence.
	MaxSilence time.Duration
}

// Status is what Verify established, and what it could not.
type Status struct {
	State State

	// Refusal is non-empty exactly when State is StateRefused, and says what an
	// operator should do about it.
	Refusal string

	// UpgradeMessage is the publisher's actionable text on a retired root set.
	UpgradeMessage string

	// Bundle and Digest are populated only when the bundle authenticated. An
	// unauthenticated document is never handed back: a caller cannot act on
	// what it was not given.
	Bundle *Bundle
	Digest string

	BundleVersion int64
	Coverage      Coverage

	RootGeneration   int
	RootFingerprints []string
	DelegationSerial int64
	DelegationExpiry string

	// Gaps are the coverage statements. Never empty unless State is
	// StateActive.
	Gaps []finding.Gap

	// Limits is INV-6.
	Limits string

	// NextFloor is what the caller should persist when FloorAdvances is true.
	// Verify performs no I/O: deciding and writing are separated so an offline
	// or read-only run can verify without touching the disk (INV-5).
	NextFloor     Floor
	FloorAdvances bool
}

func (st *Status) gap(subject, reason string) {
	st.Gaps = append(st.Gaps, finding.Gap{RuleID: GapRule, Subject: subject, Reason: reason})
}

func (st *Status) refuse(subject, format string, args ...any) Status {
	st.State = StateRefused
	st.Refusal = fmt.Sprintf(format, args...)
	st.gap(subject, st.Refusal)
	return *st
}

// Verify runs the pipeline. It performs no I/O and reads no clock.
//
// Every adversarial outcome is a Status, not an error: a refusal is a result the
// caller must report, and returning it as an error invites a caller to log it
// and carry on as though coverage were fine.
func Verify(in Input) Status {
	st := Status{
		Limits:           LimitsText,
		RootGeneration:   in.Roots.Generation(),
		RootFingerprints: in.Roots.Fingerprints(),
	}

	if in.Roots.Empty() {
		return st.refuse("root-key-set", "%s", noRootKeysMessage)
	}
	if soft := in.Roots.SoftwareKeys(); len(soft) > 0 {
		st.gap("root-key-set", fmt.Sprintf("%d of this build's %d root keys are software keys "+
			"(%v), not hardware-held; a copied root key is indistinguishable from the real one",
			len(soft), in.Roots.Size(), soft))
	}

	if len(in.BundleRaw) == 0 && len(in.DelegationRaw) == 0 {
		st.State = StateUnavailable
		st.gap("indicator-bundle", "no indicator bundle is cached, so nothing was checked "+
			"against the indicator set. This is neither an expired bundle nor a clean result: run "+
			"`aurvet update` to fetch one.")
		st.freezeHint(in)
		return st
	}
	if len(in.DelegationRaw) == 0 {
		return st.refuse("delegation", "a bundle is present but the root-signed delegation is "+
			"not, so there is nothing that says which online key may sign it")
	}

	// -- delegation, authenticated before parsed ---------------------------
	del, _, err := VerifyDelegation(in.DelegationRaw, in.DelegationSigs, in.Roots)
	if err != nil {
		return st.refuse("delegation", "the delegation does not verify against this build's "+
			"root key set: %v", err)
	}
	st.DelegationSerial = del.Serial
	st.DelegationExpiry = del.ValidUntil

	if in.FloorPresent && del.Serial < in.Floor.MinDelegationSerial {
		return st.refuse("delegation", "delegation serial %d is below the %d already seen on "+
			"this host; a superseded delegation keeps valid root signatures forever and replaying "+
			"one reinstates a rotated-out online key", del.Serial, in.Floor.MinDelegationSerial)
	}

	if del.RootSetRetired {
		st.UpgradeMessage = del.UpgradeMessage
		return st.refuse("root-key-set", "this build's root key set (generation %d, %v) has been "+
			"retired by its own holders and no bundle signed under it will be consulted. %s",
			in.Roots.Generation(), in.Roots.Fingerprints(), del.UpgradeMessage)
	}
	if del.Expired(in.Now) {
		return st.refuse("delegation", "the delegation expired at %s; no online key is currently "+
			"authorised to sign a bundle, so no bundle can be authenticated. Fetch a current "+
			"delegation with `aurvet update`.", del.ValidUntil)
	}

	online, excluded := del.ActiveKeys(in.Now)
	if len(online) == 0 {
		reason := "the delegation names no key whose window contains now"
		if len(excluded) > 0 {
			reason = fmt.Sprintf("%s: %v", reason, excluded)
		}
		return st.refuse("delegation", "%s", reason)
	}

	if len(in.BundleRaw) == 0 {
		st.State = StateUnavailable
		st.gap("indicator-bundle", "a valid delegation is cached but no bundle is; nothing was "+
			"checked against the indicator set")
		st.freezeHint(in)
		return st
	}

	// -- bundle: signature over RAW bytes, then and only then a parse -------
	b, canon, err := ParseBundle(in.BundleRaw, in.BundleSig, online)
	if err != nil {
		extra := ""
		if len(excluded) > 0 {
			extra = fmt.Sprintf(" (keys excluded by their window: %v)", excluded)
		}
		return st.refuse("indicator-bundle", "the bundle does not verify: %v%s", err, extra)
	}
	st.Bundle = b
	st.Digest = DigestOf(canon)
	st.BundleVersion = b.BundleVersion
	st.Coverage = b.Count()

	// -- anti-rollback -----------------------------------------------------
	if in.FloorPresent && in.Floor.MinBundleVersion > 0 {
		switch {
		case b.BundleVersion < in.Floor.MinBundleVersion:
			return st.refuse("indicator-bundle", "%v: bundle version %d is below the floor of %d "+
				"recorded in root-only state. Every signature on it may be perfectly valid; the "+
				"version is what says it is a replay of superseded data.",
				ErrRollback, b.BundleVersion, in.Floor.MinBundleVersion)

		case b.BundleVersion == in.Floor.MinBundleVersion:
			if st.Digest != in.Floor.HeadDigest {
				return st.refuse("indicator-bundle", "two different bundles claim version %d: this "+
					"one digests to %s, root-only state records %s. That is a fork, and a fork means "+
					"someone is being served a different indicator set from everyone else.",
					b.BundleVersion, short(st.Digest), short(in.Floor.HeadDigest))
			}

		case b.BundleVersion == in.Floor.MinBundleVersion+1:
			if b.PrevDigest != in.Floor.HeadDigest {
				return st.refuse("indicator-bundle", "bundle %d names predecessor %s, but the "+
					"bundle held here at version %d digests to %s. A wrong prev_digest is a fork.",
					b.BundleVersion, short(b.PrevDigest), in.Floor.MinBundleVersion,
					short(in.Floor.HeadDigest))
			}

		default:
			// Versions were skipped -- normal for a host that was offline across
			// two publications. The link cannot be checked, because this host
			// never held the intermediate bundles. Say so rather than pretend
			// either way (INV-6).
			st.gap("indicator-bundle", fmt.Sprintf("bundle %d follows %d here, so the "+
				"prev_digest links across versions %d-%d could not be checked: this host never "+
				"held those bundles. Signature, floor and expiry were checked.",
				b.BundleVersion, in.Floor.MinBundleVersion, in.Floor.MinBundleVersion+1,
				b.BundleVersion-1))
		}
	}

	// -- the count ---------------------------------------------------------
	if st.Coverage.Active == 0 {
		return st.refuse("indicator-bundle", "%v: bundle %d carries %d indicators this build can "+
			"act on. A signed bundle that removes detections is an attack, and a tool that "+
			"silently starts checking less is worse than one that stops.",
			ErrEmptyBundle, b.BundleVersion, st.Coverage.Active)
	}
	for _, inert := range st.Coverage.Inert {
		st.gap("indicator-bundle", inert+"; it is carried but not matched on")
	}
	if in.FloorPresent && in.Floor.IndicatorCount > st.Coverage.Active {
		st.gap("indicator-bundle", fmt.Sprintf("the active indicator count dropped from %d to "+
			"%d between bundle %d and %d. A drop is not automatically an attack -- indicators do "+
			"get retired -- but it is never routine, and the RULES-CHANGELOG should say why.",
			in.Floor.IndicatorCount, st.Coverage.Active, in.Floor.MinBundleVersion, b.BundleVersion))
	}

	// -- expiry ------------------------------------------------------------
	until, err := baseline.ParseStamp(b.ValidUntil)
	if err != nil {
		return st.refuse("indicator-bundle", "valid_until is unreadable: %v", err)
	}
	if !in.Now.Before(until) {
		st.State = StateExpired
		st.gap("indicator-bundle", fmt.Sprintf("the indicator bundle expired at %s. Its %d "+
			"indicators are still being matched -- stale data still finds known-bad things -- but "+
			"indicator coverage is INCOMPLETE and this run cannot report clean. Run `aurvet "+
			"update`.", b.ValidUntil, st.Coverage.Active))
		st.freezeHint(in)
		return st
	}

	st.State = StateActive
	st.freezeHint(in)
	if !in.FloorPresent || b.BundleVersion > in.Floor.MinBundleVersion ||
		del.Serial > in.Floor.MinDelegationSerial {
		st.FloorAdvances = true
		st.NextFloor = Floor{
			Schema:              FloorSchema,
			MinBundleVersion:    maxInt64(b.BundleVersion, in.Floor.MinBundleVersion),
			HeadDigest:          st.Digest,
			MinDelegationSerial: maxInt64(del.Serial, in.Floor.MinDelegationSerial),
			IndicatorCount:      st.Coverage.Active,
			RootGeneration:      in.Roots.Generation(),
			AcceptedAt:          stampOf(in.Now),
			CheckedAt:           stampOf(in.Now),
		}
	}
	// A gap-free StateActive is the only shape that permits a clean report.
	return st
}

// freezeHint adds the silence gap when nothing new has been accepted for a long
// time. It is explicitly a hint: see the file comment for what it cannot tell
// apart.
func (st *Status) freezeHint(in Input) {
	if !in.FloorPresent || in.Floor.AcceptedAt == "" {
		return
	}
	limit := in.MaxSilence
	if limit <= 0 {
		limit = DefaultMaxSilence
	}
	accepted, err := baseline.ParseStamp(in.Floor.AcceptedAt)
	if err != nil {
		return
	}
	age := in.Now.Sub(accepted)
	if age <= limit {
		return
	}
	checked := ""
	if in.Floor.CheckedAt != "" {
		if c, err := baseline.ParseStamp(in.Floor.CheckedAt); err == nil && c.After(accepted) {
			checked = fmt.Sprintf(" Updates have been checked as recently as %s, so the channel "+
				"is reachable and simply has nothing new.", in.Floor.CheckedAt)
		}
	}
	st.gap("indicator-bundle", fmt.Sprintf("no new indicator bundle has been accepted here since "+
		"%s (%d days).%s This cannot distinguish a publisher with nothing to say from an attacker "+
		"withholding updates; compare the version this build reports against the published one.",
		in.Floor.AcceptedAt, int(age.Hours()/24), checked))
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
