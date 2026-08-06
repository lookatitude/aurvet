// internal/bundle/delegation.go
//
// The delegation document: the ONE thing the offline root set signs.
//
// # Why a delegation exists at all
//
// The alternative is roots signing bundles directly, which means the hardware
// tokens come out for every publication -- so in practice they stop coming out,
// and the "offline" root becomes an online root with extra steps. A delegation
// names short-lived online signing keys with explicit windows, so routine
// publishing uses a key that is expected to be online and whose compromise is
// bounded in time by its own expiry rather than by anyone noticing.
//
// Rotating that online key therefore ships NO new binary: sign a new delegation
// offline, publish it, done. That property is the reason the online key is
// allowed to be short-lived at all.
//
// # Bundles cannot introduce keys; the delegation is the only place keys appear
//
// This file is the deliberate asymmetry to bundle.go's assertDeclarative, which
// refuses any key-bearing member name in a BUNDLE. A delegation carries keys and
// is signed by the offline roots; a bundle carries data and is signed by an
// online key the delegation named. If a bundle could name a key, an online key
// could name its own successor and the root set would be decorative -- the
// compromise would be permanent instead of expiring.
//
// # Counting signatures, not signature blobs
//
// The threshold is counted over DISTINCT root keys. One key signing the same
// bytes twice produces two valid signatures, and an implementation that counts
// blobs turns 2-of-3 into 1-of-3 for anyone holding a single key. There is an
// attack test for precisely this, and it is the mutation most likely to pass a
// happy-path suite unnoticed.
//
// # Retirement
//
// A root set is retired by the root set itself: a 2-of-3-signed delegation with
// root_set_retired set, no signing keys, and an upgrade message. That is the
// only announcement an old binary can authenticate, because the only keys it
// trusts are the ones being retired. It follows that a 2-of-3 root compromise
// can also brick clients -- but a 2-of-3 root compromise can already sign
// arbitrary delegations, so nothing is lost by admitting it. See
// docs/key-compromise-runbook.md.
package bundle

import (
	"errors"
	"fmt"
	"time"

	"github.com/lookatitude/aurvet/internal/baseline"
)

// MaxOnlineKeyLifetime is the hardest ceiling on an online signing key's window.
//
// The design calls for 30-90 days. Only the upper bound is a security property:
// a shorter-lived key is strictly safer, so 90 days is enforced and 30 is an
// operational target documented in the runbook rather than a rule here. A
// delegation naming a key with a multi-year window has given away the entire
// benefit of delegation, so it is refused outright rather than warned about.
const MaxOnlineKeyLifetime = 90 * 24 * time.Hour

// MaxDelegationLifetime bounds the delegation document itself. A delegation
// outliving every key it names is a document whose only remaining function is to
// be replayed.
const MaxDelegationLifetime = 365 * 24 * time.Hour

// MaxSigningKeys bounds how many online keys one delegation may name. Two is the
// working number (the outgoing key and the incoming one overlap during a
// rotation); four leaves room without letting a delegation become a keyring.
const MaxSigningKeys = 4

// MaxDelegationBytes caps a delegation document.
const MaxDelegationBytes = 64 << 10

var (
	// ErrDelegation reports a malformed delegation.
	ErrDelegation = errors.New("bundle: malformed delegation")

	// ErrThreshold reports too few DISTINCT root signatures.
	ErrThreshold = errors.New("bundle: delegation does not meet the root signing threshold")

	// ErrRootRetired reports a delegation that retires this build's root set.
	// It is a refusal with an operator-actionable message attached, never a
	// degraded mode: a retired root set means this binary's trust anchor is no
	// longer the publisher's, and continuing would be trusting a set the
	// publisher has disowned.
	ErrRootRetired = errors.New("bundle: this build's root key set has been retired")
)

// Delegation names the online bundle-signing keys.
type Delegation struct {
	SpecVersion int `json:"spec_version"`

	// RootGeneration is which root set signed this. A delegation for another
	// generation is not for this build, and is refused rather than ignored: it
	// is the difference between "I have no delegation" and "I have someone
	// else's".
	RootGeneration int `json:"root_generation"`

	// Serial is monotonic. It exists so a superseded delegation -- one whose
	// signatures are still perfectly valid -- cannot be replayed to reinstate a
	// retired online key. The floor stores the highest serial seen.
	Serial int64 `json:"serial"`

	IssuedAt   string `json:"issued_at"`
	ValidUntil string `json:"valid_until"`

	// SigningKeys is the only place in the whole format where key material
	// appears. Empty is legal exactly once: a retirement.
	SigningKeys []SigningKey `json:"signing_keys"`

	// RootSetRetired retires this build's root set. See the file comment.
	RootSetRetired bool `json:"root_set_retired"`

	// UpgradeMessage is what an operator is shown on retirement. Mandatory when
	// RootSetRetired is set, because "refuse" is only actionable if the person
	// reading it is told what to do.
	UpgradeMessage string `json:"upgrade_message"`
}

// SigningKey is one online bundle-signing key and its window.
type SigningKey struct {
	// PublicKey is an authorized_keys line: "ssh-ed25519 AAAA... comment".
	PublicKey string `json:"public_key"`

	NotBefore string `json:"not_before"`
	NotAfter  string `json:"not_after"`
}

// VerifyDelegation authenticates raw bytes against the root set and only then
// parses them.
//
// Same ordering discipline as ParseBundle, and for the same reason: the JSON
// parser must never see bytes that the root set has not already vouched for.
// The threshold is checked BEFORE parsing too -- a single valid signature is not
// enough to earn a parse.
func VerifyDelegation(raw []byte, sigs [][]byte, set RootSet) (*Delegation, []byte, error) {
	if set.Empty() {
		return nil, nil, fmt.Errorf("%w: %s", ErrNoRootKeys, noRootKeysMessage)
	}
	if len(raw) > MaxDelegationBytes {
		return nil, nil, fmt.Errorf("%w: %d bytes exceeds the %d byte cap",
			ErrDelegation, len(raw), MaxDelegationBytes)
	}
	if len(sigs) > set.Size() {
		return nil, nil, fmt.Errorf("%w: %d signatures for a set of %d; a pile of signatures is "+
			"not a threshold", ErrThreshold, len(sigs), set.Size())
	}

	trusted := set.keySlice()
	seen := make([]bool, set.Size())
	distinct := 0
	for i, sig := range sigs {
		key, err := baseline.Verify(sig, baseline.NamespaceDelegation, raw, trusted)
		if err != nil {
			// A bad signature among good ones is not tolerated and not merely
			// skipped. It is either corruption or an attempt, and neither is
			// something to shrug at while counting the others.
			return nil, nil, fmt.Errorf("%w: signature %d: %v", ErrThreshold, i, err)
		}
		idx := set.index(key)
		if idx < 0 {
			return nil, nil, fmt.Errorf("%w: signature %d verified against a key outside the set",
				ErrThreshold, i)
		}
		if seen[idx] {
			// Counting blobs instead of signers is how 2-of-3 silently becomes
			// 1-of-3.
			return nil, nil, fmt.Errorf("%w: %s signed twice; the threshold counts distinct "+
				"root keys, not signatures", ErrThreshold, key.Fingerprint())
		}
		seen[idx] = true
		distinct++
	}
	if distinct < set.Threshold() {
		return nil, nil, fmt.Errorf("%w: %d of %d distinct root keys, need %d",
			ErrThreshold, distinct, set.Size(), set.Threshold())
	}

	canon, err := baseline.Canonical(raw)
	if err != nil {
		return nil, nil, err
	}
	if string(canon) != string(raw) {
		return nil, nil, fmt.Errorf("%w: the signed bytes are validly signed but not canonical, "+
			"so their digest is not reproducible from the document", baseline.ErrNotCanonical)
	}

	d, err := decodeDelegation(canon)
	if err != nil {
		return nil, nil, err
	}
	if d.RootGeneration != set.Generation() {
		return nil, nil, fmt.Errorf("%w: delegation names root generation %d, this build embeds "+
			"generation %d", ErrDelegation, d.RootGeneration, set.Generation())
	}
	return d, canon, nil
}

func decodeDelegation(canon []byte) (*Delegation, error) {
	var d Delegation
	if err := decodeStrict(canon, &d); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDelegation, err)
	}
	again, err := baseline.Marshal(d)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDelegation, err)
	}
	if string(again) != string(canon) {
		return nil, fmt.Errorf("%w: the parsed delegation does not re-encode to the bytes that "+
			"were signed", ErrDelegation)
	}
	if err := ValidateDelegation(&d); err != nil {
		return nil, err
	}
	return &d, nil
}

// ValidateDelegation refuses a delegation that is malformed on its face. Expiry
// against a particular instant is Verify's job, not this function's -- nothing
// here reads a clock.
func ValidateDelegation(d *Delegation) error {
	if d.SpecVersion != SpecVersion {
		return fmt.Errorf("%w: spec_version %d, this build reads %d",
			ErrDelegation, d.SpecVersion, SpecVersion)
	}
	if d.RootGeneration < 1 {
		return fmt.Errorf("%w: root_generation %d", ErrDelegation, d.RootGeneration)
	}
	if d.Serial < 1 {
		return fmt.Errorf("%w: serial %d; serials start at 1", ErrDelegation, d.Serial)
	}
	issued, err := baseline.ParseStamp(d.IssuedAt)
	if err != nil {
		return fmt.Errorf("%w: issued_at: %v", ErrDelegation, err)
	}
	until, err := baseline.ParseStamp(d.ValidUntil)
	if err != nil {
		return fmt.Errorf("%w: valid_until: %v", ErrDelegation, err)
	}
	if !until.After(issued) {
		return fmt.Errorf("%w: valid_until %s is not after issued_at %s",
			ErrDelegation, d.ValidUntil, d.IssuedAt)
	}
	if until.Sub(issued) > MaxDelegationLifetime {
		return fmt.Errorf("%w: the delegation window is %s, over the %s ceiling",
			ErrDelegation, until.Sub(issued), MaxDelegationLifetime)
	}

	if d.RootSetRetired {
		if len(d.SigningKeys) != 0 {
			return fmt.Errorf("%w: a retirement names %d signing keys; a retired root set "+
				"delegates nothing", ErrDelegation, len(d.SigningKeys))
		}
		if len(d.UpgradeMessage) < 16 {
			return fmt.Errorf("%w: a retirement with no upgrade message is a refusal an "+
				"operator cannot act on", ErrDelegation)
		}
		return nil
	}
	if d.UpgradeMessage != "" {
		return fmt.Errorf("%w: upgrade_message is set on a delegation that does not retire the "+
			"root set", ErrDelegation)
	}
	if len(d.SigningKeys) == 0 {
		return fmt.Errorf("%w: no signing keys and no retirement; an empty delegation would "+
			"leave every bundle unverifiable for no stated reason", ErrDelegation)
	}
	if len(d.SigningKeys) > MaxSigningKeys {
		return fmt.Errorf("%w: %d signing keys, at most %d; a delegation is not a keyring",
			ErrDelegation, len(d.SigningKeys), MaxSigningKeys)
	}

	var prevFp string
	for i, sk := range d.SigningKeys {
		key, err := baseline.ParsePublicKey([]byte(sk.PublicKey))
		if err != nil {
			return fmt.Errorf("%w: signing_keys[%d]: %v", ErrDelegation, i, err)
		}
		nb, err := baseline.ParseStamp(sk.NotBefore)
		if err != nil {
			return fmt.Errorf("%w: signing_keys[%d].not_before: %v", ErrDelegation, i, err)
		}
		na, err := baseline.ParseStamp(sk.NotAfter)
		if err != nil {
			return fmt.Errorf("%w: signing_keys[%d].not_after: %v", ErrDelegation, i, err)
		}
		if !na.After(nb) {
			return fmt.Errorf("%w: signing_keys[%d] is valid until before it is valid from",
				ErrDelegation, i)
		}
		if na.Sub(nb) > MaxOnlineKeyLifetime {
			return fmt.Errorf("%w: signing_keys[%d] (%s) has a %s window, over the %s ceiling; "+
				"a long-lived online key gives away the point of delegating",
				ErrDelegation, i, key.Fingerprint(), na.Sub(nb), MaxOnlineKeyLifetime)
		}
		if na.After(until) {
			return fmt.Errorf("%w: signing_keys[%d] (%s) outlives the delegation that names it",
				ErrDelegation, i, key.Fingerprint())
		}
		// Sorted and unique by fingerprint, so one logical delegation has one
		// canonical spelling and a key cannot be listed twice with two windows.
		fp := key.Fingerprint()
		if i > 0 {
			if fp == prevFp {
				return fmt.Errorf("%w: %s is named twice", ErrDelegation, fp)
			}
			if fp < prevFp {
				return fmt.Errorf("%w: signing_keys is not sorted by fingerprint (%s follows %s)",
					ErrDelegation, fp, prevFp)
			}
		}
		prevFp = fp
	}
	return nil
}

// ActiveKeys returns the signing keys whose window contains now, plus the
// reasons any key was excluded.
//
// The reasons are returned rather than dropped: "the bundle is signed by a key
// that expired yesterday" and "the bundle is signed by a key nobody has ever
// heard of" are different situations for an operator, and a verifier that
// reports only "no valid signature" collapses them.
func (d *Delegation) ActiveKeys(now time.Time) ([]*baseline.PublicKey, []string) {
	var keys []*baseline.PublicKey
	var reasons []string
	for _, sk := range d.SigningKeys {
		key, err := baseline.ParsePublicKey([]byte(sk.PublicKey))
		if err != nil {
			continue // unreachable after ValidateDelegation; belt and braces
		}
		nb, err1 := baseline.ParseStamp(sk.NotBefore)
		na, err2 := baseline.ParseStamp(sk.NotAfter)
		if err1 != nil || err2 != nil {
			continue
		}
		switch {
		case now.Before(nb):
			reasons = append(reasons, fmt.Sprintf("signing key %s is not valid until %s",
				key.Fingerprint(), sk.NotBefore))
		case !now.Before(na):
			reasons = append(reasons, fmt.Sprintf("signing key %s expired at %s",
				key.Fingerprint(), sk.NotAfter))
		default:
			keys = append(keys, key)
		}
	}
	return keys, reasons
}

// Expired reports whether the delegation itself has expired at now.
func (d *Delegation) Expired(now time.Time) bool {
	until, err := baseline.ParseStamp(d.ValidUntil)
	if err != nil {
		return true // unparseable expiry is expired, never "no expiry"
	}
	return !now.Before(until)
}
