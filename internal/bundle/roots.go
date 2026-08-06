// internal/bundle/roots.go
//
// The embedded root key set.
//
// # What the root set is for, and what it deliberately cannot do
//
// The root set signs ONE kind of document: a delegation naming short-lived
// online bundle-signing keys (delegation.go). It never signs a bundle. That
// separation is what makes rotating the online key a publishing action rather
// than a release: the online key changes, a new delegation is signed offline,
// and no new binary ships.
//
// The threshold is 2-of-3 and the keys are held offline on hardware. Three so a
// lost key is recoverable without an emergency release; two so a single stolen
// key is not enough. The signatures are over the delegation's RAW bytes and are
// counted per DISTINCT key, because one key signing twice is one signature and
// an implementation that counts blobs rather than signers turns 2-of-3 into
// 1-of-3 (there is an attack test for exactly this).
//
// # There is no production key material in this repository
//
// Generating a release root key is a human action performed on hardware, off
// this machine, and it has not happened. embeddedRootKeys is therefore EMPTY,
// and that emptiness is a compiled-in refusal rather than a hole: EmbeddedRoots
// returns ErrNoRootKeys, Verify turns that into a refusal with a message an
// operator can act on, and no bundle is consumed. The failure mode this avoids
// is an empty trusted set that quietly verifies nothing, which is why
// baseline.Verify also treats an empty trusted set as a refusal.
//
// The seam is marked rather than stubbed: when the real set exists, its three
// authorized_keys lines replace the const below and the release gate checks
// EmbeddedRoots succeeds and reports three sk-ssh-ed25519 fingerprints. Nothing
// else in this file changes.
package bundle

import (
	"errors"
	"fmt"
	"strings"

	"github.com/lookatitude/aurvet/internal/baseline"
)

// RootThreshold and RootSetSize are the documented shape of the root set.
const (
	RootThreshold = 2
	RootSetSize   = 3
)

var (
	// ErrNoRootKeys reports a build with no embedded root set. It is a refusal,
	// never a permissive default.
	ErrNoRootKeys = errors.New("bundle: this build embeds no root keys")

	// ErrRootSet reports a malformed root set.
	ErrRootSet = errors.New("bundle: malformed root key set")
)

// embeddedRootKeys is the compiled-in root set, in authorized_keys format, one
// key per line. Comments (#) and blank lines are ignored.
//
// EMPTY BY DESIGN IN THIS BUILD. See the file comment: the production keys are
// human-gated hardware keys that do not exist yet, and a placeholder here would
// be indistinguishable from a real key to every reader and every test.
const embeddedRootKeys = ""

// noRootKeysMessage is what an operator sees. It says what is wrong, why it is
// refusing rather than continuing, and what would change it.
const noRootKeysMessage = "this build embeds no indicator-bundle root keys, so no bundle can be " +
	"authenticated and none will be consulted. This is a refusal, not a degraded mode: a build " +
	"with an empty trusted set would accept nothing safely and everything unsafely. Indicator " +
	"coverage is unavailable until you install a release build whose root set is populated; every " +
	"other subsystem (provenance, integrity, surfaces, baseline) is unaffected."

// RootSet is a threshold set of offline root public keys.
//
// The zero value is not usable: it has no keys and a zero threshold, and every
// method treats that as a refusal rather than as "no constraints".
type RootSet struct {
	generation int
	threshold  int
	keys       []*baseline.PublicKey
}

// NewRootSet builds a root set.
//
// It does NOT require hardware-backed keys, because the whole verification path
// has to be testable with software keys. parseRootSet, which is what the
// embedded production set goes through, does require them -- so the requirement
// is enforced on the path that carries real keys and tested there.
func NewRootSet(generation, threshold int, keys []*baseline.PublicKey) (RootSet, error) {
	if generation < 1 {
		return RootSet{}, fmt.Errorf("%w: generation %d; generations start at 1 so a zero "+
			"value cannot pass for one", ErrRootSet, generation)
	}
	if threshold < 2 {
		return RootSet{}, fmt.Errorf("%w: threshold %d; a threshold of one is a single point "+
			"of compromise and is refused", ErrRootSet, threshold)
	}
	if len(keys) < threshold {
		return RootSet{}, fmt.Errorf("%w: %d keys cannot satisfy a threshold of %d",
			ErrRootSet, len(keys), threshold)
	}
	seen := make([]*baseline.PublicKey, 0, len(keys))
	for i, k := range keys {
		if k == nil {
			return RootSet{}, fmt.Errorf("%w: key %d is nil", ErrRootSet, i)
		}
		for _, prev := range seen {
			if prev.Equal(k) {
				// One key listed twice would let a single holder reach the
				// threshold alone.
				return RootSet{}, fmt.Errorf("%w: %s appears twice", ErrRootSet, k.Fingerprint())
			}
		}
		seen = append(seen, k)
	}
	return RootSet{generation: generation, threshold: threshold, keys: seen}, nil
}

// EmbeddedRoots returns the root set compiled into this build.
//
// A build with no root keys is ErrNoRootKeys, wrapping noRootKeysMessage.
func EmbeddedRoots() (RootSet, error) {
	return parseRootSet(1, RootThreshold, embeddedRootKeys)
}

// parseRootSet parses authorized_keys lines into a root set and enforces the
// properties a PRODUCTION set must have: the documented size, and hardware
// backing on every key.
//
// Hardware backing is checked here and not in NewRootSet on purpose. INV-7 is
// meant to be satisfied by a token rather than by user discipline, and a root
// key that lives in a file on someone's laptop is the discipline version. Taking
// the string as a parameter is what makes the requirement testable without
// shipping a key.
func parseRootSet(generation, threshold int, text string) (RootSet, error) {
	var keys []*baseline.PublicKey
	for i, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, err := baseline.ParsePublicKey([]byte(line))
		if err != nil {
			return RootSet{}, fmt.Errorf("%w: line %d: %v", ErrRootSet, i+1, err)
		}
		if !k.HardwareBacked() {
			return RootSet{}, fmt.Errorf("%w: line %d (%s) is a %s key; a root key must be "+
				"hardware-held (sk-ssh-ed25519), because a root key in a file is a root key an "+
				"attacker can copy", ErrRootSet, i+1, k.Fingerprint(), k.Algorithm)
		}
		keys = append(keys, k)
	}
	if len(keys) == 0 {
		return RootSet{}, fmt.Errorf("%w: %s", ErrNoRootKeys, noRootKeysMessage)
	}
	if len(keys) != RootSetSize {
		return RootSet{}, fmt.Errorf("%w: %d keys; the documented root set is %d-of-%d",
			ErrRootSet, len(keys), RootThreshold, RootSetSize)
	}
	return NewRootSet(generation, threshold, keys)
}

// Generation is the root set's generation number. It increments on an
// out-of-band root rotation and is what a delegation names to say which set it
// was signed by; a delegation for another generation is not for this build.
func (r RootSet) Generation() int { return r.generation }

// Threshold is how many distinct root signatures a delegation needs.
func (r RootSet) Threshold() int { return r.threshold }

// Size is how many root keys are in the set.
func (r RootSet) Size() int { return len(r.keys) }

// Empty reports a set that cannot authenticate anything.
func (r RootSet) Empty() bool { return len(r.keys) == 0 || r.threshold < 2 }

// Fingerprints are the SSH fingerprints, for `--version` and for a runbook
// asking an operator to compare what their binary trusts against the published
// set. Reporting them is the only way an operator can tell two builds apart on
// the one property that matters.
func (r RootSet) Fingerprints() []string {
	out := make([]string, 0, len(r.keys))
	for _, k := range r.keys {
		out = append(out, k.Fingerprint())
	}
	return out
}

// SoftwareKeys are the fingerprints of any root key that is NOT hardware-backed.
// Empty for a production set. Reported rather than silently tolerated: a
// software root key is a real weakening of INV-7 and an operator is entitled to
// know their binary has one.
func (r RootSet) SoftwareKeys() []string {
	var out []string
	for _, k := range r.keys {
		if !k.HardwareBacked() {
			out = append(out, k.Fingerprint())
		}
	}
	return out
}

// keySlice copies the trusted keys out for baseline.Verify.
func (r RootSet) keySlice() []*baseline.PublicKey {
	return append([]*baseline.PublicKey(nil), r.keys...)
}

// index returns the position of k in the set, or -1. Used to count DISTINCT
// signers.
func (r RootSet) index(k *baseline.PublicKey) int {
	for i, have := range r.keys {
		if have.Equal(k) {
			return i
		}
	}
	return -1
}
