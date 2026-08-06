// Package bundle implements the indicator bundle: signed threat-intel DATA that
// a compiled rule consults.
//
// # Read the name before reading the code
//
// This is not a rules engine, and nothing here may grow into one. Every
// non-trivial detection decision in aurvet is compiled -- ownership resolution,
// host comparison, tombstone corroboration, correlation, symlink handling. What
// a bundle carries is the data those compiled rules look things up in: host
// lists, literal names, digests, integer thresholds, the rebuild-repo list.
//
// The reason is not taste. A network-delivered format that can express "do X
// then Y" is a remote code execution channel into a security tool that runs as
// root, and an updatable rule format is exactly that channel wearing a
// respectable name. So INV-1 is enforced structurally rather than promised in a
// comment:
//
//   - the document has a closed schema -- an unknown member is a refusal, not an
//     extension point (decodeStrict, plus the re-encode equality check);
//   - assertDeclarative refuses any member name from the executable or the
//     key-bearing denylists at any depth, so "script", "exec", "signing_keys"
//     and friends are named refusals with their own errors rather than fields
//     that merely happen not to be read today;
//   - there is no pattern language. Matching semantics are named by a
//     compiled-in enumeration (MatchExact, MatchDomainSuffix); a bundle chooses
//     from that list and cannot describe a new one. In particular there is no
//     regular expression anywhere in the format, because a regex delivered over
//     the network is both a small programming language and a denial-of-service
//     primitive.
//
// # An unknown enumeration member is inert, not fatal, and never silent
//
// A bundle naming a match kind or an indicator class this build does not know
// could mean two things: a newer publisher, or an attacker blanking the
// detections. Refusing the whole bundle lets a newer publisher brick older
// binaries; accepting silently lets the attacker win. So the indicator is INERT,
// it does NOT count towards ActiveIndicators, and it produces a coverage gap
// naming it (INV-9). The count drop is then visible to the operator, which is
// the whole point of reporting the count.
//
// # What is here and what is not
//
// This package parses, verifies and admits. It does not match: no rule in this
// repository consumes bundle data yet, so nothing here feeds a fingerprint
// epoch's declared inputs. The moment a compiled rule starts matching on a
// bundle datum, that rule's adjudicate.Semantics.Inputs must name it and its
// epoch must bump -- adjudicate's golden-history test will say so.
package bundle

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/lookatitude/aurvet/internal/baseline"
)

// SpecVersion is the bundle schema this build writes and accepts.
const SpecVersion = 1

// GenesisPrev is prev_digest for the first bundle ever published. Same shape and
// same reasoning as chain.GenesisPrev: an ABSENT link and a link to nothing must
// not be spellable the same way, or a fork is indistinguishable from a start.
const GenesisPrev = "0000000000000000000000000000000000000000000000000000000000000000"

// MaxBundleBytes caps a bundle document. Enforced before any parse and again by
// the fetcher before the bytes are in memory at all.
const MaxBundleBytes = 4 << 20

// MaxIndicators caps how many indicators one bundle may carry. A bound, not a
// prediction: the reference indicator sets are in the hundreds.
const MaxIndicators = 100_000

// LimitsText is what a verified bundle does and does not prove (INV-6). Render
// it with anything derived from bundle data.
const LimitsText = "a verified bundle proves that a key delegated by the root set published exactly " +
	"these bytes before the delegation expired; it does not prove the indicator set is COMPLETE, " +
	"that anything absent from it is safe, or that this is the newest bundle -- withholding updates " +
	"is invisible to a signature and is bounded only by valid_until."

var (
	// ErrBundle reports a malformed bundle document.
	ErrBundle = errors.New("bundle: malformed indicator bundle")

	// ErrCarriesKey reports a bundle that tries to introduce key material.
	// Bundles cannot introduce keys: the online signing keys are named by the
	// root-signed delegation and nowhere else. A bundle that could name a key
	// could name its own successor's key, and the root set would be decorative.
	ErrCarriesKey = errors.New("bundle: a bundle may not carry key material")

	// ErrExecutable reports a bundle member whose name belongs to executable
	// content. INV-1 and INV-2: a bundle is data, parsed, never executed.
	ErrExecutable = errors.New("bundle: a bundle may not carry executable content")

	// ErrEmptyBundle reports a bundle with no active indicators. Refused rather
	// than accepted-as-nothing-to-check: a signed bundle that REMOVES detections
	// is an attack, and the empty case is its limit.
	ErrEmptyBundle = errors.New("bundle: a bundle with no active indicators is refused")
)

// -- the document ------------------------------------------------------------

// Bundle is the indicator bundle. Field order in this declaration is
// irrelevant: baseline.Marshal sorts by key, so a later reordering cannot
// invalidate a published signature.
type Bundle struct {
	SpecVersion int `json:"spec_version"`

	// BundleVersion is monotonic across the publisher's whole history. It is
	// what the anti-rollback floor compares against, so it must never be reused
	// or reordered; the publisher's own tooling owns that, and the floor is what
	// protects a client when the publisher's tooling fails.
	BundleVersion int64 `json:"bundle_version"`

	// IssuedAt and ValidUntil are RFC3339 with an EXPLICIT offset (see
	// baseline.ParseStamp). Both are inputs, never a clock read: nothing in this
	// package reads the wall clock, so an auditor can reproduce every byte.
	IssuedAt   string `json:"issued_at"`
	ValidUntil string `json:"valid_until"`

	// PrevDigest is sha256 over the canonical bytes of the preceding bundle,
	// hex, or GenesisPrev for the first. It chains bundles the way prev_hash
	// chains the local trust chain, and it is what makes a fork -- two different
	// bundles published at the same version, or a bundle spliced onto the wrong
	// predecessor -- detectable rather than merely improbable.
	PrevDigest string `json:"prev_digest"`

	Indicators Indicators `json:"indicators"`
}

// Indicators is the data. Every field is a sorted, duplicate-free list, so one
// logical indicator set has exactly one canonical spelling and therefore exactly
// one digest.
type Indicators struct {
	SourceHosts   []HostIndicator   `json:"source_hosts"`
	KnownBadNames []NameIndicator   `json:"known_bad_names"`
	RebuildRepos  []RepoIndicator   `json:"rebuild_repos"`
	Digests       []DigestIndicator `json:"digests"`
	Thresholds    []Threshold       `json:"thresholds"`
}

// MatchKind is how a compiled rule compares a subject to an indicator's value.
// It is a CLOSED enumeration: a bundle picks one of these, and cannot describe a
// new one. This is the whole of the "pattern language", deliberately.
type MatchKind string

const (
	// MatchExact is byte equality after the compiled rule's own normalisation.
	MatchExact MatchKind = "exact"

	// MatchDomainSuffix matches a host equal to the value or ending in
	// "."+value. Implemented in the compiled rule, not described by the bundle:
	// "ends with" as a string operation would also match "evilpaste.com" against
	// "paste.com", which is not what a domain suffix means.
	MatchDomainSuffix MatchKind = "domain-suffix"
)

func (m MatchKind) known() bool { return m == MatchExact || m == MatchDomainSuffix }

// HostClass names why a host is on the list. The compiled rule decides what each
// class implies for severity; the bundle only supplies the membership.
type HostClass string

const (
	HostPaste     HostClass = "paste-site"
	HostShortener HostClass = "url-shortener"
	HostGist      HostClass = "code-paste"
	HostBareIP    HostClass = "bare-ip"
)

func (c HostClass) known() bool {
	switch c {
	case HostPaste, HostShortener, HostGist, HostBareIP:
		return true
	}
	return false
}

// HostIndicator is one entry of the source-host list (spec §7).
type HostIndicator struct {
	Host  string    `json:"host"`
	Match MatchKind `json:"match"`
	Class HostClass `json:"class"`
	Note  string    `json:"note"`
}

// NameIndicator is a literal known-bad package or pkgbase name.
type NameIndicator struct {
	Name string `json:"name"`
	Note string `json:"note"`
}

// RepoClass is the repo-provenance verdict a repository carries. "known-rebuild"
// is the load-bearing one: third-party rebuild repos SIGN AUR-authored packages,
// so a pgp validation there means nothing and the repo must be treated as
// foreign-equivalent (spec §5).
type RepoClass string

const (
	RepoOfficial      RepoClass = "official"
	RepoKnownRebuild  RepoClass = "known-rebuild"
	RepoDerivative    RepoClass = "derivative"
	RepoKnownHostile  RepoClass = "known-hostile"
	repoClassSentinel RepoClass = ""
)

func (c RepoClass) known() bool {
	switch c {
	case RepoOfficial, RepoKnownRebuild, RepoDerivative, RepoKnownHostile:
		return true
	}
	return false
}

// RepoIndicator is one row of the rebuild-repo list.
type RepoIndicator struct {
	Name  string    `json:"name"`
	Host  string    `json:"host"`
	Class RepoClass `json:"class"`
	Note  string    `json:"note"`
}

// DigestIndicator is a known-bad artefact digest.
type DigestIndicator struct {
	SHA256 string `json:"sha256"`
	Note   string `json:"note"`
}

// Threshold is a named integer knob a compiled rule reads.
//
// Value is an int64 and never a float, and this is not stylistic: a float has
// several IEEE-754 spellings, encoding/json has changed which one it picks, and
// a re-spelled number changes the document digest and therefore breaks every
// signature over it. baseline's canonical decoder refuses floats outright, so a
// bundle carrying 0.5 is rejected before it is ever read.
type Threshold struct {
	Name  string `json:"name"`
	Value int64  `json:"value"`
}

// -- parsing -----------------------------------------------------------------

// ParseBundle authenticates raw bytes and only then parses them.
//
// The ordering IS the security property, not an implementation detail. Nothing
// below the signature check has seen the bytes: VerifyCanonical hashes them, it
// does not interpret them, so a hostile bundle never reaches a JSON parser on
// the strength of an unchecked signature. Every check in this function is
// therefore a check on bytes that a trusted delegated key demonstrably emitted.
//
// trusted is the set of ONLINE signing keys named by a root-signed delegation.
// It is never a set assembled from the bundle itself; see ErrCarriesKey.
//
// It returns the canonical bytes alongside the parsed document so a caller can
// digest exactly what was verified rather than re-marshalling and hoping.
func ParseBundle(raw, sig []byte, trusted []*baseline.PublicKey) (*Bundle, []byte, error) {
	if len(raw) > MaxBundleBytes {
		return nil, nil, fmt.Errorf("%w: %d bytes exceeds the %d byte cap",
			ErrBundle, len(raw), MaxBundleBytes)
	}
	canon, _, err := baseline.VerifyCanonical(sig, baseline.NamespaceBundle, raw, trusted)
	if err != nil {
		return nil, nil, err
	}
	b, err := decodeBundle(canon)
	if err != nil {
		return nil, nil, err
	}
	return b, canon, nil
}

// decodeBundle admits already-authenticated canonical bytes. Split out from
// ParseBundle so the admission rules can be tested directly without a signature
// standing between the test and the rule it is exercising -- NOT so that a
// caller can skip the signature. It is unexported for that reason.
func decodeBundle(canon []byte) (*Bundle, error) {
	if err := assertDeclarative(canon); err != nil {
		return nil, err
	}
	var b Bundle
	if err := decodeStrict(canon, &b); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBundle, err)
	}
	// Re-encoding must reproduce the bytes that were signed. If it does not,
	// this build's idea of the document differs from the publisher's -- a
	// dropped field, a member this build ignores -- and every answer derived
	// from it would be about a document nobody signed.
	again, err := baseline.Marshal(b)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBundle, err)
	}
	if string(again) != string(canon) {
		return nil, fmt.Errorf("%w: the parsed bundle does not re-encode to the bytes that were signed",
			ErrBundle)
	}
	if err := ValidateBundle(&b); err != nil {
		return nil, err
	}
	return &b, nil
}

// ValidateBundle refuses a bundle that is malformed on its face. It says nothing
// about expiry, the version floor or linkage: those need state this function
// does not have, and live in Verify.
func ValidateBundle(b *Bundle) error {
	if b.SpecVersion != SpecVersion {
		return fmt.Errorf("%w: spec_version %d, this build reads %d",
			ErrBundle, b.SpecVersion, SpecVersion)
	}
	if b.BundleVersion < 1 {
		return fmt.Errorf("%w: bundle_version %d; versions start at 1 so that a zero value "+
			"cannot pass for a legitimate one", ErrBundle, b.BundleVersion)
	}
	issued, err := baseline.ParseStamp(b.IssuedAt)
	if err != nil {
		return fmt.Errorf("%w: issued_at: %v", ErrBundle, err)
	}
	until, err := baseline.ParseStamp(b.ValidUntil)
	if err != nil {
		return fmt.Errorf("%w: valid_until: %v", ErrBundle, err)
	}
	if !until.After(issued) {
		return fmt.Errorf("%w: valid_until %s is not after issued_at %s, so the bundle is "+
			"expired the moment it is published", ErrBundle, b.ValidUntil, b.IssuedAt)
	}
	if err := ValidDigest(b.PrevDigest); err != nil {
		return fmt.Errorf("%w: prev_digest: %v", ErrBundle, err)
	}
	if b.BundleVersion == 1 && b.PrevDigest != GenesisPrev {
		return fmt.Errorf("%w: bundle_version 1 has a predecessor digest", ErrBundle)
	}
	if b.BundleVersion > 1 && b.PrevDigest == GenesisPrev {
		return fmt.Errorf("%w: bundle_version %d claims to be the first bundle; a re-genesis "+
			"is how a fork is spelled", ErrBundle, b.BundleVersion)
	}
	return validateIndicators(&b.Indicators)
}

func validateIndicators(in *Indicators) error {
	total := len(in.SourceHosts) + len(in.KnownBadNames) + len(in.RebuildRepos) +
		len(in.Digests) + len(in.Thresholds)
	if total > MaxIndicators {
		return fmt.Errorf("%w: %d indicators exceeds the cap of %d", ErrBundle, total, MaxIndicators)
	}

	var hostKeys, nameKeys, repoKeys, digestKeys, thresholdKeys []string
	for i, h := range in.SourceHosts {
		if err := requireField("indicators.source_hosts", i, "host", h.Host); err != nil {
			return err
		}
		hostKeys = append(hostKeys, h.Host+"\x00"+string(h.Match))
	}
	for i, n := range in.KnownBadNames {
		if err := requireField("indicators.known_bad_names", i, "name", n.Name); err != nil {
			return err
		}
		nameKeys = append(nameKeys, n.Name)
	}
	for i, r := range in.RebuildRepos {
		if err := requireField("indicators.rebuild_repos", i, "name", r.Name); err != nil {
			return err
		}
		if r.Class == repoClassSentinel {
			return fmt.Errorf("%w: indicators.rebuild_repos[%d] has no class; an unclassified "+
				"repo is a row a compiled rule cannot act on", ErrBundle, i)
		}
		repoKeys = append(repoKeys, r.Name)
	}
	for i, d := range in.Digests {
		if err := ValidDigest(d.SHA256); err != nil {
			return fmt.Errorf("%w: indicators.digests[%d]: %v", ErrBundle, i, err)
		}
		digestKeys = append(digestKeys, d.SHA256)
	}
	for i, t := range in.Thresholds {
		if err := requireField("indicators.thresholds", i, "name", t.Name); err != nil {
			return err
		}
		thresholdKeys = append(thresholdKeys, t.Name)
	}

	// Sorted and duplicate-free, enforced rather than assumed. Two spellings of
	// one indicator set would digest differently, which breaks prev_digest
	// linkage between publisher and client for no attacker's benefit; and a
	// duplicate entry is a place where two readers can disagree about which one
	// won.
	for _, chk := range []struct {
		field string
		keys  []string
	}{
		{"indicators.source_hosts", hostKeys},
		{"indicators.known_bad_names", nameKeys},
		{"indicators.rebuild_repos", repoKeys},
		{"indicators.digests", digestKeys},
		{"indicators.thresholds", thresholdKeys},
	} {
		if err := sortedUnique(chk.field, chk.keys); err != nil {
			return err
		}
	}
	return nil
}

func requireField(field string, i int, name, value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%w: %s[%d].%s is empty", ErrBundle, field, i, name)
	}
	return nil
}

func sortedUnique(field string, keys []string) error {
	for i := 1; i < len(keys); i++ {
		switch {
		case keys[i] == keys[i-1]:
			return fmt.Errorf("%w: %s carries %q twice", ErrBundle, field, keys[i])
		case keys[i] < keys[i-1]:
			return fmt.Errorf("%w: %s is not sorted (%q follows %q); one indicator set must have "+
				"exactly one canonical spelling", ErrBundle, field, keys[i], keys[i-1])
		}
	}
	return nil
}

// -- active vs inert ---------------------------------------------------------

// Coverage is how much of a bundle this build can actually act on.
type Coverage struct {
	// Active is the number of indicators this build understands and will match
	// on. It is reported to the operator on every run: a suspicious drop toward
	// zero is the visible signature of a bundle that removes detections, which
	// is an attack and not an update.
	Active int

	// Inert names indicators this build parsed but cannot use, one string each,
	// because an unknown enumeration member is a coverage gap (INV-9) and never
	// a silent discard.
	Inert []string
}

// Count classifies every indicator as active or inert.
func (b *Bundle) Count() Coverage {
	var c Coverage
	for _, h := range b.Indicators.SourceHosts {
		switch {
		case !h.Match.known():
			c.Inert = append(c.Inert, fmt.Sprintf("source host %q names match kind %q, which this build does not implement", h.Host, h.Match))
		case !h.Class.known():
			c.Inert = append(c.Inert, fmt.Sprintf("source host %q names class %q, which this build does not implement", h.Host, h.Class))
		default:
			c.Active++
		}
	}
	c.Active += len(b.Indicators.KnownBadNames)
	for _, r := range b.Indicators.RebuildRepos {
		if !r.Class.known() {
			c.Inert = append(c.Inert, fmt.Sprintf("repo %q names class %q, which this build does not implement", r.Name, r.Class))
			continue
		}
		c.Active++
	}
	c.Active += len(b.Indicators.Digests)
	c.Active += len(b.Indicators.Thresholds)
	return c
}

// -- declarative admission ---------------------------------------------------

// deniedKeyMembers are member names that would introduce key material. The check
// is on NAMES rather than on the schema alone because a closed schema already
// rejects them -- with a generic "unknown field" that tells an operator nothing.
// This exists so the refusal is specific and so the property has a test that
// names it.
var deniedKeyMembers = map[string]bool{
	"key": true, "keys": true, "publickey": true, "publickeys": true,
	"privatekey": true, "secretkey": true, "signingkey": true, "signingkeys": true,
	"rootkey": true, "rootkeys": true, "authorizedkeys": true, "pubkey": true,
	"delegation": true, "certificate": true, "cert": true, "trustanchor": true,
	"keyring": true,
}

// deniedExecMembers are member names that would introduce executable content.
// INV-1 in one map: there is no member of a bundle that may name a program, a
// command, an expression or a scripting hook, today or in a later schema.
var deniedExecMembers = map[string]bool{
	"exec": true, "execute": true, "command": true, "cmd": true, "script": true,
	"shell": true, "eval": true, "run": true, "program": true, "hook": true,
	"interpreter": true, "code": true, "expr": true, "expression": true,
	"lambda": true, "action": true, "plugin": true, "regex": true, "regexp": true,
}

// assertDeclarative walks the document and refuses denied member names at any
// depth.
//
// It runs on bytes that baseline.Canonical has already admitted, so the parse
// here cannot hit duplicate keys, floats, invalid UTF-8 or unbounded nesting.
// Normalisation strips "-" and "_" and folds case, so "Signing_Keys",
// "signing-keys" and "SIGNINGKEYS" are one refusal rather than three bypasses.
func assertDeclarative(canon []byte) error {
	var tree any
	dec := json.NewDecoder(strings.NewReader(string(canon)))
	dec.UseNumber()
	if err := dec.Decode(&tree); err != nil {
		return fmt.Errorf("%w: %v", ErrBundle, err)
	}
	return walkMembers(tree, "$", 0)
}

func walkMembers(v any, path string, depth int) error {
	if depth > baseline.MaxDepth {
		return fmt.Errorf("%w: %s exceeds the depth limit", ErrBundle, path)
	}
	switch t := v.(type) {
	case map[string]any:
		for k, sub := range t {
			n := normaliseMember(k)
			if deniedKeyMembers[n] {
				return fmt.Errorf("%w: %s.%s -- the online signing keys are named by the "+
					"root-signed delegation and nowhere else", ErrCarriesKey, path, k)
			}
			if deniedExecMembers[n] {
				return fmt.Errorf("%w: %s.%s -- a bundle is data, parsed and never executed",
					ErrExecutable, path, k)
			}
			if err := walkMembers(sub, path+"."+k, depth+1); err != nil {
				return err
			}
		}
	case []any:
		for i, sub := range t {
			if err := walkMembers(sub, fmt.Sprintf("%s[%d]", path, i), depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

func normaliseMember(k string) string {
	var b strings.Builder
	for i := 0; i < len(k); i++ {
		c := k[i]
		if c == '-' || c == '_' || c == ' ' || c == '.' {
			continue
		}
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b.WriteByte(c)
	}
	return b.String()
}

// -- shared helpers ----------------------------------------------------------

// decodeStrict unmarshals into v and refuses an unknown member and trailing
// data. A closed schema, so a bundle cannot smuggle a field past this build on
// the theory that a later build might read it.
func decodeStrict(b []byte, v any) error {
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data after the document")
	}
	return nil
}

// ValidDigest reports whether s is a lowercase hex sha256. Exported because the
// floor and the delegation both carry digests and one spelling rule serves all
// of them.
func ValidDigest(s string) error {
	if len(s) != 64 {
		return fmt.Errorf("digest %q is %d characters, want 64 hex", s, len(s))
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return fmt.Errorf("digest %q is not lowercase hex", s)
		}
	}
	return nil
}

// DigestOf is sha256 over canonical bytes, hex. The caller must pass the bytes
// that were VERIFIED, not a re-marshalling of the parsed document.
func DigestOf(canon []byte) string {
	d := baseline.DigestBytes(canon)
	return baseline.Hex(d[:])
}

func short(h string) string {
	if len(h) <= 12 {
		return h
	}
	return h[:12]
}
