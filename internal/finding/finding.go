// internal/finding/finding.go
package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

type Severity int

const (
	SevInfo Severity = iota
	SevSuspicious
	SevCritical
)

func (s Severity) String() string {
	switch s {
	case SevInfo:
		return "info"
	case SevSuspicious:
		return "suspicious"
	case SevCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// Finding is one detection. Limits carries what this finding cannot prove and
// is rendered in output, satisfying INV-6.
type Finding struct {
	RuleID      string
	SubjectKind string
	Subject     string
	Severity    Severity
	Summary     string
	Evidence    []string
	Limits      string
}

// Gap records a check that could not run. Per INV-3 and INV-10 this is never
// silence and never a pass.
type Gap struct {
	RuleID  string
	Subject string
	Reason  string
}

type Result struct {
	Findings []Finding
	Gaps     []Gap
}

// Complete reports whether every check ran (len(Gaps) == 0). It says nothing
// about severity: a Result can be Complete with a SevCritical finding, or
// incomplete with none. Pair with MaxSeverity — a caller deriving a summary
// or exit status from MaxSeverity alone will silently treat "could not check"
// the same as "checked and clean."
func (r Result) Complete() bool { return len(r.Gaps) == 0 }

// MaxSeverity reports the highest Severity among Findings only. It says
// nothing about what could not be checked: a Result with Gaps but no
// Findings reports SevInfo, indistinguishable from a genuinely clean sweep.
// This is intentional — a Gap is not a Finding, and MaxSeverity must not
// invent a severity for "I could not check." Any caller deriving a summary
// or exit status from MaxSeverity must also gate on Complete().
func (r Result) MaxSeverity() Severity {
	max := SevInfo
	for _, f := range r.Findings {
		if f.Severity > max {
			max = f.Severity
		}
	}
	return max
}

// Fingerprint identifies a finding stably across package upgrades and rule
// rewordings. subjectIdentity must be version-independent — a package name,
// not name-version; a path, not its digest. This is caller discipline:
// Fingerprint cannot inspect its arguments, so a caller who folds a version
// into subjectIdentity (e.g. "librewolf-fix-bin-1.2.3-1") gets a
// version-bearing fingerprint that silently breaks --since-last suppression
// on every upgrade.
//
// The four fields are combined by length-prefixing each one (decimal byte
// length, ':', then the field bytes) before hashing, so the encoding is
// injective: no combination of field contents can shift a byte across a
// field boundary and collide with a different four-tuple.
func Fingerprint(ruleID, subjectKind, subjectIdentity, scope string) string {
	var b strings.Builder
	for _, field := range []string{ruleID, subjectKind, subjectIdentity, scope} {
		fmt.Fprintf(&b, "%d:", len(field))
		b.WriteString(field)
	}
	h := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(h[:16])
}
