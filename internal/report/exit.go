// internal/report/exit.go
package report

import (
	"fmt"
	"strings"

	"github.com/lookatitude/aurvet/internal/finding"
)

const (
	exitClean      = 0
	exitFindings   = 1
	exitIncomplete = 3
)

// ExitCode maps a Result to the CLI's contractual exit codes (spec §14).
//
// 3 OUTRANKS 1, deliberately, and the order of these two blocks is the
// whole contract. An incomplete scan that also found something is still
// an incomplete scan: a caller that sees 1 is entitled to conclude
// "analysis completed, here is the full picture", and with gaps present
// that conclusion is false. Both 1 and 3 are failure codes under systemd
// (spec §14), so nothing is hidden by preferring 3 — the findings are
// still rendered in full by Text/JSON. Inverting this order is the one
// change to this function that turns a partial scan into false assurance.
//
// `min` GATES FINDINGS ONLY, NEVER GAPS — decided by the operator 2026-08-05,
// recorded here because the alternative looks like an obvious improvement and
// is not.
//
// The observation that prompted the question: on the reference system three AUR
// records carry no submitter, each producing a coverage gap, so `scan` exits 3
// on every networked run even when `aur-submitter-mismatch` sits below the
// default floor at SevInfo. It is tempting to let `min` suppress gaps on
// below-floor rules so that 3 regains discriminating power.
//
// Rejected, because it conflates two different statements. A finding's severity
// says "here is something I examined and judged". A gap says "here is something
// I could not examine at all" — and how bad the *rule* would have been is
// unrelated to the fact that the subject went unexamined. Suppressing a gap
// because its rule scores low would let a raised --min-severity quietly convert
// unexamined subjects into an exit 0, which is precisely the false clean INV-3
// exists to forbid. A floor is a reporting preference; INV-3 is a contract, and
// a preference must not be able to overrule a contract.
//
// The accepted cost is that exit 3 is the normal outcome on a system with
// incomplete AUR provenance. That is the honest reading of such a system, and
// the gap list in the report is where the detail lives.
func ExitCode(r finding.Result, min finding.Severity) int {
	if !r.Complete() {
		return exitIncomplete
	}
	for _, f := range r.Findings {
		if f.Severity >= min {
			return exitFindings
		}
	}
	return exitClean
}

// ParseSeverity maps the -min-severity flag string and config.Config.MinSeverity
// onto finding.Severity. Unrecognised input is an error naming the accepted
// values rather than a silent default — a typo'd floor must never silently
// become "info" and flip a scan's verdict class.
func ParseSeverity(s string) (finding.Severity, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "info":
		return finding.SevInfo, nil
	case "suspicious":
		return finding.SevSuspicious, nil
	case "critical":
		return finding.SevCritical, nil
	default:
		return 0, fmt.Errorf("invalid severity %q: accepted values are info, suspicious, critical", s)
	}
}
