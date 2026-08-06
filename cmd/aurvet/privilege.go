// cmd/aurvet/privilege.go
//
// spec §11's privilege policy for `scan`, and nothing else.
//
// `scan` requires root and refuses unprivileged unless `--allow-degraded` is
// passed, which stamps the report and forces the incomplete exit. Measured on the
// reference system: 25 of 337,609 package-owned files are unreadable to an
// ordinary user, and an unprivileged `--tier full` run produced 32
// permission-denied coverage gaps of 72 -- so exit 3 was the outcome of every
// unprivileged run, which is the same as having no outcome.
//
// --offline-root is exempt, because that measurement is a property of a live root
// whose sensitive files belong to uid 0 while the process does not. A mounted or
// extracted tree is readable to the extent its ownership allows: an unprivileged
// scan of a user-owned offline root produced zero permission-denied gaps, so exit
// 0 stays reachable there and exit 3 keeps its meaning. The alternative -- telling
// that operator to use sudo -- would hand root read over an attacker-supplied
// filesystem to satisfy a policy about this host's own /etc/shadow.
//
// Definitions, figures and the counts §11's own numbers do and do not reproduce
// under are in this lane's receipt.
package main

import (
	"fmt"
	"strings"
)

// rulePrivilegeCoverage is the rule id the degradation is reported under. It is a
// GAP rule and never a finding: "I could not look everywhere" is a statement
// about coverage, and routing it through the gap list is what makes it survive
// --min-severity (INV-3) and reach the JSON document, the stored report and the
// exit code by the same path as every other shortfall.
const rulePrivilegeCoverage = "privilege-coverage"

// privilegeDecision is the policy's verdict for one scan: whether to run at all,
// and whether what runs must be stamped.
//
// It is a pure function's return value -- no I/O, no clock, no globals -- so every
// combination of the three inputs is assertable, which matters because the cell
// that decides the interesting case (unprivileged plus --offline-root) is the one
// nobody thinks to try by hand.
type privilegeDecision struct {
	// Refuse means nothing is scanned and the exit code is 2. A refusal is a
	// statement about the INVOCATION, not about coverage: no analysis was
	// attempted, so there is nothing to report as incomplete.
	Refuse bool

	// Degraded means the scan runs, its report carries Stamp, and its result
	// carries the Gap -- so it cannot exit 0.
	Degraded bool

	Refusal []string
	Stamp   []string
	Gap     string
}

func privilegePolicy(euid int, offlineRoot string, allowDegraded bool) privilegeDecision {
	if euid == 0 {
		// Root. --allow-degraded is not an error here and not a stamp either:
		// asserting degradation a privileged run does not suffer would put a
		// caveat on a complete report, and a caveat that can be wrong is a caveat
		// people learn to ignore. Whatever this run cannot read still becomes a
		// gap on its own merits.
		return privilegeDecision{}
	}
	if allowDegraded {
		return privilegeDecision{
			Degraded: true,
			Stamp: []string{
				"!! DEGRADED SCAN (--allow-degraded): this run is unprivileged, so its coverage is " +
					"bounded by what this user can read.",
				"   Every path it was refused appears as a coverage gap below, and this run cannot " +
					"exit 0 even when none are listed: \"I could not look everywhere\" is the finding.",
			},
			Gap: "this scan ran unprivileged under --allow-degraded: root-only files could not be " +
				"hashed and root-only directories could not be listed, so its coverage is bounded by " +
				"this user's permissions and cannot be presented as complete. On the reference system " +
				"25 package-owned files and 24 package-owned or swept directories are unreadable to an " +
				"ordinary user; what this particular run was refused is listed as its own gap above.",
		}
	}
	if offlineRoot != "" {
		// Exempt. See the file comment: the measurement behind the refusal is a
		// property of the live root, and an offline root's readability is a
		// property of the mount.
		return privilegeDecision{}
	}
	return privilegeDecision{
		Refuse: true,
		Refusal: []string{
			"aurvet: refusing to scan unprivileged. Coverage would be bounded by what this user can " +
				"read, and a scan that can never be complete teaches its reader that the incomplete " +
				"exit means nothing (spec §11).",
			"  unavailable to this user: package-owned files whose mode is root-only are unreadable " +
				"-- /etc/shadow, /etc/gshadow, /etc/sudoers, /etc/crypttab and the cups and dbus " +
				"helpers among them -- so their contents cannot be hashed, and root-only directories " +
				"cannot be listed, so what they hold is neither verified nor enumerated.",
			"  how to proceed:",
			"    sudo aurvet scan ...              the whole system; complete coverage, and exit 0 is " +
				"reachable",
			"    aurvet scan --allow-degraded ...  proceed as this user: the report is stamped " +
				"DEGRADED, every refused read is a coverage gap, and the run can never exit 0",
			"  --offline-root is exempt: examining a mounted or extracted filesystem as an ordinary " +
				"user is legitimate, and its readability is a property of the mount rather than of " +
				"this host's root-only paths.",
		},
	}
}

// scopeLine states what a --pkg run did and did not cover. It sits with the
// degradation stamp, above the findings, for the same reason: a report that
// examined 1 package out of 1,409 and said so underneath its findings is a report
// that will be read as a verdict on the system.
func scopeLine(only []string) []string {
	if len(only) == 0 {
		return nil
	}
	return []string{
		fmt.Sprintf("scope: %d named package(s) (--pkg): %s", len(only), strings.Join(only, ", ")),
		"   provenance and integrity were analysed for these packages only. The system-wide passes " +
			"-- surface enumeration, correlation and the unowned-setuid sweep -- did NOT run: with " +
			"--pkg the ownership oracle is built from the named packages alone, so every other file " +
			"on the system would read as owned by nobody and their verdicts would be fabricated.",
		"   Run `aurvet scan` without --pkg for a verdict about the system.",
	}
}
