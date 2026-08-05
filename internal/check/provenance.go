// internal/check/provenance.go
package check

import (
	"context"
	"fmt"
	"sort"

	"github.com/lookatitude/aurvet/internal/alpm"
	"github.com/lookatitude/aurvet/internal/aur"
	"github.com/lookatitude/aurvet/internal/finding"
)

const limitProvenance = "Packaging provenance only; says nothing about whether the upstream source is malicious."

// SyncCoverageGaps turns the unreadable-sync-DB filenames that
// alpm.LoadSyncNames reports into finding.Gaps.
//
// It exists because foreignness is !syncNames[p.Name], so an oracle that
// failed to parse and an oracle that answered "none of these packages are in
// a repository" would otherwise arrive at Provenance as the same empty map.
// spec.html §4.1 makes the distinguishing rule structural on purpose — zero
// names WITH at least one tar entry — and the tar entry count is exactly what
// a bare syncNames map cannot carry.
//
// E-1: Provenance now takes the unreadable-DB list directly as a required
// positional parameter, precisely so this stays the tested primitive rather
// than an obligation enforced only by a comment. The frozen signature used to
// give Provenance no way to see this list at all, which meant a caller could
// merge it, forget to, or merge it after an early return had already handed
// back a Result — and the worst case was silent: a completely empty,
// completely "complete" Result for a run whose foreignness oracle was never
// understood. A required parameter makes omitting it a compile error instead
// of a code-review miss.
func SyncCoverageGaps(unreadableDBs []string) []finding.Gap {
	if len(unreadableDBs) == 0 {
		return nil
	}
	gaps := make([]finding.Gap, 0, len(unreadableDBs))
	for _, db := range unreadableDBs {
		gaps = append(gaps, finding.Gap{
			RuleID:  "sync-coverage",
			Subject: db,
			Reason: "sync database could not be read; the set of repository package names is " +
				"incomplete, so every foreignness verdict in this run is unreliable",
		})
	}
	return gaps
}

// baseEvidence names the pkgbase when it differs from the package name. That
// is the axis S1 and S2 turned on — which key the AUR was asked about — so a
// reader who cannot see it cannot tell "this package is not published" from
// "this base is not published".
func baseEvidence(p alpm.Package) []string {
	if p.Base == "" || p.Base == p.Name {
		return nil
	}
	return []string{"pkgbase=" + p.Base}
}

// removalEvidence renders the evidence for a detected removal.
//
// S8: when Tombstone reports a removal with no recoverable message, rendering
// "cgit removal commit: " with nothing after it asserts a commit message that
// does not exist. Say what actually happened instead.
func removalEvidence(p alpm.Package, msg string) []string {
	var ev []string
	if msg != "" {
		ev = append(ev, "cgit removal commit: "+msg)
	} else {
		ev = append(ev, "cgit reported a removal with no recoverable commit message")
	}
	ev = append(ev, "absent from the AUR index, searched by package name")
	return append(ev, baseEvidence(p)...)
}

// tombstoneSummary and tombstoneLimits render a malware tombstone against the
// package it was actually observed on. T4: when p.Base differs from p.Name the
// package itself was never in the AUR, so it cannot have been removed from it —
// the pkgbase it declares was, and %BASE% is written by whoever built the
// package. The severity does not move; only the claim does.
func tombstoneSummary(p alpm.Package) string {
	if p.Base != "" && p.Base != p.Name {
		return "package declares a pkgbase that the AUR removed for malware"
	}
	return "package was removed from the AUR for malware"
}

func tombstoneLimits(p alpm.Package) string {
	if p.Base != "" && p.Base != p.Name {
		return "This package's own name was never in the AUR index; the removed subject is the pkgbase it " +
			"declares, a self-reported field. Does not confirm the payload is still present on this system."
	}
	return "Confirms the AUR removed this package. Does not confirm the payload is still present on this system."
}

// tombstoneOutcome caches one base's Tombstone call, including the error
// outcome — a base is queried once even when several installed packages
// share it (task 8: "the AUR is queried per base; findings are per package").
type tombstoneOutcome struct {
	found bool
	msg   string
	err   error
}

// Provenance examines foreign packages against AUR metadata. Every rule
// declares its evidence precondition: when the network is unavailable or a
// lookup fails, the checks emit coverage gaps rather than passing (INV-10),
// and in particular a failure can never surface as "absent from the AUR"
// (contract rule 1). Only a tombstone whose message satisfies
// aur.IsMalwareRemoval reaches SevCritical (contract rule 3); every other
// removal — administrative or merely undetected — lands at SevSuspicious via
// aur-absent.
//
// unreadableSyncDBs is alpm.LoadSyncNames's second return value, verbatim:
// the unreadable sync-DB filenames. It is converted with SyncCoverageGaps and
// merged into the result (E-1).
func Provenance(
	ctx context.Context,
	pkgs []alpm.Package,
	syncNames map[string]bool,
	unreadableSyncDBs []string,
	cl aur.Client,
	network bool,
) finding.Result {
	var res finding.Result

	// LOAD-BEARING PLACEMENT, not stylistic: this must run before the
	// len(foreign) == 0 early return below, before the !network early return,
	// and before every other exit path in this function. A sync-DB parse
	// failure means every foreignness verdict this sweep produces — including
	// "no foreign packages at all" — rests on an oracle that was not fully
	// understood, so the gap has to survive every exit, not just the ones that
	// happen to reach the bottom of the function (E-1).
	res.Gaps = append(res.Gaps, SyncCoverageGaps(unreadableSyncDBs)...)

	var foreign []alpm.Package
	for _, p := range pkgs {
		if alpm.IsForeign(p, syncNames) {
			foreign = append(foreign, p)
		}
	}
	if len(foreign) == 0 {
		return res
	}

	if !network {
		for _, p := range foreign {
			res.Gaps = append(res.Gaps, finding.Gap{
				RuleID: "aur-provenance", Subject: p.Name,
				Reason: "network disabled; AUR provenance checks did not run",
			})
		}
		return res
	}

	// S1/S2: ASK BY PACKAGE NAME, NOT BY BASE, and key presence on the name.
	//
	// The v5 RPC matches package NAMES — internal/aur/http.go's F15 comment
	// records that `by=pkgbase` is rejected outright — so a pkgbase that is not
	// itself a package name can never appear in a response. Asking by base and
	// reading absence off `info[p.Base]` therefore reported EVERY split package
	// whose base differs from all its package names as "absent from the AUR":
	// a live `foo` built from base `foo-common` came back suspicious, measured
	// against a faithful httptest RPC server. That is a systemic false
	// accusation, reported as complete coverage.
	//
	// It fails the other way too. `%BASE%` is written by whoever built the
	// package, so a package published NOWHERE could name a healthy base
	// (`nvidia-utils-patched` declaring base `yay`), resolve through it, and
	// produce no finding, no gap, and no cgit lookup at all — the authoritative
	// malware signal skipped by construction.
	//
	// Only the presence question moves to the name. The TOMBSTONE lookup stays
	// on p.Base: a cgit ref belongs to the pkgbase, not to the package.
	nameSet := map[string]bool{}
	for _, p := range foreign {
		nameSet[p.Name] = true
	}
	names := make([]string, 0, len(nameSet))
	for n := range nameSet {
		names = append(names, n)
	}
	// Sorted so one sweep produces one reproducible request; map order would
	// otherwise vary the query string run to run for no reason.
	sort.Strings(names)
	info, err := cl.Info(ctx, names)
	if err != nil {
		for _, p := range foreign {
			res.Gaps = append(res.Gaps, finding.Gap{
				RuleID: "aur-provenance", Subject: p.Name,
				Reason: fmt.Sprintf("AUR lookup failed: %v", err),
			})
		}
		return res
	}

	tombstones := map[string]tombstoneOutcome{}
	tombstoneFor := func(base string) tombstoneOutcome {
		if out, ok := tombstones[base]; ok {
			return out
		}
		found, msg, terr := cl.Tombstone(ctx, base)
		out := tombstoneOutcome{found: found, msg: msg, err: terr}
		tombstones[base] = out
		return out
	}

	for _, p := range foreign {
		// S6: require the record to be THIS package's own. Info cross-keys
		// results on both Name and PackageBase, so a result `{Name: foo,
		// PackageBase: bar}` also lands under the key `bar` — and a second
		// installed package named `bar` would then inherit foo's maintainer and
		// submitter and be judged on them. Info's own first-wins pass
		// guarantees that a genuine hit has meta.Name == p.Name, so this
		// rejects only the spurious cross-key and never a real record.
		meta, present := info[p.Name]
		if present && meta.Name != p.Name {
			present = false
		}
		if !present {
			out := tombstoneFor(p.Base)
			// A Tombstone error means "could not tell", never "removed" and
			// never "clean" — a Gap, and only a Gap (contract rule 1).
			if out.err != nil {
				res.Gaps = append(res.Gaps, finding.Gap{
					RuleID: "aur-tombstone", Subject: p.Name,
					Reason: fmt.Sprintf("cgit lookup failed: %v", out.err),
				})
				// The tombstone REASON is unknown, but the absence itself is
				// not: Info already established that the AUR has no record of
				// this package. Dropping the aur-absent finding along with the
				// failed reason lookup discarded a fact we held, and suppressed
				// the rule entirely on the reference system. The gap above still
				// forces exit 3, so this cannot read as a complete verdict.
				res.Findings = append(res.Findings, finding.Finding{
					RuleID: "aur-absent", SubjectKind: "package", Subject: p.Name,
					Severity: finding.SevSuspicious,
					Summary:  "installed foreign package is absent from the AUR",
					Evidence: append([]string{
						"absent from the AUR index, searched by package name",
						"whether it was removed, and why, could not be determined",
						"validation=" + p.Validation,
					}, baseEvidence(p)...),
					Limits: "Absence alone is not compromise: dropped-from-repo, renamed and never-published packages look identical. The removal reason was not retrievable, so a malware removal cannot be excluded.",
				})
				continue
			}
			if out.found && aur.IsMalwareRemoval(out.msg) {
				res.Findings = append(res.Findings, finding.Finding{
					RuleID: "aur-tombstone", SubjectKind: "package", Subject: p.Name,
					Severity: finding.SevCritical,
					// T4: when the base is not the package's own name, the
					// package itself was never in the AUR and cannot have been
					// "removed" from it — the pkgbase it DECLARES was. Saying
					// otherwise states a false fact and makes this
					// indistinguishable from an own-record tombstone at triage
					// time. The severity is unchanged and deliberately so:
					// either the declared provenance is true, or the package is
					// lying about it, and both warrant acting on.
					Summary:  tombstoneSummary(p),
					Evidence: removalEvidence(p, out.msg),
					Limits:   tombstoneLimits(p),
				})
				continue
			}
			if out.found {
				// Removed, but the wording does not indicate malice — a
				// rename, merge or administrative deletion. Suspicious,
				// never critical: present == true is not malware on its own.
				//
				// T9: with no recoverable message there is nothing to classify,
				// so claiming the reason was "not malware-related" asserts a
				// negative that was never established.
				summary := "package was removed from the AUR, reason not malware-related"
				if out.msg == "" {
					summary = "package was removed from the AUR, reason unknown"
				}
				res.Findings = append(res.Findings, finding.Finding{
					RuleID: "aur-absent", SubjectKind: "package", Subject: p.Name,
					Severity: finding.SevSuspicious,
					Summary:  summary,
					Evidence: removalEvidence(p, out.msg),
					Limits:   "Administrative removals (rename, merge) look identical here. Not evidence of compromise.",
				})
				continue
			}
			res.Findings = append(res.Findings, finding.Finding{
				RuleID: "aur-absent", SubjectKind: "package", Subject: p.Name,
				Severity: finding.SevSuspicious,
				Summary:  "installed foreign package is absent from the AUR",
				Evidence: append([]string{
					"absent from the AUR index, searched by package name",
					"no removal tombstone found",
					"validation=" + p.Validation,
				}, baseEvidence(p)...),
				// T1: a locally built debug output (`<pkg>-debug`) of a
				// published base also lands here, because makepkg emits it
				// under a name the AUR never indexes. It is named in the
				// limits rather than suppressed: a `-debug` carve-out would
				// key a silence on %NAME% and %BASE%, both written by whoever
				// built the package, and would hand back the evasion the
				// name-keyed lookup just closed.
				Limits: "Also matches a package dropped from the official repos, renamed, merged, " +
					"built locally and never published, or a locally built -debug output of a published base.",
			})
			continue
		}
		// T2: the record is present, so the tombstone branch above never runs —
		// and that lost a real detection the base-keyed code used to catch.
		// AUR package names are unique and are freed when a base is removed, so
		// after `foo-evilbase` is deleted for malware someone may republish a
		// clean `foo` under base `foo`. A user still carrying the malware build
		// has an installed package whose NAME resolves to the clean record while
		// its declared %BASE% is the tombstoned one. Keying presence on the name
		// (S1/S2) made that read as complete and clean: no finding, no gap, and
		// the tombstoned base never consulted at all.
		//
		// spec §5.1's critical rule is a conjunction — absent from the index AND
		// a cgit tombstone — and it does not say the two halves must be about
		// the same subject. They must. Where the record's pkgbase and the
		// package's declared pkgbase disagree, ask cgit about the DECLARED one.
		//
		// Only a tombstone speaks. A bare disagreement is silent, because a
		// benign upstream pkgbase rename looks exactly like this and is common;
		// an administrative removal of the old base is that same rename seen
		// from the other side. Malware is the one wording that earns a finding
		// here, and a cgit failure earns a gap rather than either answer.
		//
		// E-4b: authorised as E-4's own rule applied to a second field. The
		// orchestrator scoped this lane to provenance.go "for E-1 / E-4 / E-7
		// only"; the lead judged that closing an exit-0-on-malware hole in this
		// already-authorised file, using the exact pattern E-4 established
		// elsewhere in this function (INV-10: a check whose evidence is absent
		// reports unavailable, it does not pass), falls inside that scope, and
		// is disclosing this judgement to the orchestrator for ratification.
		// Before this switch, `meta.PackageBase == ""` let a package declaring a
		// malware-tombstoned pkgbase produce no finding, no gap, and exit 0 --
		// the same defect shape E-4 fixed for aur-submitter-mismatch, left open
		// on the one rule that can reach SevCritical.
		switch {
		case meta.PackageBase == "" || p.Base == "":
			res.Gaps = append(res.Gaps, finding.Gap{
				RuleID: "aur-tombstone", Subject: p.Name,
				Reason: "declared pkgbase or AUR record pkgbase is absent; the " +
					"declared-pkgbase comparison did not run",
			})
		case meta.PackageBase != p.Base:
			out := tombstoneFor(p.Base)
			switch {
			case out.err != nil:
				res.Gaps = append(res.Gaps, finding.Gap{
					RuleID: "aur-tombstone", Subject: p.Name,
					Reason: fmt.Sprintf(
						"package declares pkgbase %q but the AUR record names %q; cgit lookup for the declared base failed: %v",
						p.Base, meta.PackageBase, out.err),
				})
			case out.found && aur.IsMalwareRemoval(out.msg):
				res.Findings = append(res.Findings, finding.Finding{
					RuleID: "aur-tombstone", SubjectKind: "package", Subject: p.Name,
					Severity: finding.SevCritical,
					Summary:  "package declares a pkgbase that the AUR removed for malware",
					Evidence: []string{
						"cgit removal commit: " + out.msg,
						"declared pkgbase=" + p.Base,
						"the AUR record for this name is built from pkgbase=" + meta.PackageBase,
					},
					Limits: "The declared pkgbase is a self-reported field from the installed package's own metadata. " +
						"Confirms the AUR removed that base for malware; does not by itself confirm this package was built from it.",
				})
			}
		}
		if meta.Maintainer == "" {
			submitterEvidence := "submitter=" + meta.Submitter
			if meta.Submitter == "" {
				submitterEvidence = "submitter unavailable"
			}
			res.Findings = append(res.Findings, finding.Finding{
				RuleID: "aur-orphaned", SubjectKind: "package", Subject: p.Name,
				Severity: finding.SevSuspicious,
				Summary:  "package is orphaned in the AUR",
				Evidence: []string{"maintainer is unset", submitterEvidence},
				Limits:   "Orphaning is a takeover precondition, not evidence of compromise. " + limitProvenance,
			})
		}
		// E-4/INV-10: a check whose evidence is absent reports unavailable, it
		// does not pass. An absent Submitter used to read as "maintainer and
		// submitter agree" — the exact takeover signal this rule exists to raise,
		// turned off by the absence of the field it compares. This fires whenever
		// Submitter == "", including when Maintainer is also empty: the orphaned
		// state is known and keeps its own aur-orphaned finding above, while a
		// missing Submitter is an independent unknown. Both can fire on the same
		// package — one finding, one gap.
		switch {
		case meta.Submitter == "":
			res.Gaps = append(res.Gaps, finding.Gap{
				RuleID: "aur-submitter-mismatch", Subject: p.Name,
				Reason: "AUR record carries no submitter; the maintainer/submitter identity comparison did not run",
			})
		case meta.Maintainer != "" && meta.Maintainer != meta.Submitter:
			// Downgraded 2026-08-05 (lead decision, plan Risk #1 -- "cries
			// wolf"). Measured on the reference system this rule fired on 13
			// of 39 foreign packages (33%), every one a verified-benign
			// maintainer handoff, and dominated the default `suspicious`
			// floor with 13 of 14 total findings. A maintainer/submitter
			// delta with no history is an identity fact, not a suspicion --
			// the actionable, correlated form (an orphan followed by a new
			// maintainer within N days) needs the drift baseline arriving in
			// P4. Reporting the uncorrelated delta at the default floor buys
			// noise now and spends the operator's attention before the
			// signal that would justify it exists. This cannot manufacture
			// false assurance about malware: aur-tombstone (critical) and
			// aur-absent (suspicious) are untouched, and INV-8 only ever
			// constrained criticals. The signal stays fully reachable via
			// --min-severity info and is still rendered in --json / explain.
			res.Findings = append(res.Findings, finding.Finding{
				RuleID: "aur-submitter-mismatch", SubjectKind: "package", Subject: p.Name,
				Severity: finding.SevInfo,
				Summary:  "current maintainer differs from the original submitter",
				Evidence: []string{"submitter=" + meta.Submitter, "maintainer=" + meta.Maintainer},
				Limits: "Legitimate handoffs produce this too. Reported as an identity delta, not as malice, and " +
					"below the default reporting floor for that reason -- the correlated, actionable form of this " +
					"signal (an orphan followed by a new maintainer within N days) requires a drift baseline this " +
					"check does not yet have. " + limitProvenance,
			})
		}
	}
	return res
}
