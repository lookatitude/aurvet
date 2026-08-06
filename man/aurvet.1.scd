aurvet(1)

# NAME

aurvet - detect compromised AUR packages and verify a system has not been
tampered with

# SYNOPSIS

*aurvet* [_flags_] *scan*++
*aurvet* [_flags_] *baseline* *init*|*append*|*status*|*verify*|*pushed*|*diff*++
*aurvet* [_flags_] *review* _dir_|_pkgbase_++
*aurvet* [_flags_] *install* _pkgbase_++
*aurvet* [_flags_] *snapshot* _pkgbase_++
*aurvet* [_flags_] *explain* _fingerprint_++
*aurvet* *doctor*++
*aurvet* *version*

# DESCRIPTION

*aurvet* reads. It parses package databases, recipes and on-disk state, and it
reports what it found. It never executes a PKGBUILD, never runs *makepkg*(8)
and never runs your AUR helper (INV-2). Every command below is an analysis; the
build, if there is one, remains your action.

Flags may appear before or after the subcommand. Both _-flag_ and _--flag_
spellings are accepted, as is _-flag=value_.

# COMMANDS

*scan*
	Sweep the whole system: load the local and sync package databases,
	establish provenance for every foreign (non-repository) package, and
	report findings and coverage gaps. Takes no arguments.

*baseline* *init*|*append*|*status*|*verify*|*pushed*|*diff*
	The signed baseline and its append-only trust chain.

	*init* runs a scan and signs the first baseline -- but refuses while any
	unresolved critical finding exists (each must be adjudicated with a
	recorded reason), refuses unprivileged, refuses a scan shallower than
	*full* tier, refuses while _db.lck_ exists, and refuses any coverage gap
	not declared recordable. Signing a baseline over a compromise makes the
	compromise the reference point, and every later run then reports "no
	change".

	*append* writes a later entry on the same terms: the refusals are the same
	ones, because every condition that protects the first entry protects the
	rest. It additionally refuses while _db.lck_ exists -- reading a package
	database mid-transaction produces spurious findings, and here they would
	be signed.

	*status* prints the chain, the unpushed tail and what was not checked.
	*verify* verifies the chain against the last confirmed push and exits *3*
	when no anchor exists, because truncation is then unchecked. *pushed*
	*-remote* _url_ records that the chain has been pushed; it runs no *git*
	and holds no credentials. *diff* classifies drift against the baseline
	into corroborated, adjudicated, unexplained and log-coverage-gap.

	Signing needs a key you supply: *-key* _file_ or *-signer* _fingerprint_
	(an *ssh-agent* key, which is also the FIDO2 route). aurvet generates no
	keys.

	*A pushed chain is what makes truncation detectable at all*: entries
	removed from the end of a chain leave one that still verifies. And the
	remote's *force-push denial and branch protection are load-bearing
	security controls*, not repository hygiene -- push credentials
	necessarily live on the monitored machine, so the host being watched can
	write to the record of what happened on it.

*review* _dir_|_pkgbase_
	Analyse one recipe and never build it. Leads with the rule hits and the
	diff against the last approved recipe for that pkgbase, so what changed
	is what you read first. The full recipe text is printed only with
	*-show-recipe*.

*install* _pkgbase_
	The gate. Fetches the recipe, resolves and reviews the entire AUR
	dependency closure, prints the closure tree, prompts, and only then
	records the approval, captures a provenance snapshot and hands the
	vetted staging directory over. Only the literal answer *yes* proceeds;
	*y*, an empty line and EOF (a pipe, a cron job) all decline. Declining
	approves nothing, captures nothing and hands nothing over. aurvet does
	not build the package: the staged directories are yours to build.

*snapshot* _pkgbase_
	Capture provenance for one pkgbase. The subject is a *pkgbase*, not a
	package name -- one recipe can build several packages -- and it is one
	subject, not a list, so the exit code is never ambiguous about whose
	evidence was incomplete.

*explain* _fingerprint_
	Re-run the sweep and print the rationale behind one finding: which rule
	fired, on what evidence, and what would make it stop firing. A
	successful *explain* always exits *0*; it is a query against the
	findings, not a verdict on the system.

*doctor*
	Print the resolved configuration -- each key, its value and where that
	value came from -- and warn about degraded resolutions. Touches no
	network.

*version*
	Print build identity (version, commit, toolchain) and exit. Resolves no
	configuration and reads no files, deliberately: the moment you need to
	know which build you are running is usually the moment the system is
	broken.

# FLAGS

*-json*
	Emit machine-readable JSON on stdout instead of text. Exactly one JSON
	document is written to stdout; prompts, warnings and progress go to
	stderr.

*-key* _file_
	*baseline* only: an OpenSSH ed25519 private key file to sign the baseline
	with. aurvet generates no keys; the key is yours to create and to protect.
	An encrypted key file is not supported -- load it into *ssh-agent* and use
	*-signer*. If both are given, *-key* is used.

*-min-severity* _info_|_suspicious_|_critical_
	Reporting floor. Defaults to the configured value. An unrecognised value
	is a usage error, never a silent fallback. See *SEVERITY FLOOR* below
	for what it does *not* do.

*-no-network*
	Skip every outbound request. The checks that needed the network become
	coverage gaps, never absence findings, so a *-no-network* run can never
	exit *0*.

*-offline-root* _path_
	Examine a mounted filesystem instead of the running system, for
	inspecting a machine from a rescue environment. Nothing is written under
	_path_ (INV-5): the report is not persisted and *-since-last* is
	therefore unavailable in this mode.

*-protected-remote*
	*baseline pushed* only: assert that the remote named by *-remote* denies
	force-push and protects the branch. aurvet cannot check this itself -- it
	runs no *git* -- so the flag records your assertion, and the assertion is
	what makes the anchor mean anything. Without it the anchor is recorded as
	unprotected and truncation of the chain remains possible from the very
	machine being watched.

*-remote* _url_
	*baseline pushed* only: the remote the chain was pushed to, e.g.
	_git@host:repo.git#refs/heads/main_. Recording a push is what makes
	truncation detectable; aurvet performs no push and holds no credentials.

*-show-recipe*
	*review*/*install* only: print the recipe text in full in addition to the
	rule hits and the diff. Off by default because a gate that prints a
	400-line PKGBUILD every time teaches its operator to scroll past it.

*-signer* _fingerprint_
	*baseline* only: the fingerprint of a key held by *ssh-agent* to sign
	with. This is also the FIDO2 route: a token-held _sk-ssh-ed25519_ key
	appears in the agent like any other, so the signing key can be one that
	cannot be copied off the machine. Requires _SSH_AUTH_SOCK_.

*-since-last*
	*scan* only: list only findings that are new since the previous stored
	scan. The exit code still reflects the full result, not the filtered
	view.

*-tier* _meta_|_triage_|_full_|_paranoid_
	How much of each file a verification pass examines. Defaults to *full*.
	An unrecognised value is a usage error on every subcommand, never a
	silent fallback: a typo in a systemd unit or a cron line must not quietly
	downgrade verification.

	*meta*
		Reads no file contents at all. Every recorded path is still opened
		once, confined, and stat'd from that descriptor -- so a missing
		file, a swapped symlink and a fifo are all still established --
		but nothing is hashed. Every observation is therefore
		metadata-assisted by construction.
	*triage*
		Hashes two populations: everything whose stat disagrees with the
		record, and -- unconditionally, whatever stat says -- the
		security-relevant subset, which is every symlink and everything
		executable, setuid, setgid or sticky in the record's own mode.
		Those are the files whose contents decide what runs on the
		machine, so they are never delegated to mtime, which an attacker
		who can write the file can also set. Configuration under _/etc_ is
		deliberately *not* in the subset: it is the noisiest population on
		a real system and would spend the whole budget on the files whose
		difference says the least.
	*full*
		The default. Hashes every path with a recorded digest, skipping
		only the derived exemptions -- files pacman itself rewrites, where
		a read buys a known-useless answer at real I/O cost.
	*paranoid*
		*full*, and additionally hashes the exempt paths, so the exemption
		set can be audited rather than trusted.

	*The tier a run reports is derived from the work it actually did; the
	flag never asserts it.* The flag selects the bargain; the report states
	what was examined. Anything a weaker tier did not look at is reported as
	a coverage gap, not as silence (INV-3), and any verdict that rested on
	metadata is marked as such so it is never presented as being as strong as
	a digest. That is the whole difference between an operator-chosen tier
	and a silently sampled scan. Concretely: a run that asked for *full* and
	verified no file contents prints the tier it actually reached and records
	the shortfall as a coverage gap -- it does not relabel the request as the
	result.

	*baseline* *init* and *append* refuse a scan shallower than *full*: a
	baseline is the reference point every later run is judged against, so
	signing one over unexamined files makes the unexamined state the
	definition of correct.

# EXIT STATUS

The exit codes are a contract. Automation branches on them, so they do not
drift.

[[ *Code*
:[ *Meaning*
|  0
:  Analysis completed and covered what it was asked to cover; nothing at or
   above the reporting floor.
|  1
:  Analysis completed; findings at or above the floor were reported.
|  2
:  The invocation itself was wrong: unknown subcommand, bad arguments, an
   unparseable severity, or a failure before any analysis could begin.
|  3
:  Coverage was incomplete. Something aurvet was asked to examine could not be
   examined.

*3 outranks 1.* An incomplete scan that also found something is still an
incomplete scan; a caller that sees *1* is entitled to conclude "here is the
full picture", and with gaps present that conclusion would be false. Both *1*
and *3* are failures under systemd, so nothing is hidden by preferring *3* --
the findings are still rendered in full.

Do not mask *1* or *3* in a service unit with _SuccessExitStatus=_. That
converts a finding into silence. Use _OnFailure=_ instead.

# SEVERITY FLOOR

*-min-severity* gates *findings only, never coverage gaps.*

A finding's severity says "here is something I examined and judged". A gap says
"here is something I could not examine at all", and how severe the rule would
have been is unrelated to the fact that the subject went unexamined. If the
floor could suppress gaps, raising it would quietly convert unexamined subjects
into an exit *0* -- the false clean that INV-3 exists to forbid.

The accepted cost: on a system with incomplete AUR provenance, exit *3* is the
normal outcome, and raising the floor will not silence it. The gap list in the
report is where the detail lives.

# FILES

_/var/lib/aurvet_
	System state directory, used when running as root. Holds
	_reports/_ (scan history and the *-since-last* baseline),
	_snapshots/_ (captured provenance) and _approvals/_ (recorded
	approvals). Mode *0700*, owned by root. aurvet refuses to use an
	approval store that is group- or world-writable, or one owned by an
	account other than root or the invoking user: whoever can write the
	approval store can approve their own recipe.

_$XDG_STATE_HOME/aurvet_
	State directory for an unprivileged live run; falls back to
	_$HOME/.local/state/aurvet_. Consulted only when euid is not 0.

_<offline-root>/var/lib/aurvet_
	Where an *-offline-root* run would resolve state to. It is read, never
	written.

# ENVIRONMENT

*AURVET_STATE_DIR*
	Override the state directory. Honoured *only* when euid is not 0. A
	root-privileged run ignores it entirely, because otherwise an
	unprivileged local account would choose what a privileged security tool
	trusts.

*XDG_STATE_HOME*, *HOME*
	Used to resolve the unprivileged state directory. A relative value is
	ignored rather than joined.

# LIMITATIONS

Read these before you rely on a clean result.

- *A clean result is not evidence of a clean system.* aurvet catches sloppy
  malware: recipes and on-disk artefacts that look wrong to a static rule. An
  attacker who knows aurvet's rules can write a recipe that passes them.
- *aurvet parses; it never executes.* Anything a PKGBUILD computes at build
  time -- a URL assembled from variables, a payload fetched by a helper script
  it sources -- is outside what static analysis can see. Rules report the
  shapes they recognise, not the behaviour they cannot run.
- *Exit 3 is common and it is honest.* Missing AUR metadata, an unreachable
  network and an unreadable database entry are all coverage gaps. Treating them
  as noise defeats the tool.
- *A snapshot proves what was on disk when it was taken*, not that the upstream
  it recorded is trustworthy.

# SEE ALSO

*makepkg*(8), *pacman*(8), *systemd.timer*(5)

# BUGS AND SECURITY

Report bugs at https://github.com/lookatitude/aurvet. Security issues: see
SECURITY.md in the source distribution. For reporting a malicious package to
upstream, see the project's docs/reporting-malware.md.
