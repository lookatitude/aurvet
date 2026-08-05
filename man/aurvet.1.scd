aurvet(1)

# NAME

aurvet - detect compromised AUR packages and verify a system has not been
tampered with

# SYNOPSIS

*aurvet* [_flags_] *scan*++
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

*-show-recipe*
	*review*/*install* only: print the recipe text in full in addition to the
	rule hits and the diff. Off by default because a gate that prints a
	400-line PKGBUILD every time teaches its operator to scroll past it.

*-since-last*
	*scan* only: list only findings that are new since the previous stored
	scan. The exit code still reflects the full result, not the filtered
	view.

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
