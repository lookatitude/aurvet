aurvet(1)

# NAME

aurvet - detect compromised AUR packages and verify a system has not been
tampered with

# SYNOPSIS

*aurvet* [_flags_] *scan* [*-pkg* _name_]... [*-allow-degraded*]++
*aurvet* [_flags_] *diff*++
*aurvet* [_flags_] *baseline* *init*|*append*|*status*|*show*|*verify*|*pushed*|*diff*++
*aurvet* [_flags_] *triage* *ack*|*snooze*|*note* _fingerprint_|*list*|*drop* _fingerprint_++
*aurvet* [_flags_] *adjudicate* _fingerprint_|*list*|*revoke* _fingerprint_++
*aurvet* [_flags_] *bundle* _fingerprint_ [_directory_]++
*aurvet* [_flags_] *update* [*-check*]++
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
	report findings and coverage gaps. Takes no positional arguments.

	*It requires root, and refuses to run unprivileged unless
	*-allow-degraded* is passed.* The reason is measured rather than
	stylistic: 25 of this system's package-owned files cannot be opened by an
	ordinary user, and an unprivileged *-tier full* run produces 32
	permission-denied coverage gaps -- so under INV-3 it could never exit
	*0*, and an exit code that is always *3* teaches its reader that *3*
	means nothing. *-offline-root* is exempt; see *-allow-degraded*.

	*-pkg* restricts the run to named packages. A *-pkg* run is a question
	about packages and not about the system: the whole-system passes do not
	run, and its report is not persisted as this host's baseline.

*diff*
	Classify drift against the signed baseline into corroborated,
	adjudicated, unexplained and log-coverage-gap. Identical to *baseline*
	*diff*; both spellings exist because both are typed. Takes no arguments.

*baseline* *init*|*append*|*status*|*show*|*verify*|*pushed*|*diff*
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

	*status* prints the chain, the unpushed tail and what was not checked;
	*show* is the same command under the name the specification uses.
	*verify* verifies the chain against the last confirmed push and exits *3*
	when no anchor exists, because truncation is then unchecked. *pushed*
	*-remote* _url_ records that the chain has been pushed; it runs no *git*
	and holds no credentials. *diff* classifies drift against the baseline
	into corroborated, adjudicated, unexplained and log-coverage-gap, and is
	also spelled *aurvet diff*.

	Signing needs a key you supply: *-key* _file_ or *-signer* _fingerprint_
	(an *ssh-agent* key, which is also the FIDO2 route). aurvet generates no
	keys.

	*A pushed chain is what makes truncation detectable at all*: entries
	removed from the end of a chain leave one that still verifies. And the
	remote's *force-push denial and branch protection are load-bearing
	security controls*, not repository hygiene -- push credentials
	necessarily live on the monitored machine, so the host being watched can
	write to the record of what happened on it.

*triage* *ack*|*snooze*|*note* _fingerprint_|*list*|*drop* _fingerprint_
	The *lightweight* layer: local, *unsigned*, keyless, expiring. Spec §12 asks
	for three weights and not two, because a design whose only suppression is a
	signed judgement is a design whose users over-suppress or ignore the output.

	*It cannot unblock* *baseline* *init*. That refusal is decided from the signed
	adjudication store and nothing else, and no code path joins the two stores.
	A keyless record that could satisfy the strongest gate in the tool would make
	the middle weight a bypass of the top one.

	*ack* -- seen and expected. Hidden from the default *scan* listing until it
	expires; 30 days by default, 90 at most.

	*snooze* -- not now. The same, for a *shorter* window: 7 days by default, 30
	at most, and every rendering of it says when it comes back.

	*note* -- annotation only. *It suppresses nothing*: the finding is still
	listed in full, with the note beside it. *-reason* is required, because the
	note is the whole point of the verb. This is the one an investigation reaches
	for, and one that quietly hid something would be the worst of the three.

	What a record hides, it hides *from the listing only*. The exit code, the
	coverage verdict and the persisted report all still count a triaged finding,
	and *scan* prints how many it is not showing above the findings. A local
	unsigned file must not be able to turn a critical into exit *0*.

	Two scopes: *pin* (this exact evidence, the default; spent by any change to
	it) and *subject* (this rule for this one package or path). *Rule scope is
	not offered here* -- turning a check off everywhere is a standing property of
	the host, is echoed in every later run header, and an unsigned record with no
	author cannot answer the question that header provokes. Use *adjudicate*
	*-scope* *rule* *-force-rule-scope*, which is signed and attributable.

	A record whose rule's matching semantics move reads *stale*, is preserved
	verbatim and suppresses nothing, exactly as an adjudication does. A rule that
	declares no fingerprint epoch *can* still be triaged -- unlike an
	adjudication -- and the record then says, in words, that it cannot be told
	stale; the cost of being wrong is bounded by the expiry.

	A coverage *gap* can never be triaged (INV-3): a gap says something was not
	examined, and no acknowledgement turns unexamined into examined.

	*list* shows every record and what it is currently doing, including what it
	is hiding and which records will never do anything again. It exits *1* when
	any record needs attention (stale, expired, spent or dead) and *3* when a
	record could not be read at all. *drop* removes a record by fingerprint.

	The four writing verbs refuse under *-offline-root* (INV-5). *list* reads and
	is allowed.

*adjudicate* _fingerprint_|*list*|*revoke* _fingerprint_
	Record, list or withdraw a signed judgement about one finding: "I looked at
	this, here is why it is acceptable, and here is when that has to be decided
	again". This is what *baseline* *init*'s refusal tells you to run.

	*-reason* is mandatory and is stored inside the signed document -- and, once
	*baseline* *init* runs, inside the signed manifest. A suppression with no
	stated reason cannot be re-evaluated by anyone, including whoever made it, so
	there is no way to record one.

	Every judgement EXPIRES: 180 days by default, 365 at most, *-expiry-days* to
	choose. There is no non-expiring form, because a permanent suppression is
	indistinguishable a year later from a check that was never written.

	Three scopes, and they are not interchangeable. *pin* (the default) covers
	this exact evidence and is spent by any change to it. *subject* covers this
	rule for this one package or path, across upgrades. *rule* turns the check
	off *everywhere*, needs *-force-rule-scope*, and is echoed on every later run.

	*list* shows what is being suppressed and, more importantly, what is not:
	a record whose rule's matching semantics have moved reads *stale*, is
	preserved verbatim, and suppresses nothing until re-adjudicated. It exits *1*
	when any record needs attention (stale, expired, spent or dead) and *3* when
	a record could not be read at all.

	*revoke* withdraws a judgement, by either the record's own fingerprint or
	the finding id that created it. Anything it was hiding is reported in full
	from the next run on.

	A coverage *gap* can never be adjudicated (INV-3): adjudicating "I could not
	examine this" would turn unexamined into clean. Signing needs a key you
	supply, the same as *baseline*.

*bundle* _fingerprint_ [_directory_]
	Emit a redacted, self-contained fixture root reproducing one finding, so that
	a false-positive report can be a test case instead of a description. The
	directory defaults to *./aurvet-bundle-*_fingerprint_ and must be empty.

	*What a bundle contains, exactly.* *No file's own bytes are copied.* Every
	regular file in it is either a zero-byte placeholder -- real path, real mode,
	real mtime, contents never read -- or a file *rebuilt* from the handful of
	directives aurvet's compiled checks parse: *ExecStart=* and its siblings,
	*Exec=*, *TryExec=*, *When=*, *Type=*, the enablement keys, and the path list
	of _ld.so.preload_. Comments, *Environment=*, *EnvironmentFile=*, *User=*,
	*Description=* and every other directive are dropped unread, because the
	filter is an allowlist: a directive nobody thought of is withheld by default.

	Within a kept command, *only the program is written and the arguments are
	withheld*: *ExecStart=/usr/local/bin/backup --token* _<secret>_ is emitted as
	*ExecStart=/usr/local/bin/backup*. The allowlist alone was not enough here --
	the directive is kept for a good reason and a secret in its arguments rode
	along inside it. Nothing is lost: aurvet attributes ownership from the first
	token and reads nothing past it, so the finding still reproduces with the same
	fingerprint. An argument is uninspected free text from the reporting machine,
	and it is treated the same way *Environment=* is. Each rebuilt file's entry in
	_MANIFEST.json_ and in the README table counts the arguments it withheld.

	Package database entries are *synthesised* from parsed fields -- *%NAME%*,
	*%VERSION%*, *%BASE%*, *%VALIDATION%*, *%INSTALLDATE%*, and a *%FILES%* list
	narrowed to the paths the bundle carries. *%PACKAGER%* -- your own name and
	address on anything you built locally -- is never written. Only packages that
	own a path in the bundle are included: a bundle is not your installed-software
	inventory.

	_etc/passwd_ and _etc/pacman.conf_, where present, are *invented* from the
	bundle's own contents: the users whose home directories it already carries,
	and the *HookDir* lines its own hooks need. Neither is a copy of yours.

	*Home paths.* Absolute paths under _/home_ inside file contents are rewritten
	to _/home/redacted/redacted_. A home path that the finding *is about* -- an
	emitted file, or a program an emitted entry point resolves to -- keeps its own
	spelling, because without it the bundle reproduces nothing; every such path is
	printed before you send it and listed in the bundle's own *README.md*. Where
	the redacted path is the *program* an *Exec* directive names, the bundle says
	the finding does not reproduce rather than shipping a fixture that produces
	something else, and the path is printed to your terminal and nowhere in the
	bundle.

	*What does not reproduce.* Integrity findings need a file's contents and its
	package's mtree; AUR provenance findings need a network response; drift needs
	a signed baseline; correlation depends on when the bundle is opened. Those
	classes are *labelled in the bundle* rather than emitted as a fixture that
	quietly finds nothing, and a rule this build has not classified is reported as
	not reproducing rather than assumed to work.

	*README.md* states all of the above per file, and *MANIFEST.json* carries the
	same for a machine. Exit *0* when the bundle was written and this class of
	finding reproduces from it, *2* for no such finding id or an unusable
	destination, *3* when it was written but the class cannot be reproduced or
	something it meant to include could not be read. It never exits *1*: it
	reaches no verdict about the system.

	Under *-offline-root* the destination must lie *outside* the examined tree
	(INV-5).

*update*
	Fetch and verify the indicator bundle. *Never automatic* -- nothing else in
	aurvet reaches the network for indicator data, and the shipped timer is not
	enabled by the package.

	The bundle's signature is verified over the raw bytes *before* anything
	parses them, against a short-lived online key named by a delegation that the
	offline 2-of-3 root key set signed. A bundle can never introduce a key. A
	version below the anti-rollback floor recorded in root-only state is refused,
	as is a bundle whose *prev_digest* names the wrong predecessor. Size cap,
	timeout, and no cross-host redirects.

	It fails closed and it never reports clean: an expired bundle degrades the
	run to coverage-incomplete (exit *3*) while still matching its indicators,
	because stale data still finds known-bad things; a retired root key set
	refuses with the publisher's upgrade message; and the *active indicator
	count* is printed in every state, because a signed bundle that *removes*
	detections is an attack rather than an update.

	Nothing that failed verification is ever cached, and *-offline-root* is a
	usage error rather than a silent no-op: an update writes, and INV-5 forbids
	writing under the examined tree. *-check* reaches the same verdict and
	writes neither the cache nor the floor.

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
	Print build identity (version, commit, toolchain), followed by the
	indicator bundle trust facts: the embedded root key fingerprints, the
	delegation expiry, and the cached bundle version with its active
	indicator count. Identical to *-version*.

	The build identity is printed first and unconditionally, and every
	failure below it renders as a line rather than an error -- the moment you
	need to know which build you are running is usually the moment the system
	is broken, so an unreadable cache produces a sentence and not a non-zero
	exit. A build with no embedded root keys prints that *refusal*, because a
	blank where a fingerprint should be is indistinguishable from a
	fingerprint that failed to load.

# FLAGS

*-allow-degraded*
	*scan* only: proceed unprivileged. The report is stamped *DEGRADED* above
	the findings, the shortfall is recorded as a *privilege-coverage* coverage
	gap, and the run therefore cannot exit *0* even when nothing else is
	missing -- "I could not look everywhere" is the finding. Without it, an
	unprivileged live *scan* is a refusal (exit *2*) that names both ways
	forward.

	*-offline-root* is exempt from the refusal and needs no flag. The
	measurement behind the policy is a property of a live root whose sensitive
	files belong to uid 0 while the process does not; a mounted or extracted
	tree is readable to the extent its ownership allows, and an unprivileged
	scan of a user-owned offline root produces zero permission-denied gaps, so
	exit *0* stays reachable there and exit *3* keeps its meaning. Passing
	*-allow-degraded* with *-offline-root* is still honoured, for a mount that
	does preserve root-only modes.

*-bundle-url* _url_
	*update* only: the indicator bundle origin to fetch from. The default origin
	is compiled in; the signature, not the URL, is what makes a bundle
	trustworthy, so naming another origin is legitimate and deliberate.

*-check*
	*update* only: report what an update would do and write nothing -- no
	cached bundle, no advance of the anti-rollback floor. The delegation and
	the bundle are still fetched, authenticated and judged in full, because a
	preview that reported less than the real verdict could not be acted on;
	*internal/bundle* separates deciding from persisting, so this suppresses
	the two writes and nothing else.

*-expiry-days* _n_
	*adjudicate* and *triage*: how many days the record lasts. There is no value
	meaning never, in either weight.

	*adjudicate*: default 180, maximum 365. *triage*: default 30 and maximum 90
	for *ack* and *note*, default 7 and maximum 30 for *snooze* -- every triage
	window is shorter than an adjudication's default, because the lighter weight
	must not outlive the heavier one.

*-force-rule-scope*
	*adjudicate* only: the explicit force *-scope rule* requires. A rule-scope
	judgement turns a whole check off for every package and path on the host,
	which is a standing property of the system rather than a detail of one
	finding.

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

*-pkg* _name_
	*scan* only, repeatable: analyse only the named package. A name the local
	database does not carry is a *usage error* naming it, never an empty
	result -- a typo that scanned nothing and exited *0* would be a false
	clean produced by a keystroke.

	Two consequences are stated in the report above its findings rather than
	left to be discovered. The whole-system passes -- surface enumeration,
	correlation and the unowned-setuid sweep -- do *not* run, because the
	ownership oracle is built from the named packages alone and every other
	file on the system would read as owned by nobody; and the report is *not*
	persisted, because a scoped result stored as this host's baseline would
	make every other finding read as new on the next *-since-last*. Collection
	is not narrowed either: the same paths are read, so *-pkg* costs what a
	full scan costs and buys scope rather than speed.

*-protected-remote*
	*baseline pushed* only: assert that the remote named by *-remote* denies
	force-push and protects the branch. aurvet cannot check this itself -- it
	runs no *git* -- so the flag records your assertion, and the assertion is
	what makes the anchor mean anything. Without it the anchor is recorded as
	unprotected and truncation of the chain remains possible from the very
	machine being watched.

*-reason* _text_
	*adjudicate*: why the finding is acceptable. Mandatory, and recorded inside
	the signed document rather than printed and forgotten. Whitespace and tokens
	too short to re-evaluate ("ok", "n/a") are refused.

	*triage*: the note. Required by *triage* *note*, which exists to carry it, and
	optional for *ack* and *snooze* -- demanding twelve considered characters
	before an operator may dismiss an *info* finding about their own unit would
	rebuild the friction the middle weight exists to remove. The bound on being
	wrong there is the expiry, not the prose.

*-remote* _url_
	*baseline pushed* only: the remote the chain was pushed to, e.g.
	_git@host:repo.git#refs/heads/main_. Recording a push is what makes
	truncation detectable; aurvet performs no push and holds no credentials.

*-scope* _pin_|_subject_|_rule_
	*adjudicate* and *triage*: the blast radius of the record. Defaults to *pin*,
	the narrowest, in both. *rule* is *adjudicate* only and additionally needs
	*-force-rule-scope*; see *triage* above for why an unsigned record may not
	have it.

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

*-version*
	Print build identity, the embedded root key fingerprints, the delegation
	expiry and the cached bundle version, then exit *0*. Identical to the
	*version* subcommand. Compare the fingerprints against a source an attacker
	does not control: they are the only thing that distinguishes two builds on
	the property that decides whether indicator data can be trusted at all. A
	build with no embedded root keys prints that *refusal* rather than a blank,
	because a blank is indistinguishable from keys that failed to load.

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
