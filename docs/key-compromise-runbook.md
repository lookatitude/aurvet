# Key-compromise runbook — indicator bundle signing keys

**Status: written before the first release, deliberately.** A runbook written
during an incident is written badly: under time pressure, by whoever is awake,
with the attacker still holding whatever they took. This document exists so the
decisions are made now, calmly, and the incident is an execution problem rather
than a design problem.

It covers the P5 indicator-bundle trust path only. Release-artefact signing is
`docs/RELEASING.md`; the local baseline trust chain is a different key set with a
different owner and a different failure mode.

---

## 0 · The trust path, in one paragraph

Three **root keys**, held offline on hardware tokens by three people. Two of the
three sign a **delegation document**, which names one or two short-lived
**online signing keys** with explicit `not_before` / `not_after` windows. The
online key signs **indicator bundles**. Roots never sign a bundle; bundles never
carry a key. Clients hold an **anti-rollback floor** in root-only local state
(`/var/lib/aurvet/bundle-floor.json`, `0600`) recording the highest bundle
version and delegation serial they have accepted.

Consequences that shape everything below:

- Rotating the **online** key ships **no new binary**.
- Rotating the **root** set requires a new binary, because the root set is
  compiled in.
- Old signatures never expire on their own. Anything superseded is stopped by a
  **version floor** or a **serial floor**, not by cryptography.

---

## 1 · Roles

Name real people in the private incident notes; the roles are what matters here.

| Role | Holds | Does |
| --- | --- | --- |
| **Root holder A / B / C** | one hardware token each | signs delegations; two of three suffice |
| **Publisher** | the online signing key, the publishing pipeline | signs and uploads bundles |
| **Coordinator** | nothing | runs the incident, owns the public statement |

**No single person may hold two root tokens.** If two live in the same drawer,
the set is 2-of-2 in practice and the whole scheme is one burglary deep.

---

## 2 · Scenario A — the online signing key is compromised

**Symptoms.** Publishing infrastructure breach; an unexplained bundle version;
an operator reporting a bundle nobody published; the key file readable where it
should not be.

**Blast radius.** The attacker can sign bundles until `not_after`. They **cannot**
name a new key (bundles cannot introduce keys), **cannot** roll a client back
below its floor, and **cannot** publish a version below any version a client has
already accepted. What they *can* do is publish a **higher** version with
detections removed — which is why clients report the active indicator count on
every run and refuse a bundle with zero active indicators.

**Do this, in order.**

1. **Coordinator** declares the incident and freezes the publishing pipeline.
   Stop publishing before you understand anything: a second attacker-signed
   bundle during triage is worse than a few hours of stale data. Clients degrade
   to coverage-incomplete on expiry; they do not report clean.
2. **Publisher** generates a new online key **on a clean machine**, and records
   its fingerprint.
3. **Two root holders** sign a new delegation with:
   - `serial` **strictly greater** than the last published one — this is what
     stops the old delegation, whose root signatures remain valid forever, from
     being replayed to reinstate the compromised key;
   - the compromised key **absent** — do not "expire it early", remove it;
   - the new key's window ≤ 90 days.
   Signing happens with both tokens present, over the **canonical bytes** of the
   delegation. Verify the document you are signing, on the host it will be
   published from, before touching the token.
4. **Publisher** publishes the new delegation and a new bundle at a version
   above the highest the attacker used. If the attacker's version is unknown,
   use a version comfortably above anything you have ever published; version
   numbers are cheap.
5. **Coordinator** publishes a statement naming: the compromised key
   fingerprint, the window in which it could have signed, the bundle versions
   known to be legitimate, and the new key fingerprint.
6. **Operators** run `aurvet update`. Nothing else is required of them: no
   binary changes, no configuration changes.

**What the design does not give you.** A client that fetched an attacker's
bundle and accepted it has raised its own floor to that version. Publishing a
*lower* legitimate version will be refused as a rollback — correctly. Always
publish forward.

**Residual risk to state out loud.** Between the compromise and step 4, any
client that updated may hold an attacker-signed bundle. Its indicator count and
version are printed by `--version`; the statement in step 5 is what lets an
operator check theirs.

---

## 3 · Scenario B — one root key is compromised (2-of-3 still holds)

**Blast radius.** None, by itself. One key cannot sign a delegation: the
threshold counts **distinct** root keys, and one key signing twice is refused.
The attacker has a token and needs a second one.

This is the scenario the 2-of-3 split exists for, and the correct response is
unhurried but not optional — a second compromise later turns this into
Scenario C, and by then the first one is old news.

**Do this, in order.**

1. **Coordinator** confirms with the two uncompromised holders that their tokens
   are physically in their possession. Not "should be" — looked at.
2. **The two uncompromised holders** immediately sign a delegation with an
   incremented serial, so the current online key does not depend on any document
   the compromised holder participated in.
3. **Provision a replacement root key** on a new token, held by a new (or the
   same, if the compromise was environmental rather than personal) holder.
4. **Ship a new binary** with the new root set at generation *n+1*. This is
   unavoidable: the root set is compiled in, precisely so a network attacker
   cannot change it. Announce the new fingerprints; they are printed by
   `--version`.
5. **Retire generation *n*** once adoption is reasonable — see §5.

**Do not** attempt to "revoke" the compromised root key by publishing a
delegation that excludes it. Delegations do not name root keys, and the
compromised key remains a valid member of the compiled-in set in every binary
already installed. Retirement (§5) is the only mechanism.

---

## 4 · Scenario C — two root keys are compromised (it does not hold)

**Be honest about this one.** An attacker with two of three root tokens can sign
delegations that every released binary accepts. They can name their own online
key, publish bundles, and — because retirement is itself a root-signed
delegation — retire the set out from under you. There is no cryptographic
recovery inside the system. The trust anchor is gone.

The only recovery is **out-of-band**, and it is a distribution problem, not a
cryptography problem.

**Do this, in order.**

1. **Coordinator** publishes, through every channel the project controls (repo,
   website, package repository, mailing list, and the distribution's security
   channel), a statement that generation *n* is compromised and that **no bundle
   should be trusted** until a new binary is installed. Say plainly that an
   attacker may publish a convincing retirement or upgrade notice; the
   authoritative source is the repository, not the update channel.
2. **Ship a new binary** with a generation *n+1* root set, built and signed
   through the release path (`docs/RELEASING.md`) — a different key set, which
   is why keeping them separate matters. Publish the new fingerprints in the
   same statement, and in the repository, so an operator can compare
   `aurvet --version` against a source the attacker does not control.
3. **Do not retire generation *n* using generation *n*'s keys.** The attacker
   has those keys and can sign a competing retirement whose upgrade message
   points wherever they like. Retirement is only meaningful when the root set
   is still yours.
4. **Assume every generation *n* bundle is suspect**, including ones published
   before the compromise was discovered, unless their digests were recorded
   independently.

**Prevention is the real control.** Three tokens, three people, three locations,
and a documented rule that no two travel together. If that rule is ever broken,
treat it as a near miss and write it down.

---

## 5 · Retirement — reaching users on an old binary

The problem: a binary compiled with generation *n* trusts generation *n*. It has
no idea generation *n+1* exists, and nothing signed by *n+1* means anything to
it. Only *n*'s own holders can tell it anything it will listen to.

So retirement is a **root-signed delegation** with:

- `root_set_retired: true`
- `signing_keys: []` — a retirement that still delegates is not a retirement,
  and is refused
- `upgrade_message` — mandatory, and it must be **actionable**

The client refuses every bundle, prints the upgrade message, and reports
indicator coverage as unavailable. Every other subsystem — provenance,
integrity, surfaces, baseline — keeps working: retirement removes indicator
coverage, not the tool.

**A good upgrade message names a version, a place, and a way to check.**

> root generation 1 was retired on 2027-02-01. Install aurvet >= 0.4.0, whose
> generation 2 root set is published at https://aurvet.dev/roots; compare the
> fingerprints printed by `aurvet --version` against that page and against the
> release announcement before trusting it.

**Sequencing.** Ship the new binary *first*, give it time to propagate, and
retire the old set only when the alternative is available. Retiring first leaves
every user with a tool that refuses bundles and no build to move to, which
teaches them to ignore the message.

**What retirement cannot do.** It cannot reach a client that never fetches
another delegation. A user who never runs `aurvet update` again keeps their
bundle until `valid_until`, then degrades to coverage-incomplete — which is the
correct end state, and is why an infinite `valid_until` is not spellable.

---

## 6 · Freeze — the attack nobody signs

An attacker who can withhold updates (a hostile mirror, a network position, a
seized domain) does not need any key. They serve the last legitimate bundle
forever. Every signature verifies, the version never goes backwards, the
prev-digest chain is intact. Nothing is forged.

**What catches it, in order of reliability:**

1. `valid_until`. This is the real bound. A freeze becomes an expiry within one
   bundle lifetime, and expiry degrades coverage — it never reports clean. Keep
   bundle lifetimes short enough that this bound means something; a one-year
   `valid_until` is a one-year freeze window.
2. The delegation's own expiry, likewise.
3. The client's **silence hint**: no new bundle accepted in 14 days while checks
   have been happening. It cannot distinguish an attacker from a quiet
   publisher, and it says so.

**What the operator must do**, because nothing automatic can: compare the bundle
version in `aurvet --version` against the version published in the repository.
That comparison is the only thing that closes the gap, and it belongs in the
documentation the same way it belongs here.

**Publisher obligation.** Publish on a predictable cadence, and publish the
current version somewhere separate from the update channel. A channel that is
its own only witness cannot testify about itself.

---

## 7 · Drill

Run this before the first release and once a year, on test keys, end to end:

1. Generate a throwaway 3-key root set and a delegation. Verify a bundle.
2. Rotate the online key with an incremented serial. Confirm the old delegation
   is refused by the serial floor.
3. Attempt to publish a lower bundle version. Confirm the rollback refusal.
4. Attempt a 1-of-3 delegation, and a delegation with one key signing twice.
   Confirm both are refused.
5. Retire the set. Read the upgrade message as though you had never seen this
   document and ask whether you would know what to do.

Steps 2–4 are covered by `internal/bundle/attack_test.go`. Step 5 is the one
that needs a human, because "actionable" is not a property a test can assert.
