// Package systemd holds no Go code either: like packaging/hooks, it exists so
// the shipped units are checked by the same `go test ./...` that checks
// everything else. `systemd-analyze verify` catches misspelled directive names
// -- a typo'd `ProtectSystm=` is silently ignored by systemd and the hardening
// is simply absent -- but it is not in CI's control flow and it cannot express
// the properties that matter here, which are as much about ABSENCE as presence:
//
//   - the scan unit is sealed off the network and the update unit is not;
//   - the bounding set is exactly what internal/privdrop stages at runtime;
//   - OnFailure= exists, because without it exit 1 and exit 3 both render as a
//     red line nobody reads, and a security tool that tells nobody is worse
//     than no security tool;
//   - SuccessExitStatus= does NOT exist, because it is the tempting fix that
//     converts a finding into permanent silence (INV-3, through packaging);
//   - nothing in this repository enables a unit at install time.
//
// An absent OnFailure= is the entire bug task 8 exists to prevent, so it is
// asserted directly rather than inferred.
package systemd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/lookatitude/aurvet/internal/surfaces"
)

const (
	scanService   = "aurvet-scan.service"
	updateService = "aurvet-update.service"
	scanTimer     = "aurvet-scan.timer"
	updateTimer   = "aurvet-update.timer"
	failService   = "aurvet-failure@.service"
)

// directive is one Key=Value as systemd would read it, tagged with its section.
type directive struct {
	Section string
	Key     string
	Value   string
}

// parseUnit reads a unit the way systemd does for the two things that can hide
// a directive from a naive grep: `#`/`;` comment lines, and trailing-backslash
// line continuation. Comment stripping is what lets these files DISCUSS
// SuccessExitStatus= in prose -- naming the wrong fix so it is not
// rediscovered -- while the absence assertion below still means something.
func parseUnit(t *testing.T, name string) []directive {
	t.Helper()
	raw, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	var out []directive
	section := ""
	var joined []string
	var acc string
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimRight(line, "\r")
		if acc == "" {
			lt := strings.TrimSpace(trimmed)
			if lt == "" || strings.HasPrefix(lt, "#") || strings.HasPrefix(lt, ";") {
				continue
			}
		}
		if strings.HasSuffix(trimmed, "\\") {
			acc += strings.TrimSuffix(trimmed, "\\") + "\n"
			continue
		}
		joined = append(joined, acc+trimmed)
		acc = ""
	}
	if acc != "" {
		joined = append(joined, acc)
	}
	for _, line := range joined {
		lt := strings.TrimSpace(line)
		if strings.HasPrefix(lt, "[") && strings.HasSuffix(lt, "]") {
			section = strings.TrimSuffix(strings.TrimPrefix(lt, "["), "]")
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			t.Errorf("%s: line is neither a section nor Key=Value: %q", name, line)
			continue
		}
		if section == "" {
			t.Errorf("%s: directive %q appears before any section header", name, k)
		}
		out = append(out, directive{Section: section, Key: strings.TrimSpace(k), Value: v})
	}
	return out
}

// values returns every value for key, in file order. Empty means the directive
// is absent -- which for several keys below is the property under test.
func values(ds []directive, key string) []string {
	var out []string
	for _, d := range ds {
		if strings.EqualFold(d.Key, key) {
			out = append(out, strings.TrimSpace(d.Value))
		}
	}
	return out
}

func one(t *testing.T, name string, ds []directive, key string) string {
	t.Helper()
	v := values(ds, key)
	if len(v) != 1 {
		t.Fatalf("%s: %s appears %d times, want exactly 1", name, key, len(v))
		return ""
	}
	return v[0]
}

func hasSection(ds []directive, section string) bool {
	for _, d := range ds {
		if strings.EqualFold(d.Section, section) {
			return true
		}
	}
	return false
}

// TestEveryShippedUnitParses is the floor: a unit systemd cannot read is a unit
// that does nothing, silently.
func TestEveryShippedUnitParses(t *testing.T) {
	for _, f := range []string{scanService, updateService, scanTimer, updateTimer, failService} {
		ds := parseUnit(t, f)
		if len(ds) == 0 {
			t.Errorf("%s: parsed to zero directives", f)
		}
		if !hasSection(ds, "Unit") {
			t.Errorf("%s: no [Unit] section", f)
		}
	}
}

// TestScanUnitIsSealedOffTheNetwork. PrivateNetwork=yes on the SCAN unit is the
// strong directive in this package: a filesystem integrity scanner has no
// business reaching the network, and if it is ever subverted by the
// attacker-controlled bytes it parses, the empty network namespace is what
// stops the file inventory it just built from leaving the machine.
func TestScanUnitIsSealedOffTheNetwork(t *testing.T) {
	ds := parseUnit(t, scanService)
	if got := one(t, scanService, ds, "PrivateNetwork"); got != "yes" {
		t.Errorf("%s: PrivateNetwork=%q, want yes", scanService, got)
	}
	// The flag is the polite form of the same request. Keeping both means a
	// cooperating process is constrained by the flag and a subverted one by the
	// namespace.
	if got := one(t, scanService, ds, "ExecStart"); !strings.Contains(got, "--no-network") {
		t.Errorf("%s: ExecStart=%q does not pass --no-network", scanService, got)
	}
}

// TestUpdateUnitIsTheOnlyOneAllowedOut. The split is the whole reason there are
// two units: sealing the scan forces everything needing the network into a
// separate, differently-restricted unit. Asserting the ABSENCE here stops a
// future tidy-up from "harmonising" the two files and silently disabling
// updates -- which would fail closed in the worst way, by looking fine.
func TestUpdateUnitIsTheOnlyOneAllowedOut(t *testing.T) {
	ds := parseUnit(t, updateService)
	if got := values(ds, "PrivateNetwork"); len(got) != 0 {
		t.Errorf("%s: PrivateNetwork=%v is set; the update unit is the network half and must not be sealed", updateService, got)
	}
	// ...and it is network-ONLY: it gets no capabilities and cannot read homes.
	if got := one(t, updateService, ds, "CapabilityBoundingSet"); got != "" {
		t.Errorf("%s: CapabilityBoundingSet=%q, want empty -- fetching and verifying bytes needs no capability", updateService, got)
	}
	if got := one(t, updateService, ds, "ProtectHome"); got != "yes" {
		t.Errorf("%s: ProtectHome=%q, want yes", updateService, got)
	}
}

// TestScanUnitFilesystemHardening.
func TestScanUnitFilesystemHardening(t *testing.T) {
	ds := parseUnit(t, scanService)
	if got := one(t, scanService, ds, "ProtectSystem"); got != "strict" {
		t.Errorf("%s: ProtectSystem=%q, want strict", scanService, got)
	}
	// read-only and not `yes`: the surfaces checks enumerate per-user XDG
	// autostart paths from the target's passwd. ProtectHome=yes would make every
	// home unreadable and turn each one into a coverage gap -- exit 3 caused by
	// our own packaging rather than by the system.
	if got := one(t, scanService, ds, "ProtectHome"); got != "read-only" {
		t.Errorf("%s: ProtectHome=%q, want read-only", scanService, got)
	}
	// ProtectSystem=strict makes the whole hierarchy read-only, so the state
	// directory needs an explicit exception. StateDirectory=, not an invented
	// ReadWritePaths=: internal/config resolves state to /var/lib/aurvet for
	// euid 0, and systemd creates it with the right owner before ExecStart.
	if got := one(t, scanService, ds, "StateDirectory"); got != "aurvet" {
		t.Errorf("%s: StateDirectory=%q, want aurvet (INV-5: the only writable path)", scanService, got)
	}
}

// TestBoundingSetMatchesPrivdrop reads the capability internal/privdrop keeps
// and asserts the unit names the same one. The unit and the process must agree:
// a bounding set that omitted CAP_DAC_READ_SEARCH would not harden anything, it
// would make the scan unable to read root-only files and report coverage gaps
// for a reason that was ours.
func TestBoundingSetMatchesPrivdrop(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "internal", "privdrop", "drop.go"))
	if err != nil {
		t.Fatalf("reading privdrop: %v", err)
	}
	// keepMask is the whole capability set phase 1 needs; it is defined as a
	// single shifted constant, so the capability name is unambiguous.
	re := regexp.MustCompile(`(?m)^const keepMask = .*unix\.(CAP_[A-Z0-9_]+)`)
	m := re.FindSubmatch(src)
	if m == nil {
		t.Fatalf("could not find keepMask's capability in internal/privdrop/drop.go; " +
			"if it moved, this cross-check must be updated, not deleted")
	}
	want := string(m[1])

	ds := parseUnit(t, scanService)
	got := one(t, scanService, ds, "CapabilityBoundingSet")
	if got != want {
		t.Errorf("%s: CapabilityBoundingSet=%q but internal/privdrop keeps %q; the unit and the process must agree",
			scanService, got, want)
	}
	if fields := strings.Fields(got); len(fields) != 1 {
		t.Errorf("%s: CapabilityBoundingSet=%q grants %d capabilities, want exactly 1", scanService, got, len(fields))
	}
	// Ambient is emptied explicitly: an ambient capability survives execve, and
	// aurvet re-execs itself when it finds a hostile loader environment.
	if v := values(ds, "AmbientCapabilities"); len(v) != 1 || v[0] != "" {
		t.Errorf("%s: AmbientCapabilities=%v, want exactly one empty setting", scanService, v)
	}
}

// TestTimerUnitsSurviveASleepingLaptop. Persistent=true is what makes a missed
// run fire after the next boot; without it the machines that are asleep at the
// scheduled hour simply never scan, and the timer looks healthy the entire
// time. The randomised delay stops every installation hitting the AUR at the
// same instant.
func TestTimerUnitsSurviveASleepingLaptop(t *testing.T) {
	for _, tc := range []struct{ timer, service string }{
		{scanTimer, scanService},
		{updateTimer, updateService},
	} {
		ds := parseUnit(t, tc.timer)
		if got := one(t, tc.timer, ds, "Persistent"); got != "true" {
			t.Errorf("%s: Persistent=%q, want true", tc.timer, got)
		}
		delay := one(t, tc.timer, ds, "RandomizedDelaySec")
		if delay == "" || delay == "0" {
			t.Errorf("%s: RandomizedDelaySec=%q; a zero or absent delay synchronises every installation", tc.timer, delay)
		}
		if got := one(t, tc.timer, ds, "Unit"); got != tc.service {
			t.Errorf("%s: Unit=%q, want %q", tc.timer, got, tc.service)
		}
		if got := one(t, tc.timer, ds, "OnCalendar"); got == "" {
			t.Errorf("%s: no OnCalendar", tc.timer)
		}
		if got := one(t, tc.timer, ds, "WantedBy"); got != "timers.target" {
			t.Errorf("%s: [Install] WantedBy=%q, want timers.target", tc.timer, got)
		}
	}
}

// TestServiceUnitsCarryNoInstallSection: the services are started BY their
// timers. An [Install] section on them would let `systemctl enable
// aurvet-scan.service` schedule a full sweep at every boot, which is not what
// anyone typing that means.
func TestServiceUnitsCarryNoInstallSection(t *testing.T) {
	for _, f := range []string{scanService, updateService, failService} {
		if hasSection(parseUnit(t, f), "Install") {
			t.Errorf("%s: has an [Install] section; only the timers are enableable", f)
		}
	}
}

// TestFailureNotificationIsWiredAndNotMasked is task 8 stated as an assertion.
//
// Exit 1 (findings) and exit 3 (coverage incomplete) are contractual results,
// and systemd renders both as `failed` -- then tells nobody, because a timer
// has no operator attached. OnFailure= is the delivery mechanism.
//
// SuccessExitStatus=1 3 is the tempting fix and the destructive one: it does
// not make the scan succeed, it makes a scan that found malware look healthy,
// forever. That is INV-3 violated through packaging. Asserted absent.
func TestFailureNotificationIsWiredAndNotMasked(t *testing.T) {
	for _, f := range []string{scanService, updateService} {
		ds := parseUnit(t, f)

		onFailure := values(ds, "OnFailure")
		if len(onFailure) != 1 || strings.TrimSpace(onFailure[0]) == "" {
			t.Fatalf("%s: OnFailure=%v; without it exit 1 and exit 3 are a red line nobody reads", f, onFailure)
		}
		// The target must be a unit that actually ships, or OnFailure= points at
		// nothing and is worse than absent -- it looks wired.
		target := onFailure[0]
		if !strings.HasSuffix(target, ".service") {
			t.Errorf("%s: OnFailure=%q does not name a service", f, target)
		}
		tmpl := regexp.MustCompile(`^([^@]+)@.*\.service$`).FindStringSubmatch(target)
		if tmpl == nil {
			t.Fatalf("%s: OnFailure=%q is not a template instance; %%n is how the notifier learns which unit failed", f, target)
		}
		if want := tmpl[1] + "@.service"; want != failService {
			t.Errorf("%s: OnFailure names template %q, but the shipped notifier is %q", f, want, failService)
		}
		if _, err := os.Stat(failService); err != nil {
			t.Errorf("%s: OnFailure points at %s, which does not ship: %v", f, failService, err)
		}

		if got := values(ds, "SuccessExitStatus"); len(got) != 0 {
			t.Errorf("%s: SuccessExitStatus=%v. This does not fix the red unit, it discards the result: "+
				"a scan that finds malware now exits 0 and looks healthy forever. Use OnFailure=, which is already here.", f, got)
		}
		// The same masking wearing a different hat.
		if got := values(ds, "RestartPreventExitStatus"); len(got) != 0 {
			t.Errorf("%s: RestartPreventExitStatus=%v masks the contractual exit codes", f, got)
		}
	}

	// The notifier must not notify about itself failing: that is a loop.
	if got := values(parseUnit(t, failService), "OnFailure"); len(got) != 0 {
		t.Errorf("%s: OnFailure=%v on the notifier itself is a notification loop", failService, got)
	}
}

// TestNothingInThisRepositoryEnablesAUnit. Arch policy, and correct: shipping a
// unit is not consent to run it. The admin enables; the packager does not.
func TestNothingInThisRepositoryEnablesAUnit(t *testing.T) {
	root := filepath.Join("..", "..")
	// `systemctl preset` counts: a preset file can enable a unit just as
	// effectively as `systemctl enable`, and .install scriptlets are where both
	// would live.
	forbidden := regexp.MustCompile(`systemctl\s+(--\S+\s+)*(enable|preset|start)\b`)
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			switch info.Name() {
			case ".git", "vendor", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		name := info.Name()
		if !strings.HasSuffix(name, ".install") && !strings.HasSuffix(name, ".preset") {
			return nil
		}
		body, rerr := os.ReadFile(p)
		if rerr != nil {
			return nil
		}
		for _, line := range strings.Split(string(body), "\n") {
			lt := strings.TrimSpace(line)
			if strings.HasPrefix(lt, "#") {
				continue
			}
			if forbidden.MatchString(lt) {
				t.Errorf("%s enables a unit: %q. The packager ships units; the administrator enables them.", p, lt)
			}
		}
		if strings.HasSuffix(name, ".preset") {
			t.Errorf("%s ships a systemd preset, which enables units on the packager's behalf", p)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}
}

// ---------------------------------------------------------------------------
// The notifier's behaviour, not just its presence.
//
// An OnFailure= pointing at a unit whose command is broken is the same bug with
// extra steps, so the shipped ExecStart is extracted and RUN against a stubbed
// systemctl. The property that matters: exit 1 and exit 3 produce DIFFERENT
// messages, because "found something" and "could not look" need different
// responses from the operator, and 3 outranks 1.

// expandSpecifiers performs the one pass systemd performs: %% is a literal
// percent, %x is a specifier. Anything unknown is left alone rather than
// guessed at.
func expandSpecifiers(s string, m map[byte]string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '%' || i+1 >= len(s) {
			b.WriteByte(s[i])
			continue
		}
		c := s[i+1]
		if c == '%' {
			b.WriteByte('%')
			i++
			continue
		}
		if v, ok := m[c]; ok {
			b.WriteString(v)
			i++
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// unescapeBackslashes applies the `\\` -> `\` that systemd does inside a quoted
// ExecStart word.
func unescapeBackslashes(s string) string {
	return strings.ReplaceAll(s, `\\`, `\`)
}

// notifierScript returns the shell body of the notifier's ExecStart and the
// argv it is given, with specifiers expanded for instance.
func notifierScript(t *testing.T, instance string) (script string, argv []string) {
	t.Helper()
	raw := one(t, failService, parseUnit(t, failService), "ExecStart")
	raw = expandSpecifiers(raw, map[byte]string{'i': instance, 'n': instance})
	raw = unescapeBackslashes(raw)

	const prefix = "/bin/sh -c "
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, prefix) {
		t.Fatalf("%s: ExecStart does not start with %q: %q", failService, prefix, raw)
	}
	rest := strings.TrimPrefix(raw, prefix)
	if !strings.HasPrefix(rest, "'") {
		t.Fatalf("%s: ExecStart's script is not single-quoted: %q", failService, rest)
	}
	end := strings.LastIndex(rest, "'")
	if end <= 0 {
		t.Fatalf("%s: unterminated script in ExecStart", failService)
	}
	return rest[1:end], strings.Fields(rest[end+1:])
}

// stubPATH builds a directory of fakes for the three commands the notifier
// calls: systemctl (the source of the exit code), systemd-cat (the journal) and
// wall (the terminals). Nothing here talks to the real system bus.
func stubPATH(t *testing.T, result, status string) (dir, journal, walled string) {
	t.Helper()
	dir = t.TempDir()
	journal = filepath.Join(dir, "journal.log")
	walled = filepath.Join(dir, "wall.log")

	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// A `systemctl show -p KEY --value UNIT` stub. It answers only the two
	// properties the notifier asks for; anything else is an empty line, which is
	// what the real one does for an unknown property.
	write("systemctl", fmt.Sprintf(`#!/bin/sh
key=""
for a in "$@"; do
  case "$a" in
    ExecMainStatus|-pExecMainStatus) key=status ;;
    Result|-pResult) key=result ;;
    -p) : ;;
  esac
done
case "$key" in
  status) printf '%%s\n' %q ;;
  result) printf '%%s\n' %q ;;
  *)      printf '\n' ;;
esac
`, status, result))
	// PATH below contains ONLY this directory, so that a stub that fails to
	// match cannot silently fall through to the real systemctl and interrogate
	// the developer's own machine. That means the stubs may use shell builtins
	// and nothing else -- hence the read loop rather than cat(1).
	drain := func(log string) string {
		return "while IFS= read -r line; do printf '%s\\n' \"$line\" >> " + log + "; done\n"
	}
	write("systemd-cat", "#!/bin/sh\nprintf 'args: %s\\n' \"$*\" >> "+journal+"\n"+drain(journal))
	write("wall", "#!/bin/sh\n"+drain(walled))
	return dir, journal, walled
}

func runNotifier(t *testing.T, instance, result, status string) (code int, journal, walled string) {
	t.Helper()
	script, argv := notifierScript(t, instance)
	dir, jpath, wpath := stubPATH(t, result, status)

	args := append([]string{"-c", script}, argv...)
	cmd := exec.Command("/bin/sh", args...)
	cmd.Env = []string{"PATH=" + dir}
	out, err := cmd.CombinedOutput()
	code = 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("running the notifier: %v\n%s", err, out)
	}
	return code, readIfPresent(jpath), readIfPresent(wpath)
}

func readIfPresent(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return string(b)
}

// TestNotifierDistinguishesFindingsFromIncompleteCoverage. 3 outranks 1
// (INV-3): "I found something" and "I could not look" demand different
// responses, and a notifier that said only "the unit failed" would collapse
// them back into the ambiguity OnFailure= exists to resolve.
func TestNotifierDistinguishesFindingsFromIncompleteCoverage(t *testing.T) {
	const unit = "aurvet-scan.service"

	code, journal, walled := runNotifier(t, unit, "exit-code", "3")
	if code != 0 {
		t.Errorf("notifier for exit 3 exited %d, want 0 -- a notifier that fails notifies nobody", code)
	}
	if !strings.Contains(journal, "COVERAGE INCOMPLETE") {
		t.Errorf("exit 3 message does not say coverage was incomplete:\n%s", journal)
	}
	if !strings.Contains(journal, "-p err") {
		t.Errorf("exit 3 was not logged at err priority:\n%s", journal)
	}
	if !strings.Contains(journal, unit) {
		t.Errorf("exit 3 message does not name the failed unit:\n%s", journal)
	}
	if !strings.Contains(walled, "COVERAGE INCOMPLETE") {
		t.Errorf("exit 3 did not reach logged-in terminals:\n%s", walled)
	}
	incomplete := journal

	code, journal, walled = runNotifier(t, unit, "exit-code", "1")
	if code != 0 {
		t.Errorf("notifier for exit 1 exited %d, want 0", code)
	}
	if !strings.Contains(journal, "FINDINGS") {
		t.Errorf("exit 1 message does not say findings were reported:\n%s", journal)
	}
	if strings.Contains(journal, "COVERAGE INCOMPLETE") {
		t.Errorf("exit 1 is reported as incomplete coverage; the two must not be collapsed:\n%s", journal)
	}
	if walled == "" {
		t.Errorf("exit 1 did not reach logged-in terminals")
	}
	if journal == incomplete {
		t.Errorf("exit 1 and exit 3 produce an identical message; that is the ambiguity OnFailure= exists to remove")
	}

	// A usage error is a packaging bug, not a verdict about the system. Saying
	// so keeps an operator from hunting for a compromise that was never claimed.
	if _, journal, _ = runNotifier(t, unit, "exit-code", "2"); !strings.Contains(journal, "USAGE ERROR") {
		t.Errorf("exit 2 is not reported as a usage error:\n%s", journal)
	}

	// Killed, timed out, OOM: nothing was verified, and the message must not
	// imply a clean result.
	if _, journal, _ = runNotifier(t, unit, "signal", "9"); !strings.Contains(journal, "did not complete") {
		t.Errorf("a signalled unit is not reported as incomplete:\n%s", journal)
	}
	if strings.Contains(journal, "COVERAGE INCOMPLETE") {
		t.Errorf("a signalled unit is reported as if aurvet had produced exit 3:\n%s", journal)
	}
}

// TestNotifierSurvivesAMachineWithNoWall: util-linux is effectively always
// present, but the notifier must not turn a missing wall(1) into its own
// failure -- that would lose the journal message too.
func TestNotifierSurvivesAMachineWithNoWall(t *testing.T) {
	script, argv := notifierScript(t, "aurvet-scan.service")
	dir, jpath, _ := stubPATH(t, "exit-code", "3")
	if err := os.Remove(filepath.Join(dir, "wall")); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/sh", append([]string{"-c", script}, argv...)...)
	cmd.Env = []string{"PATH=" + dir}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("notifier failed with no wall(1) on PATH: %v\n%s", err, out)
	}
	if !strings.Contains(readIfPresent(jpath), "COVERAGE INCOMPLETE") {
		t.Errorf("the journal message was lost when wall(1) was absent")
	}
}

// TestUpdateUnitIsInertRatherThanBrokenUntilTheUpdateCommandExists.
//
// `aurvet update` ships in P5. A unit whose ExecStart names a subcommand the
// installed binary does not have would exit 2, fire OnFailure= and cry wolf
// daily. ExecCondition= is the systemd primitive for "skip, do not fail": a
// condition exiting 1-254 marks the unit `skipped`, so nothing notifies and
// nothing claims an update happened. When a release ships `update`, the same
// condition starts passing with no edit to the unit.
func TestUpdateUnitIsInertRatherThanBrokenUntilTheUpdateCommandExists(t *testing.T) {
	ds := parseUnit(t, updateService)
	cond := one(t, updateService, ds, "ExecCondition")
	if cond == "" {
		t.Fatalf("%s: no ExecCondition; on a build without `aurvet update` this unit would fail daily", updateService)
	}
	if got := one(t, updateService, ds, "ExecStart"); !strings.Contains(got, "update") {
		t.Errorf("%s: ExecStart=%q does not run the update subcommand", updateService, got)
	}

	// Run the condition against a stub that prints today's real subcommand list
	// (no `update`) and against one that prints a future list (with `update`).
	const prefix = "/bin/sh -c "
	if !strings.HasPrefix(cond, prefix) {
		t.Fatalf("%s: ExecCondition is not a /bin/sh -c command: %q", updateService, cond)
	}
	script := strings.Trim(strings.TrimPrefix(cond, prefix), "'")

	for _, tc := range []struct {
		name     string
		commands string
		wantZero bool
	}{
		{"today, before P5", "commands: scan, review, install, snapshot, explain, doctor, version", false},
		{"after P5", "commands: scan, review, install, snapshot, explain, doctor, update, version", true},
	} {
		dir := t.TempDir()
		bin := filepath.Join(dir, "usr", "bin")
		if err := os.MkdirAll(bin, 0o755); err != nil {
			t.Fatal(err)
		}
		stub := "#!/bin/sh\necho 'usage: aurvet [flags] <command>' >&2\necho '" + tc.commands + "' >&2\nexit 2\n"
		if err := os.WriteFile(filepath.Join(bin, "aurvet"), []byte(stub), 0o755); err != nil {
			t.Fatal(err)
		}
		// The condition names /usr/bin/aurvet absolutely, which is right for a
		// unit and inconvenient for a test; rewrite it to the stub.
		s := strings.ReplaceAll(script, "/usr/bin/aurvet", filepath.Join(bin, "aurvet"))
		err := exec.Command("/bin/sh", "-c", s).Run()
		gotZero := err == nil
		if gotZero != tc.wantZero {
			t.Errorf("ExecCondition against %s: exit-zero=%v, want %v (%v)", tc.name, gotZero, tc.wantZero, err)
		}
	}

	// A condition that exits 255 or dies on a signal is a FAILURE, not a skip,
	// so it must not be able to do either. `grep` returns 0/1/2 and the pipeline
	// takes grep's status.
	if !strings.Contains(script, "grep") {
		t.Errorf("%s: ExecCondition does not use grep; the 0/1 exit contract above assumes it", updateService)
	}
}

// TestShippedUnitNamesAreTheOnesReferenced: a cheap guard against a rename that
// updates four files and forgets the fifth.
func TestShippedUnitNamesAreTheOnesReferenced(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{scanService: false, updateService: false, scanTimer: false, updateTimer: false, failService: false}
	for _, e := range entries {
		n := e.Name()
		if !strings.HasSuffix(n, ".service") && !strings.HasSuffix(n, ".timer") {
			continue
		}
		if _, ok := want[n]; !ok {
			t.Errorf("%s ships but no test knows about it", n)
			continue
		}
		want[n] = true
	}
	for n, seen := range want {
		if !seen {
			t.Errorf("%s is referenced by the tests but does not ship", n)
		}
	}
}

// TestAurvetCanReadItsOwnUnits closes a loop worth closing: internal/surfaces
// parses units from disk to decide which ExecStart commands are package-owned,
// and a shape it cannot model becomes a coverage gap (INV-9). Units this
// project ships must therefore be readable by this project's own parser, or
// aurvet reports a gap on its own packaging on every run.
//
// The failure-notifier template is deliberately excluded: its ExecStart names
// %i, which is unresolvable until systemd instantiates it, and the parser is
// right to say so rather than guess.
func TestAurvetCanReadItsOwnUnits(t *testing.T) {
	for _, f := range []string{scanService, updateService, scanTimer, updateTimer} {
		body, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		u, err := surfaces.ParseUnit(f, body)
		if err != nil {
			t.Fatalf("%s: aurvet's own unit parser refuses it: %v", f, err)
		}
		if len(u.Unparsed) != 0 {
			t.Errorf("%s: aurvet's parser did not model %v; the tool would report a coverage gap on its own package",
				f, u.Unparsed)
		}
		if u.Description == "" {
			t.Errorf("%s: no Description; an unlabelled unit is unattributable in `systemctl status`", f)
		}
		for _, e := range u.Exec {
			if !e.Resolvable {
				t.Errorf("%s: %s=%q is unresolvable (%s)", f, e.Directive, e.Raw, e.Unresolvable)
				continue
			}
			if !strings.HasPrefix(e.Bin, "/") {
				t.Errorf("%s: %s resolves to a relative command %q; a unit must name an absolute path so a PATH "+
					"lookup cannot be redirected", f, e.Directive, e.Bin)
			}
		}
	}
}
