// internal/check/pkgbuild.go
//
// The PKGBUILD rules: what a recipe DOES, decided from what the tokeniser read
// and never from running it (INV-2). Nothing in this file executes a recipe, a
// command it found in one, or makepkg -- not behind a flag, not in a sandbox,
// not to resolve one stubborn variable. Everything is a pure function of
// (File, Resolution, Verdict, PKGBUILDConfig) (INV-4).
//
// The rules read internal/pkgbuild's STRUCTURE, never the file's text, and that
// choice is what keeps them quiet on ordinary recipes. Three exclusions come
// free from doing it that way, and all three are measured on the 34 cached
// recipes of the reference system:
//
//   - A COMMENT never becomes a Command. `curl` appears in exactly 2 of the 34
//     recipes and both are false positives; google-chrome's is a commented-out
//     suggestion to the maintainer.
//   - A DEPENDENCY ARRAY is an Assignment, and no rule here reads Assignments.
//     flutter's is the literal string "curl" in a depends array; yay's
//     optdepends carry 'sudo: privilege elevation' and 'doas: privilege
//     elevation'; three recipes name gnome-keyring.
//   - A HEREDOC BODY is Heredoc.Body data, never a Command. flutter-bin writes
//     three wrapper scripts whose bodies contain `source /opt/flutter/...`,
//     `$HOME/.cache` and `/opt/flutter` -- a script the recipe WRITES, analysed
//     as content, is not a build step the recipe RUNS.
//
// A rule that fires on ordinary recipes trains its operator to ignore the tool,
// which is the failure mode this project cannot afford, so every rule below was
// measured against those 34 recipes and two of them were shaped by what the
// measurement said:
//
//   - Language package managers reach the network at build time (`go mod
//     download`, `cargo fetch`, `npm install`, `yarn`) in 6 of 34 honest
//     recipes. They are deliberately NOT reported; the rule covers explicit
//     transfer tools.
//   - `chmod 4755` on a path under $pkgdir is packaged CONTENT, not escalation
//     of the build: brave-bin ships exactly that for chrome-sandbox. The
//     installed setuid file is P1-C's business, not this file's.
//
// eval is NOT rated here. It is in 3 of 34 honest recipes and is already a
// coverage gap from pkgbuild.Assess (INV-9); adding a finding on top would cry
// wolf on a tenth of the AUR. What it costs is stated in every finding's Limits
// instead of in a comment (INV-6).
package check

import (
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/lookatitude/aurvet/internal/finding"
	"github.com/lookatitude/aurvet/internal/pkgbuild"
)

// Rule IDs. Stable identifiers: a suppression bound to one must keep meaning
// the same thing across releases.
const (
	ruleNetFetch      = "pkgbuild-build-network-fetch"
	ruleVCSClone      = "pkgbuild-build-vcs-clone"
	ruleWriteOutside  = "pkgbuild-write-outside-pkgdir"
	ruleCredential    = "pkgbuild-credential-path"
	rulePrivEsc       = "pkgbuild-privilege-escalation"
	rulePasteHost     = "pkgbuild-source-paste-host"
	ruleObfuscation   = "pkgbuild-obfuscation"
	ruleSkipIntegrity = "pkgbuild-skip-fixed-url"
	ruleWeakIntegrity = "pkgbuild-weak-integrity"
)

// allPKGBUILDRules is the enumerable rule set, so a corpus measurement can
// report a count per rule including the zeros -- a rule that fires nowhere and
// a rule that was never evaluated look identical without it.
var allPKGBUILDRules = []string{
	ruleNetFetch, ruleVCSClone, ruleWriteOutside, ruleCredential,
	rulePrivEsc, rulePasteHost, ruleObfuscation, ruleSkipIntegrity, ruleWeakIntegrity,
}

// maxPKGBUILDFindings bounds one recipe's findings per rule. The input is
// attacker-controlled: a recipe with fifty thousand curls is one problem, and an
// unbounded report is a denial of service against the person reading it. The
// truncation becomes a coverage gap, never a silent cut.
const maxPKGBUILDFindings = 24

// maxEvidenceText bounds a quoted command in evidence.
const maxEvidenceText = 200

// unknownSubject names a recipe with no readable pkgbase. Such a file also
// produces pkgbuild.RuleNothingAnalysed, so it can never read as clean.
const unknownSubject = "(unnamed recipe)"

// PKGBUILDConfig parameterises the rules. It exists so that host lists are data
// rather than literals compiled into a rule (spec §5.2: "host list ships in the
// bundle"), and so nothing here reads the environment (INV-4).
type PKGBUILDConfig struct {
	// PasteHosts REPLACES the built-in paste/gist/shortener list when non-empty.
	// Entries match a host exactly or as a parent domain ("0x0.st" matches
	// "0x0.st", not "not0x0.st").
	PasteHosts []string
}

func (c PKGBUILDConfig) pasteHosts() []string {
	if len(c.PasteHosts) > 0 {
		return c.PasteHosts
	}
	return DefaultPasteHosts
}

// DefaultPasteHosts is the shipped list of hosts from which a PKGBUILD has no
// legitimate reason to fetch a source: paste sites, anonymous file drops, gist
// raw endpoints and URL shorteners. A shortener additionally makes the real
// origin unreviewable, which is the point of using one here.
//
// github.com, raw.githubusercontent.com, storage.googleapis.com,
// files.pythonhosted.org and dl.google.com are all present in the measured
// corpus and are deliberately absent from this list.
var DefaultPasteHosts = []string{
	// Paste sites and anonymous drops.
	"0x0.st", "pastebin.com", "paste.ee", "pastebin.pl", "hastebin.com",
	"ghostbin.com", "termbin.com", "ix.io", "sprunge.us", "dpaste.com",
	"dpaste.org", "paste.rs", "bpa.st", "clbin.com", "transfer.sh",
	"anonfiles.com", "file.io", "temp.sh", "catbox.moe", "filebin.net",
	"gofile.io", "pixeldrain.com", "send.vis.ee", "oshi.at",
	// Gist raw endpoints: a gist is one person's unversioned scratch space, not
	// a release artifact.
	"gist.github.com", "gist.githubusercontent.com",
	// Shorteners.
	"bit.ly", "tinyurl.com", "goo.gl", "t.co", "is.gd", "ow.ly", "cutt.ly",
	"rebrand.ly", "shorturl.at", "rb.gy", "t.ly", "s.id",
}

// fetchTools are the explicit network transfer tools. Language package managers
// are NOT here: `go mod download`, `cargo fetch`, `npm install` and `yarn`
// appear in 6 of the 34 measured benign recipes, and a critical finding on a
// fifth of an honest corpus is a rule defect, not a detection.
var fetchTools = map[string]string{
	"curl": "curl", "wget": "wget", "wget2": "wget2",
	"aria2c": "aria2c", "aria2": "aria2", "axel": "axel",
	"lftp": "lftp", "ftp": "ftp", "tftp": "tftp", "ncftpget": "ncftpget",
	"scp": "scp", "sftp": "sftp",
	"nc": "netcat", "ncat": "ncat", "netcat": "netcat", "socat": "socat",
}

// shells are the interpreters a fetch is piped into when a recipe runs what it
// just downloaded.
var shells = map[string]bool{
	"sh": true, "bash": true, "dash": true, "zsh": true, "ksh": true,
	"fish": true, "python": true, "python2": true, "python3": true,
	"perl": true, "ruby": true, "node": true, "php": true,
}

// vcsCloneSubcommands are the VCS operations that fetch a tree the source array
// never declared. `git submodule update` is deliberately absent: it is ordinary
// in prepare() and fetches what the checked-out tree already pins.
var vcsCloneSubcommands = map[string][]string{
	"git": {"clone"},
	"hg":  {"clone"},
	"svn": {"checkout", "co", "export"},
	"bzr": {"branch", "checkout"},
}

// buildDirVars are the variables makepkg sets to real build-time directories.
// A path built from one of them is inside the build, wherever it actually
// points at build time.
var buildDirVars = map[string]bool{
	"pkgdir": true, "srcdir": true, "startdir": true,
	"PKGDEST": true, "SRCDEST": true, "BUILDDIR": true, "pkgbase": false,
}

// harmlessAbsolutePrefixes are absolute paths a build may write without
// leaving anything behind on the host.
var harmlessAbsolutePrefixes = []string{"/dev/", "/tmp/", "/var/tmp/", "/proc/self/fd/"}

// credentialPaths are path-shaped, deliberately: the WORD "keyring" appears in
// the depends/optdepends of 3 of the 34 measured recipes as the package name
// gnome-keyring, so a rule keyed on the word rather than the path would fire on
// 9% of an honest corpus even before the dependency-array exclusion saved it.
var credentialPaths = []struct{ pattern, what string }{
	{"/.ssh", "SSH private keys and known_hosts"},
	{"id_rsa", "an SSH private key"},
	{"id_ed25519", "an SSH private key"},
	{"id_ecdsa", "an SSH private key"},
	{"/.gnupg", "the GnuPG keyring"},
	{"/.aws", "AWS credentials"},
	{"/.azure", "Azure credentials"},
	{"/.config/gcloud", "Google Cloud credentials"},
	{"/.docker/config.json", "Docker registry credentials"},
	{"/.kube/config", "Kubernetes cluster credentials"},
	{"/.netrc", "netrc credentials"},
	{"/.git-credentials", "stored git credentials"},
	{"/.config/gh/hosts.yml", "GitHub CLI tokens"},
	{"/.config/rclone", "rclone remote credentials"},
	{"/.pypirc", "PyPI upload credentials"},
	{"/.password-store", "the pass password store"},
	{"/.pgpass", "PostgreSQL credentials"},
	{"/.my.cnf", "MySQL credentials"},
	{"/keyrings/", "a login keyring"},
	{"/.gnome2/keyrings", "a login keyring"},
	{"/.pki/nssdb", "the NSS certificate and key database"},
	{"/.mozilla", "a Firefox profile"},
	{"/.thunderbird", "a Thunderbird profile"},
	{"/.config/google-chrome", "a Chrome profile"},
	{"/.config/chromium", "a Chromium profile"},
	{"/.config/BraveSoftware", "a Brave profile"},
	{"/.config/discord", "a Discord token store"},
	{"/.config/solana", "a Solana keypair"},
	{"/.bitcoin", "a Bitcoin wallet"},
	{"/.electrum", "an Electrum wallet"},
	{"/.ethereum", "an Ethereum keystore"},
	{"wallet.dat", "a cryptocurrency wallet"},
	{"/etc/shadow", "the system password hashes"},
}

// escalators are the commands that ask for privilege the build does not have.
var escalators = map[string]bool{
	"sudo": true, "doas": true, "pkexec": true, "su": true,
	"gksu": true, "gksudo": true, "kdesu": true, "kdesudo": true,
	"sudoedit": true, "run0": true,
}

// Limits every PKGBUILD finding carries, because this is the floor of static
// bash analysis and INV-6 puts it in the output rather than in documentation.
const (
	limitStatic = "The recipe was read as text and never executed (INV-2), so this describes the recipe AS WRITTEN: " +
		"a build step that computes what it runs -- from a fetched file, an environment variable, or makepkg.conf -- " +
		"is outside what this can see. It does not establish that the build was ever run, nor what it produced."
	limitEval = "This recipe also builds code with eval, so the commands it generates are not in the text and were " +
		"not analysed at all; eval is in 3 of 34 legitimate cached recipes, so its presence is a limit of this " +
		"analysis rather than a sign of malice. Treat the rest of this recipe's review as partial."
	limitRedirection = "The tokeniser consumes a redirection target as an operator operand, so a write performed by " +
		"redirection alone (`echo x > /etc/ld.so.preload`) is NOT covered by this rule, and neither is a " +
		"`make install` with no DESTDIR. This rule sees paths that appear as command arguments."
	limitFetch = "Reaching the network in a build step bypasses source integrity entirely: nothing fetched here is " +
		"covered by the sums arrays. Language package managers (`go mod download`, `cargo fetch`, `npm install`) " +
		"also fetch and are deliberately not reported -- they are in 6 of 34 honest recipes -- so this rule is not " +
		"a complete account of the build's network access."
	limitHost = "The host was read from the recipe's own source array; no request was made and nothing was resolved, " +
		"so this says nothing about what the URL currently serves."
)

// PKGBUILD applies every rule to one already-parsed recipe.
//
// The pkgbuild.Verdict is a REQUIRED parameter rather than something derived
// here, and its gaps are merged into the result unconditionally, for the reason
// E-1 records in provenance.go: a caller who could forget to merge them would
// report an eval-generated or unparsable recipe as clean, which is exactly the
// silent false clean INV-3 and INV-9 exist to prevent. Making it a parameter
// makes omitting it a compile error rather than a code-review miss.
//
// Nothing is executed. No file is read. No network request is made.
func PKGBUILD(f pkgbuild.File, r pkgbuild.Resolution, v pkgbuild.Verdict, cfg PKGBUILDConfig) finding.Result {
	subject := v.Subject
	if subject == "" {
		subject = r.Pkgbase
	}
	if subject == "" {
		subject = unknownSubject
	}
	rep := &pkgbuildReporter{
		subject:   subject,
		evalFloor: f.Note(pkgbuild.NoteEval),
	}
	// INV-3 / INV-9: the coverage verdict travels with the findings, always.
	rep.res.Gaps = append(rep.res.Gaps, v.Gaps...)

	for i, c := range f.Commands {
		next := pkgbuild.Command{}
		if i+1 < len(f.Commands) {
			next = f.Commands[i+1]
		}
		checkFetch(rep, c, next)
		checkVCSClone(rep, c)
		checkWrites(rep, c, r)
		checkCredentials(rep, c)
		checkPrivilege(rep, c)
		checkObfuscation(rep, c)
	}
	checkSourceHosts(rep, r, cfg)
	checkIntegrity(rep, r)

	return rep.result()
}

// pkgbuildReporter accumulates findings under a per-rule bound and a
// per-rule-plus-location dedup key, so one construct yields one finding.
type pkgbuildReporter struct {
	subject   string
	evalFloor bool
	res       finding.Result
	counts    map[string]int
	seen      map[string]bool
	truncated map[string]int
}

func (p *pkgbuildReporter) add(rule string, sev finding.Severity, key, summary string, evidence []string, limits string) {
	if p.counts == nil {
		p.counts = map[string]int{}
		p.seen = map[string]bool{}
		p.truncated = map[string]int{}
	}
	dedup := rule + "\x00" + key
	if p.seen[dedup] {
		return
	}
	p.seen[dedup] = true
	if p.counts[rule] >= maxPKGBUILDFindings {
		p.truncated[rule]++
		return
	}
	p.counts[rule]++
	if p.evalFloor {
		limits = limits + " " + limitEval
	}
	p.res.Findings = append(p.res.Findings, finding.Finding{
		RuleID:      rule,
		SubjectKind: "pkgbase",
		Subject:     p.subject,
		Severity:    sev,
		Summary:     summary,
		Evidence:    evidence,
		Limits:      limits + " " + limitStatic,
	})
}

// result appends a coverage gap for every rule whose findings were truncated.
// A cut report is an incomplete one (INV-3), never a quiet one.
func (p *pkgbuildReporter) result() finding.Result {
	rules := make([]string, 0, len(p.truncated))
	for rule := range p.truncated {
		rules = append(rules, rule)
	}
	sort.Strings(rules)
	for _, rule := range rules {
		p.res.Gaps = append(p.res.Gaps, finding.Gap{
			RuleID:  rule,
			Subject: p.subject,
			Reason: fmt.Sprintf("this rule matched more than %d times and %d further match(es) were not reported; "+
				"the recipe should be treated as unreviewed rather than as having exactly %d problems",
				maxPKGBUILDFindings, p.truncated[rule], maxPKGBUILDFindings),
		})
	}
	return p.res
}

// --- network fetch -------------------------------------------------------

func checkFetch(rep *pkgbuildReporter, c, next pkgbuild.Command) {
	tool, ok := fetchTools[base(c.Name())]
	if !ok {
		return
	}
	ev := []string{
		"command=" + tool,
		"in " + where(c),
		"reads: " + quoteCommand(c),
	}
	summary := "build step fetches over the network, bypassing the source array and its checksums"
	if c.Sep == "|" {
		if shells[base(next.Name())] && next.Func == c.Func && next.SubstDepth == c.SubstDepth {
			ev = append(ev, "output is piped straight into the shell "+base(next.Name()))
			summary = "build step downloads and pipes straight into a shell"
		} else {
			ev = append(ev, "output is piped into another command")
		}
	}
	if c.SubstDepth > 0 {
		ev = append(ev, fmt.Sprintf("inside a command substitution (depth %d); its text was read, its value was not resolved", c.SubstDepth))
	}
	rep.add(ruleNetFetch, finding.SevCritical, fmt.Sprintf("%d:%s", c.Line, tool), summary, ev, limitFetch)
}

func checkVCSClone(rep *pkgbuildReporter, c pkgbuild.Command) {
	subs, ok := vcsCloneSubcommands[base(c.Name())]
	if !ok {
		return
	}
	args := c.Args()
	var sub string
	for _, a := range args {
		lit, ok := a.Literal()
		if !ok || strings.HasPrefix(lit, "-") {
			continue
		}
		sub = lit
		break
	}
	if !hasStringEntry(subs, sub) {
		return
	}
	rep.add(ruleVCSClone, finding.SevSuspicious, fmt.Sprintf("%d:%s", c.Line, sub),
		"build step clones a repository the source array does not declare",
		[]string{
			"command=" + base(c.Name()) + " " + sub,
			"in " + where(c),
			"reads: " + quoteCommand(c),
		},
		"Rated suspicious rather than critical because a build legitimately manipulates VCS trees it already has, "+
			"and because this pattern is absent from the 34-recipe measured corpus, which means its benign rate on "+
			"the wider AUR is UNMEASURED. What it fetches is not covered by the sums arrays.")
}

// --- writes outside $pkgdir ---------------------------------------------

func checkWrites(rep *pkgbuildReporter, c pkgbuild.Command, r pkgbuild.Resolution) {
	for _, w := range destinations(c) {
		class, shown := classifyPath(w, r)
		switch class {
		case pathHome:
			rep.add(ruleWriteOutside, finding.SevCritical, fmt.Sprintf("%d:%s", w.Line, shown),
				"build step writes into the invoking user's home directory",
				[]string{
					"command=" + base(c.Name()),
					"destination=" + shown,
					"in " + where(c),
					"reads: " + quoteCommand(c),
				}, limitRedirection)
		case pathAbsoluteOutside:
			rep.add(ruleWriteOutside, finding.SevCritical, fmt.Sprintf("%d:%s", w.Line, shown),
				"build step writes to an absolute path outside $pkgdir",
				[]string{
					"command=" + base(c.Name()),
					"destination=" + shown,
					"in " + where(c),
					"reads: " + quoteCommand(c),
					"makepkg runs this as the invoking user, so the write lands on the live system rather than in the package",
				}, limitRedirection)
		}
	}
}

// destinations returns the words of a command that name something it WRITES.
// The distinction is load-bearing and measured: `ln -s /opt/x
// "$pkgdir/usr/bin/y"` has an absolute FIRST argument which is the link target,
// and 6 of the 34 cached recipes are that exact shape. A rule that looked at
// every absolute path argument would fire on all six.
func destinations(c pkgbuild.Command) []pkgbuild.Word {
	name := base(c.Name())
	args := c.Args()
	switch name {
	case "install", "cp", "mv", "ln", "rsync":
		if t, ok := flagValue(args, "-t", "--target-directory"); ok {
			return []pkgbuild.Word{t}
		}
		if name == "install" && hasFlag(args, "-d", "--directory") {
			return operands(args)
		}
		ops := operands(args)
		if len(ops) < 2 {
			// A single operand is a source with no destination we can name (or a
			// truncated command); guessing which it is would invent evidence.
			return nil
		}
		return ops[len(ops)-1:]
	case "mkdir", "rmdir", "touch", "rm", "unlink", "tee", "truncate",
		"mkfifo", "mknod", "chmod", "chown", "chgrp", "setfacl", "chattr", "patch":
		return operands(args)
	case "sed":
		if hasFlag(args, "-i", "--in-place") || hasFlagPrefix(args, "-i") {
			return sedFiles(args)
		}
	case "tar", "bsdtar":
		if t, ok := flagValue(args, "-C", "--directory"); ok {
			return []pkgbuild.Word{t}
		}
	case "unzip":
		if t, ok := flagValue(args, "-d", ""); ok {
			return []pkgbuild.Word{t}
		}
	case "dd":
		for _, a := range args {
			if w, ok := trimWordPrefix(a, "of="); ok {
				return []pkgbuild.Word{w}
			}
		}
	}
	return nil
}

// sedFiles returns the FILE operands of a `sed -i`, excluding its script.
//
// This is measured, not defensive: google-chrome's package() runs
//
//	sed -i -e "/Exec=/i\StartupWMClass=Google-chrome" -e "s|...|" "$pkgdir"/...
//
// and a rule that read every operand took the sed EXPRESSION `/Exec=/i\...` --
// which begins with a slash because it is an address, not a path -- for an
// absolute write outside $pkgdir. That was the one false positive this rule
// produced on the 34-recipe corpus.
func sedFiles(args []pkgbuild.Word) []pkgbuild.Word {
	var (
		out         []pkgbuild.Word
		skipNext    bool
		haveScript  bool
		scriptFlags = map[string]bool{"-e": true, "--expression": true, "-f": true, "--file": true}
	)
	for _, a := range args {
		lit, ok := a.Literal()
		if skipNext {
			skipNext = false
			haveScript = true
			continue
		}
		if ok && scriptFlags[lit] {
			skipNext = true
			continue
		}
		if ok && (strings.HasPrefix(lit, "--expression=") || strings.HasPrefix(lit, "--file=")) {
			haveScript = true
			continue
		}
		if ok && strings.HasPrefix(lit, "-") && lit != "-" {
			continue
		}
		if !haveScript {
			// The first bare operand is the script when no -e/-f supplied one.
			haveScript = true
			continue
		}
		out = append(out, a)
	}
	return out
}

// pathClass says where a path points, as far as text can tell.
type pathClass int

const (
	// pathRelative is relative to the build directory makepkg cd'd into.
	pathRelative pathClass = iota
	// pathBuild is built from a makepkg build-time directory variable.
	pathBuild
	// pathHome is under the invoking user's home.
	pathHome
	// pathHarmless is an absolute path a build may write without leaving
	// anything on the host (/dev, /tmp).
	pathHarmless
	// pathAbsoluteOutside is an absolute path on the live system.
	pathAbsoluteOutside
)

// classifyPath decides where a word points WITHOUT expanding anything it cannot
// pin down. A word containing $pkgdir is inside the build wherever $pkgdir
// actually is; a word starting with a literal "/" is absolute whatever follows.
// Anything else is relative, which is the safe reading: makepkg cd's into
// $srcdir, so a relative path is inside the build.
func classifyPath(w pkgbuild.Word, r pkgbuild.Resolution) (pathClass, string) {
	shown := strings.Trim(w.Raw, `"'`)
	if shown == "" {
		return pathRelative, shown
	}
	for _, s := range w.Segs {
		if s.Kind != pkgbuild.SegVar {
			continue
		}
		if buildDirVars[s.Var] {
			return pathBuild, shown
		}
		if s.Var == "HOME" {
			return pathHome, shown
		}
	}
	if shown == "~" || strings.HasPrefix(shown, "~/") {
		return pathHome, shown
	}
	lead := leadingText(w, r)
	if !strings.HasPrefix(lead, "/") {
		return pathRelative, shown
	}
	for _, p := range harmlessAbsolutePrefixes {
		if strings.HasPrefix(lead, p) || lead == strings.TrimSuffix(p, "/") {
			return pathHarmless, shown
		}
	}
	if strings.HasPrefix(lead, "/home/") || strings.HasPrefix(lead, "/root/") {
		return pathHome, shown
	}
	return pathAbsoluteOutside, shown
}

// leadingText returns as much of a word's beginning as text alone establishes:
// its first literal segment, or the resolved value of a leading variable. It
// never half-expands the rest -- only the beginning is needed to know whether a
// path is absolute, and a half-expanded path is the lie resolve.go refuses to
// tell.
func leadingText(w pkgbuild.Word, r pkgbuild.Resolution) string {
	if len(w.Segs) == 0 {
		return ""
	}
	s := w.Segs[0]
	switch s.Kind {
	case pkgbuild.SegLiteral:
		return s.Text
	case pkgbuild.SegVar:
		v, ok := r.Vars[s.Var]
		if !ok || len(v.Values) == 0 || !v.Values[0].OK() {
			return ""
		}
		return v.Values[0].Text
	}
	return ""
}

// --- credential paths ----------------------------------------------------

func checkCredentials(rep *pkgbuildReporter, c pkgbuild.Command) {
	for _, w := range c.Words {
		class, shown := classifyPath(w, pkgbuild.Resolution{})
		if class == pathBuild {
			// A dotfile shipped INTO the package is content, not a credential
			// read: `install -Dm644 gpg.conf "$pkgdir/etc/skel/.gnupg/gpg.conf"`.
			continue
		}
		for _, cred := range credentialPaths {
			if !strings.Contains(w.Raw, cred.pattern) {
				continue
			}
			rep.add(ruleCredential, finding.SevCritical, fmt.Sprintf("%d:%s", w.Line, cred.pattern),
				"build step names a credential path",
				[]string{
					"path=" + shown,
					"matches " + cred.what,
					"command=" + base(c.Name()),
					"in " + where(c),
					"reads: " + quoteCommand(c),
				},
				"A build has no reason to touch the invoking user's credentials. This states that the PATH APPEARS as "+
					"an argument -- whether the command reads, writes or merely passes it was not determined, and "+
					"nothing was executed to find out.")
			break
		}
	}
}

// --- privilege escalation ------------------------------------------------

func checkPrivilege(rep *pkgbuildReporter, c pkgbuild.Command) {
	name := base(c.Name())
	if escalators[name] {
		rep.add(rulePrivEsc, finding.SevCritical, fmt.Sprintf("%d:%s", c.Line, name),
			"build step escalates privilege",
			[]string{
				"command=" + name,
				"in " + where(c),
				"reads: " + quoteCommand(c),
			},
			"makepkg refuses to run as root, so a recipe that escalates is asking for privilege the build is not "+
				"supposed to have. Whether the escalation would SUCCEED depends on the operator's sudoers, which "+
				"was not consulted.")
		return
	}
	args := c.Args()
	switch name {
	case "chmod":
		mode, rest := firstOperand(args)
		lit, ok := mode.Literal()
		if !ok || !addsSetID(lit) {
			return
		}
		if allUnderBuildDir(rest) {
			// Packaged content: brave-bin's `chmod 4755
			// "$pkgdir/opt/brave-bin/chrome-sandbox"` (measured). The installed
			// setuid file is P1-C's integrity-unowned-setuid, not this rule's.
			return
		}
		rep.add(rulePrivEsc, finding.SevCritical, fmt.Sprintf("%d:setid", c.Line),
			"build step sets a setuid/setgid bit on a path outside $pkgdir",
			[]string{
				"mode=" + lit,
				"in " + where(c),
				"reads: " + quoteCommand(c),
			},
			"A setuid bit applied to packaged content under $pkgdir is ordinary and is NOT reported here (measured: "+
				"brave-bin ships chmod 4755 on chrome-sandbox); this fired because the target is not under $pkgdir.")
	case "setcap":
		if len(args) == 0 || allUnderBuildDir(args) {
			return
		}
		rep.add(rulePrivEsc, finding.SevCritical, fmt.Sprintf("%d:setcap", c.Line),
			"build step grants capabilities to a path outside $pkgdir",
			[]string{
				"in " + where(c),
				"reads: " + quoteCommand(c),
			},
			"Capabilities granted to packaged content under $pkgdir are not reported here; this fired because the "+
				"target is not under $pkgdir.")
	}
}

// addsSetID reports whether a chmod mode ADDS setuid or setgid. `chmod u-s`
// (visual-studio-code-bin, measured) removes one and is not escalation.
func addsSetID(mode string) bool {
	if isAllDigits(mode) {
		// 4755, 2755, 6755: the leading digit carries setuid/setgid/sticky.
		if len(mode) < 4 {
			return false
		}
		return strings.ContainsAny(mode[:len(mode)-3], "24671357")
	}
	for _, clause := range strings.Split(mode, ",") {
		plus := strings.IndexByte(clause, '+')
		if plus < 0 {
			continue
		}
		if strings.Contains(clause[plus+1:], "s") {
			return true
		}
	}
	return false
}

func allUnderBuildDir(words []pkgbuild.Word) bool {
	var seen bool
	for _, w := range words {
		lit, ok := w.Literal()
		if ok && strings.HasPrefix(lit, "-") {
			continue
		}
		class, _ := classifyPath(w, pkgbuild.Resolution{})
		switch class {
		case pathBuild:
			seen = true
		case pathRelative:
			// Relative to $srcdir, which is inside the build.
			seen = true
		default:
			return false
		}
	}
	return seen
}

// --- source hosts --------------------------------------------------------

func checkSourceHosts(rep *pkgbuildReporter, r pkgbuild.Resolution, cfg PKGBUILDConfig) {
	hosts := cfg.pasteHosts()
	for _, s := range r.Sources {
		if !s.Value.OK() {
			// An unresolvable entry is a coverage gap the verdict already carries
			// (INV-9); it must never become a finding here.
			continue
		}
		if s.Host == "" {
			if s.Local && strings.Contains(s.Value.Text, "://") {
				// The entry resolved to a URL that the source-entry parser read as
				// a local file, so there is no host to check. The measured shape is
				// a bare IPv6 authority -- `http://[2001:db8::1]/x.tar.gz`, whose
				// `::` is taken as the rename:: separator -- which is exactly the
				// shape this rule exists to catch. A gap, not a finding and not
				// silence (INV-9): the host check did not run.
				rep.res.Gaps = append(rep.res.Gaps, finding.Gap{
					RuleID:  rulePasteHost,
					Subject: rep.subject,
					Reason: fmt.Sprintf("source entry %d%s resolves to %q, which contains a URL scheme but was parsed "+
						"as a local file, so no host could be extracted and the host check did not run",
						s.Index, archNote(s.Arch), s.Value.Text),
				})
			}
			continue
		}
		host := strings.ToLower(s.Host)
		var why string
		switch {
		case matchHost(hosts, host):
			why = "the host is a paste site, anonymous file drop, gist endpoint or URL shortener"
		case isBareIP(host):
			why = "the host is a bare IP address, so there is no domain to attribute the source to"
		default:
			continue
		}
		rep.add(rulePasteHost, finding.SevCritical, host,
			"source is fetched from a host no release artifact belongs on",
			[]string{
				"host=" + host,
				"url=" + s.URL,
				fmt.Sprintf("source entry %d%s", s.Index, archNote(s.Arch)),
				why,
			}, limitHost)
	}
}

func matchHost(list []string, host string) bool {
	for _, h := range list {
		h = strings.ToLower(h)
		if host == h || strings.HasSuffix(host, "."+h) {
			return true
		}
	}
	return false
}

// isBareIP reports a host that is an address literal rather than a name. The
// bracketed form is what parseSourceEntry leaves of an IPv6 authority.
func isBareIP(host string) bool {
	if strings.HasPrefix(host, "[") {
		return true
	}
	if isAllDigits(host) {
		// A dotless all-digit host is a decimal IP (http://3232235521/).
		return true
	}
	parts := strings.Split(host, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" || !isAllDigits(p) {
			return false
		}
	}
	return true
}

// --- obfuscation ---------------------------------------------------------

func checkObfuscation(rep *pkgbuildReporter, c pkgbuild.Command) {
	name := base(c.Name())
	args := c.Args()
	switch name {
	case "base64", "base32", "basenc", "base16":
		if hasFlag(args, "-d", "--decode") || hasFlag(args, "-D", "") {
			rep.report(ruleObfuscation, c, "build step decodes an encoded payload",
				"command="+name+" (decoding)")
			return
		}
	case "xxd":
		if hasFlag(args, "-r", "--revert") {
			rep.report(ruleObfuscation, c, "build step decodes a hex payload", "command=xxd -r")
			return
		}
	case "uudecode":
		rep.report(ruleObfuscation, c, "build step decodes an encoded payload", "command=uudecode")
		return
	case "openssl":
		if hasOperand(args, "enc") && hasFlag(args, "-d", "-decrypt") {
			rep.report(ruleObfuscation, c, "build step decrypts a payload", "command=openssl enc -d")
			return
		}
	}
	for _, w := range c.Words {
		if n := countHexEscapes(w.Raw); n >= 8 {
			rep.report(ruleObfuscation, c,
				"build step contains a hex-escaped string rather than readable text",
				fmt.Sprintf("%d hex escapes in one word", n))
			return
		}
		if lit, ok := w.Literal(); ok && isOpaqueToken(lit) {
			rep.report(ruleObfuscation, c,
				"build step contains a long opaque encoded token",
				fmt.Sprintf("a %d-byte word of base64 characters and nothing else", len(lit)))
			return
		}
	}
}

// report is the obfuscation rule's shared emitter: same severity, same limits,
// one finding per command.
func (p *pkgbuildReporter) report(rule string, c pkgbuild.Command, summary, detail string) {
	p.add(rule, finding.SevCritical, fmt.Sprintf("%d", c.Line), summary,
		[]string{
			detail,
			"in " + where(c),
			"reads: " + quoteCommand(c),
		},
		"Encoding hides what a build step does from review, and this pattern is absent from the 34-recipe measured "+
			"corpus. ENCODING is not reported, only decoding: `base64` without a decode flag and `gzip -d` are "+
			"ordinary. eval is deliberately not treated as obfuscation -- it is in 3 of 34 honest recipes and is a "+
			"coverage gap instead.")
}

// countHexEscapes counts \xNN sequences, which is how a payload smuggles
// readable text past a reviewer.
func countHexEscapes(s string) int {
	var n int
	// i+3 < len(s) keeps every index below in range: a \xNN escape is four bytes.
	for i := 0; i+3 < len(s); {
		if s[i] == '\\' && s[i+1] == 'x' && isHexDigit(s[i+2]) && isHexDigit(s[i+3]) {
			n++
			i += 4
			continue
		}
		i++
	}
	return n
}

// isOpaqueToken reports a long word made only of base64 characters. The
// threshold is deliberately far above anything in the measured corpus: the
// longest source URL there is 158 bytes and contains characters (':', '.') this
// charset excludes, and a sha512sum lives in an ASSIGNMENT, which no rule reads.
func isOpaqueToken(s string) bool {
	const minOpaque = 120
	if len(s) < minOpaque {
		return false
	}
	var alnum int
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			alnum++
		case c == '+', c == '/', c == '=':
		default:
			return false
		}
	}
	// A run of pure hex is a digest, not a payload; require a mixed alphabet.
	return alnum > 0 && !isAllHex(s)
}

// --- integrity -----------------------------------------------------------

func checkIntegrity(rep *pkgbuildReporter, r pkgbuild.Resolution) {
	for _, s := range r.Sources {
		if s.Local || s.VCS != "" || !s.Value.OK() || len(s.Integrity) == 0 {
			// A VCS source MUST be SKIP -- there is nothing stable to hash -- and
			// getting this backwards would fire on most -git packages (viewmd,
			// measured, is exactly this shape). A local file ships in the same AUR
			// repository as the recipe, so there is no fetch to substitute. An
			// entry with no integrity at all is not rated here: cursor-bin's
			// `sha512sums[0]=` makes the resolved arrays shorter than the source
			// array, and reporting that shape would fire on an honest recipe.
			continue
		}
		var skipped bool
		var algos []string
		var strong bool
		for _, in := range s.Integrity {
			algos = append(algos, in.Algo)
			if in.Skip {
				skipped = true
			}
			if in.Algo != "md5" && in.Algo != "ck" && in.Algo != "sha1" && !in.Skip {
				strong = true
			}
		}
		label := fmt.Sprintf("source entry %d%s", s.Index, archNote(s.Arch))
		switch {
		case skipped:
			rep.add(ruleSkipIntegrity, finding.SevSuspicious, fmt.Sprintf("%d:%s", s.Index, s.Arch),
				"fixed source URL is fetched with integrity checking disabled",
				[]string{
					"url=" + s.URL,
					label,
					"integrity=" + strings.Join(algos, ",") + " (SKIP)",
					"the URL is fixed, not a VCS reference, so whatever it serves at build time is accepted unverified",
				},
				"SKIP is MANDATORY for a VCS source and is not reported for one. On a fixed URL it means the build "+
					"trusts whatever the host serves at the time, which is what a compromised or repointed mirror "+
					"needs. It does not establish that the URL has served anything unexpected.")
		case !strong:
			// Deviation from spec §5.2, which rates this `suspicious`: 3 of the 34
			// cached recipes (brscan4, nperf-gui-appimage, flutter-bin) are
			// md5-only on a fixed URL. At suspicious this rule would fire on 9% of
			// an honest corpus and dominate the default floor -- the precedent is
			// aur-submitter-mismatch, downgraded for the same measured reason. The
			// signal stays fully rendered and reachable with --min-severity info.
			rep.add(ruleWeakIntegrity, finding.SevInfo, fmt.Sprintf("%d:%s", s.Index, s.Arch),
				"fixed source URL is verified only by a broken hash",
				[]string{
					"url=" + s.URL,
					label,
					"integrity=" + strings.Join(algos, ","),
					"md5 and sha1 collisions are constructible, so this checksum does not pin the artifact",
				},
				"Reported below the default floor deliberately: md5-only integrity is in 3 of 34 measured benign "+
					"recipes, so at `suspicious` this rule would fire on 9% of an honest corpus. It is a weak "+
					"guarantee, not evidence of tampering.")
		}
	}
}

// --- shared helpers ------------------------------------------------------

// base strips a path from a command name so /usr/bin/curl is curl.
func base(name string) string {
	if name == "" {
		return ""
	}
	if strings.ContainsRune(name, '/') {
		return path.Base(name)
	}
	return name
}

// where names the location of a command in terms a reader can act on.
func where(c pkgbuild.Command) string {
	fn := c.Func
	if fn == "" {
		fn = "the recipe body, which makepkg sources"
	} else {
		fn += "()"
	}
	return fmt.Sprintf("%s at line %d", fn, c.Line)
}

// quoteCommand renders a command for evidence, bounded.
func quoteCommand(c pkgbuild.Command) string {
	parts := make([]string, 0, len(c.Words))
	for _, w := range c.Words {
		parts = append(parts, w.Raw)
	}
	out := strings.Join(parts, " ")
	if len(out) > maxEvidenceText {
		out = out[:maxEvidenceText] + "..."
	}
	return out
}

func archNote(arch string) string {
	if arch == "" {
		return ""
	}
	return " (" + arch + ")"
}

// operands returns the non-flag words of an argument list.
func operands(args []pkgbuild.Word) []pkgbuild.Word {
	var out []pkgbuild.Word
	for _, a := range args {
		if lit, ok := a.Literal(); ok && strings.HasPrefix(lit, "-") && lit != "-" {
			continue
		}
		out = append(out, a)
	}
	return out
}

func firstOperand(args []pkgbuild.Word) (pkgbuild.Word, []pkgbuild.Word) {
	ops := operands(args)
	if len(ops) == 0 {
		return pkgbuild.Word{}, nil
	}
	return ops[0], ops[1:]
}

func hasFlag(args []pkgbuild.Word, short, long string) bool {
	for _, a := range args {
		lit, ok := a.Literal()
		if !ok {
			continue
		}
		if lit == short || (long != "" && lit == long) {
			return true
		}
		// Clustered short flags: -Dm755 carries -D, `tar -xzf` carries -x.
		if short != "" && len(short) == 2 && strings.HasPrefix(lit, "-") && !strings.HasPrefix(lit, "--") &&
			strings.ContainsRune(lit[1:], rune(short[1])) {
			return true
		}
	}
	return false
}

// hasFlagPrefix matches `sed -i.bak`.
func hasFlagPrefix(args []pkgbuild.Word, short string) bool {
	for _, a := range args {
		if lit, ok := a.Literal(); ok && strings.HasPrefix(lit, short) {
			return true
		}
	}
	return false
}

func hasOperand(args []pkgbuild.Word, want string) bool {
	for _, a := range args {
		if lit, ok := a.Literal(); ok && lit == want {
			return true
		}
	}
	return false
}

// flagValue returns the word after a flag, or the value of --flag=value.
func flagValue(args []pkgbuild.Word, short, long string) (pkgbuild.Word, bool) {
	for i, a := range args {
		lit, ok := a.Literal()
		if !ok {
			continue
		}
		if lit == short || (long != "" && lit == long) {
			if i+1 < len(args) {
				return args[i+1], true
			}
			return pkgbuild.Word{}, false
		}
		if long != "" {
			if w, ok := trimWordPrefix(a, long+"="); ok {
				return w, true
			}
		}
	}
	return pkgbuild.Word{}, false
}

// trimWordPrefix drops a literal prefix from a word, preserving the structure of
// the remainder so `of="$pkgdir/x"` still classifies as a build path.
func trimWordPrefix(w pkgbuild.Word, prefix string) (pkgbuild.Word, bool) {
	if len(w.Segs) == 0 || w.Segs[0].Kind != pkgbuild.SegLiteral || !strings.HasPrefix(w.Segs[0].Text, prefix) {
		return pkgbuild.Word{}, false
	}
	out := pkgbuild.Word{Raw: strings.TrimPrefix(strings.Trim(w.Raw, `"'`), prefix), Line: w.Line}
	first := w.Segs[0]
	first.Text = strings.TrimPrefix(first.Text, prefix)
	if first.Text != "" {
		out.Segs = append(out.Segs, first)
	}
	out.Segs = append(out.Segs, w.Segs[1:]...)
	return out, true
}

func hasStringEntry(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func isHexDigit(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func isAllHex(s string) bool {
	for i := 0; i < len(s); i++ {
		if !isHexDigit(s[i]) {
			return false
		}
	}
	return true
}
