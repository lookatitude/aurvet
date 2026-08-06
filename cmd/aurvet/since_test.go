package main

import (
	"bytes"
	"strings"
	"testing"
)

// refs builds a chain of n entries whose hashes are distinguishable and whose
// seqs start at 0, the way a real chain's do.
func refs(hashes ...string) []entryRef {
	out := make([]entryRef, len(hashes))
	for i, h := range hashes {
		out[i] = entryRef{
			Seq:  int64(i),
			Hash: h + strings.Repeat("0", 64-len(h)),
			Kind: "append",
			Time: "2026-08-0" + string(rune('1'+i)) + "T00:00:00+0000",
		}
	}
	out[0].Kind = "baseline"
	return out
}

func TestResolveEntryAcceptsEverySpelling(t *testing.T) {
	c := refs("aaaa1111", "bbbb2222", "cccc3333")

	for _, tc := range []struct {
		sel  string
		want int
		why  string
	}{
		{"", 2, "an empty selector is the head, which is what diff did before the flag existed"},
		{"head", 2, "head names the newest entry"},
		{"HEAD", 2, "the selector is case-insensitive"},
		{"head~0", 2, "head~0 is the head itself"},
		{"head~1", 1, "one step back"},
		{"head~2", 0, "back to the first entry"},
		{"0", 0, "a seq"},
		{"2", 2, "a seq naming the head"},
		{"aaaa1111", 0, "a hash prefix at exactly the minimum length"},
		{"AAAA1111", 0, "a hash prefix, upper case"},
		{"bbbb2222000", 1, "a longer hash prefix"},
		{"  1  ", 1, "surrounding whitespace is not part of the selector"},
	} {
		got, err := resolveEntry(c, tc.sel)
		if err != nil {
			t.Errorf("resolveEntry(%q) errored: %v (%s)", tc.sel, err, tc.why)
			continue
		}
		if got != tc.want {
			t.Errorf("resolveEntry(%q) = %d, want %d -- %s", tc.sel, got, tc.want, tc.why)
		}
	}
}

// The ambiguity rule is the reason resolveEntry works over entryRef instead of
// chain.Record: a Record's hash comes from signed bytes, so no test could build
// one whose hash begins with the digits of another entry's seq.
func TestResolveEntryRefusesASelectorThatIsBothASeqAndAHash(t *testing.T) {
	// Entry 2's hash begins "00000001" -- which is also a valid decimal, and a
	// chain this long has no seq 1 collision... but "00000001" parses as 1, and
	// entry 1 exists. Two readings, two different entries.
	c := refs("aaaa1111", "bbbb2222", "00000001")

	_, err := resolveEntry(c, "00000001")
	if err == nil {
		t.Fatal("a selector that is both a valid seq and a hash prefix of a DIFFERENT entry was " +
			"resolved silently; the operator would have no way to tell which baseline was used")
	}
	for _, want := range []string{"ambiguous", "seq of entry", "hash prefix of", "head~N"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the ambiguity refusal does not mention %q: %v", want, err)
		}
	}
}

// The mirror of the above: when both readings land on the SAME entry there is
// nothing ambiguous about it, and refusing would be pedantry.
func TestResolveEntryAcceptsBothReadingsAgreeing(t *testing.T) {
	// Entry 1's hash begins "00000001", and "00000001" also parses as seq 1.
	c := refs("aaaa1111", "00000001", "cccc3333")
	got, err := resolveEntry(c, "00000001")
	if err != nil {
		t.Fatalf("both readings name entry 1, so this is not ambiguous: %v", err)
	}
	if got != 1 {
		t.Errorf("resolveEntry = %d, want 1", got)
	}
}

func TestResolveEntryRefusalsSayWhatIsWrongAndListTheChain(t *testing.T) {
	c := refs("aaaa1111", "bbbb2222", "cccc3333")

	for _, tc := range []struct {
		sel   string
		wants []string
	}{
		{"9", []string{"no entry has seq 9", "3 entries", "seq 0 to 2", "the chain holds"}},
		{"deadbeef", []string{"no entry has a hash beginning", "the chain holds"}},
		{"abc", []string{"shorter than the 8 hex characters", "refused rather than matched loosely"}},
		{"nonsense", []string{"is not an entry", "give a seq", "head~N"}},
		{"head~9", []string{"steps back past the start", "3 entries", "seq 0 to 2"}},
		{"head~x", []string{"is not a relative entry", "head~N"}},
		{"head~-1", []string{"is not a relative entry"}},
	} {
		_, err := resolveEntry(c, tc.sel)
		if err == nil {
			t.Errorf("resolveEntry(%q) was accepted, want a refusal", tc.sel)
			continue
		}
		for _, want := range tc.wants {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("resolveEntry(%q) refusal is missing %q:\n%v", tc.sel, want, err)
			}
		}
	}
}

// A refusal has to name entries the operator can then type, because nothing in
// aurvet lists chain entries. A message that said only "no such entry" would
// leave them with no next move.
func TestARefusalNamesEntriesThatAreThemselvesValidSelectors(t *testing.T) {
	c := refs("aaaa1111", "bbbb2222", "cccc3333")
	_, err := resolveEntry(c, "9")
	if err == nil {
		t.Fatal("want a refusal")
	}
	msg := err.Error()
	// Every listed seq must resolve.
	for _, sel := range []string{"0", "1", "2"} {
		if !strings.Contains(msg, "seq "+sel) {
			t.Errorf("the refusal does not list seq %s:\n%s", sel, msg)
		}
		if _, err := resolveEntry(c, sel); err != nil {
			t.Errorf("the refusal lists seq %s but it does not resolve: %v", sel, err)
		}
	}
	// And the short hashes it prints must be usable as prefixes.
	for _, short := range []string{"aaaa1111", "bbbb2222", "cccc3333"} {
		if !strings.Contains(msg, short) {
			t.Errorf("the refusal does not print hash %s:\n%s", short, msg)
		}
		if _, err := resolveEntry(c, short); err != nil {
			t.Errorf("the refusal prints %s but it does not resolve: %v", short, err)
		}
	}
}

func TestResolveEntryRefusesAnAmbiguousHashPrefix(t *testing.T) {
	c := refs("aaaa1111", "aaaa1112", "cccc3333")
	_, err := resolveEntry(c, "aaaa111")
	if err == nil {
		t.Fatal("a prefix matching two entries was resolved")
	}
	// It is under the minimum length, so that is the honest complaint; either way
	// it must not silently pick one.
	if !strings.Contains(err.Error(), "hex characters") && !strings.Contains(err.Error(), "matches 2") {
		t.Errorf("unexpected refusal: %v", err)
	}

	// At full minimum length and still colliding, the refusal must list both.
	c2 := refs("aaaa1111aa", "aaaa1111bb", "cccc3333")
	_, err = resolveEntry(c2, "aaaa1111")
	if err == nil {
		t.Fatal("a minimum-length prefix matching two entries was resolved")
	}
	for _, want := range []string{"matches 2 entries", "lengthen it", "seq 0", "seq 1"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the collision refusal is missing %q:\n%v", want, err)
		}
	}
}

func TestResolveEntryOnAnEmptyChain(t *testing.T) {
	if _, err := resolveEntry(nil, "0"); err == nil {
		t.Fatal("an empty chain must not resolve any selector")
	}
}

// The cap keeps a refusal readable, and it must say how many it hid rather than
// simply stopping -- a truncated list that looks complete is the reporting
// failure this project treats as a defect.
func TestALongChainRefusalSaysWhatItDidNotShow(t *testing.T) {
	hashes := make([]string, 0, 25)
	for i := 0; i < 25; i++ {
		hashes = append(hashes, string(rune('a'+i%6))+"bcd111"+string(rune('a'+i%6)))
	}
	c := refs(hashes...)
	for i := range c {
		c[i].Hash = "h" + strings.Repeat("0", 62) + string(rune('a'+i%26))
	}
	_, err := resolveEntry(c, "999")
	if err == nil {
		t.Fatal("want a refusal")
	}
	if !strings.Contains(err.Error(), "older entries") {
		t.Errorf("a capped listing did not say how many entries it hid:\n%v", err)
	}
}

// -- through the command --------------------------------------------------------

// chainOfThree signs three entries whose manifests differ, so that diffing
// against different entries is a distinguishable operation rather than three
// identical answers.
func chainOfThree(t *testing.T) (state string) {
	t.Helper()
	state = stateWithTrust(t)
	if code := runBaseline(initOpts(t, state, fakeEvidence(t)), &bytes.Buffer{}, &bytes.Buffer{}); code != exitClean {
		t.Fatal("init failed")
	}
	for _, digest := range []string{"d", "e"} {
		ev := fakeEvidence(t)
		ev.Packages[0].MtreeSHA256 = strings.Repeat(digest, 64)
		ev.Observed[0].MtreeSHA256 = strings.Repeat(digest, 64)
		o := initOpts(t, state, ev)
		o.args = []string{"append"}
		var out, errb bytes.Buffer
		if code := runBaseline(o, &out, &errb); code != exitClean {
			t.Fatalf("append failed: %d\n%s\n%s", code, out.String(), errb.String())
		}
	}
	return state
}

// The point of the flag: an older basis sees drift the newest one does not,
// because the newest baseline already recorded the change.
func TestDiffSinceAnOlderEntryReportsDriftTheHeadDoesNot(t *testing.T) {
	state := chainOfThree(t)

	// The observed system matches the HEAD baseline exactly.
	ev := fakeEvidence(t)
	ev.Observed[0].MtreeSHA256 = strings.Repeat("e", 64)

	run := func(since string) (int, string) {
		o := initOpts(t, state, ev)
		o.args = []string{"diff"}
		o.since = since
		var out, errb bytes.Buffer
		code := runBaseline(o, &out, &errb)
		return code, out.String() + errb.String()
	}

	_, headOut := run("")
	if !strings.Contains(headOut, "0 unexplained") {
		t.Fatalf("the system matches the head baseline, so nothing should be unexplained:\n%s", headOut)
	}
	// Logged because `baseline init` refuses unprivileged and this suite is the
	// only place a real signed chain gets built: `go test -v -run DiffSince` is how
	// a reviewer reads the actual wording without a root shell.
	t.Logf("diff (no -since):\n%s", firstLine(headOut))

	// Against entry 0, whose manifest recorded a different digest, the same system
	// has drifted.
	_, oldOut := run("0")
	t.Logf("diff -since 0:\n%s", firstLine(oldOut))
	if strings.Contains(oldOut, "0 unexplained") {
		t.Fatalf("-since 0 found no drift, but entry 0's manifest recorded a different digest than "+
			"the system now has:\n%s", oldOut)
	}
	if !strings.Contains(oldOut, "entry seq 0") {
		t.Errorf("the output does not name the basis it used:\n%s", oldOut)
	}
	if !strings.Contains(oldOut, "NOT the newest baseline") {
		t.Errorf("a diff against an older entry must say so, or its numbers read as though they "+
			"were measured from the current baseline:\n%s", oldOut)
	}
}

// head~N and a hash prefix must select the same entry a seq does.
func TestDiffSinceSpellingsAgree(t *testing.T) {
	state := chainOfThree(t)
	ev := fakeEvidence(t)
	ev.Observed[0].MtreeSHA256 = strings.Repeat("e", 64)

	run := func(since string) string {
		o := initOpts(t, state, ev)
		o.args = []string{"diff"}
		o.since = since
		var out, errb bytes.Buffer
		runBaseline(o, &out, &errb)
		return out.String() + errb.String()
	}
	bySeqOut := run("0")
	byRelOut := run("head~2")
	if !strings.Contains(bySeqOut, "entry seq 0") || !strings.Contains(byRelOut, "entry seq 0") {
		t.Fatalf("seq and head~N did not select the same entry:\n--- seq 0:\n%s\n--- head~2:\n%s",
			bySeqOut, byRelOut)
	}
}

// Every run names its basis, with or without the flag. Before the flag existed
// the line carried only the manifest timestamp, which does not identify an entry.
func TestDiffAlwaysNamesTheEntryItMeasuredFrom(t *testing.T) {
	state := chainOfThree(t)
	o := initOpts(t, state, fakeEvidence(t))
	o.args = []string{"diff"}
	var out, errb bytes.Buffer
	runBaseline(o, &out, &errb)
	got := out.String()
	if !strings.Contains(got, "entry seq 2") {
		t.Errorf("a diff with no -since does not name its basis entry:\n%s", got)
	}
	if strings.Contains(got, "NOT the newest") {
		t.Errorf("a diff against the head must not warn that it is not the newest:\n%s", got)
	}
}

func TestDiffSinceAnUnknownEntryIsAUsageErrorThatListsTheChain(t *testing.T) {
	state := chainOfThree(t)
	o := initOpts(t, state, fakeEvidence(t))
	o.args = []string{"diff"}
	o.since = "41"
	var out, errb bytes.Buffer
	code := runBaseline(o, &out, &errb)
	if code != exitUsage {
		t.Fatalf("diff -since 41 = %d, want %d (usage)", code, exitUsage)
	}
	combined := out.String() + errb.String()
	for _, want := range []string{"no entry has seq 41", "the chain holds", "seq 0"} {
		if !strings.Contains(combined, want) {
			t.Errorf("the refusal is missing %q:\n%s", want, combined)
		}
	}
}

// An unknown entry must never fall back to the head: silently diffing against a
// different basis than the one asked for is a wrong answer presented as a right
// one.
func TestDiffSinceNeverFallsBackToTheHead(t *testing.T) {
	state := chainOfThree(t)
	o := initOpts(t, state, fakeEvidence(t))
	o.args = []string{"diff"}
	o.since = "41"
	var out, errb bytes.Buffer
	runBaseline(o, &out, &errb)
	if strings.Contains(out.String(), "drift against baseline") {
		t.Fatalf("an unresolvable -since produced a drift report anyway:\n%s", out.String())
	}
}

// -since means nothing to the other subcommands, so they refuse it. An ignored
// flag would let `baseline init -since 0` look as though it had honoured one.
func TestSinceIsRefusedBySubcommandsThatDoNotUseIt(t *testing.T) {
	state := chainOfThree(t)
	for _, sub := range []string{"init", "append", "status", "show", "verify", "pushed"} {
		o := initOpts(t, state, fakeEvidence(t))
		o.args = []string{sub}
		o.since = "0"
		var out, errb bytes.Buffer
		code := runBaseline(o, &out, &errb)
		if code != exitUsage {
			t.Errorf("baseline %s -since 0 = %d, want %d: an unused flag must be refused, not "+
				"ignored", sub, code, exitUsage)
		}
		if !strings.Contains(errb.String(), "-since") {
			t.Errorf("baseline %s refused without naming the flag:\n%s", sub, errb.String())
		}
	}
}

// diff still takes no POSITIONAL argument: the selector is a flag, and accepting
// `aurvet diff HEAD~1` would honour a spelling the tool does not implement.
func TestDiffStillRejectsAPositional(t *testing.T) {
	state := chainOfThree(t)
	o := initOpts(t, state, fakeEvidence(t))
	o.args = []string{"diff", "head~1"}
	var out, errb bytes.Buffer
	if code := runBaseline(o, &out, &errb); code != exitUsage {
		t.Fatalf("diff head~1 = %d, want %d", code, exitUsage)
	}
	if !strings.Contains(errb.String(), "takes no arguments") {
		t.Errorf("unexpected message:\n%s", errb.String())
	}
}

// firstLine returns the drift headline plus any "!!" warning under it -- the
// lines that say what was measured and from where.
func firstLine(s string) string {
	var keep []string
	for _, l := range strings.Split(s, "\n") {
		if strings.HasPrefix(l, "drift against baseline") || strings.HasPrefix(l, "!!") {
			keep = append(keep, l)
		}
	}
	if len(keep) == 0 {
		return s
	}
	return strings.Join(keep, "\n")
}
