// cmd/aurvet/since.go
//
// Resolving `--since ENTRY` to one chain entry.
//
// Spec §14 spells the flag and not its argument, so the accepted forms are a
// decision made here:
//
//   - a SEQ, the decimal position printed by `baseline init`/`append` and bounded
//     by the entry count `baseline status` reports. This is the canonical form: it
//     is short, stable, and already discoverable without a new listing command.
//   - a HASH PREFIX of at least minHashPrefix hex characters, so the 12-character
//     hash `status` and `append` print can be pasted straight in.
//   - head, or head~N, for the common "the one before this" case.
//
// # Ambiguity is refused, never guessed
//
// A token like `12345678` is both a decimal seq and a valid hex prefix. Where
// both readings resolve to DIFFERENT entries this refuses and says so rather than
// picking one, because the two readings would silently diff against different
// baselines and the operator would have no way to tell which they got. Being told
// to disambiguate costs a second attempt; a wrong basis costs a wrong answer.
//
// # A refusal enumerates
//
// Nothing in aurvet lists chain entries, so a bad selector cannot be answered
// with "see `baseline show`" -- that would name a command which does not carry the
// information. The refusals below print the entries themselves, which is the same
// rule `triage list` follows when it names a dead record: do not report something
// the operator cannot act on.
//
// # Why the matching is separate from chain.Record
//
// resolveEntry works over entryRef rather than chain.Record so every branch is
// reachable from a test. A Record's hash is unexported and computed from signed
// bytes, so a test cannot construct one whose hash begins with chosen digits --
// which is exactly the input the ambiguity rule above exists for. Matching that
// could not be tested for the case it was written for would be matching nobody
// has checked.
package main

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/lookatitude/aurvet/internal/chain"
)

// minHashPrefix is the shortest accepted hash prefix. Eight hex characters is
// short enough to type and long enough that a collision in a chain of any
// plausible length is not a thing anyone will meet; a shorter prefix is refused
// with the minimum named rather than matched loosely.
const minHashPrefix = 8

// entryRef is the part of a chain entry a selector can name or a refusal needs to
// print. It exists so resolveEntry is a pure function of comparable values.
type entryRef struct {
	Seq  int64
	Hash string
	Kind string
	Time string
}

func (e entryRef) String() string {
	return fmt.Sprintf("seq %d  %s  %s  %s", e.Seq, short12(e.Hash), e.Kind, e.Time)
}

// refOf names one record the way every other command in this tool names it.
func refOf(r chain.Record) entryRef {
	return entryRef{Seq: r.Entry.Seq, Hash: r.Hash(), Kind: r.Entry.Kind, Time: r.Entry.Time}
}

// selectEntry resolves a --since selector to one record. An empty selector means
// the head, which is what `diff` compared against before the flag existed.
//
// records is in chain order, oldest first, exactly as chain.Store.Load returns
// it, and every record has already been authenticated against the trusted set by
// the caller. This function chooses among verified records; it never widens what
// is trusted.
func selectEntry(records []chain.Record, sel string) (chain.Record, error) {
	refs := make([]entryRef, len(records))
	for i, r := range records {
		refs[i] = refOf(r)
	}
	i, err := resolveEntry(refs, sel)
	if err != nil {
		return chain.Record{}, err
	}
	return records[i], nil
}

// resolveEntry returns the index of the entry the selector names.
func resolveEntry(refs []entryRef, sel string) (int, error) {
	if len(refs) == 0 {
		return 0, errors.New("the chain has no entries")
	}
	last := len(refs) - 1

	s := strings.TrimSpace(sel)
	if s == "" {
		return last, nil
	}
	low := strings.ToLower(s)

	if low == "head" {
		return last, nil
	}
	if rest, ok := strings.CutPrefix(low, "head~"); ok {
		n, err := strconv.Atoi(rest)
		if err != nil || n < 0 {
			return 0, fmt.Errorf("%q is not a relative entry: write head~N, where N is a whole "+
				"number of entries to step back (head~0 is the head itself)", sel)
		}
		i := last - n
		if i < 0 {
			return 0, fmt.Errorf("head~%d steps back past the start of the chain, which holds %s "+
				"(seq %d to %d)\n%s", n, countEntries(len(refs)), refs[0].Seq, refs[last].Seq,
				entryList(refs))
		}
		return i, nil
	}

	seqHit, seqParsed := bySeq(refs, s)
	hashHits, hexParsed := byHashPrefix(refs, low)

	// Both readings resolved, and to different entries: refuse. See the package
	// comment -- guessing here would pick a baseline the operator did not choose.
	if seqHit >= 0 && len(hashHits) == 1 && hashHits[0] != seqHit {
		return 0, fmt.Errorf("%q is ambiguous: it is the seq of entry [%s] and also a hash prefix of "+
			"entry [%s]. Disambiguate with head~N or a longer hash prefix",
			sel, refs[seqHit], refs[hashHits[0]])
	}
	if seqHit >= 0 {
		return seqHit, nil
	}
	switch len(hashHits) {
	case 1:
		return hashHits[0], nil
	case 0:
		// Nothing matched. Which message is useful depends on what the operator
		// appears to have typed, so say that rather than one generic line. seq is
		// tested first: an all-digit token is also valid hex, and "no entry has seq
		// 12345678" is the more likely reading of it than a hash prefix.
		switch {
		case seqParsed:
			return 0, fmt.Errorf("no entry has seq %s; the chain holds %s (seq %d to %d)\n%s",
				s, countEntries(len(refs)), refs[0].Seq, refs[last].Seq, entryList(refs))
		case hexParsed:
			return 0, fmt.Errorf("no entry has a hash beginning %q\n%s", low, entryList(refs))
		case isHexString(low):
			return 0, fmt.Errorf("%q is shorter than the %d hex characters a hash prefix needs; a "+
				"shorter prefix is refused rather than matched loosely\n%s",
				sel, minHashPrefix, entryList(refs))
		default:
			return 0, fmt.Errorf("%q is not an entry: give a seq, a hash prefix of at least %d hex "+
				"characters, or head~N\n%s", sel, minHashPrefix, entryList(refs))
		}
	default:
		var b strings.Builder
		fmt.Fprintf(&b, "hash prefix %q matches %d entries; lengthen it:", low, len(hashHits))
		for _, i := range hashHits {
			fmt.Fprintf(&b, "\n  %s", refs[i])
		}
		return 0, errors.New(b.String())
	}
}

// bySeq returns the index of the entry whose Seq the token names, or -1, plus
// whether the token looked like a seq at all. A token that is not a non-negative
// decimal is left to the other readings rather than being rejected here.
func bySeq(refs []entryRef, s string) (int, bool) {
	if !isAllDigits(s) {
		return -1, false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return -1, true // a decimal too large for int64 still reads as a seq
	}
	for i, r := range refs {
		if r.Seq == n {
			return i, true
		}
	}
	return -1, true
}

// byHashPrefix returns the indices of every entry whose hash begins with the
// token, and whether the token was long enough to be treated as a prefix at all.
func byHashPrefix(refs []entryRef, low string) ([]int, bool) {
	if len(low) < minHashPrefix || !isHexString(low) {
		return nil, false
	}
	var hits []int
	for i, r := range refs {
		if strings.HasPrefix(strings.ToLower(r.Hash), low) {
			hits = append(hits, i)
		}
	}
	return hits, true
}

// entryList renders the chain for a refusal message, newest first because the
// recent end is what an operator is choosing between. Long chains are capped so
// a refusal stays readable, and the cap says how many it hid rather than
// trailing off.
func entryList(refs []entryRef) string {
	const maxShown = 10
	var b strings.Builder
	b.WriteString("the chain holds:")
	shown := 0
	for i := len(refs) - 1; i >= 0 && shown < maxShown; i-- {
		fmt.Fprintf(&b, "\n  %s", refs[i])
		shown++
	}
	if hidden := len(refs) - shown; hidden > 0 {
		fmt.Fprintf(&b, "\n  ... and %d older entr%s, seq %d to %d", hidden,
			plural(hidden, "y", "ies"), refs[0].Seq, refs[hidden-1].Seq)
	}
	return b.String()
}

func countEntries(n int) string {
	return fmt.Sprintf("%d entr%s", n, plural(n, "y", "ies"))
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
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

func isHexString(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
