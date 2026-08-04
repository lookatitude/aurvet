# cgit fixtures — captured, not constructed

Fetched 2026-08-04 from `https://aur.archlinux.org/cgit/aur.git/log/?h=<base>`.
These exist because the tombstone matcher was originally written against markup
cgit does not emit (`class='logsubject'`, a `logmsg` body cell), and the review
that found the resulting defects could only construct its evidence, not pin it.

| File | Base | Status | Shape |
|---|---|---|---|
| `log-tombstoned-librewolf-fix-bin.html` | `librewolf-fix-bin` | 200 | exactly one log row, subject `history removed due to malware` |
| `log-present-yay.html` | `yay` | 200 | 50 log rows, ordinary upgpkg subjects |
| `log-404-nonexistent-branch.html` | `zzz-arch-drift-does-not-exist-zzz` | **404** | cgit error page, zero log rows |

## Measured facts these fixtures pin

1. **A nonexistent branch returns 404, not 200 with the default branch's log.**
   This was the open question that would have escalated page-wide matching from
   "plausible false accusation" to "systematic": if a bogus `h=` served the
   shared `master` log, every not-in-AUR package would be checked against other
   packages' commit messages. It does not.
2. **The commit subject is the anchor text of the second cell of each log row**,
   inside `<table class='list nowrap'>`, delimited by `</a>`:
   `<td><a href='/cgit/aur.git/commit/?h=BASE&amp;id=SHA'>SUBJECT</a></td>`.
   The newest commit is the first such row. There is no `logsubject` class and
   no message body unless `showmsg=1` is requested.
3. **Subjects are HTML-escaped** in that anchor text, so `'` arrives as `&#39;`.
   Classification must unescape before matching or the escaping eats the keyword.
4. The page also contains a search form and six tab links that mention the base,
   which is why matching the whole page body rather than the extracted subject
   produces false positives.

Verified tombstone wording, from the real 2025 removal:
`history removed due to malware`.
