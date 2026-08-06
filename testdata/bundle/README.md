# testdata/bundle

Golden fixtures for `internal/bundle`: one delegation with two of three root
signatures, and one indicator bundle signed by the online key that delegation
names.

## There is no production key material here, and there never will be

Every key behind these files is a throwaway ed25519 key derived in-process from a
fixed one-byte seed (`internal/bundle/helpers_test.go`). Nothing here is, or
resembles, a release key:

- **no private key file is committed**, in any form;
- the public halves are not committed either — they are recomputed from the
  seeds each run, so there is no file anyone could mistake for a trust anchor;
- the compiled-in root set (`embeddedRootKeys` in `internal/bundle/roots.go`) is
  **empty**, and a build with an empty root set refuses to consume any bundle.
  That refusal has its own test.

Generating the real 2-of-3 root key set is a human action performed on hardware
tokens, off any machine that builds this repository. See
`docs/key-compromise-runbook.md`.

## Why these files are committed at all

The wire format has to be pinned. ed25519 signing is deterministic, canonical
serialisation is deterministic, and nothing in `internal/bundle` reads a clock —
so these bytes are reproducible forever. `TestGoldenFixturesAreByteStable`
regenerates them and compares byte for byte.

A diff here means the document format moved. That is sometimes correct and
always a decision: a format change makes bundles signed by the publisher
unreadable to already-released binaries, and vice versa. It must surface as a
failing test rather than as a quietly different document.

Regenerate deliberately:

```
AURVET_UPDATE_GOLDEN=1 go test ./internal/bundle/ -run Golden
```

## Files

| File | What it is |
| --- | --- |
| `delegation.json` | canonical delegation document, serial 7, one online signing key with a 62-day window |
| `delegation.json.sig.1`, `.2` | detached SSHSIG signatures from two of the three throwaway root keys, namespace `delegation.aurvet.dev` |
| `bundle.json` | canonical indicator bundle, version 5, six indicators |
| `bundle.json.sig` | detached SSHSIG from the online key, namespace `bundle.aurvet.dev` |

The two namespaces are distinct on purpose. A signature made over a bundle must
not verify as a delegation — otherwise an online key could name its own
successor and the offline root set would be decorative.
`TestAttackNamespaceConfusionBetweenBundleAndDelegation` checks both directions.
