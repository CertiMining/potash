# Contributing

## Vectors are generated, never edited

Everything under `vectors/` is output. It is produced by

```sh
cargo xtask gen-vectors
```

**The generator never deletes.** It writes into a directory it creates, and refuses one that already
holds files. To replace a committed set you remove it yourself first, which keeps the deletion a
deliberate act:

```sh
rm -rf vectors && cargo xtask gen-vectors
```

Then commit what it wrote, including `vectors/MANIFEST.sha256`. Each manifest line carries the
SHA-256, the file mode and the name, so a vector that was edited and one that became executable or
unreadable both fail the check.

**Editing a file under `vectors/` by hand will fail CI.** Two checks stand in the way, and they
catch different mistakes:

- `shasum -a 256 -c MANIFEST.sha256` catches an edited vector.
- Regenerating into a temporary directory and comparing catches an edit whose manifest was updated
  to match, and a generator that has drifted from the output committed beside it.

Both run in the `vectors` group: `scripts/ci.sh vectors`.

## What a vector contains

Byte strings are lowercase hex with a `0x` prefix. **Integers are decimal strings**, because the
TypeScript verifier of E-11 reads these files and a JSON number there is a double, which would
misread any value above 2^53. Keys are sorted, indentation is two spaces, and nothing environmental
appears in a file: no timestamps, no toolchain versions, no paths. That is what makes regeneration
identical on another machine.

Every hashing step records its preimage as well as its digest, so an implementation that disagrees
can tell whether it built the wrong bytes or hashed the right ones wrongly.

**Vector identifiers come from §4.3 and §4.2, never from this repository.** Where the specification
gives one identifier to several inputs, such as V-N-02's gap and replay, the file carries them as
cases under that one identifier. A new identifier is declared in the specification first, as V-N-25
was, and never invented here as a suffix.

**The generator holds its own copy of the specification's values.** `xtask/src/spec.rs` carries the
domain tags, the canonical form of V-P-01, every preimage layout and §1.8's limits, transcribed by
hand and read from nothing. The generator checks the engine against them and stops if they disagree,
so an engine that has drifted cannot write its drift into the committed set.

**Two kinds of expectation, with different authority.** A positive vector's digests lock the
engine's output: no document can state a digest, and what stands behind them is KAT-01 and the
independent re-implementation at E-11. A negative vector's error code, and every assertion §4.2
makes — that two spellings agree, that a recomputed head matches, that a flag does not move a digest
— come from the specification. The generator writes those from §4.3's table and §4.2's claims, runs
the engine, and **fails generation if the engine disagrees**. A generator that recorded whatever the
engine returned would enshrine an engine's mistake as the correct answer, and the TypeScript verifier
would then be obliged to reproduce it.

Where a signature is needed, the key is **RFC 8032 §7.1's published specification test key**, named
as such in every file that shows it. Its private half is public, so anyone can reproduce any
signature in the set. No generated key and no real key belongs in this repository.

## Running the checks

`scripts/ci.sh all` is the pipeline CI runs, verbatim. Individual groups:

| Group | What it does |
|---|---|
| `kat01-offchain`, `kat01-onchain` | Keccak-256 against the published vectors, off-chain then on the Solana runtime. A failure stops the build. |
| `kat02` | Ed25519 against RFC 8032 §7.1. |
| `vectors` | The manifest, and regeneration. |
| `checks` | Formatting, clippy and the tests, in each of the four feature sets. |
| `miri` | The core crate under Miri. |
| `deny` | Advisories, licences, sources and bans. |

Clippy runs once per feature set, because code behind a feature gate is only linted when that
feature is compiled.
