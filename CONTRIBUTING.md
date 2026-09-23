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

**The epoch-tree vectors carry the whole tree where they can.** V-P-05 records every leaf of its
epoch and every hashing step behind its one proof: the epoch key, the slot seed, the leaf as it enters
the tree, a padding leaf beside it, and each node up the path. V-P-06 records every leaf, the whole
assignment and three proofs in full, and verifies all 255 while it is generated. Above 256 slots the
leaf set is left out and the root, the assignment and the proofs are kept, which is why V-P-06b's
`H = 12` half is shorter than its `H = 4` half. The master key in these files is a specification test
key whose bytes spell out what it is; a real `k_master` never appears in this repository.

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
| `checks` | Formatting, clippy and the tests, in each of the four feature sets, for both engine crates, and the bare-metal `no_std` builds. |
| `miri` | The engine crates under Miri. The statistical privacy tests are ignored there and run in `checks`: Miri is for undefined behaviour, and the structural tests reach the same code paths for a fraction of the cost. |
| `deny` | Advisories, licences, sources and bans. |

Clippy runs once per feature set, because code behind a feature gate is only linted when that
feature is compiled.

## The privacy release gate

§4.4's V-Z-02, V-Z-03 and V-Z-04 are release blockers and run in `checks` at the sample sizes D-66
fixes. V-Z-04's full 10,000-epoch run takes about two seconds in a release build and two and a half
minutes in the debug build `checks` uses, so it is ignored by default and run before submission:

```sh
cargo test --release -p certimining-log -- --ignored
```

Its three correlations are recorded on issue #16. The bound there is 0.02, against 0.05 at the sample
CI runs.
