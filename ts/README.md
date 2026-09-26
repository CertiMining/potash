# TCU-02 disclosure-package verifier (TypeScript)

An independent verifier for the §2.5 disclosure package of *TCU-02 — CertiMining Anchored Log*,
v0.1.18. It was written from the specification in `../spec/` and from the committed vectors in
`../vectors/`, and from nothing else. No other implementation of this specification was read while
it was built, which is the only reason agreement between the two carries any information.

It satisfies INV-DISC-01, INV-DISC-02, INV-DISC-03 and INV-IFACE-01, and it reproduces every
committed vector.

---

## What it checks

Given a §2.5 package, a root and, when the caller has it, the log's configured height, the verifier
runs these in this order and stops at the first that fails.

1. **The package is a §2.5 package.** `schema` is `certimining/v1/disclosure`, every field named in
   §2.5 is present and of the right shape, hex fields are hex of the right length, integers are
   exactly representable, and `preimage_borsh` is strict base64. A field §2.5 does not list is
   reported and does not refuse the package.
2. **`preimage_borsh` is a §1.3 leaf preimage.** 161 bytes, opening with `CMv1LEAF`. Another tag is
   `0x0B` (V-N-09); another length is `0x05`.
3. **The display copy agrees with the bytes.** Every field is derived from the preimage and
   compared against the JSON's copy, in the order §1.3 writes them, stopping at the first that
   differs. This runs **before** the signature check and **before** the inclusion check, because
   until the two agree there is no single record to judge. `flags` is excluded (INV-DISC-03).
   A disagreement is a verifier-level failure named `JsonBorshMismatch`, carrying **no §2.1 code**:
   §2.1's codes belong to §1.3's transition conditions and no registry ever sees a package.
4. **The leaf.** `Keccak256` of those 161 bytes, recomputed rather than taken from the package.
5. **The qualified person's signature**, Ed25519 over the 161 preimage bytes under the `qp_key` the
   *preimage* carries, never the JSON's copy (INV-ENC-03). Absent is `0x06`, bad is `0x07`.
6. **The chain segment.** `chain.head` must be `Keccak256(TAG_HEAD ‖ prev_head ‖ leaf)`, else
   `0x03`. When `seq` is 1, `prev_head` must be `chain.genesis`, else `ChainSegmentBroken`.
7. **Inclusion**, against a root the caller obtained independently. The verifier applies `TAG_MTL0`
   to the leaf itself, walks `height` siblings by the bits of `slot_index`, and compares with the
   root. A sibling count that is not `height`, a `slot_index` outside the tree, a height outside
   §1.8's [4, 16], or a path that does not reach the root is `0x13`. Given the log's configured
   height, a proof whose `height` disagrees is `0x13` before any hashing (V-N-16b).
8. **Flags**, which are advisory and never a reason to refuse. Given the chain context the
   computation needs, they are recomputed and any discrepancy is reported; without it they are
   reported as not recomputable. See SPEC-DEFECTS.md D-3.

Beside the package verifier, and used by the vector suite, the same code carries §1.3's state
machine and its four stages, §1.3's canonicalization, §1.4's epoch tree with PRF slot assignment
and padding, §1.6's promise policy and D-72's window, and §2.4's address derivation and account
decoding.

### Fetching a root

The verifier derives the checkpoint address itself and decodes the account itself, because address
derivation is the step that decides which account is being read. It speaks JSON-RPC over `fetch`.
No Solana SDK is on the path.

- `LogConfig` at the PDA for seeds `["cm_cfg"]`, `CheckpointAccount` at `["cm_ckpt", epoch_le]`,
  both derived by the SHA-256 construction, with the canonical bump and the off-curve check.
- Every byte of both layouts is accounted for, `LogConfig.start_epoch` at offset 52 included. That
  field is where §1.4 puts the beginning of a log, and §1.4's clock, `floor(unix_seconds / 86400)`,
  is implemented as `utcDayIndex`.
- The 8-byte Anchor discriminators are **computed** from `SHA-256("account:" ‖ N)` rather than
  copied from §2.4's table, and a test asserts they equal the two constants the table publishes.
- A fetched account is refused unless it is owned by the program, carries the right discriminator,
  is exactly the length §2.4 fixes, and answers for the epoch that was asked for.
- **An absent checkpoint is refused with the reason it is absent**, which is what INV-ANCH-02 asks a
  client to distinguish. An epoch before `start_epoch` is `EpochBeforeLogStart`, a day the log did
  not exist for and not a gap. An epoch inside `start_epoch .. last_epoch` is
  `CheckpointSequenceGap`. An epoch past `last_epoch` is `CheckpointNotYetPublished`, carrying
  `last_epoch` so a caller holding a clock can measure the lag. Reporting the three alike would
  accuse a batcher of failing to publish before it was deployed. The log's configuration is read
  only when a checkpoint is missing, or not at all when the caller passes one in.

## What it does not check

- **`payload_uri`.** It is in §2.5's `record` block and not in §1.3's leaf preimage, so nothing
  binds it to the signature and no comparison can reach it. SPEC-DEFECTS.md D-1.
- **`chain.genesis` for a record past `seq` 1.** One package carries no intermediate leaves, so
  the genesis cannot be walked forward to `prev_head`. D-4.
- **`flags`, unless the caller supplies chain context.** Bits 0 and 1 are properties of earlier
  records. D-3.
- **The `anchor` block.** `solana_tx`, `solana_slot` and `ots_receipt_digest` are not checked
  against anything. Publication provenance enters through the checkpoint account the verifier
  fetches for `inclusion.epoch`, which is the seam §2.3 leaves to the caller. D-12.
- **`published_unix` against the epoch a checkpoint names.** §1.4 gives the epoch an arithmetic
  meaning, and nothing relates it to the publication timestamp beside it. INV-ANCH-01 licenses the
  landing time to vary and INV-ANCH-02 contemplates a batcher that lags, so a root published today
  may legitimately name a much earlier day. SPEC-DEFECTS.md D-14.
- **Whether `start_epoch` is the day index the chain reported at `initialize`.** That is a rule on
  `initialize`, and it cannot be re-derived from the account, which does not record the slot it was
  written in. The verifier reads the field and reports it rather than refusing a log that predates
  the rule. D-15.
- **Whether the batcher is behind.** Measuring the lag of `last_epoch` against today needs a clock,
  and the verifier holds none. It reports `last_epoch` and leaves the judgement to the caller. D-16.
- **Whether the root is the one the honest batcher published.** The verifier checks that the
  account at the derived address answers for that epoch. It cannot check that the authority
  published a root over a tree it honestly built, which INV-GOV-02 and RES-03 already say.
- **Anything §0 excludes.** Asset equivocation, NI 43-101 compliance, whether the estimate is
  accurate, and whether the log is complete.

## How to run it

```
npm ci                 # installs the two runtime dependencies and the two dev ones, from the lock file
npm test               # KAT-01 and KAT-02 first, then everything else; no network
npm run typecheck      # tsc --noEmit over src and test
npm run build          # emits dist/: src only, no Node types, ES modules for a browser
npm run test:net       # adds the devnet test, which npm test skips
node tools/mutation-check.mjs   # breaks one thing at a time and checks the suite goes red
```

`npm test` runs `node --test test/kat.test.ts` first and stops if it fails, which is what §4.1 asks
of KAT-01. The devnet test is skipped unless `CERTIMINING_DEVNET=1`, so it never runs in CI and
never runs by default.

There is no build step for the tests. Node runs the TypeScript sources directly, and the sources
are written so that every type annotation is erasable (`erasableSyntaxOnly`), which is checked by
`npm run typecheck`.

### One code path, two runtimes

`src/` uses no Node API. It builds under `tsconfig.build.json`, which sets `"types": []` and so
removes Node's type declarations altogether, and the emitted `dist/` contains no `process`,
`Buffer`, `require` or `__dirname`. Hex, base64 and base58 are written out rather than taken from a
platform, so what the verifier refuses is the same in both runtimes. `fetch`, `TextEncoder`,
`TextDecoder` and `performance` are the only platform APIs used, and both runtimes have all four.
Node's `fs`, `path`, `crypto` and `os` appear in `test/` only.

## Layout

```
src/bytes.ts             hex, strict base64, little-endian integers, UTF-8
src/errors.ts            §2.1's codes, and the package-level failures that carry no code
src/tags.ts              §1.2's domain tags
src/hash.ts              Keccak-256, Ed25519 (RFC 8032), and SHA-256 walled off for §2.4
src/preimage.ts          every §1.2/§1.3/§1.4/§1.6 writer, through one 256-byte sink (0x0C)
src/canonical.ts         §1.3's canonical tenure
src/chain.ts             §1.3's commitment, genesis, leaf, and the four-stage transition
src/tree.ts              §1.4's PRF, slot assignment, padding, build, proof, pure verifier
src/promise.ts           §1.6's SPI, its policy, and D-72's window
src/disclosure.ts        §2.5's package and INV-DISC-02's verifier
src/solana/base58.ts     addresses in and out
src/solana/pda.ts        §2.4's program-derived addresses
src/solana/accounts.ts   §2.4's two layouts, their computed discriminators, §1.4's epoch clock
src/solana/rpc.ts        getAccountInfo over fetch, and the two fetches a verifier needs
test/kat.test.ts         §4.1's KAT-01 and KAT-02; runs first
test/vectors.test.ts     the manifest, the enumeration, and every committed vector
test/handlers.ts         one handler per vector
test/disclosure.test.ts  assembled §2.5 packages, right and wrong in each way INV-DISC-02 names
test/packages.ts         how those packages are assembled
test/units.test.ts       §2.4, §1.6's policy, canonicalization, the preimage ceiling, encodings
test/perf.test.ts        §4.4a
test/devnet.test.ts      the one test that touches a network; skipped by default
tools/mutation-check.mjs the evidence that each test fails for the reason it names
```

## The deployment this was run against

`test/devnet.test.ts`, run by hand on 26 September 2026 against
`HS82CAXgVykfVniBzPp9eArDfVLmFYcik3evyAx7iVZB`, read `LogConfig` at
`DEoAdvXnMNYxuboN1MXUJRUynbixzF42DCBPUV6wvafw`: schema 1, `tree_height` 8, **`start_epoch` 0**,
`last_epoch` 1, and one checkpoint at epoch 1 carrying the root `0xabab…ab`.

`start_epoch` 0 is not a value a conforming `initialize` under v0.1.18 could write, and
`last_epoch` 1 with today at day 20722 is the state §1.4's amendment exists to prevent: the first
publishable epoch is 2 January 1970 and the current day is some twenty thousand transactions away,
so INV-ANCH-01's daily cadence is unreachable. The deployment predates the amendment. The verifier
reads it rather than refusing it, for the reason D-15 gives, and the devnet test prints the state
instead of asserting conformance.

## Dependencies

Two on the verifier's path, which is the whole trust surface a counterparty inherits.

| Package | Version | Licence | Where |
|---|---|---|---|
| `@noble/hashes` | 2.4.0 | MIT | **runtime**: Keccak-256 for every digest; SHA-256 for §2.4 only |
| `@noble/curves` | 2.4.0 | MIT | **runtime**: Ed25519 verification, and point decoding for the off-curve test |
| `typescript` | 7.0.2 | Apache-2.0 | dev only: `tsc` for typechecking and for the browser build |
| `@types/node` | 24.10.1 | MIT | dev only: type declarations for the Node APIs the tests use |

`@noble/curves` depends on `@noble/hashes` and on nothing else, so the runtime tree is those two
packages and no more. `@types/node` pulls `undici-types` 7.16.0 (MIT), which is type declarations
and emits nothing. `typescript` 7.0.2 pulls its own platform binaries (Apache-2.0). None of the
four dev packages is reachable from `src/`: the build under `tsconfig.build.json` proves it for the
types, and `dist/` contains no import outside `@noble/*`.

No test oracle library is used. The vector suite's oracle is the committed vectors themselves, and
KAT-01's rate-boundary cross-check uses the platform's own SHA-3 (see SPEC-DEFECTS.md D-10).

## Toolchain

| Tool | Version, as the tool printed it |
|---|---|
| `node --version` | `v24.21.0` |
| `npm --version` | `11.19.0` |
| `npx tsc --version` | `Version 7.0.2` |

## §4.4a

Measured by `test/perf.test.ts`, which prints the numbers and the machine on every run. The row
that names this artifact is the third one.

| Measure | Threshold | Measured (median) |
|---|---|---|
| TS verifier, 1,000-record chain, hash recomputation only | < 50 ms | **10.3 ms** (10.32, 10.79 on two runs) |
| the same chain including per-record Ed25519 verification | none in v0.1 | 1,035 ms (1,035.40, 1,037.48) |
| epoch root build, 256 leaves | < 10 ms | 2.7 ms (2.70, 2.75) |
| inclusion proof verification | < 1 ms | 0.030 ms (0.0297, 0.0304) |

Each figure is the median of several timed repetitions inside one run; the two runs quoted are
consecutive and show the spread.

Machine: Apple M2 (Mac14,2), macOS Darwin 25.6.0 arm64, 16 GB, Node v24.21.0, single thread.

The split §4.4a draws holds here and is worth restating: signature verification is about a
hundred times the cost of the hash chain, at roughly 1.03 ms per record, so a threshold on the
signature path should be set against real data rather than guessed.

## Evidence that the tests fail for the reasons they name

`node tools/mutation-check.mjs` breaks one thing at a time, runs the suite, restores the file, and
reports. It carries 37 mutations, one per property the suite claims to hold, from the hash family
and the leaf field order to the slot assignment order, the condition ordering of §1.3, the
JSON-versus-Borsh ordering, §2.4's account offsets including `start_epoch`, INV-ANCH-02's three
placements, §1.4's flooring clock, and the handler table that makes "every vector" enforced rather
than claimed. All 37 are caught. A mutation that leaves the suite green is printed
as a failure of the script, which is how the one hole found during development was closed.
