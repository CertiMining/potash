# CertiMining Anchored Log

An append-only log of mineral estimate records, anchored to two independent chains. It lets a
counterparty establish that a record existed, unaltered, and was included in a stated epoch, at a
time bounded by a Solana slot and a Bitcoin block. Its **position** in an asset's chain is a separate
question, and one disclosure package does not answer it — see below.

Specification: [`docs/TCU-02_CertiMining_Anchored_Log_v0.1.md`](docs/TCU-02_CertiMining_Anchored_Log_v0.1.md).
Every decision behind the build: [`docs/DECISIONS.md`](docs/DECISIONS.md).

---

## Status: not audited

No external audit has completed, and no figure below was measured by anyone outside this project.
What has run is independent review, in rounds, against posted heads:

| Reviewed | Rounds |
|---|---|
| §4.4's privacy instrument | **6** |
| A publication cycle and its live-value record | 4 |
| The TypeScript verifier | 3 |
| The fuzz and property harness | 3 |
| The benchmarks | 3 |
| The Anchor program and the anchor client | 2 |
| Anchor B | 2 |
| The demo | 2 |

Every round found defects in the previous round's fixes. That is why they are counted rather than
called reviewed, and why the longest count is against the privacy tests, which are the release
blockers. There is no OpenTimestamps worker to review: the daily cycle is run by hand
(D-117, [#49](https://github.com/CertiMining/potash/issues/49)).

**What is measured.** Numbers this repository produces and checks, not estimates. Each row names the
implementation that produced it, because the two differ by an order of magnitude. Rust figures are
release builds via `scripts/ci.sh thresholds` and `scripts/ci.sh bench` on the reference machine
§4.4a names — Apple M2, 8 cores, macOS 26.6.2. The chain-walk range spans two machines both matching
that description, which is why D-137 removed its bound.

| | Threshold | Measured | By |
|---|---|---|---|
| `publish_checkpoint` compute | ≤ 15,000 CU (**exceeded; see below**) | 9,071 to 25,575 CU, by epoch | LiteSVM; the chain shows 8,810, which is the program before v0.2.4 ([why](docs/performance.md)) |
| `attach_anchor_receipt` compute | ≤ 12,000 CU | 5,687 CU | LiteSVM, and the same on chain |
| Chain walk, 10,000 records, hash recomputation only | none (D-137) | 7–19.5 ms, machine-dependent | Rust |
| Epoch root build, 256 leaves | none (D-137) | 0.20–0.38 ms | Rust |
| Epoch root build, 256 leaves | none (D-137) | 2.66 ms | TypeScript |
| Inclusion proof verification | none (D-137) | 0.0023–0.0043 ms | Rust |
| Inclusion proof verification | none (D-137) | 0.0288 ms | TypeScript |
| TypeScript verifier, 1,000-record chain, hashing only | < 50 ms | 10.23 ms | TypeScript |
| Full verification including per-record Ed25519 | none in v0.1 | 395–400 ms on 12 Oct 2026, 460–486 ms on 7 Oct, 399 ms when the row was written ([why](docs/performance.md)) | Rust |
| Full verification including per-record Ed25519 | none in v0.1 | 1,004 ms | TypeScript |
| Landing-delay correlation with record count | \|r\| < 0.2 | −0.0440 | devnet, 200 epochs |
| Landing-delay correlation with build time | \|r\| < 0.2 | +0.0693 | devnet, 200 epochs |

**`publish_checkpoint` has no single compute figure, and §1.8's bound is exceeded.** Its cost is
`8,810 + 1,500 × (255 − bump)` CU, where `bump` is the canonical bump of the epoch's checkpoint PDA:
Anchor searches downward from 255 and each rejected candidate costs a `create_program_address`
syscall, and the epoch is one of the seeds. So the figure is a property of the day, not of the
instruction. CI records five rows with their epochs and bumps and asserts all of them.

Five rejected candidates cross 15,000, which is about one epoch in 32 — and **four of the 212 epochs
the superseded deployment actually published were over the bound**, by 1,500 to 6,000 CU. They
succeeded because nothing here requests a compute budget, so the runtime's own 200,000 CU limit
absorbed them. Whether 15,000 is the right number is open
([#193](https://github.com/CertiMining/potash/issues/193)); the measurement is not.

Two independent implementations — Rust and TypeScript, the second written from the specification
alone by someone who never read the first — agree on all 32 committed vectors, including the ones
that fix which error code wins when more than one condition fails. The engine's digests are identical
inside the Solana runtime and outside it, across every committed preimage.

**What is not measured, and should not be read as if it were.**

- The landing-delay correlation above ran **once**, over 200 consecutive epochs at one epoch per
  minute on one endpoint. A day-long cadence would sample network conditions this run did not. That
  run is filed for after the submission deadline.
- Anchor B has completed **fourteen** cycles on the deployed log, epochs 20723 to 20736, all `dual`
  with their receipts committed under `anchors/epochs/`. Fourteen instances, not a measured latency:
  a newly published epoch reads `single` for the hours before a Bitcoin block confirms it (D-112),
  so that column is a snapshot. The cadence INV-ANCH-01 asks for has also already been missed five
  times — nothing published on day 20726, 20729, 20732, 20734 or 20737 — and each time the next day
  paid both the owed epoch and its own, which is what a cadence run by hand does
  ([#49](https://github.com/CertiMining/potash/issues/49)). **The log has been paused since epoch
  20738 on 12 October 2026**, recorded in [docs/anchoring.md](docs/anchoring.md): the cycle did not
  run, nothing watches for a trailing gap, and resuming would mean publishing every intervening epoch
  because the range is contiguous by construction. The distance from `last_epoch` to today
  is not written here, because a written distance ages into a false claim; `sequence_lag` reports it
  against a clock. `docs/anchoring.md` carries the roots, slots, blocks and receipt digests.
- The fuzz and property harness exists (§4.5's five targets and four properties,
  [`docs/fuzzing.md`](docs/fuzzing.md)) and **has not accumulated a history**. The nightly job is
  new, so behind it are single runs at the stated counts, not a record of quiet nights. F-05 runs
  25,000 iterations rather than a million because one unit may build a 65,536-leaf tree — four
  orders of magnitude less input than F-01, which is a cost, not a judgement that less suffices.
- The count-hiding property is computational, not information-theoretic, and rests on the batcher's
  key custody. Both are stated in Appendix A of the specification as RES-09 and RES-03.
- **The announced log does not demonstrate count-hiding, and never did (D-138).** Its record set is
  a public constant: the harness builds every epoch from three records whose submission ids and
  leaves sit in `crates/certimining-client/tests/publish_epoch.rs`. A property hiding how many
  records an epoch held cannot be shown by a log whose record count is in its own source. Epochs
  20723 to 20731 rebuild from this repository alone; from 20732 they do not, the master key having
  moved outside it — which changes nothing here, because the count is still in the harness. What
  exercises count-hiding is §4.4's privacy tests and the demo, not the deployment.

## What this asserts

That a signed record existed, unaltered, and was included in a stated epoch, at a time bounded by a
Solana slot and a Bitcoin block.

**Position in a chain is established only when the holder also holds the chain segment back to
genesis, or back to a head they already trust.** One disclosure package carries the issuer's signed
statement of its position and no evidence for it: §1.3's leaf preimage covers neither `prev_head` nor
`head`, so no signature binds them, and an inclusion proof binds only the leaf (D-129, SD-19). The
TypeScript verifier reports this rather than passing over it — `chainPosition.established` is `false`
with the reason, and the check line reads `unestablished`.

## What this does not assert

NI 43-101 compliance, the accuracy of the estimate, the honesty of the assayer, the existence of the
mineralization, or that the log is complete.

This architecture carries tamper-evidence, ordering, and timestamp assurance. It does **not** carry a
fraud-prevention or double-pledge claim, and nothing in this repository may imply one. That is a
merge gate in the specification's §4.6, enforced by
[`scripts/claim-check.sh`](scripts/claim-check.sh) in CI, not an editorial preference.

Category flags are observations. A flag says what the engine noticed; it never says a filing is
improper, and the engine never rejects a record because of one.

## What this architecturally cannot carry

**Asset equivocation is unsolved, and this design does not address it.** An issuer can maintain two
divergent chains for the same physical asset, submit both, and present the first to one lender and
the second to another. Both inclusion proofs verify against the same root. Neither lender detects it.

The distinction matters, because it is narrower than log equivocation and the two are routinely
conflated. *Log* equivocation — showing different verifiers different logs — **is** eliminated here:
the root is on a public chain, so every verifier resolves the same root for an epoch. What remains is
that the binding from physical asset to chain is unverifiable without a shared, jointly observable
asset identifier, and providing one is exactly what the confidentiality requirement forbids.

Appendix A of the specification lists ten further residuals, each naming a limit rather than a
feature. A reader who wants the limits has them there in full.

## Shape

Records and verification live off the chain **by design**, not as a workaround. The mining sector
will not publish when or where an estimate changed, which is why an earlier version of this design
was withdrawn: it put categories, effective dates and qualified-person keys on-chain, and so
published the timing of material change at an identified asset.

What the chain carries is a 32-byte root per epoch and nothing else. Counterparties receive records
and inclusion proofs out of band, under whatever agreement already governs the data room, and verify
offline against a root they fetch themselves.

**Two anchors, and the second is not an extra.** Solana is anchor A: a checkpoint every epoch,
published at a fixed time whether the epoch held 255 records or none, so the cadence discloses
nothing about filing activity. OpenTimestamps and Bitcoin are anchor B: the epoch's root is
timestamped independently, and the receipt's digest is attached to the checkpoint once the receipt
carries a Bitcoin attestation.

**That attestation is checked against Bitcoin, and this paragraph used to say it was not.** All
seventeen receipts this repository holds — the three repository-head stamps and the fourteen epoch
rows — are confirmed: the digest each receipt's operations reach *is* the merkle root of the block it
names. The headers are committed bytes and each must meet the target its own `bits` encode, which is
the target in force in its retarget period, so an altered one fails arithmetic rather than a
comparison with an authority. It runs in CI, offline
([#48](https://github.com/CertiMining/potash/issues/48),
`crates/certimining-client/src/bitcoin.rs`, `Confirmed`).

What a reader still takes on this repository's word is the **checkpoint** one block below each range —
its height, hash and difficulty, which is one query to any Bitcoin node. Everything after it is
believed for its work. A `BitcoinClaim` is what a receipt says and a `Confirmed` is what a block
shows, and the two are different types so a caller cannot treat one as the other.

The integrity claim rests on both anchors. Until anchor B attaches, a client reports the
epoch as `single` rather than `dual` — an epoch waiting hours for a Bitcoin block is the latency this
design budgets for, and reporting it as anchored twice would be a failure the specification treats as
a merge blocker.

## The deployment, and a key that can replace it

The program runs on Solana **devnet**. Addresses, the authority that holds it, and what that costs a
reader are in [`docs/anchoring.md`](docs/anchoring.md).

**The upgrade authority is live.** It has not been burned. Whoever holds that key can replace the
program, and with it every invariant this repository states, so those invariants are conditional on
this deployment rather than absolute. The specification allows two answers to that — remove the
authority, or say plainly that it is there — and this deployment says it is there. Burning it is a
decision for a deployment claiming permanence, and it is recorded for after the deadline rather than
taken by default.

## Layout

| | |
|---|---|
| `crates/certimining-core` | digests, encodings, the record state machine. `no_std`, no Solana dependency |
| `crates/certimining-log` | the epoch tree, inclusion proofs, the batcher, inclusion promises |
| `crates/certimining-client` | fetching a root, the publish path, the anchor-B client, and the three binaries around them: `batcher-handoff` builds an epoch and signs the handoff, `anchor-b-worker` publishes a root it was given and refuses to start without one it can verify, and `confirm-anchor-b` checks a receipt against Bitcoin headers. D-139 divides the cycle so `k_master` never reaches the process that runs unattended. Neither runs on a timer yet: the log is paused (D-117, D-139) |
| `programs/certimining-checkpoint` | the Anchor program: three instructions, and no others ever |
| `programs/core-harness` | proves the engine's digests match inside the Solana runtime |
| `vectors/` | the committed test vectors both implementations check themselves against |
| `benches/` | §4.4a's performance figures: Criterion distributions, the reported wall-clock measures, and the CI regression band, which **fails** on drift past 15% — derived from 30 CI runs, in which no measure exceeded its baseline by more than 2.4% ([`docs/performance.md`](docs/performance.md)) |
| `fuzz/` | §4.5's five fuzz targets. Its own workspace, outside the main one, and nothing in it ships ([`docs/fuzzing.md`](docs/fuzzing.md)) |
| `ts/` | the independent TypeScript verifier a counterparty runs, with its own gate ([`ts/README.md`](ts/README.md)) |
| `demo/` | three browser scenes and a read-only status page that reads devnet ([`demo/README.md`](demo/README.md)) |
| `docs/` | the specification, every decision, and per-unit notes |
| `scripts/ci.sh` | the whole pipeline as one script, so a local run is what CI runs |

## Running it

```bash
scripts/ci.sh all
```

That is the push pipeline verbatim. The fuzz targets are not in it: they take tens of minutes and run
nightly instead, as `scripts/ci.sh fuzz` and `.github/workflows/fuzz.yml`. What each target establishes,
and what three of them failed to establish on the first attempt, is in
[`docs/fuzzing.md`](docs/fuzzing.md).

To see it rather than test it:

```bash
scripts/demo.sh
```

That serves `http://localhost:8730` — three scenes that build epoch trees in the browser, and a
status page at `/status.html` that reads Solana devnet through the TypeScript verifier this
repository ships. The scenes are offline and synthetic on purpose; the status page is read-only,
holds no key and is not an operator console. [`demo/README.md`](demo/README.md) says what each scene
establishes and which failure the status page is built around.

Toolchain versions are pinned and the script refuses to proceed on the wrong ones. The Solana
programs build only through `scripts/build-sbf.sh`, which uses a project-private Rust installation so
nothing on the machine's global toolchain is touched. `CONTRIBUTING.md` has the detail, including a
dependency that no automated gate covers and why.

## Licence

Dual licensed under either [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your option. Every
source file carries `SPDX-License-Identifier: MIT OR Apache-2.0`.
