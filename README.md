# CertiMining Anchored Log

An append-only log of mineral estimate records, anchored to two independent chains. It lets a
counterparty establish that a record existed, unaltered, in a stated position of a stated asset's
chain, at a time bounded by a Solana slot and a Bitcoin block.

Specification: [`docs/TCU-02_CertiMining_Anchored_Log_v0.1.md`](docs/TCU-02_CertiMining_Anchored_Log_v0.1.md).
Every decision behind the build: [`docs/DECISIONS.md`](docs/DECISIONS.md).

---

## Status: not audited

No external audit has completed, and no figure below was measured by anyone outside this project.
What has run is independent review, in rounds, against posted heads: two on the Anchor program and the
anchor client, two on anchor B, three on the TypeScript verifier, and two on the demo. Each round
found defects in the previous round's fixes, which is the reason for counting them rather than
declaring the work reviewed. There is no OpenTimestamps worker to review: the daily cycle is run by
hand (D-117, [#49](https://github.com/CertiMining/potash/issues/49)).

**What is measured.** These are numbers this repository produces and checks, not estimates.

| | Threshold | Measured |
|---|---|---|
| `publish_checkpoint` compute | ≤ 15,000 CU | 10,310 CU |
| `attach_anchor_receipt` compute | ≤ 12,000 CU | 5,687 CU |
| TypeScript verifier, 1,000-record chain, hashing only | < 50 ms | 10.3 ms |
| Epoch root build, 256 leaves | < 10 ms | 2.7 ms |
| Inclusion proof verification | < 1 ms | 0.030 ms |
| Landing-delay correlation with record count | \|r\| < 0.2 | −0.0440 |
| Landing-delay correlation with build time | \|r\| < 0.2 | +0.0693 |

Two independent implementations — Rust and TypeScript, the second written from the specification
alone by someone who never read the first — agree on all 32 committed vectors, including the ones
that fix which error code wins when more than one condition fails. The engine's digests are identical
inside the Solana runtime and outside it, across every committed preimage.

**What is not measured, and should not be read as if it were.**

- The landing-delay correlation above ran **once**, over 200 consecutive epochs at one epoch per
  minute on one endpoint. A day-long cadence would sample network conditions this run did not. That
  run is filed for after the submission deadline.
- Anchor B has completed **five** cycles on the deployed log, epochs 20723 to 20727. All five read
  `dual` and all five receipts are committed under `anchors/epochs/`. Five cycles are five instances,
  not a measured latency. A sixth, epoch 20728, is published and stamped but **not** complete: its
  receipt carries calendar attestations only, so the epoch reads `single` until a Bitcoin block confirms
  it and the receipt is attached.
  The cadence INV-ANCH-01 asks for has also already been missed twice — nothing
  published on day 20726 or on day 20729, and each time the log caught up the next day — which is what
  a cadence run by hand does, there being no worker
  ([#49](https://github.com/CertiMining/potash/issues/49)).
  `docs/anchoring.md` carries the roots, the slots, the blocks and the receipt digests.
- The fuzz and property harness exists (§4.5's five targets and four properties,
  [`docs/fuzzing.md`](docs/fuzzing.md)) and **has not accumulated a history**. The nightly job is new,
  so what is behind it is single runs at the stated counts, not a record of nights that found nothing.
  F-05 runs 25,000 iterations rather than a million because one unit may build a 65,536-leaf tree; it
  explores four orders of magnitude less input than F-01, and that is a cost, not a judgement that less
  suffices.
- The count-hiding property is computational, not information-theoretic, and rests on the batcher's
  key custody. Both are stated in Appendix A of the specification as RES-09 and RES-03.
- **The announced log does not demonstrate count-hiding, and never did (D-138).** Its record set is a
  public constant: the publication harness builds every epoch from three records whose submission ids
  and leaves are written in `crates/certimining-client/tests/publish_epoch.rs`. A property that hides
  how many records an epoch held cannot be shown by a log whose record count is in its own source. All
  nine published roots, epochs 20723 to 20731, can be rebuilt from this repository alone — 20731
  because the cycle for that day was run from a checkout that predated the key's move, which is
  recorded with the cycle. What
  exercises count-hiding is §4.4's privacy tests and the demo, not the deployment.

## What this asserts

That a record existed, unaltered, in a stated position of a stated asset's chain, at a time bounded
by a Solana slot and a Bitcoin block.

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
carries a Bitcoin attestation. **That attestation is the receipt's claim, checked for presence and not
against Bitcoin**: verifying it means recomputing the path to a block's merkle root, which needs a
source of Bitcoin headers this client does not have ([#48](https://github.com/CertiMining/potash/issues/48),
`crates/certimining-client/src/ots.rs`, `BitcoinClaim`). The integrity claim rests on both. Until anchor B attaches, a client reports the
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
| `crates/certimining-client` | fetching a root, the publish path, and the anchor-B client a worker would use. There is no worker: the daily cycle is run by hand (D-117, [#49](https://github.com/CertiMining/potash/issues/49)) |
| `programs/certimining-checkpoint` | the Anchor program: three instructions, and no others ever |
| `programs/core-harness` | proves the engine's digests match inside the Solana runtime |
| `vectors/` | the committed test vectors both implementations check themselves against |
| `fuzz/` | §4.5's five fuzz targets. Its own workspace, outside the main one, and nothing in it ships ([`docs/fuzzing.md`](docs/fuzzing.md)) |
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

Toolchain versions are pinned and the script refuses to proceed on the wrong ones. The Solana
programs build only through `scripts/build-sbf.sh`, which uses a project-private Rust installation so
nothing on the machine's global toolchain is touched. `CONTRIBUTING.md` has the detail, including a
dependency that no automated gate covers and why.

## Licence

Dual licensed under either [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your option. Every
source file carries `SPDX-License-Identifier: MIT OR Apache-2.0`.
