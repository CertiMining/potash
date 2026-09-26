# CertiMining Anchored Log

An append-only log of mineral estimate records, anchored to two independent chains. It lets a
counterparty establish that a record existed, unaltered, in a stated position of a stated asset's
chain, at a time bounded by a Solana slot and a Bitcoin block.

Specification: [`docs/TCU-02_CertiMining_Anchored_Log_v0.1.md`](docs/TCU-02_CertiMining_Anchored_Log_v0.1.md).
Every decision behind the build: [`docs/DECISIONS.md`](docs/DECISIONS.md).

---

## Status: not audited

No external review has completed. One independent review round has been answered on the Anchor
program and the anchor client; a second has not run, and the OpenTimestamps worker and the TypeScript
verifier have had none. Treat every figure below as measured by the people who wrote the code.

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
- Anchor B has not completed a cycle on the deployed log. A root is submitted to the OpenTimestamps
  calendars and the receipt is not yet carried by a Bitcoin block, so the deployed epoch reads
  `single`. That wait is the design, not a fault: see below.
- There is no fuzz or property harness yet.
- The count-hiding property is computational, not information-theoretic, and rests on the batcher's
  key custody. Both are stated in Appendix A of the specification as RES-09 and RES-03.

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
timestamped independently, and the receipt's digest is attached to the checkpoint once a Bitcoin
block carries it. The integrity claim rests on both. Until anchor B attaches, a client reports the
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
| `crates/certimining-client` | fetching a root, the publish path, anchor B's worker |
| `programs/certimining-checkpoint` | the Anchor program: three instructions, and no others ever |
| `programs/core-harness` | proves the engine's digests match inside the Solana runtime |
| `vectors/` | the committed test vectors both implementations check themselves against |
| `docs/` | the specification, every decision, and per-unit notes |
| `scripts/ci.sh` | the whole pipeline as one script, so a local run is what CI runs |

## Running it

```bash
scripts/ci.sh all
```

Toolchain versions are pinned and the script refuses to proceed on the wrong ones. The Solana
programs build only through `scripts/build-sbf.sh`, which uses a project-private Rust installation so
nothing on the machine's global toolchain is touched. `CONTRIBUTING.md` has the detail, including a
dependency that no automated gate covers and why.

## Licence

Dual licensed under either [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT), at your option. Every
source file carries `SPDX-License-Identifier: MIT OR Apache-2.0`.
