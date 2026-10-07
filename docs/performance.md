# Performance: §4.4a's figures, what is asserted, what is reported, and on what machine

§4.4a has seven rows. This file says which mechanism covers each, what the figures are, and how three of
the seven lost their thresholds — one because the code did not meet it, then all three because the figure
turned out not to be reproducible.

| §4.4a row | Threshold | Asserted by | Measured |
|---|---|---|---|
| `publish_checkpoint` compute | ≤ 15,000 CU | `programs/certimining-checkpoint/tests/compute.rs`, in `kat01-onchain` | **8,810 CU**, recorded exactly; the same on chain |
| `attach_anchor_receipt` compute | ≤ 12,000 CU | the same test | **5,687 CU**, recorded exactly; the same on chain |
| Chain walk, 10,000 records, hash recomputation only | **none** (D-137) | reported by `benches/thresholds.rs`; `benches/band.rs` catches regression on the CI runner | 7 ms idle, 13.8 ms loaded, 17.6–19.5 ms on another conforming M2 |
| Epoch root, 256 leaves | **none** (D-137) | the same two | 0.20–0.38 ms |
| Inclusion proof verification | **none** (D-137) | the same two | 0.0023–0.0043 ms |
| TS verifier, 1,000-record chain, hash recomputation only | < 50 ms | `ts/test/perf.test.ts`, in the `ts` group (E-11) | in CI, every push |
| Full verification including per-record Ed25519 | **none in v0.1** | nothing asserts it; `benches/thresholds.rs` prints it | 465–486 ms on the development machine, 7 Oct 2026; 399 ms when the row was written, which does not reproduce — see below |

## The Ed25519 row moved and this does not explain why

The row was written at `bc85524` reading **399 ms**. Two runs on 7 Oct 2026, on an Apple M2 with 16 GiB
under macOS 25.6.0, measured **460.3–474.0** and **464.7–486.0 ms**. The two runs agree with each other
and neither reproduces 399.

What was checked before recording the new figure, because a changed measurement usually means a changed
measurement rather than changed code: the record count is `RECORDS = 10_000` in both, `chain_of(true)`
built all ten thousand in both, and both walk the same chain through `walk::<DalekVerifier>`. So the two
numbers are over the same workload with the same verifier.

What changed in between is the harness around it. E-13's fourth round moved every fixture's construction
to before the first `measure`, because pinning the fixtures a function happens to build first protects
only those — a review had made the signed branch a hundredth of its size and the row still printed
"10,000 records". A consequence nobody was aiming at is that the signed chain is no longer built
immediately before it is walked, so it is not hot in cache the way it was at `bc85524`. That is a
plausible cause and it is **not** a demonstrated one: establishing it would mean reordering the harness
to see the number move, which would undo the fix that produced the honest figure.

So the new number is recorded, the old one is kept beside it, and the gap is stated rather than
reconciled. §4.4a asserts nothing here (D-137), so nothing gates on either.

## The wall-clock bounds are gone (D-137)

§4.4a carried three of them and no longer does. The chain-walk row began at `< 5 ms`, written before
anything here had timed the walk; D-136 amended it to `< 10 ms` after E-13 measured 7.1 ms. Then an
independent review ran the same assertion on **a different machine matching §4.4a's own description** —
Apple M2, 8 cores, macOS 26.6.2 — and measured medians of 17.92, 16.65 and 19.52 ms. While the section
was being amended, this machine, which had measured 7 ms idle, measured 13.77 ms with another suite
running beside it.

Four values from 7 to 19.5 ms, all on hardware matching the specification's words. **The description does
not determine the figure.** A bound stated against it is not a property of this system, so the owner
removed the three rows rather than raising a number a second time and having it track the slowest machine
anyone tried.

What asserts absolutely is now only what can: the compute figures, which are deterministic and were
confirmed against the announced deployment's own transactions. What catches a slowdown in the *code* is
the band, holding one runner to its own previous numbers. What the wall-clock measures give you is a
record, with the machine named — and a record has to be read, which is why `scripts/ci.sh thresholds` is
on CONTRIBUTING's run-before-submission list rather than in CI.

## Two kinds of number, and why they are gated differently (D-132)

**Compute units are deterministic.** The same instruction against the same program costs the same CU on
any machine, so §1.8's limits are asserted absolutely in CI and have been since E-08.

§4.4a also says the figures are "recorded per commit", and until E-13 they were not: they reached a
`println!` that disappears with the run, which let `publish_checkpoint` drift anywhere inside its 15,000
bound without anyone seeing. The measured figures are now committed in `compute.rs` and asserted
**exactly** — `initialize` 13,735 CU, `publish_checkpoint` 8,810, `attach_anchor_receipt` 5,687 — so a
change to the program changes a line in the diff. Three consecutive runs gave byte-identical figures,
which is what makes equality the right assertion rather than a tolerance. A runtime bump may legitimately
move them; `litesvm` is pinned at `=0.16.0` against Agave 4.2.2, and if that pin moves the figures are
re-measured and re-committed naming the version that moved them. Not widened into a bound — §1.8's bounds
are separate assertions in the same test, and a figure inside its bound can still drift a long way
unseen.

**Wall-clock is not.** A shared runner is slower and noisier than a laptop by an amount nobody controls,
so asserting fixed figures there would either flake or be loose enough to mean nothing. D-132 split it by
machine, and D-137 then removed the absolute half outright, which leaves:

- **On the reference machine**, the figures are measured and reported with the machine named —
  `benches/thresholds.rs`, `#[ignore]`d so CI does not run it, and run before submission the way V-Z-04's
  full 10,000-epoch run is. It asserts no performance threshold. Its correctness controls still fail: the
  chain walk is cross-checked against the state machine, the proof is verified, and the workload is
  pinned to the sizes its rows name.
- **In CI**, the runner is held to its own previous figures: `benches/band.rs` reads
  `benches/BASELINE.toml` and fails if a measure drifts more than `band_percent` above its baseline. Since
  D-137 this is the only wall-clock gate in the repository. It is a regression detector, not a
  performance claim.

An absent baseline entry **fails** and prints what it measured. A baseline nobody measured would be a
gate that cannot fail, and this repository has filed that defect more than once.

**Run anywhere but the runner, `bench-band` proves nothing.** The baseline is one machine's figures and
the reference machine is about 1.8× faster, so locally the measures come in below the baseline and the
comparison passes without meaning anything — it cannot fail on a machine faster than the one it is
calibrated to. It sits in `all` because `all` mirrors the push pipeline verbatim; the run that matters is
CI's. Nothing gates the reference machine: `scripts/ci.sh thresholds` records its figures (D-137).

The band itself is **50%, and that is a guess**. How much these measures vary between runs on a shared
runner has not been observed, so the number is not derived from anything; it is wide because a band that
flakes gets disabled and a disabled gate is worse than a loose one. It is set from observed spread once a
few runs exist. Until then a failure there means "look", not "something regressed by at least half".

## The reference machine

**Apple M2, 8 cores, macOS 26.6.2.** §4.4a names it, because a figure without a machine is not a figure.

```sh
scripts/ci.sh thresholds   # §4.4a's wall-clock figures, measured and reported
scripts/ci.sh bench        # the Criterion distributions behind them
scripts/ci.sh bench-band   # what CI runs: this machine against the committed baseline
```

## The threshold that changed, then went (D-136, then D-137)

§4.4a's chain-walk row read **< 5 ms**, and 5 ms was never measured — it was written when §4.4a was
restored, before anything in the repository timed the walk. E-13 timed it: **7.1 ms**, over by 40%. D-136
amended the row to the measurement with a gate above it, because a threshold the implementation misses is
a claim the specification cannot carry. That bound held two days: a second machine matching §4.4a's own
description measured 17.6–19.5 ms, and D-137 removed the row's threshold rather than raise it again. The
measurement discipline below is why the second figure was believed.

Two measurements had to be told apart to get there. §4.4a's row says "hash recomputation only", and its
own note says the figure "is achievable only for the hash chain". That is what a verifier does — for each
record `leafₙ`, then `hₙ = Keccak256(TAG_HEAD ‖ hₙ₋₁ ‖ leafₙ)`, two Keccak-256 invocations and no
condition judged. `AssetChain::apply` is the issuer's path and judges every §1.3 condition on top of the
same two hashes. The first version of the bench measured `apply` and reported 7.73 ms as the miss; both
are now measured and named, and `apply` costs 7.3 ms. **The 0.2 ms between them is the whole state
machine**, which is why no work on it would have reached 5 ms: the cost is hashing.

Rejected, and recorded in §4.4a rather than dropped: RustCrypto `sha3`'s `asm` feature measures
**5.16 ms**, a 27% gain that still missed the old 5 ms, and changing how the system's hash primitive is
built is not a performance decision to take under deadline. The per-call overhead of the preimage path is
unexamined and is H-19 ([#58](https://github.com/CertiMining/potash/issues/58)), with the constraint that
nothing there may weaken INV-ENC-01's staged tag writing — the guarantee that a caller cannot omit a tag
is worth more than the milliseconds.

## Warm-up is part of the instrument, not a detail

`thresholds.rs` and `band.rs` discard five runs before sampling. Without that they read **30% high** —
9.3 ms against Criterion's 7.1 ms — because seven cold samples measure cache and branch-predictor state
as much as they measure code. Criterion warms up for seconds before recording anything, and §4.4a's
figure describes steady state, so these have to as well. An instrument that disagrees with the figure it
is checking is not checking it.

The figure reported, and the one `band.rs` compares, is the **median** of seven. The best of N reports
only the moments the operating system left alone and the worst reports the moments it did not; the median
is the figure that moves when the code moves. All three are printed, because a figure reported without its
spread is the single-sample problem D-132 rejected — and the spread is what made D-137 visible.

## Two implementations, and a table that could not tell them apart

§4.4a's epoch-root and inclusion-proof rows are implementation-independent, and both implementations
meet them — by very different margins. Rust builds a 256-leaf epoch root in **0.195 ms** and the
TypeScript verifier in **2.66 ms**; Rust verifies an inclusion proof in **0.0023 ms** and TypeScript in
**0.0288 ms**. Both are real measurements of real code and neither is wrong.

The README's table published the TypeScript figures for those two rows without saying so, beside a row
that was explicitly labelled TypeScript, which made them read as the Rust ones. Nothing was stale and no
number was invented; the defect was that a reader could not tell which implementation a row described.
Every row now names it. Reviewing this is also what caught the one figure that *was* wrong — the
README's 10,310 CU for `publish_checkpoint`, against 8,810 measured in LiteSVM and 8,810 consumed on
chain, on a program whose source has not changed since that figure was written.

## What these figures do not establish

They are one machine's, on one day, at one tree height. They say nothing about a device under memory
pressure, a different Keccak backend, or a log at `H = 16`, where an epoch is 65,536 leaves rather than
256. §4.4a's remaining thresholds — the compute units, and the TypeScript chain walk — bound the deployed
shape; outside it there is no claim here, and for the three wall-clock rows there is no threshold at all.
