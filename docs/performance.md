# Performance: §4.4a's figures, what is asserted, what is reported, and on what machine

§4.4a has seven rows. This file says which mechanism covers each, what the figures are, and how three of
the seven lost their thresholds — one because the code did not meet it, then all three because the figure
turned out not to be reproducible.

| §4.4a row | Threshold | Asserted by | Measured |
|---|---|---|---|
| `publish_checkpoint` compute | ≤ 15,000 CU | `programs/certimining-checkpoint/tests/compute.rs`, in `kat01-onchain` | **8,810 CU**, recorded exactly; the same on chain |
| `attach_anchor_receipt` compute | ≤ 12,000 CU | the same test | **5,687 CU**, recorded exactly; the same on chain |
| Chain walk, 10,000 records, hash recomputation only | **none** (D-137) | reported by `benches/thresholds.rs`, and by `benches/band.rs` on the CI runner, which fails on neither | 7 ms idle, 13.8 ms loaded, 17.6–19.5 ms on another conforming M2 |
| Epoch root, 256 leaves | **none** (D-137) | the same two | 0.20–0.38 ms |
| Inclusion proof verification | **none** (D-137) | the same two | 0.0023–0.0043 ms |
| TS verifier, 1,000-record chain, hash recomputation only | < 50 ms | `ts/test/perf.test.ts`, in the `ts` group (E-11) | in CI, every push |
| Full verification including per-record Ed25519 | **none in v0.1** | nothing asserts it; `benches/thresholds.rs` prints it | 399 ms when the row was written, 460–486 ms on 7 Oct 2026, 395–400 ms on 12 Oct — three days, one machine, unexplained; see below |

## The Ed25519 row moved, and then moved back, and nothing here explains either

Three days of measurement on **Apple M2, 8 cores, macOS 26.6.2**, the machine §4.4a names:

| Day | Commit | Medians | Spread |
|---|---|---|---|
| 2 Oct 2026, when the row was written | `bc85524` | **399 ms** | one figure recorded |
| 7 Oct 2026 | `e21f46d` | two runs | 460.3–474.0 and 464.7–486.0 |
| 12 Oct 2026 | `2c821f3` | **399.9, 395.1 ms** | 398.2–409.0 and 393.7–402.6 |

The 12 October runs reproduce the original figure and do not reproduce 7 October's. Both were taken
with the submission checklist's own command, minutes apart, on an otherwise idle machine, with the
other three rows landing inside their recorded ranges in the same runs — 6.89 and 7.01 ms for the
chain walk, 0.188 and 0.191 ms for the epoch root, 0.0021 and 0.0028 ms for the proof.

**This falsifies the cause previously offered here.** That was E-13's fourth round moving every
fixture's construction ahead of the first `measure`, leaving the signed chain no longer hot in cache.
The harness has not changed since; had that been the cause the figure would have stayed high, and it
did not. The explanation is withdrawn rather than replaced, because a second guess would be worth no
more than the first.

What is on the record is five runs across three days on one named machine, with one harness and one
workload of 10,000 records through `walk::<DalekVerifier>`: three of them under 410 ms and two of them
above 460. Nothing here explains the difference, which is why the heading says so.
§4.4a asserts nothing on this row (D-137), so nothing gates on any of the four.

## The wall-clock bounds are gone (D-137)

§4.4a carried three and no longer does. Four values from **7 to 19.5 ms** were measured for the chain
walk, all on hardware matching §4.4a's own description — 7 ms idle and 13.8 ms loaded on this machine,
17.6–19.5 ms on another conforming M2. **The description does not determine the figure**, so a bound
stated against it is not a property of this system, and the rows lost their thresholds rather than
tracking the slowest machine anyone tried (D-136, then D-137).

What still asserts absolutely is what can: the compute figures, which are deterministic and confirmed
against the announced deployment's own transactions. The band compares one runner against its own
previous numbers and **records and reports the drift without failing on it**, so **no wall-clock
regression gate exists here** until calibration restores the assertion. Every wall-clock measure is
therefore a record with the machine named — and a record has to be read, which is why both
`scripts/ci.sh thresholds` and the band's own output are read rather than trusted to a green tick.

## Two kinds of number, and why they are gated differently (D-132)

**Compute units are deterministic.** The same instruction against the same program costs the same CU on
any machine, so §1.8's limits are asserted absolutely in CI and have been since E-08.

§4.4a requires the figures "recorded per commit". They are committed in `compute.rs` and asserted
**exactly** — `initialize` 13,735 CU, `publish_checkpoint` 8,810, `attach_anchor_receipt` 5,687 — so a
change to the program changes a line in the diff. Three consecutive runs gave byte-identical figures,
which is what makes equality right rather than a tolerance. A runtime bump may legitimately move them:
`litesvm` is pinned at `=0.16.0` against Agave 4.2.2, and if that pin moves the figures are re-measured
and re-committed naming the version that moved them. Not widened into a bound — §1.8's bounds are
separate assertions in the same test, and a figure inside its bound can still drift a long way unseen.

**Wall-clock is not.** A shared runner is slower and noisier than a laptop by an amount nobody controls,
so asserting fixed figures there would either flake or be loose enough to mean nothing. D-132 split it by
machine, and D-137 then removed the absolute half outright, which leaves:

- **On the reference machine**, the figures are measured and reported with the machine named —
  `benches/thresholds.rs`, `#[ignore]`d so CI does not run it, and run before submission the way V-Z-04's
  full 10,000-epoch run is. It asserts no performance threshold. Its correctness controls still fail: the
  chain walk is cross-checked against the state machine, the proof is verified, and the workload is
  pinned to the sizes its rows name.
- **In CI**, the runner is held to its own previous figures: `benches/band.rs` reads
  `benches/BASELINE.toml` and compares each measure against its baseline plus `band_percent`.
  **It reports drift and does not fail on it** (owner, 12 Oct 2026, H-37, H-31): the band is one
  sample's 50% guess, it failed a pull request containing no Rust by 0.9% of the limit, and a gate
  whose failures read as noise takes a real one down with them. Timings from at least twenty CI runs
  will set the band from measured spread, the derivation recorded, and it becomes a failing gate
  again. Its other assertions still fail — a missing baseline row, a non-finite band or baseline, a
  fixture that is not the size its label claims, a timed no-op, a verifier accepting a corrupted
  leaf. **So there is currently no wall-clock gate in the repository**, which D-137 had already left
  as the only one.

An absent baseline entry **fails** and prints what it measured. A baseline nobody measured would be a
gate that cannot fail, and this repository has filed that defect more than once.

**Run anywhere but the runner, `bench-band`'s comparison means nothing**, and that is true twice over
now. The baseline is one machine's figures and the reference machine is about 1.8× faster, so locally the
measures come in below the baseline and the comparison would not fire even if it asserted; and since it
reports rather than asserts, it does not fire anywhere. It sits in `all` because `all` mirrors the push
pipeline verbatim; the run that matters is CI's, where its figures are the series the calibration needs.
Nothing gates the reference machine either: `scripts/ci.sh thresholds` records its figures (D-137).

The band itself is **50%, and that is a guess**. How much these measures vary between runs on a shared
runner has not been observed, so the number is not derived from anything; it is wide because a band that
flakes gets disabled and a disabled gate is worse than a loose one. It is set from observed spread once a
few runs exist. Until then a measure above its limit is reported, not failed, and means "look".

## The reference machine

**Apple M2, 8 cores, macOS 26.6.2.** §4.4a names it, because a figure without a machine is not a figure.

```sh
scripts/ci.sh thresholds   # §4.4a's wall-clock figures, measured and reported
scripts/ci.sh bench        # the Criterion distributions behind them
scripts/ci.sh bench-band   # what CI runs: this machine against the committed baseline, reported
```

## What "hash recomputation only" measures

§4.4a's row says "hash recomputation only", and two measurements have to be told apart. A verifier
does, for each record, `leafₙ` then `hₙ = Keccak256(TAG_HEAD ‖ hₙ₋₁ ‖ leafₙ)` — two Keccak-256
invocations, no condition judged. `AssetChain::apply` is the issuer's path and judges every §1.3
condition on top of the same two hashes. Both are measured and named: the walk 7.1 ms, `apply`
7.3 ms. **The 0.2 ms between them is the whole state machine**, so the cost is hashing and no work on
the state machine would have reached the 5 ms the row once carried.

Rejected and recorded in §4.4a rather than dropped: RustCrypto `sha3`'s `asm` feature measures
**5.16 ms**, a 27% gain, and changing how the system's hash primitive is built is not a performance
decision to take under deadline. The preimage path's per-call overhead is unexamined — H-19
([#58](https://github.com/CertiMining/potash/issues/58)) — with the constraint that nothing there may
weaken INV-ENC-01's staged tag writing: a caller being unable to omit a tag is worth more than the
milliseconds.

## Warm-up is part of the instrument, not a detail

`thresholds.rs` and `band.rs` discard five runs before sampling. Without that they read **30% high** —
9.3 ms against Criterion's 7.1 ms — because seven cold samples measure cache and branch-predictor state
as much as they measure code. Criterion warms up for seconds before recording anything, and §4.4a's
figure describes steady state, so these have to as well. An instrument that disagrees with the figure it
is checking is not checking it.

The reported figure, and the one `band.rs` compares, is the **median** of seven: the best of N reports
only the moments the operating system left alone, the worst only the moments it did not. All three are
printed, because a figure without its spread is the single-sample problem D-132 rejected — and the
spread is what made D-137 visible.

## Two implementations, measured separately

§4.4a's epoch-root and inclusion-proof rows are implementation-independent, and both implementations
meet them by very different margins. Rust builds a 256-leaf epoch root in **0.195 ms**, the TypeScript
verifier in **2.66 ms**; Rust verifies an inclusion proof in **0.0023 ms**, TypeScript in
**0.0288 ms**. Both are real measurements of real code. Every row that reports a figure names the
implementation that produced it, because an order of magnitude separates them.

## What these figures do not establish

They are one machine's, on one day, at one tree height. They say nothing about a device under memory
pressure, a different Keccak backend, or a log at `H = 16`, where an epoch is 65,536 leaves rather than
256. §4.4a's remaining thresholds — the compute units, and the TypeScript chain walk — bound the deployed
shape; outside it there is no claim here, and for the three wall-clock rows there is no threshold at all.
