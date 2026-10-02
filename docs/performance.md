# Performance: what §4.4a asserts, where, and on what machine

§4.4a has seven rows. This file says which mechanism covers each, what the figures are, and the one
threshold that was changed because the code did not meet it.

| §4.4a row | Threshold | Asserted by | Measured |
|---|---|---|---|
| `publish_checkpoint` compute | ≤ 15,000 CU | `programs/certimining-checkpoint/tests/compute.rs`, in `kat01-onchain` | in CI, every push |
| `attach_anchor_receipt` compute | ≤ 12,000 CU | the same test | in CI, every push |
| Chain walk, 10,000 records, hash recomputation only | < 10 ms (D-136) | `benches/thresholds.rs` on the reference machine; `benches/band.rs` in CI | 7.1 ms |
| Epoch root, 256 leaves | < 10 ms | the same two | 0.20 ms |
| Inclusion proof verification | < 1 ms | the same two | 0.0023 ms |
| TS verifier, 1,000-record chain, hash recomputation only | < 50 ms | `ts/test/perf.test.ts`, in the `ts` group (E-11) | in CI, every push |
| Full verification including per-record Ed25519 | **none in v0.1** | nothing; printed | 399 ms |

## Two kinds of number, and why they are gated differently (D-132)

**Compute units are deterministic.** The same instruction against the same program costs the same CU on
any machine, so §1.8's limits are asserted absolutely in CI and have been since E-08.

**Wall-clock is not.** A shared runner is slower and noisier than a laptop by an amount nobody controls,
so asserting §4.4a's absolute figures there would either flake or be loose enough to assert nothing.
D-132 splits it:

- **On the reference machine**, §4.4a's absolutes are asserted — `benches/thresholds.rs`, `#[ignore]`d so
  CI does not run it, and run before submission the way V-Z-04's full 10,000-epoch run is.
- **In CI**, the runner is held to its own previous figures instead: `benches/band.rs` reads
  `benches/BASELINE.toml` and fails if a measure drifts more than `band_percent` above its baseline. It
  is a regression detector, not a performance claim.

An absent baseline entry **fails** and prints what it measured. A baseline nobody measured would be a
gate that cannot fail, and this repository has filed that defect more than once.

## The reference machine

**Apple M2, 8 cores, macOS 26.6.2.** §4.4a names it, because a figure without a machine is not a figure.

```sh
scripts/ci.sh thresholds   # §4.4a's absolutes, asserted
scripts/ci.sh bench        # the Criterion distributions behind them
scripts/ci.sh bench-band   # what CI runs: this machine against the committed baseline
```

## The threshold that changed (D-136)

§4.4a's chain-walk row read **< 5 ms**, and 5 ms was never measured — it was written when §4.4a was
restored, before anything in the repository timed the walk. E-13 timed it: **7.1 ms**, over by 40%. The
row now carries the measurement and a gate above it, because a threshold the implementation misses is a
claim the specification cannot carry.

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

The assertion is on the **median** of seven. The best of N reports only the moments the operating system
left alone and the worst reports the moments it did not; the median is the figure that moves when the
code moves. All three are printed, because a threshold reported without its spread is the single-sample
problem D-132 rejected.

## What these figures do not establish

They are one machine's, on one day, at one tree height. They say nothing about a device under memory
pressure, a different Keccak backend, or a log at `H = 16`, where an epoch is 65,536 leaves rather than
256. §4.4a's thresholds bound the deployed shape; outside it there is no claim here.
