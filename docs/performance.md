# Performance: §4.4a's figures, what is asserted, what is reported, and on what machine

§4.4a has seven rows. This file says which mechanism covers each, what the figures are, and how three of
the seven lost their thresholds — one because the code did not meet it, then all three because the figure
turned out not to be reproducible.

| §4.4a row | Threshold | Asserted by | Measured |
|---|---|---|---|
| `publish_checkpoint` compute | ≤ 15,000 CU, **exceeded by two of five recorded rows** | `programs/certimining-checkpoint/tests/compute.rs`, in `kat01-onchain` | **9,071 to 25,575 CU by epoch**, five rows recorded exactly; the chain shows 8,810 — see below |
| `attach_anchor_receipt` compute | ≤ 12,000 CU | the same test | **5,687 CU**, recorded exactly; the same on chain |
| Chain walk, 10,000 records, hash recomputation only | **none** (D-137) | reported by `benches/thresholds.rs`; **not gated in CI** since D-144 — `benches/band.rs` still fails past 15% against a matched runner class, and runs where one is committed, which CI is not | 7 ms idle, 13.8 ms loaded, 17.6–19.5 ms on another conforming M2 |
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

What still asserts absolutely is what can: the compute figures, which are deterministic. The band
**fails on drift**, restored on 22 October 2026 from a series of 30 CI runs in which no measure
exceeded its baseline by more than 2.4% (H-47).

**CI gates no wall-clock measure at present, since D-144 on 1 November 2026.** The band held a runner
against figures committed for a runner class, and no CI runner ever matched one: five sampled jobs
calibrated at 0.9072, 1.0988, 1.1029, 1.3470 and 1.3503 ms, each 2.96% to 6.22% from its nearest class
against a 2.5% tolerance. Every CI run fell to the fallback described below, whose band is narrower
than the population it covers, so the verdict tracked which machine the run landed on. `bench-band` is
out of `all` and out of `ci.yml`; it still fails on drift and runs where a class is committed. **What
this costs, plainly: a real wall-clock regression merges.** What remains enforcing in CI is §1.8's
compute-unit limits, asserted absolutely, and the TypeScript bound. H-77 (#271) records the successor
the ruling declined to build now.

**Where it does run it has two sensitivities, and which applies depends on the machine (H-61, H-64, H-65, D-141).** A
calibration — a fixed count of version-pinned Ed25519 verifications, on nothing this repository's code
can move — selects what a run is compared against. Where it matches a committed runner class, the
measures are held to figures taken on that class at **15%**. Where it matches none, each measure is
divided by the calibration and compared against a fleet-wide ratio at **25%**, two-sided. The wider
band is not slack: normalising removes machine speed but not the relation between Ed25519 and
SHA-256, which is a property of each CPU, so the quotients still span 18 to 21% across the fleet. **A
regression under 25% escapes on that path**, which is why classes are the rule and the fallback the
exception. **D-144 found the fallback unsound rather than merely loose**, which is why CI no longer
invokes the comparison at all rather than the band being widened: the full observed range of `inclusion_proof_verify` across the machines
that ran this gate is 71% wide against a band of 67%, and the quotient is not monotonic in the
calibration, so dividing by it does not order the two machines it is meant to compare.

**A faster runner can fail now, and that is the half of this that added gating.** It could not before
H-61: one baseline was held for the whole fleet, so 8 of those 30 runs came in at 0.59 to 0.64 of it
where no code change could have pushed a measure over the limit, and the harness had to disclose that
a pass was not a pass about the code. A class is compared against its own baseline, so there is
nothing left to disclose.

`scripts/ci.sh thresholds` still reports §4.4a's figures with the machine named rather than asserting
them, and that record still has to be read.

## Two kinds of number, and why they are gated differently (D-132)

**Compute units are deterministic.** The same instruction against the same program costs the same CU on
any machine, so §1.8's limits are asserted absolutely in CI and have been since E-08.

§4.4a requires the figures "recorded per commit". They are committed in `compute.rs` and asserted
**exactly** — `initialize` 13,735 CU and `attach_anchor_receipt` 5,687, at every epoch — so a change to
the program changes a line in the diff. A runtime bump may legitimately move them: `litesvm` is pinned
at `=0.16.0` against Agave 4.2.2, and if that pin moves the figures are re-measured and re-committed
naming the version that moved them. Not widened into a bound — §1.8's bounds are separate assertions
in the same test, and a figure inside its bound can still drift a long way unseen.

**`publish_checkpoint` no longer depends on the epoch, as of v0.2.7 (H-52).** The bump travels in the
instruction data — 48 bytes to 49 — so Anchor makes one `create_program_address` call where it used to
search from 255 downward. The five rows CI records read:

| epoch | bump | before v0.2.7 | v0.2.7 | v0.2.9 |
|---|---|---|---|---|
| 40001 | 255 | 9,071 | 9,093 | 9,096 |
| 40002 | 253 | 12,071 | 9,093 | 9,096 |
| 40000 | 252 | 13,569 | 9,091 | 9,094 |
| 40010 | 250 | **16,573** | 9,095 | 9,098 |
| 40203 | 244 | **25,575** | 9,097 | 9,100 |

A spread of 16,504 CU became one of 6; the 22 CU every row gained at v0.2.7 is the extra
instruction-data octet.

**The v0.2.9 column is 3 CU dearer on every row**, and the uniformity is the point: refusing a wrong
length costs one probe of the deserialiser's reader, not work that scales with anything. The 6 CU
spread did not move, so it is still the epoch-dependent residual below rather than a second effect.
No row exceeds §1.8's bound now, and `compute.rs` asserts the bound on **every** row rather than only
on the epoch it pins — the assertion that required exactly two rows over the bound is what failed when
the search came out, which is how it earned its place.

**The table stays five rows.** Five rows agreeing at five different bumps is what establishes the
dependence is gone; one figure would assert it.

**What is not checked is canonicality**, because proving a bump canonical means showing every larger
candidate is on the curve — the search this removed. §1.8 makes it the publisher's and states the
consequence: a non-canonical publish writes the account where nothing looks, so every verifier reports
the epoch missing while `last_epoch` has advanced. Detectable at once, and only causable by the key
that signs the instruction.

**The account below is of the program before v0.2.7**, kept because it is how the dependence was found
and because the chain still runs that program.

**`publish_checkpoint` was a table and not a figure, and this document said 9,066 in four places**
(H-52, [#193](https://github.com/CertiMining/potash/issues/193)). Its cost is

    publish_checkpoint = 8,810 + 1,500 × (255 − bump)

where `bump` is the canonical bump of the epoch's checkpoint PDA: `#[account(init, seeds = …, bump)]`
makes Anchor search downward from 255, each rejected candidate costs one `create_program_address`
syscall, and **the epoch is one of the seeds**. So a single recorded number was a property of whichever
day the harness happened to pin. `main` went red proving it: one pull request recorded 9,066 measured
at one epoch and another moved the pinned clock to a different one, each green on its own branch.

CI now records five rows and asserts all of them, each with its epoch and that epoch's bump:

| epoch | bump | rejected candidates | `publish_checkpoint` |
|---|---|---|---|
| 40001 | 255 | 0 | 9,071 |
| 40002 | 253 | 2 | 12,071 |
| 40000 | 252 | 3 | 13,569 |
| 40010 | 250 | 5 | **16,573** |
| 40203 | 244 | 11 | **25,575** |

`initialize` and `attach_anchor_receipt` hold the same figure at every one of those epochs, which is
what establishes that the dependence belongs to `publish_checkpoint` alone: `initialize`'s only seed is
a constant, and `attach_anchor_receipt` reads the bump the account stores rather than searching.

**§1.8's bound is exceeded, and the test asserts that it is.** Five rejected candidates cross 15,000,
which is about one epoch in 32, and **four of the 212 epochs the program superseded on 25 September
actually published were over it** — by 1,500 to 6,000 CU on the program as it stood then. They
succeeded because nothing in this repository requests a compute budget, so the runtime's own 200,000 CU
limit absorbed them. A test that recorded those rows quietly would leave "Hard limits" reading as
though it held. Whether 15,000 is the right number, and whether the program should store its bump
rather than search for it, are the two questions #193 holds.

**What each check costs, measured by removing it (H-05, [#35](https://github.com/CertiMining/potash/issues/35)).**
That issue has asked since it was filed for "each addition separately rather than inferring from one
total", naming D-104's ownership test and D-109's clock read, and nothing had measured either. Both
were measured on 22 October 2026 by deleting the check, rebuilding the program with
`scripts/build-sbf.sh`, and reading the harness's figure at epoch 40001, bump 255:

| the program | `publish_checkpoint` | the check costs |
|---|---|---|
| as committed | 9,071 | — |
| without D-104's ownership-and-data test | 9,042 | **29 CU** |
| without H-11's calendar comparison | 8,814 | **257 CU** |

**29 CU, which corrects the premise this issue was filed on.** It said D-104 was one of "two changes"
that moved `publish_checkpoint` from 8,765 to a figure thought to be 13,310, and that "the extra cost
is in the checks around it". The checks cost 29 CU. What moved the figure was the bump search
(H-52): 13,310 is this instruction at bump 252, and D-104's contribution to any of it is a thirtieth
of one syscall.

**257 and not 256, and the difference is the epoch.** H-11's before-and-after gave 256 CU measured at
epoch 20721; this gives 257 at epoch 40001. Compute is deterministic, so both are right about their
own epoch, and the single unit is the residual H-52 records: the `1,500 × (255 − bump)` law holds to
within a few CU and the remainder moves with the day.

**Only `Clock::get()`'s result is reused, so only the comparison was removed.** The syscall was already
there for `published_slot` and `published_unix` before H-11, which is why the 257 is the division and
the `require!` and not the cost of reading the clock. The same care applies to D-104: its
`to_account_info()` binding is reused for `lamports()` further down, so the two `require!` statements
came out and the binding stayed. A first attempt removed the bindings too and failed to build, which
is how both facts were established.

**These three figures are not asserted in CI and that is a limitation, not an oversight.** Asserting
them would mean two extra SBF builds per run to measure programs this repository does not ship. So a
change to either check would move no gate, and the figures above would go stale silently — the one
thing this document is otherwise careful about. They are dated and the method is written down so the
measurement can be repeated rather than trusted.

**The chain shows 8,810 and that is also right** (H-11, v0.2.4). The deployed program predates the
calendar bound: an epoch ahead of the chain's own day index is now refused, which costs one comparison
on a `Clock::get()` the instruction already made — 256 CU — and epoch 20728, whose transaction was
read, has bump 255. The announced deployment has not been redeployed, so its transactions go on
showing 8,810. Nothing on chain is wrong; the chain is running an older program, which is the ordinary
state of a deployment that predates a change.

**Wall-clock is not.** A shared runner is slower and noisier than a laptop by an amount nobody controls,
so asserting fixed figures there would either flake or be loose enough to mean nothing. D-132 split it by
machine, and D-137 then removed the absolute half outright, which leaves:

- **On the reference machine**, the figures are measured and reported with the machine named —
  `benches/thresholds.rs`, `#[ignore]`d so CI does not run it, and run before submission the way V-Z-04's
  full 10,000-epoch run is. It asserts no performance threshold. Its correctness controls still fail: the
  chain walk is cross-checked against the state machine, the proof is verified, and the workload is
  pinned to the sizes its rows name.
- **In CI**, the runner is held to figures taken on its own kind of machine: `benches/band.rs` reads
  `benches/BASELINE.toml`, selects a runner class by calibration, and compares each measure against
  that class's baseline plus `band_percent`. **It fails on drift** (H-47, 22 Oct 2026). It reported
  without failing between 12 October and that date, because the band was then one sample's 50% guess
  which had flaked on a pull request containing no Rust, and a gate whose failures read as noise
  takes a real one down with it; the owner named the way back — twenty runs, the band derived from
  the measured spread, the derivation recorded — and thirty runs took it. Where no class matches, the
  comparison is against a fleet-wide ratio at 25% instead (D-141). Its other assertions fail as they
  always did: a missing baseline row, a non-finite band or baseline, a fixture that is not the size
  its label claims, a timed no-op, a verifier accepting a corrupted leaf.

An absent baseline entry **fails** and prints what it measured. A baseline nobody measured would be a
gate that cannot fail, and this repository has filed that defect more than once.

**Run anywhere but the runner, `bench-band`'s comparison still means nothing**, and it now says so by
failing rather than by passing quietly. The reference machine's calibration has landed both inside and
outside a committed class on different runs, which is itself the point: when it matches none it takes
the fallback, and its Ed25519-to-SHA-256 relation is lower than any the fleet has shown — about 7.13
where the fleet's lowest is 9.08 — which puts `inclusion_proof_verify` below the floor. The run then
reports that nothing can be concluded. That is the correct verdict for this machine; what changed is only which
sentence delivers it. `bench-band` sat in `all` because `all` mirrors the push pipeline verbatim, and
the run that was supposed to matter was CI's — **which is exactly what D-144 withdrew, because CI's run
never matched a class and so never made the comparison this document describes.** The group is out of
`all` and out of `ci.yml`, and nothing gates the reference machine either: `scripts/ci.sh thresholds`
records its figures (D-137).

**The bands are 15% and 25%, and both are derived — and since D-144 neither is run in CI.** 15% came from thirty CI runs whose widest
excursion above baseline was 2.4%, so it fails a regression of 15% while leaving room no run has used
(H-47). 25% came from the quotient spread across the fleet, 18 to 21%, measured over the readings
taken under the current instrument (D-141). Neither is the 50% that preceded them, which was recorded
as a guess at the time and flaked on a pull request containing no Rust.

## The reference machine

**Apple M2, 8 cores, macOS 26.6.2.** §4.4a names it, because a figure without a machine is not a figure.

```sh
scripts/ci.sh thresholds   # §4.4a's wall-clock figures, measured and reported
scripts/ci.sh bench        # the Criterion distributions behind them
scripts/ci.sh bench-band   # what CI runs. On this machine no class matches, so it takes the
                           # fallback and reports that nothing can be concluded — see above.
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

## What the preimage path costs: nothing measurable (H-19)

Every digest builds its preimage into a `PreimageBuf` through `staged` writes that enforce INV-ENC-01's
tag placement, then hashes the result. That is why no caller can omit a tag (D-36, D-64). Whether it
also cost anything per call was unmeasured, and §4.4a's chain walk is two of these per record.

Measured with Criterion on **Apple M2, 8 cores, macOS 26.6.2**, `benches/preimage.rs`:

| | through the preimage path | the same bytes, already contiguous |
|---|---|---|
| leaf, 161 bytes | 444.07 – **448.04** – 452.15 ns | 447.72 – **454.27** – 462.17 ns |
| head, 72 bytes | 228.71 – **230.34** – 232.38 ns | 227.12 – **230.01** – 233.44 ns |

**The intervals overlap at both sizes, so the construction is free at this resolution.** The path's
midpoint is lower than hashing a ready-made buffer at 161 bytes, which is noise and not a saving. What
the figures say is that staging, the bounds checks and the copy are not where the time goes: the hash
is. INV-ENC-01's guarantee costs nothing, which is the answer the question wanted.

**The slice interface does cost something, and the engine does not pay it.** `Hasher::hashv` takes
`&[&[u8]]`. The same 161 bytes as one slice measure 445.29 – **455.08** – 468.25 ns and as two slices
469.67 – **475.52** – 482.34 ns. Those intervals do not overlap: two slices is about 20 ns dearer,
roughly 4%. Every caller in the engine passes one slice, so this is a property of the interface rather
than a cost anything here bears.

**It reproduces §4.4a's chain walk, which is the useful check on all of it.** One record is one
161-byte leaf and one 72-byte head: 448 + 230 ≈ 678 ns. Ten thousand records is **6.8 ms** against the
7.1 ms §4.4a records for the walk, leaving about 0.3 ms for everything that is not hashing — which is
the same conclusion `apply` reached from the other direction, where judging every §1.3 condition on top
of the same two hashes cost 0.2 ms.

**The first attempt at this measurement was abandoned, and that is worth recording.** A hand-rolled
timing loop reported the full path as *faster* than hashing alone three times, by 162, 372 and 381 ns.
No figure was published from it. The difference being looked for is a fraction of 350 ns, which is
below what a loop around `Instant::now()` resolves on a machine with a scheduler. Criterion samples and
reports an interval, so it can say two things are indistinguishable instead of inventing a difference.

## Warm-up is part of the instrument, not a detail

`thresholds.rs` and `band.rs` discard five runs before sampling. Without that they read **30% high** —
9.3 ms against Criterion's 7.1 ms — because seven cold samples measure cache and branch-predictor state
as much as they measure code. Criterion warms up for seconds before recording anything, and §4.4a's
figure describes steady state, so these have to as well. An instrument that disagrees with the figure it
is checking is not checking it.

The reported figure, and the one `band.rs` compares for the three measures, is the **median** of
seven: the best of N reports only the moments the operating system left alone, the worst only the
moments it did not. All three are printed, because a figure without its spread is the single-sample
problem D-132 rejected — and the spread is what made D-137 visible.

**The calibration is the exception, and takes the fastest of the seven (H-64, D-141).** It is not
being reported; it is identifying a machine, and interference can only make a sample slower, so the
smallest is the closest any of them came to the machine's own speed. It is also the shortest thing
this file times — 0.87 ms on the fastest class against a 7.9 ms chain walk — which made a median of
it the noisiest number in the file while being the one that chose the baseline for the rest. One
commit passed `bench-band` on its `push` run and failed on its `pull_request` run with chain walks
1.8% apart and calibrations 90% apart, which is what prompted the change.

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
