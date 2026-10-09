# Fuzzing and property testing

§4.5 names five fuzz targets and four properties. This file says what each one actually establishes,
what it costs to run, and — for two of the five targets, plus one assertion that was removed — what
they failed to establish on the first attempt, because that is the part a reviewer cannot reconstruct
from the code.

The targets live in `fuzz/`, which is its own Cargo workspace. It is outside the main one because
cargo-fuzz builds with a sanitizer on a nightly toolchain, and D-131 settled that the toolchain is the
one `scripts/ci.sh` already pins for Miri rather than a second one. Nothing in `fuzz/` ships: the
binaries are test tooling and reach neither the deployed program nor the client.

## Running them

```
scripts/ci.sh fuzz          # all five at the counts §4.6 gates on
cargo +nightly-2026-06-16 fuzz run fuzz_apply -- -runs=20000
```

The group is not in `scripts/ci.sh all`, which is the push pipeline verbatim. It runs nightly in
`.github/workflows/fuzz.yml`: the group takes roughly twenty minutes, which is not a cost worth paying on every
push.

**A `timeout-` artifact does not by itself mean a timeout, and `fuzz/artifacts/` is not cleared between
runs.** Killing a run mid-unit makes libFuzzer's watchdog treat the interrupted unit as a hang and dump
it as `timeout-<hash>`. One of those was left here on 1 Oct 2026 by a run that was deliberately
terminated; replaying it took **0 ms** and exited 0, so §4.5's "zero timeouts" was never violated. Two
`slow-unit-` files from the same period replay in 3 ms each — libFuzzer flags a unit against the running
average, which early in a run is sub-millisecond. **Replay the reproducer before believing the
filename**, and read it against the run that produced it:

```sh
cargo +nightly-2026-06-16 fuzz run <target> fuzz/artifacts/<target>/<file> -- -timeout=10
```

The `fuzz` group's own report is the authority for a given run: every target printed
`slowest_unit_time_sec: 0` and the group exited 0.

**The limits are live, not decorative.** `-rss_limit_mb=2048` and `-timeout=10` are passed explicitly
rather than left to libFuzzer's defaults: §4.5 asks F-01 for zero OOM and zero timeouts, and neither can
be reported unless a limit exists to cross, so defaults would have made a gate that could not fail on
two of its three criteria. `-rss_limit_mb` was checked by running F-05 against
`-rss_limit_mb=1`, which failed with `ERROR: libFuzzer: out-of-memory (malloc(2162688))` and exit 1 — so
§4.5's zero-OOM criterion is one that can fail rather than one satisfied by never being tested. Note
which mechanism fired: the malloc hook catches a single large allocation immediately, while the RSS
poller runs on a one-second timer, so a very short run can exit before it checks at all.

When a target does find a crash, libFuzzer writes the input that caused it under `fuzz/artifacts/`,
which is gitignored and on CI exists only on the runner. The nightly job uploads that directory on
failure, because a run that reports a crash and discards the reproducer has reported a number rather
than a defect. The corpus is **not** carried between nights: every run explores from empty, which keeps
each night's count meaning the same thing at the cost of never going deeper than one night buys.


## The targets

| | What it drives | Count | Time | Rate | Peak RSS |
|---|---|---|---|---|---|
| F-01 `fuzz_params_decode` | arbitrary bytes into every decoder, including the client's account placement | 1,000,000 | 13 s | 76,923/s | 505 MB |
| F-02 `fuzz_canonicalize` | arbitrary bytes and invalid UTF-8 | 1,000,000 | 11 s | 90,909/s | 434 MB |
| F-03 `fuzz_apply` | arbitrary record sequences against a live chain | 1,000,000 | 355 s | 2,816/s | 565 MB |
| F-04 `fuzz_proof_verify` | arbitrary proof bytes against a fixed root | 1,000,000 | 527 s | 1,897/s | 404 MB |
| F-05 `fuzz_tree_build` | arbitrary leaf sets `0..=C` and arbitrary height bytes | 25,000 | 620 s | 40/s | 380 MB |

**One run, 3 Oct 2026, every figure from it, total derived by addition: 1,526 s — 25 min 26 s.** Highest
peak 565 MB against the 2,048 MB limit; `slowest_unit_time_sec` 0 for all five; `scripts/ci.sh fuzz`
exited 0.

A review found the previous version of this table arithmetically impossible, and it was: F-01's figure
came from one run while F-03's and F-04's came from an earlier one, and the stated total came from a
third. Mixing runs is what produced a total no addition of its own rows could reach. **Every figure here
is from the single run named above**, and the total is computed from the rows rather than quoted.

**F-05 has no stable rate, and the spread is the finding.** Runs of 25,000 from an empty corpus have
measured 16, 64, 75, 195, 217, 318 and 620 seconds, with an independent reviewer recording 222.60 s and
231.46 s. The leaf count is itself fuzzed and a 4,096-leaf unit at `H = 16` costs orders of magnitude
more than a small one, so throughput depends on what the search happens to explore. No single number
describes this target; the 16 s once published as its figure was the fastest of nine samples.

**A false timeout, and what it cost.** One group run aborted with libFuzzer exit 70 after F-05 reported
`slowest_unit_time_sec: 1034`. The input it saved replays in **223 ms** — a unit worth 223 ms of work was
measured at 1,034 seconds of wall clock, so the machine stalled rather than the code looping. Two fresh
runs then completed with `slowest_unit_time_sec: 0`. No `-timeout` value survives a thousand-second
stall, so nothing was loosened; what caught it was the rule above, replay before believing the filename.
An independent review had written of the per-unit margin that it was "strong operational confirmation,
not a proof against arbitrary machine load", and this is that caveat arriving within the hour.

## Round one's findings, and what they say about this file's own claims

An independent review of E-12 found five, three of them in the targets and properties this file describes
as working. Two are the same defect the section below is about, found again in places this file had not
looked.

**F-05 treated a forbidden refusal as success (E12-01).** Its refusal branch accepted `MalformedPayload`
for any input and only *required* it when the height was invalid. §4.5's obligation is positive — a valid
height always produces a complete tree — so an engine that began refusing valid trees would not have
failed it. The reviewer proved it: a defect refusing a valid, unique, one-leaf tree at `H = 8` completed
25,000 iterations green while the ordinary positive test failed at once. The target now decides what the
engine owes for every input — `Ok`, `0x05` for an invalid height or a duplicate identifier, `0x12` over
capacity — and requires exactly that. Re-checked with the same defect: it now fails naming §4.5.

**P-02 never reached an accepted transition (E12-02).** It compared two applications of an arbitrary
record against an arbitrary snapshot. An arbitrary `prev_head` fails condition (a), so the `Ok` arm was
dead and nondeterminism in the accepted path passed 10,000 cases — the reviewer demonstrated it with a
rising nonce XORed into accepted heads. Each case now also applies the same record rewritten to satisfy
every §1.3 condition from that snapshot, and fails if it is refused. Re-checked with the same defect: it
fails on the first case.

That is the third time this pattern has been found here, after F-01's refuted assertion and F-03's four
attempts. The lesson this file already drew was right and was not applied widely enough: **a target or
property that only inspects refusals has not tested the thing that must succeed.**

**F-05 could not represent its own domain (E12-03).** §4.5 asks for real-leaf sets over `0..=C`. Each
element costs 48 input bytes and libFuzzer's default `-max_len` is 4,096, so roughly 85 elements fitted and
the old 300-element source cap was never the binding constraint — its comment claimed to sit "a little
above the largest capacity this bound allows", which held only for `H = 8`. The input now carries a small
arbitrary set plus a **derived** count, so any count costs two bytes. That made the target about ten times
faster, because large sets no longer have to be decoded from input.

It did not make the whole domain reachable, and the limit is recorded rather than glossed. The derived
count is clamped at 4,096: left at the full `u16`, a unit could ask for 65,536 leaves at `H = 16`, and that
build under a sanitizer **exceeded the 10-second per-unit timeout and aborted the run**. So the fuzzer
reaches capacity for heights 4 through 12 and not for 13 through 16. Those boundaries are pinned
deterministically instead, by `the_leaf_count_boundaries_hold_at_every_height_class` in
`crates/certimining-log/tests/tree.rs`, which does 0, 1, `C-1`, `C` and `C+1` at every height class in
about two seconds — 1.65 s here and 2.01 s for an independent reviewer, so not a guarantee. Content search is what the fuzzer is for; a boundary should not depend on a mutation
happening to find it.

**§4.5's 10,000 P-02 cases reached no committed job (E12-04).** `config()` runs 512 and the requirement
lived in a comment telling a reader to set `PROPTEST_CASES` by hand. `scripts/ci.sh checks` now runs the
10,000 on every push; it costs a few seconds.

**The licence record named the wrong file population (E12-05).** See `deny.toml`, which now carries the
commands that reproduce all three figures — 53 files in the crate, 53 carrying the SPDX header, 26
compiled.

## Where E-12's round-three findings went

A third review round found five instances, none High. Four went to Post-deadline hardening on the owner's
ruling of 3 Oct 2026 — below High goes to hardening and the unit closes. The pointer is here because the
commit that first recorded it landed after PR #55's head was taken:

- ~~**H-21** P-02's accepted lane derives URI form and claimed-key presence from the same parity bit,
  so two of four valid combinations never occur and a partial commit in one of them passed 10,000
  cases.~~ **Closed.** The two come from independent bits — the key from `category`'s parity, the URI
  from `qp_key`'s first byte — so all four combinations occur.
- ~~**H-22** F-01 reduces an accepted checkpoint to its epoch, so a forced-zero root passed a million
  runs.~~ **Closed.** F-01 compares every field `decode_checkpoint` returns, in both lanes.
- ~~**H-23** F-02 never requires raw input over 256 bytes to be refused.~~ **Closed.** The rule is
  asserted against the input's own length, because the result of an over-long input is the thing that
  should not exist.
- ~~**H-24** F-04's genuine-proof control is one fixed epoch, so refusing every *other* genuine proof
  survives.~~ **Closed.** A second genuine proof is built from the input each iteration, at height 4
  to 6; the fixed control keeps height 8.

Each was closed by running the reviewer's own mutant against the repaired target: a forced-zero root,
a removed length refusal, a `verify` that refuses every proof outside epoch 20723, and a
`previous_category` committed for every shape but `https://` with a claimed key. All four now fail,
and all four passed before.

**F-04's cost went up and the table above has not been re-measured.** Building a second epoch per
iteration took 200,000 runs from about 2 seconds to 121 on the development machine, so the nightly's
figure for that row will move. The row is a measurement and is left as the last one taken rather than
estimated forward; `scripts/ci.sh fuzz` records the next.

The fifth was in V-Z-04, a §4.4 release blocker, and went out as its own pull request rather than waiting
behind a unit.

## Targets that could not reach what they tested

Each of these passed, and each was worthless, which is the failure mode a fuzz target is most prone to:
the harness refuses every input before the assertion under test executes, and a green run says nothing.

**F-01's first assertion was refuted in seconds.** It asserted §1.4's `last_epoch` / `start_epoch`
relation on any buffer that parsed. Borsh decoding does not establish that the program wrote the
buffer, so arbitrary bytes satisfy the decoder and violate the invariant; it also overflowed at
`u64::MAX`. Replaced with a round-trip assertion, which is a property of the codec rather than a claim
about provenance.

**F-03 took four attempts.** (1) An arbitrary `prev_head` fails §1.3's condition (a), so condition (b)
was never consulted. (2) The chain sets its own counter, so "the sequence rose by one" held even with
(b) relaxed — fixed by asserting `record.seq == chain.seq()`. (3) Arbitrary signatures never verify and
arbitrary URI bytes are never well-formed, so the accepted path was unreachable and every accept-side
assertion was dead. Fixed by signing with RFC 8032 §7.1's published key and a valid URI, and by adding
a **positive control**: a record satisfying every §1.3 condition must be accepted. Without that
control, a future change that refused everything would still pass.

**A tautological length assertion was removed.** `read_tag`'s length check was enforced twice on the
same path, so the assertion could not fail. It is gone, with the reason recorded rather than the
assertion left in place looking like coverage.

## The properties

**P-01** (`crates/certimining-core/tests/state_props.rs`) removes and reorders leaves in a valid chain
and requires the head to change. It is INV-STATE-02 from the other side: the invariant says a later
head is recomputable from an earlier one and the leaves between, and P-01 says no *other* sequence of
leaves reaches the same head. A chain failing it would let an issuer drop a record and present a head
that still verified.

**P-02** asserts `apply` is deterministic from arbitrary resumed states — the thing every other
property quietly assumes. §4.5 asks for 10,000 cases, which is `PROPTEST_CASES=10000`; the default run
is 512.

**P-03** (`programs/certimining-checkpoint/tests/privacy.rs`) is the property form of V-Z-01, and it
runs its whole domain instead of sampling it. Capacity at `H = 8` is 256 and the engine refuses a set
only when `real.len() > capacity`, so a real-leaf count is one of 257 values and all of them are
published — settling all 32,896 pairs exactly. Two things follow from that which four fixed counts did
not reach: a **completely full** epoch, the worst case for the tree's open addressing, and both
neighbours of each of V-Z-01's points. See D-133 for why the comparison is redaction rather than
V-Z-01's shape, and for the control that keeps it from comparing a publication against itself.

**P-04** is Miri on the two engine crates and `cargo-deny` on the workspace, both in `scripts/ci.sh`
as their own groups. Miri covers `certimining-core` and `certimining-log` with `--all-features`.

## V-N-18, and why only one implementation walks every prefix

E-12's acceptance criteria name V-N-18 — "every truncation prefix returns a code, never a panic" — and
it is worth saying plainly which implementation establishes that, because only one does and that is not
an oversight.

`vectors/V-N-18.json` fixes one canonical 161-byte leaf preimage and asserts every shorter prefix is
refused at the decode step with `0x05`. The TypeScript verifier walks all 161 of them
(`ts/test/handlers.ts`, `vN18`). **Nothing in Rust does, because nothing in Rust parses a leaf
preimage.** The engine builds preimages from typed fields — `LeafPreimage` in
`crates/certimining-core/src/preimage.rs` writes bytes and never reads them — so there is no Rust
function to hand a truncated buffer to. Adding one for the test would mean new API on a shipped crate
existing only to be truncated.

What the Rust side does have, it covers: `read_tag` is checked at every prefix 0..8
(`crates/certimining-core/tests/preimage.rs`) and proved total over arbitrary buffers up to 64 bytes
(`the_tag_reader_is_total`), and the decoders that do read untrusted bytes are F-01's target. The
asymmetry follows from the two implementations facing opposite directions: the engine writes, the
verifier reads. V-N-18 is a claim about reading.

## V-Z-04 scored its own worst outcome as ideal

**There were two such helpers, not one.** `crates/certimining-log/tests/common/mod.rs` serves V-Z-04 and
`crates/certimining-client/tests/correlation.rs` serves V-Z-01's devnet gate; both returned `0.0` on a
constant series, and an earlier version of this section said V-Z-04 was the only §4.4 instance. V-Z-01's
is fixed here too. Its two roles were separated at first — a constant *feature* refused, while a constant
*landing delay* was reported as favourable rather than scored — and a later round showed that split was
wrong. A collapsed slot reading produces exactly the series a genuinely flat delay would, and §4.4 asks
for `|r| < 0.2`, which an undefined r does not meet. Both roles refuse now, as they always did in
`certimining-log`.

`pearson` in `crates/certimining-log/tests/common/mod.rs` returned `0.0` whenever either series was
constant. For §4.4's V-Z-04 bounds, which require |r| below a threshold, that is the **best possible**
answer — so the worst possible placement result passed the privacy gate.

A review forced all 25,600 observed placements into slot zero. `v_z_04_position_carries_no_meaning`
reported correlation 0 for submission order, issuer and time, and passed. Every submission landing in one
slot is exactly what INV-TREE-03 forbids, and the instrument scored it as perfect non-correlation.

Zero variance means one of two things and both are failures. A constant **observation** is that
catastrophic placement result. A constant **feature** is a malformed sample: a run that varied nothing
cannot establish whether position follows it. Neither is a number this function may return, so it now
refuses, naming which series was constant.

## What this class is, stated to the evidence

An earlier version of this section called V-Z-04 "the eighth instance of one class" and said such a
defect "cannot be caught by running it". A review narrowed both claims, and it was right to.

**Five predecessors have committed before-and-after evidence**, where the repository holds the bad branch
and its repair: F-05's refusal branch (`eb88730`, repaired in `8eb2eda`), and F-02's and F-04's missing
positive obligations, P-01's silent prefix and P-02's absent commit proof (all repaired in `2d546c2`).
**Two are author-recorded development history only** — F-01's refuted assertion and F-03's four
attempts arrived already repaired, and survive in comments rather than in the history. So the count of
*named harnesses in which adversarial mutation exposed an invalid green path* is eight including V-Z-04;
the count of independently verifiable defect instances is five.

**And "cannot be caught by running it" was too strong.** F-01's own account in this file says the fuzzer
refuted its first assertion in seconds — that one *was* caught by running it. P-02 had an unreachable
accepted path before its later missing commit proof, and F-03 records several distinct reachability
failures, so the instances are not uniform either.

The bounded claim is the useful one: **ordinary green runs did not expose these paths, and adversarial
mutation did.** Each was found by changing what the instrument watches and checking whether it noticed —
not by running the suite again.

## What none of this covers

**The targets are linted, over the second graph (H-18).** `checks` runs
`cargo clippy --workspace --all-targets -- -D warnings`, which covers test code — P-03 was caught by
it on first writing — but `fuzz/` is a separate workspace and `--workspace` does not reach it, the same
gap that made `deny` check the fuzz manifest as a second graph (D-135). `checks` now runs
`cargo clippy --manifest-path fuzz/Cargo.toml --all-targets -- -D warnings` as well.

Two things were unknown when this was filed and are now answered: the `libfuzzer_sys::fuzz_target!`
expansions are lint-clean as written, and the run takes about sixteen seconds, which is cheap enough
for the push pipeline rather than the nightly one.

Fuzzing and properties establish that code does not panic and that stated relations hold on generated
input. They do not establish that the relations are the right ones, and they are not a cryptographic
review. §4.5's targets sit under the KATs and the committed vectors, which fix published values; a
target agreeing with an implementation that is wrong agrees with it consistently.
