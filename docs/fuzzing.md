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

## What the review rounds changed, and the rule they produced

Three independent rounds found the same defect in different places, and the rule is the one claim in
this file worth reading twice:

> **A target or property that only inspects refusals has not tested the thing that must succeed.**

F-01 asserted §1.4's `last_epoch` / `start_epoch` relation on any buffer that parsed, which Borsh
decoding does not establish; it is a round-trip assertion now. F-03 took four attempts before its
accepted path was reachable at all — arbitrary signatures never verify and arbitrary URI bytes are
never well-formed, so every accept-side assertion was dead — and now signs with RFC 8032 §7.1's
published key and carries a **positive control**: a record satisfying every §1.3 condition must be
accepted. F-05 (E12-01) accepted `MalformedPayload` for any input; it now decides what the engine
owes for every input and requires exactly that. P-02 (E12-02) compared two applications of a record
an arbitrary snapshot always refused; each case now also applies a record rewritten to satisfy every
§1.3 condition, and fails if that is refused. A tautological length assertion in `read_tag` was
removed rather than left looking like coverage.

Round one's other findings: §4.5's 10,000 P-02 cases lived in a comment and now run in
`scripts/ci.sh checks` on every push (E12-04); the licence record named the wrong file population and
`deny.toml` now carries the commands that reproduce its figures (E12-05). Round three found five more,
four closed as H-21 to H-24 by running each reviewer's own mutant against the repaired target — a
forced-zero root, a removed length refusal, a `verify` refusing every proof outside epoch 20723, a
`previous_category` committed for every shape but one. All four failed after repair and had passed
before. The fifth was in V-Z-04 and went out as its own pull request.

**A limit this left behind.** F-05's input carries a small arbitrary set and a derived count, clamped
at 4,096: left at the full `u16` a unit could ask for 65,536 leaves at `H = 16`, and that build under
a sanitizer exceeded the 10-second per-unit timeout and aborted the run. **The fuzzer reaches capacity
for heights 4 through 12 and not for 13 through 16.** Those boundaries are pinned deterministically
instead — `the_leaf_count_boundaries_hold_at_every_height_class` in
`crates/certimining-log/tests/tree.rs` does 0, 1, `C-1`, `C` and `C+1` at every height class.

**F-04's cost went up and the table above has not been re-measured.** Building a second epoch per
iteration took 200,000 runs from about 2 seconds to 121 on the development machine. The row is left as
the last measurement taken rather than estimated forward; `scripts/ci.sh fuzz` records the next.

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

## A correlation helper may not return zero for a constant series

`pearson` returned `0.0` whenever either series was constant. For §4.4's V-Z-04 bounds, which require
|r| below a threshold, that is the **best possible** answer — so the worst possible placement result
passed the privacy gate. A review forced all 25,600 observed placements into slot zero;
`v_z_04_position_carries_no_meaning` reported correlation 0 for submission order, issuer and time, and
passed. Every submission landing in one slot is exactly what INV-TREE-03 forbids.

Zero variance means one of two things and both are failures. A constant **observation** is that
catastrophic placement result. A constant **feature** is a malformed sample: a run that varied nothing
cannot establish whether position follows it. Neither is a number this function may return, so it
refuses and names which series was constant.

There were two such helpers: `crates/certimining-log/tests/common/mod.rs` for V-Z-04 and
`crates/certimining-client/tests/correlation.rs` for V-Z-01's devnet gate. Both refuse now, in both
roles — a collapsed slot reading produces exactly the series a genuinely flat landing delay would, and
§4.4 asks for `|r| < 0.2`, which an undefined r does not meet.

## What this class is, stated to the evidence

**Eight named harnesses** are ones in which adversarial mutation exposed an invalid green path. Of
those, **five have committed before-and-after evidence** — the repository holds the bad branch and its
repair: F-05's refusal branch (`eb88730`, repaired in `8eb2eda`), F-02's and F-04's missing positive
obligations, P-01's silent prefix and P-02's absent commit proof (all repaired in `2d546c2`). Two are
author-recorded development history only, surviving in comments rather than in the history: F-01's
refuted assertion and F-03's four attempts. V-Z-04 is the eighth.

The instances are not uniform. F-01's first assertion *was* caught by running it — the fuzzer refuted
it in seconds. The bounded claim is the useful one: **ordinary green runs did not expose these paths,
and adversarial mutation did.** Each was found by changing what the instrument watches and checking
whether it noticed, not by running the suite again.

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
