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
`.github/workflows/fuzz.yml`: the group takes 17 minutes, which is not a cost worth paying on every
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
| F-01 `fuzz_params_decode` | arbitrary bytes into every decoder | 1,000,000 | 4 s | 250,000/s | 516 MB |
| F-02 `fuzz_canonicalize` | arbitrary bytes and invalid UTF-8 | 1,000,000 | 2 s | 500,000/s | 366 MB |
| F-03 `fuzz_apply` | arbitrary record sequences against a live chain | 1,000,000 | 349 s | 2,865/s | 480 MB |
| F-04 `fuzz_proof_verify` | arbitrary proof bytes against a fixed root | 1,000,000 | 510 s | 1,960/s | 403 MB |
| F-05 `fuzz_tree_build` | arbitrary leaf sets `0..=C` and arbitrary height bytes | 25,000 | 169 s | 147/s | 453 MB |

The whole group is 1,034 seconds — 17 minutes 14 seconds. `slowest_unit_time_sec` was 0 for every
target and the highest peak was 516 MB against the 2,048 MB limit, so §4.5's "zero panics, zero OOM,
zero timeouts" is met for F-01 and F-02 and holds for the other three at their counts.

Measured end to end at these counts, from an empty corpus, on an Apple M2, 8 cores, macOS 26.6.2, under
cargo-fuzz's default AddressSanitizer build.

**Short measurements do not extrapolate here, and an earlier version of this file was wrong because of
it.** F-03 measured 2,222/s over 20,000 runs against a 262-entry corpus, which predicts a million
iterations in seven and a half minutes; the actual run took over 34 minutes, its corpus growing to
1,527 entries. libFuzzer mutates from the corpus it accumulates, so a warm corpus is slower than a cold
one and a short sample overstates a long run. From empty, that same million is 349 seconds. The nightly
job always starts from empty, so the table above is what describes it, and no figure in it is derived
from a shorter run.

**F-05's count is the one below a million, and it is a budget rather than a result.** §4.5 fixes a
million for F-01 and F-02; it states no count for the other three, and F-03 and F-04 run a million
anyway because at these rates they can. F-05 cannot: an arbitrary height byte may ask for `H = 16`, a
complete tree of 65,536 leaves is milliseconds of Keccak under a sanitizer, and a million units at
147/s is 1.9 hours, against 14 min 25 s for the other four combined.

So F-05 sees four orders of magnitude less input than F-01. That is the cost of one unit, not a finding
that less exploration suffices, and raising it is one edit to `fuzz()` in `scripts/ci.sh` plus a longer
`timeout-minutes` in the workflow.

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

## What none of this covers

**The targets themselves are not linted.** `checks` runs
`cargo clippy --workspace --all-targets -- -D warnings`, which does cover test code — P-03 was caught by
it on first writing — but `fuzz/` is a separate workspace and `--workspace` does not reach it. The same
two-graph argument that made `deny` check the fuzz manifest applies to clippy, and it has not been
applied: §4.5 asks nothing about lints on the targets, and adding `-D warnings` over
`libfuzzer_sys::fuzz_target!` expansions is scope this unit did not take. It is one `check` line in
`checks()` if that changes.

Fuzzing and properties establish that code does not panic and that stated relations hold on generated
input. They do not establish that the relations are the right ones, and they are not a cryptographic
review. §4.5's targets sit under the KATs and the committed vectors, which fix published values; a
target agreeing with an implementation that is wrong agrees with it consistently.
