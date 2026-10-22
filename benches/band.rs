// SPDX-License-Identifier: MIT OR Apache-2.0
//! The CI regression band over §4.4a's wall-clock measures (E-13, D-132): a committed baseline and a
//! band. §4.4a states no wall-clock threshold since D-137; this compares a runner against itself.
//!
//! `thresholds.rs` measures and reports those figures with the machine named. This is the other half of
//! D-132's split: a shared runner cannot be held to those numbers, so it is compared against its own
//! previous numbers instead.
//!
//! **It fails on drift past the band again (H-47, issue #162).** It did not between 12 October and 22
//! October: the band was 50% and `BASELINE.toml` said outright that the number was a guess, it flaked
//! on a pull request containing no Rust at all, and the owner made it report-only and named the way
//! back — twenty CI runs, the band set from the measured spread, the derivation recorded, the
//! assertion restored. Thirty runs were collected on 22 October and `BASELINE.toml` carries what they
//! show. **So a wall-clock regression gate exists in this repository again**, at 15% rather than 50%.
//!
//! **A pass on a fast runner means nothing, and this says so.** GitHub's fleet is mixed: 8 of those 30
//! runs came in at 0.59 to 0.64 times the baseline, where no code change could have pushed a measure
//! over the limit. A run reporting "every measure is inside its limit" from a machine 1.6 times faster
//! than the one the baseline was taken on has not exercised the gate, and a report that did not
//! distinguish the two would be this repository's oldest defect: an instrument reading its own
//! acceptance predicate back.
//!
//! **What this file does still fail on is structural**, and all of it below: an absent baseline entry, a
//! non-finite band or baseline, a fixture that is not the size its label names, a timed no-op, a
//! verifier accepting a corrupted leaf. **A baseline nobody measured would be a gate that cannot fail**,
//! so an absent entry is a failure that prints what it measured, and the figure is committed from that
//! run's output. Nothing here invents a number.

use certimining_benches::{
    chain_of, genesis, hash_chain, real_leaves, walk, HashOnly, EPOCH, HEIGHT, MASTER, RECORDS,
};
use certimining_core::NativeKeccak;
use certimining_log::{BuiltEpoch, EpochTree, InclusionVerifier, ProofVerifier};
use std::time::{Duration, Instant};

const WARM_UP: usize = 5;
const SAMPLES: usize = 7;

/// Warm up, then the median of `SAMPLES`. The same instrument `thresholds.rs` uses, for the same reason:
/// without warm-up this reads 30% high and measures cache state rather than code.
fn median_ms<T>(mut f: impl FnMut() -> T) -> f64 {
    for _ in 0..WARM_UP {
        drop(std::hint::black_box(f()));
    }
    let mut times: Vec<Duration> = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let start = Instant::now();
        let out = f();
        times.push(start.elapsed());
        drop(std::hint::black_box(out));
    }
    times.sort_unstable();
    times[SAMPLES / 2].as_secs_f64() * 1_000.0
}

/// `band_percent` and the `[measures]` table, read from the committed file rather than restated here.
fn baseline() -> (f64, Vec<(String, f64)>) {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("BASELINE.toml");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let mut band = None;
    let mut measures = Vec::new();
    let mut in_measures = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        if line == "[measures]" {
            in_measures = true;
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let (key, value) = (key.trim(), value.trim());
        let parsed: f64 = value
            .parse()
            .unwrap_or_else(|_| panic!("{key}: {value} is not a number"));
        if in_measures {
            // **A baseline that is not a number switches its row off silently (PR #59, round three).**
            // Rust's f64 parser accepts `NaN`, `NaN * 1.5` is `NaN`, and `now > NaN` is false, so one
            // typo turned `epoch_root_256_leaves` into a comparison that could not fail while the test
            // reported a pass. `band_percent` was already checked for this; the measures were not.
            assert!(
                parsed.is_finite() && parsed >= 0.0,
                "benches/BASELINE.toml: {key} is {value}, which is not a measurable duration. A \
                 non-finite or negative baseline makes its limit non-finite and the comparison \
                 vacuous, so the row would pass without being checked."
            );
            measures.push((key.to_string(), parsed));
        } else if key == "band_percent" {
            band = Some(parsed);
        }
    }
    (band.expect("band_percent"), measures)
}

#[test]
fn wall_clock_measures_are_compared_against_the_baseline() {
    // Constant by design: the point is to refuse a debug run, where the figures would be several times
    // over and the failure would say nothing. Written as a conditional panic rather than an assertion,
    // because `assert!` on a compile-time constant is a clippy error and a cfg-gated `panic!` makes the
    // rest of the function unreachable in clippy's own debug build.
    if cfg!(debug_assertions) {
        panic!(
            "build this with --release: cargo test --release -p certimining-benches --test band"
        );
    }

    let (band, committed) = baseline();
    // **A non-finite band disables the gate silently (PR #59, Low 6).** `band_percent = NaN` makes every
    // `limit` NaN, every `now > limit` false, and every row pass. A typo should not be able to switch a
    // gate off, so the band has to be a usable number before anything is compared.
    assert!(
        band.is_finite() && band >= 0.0,
        "benches/BASELINE.toml: band_percent is {band}, which is not a usable percentage. A non-finite \
         or negative band makes every comparison below vacuously true and the gate stops gating."
    );

    let unsigned = chain_of(false);
    let from = genesis();
    let full = real_leaves(1 << HEIGHT);
    let built = <BuiltEpoch as EpochTree>::build::<NativeKeccak>(EPOCH, HEIGHT, &MASTER, &full)
        .expect("builds");
    let id = full[full.len() / 2].0;
    let leaf = full
        .iter()
        .find(|(i, _)| *i == id)
        .map(|(_, l)| *l)
        .expect("in the set");
    let proof = built.proof(&id).expect("a proof");
    let root = built.root;

    // **The workload itself has to be pinned, not just the shape of the result (PR #59, round two,
    // High 1).** The structural checks below compare a build against `1 << HEIGHT`, and `HEIGHT` is a
    // mutable benchmark constant — so both sides moved together. A review changed it from 8 to 4 and the
    // band passed while timing a 16-leaf build and a four-level proof, under a row still called
    // `epoch_root_256_leaves` and against a baseline measured at 256. That is the third variant of one
    // mistake in this file: an oracle that shares its subject.
    //
    // These are literals, deliberately. They are what §4.4a's rows and `BASELINE.toml`'s names say the
    // figures describe, and they are checked before anything is timed, so shrinking the fixture fails
    // here rather than producing a fast number under the old label.
    assert_eq!(
        HEIGHT, 8,
        "§4.4a's figures are at the deployed height; BASELINE.toml's rows assume it"
    );
    assert_eq!(
        RECORDS, 10_000,
        "§4.4a's chain-walk row is over 10,000 records"
    );
    assert_eq!(
        unsigned.len(),
        10_000,
        "the chain fixture is not 10,000 records"
    );
    assert_eq!(
        full.len(),
        256,
        "the epoch fixture is not the 256 leaves the row names"
    );
    assert_eq!(built.leaves.len(), 256, "the built epoch is not 256 leaves");
    assert_eq!(
        proof.siblings.len(),
        8,
        "an inclusion proof at the deployed height carries eight siblings; this one carries {}",
        proof.siblings.len()
    );

    // **Timing an operation is not evidence it happened (PR #59, High 1).** This measured three closures
    // and threw their results away: the chain walk's head was discarded, and the proof verification's
    // `Result` went into `black_box` without being inspected. A review made `hash_chain` return
    // immediately and corrupted the proof's leaf, and the band passed at 0.0000 ms and 0.0039 ms — a
    // measurement of nothing, inside the band, reported as a pass.
    //
    // That is the same class E-12's three rounds found eight times, in the gate written to watch for
    // regressions. Each closure now returns something the loop checks, so a no-op cannot be timed.
    // **And the expectation may not come from the thing under test.** The first attempt at this fix took
    // `expected_head` from `hash_chain` itself, so the no-op mutation changed both sides and still
    // passed — the same defect E-12's M-02 found in F-01's oracle, repeated here. The head now comes
    // from the state machine, which is a different implementation of the same recurrence.
    let expected_head = walk::<HashOnly>(&unsigned);
    // A corrupted proof must be refused, so a verifier that accepts everything cannot pass either.
    let mut wrong_leaf = leaf;
    wrong_leaf[0] ^= 0xff;
    ProofVerifier::verify::<NativeKeccak>(&leaf, &proof, &root)
        .expect("the epoch's own proof verifies before anything is timed");
    assert!(
        ProofVerifier::verify::<NativeKeccak>(&wrong_leaf, &proof, &root).is_err(),
        "a proof verified for a leaf the epoch does not hold, so the timing below measures a verifier \
         that accepts anything"
    );

    let measured: Vec<(&str, f64)> = vec![
        (
            "chain_walk_hash_chain_only",
            median_ms(|| {
                let head = hash_chain(&unsigned, from);
                assert_eq!(
                    head, expected_head,
                    "the timed chain walk reached a different head"
                );
                head
            }),
        ),
        (
            "epoch_root_256_leaves",
            median_ms(|| {
                let again =
                    <BuiltEpoch as EpochTree>::build::<NativeKeccak>(EPOCH, HEIGHT, &MASTER, &full)
                        .expect("builds");
                // Structural, so a build that returned a default or did nothing cannot be timed. There
                // is no second implementation of the tree to compare a root against, so what is checked
                // is what INV-TREE-01 fixes: a complete tree, every submission placed. The sizes are
                // literals, not `1 << HEIGHT` and `full.len()`, so this closure does not check the
                // workload against the same constants that chose it.
                assert_eq!(
                    again.leaves.len(),
                    256,
                    "the timed build did not produce a complete 256-leaf tree"
                );
                assert_eq!(
                    again.assignment.len(),
                    256,
                    "the timed build did not place all 256 submissions"
                );
                assert_ne!(
                    again.root, [0u8; 32],
                    "the timed build produced a zero root"
                );
                again
            }),
        ),
        (
            "inclusion_proof_verify",
            median_ms(|| {
                ProofVerifier::verify::<NativeKeccak>(&leaf, &proof, &root)
                    .expect("the timed verification refused the epoch's own proof");
            }),
        ),
    ];

    let mut missing: Vec<String> = Vec::new();
    let mut over: Vec<String> = Vec::new();
    for (name, now) in &measured {
        match committed.iter().find(|(k, _)| k == name) {
            None => missing.push(format!("{name} = {now:.4}")),
            Some((_, was)) => {
                let limit = was * (1.0 + band / 100.0);
                // **Finite was necessary and not sufficient (PR #59, round four).** `f64::MAX` passes
                // the parse check, `f64::MAX * 1.5` is infinity, and `now > inf` is never true, so a
                // finite baseline could still switch its row off. The number that has to be usable is
                // the one the comparison uses.
                assert!(
                    limit.is_finite(),
                    "benches/BASELINE.toml: {name}'s baseline {was} with a {band}% band gives a limit \
                     of {limit}, which nothing can exceed, so the row would pass unchecked"
                );
                println!("{name}: {now:.4} ms, baseline {was:.4} ms, limit {limit:.4} ms");
                if now > &limit {
                    over.push(format!(
                        "{name}: {now:.4} ms against a baseline of {was:.4} ms, which is more than \
                         {band}% above it"
                    ));
                }
            }
        }
    }

    assert!(
        missing.is_empty(),
        "benches/BASELINE.toml has no figure for {} measure(s) on this machine, so there is nothing to \
         compare against and this gate would otherwise pass without checking anything. Measured now — \
         commit these under [measures] if this run is the runner the baseline is for:\n{}",
        missing.len(),
        missing.join("\n")
    );
    // **Whether this run could have failed at all (H-47, issue #162).** GitHub's runner fleet is
    // mixed, and the baseline came from its slowest class. A run on a faster one measures well below
    // the baseline, so nothing it does can push a measure over the limit: "every measure is inside its
    // limit" is then a true sentence about a gate that was not exercised. 8 of the 30 calibration runs
    // were like that, at 0.59 to 0.64 times the baseline.
    //
    // The floor is 0.8 because the classes observed sit at about 1.00, 0.88 and 0.61 times the
    // baseline, so 0.8 separates the slow pair from the fast one. It is a disclosure and not a gate:
    // a fast runner is not a failure, and a run that cannot fail saying so is the difference between a
    // pass and a pass that means something.
    const FASTER_CLASS_FLOOR: f64 = 0.8;
    let faster: Vec<String> = measured
        .iter()
        .filter_map(|(name, now)| {
            let (_, was) = committed.iter().find(|(k, _)| k == name)?;
            (now < &(was * FASTER_CLASS_FLOOR))
                .then(|| format!("{name}: {now:.4} ms against a baseline of {was:.4} ms"))
        })
        .collect();
    if !faster.is_empty() {
        println!(
            "band: {} measure(s) came in below {:.0}% of baseline, so this runner is a faster class \
             than the one the baseline was taken on and the comparison below could not have failed \
             for them whatever the code did:\n{}",
            faster.len(),
            FASTER_CLASS_FLOOR * 100.0,
            faster.join("\n")
        );
    }

    // **The assertion, restored (H-47, issue #162).** It was report-only from 12 October, after a 50%
    // band derived from one sample flaked on a pull request containing no Rust at all. The owner named
    // the way back and this is the far end of it: thirty runs collected, the band set to 15% from the
    // spread they show, the derivation in `BASELINE.toml` beside the number.
    //
    // What the band does not cover is a runner class *slower* than the baseline's, which none of the
    // thirty was. If one appears, this fails and the answer is to re-measure the baseline on it rather
    // than to widen the band — and the failure names the measure and both figures, which is what tells
    // the difference between that and a regression.
    assert!(
        over.is_empty(),
        "band: {} measure(s) above the limit. The band is {band}% and is derived from 30 CI runs, in \
         which no measure exceeded its baseline by more than 2.4% — so this is either a regression or \
         a runner class slower than the one the baseline was taken on, and the figures below say \
         which: a regression moves one measure, a slower machine moves all of them \
         together.\n{}",
        over.len(),
        over.join("\n")
    );
    println!("band: every measure is inside its limit, which is asserted and not merely reported");
}
