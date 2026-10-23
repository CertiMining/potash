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

/// How many Ed25519 verifications the calibration measure performs.
///
/// Sized so the figure is milliseconds rather than microseconds: `inclusion_proof_verify` runs in
/// about 4 µs, where a single timer step is a comparable amount, and that is the measure whose
/// quantisation noise crossed the band. A discriminator has to be the opposite of that.
const CALIBRATION_VERIFICATIONS: usize = 32;

/// RFC 8032 §7.1's first secret key, a published value, as `certimining-benches` already uses it.
const RFC8032_SECRET: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];

/// **A measure of the machine, which this repository's code cannot move** (H-61, issue #228).
///
/// This is what says which runner class a run is on, and it has to be independent of the thing being
/// gated: using one of the three measures would mean a code regression shifted the class selection
/// and so chose a baseline that absorbed it — the gate would hide exactly what it exists to find.
///
/// So the work is `ed25519-dalek`'s verification, pinned at `=2.2.0`, over a signature made from a
/// published key. Nothing in `crates/` is on this path. A version bump would move the figure and
/// every class with it, which is a deliberate change that owes a re-measure; the pin is what makes
/// that a decision rather than a drift.
///
/// **It reads the fastest sample, not the median (H-64, issue #243, ruled 23 October 2026).**
/// [`minimum_ms`] records why. The same change makes the figures a *median* produced no longer
/// describe this measure, which is why `BASELINE.toml` carries no class blocks until runs under this
/// instrument put them there.
fn calibration_ms() -> f64 {
    use ed25519_dalek::{Signer as _, SigningKey, Verifier as _};
    let key = SigningKey::from_bytes(&RFC8032_SECRET);
    let verifying = key.verifying_key();
    let message = b"certimining band calibration, a fixed workload";
    let signature = key.sign(message);
    verifying
        .verify(message, &signature)
        .expect("the calibration's own signature verifies before anything is timed");
    minimum_ms(|| {
        let mut ok = 0usize;
        for _ in 0..CALIBRATION_VERIFICATIONS {
            if verifying.verify(message, &signature).is_ok() {
                ok += 1;
            }
        }
        // Returned and checked, so a verifier that did nothing cannot be timed — the defect this
        // file records three variants of.
        assert_eq!(
            ok, CALIBRATION_VERIFICATIONS,
            "the calibration verified nothing"
        );
        ok
    })
}

/// Warm up, then the median of `SAMPLES`. The same instrument `thresholds.rs` uses, for the same reason:
/// without warm-up this reads 30% high and measures cache state rather than code.
fn median_ms<T>(f: impl FnMut() -> T) -> f64 {
    sorted_ms(f)[SAMPLES / 2]
}

/// Warm up, then the **fastest** of `SAMPLES`, which is what the calibration reads (H-64, issue #243).
///
/// **Interference can only make a sample slower.** A timed run shares its machine with whatever else
/// the host is doing, and every one of those things adds time; none removes it. So the smallest of a
/// set of samples is the closest any of them came to the machine's own speed, and the median carries
/// whatever the machine was also doing during the middle sample.
///
/// That matters because the calibration is the shortest thing this file times — 0.87 ms on the
/// fastest class, against a 7.9 ms chain walk — and it is the one that decides which baseline the
/// other three are compared against. Commit `d24dd83` passed `bench-band` on its `push` run and
/// failed on its `pull_request` run minutes later: the chain walks were 1.8% apart, which is the same
/// machine, and the calibrations were 90% apart. A verdict about interference, delivered as a verdict
/// about the diff — which is the defect H-61 was written to end, relocated from the measures to the
/// thing that selects their baseline.
///
/// **The three measures keep the median**, because they are not identifying anything: they are
/// compared against a band, and a band derived from medians has to be read by one.
fn minimum_ms<T>(f: impl FnMut() -> T) -> f64 {
    // `sorted_ms` sorts, so the first element is the fastest sample.
    sorted_ms(f)[0]
}

/// Warm up, then `SAMPLES` timings in milliseconds, ascending.
fn sorted_ms<T>(mut f: impl FnMut() -> T) -> [f64; SAMPLES] {
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
    let mut out = [0.0; SAMPLES];
    for (slot, time) in out.iter_mut().zip(&times) {
        *slot = time.as_secs_f64() * 1_000.0;
    }
    out
}

/// One runner class: what the calibration reads on it, and what the measures were when it was taken.
struct Class {
    name: String,
    calibration_ms: f64,
    measures: Vec<(String, f64)>,
}

/// `band_percent`, `class_tolerance_percent` and one `[class.<name>]` block each, read from the
/// committed file rather than restated here.
fn committed() -> (f64, f64, Vec<Class>) {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("BASELINE.toml");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let mut band = None;
    let mut tolerance = None;
    let mut classes: Vec<Class> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        if let Some(name) = line
            .strip_prefix("[class.")
            .and_then(|r| r.strip_suffix(']'))
        {
            classes.push(Class {
                name: name.to_string(),
                calibration_ms: f64::NAN,
                measures: Vec::new(),
            });
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let (key, value) = (key.trim(), value.trim());
        let parsed: f64 = value
            .parse()
            .unwrap_or_else(|_| panic!("{key}: {value} is not a number"));
        // Computed before the mutable borrow below, which cannot coexist with reading the length.
        let at_top = classes.is_empty();
        match (classes.last_mut(), key) {
            (_, "band_percent") if at_top => band = Some(parsed),
            (_, "class_tolerance_percent") if at_top => tolerance = Some(parsed),
            (Some(class), "calibration_ms") => {
                // The figure that selects this class. Non-finite would make every comparison below
                // match nothing or everything, which is the same defect as a non-finite baseline.
                assert!(
                    parsed.is_finite() && parsed > 0.0,
                    "benches/BASELINE.toml: [class.{}]'s calibration_ms is {value}, which cannot \
                     identify a machine",
                    class.name
                );
                class.calibration_ms = parsed;
            }
            (Some(class), _) => {
                // **A baseline that is not a number switches its row off silently (PR #59, round
                // three).** Rust's f64 parser accepts `NaN`, `NaN * 1.5` is `NaN`, and `now > NaN` is
                // false, so one typo turned `epoch_root_256_leaves` into a comparison that could not
                // fail while the test reported a pass.
                assert!(
                    parsed.is_finite() && parsed >= 0.0,
                    "benches/BASELINE.toml: [class.{}]'s {key} is {value}, which is not a measurable \
                     duration. A non-finite or negative baseline makes its limit non-finite and the \
                     comparison vacuous, so the row would pass without being checked.",
                    class.name
                );
                class.measures.push((key.to_string(), parsed));
            }
            (None, _) => {}
        }
    }
    for class in &classes {
        assert!(
            class.calibration_ms.is_finite(),
            "benches/BASELINE.toml: [class.{}] carries no calibration_ms, so nothing can select it \
             and its baselines are unreachable",
            class.name
        );
    }
    (
        band.expect("band_percent"),
        tolerance.expect("class_tolerance_percent"),
        classes,
    )
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

    let (band, tolerance, classes) = committed();
    assert!(
        tolerance.is_finite() && tolerance > 0.0,
        "benches/BASELINE.toml: class_tolerance_percent is {tolerance}, which cannot select a class"
    );
    // **A non-finite band disables the gate silently (PR #59, Low 6).** `band_percent = NaN` makes every
    // `limit` NaN, every `now > limit` false, and every row pass. A typo should not be able to switch a
    // gate off, so the band has to be a usable number before anything is compared.
    assert!(
        band.is_finite() && band >= 0.0,
        "benches/BASELINE.toml: band_percent is {band}, which is not a usable percentage. A non-finite \
         or negative band makes every comparison below vacuously true and the gate stops gating."
    );

    // **Two classes whose intervals meet make a gate that cannot pass (H-61, issue #228).** A class
    // applies when a run's calibration is within `tolerance` of *that class's* figure, so each class
    // owns `[(1 - t)·c, (1 + t)·c]` and two of them stay distinct only while
    // `c2 / c1 > (1 + t) / (1 - t)`.
    //
    // The first tolerance committed here was 6%, derived before any calibration had been measured,
    // from `chain_walk` ratios that put the nearest two classes 14% apart. Two of the four classes
    // since met are 6.275% apart, so at 6% their intervals met: a run on the faster of them matched
    // both classes, which the ambiguity check below refuses, and that class could never have passed.
    // Nothing in the file looked wrong — only a run landing in the overlap would have shown it.
    //
    // So it is checked here, over the committed figures, before anything is timed. A file that cannot
    // give an unambiguous answer fails for that reason rather than for whichever machine ran it.
    assert!(
        tolerance < 100.0,
        "benches/BASELINE.toml: class_tolerance_percent is {tolerance}, and at 100% or more every          class matches every calibration, so no class could be selected unambiguously"
    );
    let needed = ((1.0 + tolerance / 100.0) / (1.0 - tolerance / 100.0) - 1.0) * 100.0;
    for (i, a) in classes.iter().enumerate() {
        for b in classes.iter().skip(i + 1) {
            let (low, high) = if a.calibration_ms <= b.calibration_ms {
                (a, b)
            } else {
                (b, a)
            };
            let apart = (high.calibration_ms / low.calibration_ms - 1.0) * 100.0;
            assert!(
                apart > needed,
                "benches/BASELINE.toml: [class.{}] at {:.4} ms and [class.{}] at {:.4} ms are                  {apart:.3}% apart, and at a tolerance of {tolerance}% two classes need more than                  {needed:.3}% between them or their intervals meet. A calibration inside the overlap                  matches both and is refused as ambiguous, so one of these classes could never pass.                  Separate them or narrow class_tolerance_percent.",
                low.name,
                low.calibration_ms,
                high.name,
                high.calibration_ms
            );
        }
    }

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

    // **Which runner class this is, decided before anything is compared (H-61, issue #228).**
    //
    // The band used to hold one baseline, taken from the slowest class the fleet showed. That made a
    // slower class fail with nothing wrong — four pull requests on 22 October, one of which had the
    // same commit pass on one runner and fail on another — and it made a *faster* class unable to fail
    // at all, which 8 of the 30 calibration runs were. Both are the same mistake: comparing a measure
    // against a machine it was not taken on.
    let cal = calibration_ms();
    let matched: Vec<&Class> = classes
        .iter()
        .filter(|c| ((cal / c.calibration_ms) - 1.0).abs() * 100.0 <= tolerance)
        .collect();

    // Printed whenever a class cannot be chosen, so the remedy is to paste rather than to derive.
    let block = {
        let mut out = String::from("[class.<a name for this machine>]\n");
        out.push_str(&format!("calibration_ms = {cal:.4}\n"));
        for (name, now) in &measured {
            out.push_str(&format!("{name} = {now:.4}\n"));
        }
        out
    };

    // **An unseen class fails, by design** (owner's ruling, 22 October). A gate that passed on hardware
    // it has no baseline for would be reporting a comparison it did not make — the same defect as an
    // absent baseline, which this file has failed on since it was written. The first run on a class
    // fails once and the block below is committed from its own output, which is how every figure in
    // `BASELINE.toml` got there.
    assert!(
        !matched.is_empty(),
        "band: no runner class in benches/BASELINE.toml matches this machine. The calibration reads \
         {cal:.4} ms and no committed class is within {tolerance}% of it, so there is no baseline this \
         run could be compared against and passing would mean nothing. This is expected the first time \
         a class appears. Commit this block, from this run's own output:\n\n{block}"
    );
    assert!(
        matched.len() == 1,
        "band: {} classes in benches/BASELINE.toml match a calibration of {cal:.4} ms within \
         {tolerance}%, so which baseline applies is ambiguous and the gate would be choosing one \
         arbitrarily. The classes overlap: widen their separation or narrow class_tolerance_percent.",
        matched.len()
    );
    let class = matched[0];
    println!(
        "band: calibration {cal:.4} ms selects [class.{}], whose own is {:.4} ms — within {tolerance}%",
        class.name, class.calibration_ms
    );

    let mut missing: Vec<String> = Vec::new();
    let mut over: Vec<String> = Vec::new();
    for (name, now) in &measured {
        match class.measures.iter().find(|(k, _)| k == name) {
            None => missing.push(format!("{name} = {now:.4}")),
            Some((_, was)) => {
                let limit = was * (1.0 + band / 100.0);
                // **Finite was necessary and not sufficient (PR #59, round four).** `f64::MAX` passes
                // the parse check, `f64::MAX * 1.5` is infinity, and `now > inf` is never true, so a
                // finite baseline could still switch its row off. The number that has to be usable is
                // the one the comparison uses.
                assert!(
                    limit.is_finite(),
                    "benches/BASELINE.toml: [class.{}]'s {name} baseline {was} with a {band}% band \
                     gives a limit of {limit}, which nothing can exceed, so the row would pass \
                     unchecked",
                    class.name
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
        "benches/BASELINE.toml: [class.{}] has no figure for {} measure(s), so there is nothing to \
         compare against and this gate would otherwise pass without checking anything. Measured now, \
         to be committed under that class:\n{}",
        class.name,
        missing.len(),
        missing.join("\n")
    );

    // **The faster-class disclosure is gone, because the reason for it is (H-61, #228).** It said when a
    // run came in below 80% of baseline, because such a run could not have failed whatever the code
    // did — a true sentence about a gate that was not exercised. A class is now compared against its
    // own baseline, so a fast runner fails on a regression like any other, and there is nothing to
    // disclose. That is the half of this change that adds gating rather than removing noise.
    //
    // **What the band still does not cover**, said rather than discovered: a *change* in a class's own
    // speed, from a kernel or microcode update on the same hardware. The calibration moves with it, so
    // the class stops matching and this fails asking for a new block — which is the right failure, and
    // it reads the same as new hardware because from here it is indistinguishable.
    assert!(
        over.is_empty(),
        "band: {} measure(s) above the limit for [class.{}], whose baseline was taken on a machine \
         this run's calibration matches to within {tolerance}%. So this is a regression rather than a \
         slower runner — which is what the calibration is for, and what the figures below could not \
         have told you before it:\n{}",
        over.len(),
        class.name,
        over.join("\n")
    );
    println!(
        "band: every measure is inside its limit for its own runner class, which is asserted and not \
         merely reported"
    );
}
