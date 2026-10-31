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

/// Everything `BASELINE.toml` holds, read from the committed file rather than restated here.
struct Committed {
    /// How far above its class's baseline a measure may drift before failing. 15%.
    band: f64,
    /// How close a calibration must be to a class's for that class to apply.
    tolerance: f64,
    classes: Vec<Class>,
    /// The band on the normalised fallback, which is wider because it covers the whole fleet. 25%.
    fallback_band: f64,
    /// One ratio per measure, fleet-wide: the measure divided by the calibration (D-141).
    fallback: Vec<(String, f64)>,
}

/// Which part of the file the reader is inside.
///
/// **It used to track nothing, and that was a silent mis-attribution waiting to happen.** Any line
/// that was not `[class.…]` and held an `=` was given to the *last class seen*, so a section added
/// below the classes would have had its values recorded as that class's baselines. Nothing would have
/// reported it. An unknown section is now refused rather than absorbed.
enum Section {
    Top,
    Class(usize),
    Fallback,
}

/// `band_percent`, `class_tolerance_percent`, the `[class.<name>]` blocks and `[fallback]`, read from
/// the committed file rather than restated here.
fn committed() -> Committed {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("BASELINE.toml");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let mut band = None;
    let mut tolerance = None;
    let mut fallback_band = None;
    let mut fallback: Vec<(String, f64)> = Vec::new();
    let mut classes: Vec<Class> = Vec::new();
    let mut section = Section::Top;
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
            section = Section::Class(classes.len().saturating_sub(1));
            continue;
        }
        if line == "[fallback]" {
            section = Section::Fallback;
            continue;
        }
        // Any other section is refused rather than absorbed: see `Section`.
        assert!(
            !(line.starts_with('[') && line.ends_with(']')),
            "benches/BASELINE.toml: {line} is a section this file does not define. Its values would \
             otherwise be recorded against whichever class was read last."
        );
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let (key, value) = (key.trim(), value.trim());
        let parsed: f64 = value
            .parse()
            .unwrap_or_else(|_| panic!("{key}: {value} is not a number"));
        match (&section, key) {
            (Section::Top, "band_percent") => band = Some(parsed),
            (Section::Top, "class_tolerance_percent") => tolerance = Some(parsed),
            (Section::Top, "fallback_band_percent") => fallback_band = Some(parsed),
            (Section::Fallback, _) => {
                // The same condition the class baselines are held to, for the same reason: a
                // non-finite ratio makes its limit non-finite and the comparison vacuous.
                assert!(
                    parsed.is_finite() && parsed > 0.0,
                    "benches/BASELINE.toml: [fallback]'s {key} is {value}, which cannot normalise a \
                     measure. A non-finite or zero ratio makes its limit non-finite and the row \
                     would pass without being checked."
                );
                fallback.push((key.to_string(), parsed));
            }
            (Section::Top, _) => {}
            (Section::Class(at), _) => match (classes.get_mut(*at), key) {
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
            },
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
    Committed {
        band: band.expect("band_percent"),
        tolerance: tolerance.expect("class_tolerance_percent"),
        classes,
        fallback_band: fallback_band.expect("fallback_band_percent"),
        fallback,
    }
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

    let Committed {
        band,
        tolerance,
        classes,
        fallback_band,
        fallback,
    } = committed();
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
    // The fallback band is held to the same condition, and additionally below 100: at 100% or more
    // the floor below is at or under zero and the perturbation guard could never fire.
    assert!(
        fallback_band.is_finite() && fallback_band > 0.0 && fallback_band < 100.0,
        "benches/BASELINE.toml: fallback_band_percent is {fallback_band}, which is not a usable \
         percentage. At 100% or more its floor is at or below zero and the perturbation guard on the \
         fallback path could never fire."
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

    // **An unseen class no longer fails outright (H-65, issue #245, D-141).** It did, by the ruling
    // of 22 October, and that was right while a class baseline was the only thing a measure could be
    // compared against. The fleet then showed machines *between* the classes: a reading of 0.8961 sat
    // +2.80% from one committed class and -3.27% from the other, with a ratio to its own chain walk
    // inside the band every unperturbed run occupies — an ordinary machine in a dead zone, reported as
    // a defect in the diff. "Unseen" had stopped meaning "new hardware".
    //
    // Such a run is now compared against a fleet-wide ratio instead, at a wider band, and the first
    // run on a class still establishes one. Two matches remain ambiguous and still fail: the file
    // cannot say which baseline applies, and picking one would be arbitrary.
    assert!(
        matched.len() <= 1,
        "band: {} classes in benches/BASELINE.toml match a calibration of {cal:.4} ms within \
         {tolerance}%, so which baseline applies is ambiguous and the gate would be choosing one \
         arbitrarily. The classes overlap: widen their separation or narrow class_tolerance_percent.",
        matched.len()
    );

    match matched.first() {
        Some(class) => against_its_own_class(class, &measured, band, tolerance),
        None => against_the_fleet(cal, &measured, fallback_band, &fallback, tolerance, &block),
    }
}

/// The matched path: a baseline measured on this machine's own class, at the tighter band.
fn against_its_own_class(class: &Class, measured: &[(&str, f64)], band: f64, tolerance: f64) {
    println!(
        "band: calibration selects [class.{}], whose own is {:.4} ms — within {tolerance}%",
        class.name, class.calibration_ms
    );

    let mut missing: Vec<String> = Vec::new();
    let mut over: Vec<String> = Vec::new();
    for (name, now) in measured {
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
    // the class stops matching and the run leaves this path for the fleet fallback at its wider band
    // (H-65, D-141). It reads the same as new hardware because from here it is indistinguishable, and
    // the remedy is the same: a class block measured on the new reading, not a wider band.
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

/// What the fleet comparison concluded, kept apart from the assertions so it can be tested.
///
/// **A verdict that exists only inside a panic cannot be checked.** The class path has been exercised
/// by every CI run since it was written; this one runs only on a machine no class covers, which is
/// rare by design — so without this split the cases that matter most here would be the ones nothing
/// ever reaches.
#[derive(Debug, Default, PartialEq, Eq)]
struct Verdict {
    missing: Vec<String>,
    over: Vec<String>,
    under: Vec<String>,
}

fn fleet_verdict(
    cal: f64,
    measured: &[(&str, f64)],
    band: f64,
    fallback: &[(String, f64)],
    report: bool,
) -> Verdict {
    let mut out = Verdict::default();
    for (name, now) in measured {
        match fallback.iter().find(|(k, _)| k == name) {
            None => out.missing.push(format!("{name} = {:.6}", now / cal)),
            Some((_, ratio)) => {
                let normalised = now / cal;
                let limit = ratio * (1.0 + band / 100.0);
                let floor = ratio * (1.0 - band / 100.0);
                // The same condition the class path holds its limit to, for the same reason.
                assert!(
                    limit.is_finite() && floor.is_finite(),
                    "benches/BASELINE.toml: [fallback]'s {name} ratio {ratio} with a {band}% band \
                     gives bounds of {floor} to {limit}, which nothing can leave, so the row would \
                     pass unchecked"
                );
                if report {
                    println!(
                        "{name}: {now:.4} ms / {cal:.4} ms = {normalised:.6}, fleet {ratio:.6}, \
                         range {floor:.6} to {limit:.6}"
                    );
                }
                if normalised > limit {
                    out.over.push(format!(
                        "{name}: {normalised:.6} against a fleet ratio of {ratio:.6}, which is more \
                         than {band}% above it"
                    ));
                } else if normalised < floor {
                    out.under.push(format!(
                        "{name}: {normalised:.6} against a fleet ratio of {ratio:.6}, which is more \
                         than {band}% below it"
                    ));
                }
            }
        }
    }
    out
}

/// **The fallback: no class matched, so the machine is compared against the fleet (D-141).**
///
/// Each measure is divided by the calibration. A faster machine lowers both, so the quotient holds;
/// a code regression raises only the measure, so it rises. That is what lets one committed figure
/// serve every machine, including ones no class covers.
///
/// **It is weaker, and the file says by how much.** Normalising removes machine speed but not the
/// relation between Ed25519 and SHA-256, which is a property of each CPU rather than of how fast it
/// is: over the readings taken so far the quotient still spans 18 to 21% across the fleet, where a
/// measure inside its own class varies by a few per cent. So the band here is 25% where a matched
/// class gets 15%, and a regression smaller than 25% escapes on this path. That is the cost of
/// covering a machine nothing was measured on, and it is why this is a fallback and not the rule.
///
/// **And a one-sided band would be a gate that cannot fail here.** The calibration is in the
/// denominator, so a perturbed one — reading high because the runner was busy — makes every quotient
/// *small*, and small passes an upper limit. The run that found this read 1.6240 ms where its own
/// measures said 0.85; its chain walk normalises to 4.89 against a fleet figure of 9.08. So the band
/// is two-sided on this path.
///
/// **What below the floor does not say is why.** A machine whose Ed25519-to-SHA-256 relation is
/// genuinely lower than any the fleet has shown lands there too, and the reference laptop is one:
/// about 7.13 against a fleet low of 9.08, which is 21% under. This comparison cannot separate that
/// from a perturbed calibration, so it claims neither. The verdict is the same either way — nothing
/// is concluded about the code — and that is what the floor is for.
fn against_the_fleet(
    cal: f64,
    measured: &[(&str, f64)],
    band: f64,
    fallback: &[(String, f64)],
    tolerance: f64,
    class_block: &str,
) {
    // Printed when the fleet figures are absent, so the remedy is to paste rather than to derive.
    let block = {
        let mut out = String::from("[fallback]\n");
        for (name, now) in measured {
            // Six places, not four: the smallest measure is about 4 microseconds, so its quotient
            // is near 0.0029 and four places would commit it to two significant figures.
            out.push_str(&format!("{name} = {:.6}\n", now / cal));
        }
        out
    };
    assert!(
        !fallback.is_empty(),
        "band: no runner class matches this machine and benches/BASELINE.toml carries no [fallback] \
         ratios either, so there is nothing to compare against on either path. Commit either block, \
         from this run's own output — the class block if this machine will recur, the fallback block \
         to cover every machine no class holds:\n\n{class_block}\n{block}"
    );

    println!(
        "band: no class is within {tolerance}% of this calibration, so each measure is compared \
         against the fleet ratio at {band}% rather than against a class at a tighter one"
    );

    let Verdict {
        missing,
        over,
        under,
    } = fleet_verdict(cal, measured, band, fallback, true);

    assert!(
        missing.is_empty(),
        "benches/BASELINE.toml: [fallback] has no ratio for {} measure(s), so there is nothing to \
         compare against and this path would pass without checking anything. Measured now, to be \
         committed under [fallback]:\n{}",
        missing.len(),
        missing.join("\n")
    );

    // **Below the floor means nothing can be concluded, and the message does not guess why.** Two
    // causes produce it and this comparison cannot tell them apart: a calibration perturbed upward,
    // which makes every quotient small and would otherwise clear an upper limit; and a machine whose
    // Ed25519-to-SHA-256 relation is genuinely lower than anything the fleet has shown. The reference
    // laptop is the second — it reads about 7.13 where the fleet's lowest is 9.08 — so naming only the
    // first would be wrong on the machine a developer most often runs this on.
    //
    // The remedy differs but the verdict does not: on either cause this run says nothing about the
    // code, which is the whole reason the band is two-sided here.
    assert!(
        under.is_empty(),
        "band: {} measure(s) below the fleet range. Either this calibration did not describe the \
         machine — it reads high when the runner is busy, and a high denominator makes every quotient \
         small — or this machine's Ed25519-to-SHA-256 relation is lower than any the fleet has shown, \
         which the reference laptop's is. This comparison cannot tell those apart, and on either \
         nothing is concluded about the code:\n{}",
        under.len(),
        under.join("\n")
    );

    assert!(
        over.is_empty(),
        "band: {} measure(s) above the fleet range at {band}%. No class matched this calibration, so \
         this is the fleet-wide comparison and not a class one — which is the weaker of the two, and \
         a figure that leaves it has left a range covering every machine seen:\n{}",
        over.len(),
        over.join("\n")
    );
    println!(
        "band: every measure is inside the fleet range, which is asserted and not merely reported. \
         This is the {band}% path; a matched class would have been held to a tighter one."
    );
}

// ----------------------------------------------- H-65 (issue #245, D-141): the fallback path

/// The committed fleet ratios, as `BASELINE.toml` holds them.
#[cfg(test)]
fn fleet() -> Vec<(String, f64)> {
    vec![
        ("chain_walk_hash_chain_only".to_string(), 9.078814),
        ("epoch_root_256_leaves".to_string(), 0.250205),
        ("inclusion_proof_verify".to_string(), 0.002913),
    ]
}

/// Every reading taken under the minimum instrument: calibration, then the three measures.
#[cfg(test)]
const FLEET_READINGS: [(f64, f64, f64, f64); 7] = [
    (0.8541, 7.7545, 0.2137, 0.0025),
    (1.0523, 11.3053, 0.3182, 0.0037),
    (1.2781, 12.7398, 0.3634, 0.0041),
    (1.3386, 12.1529, 0.3457, 0.0039),
    (1.2844, 12.7411, 0.3584, 0.0041),
    (1.2807, 12.7197, 0.3640, 0.0041),
    (1.2772, 12.7633, 0.3596, 0.0041),
];

#[cfg(test)]
fn reading(r: (f64, f64, f64, f64)) -> (f64, Vec<(&'static str, f64)>) {
    (
        r.0,
        vec![
            ("chain_walk_hash_chain_only", r.1),
            ("epoch_root_256_leaves", r.2),
            ("inclusion_proof_verify", r.3),
        ],
    )
}

/// **The committed ratios have to cover every machine seen, or the fallback fails unchanged code.**
/// This is the condition the figures were chosen for, asserted over them rather than assumed.
#[test]
fn every_reading_the_fleet_has_shown_is_inside_the_fallback_range() {
    for r in FLEET_READINGS {
        let (cal, measured) = reading(r);
        let v = fleet_verdict(cal, &measured, 25.0, &fleet(), false);
        assert!(
            v.over.is_empty() && v.under.is_empty() && v.missing.is_empty(),
            "calibration {cal}: {v:?}"
        );
    }
}

/// And the band is not idly wide: at 15%, the band a matched class gets, it would not cover them.
/// That is the cost D-141 records, demonstrated rather than asserted.
#[test]
fn fifteen_percent_would_not_cover_the_fleet_which_is_why_the_fallback_is_wider() {
    let failing = FLEET_READINGS
        .into_iter()
        .filter(|r| {
            let (cal, measured) = reading(*r);
            !fleet_verdict(cal, &measured, 15.0, &fleet(), false)
                .over
                .is_empty()
        })
        .count();
    assert!(
        failing > 0,
        "if 15% covered every reading, the 25% band would be unexplained"
    );
}

/// A regression raises the measure and not the calibration, so the quotient rises past the limit.
#[test]
fn a_measure_above_the_fleet_range_is_reported() {
    let (cal, mut measured) = reading(FLEET_READINGS[0]);
    if let Some(row) = measured.first_mut() {
        row.1 *= 1.30;
    }
    let v = fleet_verdict(cal, &measured, 25.0, &fleet(), false);
    assert_eq!(v.over.len(), 1, "{v:?}");
    assert!(v.over[0].contains("chain_walk_hash_chain_only"));
    assert!(v.under.is_empty(), "a regression is not a perturbation");
}

/// **The case a one-sided band would have passed, which is why this one is two-sided.** A calibration
/// perturbed upward makes every quotient small, and small clears an upper limit. These are the real
/// figures from the run that found it: 1.6240 ms where that machine's own measures said about 0.85.
#[test]
fn a_perturbed_calibration_reads_below_the_floor_rather_than_passing() {
    let measured = vec![
        ("chain_walk_hash_chain_only", 7.9433),
        ("epoch_root_256_leaves", 0.2211),
        ("inclusion_proof_verify", 0.0025),
    ];
    let v = fleet_verdict(1.6240, &measured, 25.0, &fleet(), false);
    assert!(
        v.over.is_empty(),
        "an upper limit alone would have called this a pass: {v:?}"
    );
    assert_eq!(v.under.len(), 3, "every measure is below the floor: {v:?}");
}

/// A ratio the file does not carry is reported, never skipped: skipping would pass the row unchecked.
#[test]
fn a_measure_with_no_fleet_ratio_is_reported() {
    let (cal, measured) = reading(FLEET_READINGS[0]);
    let partial: Vec<(String, f64)> = fleet().into_iter().take(1).collect();
    let v = fleet_verdict(cal, &measured, 25.0, &partial, false);
    assert_eq!(v.missing.len(), 2, "{v:?}");
}

/// **The fleet figures are the lowest quotient seen, and that is what makes the limit as tight as
/// the band allows.** Committing a higher one would raise every limit and weaken the gate.
#[test]
fn the_committed_ratio_is_the_lowest_the_fleet_has_shown() {
    for (index, (name, committed)) in fleet().iter().enumerate() {
        let lowest = FLEET_READINGS
            .into_iter()
            .map(|r| reading(r).1[index].1 / r.0)
            .fold(f64::INFINITY, f64::min);
        assert!(
            (committed - lowest).abs() < 1e-6,
            "{name}: committed {committed}, lowest seen {lowest}"
        );
    }
}

/// **A machine below the fleet's ratio range is not a perturbed calibration, and the two are not
/// distinguished.** The reference laptop reads about 7.13 where the fleet's lowest is 9.08. The
/// verdict is the same — nothing is concluded — but the message claims neither cause, because this
/// comparison cannot tell them apart.
#[test]
fn a_machine_below_the_fleets_ratio_range_reads_the_same_as_a_perturbation() {
    // The reference laptop, measured on 23 October 2026.
    let measured = vec![
        ("chain_walk_hash_chain_only", 6.8543),
        ("epoch_root_256_leaves", 0.1831),
        ("inclusion_proof_verify", 0.0021),
    ];
    let v = fleet_verdict(0.9615, &measured, 25.0, &fleet(), false);
    assert!(v.over.is_empty(), "nothing is above the range: {v:?}");
    assert!(
        !v.under.is_empty(),
        "a machine outside the fleet's relation lands below the floor: {v:?}"
    );
}
