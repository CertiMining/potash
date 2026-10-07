// SPDX-License-Identifier: MIT OR Apache-2.0
//! **§4.4's privacy acceptance tests. V-Z-02, V-Z-03 and V-Z-04 are release blockers.**
//!
//! These were written before the tree they measure (D-65), and their pass conditions were fixed
//! before any of the implementation's numbers were visible (D-66). Every input is deterministic, so
//! a failure here is a finding rather than an unlucky draw, and nothing in this file can flake.
//!
//! The real Keccak-256 is the only honest primitive for these, so the file needs the `native`
//! feature. Under `--no-default-features` the epoch tree still has its structural tests; it has no
//! privacy claim without them.
#![cfg(feature = "native")]

mod common;

use certimining_core::{epoch_key, padding_prf, Digest, Hasher, NativeKeccak, SubmissionId};
use certimining_log::{BuiltEpoch, EpochTree};
use common::{
    assert_indistinguishable, assignment_oracle, binomial_band, combined_scores, epoch,
    feature_deviations, feature_matrix, leaf_digest, padding_slots, pearson, real_slots,
    scattered_id, sequential_id, SplitMix, FEATURE_COUNT, FEATURE_NAMES, TEST_MASTER_KEY,
};

/// The deployment's height (D-02).
const HEIGHT: u8 = 8;
/// D-66's CI sample for V-Z-02: 200 balanced epochs, which is 25,600 pair trials.
const EPOCHS_VZ02: u64 = 200;
/// D-66's CI sample for V-Z-03.
const EPOCHS_VZ03: u64 = 50;
/// D-66's CI sample for V-Z-04: 400 epochs of 64 submissions, which is 25,600 placements.
const EPOCHS_VZ04: u64 = 400;
/// §4.4's full sample, run before submission rather than in CI (D-66).
const EPOCHS_VZ04_FULL: u64 = 10_000;
const REAL_PER_EPOCH: usize = 64;
/// D-66's bound at CI's sample size, and over the full run.
const CORRELATION_BOUND_CI: f64 = 0.05;
const CORRELATION_BOUND_FULL: f64 = 0.02;

// **§4.4 and D-66 own these, so they are checked rather than trusted (PR #69, round three).** A
// changed height, bound or per-epoch count leaves every test green while measuring something the
// specification did not ask for. V-Z-02's epoch count is asserted inside the test that uses it.
const _: () = assert!(HEIGHT == 8, "D-02's deployed height");
const _: () = assert!(
    REAL_PER_EPOCH == 64,
    "D-66's submissions per epoch for V-Z-04"
);
const _: () = assert!(EPOCHS_VZ03 == 50, "D-66's CI sample for V-Z-03");
const _: () = assert!(EPOCHS_VZ04 == 400, "D-66's CI sample for V-Z-04");
const _: () = assert!(EPOCHS_VZ04_FULL == 10_000, "§4.4's full sample for V-Z-04");
const _: () = assert!(
    CORRELATION_BOUND_CI == 0.05,
    "D-66's bound at CI's sample size"
);
const _: () = assert!(
    CORRELATION_BOUND_FULL == 0.02,
    "D-66's bound over the full run"
);

/// One pair trial: the classifier names which of the two leaves is real, and ties alternate so a tie
/// cannot bias the count in either direction.
fn picked_real(real_score: f64, padding_score: f64, tie_break: bool) -> bool {
    if real_score == padding_score {
        tie_break
    } else {
        real_score > padding_score
    }
}

/// **Which slots are real, decided from the leaves rather than from the assignment (PR #69, round
/// five, H-02).** V-Z-02 and V-Z-03 took both their trial vectors and their validation oracle from
/// `real_slots`, so a review corrupted that one helper to call the first half of every epoch real and
/// both blockers stayed green: the stream and its check agreed because they were the same statement.
///
/// This asks a different question of a different object. A slot holds padding exactly when its leaf is
/// the value `padding_prf` derives for that slot under the epoch key, which the test holds and the
/// classifier does not. It never consults `built.assignment`, so corrupting the assignment path cannot
/// move it.
fn real_by_recomputation(built: &BuiltEpoch, epoch_number: u64) -> Vec<bool> {
    // **An oracle that calls the production path degrades with it (PR #69, round six, M-01).** This
    // used `epoch_key`, `padding_prf` and `PaddingPreimage::digest` — the same functions the engine
    // uses — so a review changed padding's domain code from `0x03` to `0x02` and engine and oracle
    // produced the same wrong value together. The privacy suite stayed green. (`certimining-core`'s
    // own PRF vector caught that mutation, which is why it was graded Medium and not High, but an
    // oracle whose independence is supplied by a different test is not independent.)
    //
    // So the derivation is transcribed here from §1.2 and §1.4, as `assignment_oracle` already does:
    // the tags and use codes are literals, not imports.
    const SPEC_TAG_PRF: [u8; 8] = *b"CMv1PRF0";
    const SPEC_TAG_PAD: [u8; 8] = *b"CMv1PADD";
    const SPEC_USE_EPOCH_KEY: u8 = 0x01;
    const SPEC_USE_PADDING: u8 = 0x03;

    // `PRF(k, x) = Keccak256(TAG_PRF ‖ k ‖ len(x) ‖ x)`, the length a little-endian `u16` (§1.1, D-59).
    let prf = |key: &Digest, input: &[u8]| -> Digest {
        let mut preimage = Vec::new();
        preimage.extend_from_slice(&SPEC_TAG_PRF);
        preimage.extend_from_slice(key);
        preimage.extend_from_slice(&(input.len() as u16).to_le_bytes());
        preimage.extend_from_slice(input);
        NativeKeccak::hashv(&[&preimage])
    };

    let mut epoch_input = vec![SPEC_USE_EPOCH_KEY];
    epoch_input.extend_from_slice(&epoch_number.to_le_bytes());
    let k_e = prf(&TEST_MASTER_KEY, &epoch_input);

    built
        .leaves
        .iter()
        .enumerate()
        .map(|(slot, leaf)| {
            let mut padding_input = vec![SPEC_USE_PADDING];
            padding_input.extend_from_slice(&(slot as u16).to_le_bytes());
            let prf_output = prf(&k_e, &padding_input);
            // The padding leaf is the digest of that output under its own tag (§1.4).
            let mut padding_preimage = Vec::new();
            padding_preimage.extend_from_slice(&SPEC_TAG_PAD);
            padding_preimage.extend_from_slice(&prf_output);
            *leaf != NativeKeccak::hashv(&[&padding_preimage])
        })
        .collect()
}

/// **Conformance is equality with an independent answer, not movement (PR #69, round five, H-01).**
/// Round four asserted that each column changed when the property it names changed, with leaf byte 0
/// held fixed so a byte-0 alias would fail. A review then made column 0 an exact copy of column 1 —
/// population count — and all nine cases passed, because the contrast chosen for column 0 (a tail of
/// `0x00` against `0xff`) moves population count too. "It moved" is satisfied by any column that
/// happens to correlate; only the right number is satisfied by the right implementation.
///
/// So every feature is recomputed here, independently of the extractor and of its helpers — different
/// loops, different primitives, `count_ones` nowhere — and the column must equal it. A duplicated or
/// permuted implementation now produces the wrong number for at least one of the fixtures and fails.
#[cfg_attr(
    miri,
    ignore = "nine recomputations over a small matrix, not a Miri question"
)]
#[test]
fn each_named_feature_equals_an_independently_computed_value() {
    // A set with enough shape that no two features agree across it by accident.
    let leaves: Vec<Digest> = vec![
        [0x00; 32],
        [0xff; 32],
        {
            let mut d = [0u8; 32];
            for (i, b) in d.iter_mut().enumerate() {
                *b = i as u8;
            }
            d
        },
        {
            let mut d = [0xaa; 32];
            d[0] = 0x00;
            d[31] = 0x01;
            d
        },
        {
            let mut d = [0u8; 32];
            for (i, b) in d.iter_mut().enumerate() {
                *b = if i.is_multiple_of(2) { 0x0f } else { 0xf0 };
            }
            d
        },
    ];
    let root: Digest = [0x5c; 32];

    // **The blockers score 128- and 256-row matrices and this checked five (PR #69, round six, H-01).**
    // A review gave the first column a shape-dependent path — slot parity when the row count is a power
    // of two, the real feature otherwise — and the five-row fixture still saw the right implementation
    // while V-Z-02 and V-Z-03 got unrelated noise. The noise varied in every epoch, so the liveness
    // floor cleared, and its success rate sat at chance, which is the passing value. Conformance has to
    // run at the shapes the statistic consumes, so this now checks all three.
    check_conformance(&leaves, &root);
    check_conformance(&deployment_shaped(256), &root);
    check_conformance(&deployment_shaped(128), &root);
    println!("conformance: all {FEATURE_COUNT} columns equal an independent computation at 5, 128 and 256 rows");
}

/// Leaves with enough structure that every named feature varies, at whatever row count the caller
/// needs — so conformance can be checked at the shapes V-Z-02 and V-Z-03 actually score.
fn deployment_shaped(rows: usize) -> Vec<Digest> {
    (0..rows)
        .map(|i| {
            let mut d = [0u8; 32];
            for (j, b) in d.iter_mut().enumerate() {
                *b = ((i * 31 + j * 7) % 256) as u8;
            }
            // A few rows carry runs and zeros, so the run and zero-byte columns are not constant.
            if i % 7 == 0 {
                d[4..12].fill(0x00);
            }
            if i % 11 == 0 {
                d[16..24].fill(0xcc);
            }
            d
        })
        .collect()
}

fn check_conformance(leaves: &[Digest], root: &Digest) {
    fn bits(mut b: u8) -> u32 {
        let mut n = 0;
        while b != 0 {
            n += u32::from(b & 1);
            b >>= 1;
        }
        n
    }
    fn bits_of(d: &Digest) -> u32 {
        d.iter().map(|b| bits(*b)).sum()
    }
    fn differing_bits(a: &Digest, b: &Digest) -> u32 {
        (0..32).map(|i| bits(a[i] ^ b[i])).sum()
    }
    fn leading_zeros_independently(d: &Digest) -> u32 {
        let mut n = 0;
        for byte in d {
            for shift in (0..8).rev() {
                if (byte >> shift) & 1 == 1 {
                    return n;
                }
                n += 1;
            }
        }
        n
    }
    fn longest_run_independently(d: &Digest) -> usize {
        let (mut best, mut run) = (1usize, 1usize);
        for i in 1..d.len() {
            run = if d[i] == d[i - 1] { run + 1 } else { 1 };
            if run > best {
                best = run;
            }
        }
        best
    }
    fn distinct_independently(d: &Digest) -> usize {
        let mut values: Vec<u8> = d.to_vec();
        values.sort_unstable();
        values.dedup();
        values.len()
    }
    fn chi_squared_independently(d: &Digest) -> f64 {
        let mut counts = [0usize; 16];
        for byte in d {
            counts[usize::from(*byte) / 16] += 1;
            counts[usize::from(*byte) % 16] += 1;
        }
        let expected = 4.0_f64;
        counts
            .iter()
            .map(|c| {
                let diff = *c as f64 - expected;
                diff * diff / expected
            })
            .sum()
    }

    let n = leaves.len();
    let mut mean = [0f64; 32];
    for position in 0..32 {
        mean[position] = leaves.iter().map(|l| f64::from(l[position])).sum::<f64>() / n as f64;
    }

    let matrix = feature_matrix(leaves, root);
    assert_eq!(matrix.len(), n, "one row per leaf");

    for (index, leaf) in leaves.iter().enumerate() {
        let previous = leaves[(index + n - 1) % n];
        let next = leaves[(index + 1) % n];
        let expected: [f64; FEATURE_COUNT] = [
            (0..32).map(|p| (f64::from(leaf[p]) - mean[p]).abs()).sum(),
            f64::from(bits_of(leaf)),
            leaf.iter().filter(|b| **b == 0).count() as f64,
            f64::from(leading_zeros_independently(leaf)),
            longest_run_independently(leaf) as f64,
            distinct_independently(leaf) as f64,
            chi_squared_independently(leaf),
            f64::from(differing_bits(leaf, &previous) + differing_bits(leaf, &next)),
            f64::from(differing_bits(leaf, root)),
        ];
        for feature in 0..FEATURE_COUNT {
            assert!(
                (matrix[index][feature] - expected[feature]).abs() < 1e-9,
                "{}: row {index} is {} and an independent computation says {}. The column does not \
                 implement the feature it is named after.",
                FEATURE_NAMES[feature],
                matrix[index][feature],
                expected[feature]
            );
        }
    }

    // And the fixtures must actually separate the features, or equality above would be satisfied by a
    // battery of duplicates that happened to agree. Every pair of columns must differ somewhere.
    for a in 0..FEATURE_COUNT {
        for b in (a + 1)..FEATURE_COUNT {
            assert!(
                (0..n).any(|r| (matrix[r][a] - matrix[r][b]).abs() > 1e-9),
                "{} and {} agree on every fixture, so these fixtures cannot tell a duplicated \
                 implementation from a correct one",
                FEATURE_NAMES[a],
                FEATURE_NAMES[b]
            );
        }
    }
    println!("conformance: all {FEATURE_COUNT} columns equal an independent computation, and no two agree across the fixtures");
}

/// **The control V-Z-04's instrument never had.** V-Z-02 and V-Z-03 are guarded by
/// `the_classifier_detects_a_leak_it_is_given`, which proves their classifier reacts to a planted
/// difference. The correlation V-Z-04 reports had no equivalent: `pearson` hardcoded to `return 0.0` —
/// the best possible answer for §4.4's bound — leaves every privacy test green, V-Z-04 included.
///
/// Round one of this unit fixed `pearson` returning `0.0` on a *degenerate* sample. Nothing then
/// established that it returns the right number on a good one, which is the same omission one level
/// along: an instrument whose failure is indistinguishable from the result the predicate rewards.
///
/// The expected values are computed by hand and written as literals, so the control cannot be
/// satisfied by the implementation it is checking.
#[test]
fn the_correlation_instrument_reports_a_correlation_that_exists() {
    // r = +1: y is a positive affine function of x.
    let x = [1.0, 2.0, 3.0, 4.0, 5.0];
    let up = [2.0, 4.0, 6.0, 8.0, 10.0];
    assert!(
        (pearson(&up, &x, "a perfectly correlated feature") - 1.0).abs() < 1e-12,
        "a perfectly correlated pair must report +1 and reported {}",
        pearson(&up, &x, "a perfectly correlated feature")
    );

    // r = -1: the same, reversed.
    let down = [10.0, 8.0, 6.0, 4.0, 2.0];
    assert!(
        (pearson(&down, &x, "a perfectly anti-correlated feature") + 1.0).abs() < 1e-12,
        "a perfectly anti-correlated pair must report -1 and reported {}",
        pearson(&down, &x, "a perfectly anti-correlated feature")
    );

    // r = 0.5, by hand: x = [1,2,3] and y = [1,3,2] give means of 2, deviations [-1,0,1] and [-1,1,0],
    // a covariance of 1 and variances of 2 and 2, so r = 1 / sqrt(2 * 2) = 0.5 exactly.
    let a = [1.0, 2.0, 3.0];
    let b = [1.0, 3.0, 2.0];
    assert!(
        (pearson(&b, &a, "a partially correlated feature") - 0.5).abs() < 1e-12,
        "a pair whose correlation is 0.5 by hand reported {}",
        pearson(&b, &a, "a partially correlated feature")
    );

    // And the bound V-Z-04 asserts must actually reject each of those, or the bound is decorative.
    for (label, r) in [
        ("+1", pearson(&up, &x, "f")),
        ("-1", pearson(&down, &x, "f")),
        ("0.5", pearson(&b, &a, "f")),
    ] {
        assert!(
            r.abs() >= CORRELATION_BOUND_CI,
            "a correlation of {label} must exceed V-Z-04's bound of {CORRELATION_BOUND_CI}"
        );
    }
    println!("correlation control: +1, -1 and 0.5 reported exactly, and each exceeds the bound");
}

/// **The control for V-Z-02 and V-Z-03: the classifier must catch a leak it is given (PR #69, round
/// two, High).** Those two tests pass when the classifier is right half the time, which is also what a
/// dead classifier produces — a review returned zero for every feature of every row and both stayed
/// green, because tied scores alternate and alternation is exactly 50%. `combined_scores` now refuses an
/// all-constant matrix, but refusing the obvious corpse is not the same as showing a pulse.
///
/// So this feeds the same pipeline a set it *should* separate: padding leaves left alone, real leaves
/// with their first byte pushed hard the other way. The combined score is unsigned — it says the two
/// sets differ, not which is which — so a working classifier lands far from chance in **either**
/// direction, and that is what this asserts. The first version of this control demanded that the real
/// leaf win, and failed at 0.3484 while the classifier was working perfectly: the features ranked the
/// altered set lower, which is detection, not blindness.
///
/// A dead classifier therefore fails here while passing V-Z-02 and V-Z-03, which is the point: those
/// two cannot distinguish "indistinguishable" from "not measured", and this one can.
#[test]
#[cfg_attr(
    miri,
    ignore = "statistical, and the sample is what makes it mean anything"
)]
fn the_classifier_detects_a_leak_it_is_given() {
    let mut separated = 0usize;
    let mut trials = 0usize;
    let mut mix = SplitMix(0x5eed_0005);

    for number in 0..50u64 {
        let capacity = 1usize << HEIGHT;
        let built = epoch::<NativeKeccak>(number, HEIGHT, capacity / 2);
        let reals = real_slots(&built);
        let paddings = padding_slots(&built);

        // The leak: every real leaf carries a high first byte, every padding leaf a low one. Nothing
        // about the real construction is used, so this measures the classifier and not the engine.
        let mut leaves = built.leaves.clone();
        for slot in &reals {
            leaves[usize::from(*slot)][0] = 0xf0 | (leaves[usize::from(*slot)][0] & 0x0f);
        }
        for slot in &paddings {
            leaves[usize::from(*slot)][0] &= 0x0f;
        }

        let matrix = feature_matrix(&leaves, &built.root);
        let combined = combined_scores(&matrix);
        for (real, padding) in reals.iter().zip(&paddings) {
            if picked_real(
                combined[usize::from(*real)],
                combined[usize::from(*padding)],
                mix.next_u64().is_multiple_of(2),
            ) {
                separated += 1;
            }
            trials += 1;
        }
    }

    let rate = separated as f64 / trials as f64;
    let (low, high) = binomial_band(trials);
    assert!(
        (separated as f64) < low || (separated as f64) > high,
        "the classifier put the leaked set on top {separated} of {trials} times ({rate:.4}), inside the \
         chance band [{low:.1}, {high:.1}] it must leave. A classifier that cannot see a planted \
         difference cannot testify that there is none, so V-Z-02 and V-Z-03 would be reporting nothing."
    );
    println!(
        "classifier control: {separated} of {trials} ({rate:.4}), outside the chance band \
         [{low:.1}, {high:.1}] — the planted difference is visible to it"
    );
}

#[test]
#[cfg_attr(
    miri,
    ignore = "200 epochs of real Keccak-256; Miri covers the same code paths in tree.rs"
)]
fn v_z_02_padding_is_indistinguishable_from_a_real_leaf() {
    // One statistic per feature, and one for the combination (D-66).
    let mut pair_successes = [0usize; FEATURE_COUNT + 1];
    let mut pair_trials = 0usize;
    // The second form: a balanced epoch classified leaf by leaf, where accuracy means something.
    let mut leaf_correct = 0usize;
    let mut leaf_total = 0usize;
    let mut mix = SplitMix(0x5eed_0002);
    let mut live_epochs = [0usize; FEATURE_COUNT];
    let mut epochs_sampled = 0usize;

    // D-66 fixes this sample and the band below is computed from it, so the constant is checked rather
    // than trusted: a reduced sample would widen nothing and simply test less (PR #69, round two).
    assert_eq!(
        EPOCHS_VZ02, 200,
        "D-66 fixes V-Z-02's CI sample at 200 balanced epochs"
    );

    for number in 0..EPOCHS_VZ02 {
        let capacity = 1usize << HEIGHT;
        let built = epoch::<NativeKeccak>(number, HEIGHT, capacity / 2);
        // The classifier is given the root and the leaves in slot order, and no key.
        let matrix = feature_matrix(&built.leaves, &built.root);
        epochs_sampled += 1;
        for (seen, deviation) in live_epochs.iter_mut().zip(feature_deviations(&matrix)) {
            if deviation > 0.0 {
                *seen += 1;
            }
        }
        let combined = combined_scores(&matrix);

        let mut reals = real_slots(&built);
        let mut paddings = padding_slots(&built);
        assert_eq!(reals.len(), paddings.len(), "a balanced epoch");
        mix.shuffle(&mut reals);
        mix.shuffle(&mut paddings);

        // **A pair that is not one real and one padding is not a trial (PR #69, round four, H-02).**
        // The oracle is the built epoch itself, read again rather than taken from the shuffled vectors
        // the loop consumes, so a pairing layer that supplied the real side twice is caught here and
        // not converted into the ideal result by the tie-break.
        // Independent of `real_slots`, which supplies the vectors this loop consumes (round five, H-02).
        let is_real = real_by_recomputation(&built, number);
        assert_eq!(
            is_real.iter().filter(|r| **r).count(),
            reals.len(),
            "epoch {number}: the leaves say {} slots are real and the assignment says {}",
            is_real.iter().filter(|r| **r).count(),
            reals.len()
        );
        for (real, padding) in reals.iter().zip(&paddings) {
            assert!(
                is_real[usize::from(*real)],
                "epoch {number}: slot {real} was offered as the real side and its leaf is the padding \
                 the epoch key derives for that slot"
            );
            assert!(
                !is_real[usize::from(*padding)],
                "epoch {number}: slot {padding} was offered as the padding side and its leaf is not \
                 the padding the epoch key derives for it"
            );
            assert_ne!(
                real, padding,
                "epoch {number}: a slot was compared with itself, which ties by construction"
            );
            pair_trials += 1;
            let tie_break = pair_trials.is_multiple_of(2);
            let real_row = matrix[usize::from(*real)];
            let padding_row = matrix[usize::from(*padding)];
            for feature in 0..FEATURE_COUNT {
                if picked_real(real_row[feature], padding_row[feature], tie_break) {
                    pair_successes[feature] += 1;
                }
            }
            if picked_real(
                combined[usize::from(*real)],
                combined[usize::from(*padding)],
                tie_break,
            ) {
                pair_successes[FEATURE_COUNT] += 1;
            }
        }

        // Rank every slot by the combined score and call the better half real. The number correct is
        // hypergeometric rather than binomial under the null, so the binomial band is the
        // conservative one to hold it to.
        let mut ranked: Vec<(usize, f64)> = combined.iter().copied().enumerate().collect();
        ranked.sort_by(|a, b| b.1.total_cmp(&a.1));
        // **The second form was still labelled from the assignment (PR #69, round six, H-03).** The pair
        // game above was wired to `real_by_recomputation` and this one was not: it rebuilt its truth
        // through `real_slots`, so a review labelled the first half of every epoch real and the test
        // passed — unrelated labels produce chance accuracy, and chance is what this asserts. D-66
        // requires both forms, and one correct form does not make the other's result evidence.
        let real_count = is_real.iter().filter(|r| **r).count();
        for (rank, (slot, _)) in ranked.iter().enumerate() {
            let called_real = rank < real_count;
            let is_real_slot = is_real[*slot];
            if called_real == is_real_slot {
                leaf_correct += 1;
            }
            leaf_total += 1;
        }
    }

    // **Liveness over the whole sample, which is the scope the claim is at (PR #69, round four).** A
    // feature may be constant in one epoch and still be a working instrument; one that never varies in
    // any of them measured nothing, and summing it reported the absence of an instrument as the absence
    // of a signal. Conformance — that each column is the feature its name says — is a different
    // question, and `each_named_feature_responds_to_its_own_property` answers it.
    // **"Varied somewhere" is not support (PR #69, round five, H-03).** Round four accumulated a
    // boolean per feature across the sample. A review then made one feature compute its real value for
    // a single epoch and return 0.0 for the other 199, and the boolean was still true: a feature
    // contributing nothing to 99.5% of the trials satisfied the check, which reopens round two's
    // neutral-value hole for almost the whole run.
    //
    // The sample has to support the claim, so the count is kept and a floor applied. Measured on the
    // committed fixtures, every one of the nine varies in **every** epoch — 200 of 200 here and 50 of
    // 50 in V-Z-03. The floor is nine tenths rather than all of them, because round four's L-02 showed
    // a legitimate epoch can hold a genuinely constant column and must not abort the run; the gap
    // between the measured 100% and the required 90% is exactly that allowance, and it is wide.
    let floor = (epochs_sampled * 9) / 10;
    let thin: Vec<String> = FEATURE_NAMES
        .iter()
        .zip(&live_epochs)
        .filter(|(_, live)| **live < floor)
        .map(|(name, live)| format!("{name} ({live} of {epochs_sampled})"))
        .collect();
    assert!(
        thin.is_empty(),
        "{} of {FEATURE_COUNT} features varied in fewer than {floor} of {epochs_sampled} epochs, so \
         they do not support a statistic computed over all of them: {}",
        thin.len(),
        thin.join(", ")
    );

    // **Pinning the epoch count does not pin what each epoch contributes (PR #69, round four, L-01).**
    // D-66's sample is 200 balanced epochs of 128 pairs. A review truncated each epoch to one pair,
    // leaving 200 trials instead of 25,600 — a 128-fold reduction — with every compile-time assertion
    // intact. The band is computed from whatever count arrives, so a smaller sample simply widens it.
    assert_eq!(
        pair_trials, 25_600,
        "D-66's V-Z-02 sample is 200 balanced epochs of 128 pairs"
    );
    assert_eq!(
        leaf_total,
        200 * 256,
        "the leaf-by-leaf form sees every slot of every epoch"
    );

    for (index, successes) in pair_successes.iter().enumerate() {
        let label = if index == FEATURE_COUNT {
            "combined score"
        } else {
            FEATURE_NAMES[index]
        };
        assert_indistinguishable(label, *successes, pair_trials);
    }
    assert_indistinguishable("balanced epoch, leaf by leaf", leaf_correct, leaf_total);
}

#[test]
#[cfg_attr(
    miri,
    ignore = "50 epochs of real Keccak-256; Miri covers the same code paths in proof.rs"
)]
fn v_z_03_a_proof_leaks_nothing_about_a_sibling() {
    let capacity = 1usize << HEIGHT;
    let mut pair_successes = [0usize; FEATURE_COUNT + 1];
    let mut pair_trials = 0usize;
    let mut mix = SplitMix(0x5eed_0003);
    let mut live_epochs = [0usize; FEATURE_COUNT];
    let mut epochs_sampled = 0usize;

    for number in 0..EPOCHS_VZ03 {
        let real: Vec<(SubmissionId, Digest)> = (0..(capacity / 2) as u64)
            .map(|n| {
                let counter = number.wrapping_mul(9_973).wrapping_add(n);
                (sequential_id(counter), leaf_digest(counter))
            })
            .collect();
        let built = BuiltEpoch::build::<NativeKeccak>(number, HEIGHT, &TEST_MASTER_KEY, &real)
            .expect("builds");
        let k_e = epoch_key::<NativeKeccak>(&TEST_MASTER_KEY, number).expect("derives");
        let reals = real_slots(&built);
        let real_from_leaves = real_by_recomputation(&built, number);
        assert_eq!(
            real_from_leaves.iter().filter(|r| **r).count(),
            reals.len(),
            "epoch {number}: the leaves say {} slots are real and the assignment says {}",
            real_from_leaves.iter().filter(|r| **r).count(),
            reals.len()
        );

        // Nothing a proof carries may be a preimage. Every chain leaf of this epoch and every PRF
        // output behind its padding is collected, and no sibling may be any of them: a sibling that
        // was one would expose the content behind the digest rather than the digest alone.
        let mut preimages: Vec<Digest> = (0..capacity as u16)
            .map(|slot| padding_prf::<NativeKeccak>(&k_e, slot).expect("derives"))
            .collect();
        preimages.extend(real.iter().map(|(_, leaf)| *leaf));
        preimages.sort_unstable();

        // What a counterparty holding every proof of this epoch sees at the bottom level.
        let mut siblings: Vec<Digest> = Vec::new();
        let mut sibling_is_real: Vec<bool> = Vec::new();
        for (id, slot) in &built.assignment {
            let proof = built.proof(id).expect("the epoch holds it");
            for sibling in proof.siblings.iter() {
                assert!(
                    preimages.binary_search(sibling).is_err(),
                    "V-Z-03: a sibling is a preimage, so a sibling's content is recoverable"
                );
            }
            siblings.push(
                *proof
                    .siblings
                    .first()
                    .expect("a proof carries at least four siblings"),
            );
            // From the leaves, not from `reals`, which is the vector this loop's partners come from
            // (round five, H-02).
            sibling_is_real.push(real_from_leaves[usize::from(*slot ^ 1)]);
        }

        let matrix = feature_matrix(&siblings, &built.root);
        epochs_sampled += 1;
        for (seen, deviation) in live_epochs.iter_mut().zip(feature_deviations(&matrix)) {
            if deviation > 0.0 {
                *seen += 1;
            }
        }
        let combined = combined_scores(&matrix);
        let mut real_rows: Vec<usize> = (0..siblings.len())
            .filter(|index| sibling_is_real[*index])
            .collect();
        let mut padding_rows: Vec<usize> = (0..siblings.len())
            .filter(|index| !sibling_is_real[*index])
            .collect();
        mix.shuffle(&mut real_rows);
        mix.shuffle(&mut padding_rows);

        // The same boundary check as V-Z-02 (PR #69, round four, H-02): the oracle is
        // `sibling_is_real`, which is derived from the epoch's own assignment, not from the shuffled
        // vectors this loop consumes.
        for (real_row, padding_row) in real_rows.iter().zip(&padding_rows) {
            assert!(
                sibling_is_real[*real_row],
                "epoch {number}: row {real_row} was offered as the real side and its sibling is padding"
            );
            assert!(
                !sibling_is_real[*padding_row],
                "epoch {number}: row {padding_row} was offered as the padding side and its sibling is real"
            );
            assert_ne!(
                real_row, padding_row,
                "epoch {number}: a row was compared with itself, which ties by construction"
            );
            pair_trials += 1;
            let tie_break = pair_trials.is_multiple_of(2);
            for feature in 0..FEATURE_COUNT {
                if picked_real(
                    matrix[*real_row][feature],
                    matrix[*padding_row][feature],
                    tie_break,
                ) {
                    pair_successes[feature] += 1;
                }
            }
            if picked_real(combined[*real_row], combined[*padding_row], tie_break) {
                pair_successes[FEATURE_COUNT] += 1;
            }
        }
    }

    // A proof's own fields are a count channel, and no other test in §4.4 watches them: V-Z-01
    // inspects on-chain bytes, and a proof never goes on chain. An engine that folded the record
    // count into `epoch`, `height` or the sibling count would pass every other case here.
    let mut shapes: Vec<(u8, usize, u64)> = Vec::new();
    for real_count in [1usize, 128, 255] {
        let real: Vec<(SubmissionId, Digest)> = (0..real_count as u64)
            .map(|n| (scattered_id(90_000 + n), leaf_digest(90_000 + n)))
            .collect();
        let built = BuiltEpoch::build::<NativeKeccak>(4_242, HEIGHT, &TEST_MASTER_KEY, &real)
            .expect("builds");

        // `slot_index` is the fourth field a proof carries, and the three checks below cannot see it.
        // Every slot is compared against D-60's assignment, transcribed independently in the test. This
        // blocker samples three counts under the engine's own hasher; the tree's conformance test runs
        // the same comparison at every count from 0 to C at H = 4 and H = 8, which is where a mutation
        // confined to an unvisited count is caught. A regenerated vector set cannot serve either
        // purpose, because the generator runs the engine under test.
        assert_eq!(
            built.assignment,
            assignment_oracle::<NativeKeccak>(4_242, HEIGHT, &TEST_MASTER_KEY, &real),
            "V-Z-03: at {real_count} real leaves, every slot must be the one §1.4 prescribes"
        );

        for (id, _) in &built.assignment {
            let proof = built.proof(id).expect("the epoch holds it");
            assert_eq!(
                proof.epoch, built.epoch,
                "V-Z-03: a proof's epoch is its tree's, and nothing else"
            );
            assert_eq!(
                proof.height, built.height,
                "V-Z-03: a proof's height is the log's, and nothing else"
            );
            assert_eq!(
                proof.siblings.len(),
                usize::from(built.height),
                "V-Z-03: the sibling count is the height, whatever the record count"
            );
            shapes.push((proof.height, proof.siblings.len(), proof.epoch));
        }
    }
    shapes.dedup();
    assert_eq!(
        shapes.len(),
        1,
        "V-Z-03: one proof shape across 1, 128 and 255 real leaves, and {shapes:?} is not one"
    );

    assert!(
        pair_trials > 1_000,
        "V-Z-03 needs a sample, and {pair_trials} pairs is not one"
    );
    // The same aggregate liveness V-Z-02 asserts; see the note there (PR #69, round four).
    // **"Varied somewhere" is not support (PR #69, round five, H-03).** Round four accumulated a
    // boolean per feature across the sample. A review then made one feature compute its real value for
    // a single epoch and return 0.0 for the other 199, and the boolean was still true: a feature
    // contributing nothing to 99.5% of the trials satisfied the check, which reopens round two's
    // neutral-value hole for almost the whole run.
    //
    // The sample has to support the claim, so the count is kept and a floor applied. Measured on the
    // committed fixtures, every one of the nine varies in **every** epoch — 200 of 200 here and 50 of
    // 50 in V-Z-03. The floor is nine tenths rather than all of them, because round four's L-02 showed
    // a legitimate epoch can hold a genuinely constant column and must not abort the run; the gap
    // between the measured 100% and the required 90% is exactly that allowance, and it is wide.
    let floor = (epochs_sampled * 9) / 10;
    let thin: Vec<String> = FEATURE_NAMES
        .iter()
        .zip(&live_epochs)
        .filter(|(_, live)| **live < floor)
        .map(|(name, live)| format!("{name} ({live} of {epochs_sampled})"))
        .collect();
    assert!(
        thin.is_empty(),
        "{} of {FEATURE_COUNT} features varied in fewer than {floor} of {epochs_sampled} epochs, so \
         they do not support a statistic computed over all of them: {}",
        thin.len(),
        thin.join(", ")
    );

    for (index, successes) in pair_successes.iter().enumerate() {
        let label = if index == FEATURE_COUNT {
            "sibling nature, combined score"
        } else {
            FEATURE_NAMES[index]
        };
        assert_indistinguishable(label, *successes, pair_trials);
    }
}

/// Every real submission's slot, against its submission order, its issuer and its time in the epoch.
fn position_correlations(epochs: u64) -> [f64; 3] {
    // **The function defends its own sample (H-33).** Pinning `EPOCHS_VZ04` stops the constant being
    // edited; it does nothing about a caller that passes something else, and the bound this returns
    // against is computed from a sample of 400. A review found nine epochs green under the unchanged
    // bound. The literal is deliberate: taking it from the constant would make the check restate the
    // thing it is checking, which is the defect this unit spent five rounds on.
    assert!(
        epochs >= 400,
        "V-Z-04's bound is computed from a sample of 400 epochs and this run has {epochs}; a smaller \
         sample does not widen the bound, it just measures less"
    );
    let mut slots: Vec<f64> = Vec::new();
    let mut orders: Vec<f64> = Vec::new();
    let mut issuers: Vec<f64> = Vec::new();
    let mut times: Vec<f64> = Vec::new();
    let mut mix = SplitMix(0x5eed_0004);

    for number in 0..epochs {
        // Sequential identifiers are the hard case: the identifier itself carries the submission's
        // order, so a slot that followed the identifier would follow the order too.
        let real: Vec<(SubmissionId, Digest)> = (0..REAL_PER_EPOCH as u64)
            .map(|n| {
                let counter = number.wrapping_mul(REAL_PER_EPOCH as u64).wrapping_add(n);
                (sequential_id(counter), leaf_digest(counter))
            })
            .collect();
        let built = BuiltEpoch::build::<NativeKeccak>(number, HEIGHT, &TEST_MASTER_KEY, &real)
            .expect("builds");

        // **The support a valid sample owes, asserted per epoch (PR #69, H-01).** The exact-zero guard in
        // `pearson` proves only that the denominator is not literally zero. A review left 25,599
        // identical slots and one outlier: variance was about 1e-301, the guard passed, and all three
        // V-Z-04 bounds reported |r| near 0.01 while placement had collapsed. Scale invariance means the
        // same holds with the outlier at slot 1, so it is not an artefact of subnormal arithmetic, and a
        // larger sample hides one outlier better rather than worse.
        //
        // An epsilon in `pearson` would be the wrong remedy — r is unitless, so an absolute floor there
        // would make it depend on units. This is where the meaning lives: first-free probing marks each
        // slot taken, so an epoch holding `REAL_PER_EPOCH` submissions owes exactly that many distinct
        // slots. Anything less is a placement failure, and the correlations computed from it would be
        // arithmetic rather than observation.
        let placed: std::collections::BTreeSet<u16> =
            built.assignment.iter().map(|(_, slot)| *slot).collect();
        assert_eq!(
            placed.len(),
            REAL_PER_EPOCH,
            "epoch {number} placed {} submissions into {} distinct slots; INV-TREE-03's premise is that \
             each takes its own, so a correlation over this sample would measure arithmetic rather than \
             placement",
            built.assignment.len(),
            placed.len()
        );

        // **The observation is checked per epoch, after it is collected (PR #69, round five, H-04).**
        // The guard above and the dispersion floor below are both global: a review kept epoch zero
        // correct and wrote 0.0 for the other 399, destroying 25,536 of 25,600 observations, and epoch
        // zero alone satisfied the distinctness floor while all three correlations moved *towards* the
        // passing value. A sample is not supported by one good epoch. What this epoch contributed is
        // therefore compared against what this epoch placed, before the next one is built.
        let before = slots.len();
        for (order, (id, _)) in real.iter().enumerate() {
            let slot = built
                .assignment
                .iter()
                .find(|(candidate, _)| candidate == id)
                .map(|(_, slot)| *slot)
                .expect("every submission was placed");
            slots.push(f64::from(slot));
            orders.push(order as f64);
            issuers.push((order % 8) as f64);
            // Time rises through the epoch, with jitter that owes nothing to the slot.
            times.push((order as f64) * 137.0 + (mix.next_u64() % 100) as f64);
        }

        // **A set is not an alignment (PR #69, round six, H-02).** Pearson consumes ordered pairs:
        // `slots[i]` against `orders[i]`, `issuers[i]` and `times[i]`. The round-five check compared
        // this epoch's contribution as a *set* against what it placed, which a rotation satisfies
        // exactly — same values, same count, every pairing destroyed. A review rotated each epoch by
        // one and both the 400-epoch CI test and the 10,000-epoch release gate passed.
        //
        // So the record is checked where it is made: each appended observation is compared against the
        // slot the assignment gives for the submission that produced it, in order, before anything is
        // projected into a column.
        for (offset, (id, _)) in real.iter().enumerate() {
            let expected = built
                .assignment
                .iter()
                .find(|(candidate, _)| candidate == id)
                .map(|(_, slot)| *slot)
                .expect("every submission was placed");
            assert_eq!(
                slots[before + offset] as u16,
                expected,
                "epoch {number}: observation {offset} is the slot of a different submission, so the \
                 pair this contributes to the correlation is fabricated"
            );
        }

        // The set and count checks below are kept behind the alignment check above. They are weaker —
        // a rotation satisfies both — but they catch a flattened or truncated contribution with a
        // message about the epoch rather than about one observation.
        let contributed: std::collections::BTreeSet<u16> =
            slots[before..].iter().map(|value| *value as u16).collect();
        assert_eq!(
            slots.len() - before,
            REAL_PER_EPOCH,
            "epoch {number} contributed {} observations for {REAL_PER_EPOCH} submissions",
            slots.len() - before
        );
        assert_eq!(
            contributed, placed,
            "epoch {number}: the observed slots are not the slots the epoch placed, so this epoch's \
             contribution to the correlation is not a measurement of placement"
        );
    }

    // **And the same obligation on the observation actually correlated (PR #69, H-01).** The per-epoch
    // assertion above guards the engine: it catches a builder that stopped spreading submissions. It does
    // not guard *this* series, because a collection or instrument fault corrupts the vector downstream of
    // a correct placement — which is precisely what the review demonstrated, by overwriting the collected
    // slots with 25,599 zeros and one outlier and watching all three bounds pass.
    //
    // The first attempt at this fix asserted only the per-epoch property and did **not** catch that
    // mutation; running it is how that was established rather than assumed. A sample spanning at least
    // one epoch of `REAL_PER_EPOCH` submissions, each in its own slot, owes at least that many distinct
    // observed slots.
    let distinct: std::collections::BTreeSet<u64> = slots.iter().map(|s| s.to_bits()).collect();
    assert!(
        distinct.len() >= REAL_PER_EPOCH,
        "the observed slot series carries {} distinct values over {} points; a valid sample of {} epochs \
         owes at least {}, so a correlation computed from this would be arithmetic rather than placement",
        distinct.len(),
        slots.len(),
        epochs,
        REAL_PER_EPOCH
    );

    // The sample that actually arrived, not the one the loop was asked for (H-33). Each epoch owes
    // `REAL_PER_EPOCH` placements and the per-epoch check above enforces that one epoch at a time;
    // this is the total those are supposed to add up to.
    let owed = epochs as usize * REAL_PER_EPOCH;
    assert_eq!(
        slots.len(),
        owed,
        "{epochs} epochs of {REAL_PER_EPOCH} submissions owe {owed} observations and {} arrived",
        slots.len()
    );

    [
        pearson(&slots, &orders, "submission order"),
        pearson(&slots, &issuers, "issuer"),
        pearson(&slots, &times, "time in the epoch"),
    ]
}

#[test]
#[cfg_attr(
    miri,
    ignore = "400 epochs of real Keccak-256; Miri covers the same code paths in tree.rs"
)]
fn v_z_04_position_carries_no_meaning() {
    let [order, issuer, time] = position_correlations(EPOCHS_VZ04);
    for (label, correlation) in [
        ("submission order", order),
        ("issuer", issuer),
        ("time within epoch", time),
    ] {
        assert!(
            correlation.abs() < CORRELATION_BOUND_CI,
            "V-Z-04: slot against {label} correlates at {correlation:.5}, and D-66's bound at this \
             sample is {CORRELATION_BOUND_CI}"
        );
    }
    println!(
        "V-Z-04 at {EPOCHS_VZ04} epochs: order {order:.5}, issuer {issuer:.5}, time {time:.5}"
    );
}

/// §4.4's full sample. A release gate rather than a CI step (D-66): run it before submission with
/// `cargo test --release -p certimining-log -- --ignored`, and record the numbers on issue #16.
#[test]
#[ignore = "the full 10,000-epoch run is a release gate, not a CI step (D-66)"]
fn v_z_04_position_carries_no_meaning_over_ten_thousand_epochs() {
    let [order, issuer, time] = position_correlations(EPOCHS_VZ04_FULL);
    for (label, correlation) in [
        ("submission order", order),
        ("issuer", issuer),
        ("time within epoch", time),
    ] {
        assert!(
            correlation.abs() < CORRELATION_BOUND_FULL,
            "V-Z-04: slot against {label} correlates at {correlation:.5} over \
             {EPOCHS_VZ04_FULL} epochs, and D-66's bound is {CORRELATION_BOUND_FULL}"
        );
    }
    println!(
        "V-Z-04 at {EPOCHS_VZ04_FULL} epochs: order {order:.5}, issuer {issuer:.5}, time {time:.5}"
    );
}
