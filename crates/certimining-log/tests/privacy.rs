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

use certimining_core::{epoch_key, padding_prf, Digest, NativeKeccak, SubmissionId};
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

/// **Liveness is not conformance, and a review proved the gap (PR #69, round four, H-01).** Round three
/// required all nine feature columns to vary. An extractor that copies leaf byte 0 into all nine
/// satisfies that, and the positive control plants its leak in byte 0, so the control reached 1.0000
/// while eight named instruments were absent and both release blockers stayed green.
///
/// So each column is checked against the property its name claims. **Every case below holds leaf byte 0
/// identical between the two inputs**, which is what makes the test discriminating: an extractor
/// aliasing byte 0 produces the same column for both sides of every case and fails all nine. The last
/// two hold the whole leaf identical and vary its neighbour and the root, because that is what those
/// two features are about.
#[cfg_attr(
    miri,
    ignore = "nine feature extractions over a small matrix, not a Miri question"
)]
#[test]
fn each_named_feature_responds_to_its_own_property() {
    const FIXED: u8 = 0x5a;
    // A leaf whose byte 0 is `first` and whose remaining bytes come from `rest`.
    fn leaf(first: u8, rest: impl Fn(usize) -> u8) -> Digest {
        let mut out = [0u8; 32];
        out[0] = first;
        for (i, slot) in out.iter_mut().enumerate().skip(1) {
            *slot = rest(i);
        }
        out
    }
    // Four rows so the cyclic neighbours in the extractor are well defined; row 1 is the one examined.
    fn matrix_of(subject: Digest, neighbour: Digest, root: Digest) -> Vec<[f64; FEATURE_COUNT]> {
        let filler = leaf(0x11, |i| i as u8);
        feature_matrix(&[filler, subject, neighbour, filler], &root)
    }

    let plain_root = [0x33; 32];
    let quiet = leaf(FIXED, |_| 0x00);
    let cases: [(usize, Digest, Digest, Digest, Digest, Digest, Digest); FEATURE_COUNT] = [
        // per-position byte deviation: same byte 0, a tail far from the set mean versus one at it.
        (
            0,
            leaf(FIXED, |_| 0x00),
            quiet,
            leaf(FIXED, |_| 0xff),
            quiet,
            plain_root,
            plain_root,
        ),
        // population count: a tail of no bits versus a tail of every bit.
        (
            1,
            leaf(FIXED, |_| 0x00),
            quiet,
            leaf(FIXED, |_| 0xff),
            quiet,
            plain_root,
            plain_root,
        ),
        // zero bytes: thirty-one zero bytes versus none.
        (
            2,
            leaf(FIXED, |_| 0x00),
            quiet,
            leaf(FIXED, |_| 0x01),
            quiet,
            plain_root,
            plain_root,
        ),
        // leading zero bits: byte 0 is zero in both, and byte 1 decides.
        (
            3,
            leaf(0x00, |i| if i == 1 { 0x00 } else { 0xff }),
            quiet,
            leaf(0x00, |i| if i == 1 { 0x01 } else { 0xff }),
            quiet,
            plain_root,
            plain_root,
        ),
        // longest equal run: an alternating tail versus a constant one.
        (
            4,
            leaf(FIXED, |i| if i.is_multiple_of(2) { 0x01 } else { 0x02 }),
            quiet,
            leaf(FIXED, |_| 0x01),
            quiet,
            plain_root,
            plain_root,
        ),
        // distinct byte values: two distinct values versus thirty-two.
        (
            5,
            leaf(FIXED, |_| 0x01),
            quiet,
            leaf(FIXED, |i| i as u8),
            quiet,
            plain_root,
            plain_root,
        ),
        // nibble chi-squared: one nibble pair repeated versus a spread of them.
        (
            6,
            leaf(FIXED, |_| 0x11),
            quiet,
            leaf(FIXED, |i| ((i as u8) << 4) | (i as u8)),
            quiet,
            plain_root,
            plain_root,
        ),
        // hamming distance to the adjacent slots: the subject is identical, the neighbour is not.
        (
            7,
            quiet,
            leaf(0x00, |_| 0x00),
            quiet,
            leaf(0xff, |_| 0xff),
            plain_root,
            plain_root,
        ),
        // hamming distance to the root: the subject is identical, the root is not.
        (8, quiet, quiet, quiet, quiet, [0x00; 32], [0xff; 32]),
    ];

    for (feature, a_subject, a_neighbour, b_subject, b_neighbour, a_root, b_root) in cases {
        assert_eq!(
            a_subject[0], b_subject[0],
            "{}: the two inputs must agree on byte 0 or this case cannot discriminate an alias of it",
            FEATURE_NAMES[feature]
        );
        let a = matrix_of(a_subject, a_neighbour, a_root)[1][feature];
        let b = matrix_of(b_subject, b_neighbour, b_root)[1][feature];
        assert_ne!(
            a, b,
            "{} did not move when the property it names changed, and byte 0 did not change, so this \
             column is not the feature it is named after",
            FEATURE_NAMES[feature]
        );
    }
    println!("conformance: all {FEATURE_COUNT} feature columns respond to their own property with leaf byte 0 held fixed");
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
    let mut ever_varied = [false; FEATURE_COUNT];

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
        for (seen, deviation) in ever_varied.iter_mut().zip(feature_deviations(&matrix)) {
            *seen |= deviation > 0.0;
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
        let real_oracle = real_slots(&built);
        let padding_oracle = padding_slots(&built);
        for (real, padding) in reals.iter().zip(&paddings) {
            assert!(
                real_oracle.binary_search(real).is_ok(),
                "epoch {number}: slot {real} was offered as the real side and the epoch does not place a \
                 real submission there"
            );
            assert!(
                padding_oracle.binary_search(padding).is_ok(),
                "epoch {number}: slot {padding} was offered as the padding side and the epoch does not \
                 pad there"
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
        let real_lookup = real_slots(&built);
        for (rank, (slot, _)) in ranked.iter().enumerate() {
            let called_real = rank < real_lookup.len();
            let is_real = real_lookup.binary_search(&(*slot as u16)).is_ok();
            if called_real == is_real {
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
    let never: Vec<&str> = FEATURE_NAMES
        .iter()
        .zip(&ever_varied)
        .filter(|(_, seen)| !**seen)
        .map(|(name, _)| *name)
        .collect();
    assert!(
        never.is_empty(),
        "{} of {FEATURE_COUNT} features never varied anywhere in this sample: {}",
        never.len(),
        never.join(", ")
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
    let mut ever_varied = [false; FEATURE_COUNT];

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
            sibling_is_real.push(reals.binary_search(&(*slot ^ 1)).is_ok());
        }

        let matrix = feature_matrix(&siblings, &built.root);
        for (seen, deviation) in ever_varied.iter_mut().zip(feature_deviations(&matrix)) {
            *seen |= deviation > 0.0;
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
    let never: Vec<&str> = FEATURE_NAMES
        .iter()
        .zip(&ever_varied)
        .filter(|(_, seen)| !**seen)
        .map(|(name, _)| *name)
        .collect();
    assert!(
        never.is_empty(),
        "{} of {FEATURE_COUNT} features never varied anywhere in this sample: {}",
        never.len(),
        never.join(", ")
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
