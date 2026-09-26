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
    assert_indistinguishable, assignment_oracle, combined_scores, epoch, feature_matrix,
    leaf_digest, padding_slots, pearson, real_slots, scattered_id, sequential_id, SplitMix,
    FEATURE_COUNT, FEATURE_NAMES, TEST_MASTER_KEY,
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

/// One pair trial: the classifier names which of the two leaves is real, and ties alternate so a tie
/// cannot bias the count in either direction.
fn picked_real(real_score: f64, padding_score: f64, tie_break: bool) -> bool {
    if real_score == padding_score {
        tie_break
    } else {
        real_score > padding_score
    }
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

    for number in 0..EPOCHS_VZ02 {
        let capacity = 1usize << HEIGHT;
        let built = epoch::<NativeKeccak>(number, HEIGHT, capacity / 2);
        // The classifier is given the root and the leaves in slot order, and no key.
        let matrix = feature_matrix(&built.leaves, &built.root);
        let combined = combined_scores(&matrix);

        let mut reals = real_slots(&built);
        let mut paddings = padding_slots(&built);
        assert_eq!(reals.len(), paddings.len(), "a balanced epoch");
        mix.shuffle(&mut reals);
        mix.shuffle(&mut paddings);

        for (real, padding) in reals.iter().zip(&paddings) {
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
        let combined = combined_scores(&matrix);
        let mut real_rows: Vec<usize> = (0..siblings.len())
            .filter(|index| sibling_is_real[*index])
            .collect();
        let mut padding_rows: Vec<usize> = (0..siblings.len())
            .filter(|index| !sibling_is_real[*index])
            .collect();
        mix.shuffle(&mut real_rows);
        mix.shuffle(&mut padding_rows);

        for (real_row, padding_row) in real_rows.iter().zip(&padding_rows) {
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

    [
        pearson(&slots, &orders),
        pearson(&slots, &issuers),
        pearson(&slots, &times),
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
