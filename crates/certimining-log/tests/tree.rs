//! E-06: the fixed-capacity epoch tree of §1.4 and the positive vectors of §4.2 that belong to it.
//!
//! The structural cases run in every feature set against a stand-in hasher. The cases §4.2 names run
//! under the engine's own Keccak-256, because a vector is only a vector under the real primitive.
//!
//! **Under Miri, only the trees at `H = 4` and `H = 8` are built.** Miri interprets a hash in about a
//! tenth of a second, so a tree at `H = 12` costs minutes and one at `H = 16`, being 196,607 hashes,
//! costs hours. Every test that builds a taller tree is ignored there and runs everywhere else: Miri
//! is looking for undefined behaviour, and the taller trees execute the same code with a longer loop.

mod common;

use certimining_core::{
    epoch_key, padding_prf, Digest, PaddingPreimage, Preimage, RealLeafPreimage, RegistryError,
    SubmissionId,
};
use certimining_log::{slot_from_seed, BuiltEpoch, EpochTree, MAX_HEIGHT, MIN_HEIGHT};
use common::{
    epoch, leaf_digest, padding_slots, real_slots, sequential_id, submissions, MixHash, SplitMix,
    TEST_MASTER_KEY,
};

#[test]
#[cfg_attr(
    miri,
    ignore = "H = 12 is 4,096 slots; the same code runs at H = 4 and H = 8 above"
)]
fn a_built_epoch_has_c_leaves_at_every_height() {
    for height in [4u8, 8, 12] {
        let built = epoch::<MixHash>(1, height, 3);
        assert_eq!(
            built.leaves.len(),
            1usize << height,
            "INV-TREE-01: every epoch at H = {height} has exactly C leaves"
        );
        assert_eq!(built.height, height);
        assert_eq!(built.epoch, 1);
        assert_eq!(built.capacity(), 1usize << height);
    }
}

#[test]
fn the_assignment_is_ascending_by_identifier() {
    let built = epoch::<MixHash>(4, 8, 40);
    let ids: Vec<SubmissionId> = built.assignment.iter().map(|(id, _)| *id).collect();
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    assert_eq!(ids, sorted, "D-60: ascending by submission identifier");
}

#[test]
fn every_real_submission_holds_a_distinct_slot() {
    let built = epoch::<MixHash>(7, 8, 200);
    let slots = real_slots(&built);
    let mut unique = slots.clone();
    unique.dedup();
    assert_eq!(
        slots.len(),
        unique.len(),
        "linear probing gives one slot each"
    );
    assert_eq!(built.assignment.len(), 200);
    assert!(slots
        .iter()
        .all(|slot| usize::from(*slot) < built.capacity()));
}

#[test]
fn one_set_of_submissions_gives_one_tree_whatever_order_it_arrives_in() {
    let ascending = submissions(64);
    let mut descending = ascending.clone();
    descending.reverse();
    let mut shuffled = ascending.clone();
    SplitMix(0xc0ffee).shuffle(&mut shuffled);

    let first = BuiltEpoch::build::<MixHash>(9, 8, &TEST_MASTER_KEY, &ascending).expect("builds");
    for (label, order) in [("descending", descending), ("shuffled", shuffled)] {
        let other = BuiltEpoch::build::<MixHash>(9, 8, &TEST_MASTER_KEY, &order).expect("builds");
        assert_eq!(first.root, other.root, "D-60: {label} gives the same root");
        assert_eq!(
            first.leaves, other.leaves,
            "D-60: {label} gives the same leaves"
        );
        assert_eq!(
            first.assignment, other.assignment,
            "D-60: {label} gives the same assignment"
        );
    }
}

#[test]
fn a_real_slot_holds_its_leaf_under_the_real_leaf_tag() {
    let real = submissions(5);
    let built = BuiltEpoch::build::<MixHash>(2, 8, &TEST_MASTER_KEY, &real).expect("builds");
    for (id, slot) in &built.assignment {
        let leaf = real
            .iter()
            .find(|(candidate, _)| candidate == id)
            .map(|(_, leaf)| *leaf)
            .expect("the assignment names a submission that was supplied");
        assert_eq!(
            built.leaves[usize::from(*slot)],
            RealLeafPreimage { leaf }
                .digest::<MixHash>()
                .expect("digest"),
            "§1.4: real leaf = Keccak256(TAG_MTL0 ‖ leafₙ)"
        );
    }
}

#[test]
fn every_other_slot_holds_the_padding_of_its_own_index() {
    let built = epoch::<MixHash>(3, 8, 10);
    // The test derives k_e the way the specification does, from the master key and the epoch, which
    // is how it can check padding the builder produced without being handed the builder's key.
    let k_e = epoch_key::<MixHash>(&TEST_MASTER_KEY, 3).expect("derives");
    for slot in padding_slots(&built) {
        let prf_output = padding_prf::<MixHash>(&k_e, slot).expect("derives");
        assert_eq!(
            built.leaves[usize::from(slot)],
            PaddingPreimage { prf_output }
                .digest::<MixHash>()
                .expect("digest"),
            "§1.4: padding leaf = Keccak256(TAG_PAD ‖ PRF(k_e, 0x03 ‖ slot_index_le)), slot {slot}"
        );
    }
}

#[test]
fn the_epoch_key_is_derived_inside_the_build_from_the_epoch() {
    let real = submissions(8);
    let first = BuiltEpoch::build::<MixHash>(100, 8, &TEST_MASTER_KEY, &real).expect("builds");
    let second = BuiltEpoch::build::<MixHash>(101, 8, &TEST_MASTER_KEY, &real).expect("builds");
    assert_ne!(
        first.assignment, second.assignment,
        "INV-TREE-05: one epoch key per epoch, so the same submissions move"
    );
    assert_ne!(first.root, second.root);
}

#[test]
fn a_full_epoch_builds_and_one_more_submission_is_0x12() {
    let height = 4u8;
    let capacity = 1usize << height;
    let full = submissions(capacity);
    let built = BuiltEpoch::build::<MixHash>(5, height, &TEST_MASTER_KEY, &full).expect("builds");
    assert_eq!(
        built.assignment.len(),
        capacity,
        "every slot is a real leaf"
    );
    assert_eq!(padding_slots(&built).len(), 0);

    let over = submissions(capacity + 1);
    assert_eq!(
        BuiltEpoch::build::<MixHash>(5, height, &TEST_MASTER_KEY, &over).err(),
        Some(RegistryError::EpochCapacityExceeded),
        "V-N-14: C + 1 real submissions in one epoch is 0x12"
    );
}

#[test]
fn two_submissions_under_one_identifier_are_0x05() {
    let repeated = vec![
        (sequential_id(1), leaf_digest(1)),
        (sequential_id(1), leaf_digest(2)),
    ];
    assert_eq!(
        BuiltEpoch::build::<MixHash>(6, 8, &TEST_MASTER_KEY, &repeated).err(),
        Some(RegistryError::MalformedPayload),
        "§1.4, D-60: the set is malformed, and a proof could be answered for neither"
    );
}

#[test]
fn a_height_outside_the_range_is_0x05() {
    for height in [0u8, 1, 3, 17, 255] {
        assert_eq!(
            BuiltEpoch::build::<MixHash>(1, height, &TEST_MASTER_KEY, &[]).err(),
            Some(RegistryError::MalformedPayload),
            "§1.8: H is in [4, 16], and {height} is not"
        );
    }
    for height in [MIN_HEIGHT, 8] {
        assert!(
            BuiltEpoch::build::<MixHash>(1, height, &TEST_MASTER_KEY, &[]).is_ok(),
            "H = {height} is inside §1.8's range"
        );
    }
}

#[test]
#[cfg_attr(
    miri,
    ignore = "H = 16 is 65,536 slots, which Miri would interpret for hours"
)]
fn the_deepest_tree_the_specification_allows_builds() {
    let built = BuiltEpoch::build::<MixHash>(1, MAX_HEIGHT, &TEST_MASTER_KEY, &[]).expect("builds");
    assert_eq!(
        built.leaves.len(),
        1usize << MAX_HEIGHT,
        "§1.8: H = 16 is the top of the range, and it is 65,536 slots"
    );
    assert_eq!(built.height, MAX_HEIGHT);
}

#[test]
fn the_shape_never_varies_with_the_number_of_real_leaves() {
    let mut shapes = Vec::new();
    for count in [0usize, 1, 128, 255] {
        let built = epoch::<MixHash>(11, 8, count);
        let proof_lengths: Vec<usize> = built
            .assignment
            .iter()
            .map(|(id, _)| {
                built
                    .proof(id)
                    .expect("a held submission has a proof")
                    .siblings
                    .len()
            })
            .collect();
        assert!(
            proof_lengths.iter().all(|length| *length == 8),
            "INV-TREE-01: proof length is constant at H, whatever the record count"
        );
        shapes.push(built.leaves.len());
    }
    assert!(
        shapes.windows(2).all(|pair| pair[0] == pair[1]),
        "INV-TREE-01: the leaf count does not move with the record count: {shapes:?}"
    );
}

#[test]
fn an_empty_epoch_still_has_a_root() {
    let built = BuiltEpoch::build::<MixHash>(12, 8, &TEST_MASTER_KEY, &[]).expect("builds");
    assert_eq!(built.leaves.len(), 256);
    assert_eq!(built.assignment.len(), 0);
    assert_ne!(
        built.root, [0u8; 32],
        "an epoch with no records publishes a root like any other"
    );
}

#[test]
fn changing_one_leaf_changes_the_root() {
    let mut real = submissions(4);
    let before = BuiltEpoch::build::<MixHash>(13, 8, &TEST_MASTER_KEY, &real).expect("builds");
    real[0].1[0] ^= 0x01;
    let after = BuiltEpoch::build::<MixHash>(13, 8, &TEST_MASTER_KEY, &real).expect("builds");
    assert_ne!(before.root, after.root, "one flipped bit moves the root");
}

#[test]
fn a_different_master_key_moves_every_slot() {
    let real = submissions(32);
    let mine = BuiltEpoch::build::<MixHash>(14, 8, &TEST_MASTER_KEY, &real).expect("builds");
    let other_key: Digest = [0x01; 32];
    let theirs = BuiltEpoch::build::<MixHash>(14, 8, &other_key, &real).expect("builds");
    assert_ne!(
        mine.assignment, theirs.assignment,
        "INV-TREE-03: position is pseudorandom under k_e"
    );
}

#[test]
fn slot_from_seed_reads_the_low_bits_of_a_little_endian_integer() {
    let mut seed = [0xffu8; 32];
    seed[0] = 0x34;
    seed[1] = 0x12;
    // 0x1234 little-endian, and every byte above the first two is noise the reduction ignores.
    assert_eq!(slot_from_seed(&seed, 16), Ok(0x1234));
    assert_eq!(slot_from_seed(&seed, 12), Ok(0x0234));
    assert_eq!(slot_from_seed(&seed, 8), Ok(0x0034));
    assert_eq!(slot_from_seed(&seed, 4), Ok(0x0004));

    let mut louder = seed;
    louder[2] = 0x00;
    assert_eq!(
        slot_from_seed(&louder, 8),
        slot_from_seed(&seed, 8),
        "D-60: only the low H bits decide the slot"
    );
}

#[test]
fn slot_from_seed_refuses_a_height_outside_the_range() {
    for height in [0u8, 3, 17] {
        assert_eq!(
            slot_from_seed(&[0u8; 32], height).err(),
            Some(RegistryError::MalformedPayload),
            "§1.8: H is in [4, 16]"
        );
    }
}

#[test]
fn a_probe_that_wraps_still_finds_the_free_slot() {
    // A nearly full epoch at H = 4 forces the probe past the end of the array and round to the
    // start, which is the case the wrap exists for.
    let height = 4u8;
    let real = submissions((1usize << height) - 1);
    let built = BuiltEpoch::build::<MixHash>(15, height, &TEST_MASTER_KEY, &real).expect("builds");
    assert_eq!(built.assignment.len(), real.len());
    assert_eq!(
        padding_slots(&built).len(),
        1,
        "one slot left, and it is padding"
    );
}

/// §4.2's tree vectors, under the engine's own Keccak-256.
#[cfg(feature = "native")]
mod with_real_keccak {
    use super::*;
    // Only the cases under the real hasher build these identifiers, so the import belongs here
    // rather than at the top, where it would be unused in the feature sets without `native` (D-50).
    use super::common::scattered_id;
    use certimining_core::NativeKeccak;
    use certimining_log::{InclusionVerifier, ProofVerifier};

    #[test]
    fn v_p_05_one_real_leaf_at_h8() {
        let real = vec![(scattered_id(1), leaf_digest(1))];
        let built =
            BuiltEpoch::build::<NativeKeccak>(20, 8, &TEST_MASTER_KEY, &real).expect("builds");
        let again =
            BuiltEpoch::build::<NativeKeccak>(20, 8, &TEST_MASTER_KEY, &real).expect("builds");
        assert_eq!(built.root, again.root, "V-P-05: the root is fixed");
        let proof = built.proof(&real[0].0).expect("the epoch holds it");
        assert_eq!(proof.siblings.len(), 8, "V-P-05: an eight-sibling proof");
        assert_eq!(
            ProofVerifier::verify::<NativeKeccak>(&real[0].1, &proof, &built.root),
            Ok(()),
            "V-P-05: and it verifies"
        );
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "255 proofs verified under real Keccak-256; the paths are covered above"
    )]
    fn v_p_06_255_real_leaves_at_h8() {
        let real: Vec<_> = (0..255u64)
            .map(|n| (scattered_id(n + 500), leaf_digest(n + 500)))
            .collect();
        let built =
            BuiltEpoch::build::<NativeKeccak>(21, 8, &TEST_MASTER_KEY, &real).expect("builds");
        assert_eq!(built.assignment.len(), 255);
        for (id, leaf) in &real {
            let proof = built.proof(id).expect("the epoch holds it");
            assert_eq!(proof.siblings.len(), 8, "V-P-06: proof length is still 8");
            assert_eq!(
                ProofVerifier::verify::<NativeKeccak>(leaf, &proof, &built.root),
                Ok(()),
                "V-P-06: every proof verifies"
            );
        }
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "H = 12 under the real hasher; the H = 4 half of this case is enough there"
    )]
    fn v_p_06b_the_same_leaves_at_h4_and_h12() {
        let real: Vec<_> = (0..12u64)
            .map(|n| (scattered_id(n + 900), leaf_digest(n + 900)))
            .collect();
        for height in [4u8, 12] {
            let built = BuiltEpoch::build::<NativeKeccak>(22, height, &TEST_MASTER_KEY, &real)
                .expect("builds");
            assert_eq!(built.leaves.len(), 1usize << height);
            for (id, leaf) in &real {
                let proof = built.proof(id).expect("the epoch holds it");
                assert_eq!(
                    proof.siblings.len(),
                    usize::from(height),
                    "V-P-06b: proof length tracks H exactly"
                );
                assert_eq!(
                    ProofVerifier::verify::<NativeKeccak>(leaf, &proof, &built.root),
                    Ok(())
                );
            }
        }
    }

    #[test]
    fn the_root_is_reproducible_from_the_same_inputs() {
        let real = submissions(37);
        let first =
            BuiltEpoch::build::<NativeKeccak>(23, 8, &TEST_MASTER_KEY, &real).expect("builds");
        let second =
            BuiltEpoch::build::<NativeKeccak>(23, 8, &TEST_MASTER_KEY, &real).expect("builds");
        assert_eq!(first.root, second.root);
        assert_eq!(first.leaves, second.leaves);
    }

    /// §4.4a's threshold: 256 leaves in under 10 ms. A debug build measures an order of magnitude
    /// slower than the release build the threshold is about, so the number is reported either way
    /// and asserted only where the comparison means something.
    #[test]
    #[cfg_attr(
        miri,
        ignore = "a timing measurement under an interpreter measures the interpreter"
    )]
    fn a_256_leaf_epoch_builds_inside_the_threshold() {
        let real = submissions(128);
        let start = std::time::Instant::now();
        let built =
            BuiltEpoch::build::<NativeKeccak>(24, 8, &TEST_MASTER_KEY, &real).expect("builds");
        let elapsed = start.elapsed();
        assert_eq!(built.leaves.len(), 256);
        println!("tree build, 256 leaves: {:?}", elapsed);
        if cfg!(debug_assertions) {
            println!("debug build: §4.4a's 10 ms threshold is not asserted here");
        } else {
            assert!(
                elapsed < std::time::Duration::from_millis(10),
                "§4.4a: 256 leaves in under 10 ms, measured {elapsed:?}"
            );
        }
    }
}
