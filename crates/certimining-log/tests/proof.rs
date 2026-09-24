//! E-06: inclusion proofs, the pure verifier, and §4.3's proof vectors, each returning `0x13`.

mod common;

use certimining_core::{Digest, NodePreimage, Preimage, RealLeafPreimage, RegistryError};
use certimining_log::{
    BuiltEpoch, EpochTree, InclusionProof, InclusionVerifier, ProofVerifier, MAX_SIBLINGS,
};
use common::{epoch, leaf_digest, scattered_id, MixHash, TEST_MASTER_KEY};

/// One epoch and one submission inside it, with the chain leaf the counterparty would hold.
fn one_proof(height: u8) -> (BuiltEpoch, Digest, InclusionProof) {
    let real = vec![(scattered_id(11), leaf_digest(11))];
    let built = BuiltEpoch::build::<MixHash>(30, height, &TEST_MASTER_KEY, &real).expect("builds");
    let proof = built.proof(&real[0].0).expect("the epoch holds it");
    (built, real[0].1, proof)
}

#[test]
fn a_valid_proof_verifies_for_every_slot_in_the_tree() {
    // At H = 4 every slot can be filled, so every path through the tree is exercised.
    let height = 4u8;
    let real: Vec<_> = (0..16u64)
        .map(|n| (scattered_id(n + 40), leaf_digest(n + 40)))
        .collect();
    let built = BuiltEpoch::build::<MixHash>(31, height, &TEST_MASTER_KEY, &real).expect("builds");
    for (id, leaf) in &real {
        let proof = built.proof(id).expect("the epoch holds it");
        assert_eq!(
            ProofVerifier::verify::<MixHash>(leaf, &proof, &built.root),
            Ok(()),
            "slot {} must verify",
            proof.slot_index
        );
    }
}

#[test]
fn the_path_runs_from_the_leaf_upward_with_the_slot_as_its_bits() {
    let (built, leaf, proof) = one_proof(8);
    // The specification's own walk, written out here: the tagged leaf, then one node per level,
    // taking the side from the slot index's bits, lowest first.
    let mut node = RealLeafPreimage { leaf }
        .digest::<MixHash>()
        .expect("digest");
    for (level, sibling) in proof.siblings.iter().enumerate() {
        let on_the_left = (proof.slot_index >> level) & 1 == 0;
        let (left, right) = if on_the_left {
            (node, *sibling)
        } else {
            (*sibling, node)
        };
        node = NodePreimage { left, right }
            .digest::<MixHash>()
            .expect("digest");
    }
    assert_eq!(
        node, built.root,
        "D-64: siblings leaf-first, path bits from the slot index"
    );
}

#[test]
fn reversing_the_siblings_fails() {
    let (built, leaf, proof) = one_proof(8);
    let mut reversed = proof.clone();
    let mut siblings: Vec<Digest> = reversed.siblings.iter().copied().collect();
    siblings.reverse();
    reversed.siblings = siblings.iter().copied().collect();
    assert_eq!(
        ProofVerifier::verify::<MixHash>(&leaf, &reversed, &built.root),
        Err(RegistryError::InclusionProofInvalid),
        "D-64: the order is load-bearing, not decoration"
    );
}

#[test]
fn v_n_15_one_altered_sibling_is_0x13() {
    let (built, leaf, proof) = one_proof(8);
    for level in 0..proof.siblings.len() {
        let mut altered = proof.clone();
        let mut siblings: Vec<Digest> = altered.siblings.iter().copied().collect();
        siblings[level][0] ^= 0x01;
        altered.siblings = siblings.iter().copied().collect();
        assert_eq!(
            ProofVerifier::verify::<MixHash>(&leaf, &altered, &built.root),
            Err(RegistryError::InclusionProofInvalid),
            "V-N-15: one bit flipped in the sibling at level {level}"
        );
    }
}

#[test]
fn v_n_16_too_few_or_too_many_siblings_is_0x13() {
    let (built, leaf, proof) = one_proof(8);

    let mut short = proof.clone();
    let mut siblings: Vec<Digest> = short.siblings.iter().copied().collect();
    siblings.pop();
    short.siblings = siblings.iter().copied().collect();
    assert_eq!(
        ProofVerifier::verify::<MixHash>(&leaf, &short, &built.root),
        Err(RegistryError::InclusionProofInvalid),
        "V-N-16: H − 1 siblings"
    );

    let mut long = proof.clone();
    long.siblings.push([0x00; 32]).expect("room below sixteen");
    assert_eq!(
        ProofVerifier::verify::<MixHash>(&leaf, &long, &built.root),
        Err(RegistryError::InclusionProofInvalid),
        "V-N-16: H + 1 siblings"
    );
}

#[test]
fn v_n_16b_a_height_that_disagrees_with_the_log_is_0x13() {
    let (built, leaf, proof) = one_proof(8);
    assert_eq!(
        ProofVerifier::verify_for_height::<MixHash>(&leaf, &proof, &built.root, 8),
        Ok(()),
        "the log's own height verifies"
    );
    for configured in [4u8, 7, 9, 12, 16] {
        assert_eq!(
            ProofVerifier::verify_for_height::<MixHash>(&leaf, &proof, &built.root, configured),
            Err(RegistryError::InclusionProofInvalid),
            "V-N-16b: a proof claiming 8 against a log configured at {configured}"
        );
    }
}

#[test]
fn v_n_17_the_wrong_epochs_root_is_0x13() {
    let (built, leaf, proof) = one_proof(8);
    let other = epoch::<MixHash>(31, 8, 4);
    assert_ne!(built.root, other.root);
    assert_eq!(
        ProofVerifier::verify::<MixHash>(&leaf, &proof, &other.root),
        Err(RegistryError::InclusionProofInvalid),
        "V-N-17: a proof against another epoch's root"
    );
}

#[test]
fn a_slot_index_outside_the_height_is_0x13() {
    let (built, leaf, proof) = one_proof(4);
    let mut beyond = proof.clone();
    beyond.slot_index = 16;
    assert_eq!(
        ProofVerifier::verify::<MixHash>(&leaf, &beyond, &built.root),
        Err(RegistryError::InclusionProofInvalid),
        "at H = 4 there are sixteen slots, numbered 0 to 15"
    );
}

#[test]
fn a_height_outside_the_range_is_0x13() {
    let (built, leaf, proof) = one_proof(8);
    for height in [0u8, 3, 17, 255] {
        let mut odd = proof.clone();
        odd.height = height;
        assert_eq!(
            ProofVerifier::verify::<MixHash>(&leaf, &odd, &built.root),
            Err(RegistryError::InclusionProofInvalid),
            "§1.8: a proof claiming H = {height}"
        );
    }
}

#[test]
fn the_wrong_leaf_is_0x13() {
    let (built, _, proof) = one_proof(8);
    assert_eq!(
        ProofVerifier::verify::<MixHash>(&leaf_digest(999), &proof, &built.root),
        Err(RegistryError::InclusionProofInvalid),
        "a proof binds the leaf it was made for"
    );
}

#[test]
fn the_verifier_applies_the_leaf_tag_itself() {
    let (built, leaf, proof) = one_proof(8);
    let already_tagged = RealLeafPreimage { leaf }
        .digest::<MixHash>()
        .expect("digest");
    assert_eq!(
        ProofVerifier::verify::<MixHash>(&already_tagged, &proof, &built.root),
        Err(RegistryError::InclusionProofInvalid),
        "D-64: verify takes the chain leaf and applies TAG_MTL0 itself, so a caller cannot omit it"
    );
}

#[test]
fn a_proof_for_a_submission_the_epoch_does_not_hold_is_0x16() {
    let built = epoch::<MixHash>(32, 8, 4);
    assert_eq!(
        built.proof(&scattered_id(u64::MAX)).err(),
        Some(RegistryError::SubmissionNotInEpoch),
        "D-67: its own condition, and so its own code, not 0x13"
    );
    // The distinction is the point of the new code: a proof that does not verify is still 0x13.
    let (built, leaf, proof) = one_proof(8);
    let mut altered = proof.clone();
    let mut siblings: Vec<Digest> = altered.siblings.iter().copied().collect();
    siblings[0][0] ^= 0x01;
    altered.siblings = siblings.iter().copied().collect();
    assert_eq!(
        ProofVerifier::verify::<MixHash>(&leaf, &altered, &built.root),
        Err(RegistryError::InclusionProofInvalid),
        "0x13 still means a proof that does not reconcile"
    );
}

#[test]
fn verify_needs_only_the_leaf_the_proof_and_the_root() {
    // INV-IFACE-01 is a property of the signature: this scope holds no log, no batcher and no
    // clock, and the call still compiles and answers.
    let (root, leaf, proof) = {
        let (built, leaf, proof) = one_proof(8);
        (built.root, leaf, proof)
    };
    assert_eq!(
        ProofVerifier::verify::<MixHash>(&leaf, &proof, &root),
        Ok(()),
        "a counterparty verifies offline, given the record, the proof and a root"
    );
}

#[test]
#[cfg_attr(
    miri,
    ignore = "a tree at H = 16 is 65,536 leaves; every path it uses is covered above"
)]
fn a_proof_carries_sixteen_siblings_at_most() {
    assert_eq!(MAX_SIBLINGS, 16, "§1.8: H is at most 16");
    let built = epoch::<MixHash>(33, 16, 2);
    let proof = built
        .proof(&built.assignment[0].0)
        .expect("the epoch holds it");
    assert_eq!(
        proof.siblings.len(),
        16,
        "the deepest tree fills the vector"
    );
}
