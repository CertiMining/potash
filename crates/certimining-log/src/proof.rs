// SPDX-License-Identifier: MIT OR Apache-2.0
//! Inclusion proofs and the pure verifier (§2.3, INV-IFACE-01).
//!
//! A proof carries digests and indices: one sibling per level from the leaf upward, the slot whose
//! bits are the path, the height it was built at, and the epoch its root belongs to. Nothing in it is
//! a preimage, so a counterparty holding a proof learns the position of one leaf and nothing about
//! any sibling's nature (INV-TREE-02, V-Z-03).
//!
//! Verification is pure. It takes no batcher handle, reads no clock and touches no storage, so a
//! counterparty verifies offline against a root they fetched from Solana themselves.

use certimining_core::{
    Digest, Hasher, NodePreimage, Preimage, RealLeafPreimage, RegistryError, Result,
};

use crate::{MAX_HEIGHT, MIN_HEIGHT};

/// The most siblings a proof can carry, which is `MAX_HEIGHT` (§1.8, §2.3).
pub const MAX_SIBLINGS: usize = 16;

/// One inclusion proof (§2.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InclusionProof {
    /// The height of the tree this proof came from, which must equal the log's configured `H`.
    pub height: u8,
    /// One sibling per level, from the leaf upward, exactly `height` of them (D-64).
    pub siblings: heapless::Vec<Digest, MAX_SIBLINGS>,
    /// The slot the leaf sits in. Its bits are the path, bit 0 first (D-64).
    pub slot_index: u16,
    /// The epoch whose root this proof is against.
    pub epoch: u64,
}

/// §2.3's verifier. Pure: no network, no clock, no storage, no log handle (INV-IFACE-01).
pub trait InclusionVerifier {
    /// Checks a proof against a root. `leaf` is the chain leaf `leafₙ`; the verifier applies
    /// `TAG_MTL0` itself, so no caller can omit the tag (INV-ENC-01, D-64). Any failure is `0x13`.
    fn verify<H: Hasher>(leaf: &Digest, proof: &InclusionProof, root: &Digest) -> Result<()>;
    /// The same check for a caller that knows its log's configured height: a proof whose `height`
    /// disagrees is `0x13` before any hashing (V-N-16b, D-64).
    fn verify_for_height<H: Hasher>(
        leaf: &Digest,
        proof: &InclusionProof,
        root: &Digest,
        configured_height: u8,
    ) -> Result<()>;
}

/// The verifier this crate provides.
#[derive(Debug, Clone, Copy)]
pub struct ProofVerifier;

impl InclusionVerifier for ProofVerifier {
    fn verify<H: Hasher>(leaf: &Digest, proof: &InclusionProof, root: &Digest) -> Result<()> {
        // What a proof can be checked for on its own: a height §1.8 allows, one sibling per level,
        // and a slot that addresses a leaf at that height (D-64).
        if !(MIN_HEIGHT..=MAX_HEIGHT).contains(&proof.height) {
            return Err(RegistryError::InclusionProofInvalid);
        }
        if proof.siblings.len() != usize::from(proof.height) {
            return Err(RegistryError::InclusionProofInvalid);
        }
        let capacity = 1u32
            .checked_shl(u32::from(proof.height))
            .ok_or(RegistryError::InclusionProofInvalid)?;
        let mut index = u32::from(proof.slot_index);
        if index >= capacity {
            return Err(RegistryError::InclusionProofInvalid);
        }

        // The leaf enters the tree under its own tag, then one node per level, taking the side from
        // the slot's bits, lowest first.
        let mut node = RealLeafPreimage { leaf: *leaf }.digest::<H>()?;
        for sibling in proof.siblings.iter() {
            let (left, right) = if index & 1 == 0 {
                (node, *sibling)
            } else {
                (*sibling, node)
            };
            node = NodePreimage { left, right }.digest::<H>()?;
            index = index
                .checked_shr(1)
                .ok_or(RegistryError::InclusionProofInvalid)?;
        }
        if node == *root {
            Ok(())
        } else {
            Err(RegistryError::InclusionProofInvalid)
        }
    }

    fn verify_for_height<H: Hasher>(
        leaf: &Digest,
        proof: &InclusionProof,
        root: &Digest,
        configured_height: u8,
    ) -> Result<()> {
        if proof.height != configured_height {
            return Err(RegistryError::InclusionProofInvalid);
        }
        Self::verify::<H>(leaf, proof, root)
    }
}
