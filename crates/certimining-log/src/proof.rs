//! Inclusion proofs and the pure verifier (§2.3, INV-IFACE-01).
//!
//! **STUB. This module has no implementation yet (D-65).** See `tree.rs` for why.

use certimining_core::{Digest, Hasher, RegistryError, Result};

/// STUB (D-65): what every entry point in this module returns until the implementation lands.
const STUB_REFUSAL: RegistryError = RegistryError::InclusionProofInvalid;

/// The most siblings a proof can carry, which is `MAX_HEIGHT` (§1.8, §2.3).
pub const MAX_SIBLINGS: usize = 16;

/// One inclusion proof (§2.3). Digests and indices, and nothing else: there is no field here from
/// which a sibling's preimage could be recovered (V-Z-03).
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
        // STUB (D-65).
        let _ = (leaf, proof, root);
        Err(STUB_REFUSAL)
    }

    fn verify_for_height<H: Hasher>(
        leaf: &Digest,
        proof: &InclusionProof,
        root: &Digest,
        configured_height: u8,
    ) -> Result<()> {
        // STUB (D-65).
        let _ = (leaf, proof, root, configured_height);
        Err(STUB_REFUSAL)
    }
}
