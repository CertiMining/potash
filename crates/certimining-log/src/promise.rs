//! Signed inclusion promises, and what they can be used to show (§1.6, §2.3).
//!
//! A promise is the anti-censorship device: it binds one leaf to one epoch window under the batcher's
//! key, and a counterparty checks it without the batcher. What it cannot do is prove absence. Only the
//! batcher can show a leaf is present, so an unsatisfied promise is a transferable accusation the
//! batcher may rebut with an inclusion proof, and a rebuttal counts only if that proof resolves to a
//! root published inside the window. A proof against a later root confirms the breach (D-72).
//!
//! One difference from a record's attestation is worth stating, because getting it wrong would be
//! invisible: the qualified person signs the leaf **preimage**, while §1.6 signs the SPI **digest**.

use certimining_core::{
    Digest, Hasher, Preimage, RegistryError, Result, SpiPreimage, SubmissionId, Verifier,
};

use crate::{InclusionProof, InclusionVerifier, ProofVerifier};

/// §1.8's merge delay: the promised epoch and the two after it.
pub const MAX_MERGE_DELAY: u8 = 2;

/// A batcher's promise (§1.6, D-68).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedPromise {
    /// The exact leaf the promise binds (INV-SPI-02).
    pub leaf: Digest,
    /// The submission's ordinal identifier, which travels only inside this promise (D-69).
    pub submission_id: SubmissionId,
    /// The first epoch whose root may carry the leaf.
    pub promised_epoch: u64,
    /// How many epochs past `promised_epoch` still satisfy it.
    pub max_merge_delay: u8,
    /// The public half of the key that signed this promise, carried for display. Never the authority.
    pub batcher_key: [u8; 32],
    /// Ed25519 over the SPI digest, which is what §1.6 signs.
    pub signature: [u8; 64],
}

/// The digest §1.6 signs:
/// `Keccak256( TAG_SPI ‖ leaf ‖ submission_id ‖ promised_epoch ‖ max_merge_delay )`.
pub fn promise_digest<H: Hasher>(promise: &SignedPromise) -> Result<Digest> {
    SpiPreimage {
        leaf: promise.leaf,
        submission_id: promise.submission_id,
        promised_epoch: promise.promised_epoch,
        max_merge_delay: promise.max_merge_delay,
    }
    .digest::<H>()
}

/// Checks a promise against the batcher key the counterparty expects (D-68).
///
/// The key a promise carries is not the authority: anyone can sign a promise, so the expected key
/// decides first. A key that is not the expected one is `0x08`, decided before any verification runs,
/// exactly as §1.3's condition (c) decides a qualified person's key. A signature that does not verify
/// is `0x07`.
pub fn verify_promise<H: Hasher, V: Verifier>(
    promise: &SignedPromise,
    expected_batcher_key: &[u8; 32],
) -> Result<()> {
    if &promise.batcher_key != expected_batcher_key {
        return Err(RegistryError::AttestationKeyMismatch);
    }
    let digest = promise_digest::<H>(promise)?;
    V::verify(expected_batcher_key, &digest, &promise.signature)
}

/// Whether a promise was kept.
///
/// The proof must verify for the promise's own leaf against `root`, and `root_epoch` must fall inside
/// the promised window. A root published later than the window confirms the breach rather than
/// rebutting it, and returns `0x14`; a root earlier than the promise is outside the window too. A proof
/// that does not verify is `0x13`, which is also what a proof of some other leaf gives.
pub fn promise_kept<H: Hasher>(
    promise: &SignedPromise,
    proof: &InclusionProof,
    root: &Digest,
    root_epoch: u64,
) -> Result<()> {
    let last = promise
        .promised_epoch
        .checked_add(u64::from(promise.max_merge_delay))
        .ok_or(RegistryError::ArithmeticOverflow)?;
    if root_epoch < promise.promised_epoch || root_epoch > last {
        return Err(RegistryError::MergeDelayExceeded);
    }
    ProofVerifier::verify::<H>(&promise.leaf, proof, root)
}
