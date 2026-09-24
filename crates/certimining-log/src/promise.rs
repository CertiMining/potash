//! Signed inclusion promises, and what they can be used to show (§1.6, §2.3).
//!
//! **STUB. This module has no implementation yet (D-65).** The batcher seals epoch trees, so S4's rule
//! applies: the tests come first and every entry point here refuses until the next commit.
//!
//! A promise is the anti-censorship device. It binds one leaf to one epoch window under the batcher's
//! key, and a counterparty checks it without the batcher. What it cannot do is prove absence: only the
//! batcher can show a leaf is present, so an unsatisfied promise is a transferable accusation the
//! batcher may rebut with an inclusion proof, and a rebuttal counts only inside the window (D-72).

use certimining_core::{Digest, Hasher, RegistryError, Result, SubmissionId, Verifier};

use crate::InclusionProof;

/// STUB (D-65).
const STUB_REFUSAL: RegistryError = RegistryError::AttestationInvalid;

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

/// The digest §1.6 signs: `Keccak256( TAG_SPI ‖ leaf ‖ submission_id ‖ promised_epoch ‖ max_merge_delay )`.
///
/// Note the difference from a record's attestation, which signs the leaf **preimage**: §1.6 signs the
/// SPI **digest**, so the message is 32 bytes.
pub fn promise_digest<H: Hasher>(promise: &SignedPromise) -> Result<Digest> {
    let _ = promise;
    Err(STUB_REFUSAL)
}

/// Checks a promise against the batcher key the counterparty expects (D-68). A key that is not the
/// expected one is `0x08` and is decided before any verification runs; a signature that does not
/// verify is `0x07`.
pub fn verify_promise<H: Hasher, V: Verifier>(
    promise: &SignedPromise,
    expected_batcher_key: &[u8; 32],
) -> Result<()> {
    let _ = (promise, expected_batcher_key);
    Err(STUB_REFUSAL)
}

/// Whether a promise was kept: the proof must verify for the promise's leaf against `root`, and
/// `root_epoch` must fall inside the promised window. A root published later than the window confirms
/// the breach rather than rebutting it, and is `0x14` (D-72).
pub fn promise_kept<H: Hasher>(
    promise: &SignedPromise,
    proof: &InclusionProof,
    root: &Digest,
    root_epoch: u64,
) -> Result<()> {
    let _ = (promise, proof, root, root_epoch);
    Err(STUB_REFUSAL)
}
