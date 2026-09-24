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

/// The number of octets a promise encodes to (L-01): 32 + 16 + 8 + 1 + 32 + 64.
pub const PROMISE_ENCODED_LEN: usize = 153;

/// An epoch's root as the caller obtained it from a published checkpoint.
///
/// The two travel together because a root without its epoch says nothing about when it was published,
/// and an epoch beside a root it did not come from says nothing at all. **This type does not establish
/// provenance and cannot:** nothing inside this crate proves the pair was ever published. The caller
/// reads it from the checkpoint account E-08 writes and E-09 fetches, and the type exists so the two
/// halves cannot drift apart between there and here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublishedRoot {
    /// The epoch the checkpoint was published for.
    pub epoch: u64,
    /// The root it published.
    pub root: Digest,
}

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

impl SignedPromise {
    /// The promise as octets, in §1.6's field order followed by the key and the signature.
    ///
    /// This is the transferable artifact's encoding. The Rust value is not it: `size_of` includes
    /// padding and says nothing about what travels between two parties (L-01).
    pub fn encode(&self) -> [u8; PROMISE_ENCODED_LEN] {
        let mut out = [0u8; PROMISE_ENCODED_LEN];
        let (leaf, rest) = out.split_at_mut(32);
        leaf.copy_from_slice(&self.leaf);
        let (id, rest) = rest.split_at_mut(16);
        id.copy_from_slice(&self.submission_id);
        let (epoch, rest) = rest.split_at_mut(8);
        epoch.copy_from_slice(&self.promised_epoch.to_le_bytes());
        let (delay, rest) = rest.split_at_mut(1);
        delay.copy_from_slice(&[self.max_merge_delay]);
        let (key, signature) = rest.split_at_mut(32);
        key.copy_from_slice(&self.batcher_key);
        signature.copy_from_slice(&self.signature);
        out
    }
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
    // A signature proves authorship, not compliance. INV-SPI-01 fixes the merge delay at 2, so a
    // correctly signed promise carrying any other value is refused rather than authenticated: the key
    // holder does not get to choose the policy the promise is judged against (H-01).
    if promise.max_merge_delay != MAX_MERGE_DELAY {
        return Err(RegistryError::MalformedPayload);
    }
    let digest = promise_digest::<H>(promise)?;
    V::verify(expected_batcher_key, &digest, &promise.signature)
}

/// Whether a promise was kept, as far as anything here can tell.
///
/// The proof must be for the same epoch as the root it is checked against, that epoch must fall inside
/// the promised window, and the path must verify for the promise's own leaf. A root outside the window
/// in either direction is `0x14`; an inconsistent or failing proof is `0x13`.
///
/// **What this does not do.** It does not establish that `published` was ever published. D-72's rule is
/// that only a root published inside the window rebuts the accusation, and publication provenance comes
/// from the checkpoint account E-08 writes, which E-09 fetches and hands here. This function enforces
/// consistency between what it is given; the seam where provenance enters is the caller's, and it is
/// named rather than implied (H-02).
pub fn promise_kept<H: Hasher>(
    promise: &SignedPromise,
    proof: &InclusionProof,
    published: &PublishedRoot,
) -> Result<()> {
    // The proof must be for the epoch whose root it is being checked against. A proof carries its own
    // epoch and the Merkle path does not commit to it, so this is a consistency check and not a proof
    // of anything: what makes `published` trustworthy is where the caller got it (H-02).
    if proof.epoch != published.epoch {
        return Err(RegistryError::InclusionProofInvalid);
    }
    let last = promise
        .promised_epoch
        .checked_add(u64::from(promise.max_merge_delay))
        .ok_or(RegistryError::ArithmeticOverflow)?;
    if published.epoch < promise.promised_epoch || published.epoch > last {
        return Err(RegistryError::MergeDelayExceeded);
    }
    ProofVerifier::verify::<H>(&promise.leaf, proof, &published.root)
}
