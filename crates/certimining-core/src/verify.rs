//! Ed25519 verification and signing (§1.1, §2.2, D-38, D-73).
//!
//! The caller names the implementation, exactly as it names the hasher (D-20). Only the `native`
//! feature carries a verifier, so a program built for Solana has no way to verify a signature, which
//! is what INV-PRIM-02 requires.
//!
//! **No signer implementation lives here, under any feature.** `Signer` is a trait and nothing more:
//! a signer holds a key, and S6 keeps the batcher key outside this repository, so the engine is given
//! nowhere to put one. The tests supply RFC 8032 §7.1's published key through the trait, and the
//! service at E-09 supplies a real one from outside.

use crate::Result;

/// Ed25519 verification, RFC 8032.
pub trait Verifier {
    /// `Ok(())` when `signature` is a valid signature by `public_key` over `message`, and `0x07`
    /// otherwise. A malformed key or signature is also `0x07`: neither verifies.
    fn verify(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> Result<()>;
}

/// Ed25519 signing, for the batcher's promises of §1.6 (D-73).
///
/// `&self` because an implementation holds a key. Nothing in this crate implements it.
pub trait Signer {
    /// A signature by the held key over `message`.
    fn sign(&self, message: &[u8]) -> Result<[u8; 64]>;
    /// The public half, which a promise carries so a counterparty can see which key signed it.
    fn public_key(&self) -> [u8; 32];
}

/// Ed25519 through `ed25519-dalek` 2.2.0 (D-39). Off-chain only.
#[cfg(feature = "native")]
#[derive(Debug, Clone, Copy)]
pub struct DalekVerifier;

#[cfg(feature = "native")]
impl Verifier for DalekVerifier {
    fn verify(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> Result<()> {
        use ed25519_dalek::{Signature, VerifyingKey};
        let key = VerifyingKey::from_bytes(public_key)
            .map_err(|_| crate::RegistryError::AttestationInvalid)?;
        // verify_strict rejects the small-order and non-canonical keys that plain verification
        // accepts, so one signature cannot be made to verify under two different keys.
        key.verify_strict(message, &Signature::from_bytes(signature))
            .map_err(|_| crate::RegistryError::AttestationInvalid)
    }
}
