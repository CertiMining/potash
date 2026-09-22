//! Ed25519 verification (§1.1, D-38).
//!
//! The caller names the implementation, exactly as it names the hasher (D-20). Only the `native`
//! feature carries one, so a program built for Solana has no way to verify a signature, which is
//! what INV-PRIM-02 requires.

use crate::Result;

/// Ed25519 verification, RFC 8032.
pub trait Verifier {
    /// `Ok(())` when `signature` is a valid signature by `public_key` over `message`, and `0x07`
    /// otherwise. A malformed key or signature is also `0x07`: neither verifies.
    fn verify(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> Result<()>;
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
