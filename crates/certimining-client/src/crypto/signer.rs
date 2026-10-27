// SPDX-License-Identifier: MIT OR Apache-2.0
//! A fail-closed adapter from an external Ed25519 provider to Solana's signer interface.
//!
//! A provider implementation may call PKCS#11, a cloud KMS, or a secure-enclave service. This
//! module deliberately contains no vendor SDK: provider selection, authentication and sessions are
//! deployment concerns, while this boundary fixes what the anchoring client accepts from them. The
//! provider exposes public-key lookup and Ed25519 signing only; private key bytes never cross it.

use ed25519_dalek::{Signature as DalekSignature, VerifyingKey};
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::{Signer, SignerError};
use std::fmt;

const MAX_KEY_REFERENCE_BYTES: usize = 256;

/// Closed failures an external PKCS#11, KMS, or enclave provider may return.
///
/// These values are safe to surface to an operator. Provider error strings, PINs, session handles
/// and key references are intentionally absent so they cannot enter transaction or worker logs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum HardwareSignerProviderError {
    Unavailable,
    Unauthorized,
    KeyNotFound,
    UnsupportedAlgorithm,
    Refused,
    InvalidResponse,
}

impl fmt::Display for HardwareSignerProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "provider unavailable",
            Self::Unauthorized => "provider authorization failed",
            Self::KeyNotFound => "provider key not found",
            Self::UnsupportedAlgorithm => "provider does not support Ed25519",
            Self::Refused => "provider refused the signing operation",
            Self::InvalidResponse => "provider returned an invalid response",
        })
    }
}

impl std::error::Error for HardwareSignerProviderError {}

/// The narrow interface a PKCS#11, KMS, or secure-enclave integration must implement.
///
/// `key_reference` is an opaque, non-secret locator. It must never contain a PIN, access token,
/// private key, or other credential. The implementation must request raw Ed25519 signing of the
/// exact message bytes; prehash or algorithm substitution is not accepted by `ConsensusSigner`.
pub trait ConsensusSignerBackend: Send + Sync {
    fn public_key(&self, key_reference: &str) -> Result<[u8; 32], HardwareSignerProviderError>;

    fn sign_ed25519(
        &self,
        key_reference: &str,
        message: &[u8],
    ) -> Result<[u8; 64], HardwareSignerProviderError>;

    fn is_interactive(&self) -> bool {
        false
    }
}

/// Failures at the hardware-backed consensus signing boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HardwareSignerError {
    EmptyKeyReference,
    KeyReferenceTooLong,
    KeyReferenceContainsControl,
    InvalidPublicKey,
    PublicKeyMismatch,
    InvalidSignature,
    Provider(HardwareSignerProviderError),
}

impl fmt::Display for HardwareSignerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyKeyReference => formatter.write_str("key reference is empty"),
            Self::KeyReferenceTooLong => formatter.write_str("key reference exceeds 256 bytes"),
            Self::KeyReferenceContainsControl => {
                formatter.write_str("key reference contains a control character")
            }
            Self::InvalidPublicKey => formatter.write_str("configured public key is not Ed25519"),
            Self::PublicKeyMismatch => {
                formatter.write_str("provider public key does not match the authority manifest")
            }
            Self::InvalidSignature => {
                formatter.write_str("provider signature does not verify for the requested message")
            }
            Self::Provider(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for HardwareSignerError {}

impl From<HardwareSignerProviderError> for HardwareSignerError {
    fn from(error: HardwareSignerProviderError) -> Self {
        Self::Provider(error)
    }
}

/// A Solana transaction signer backed by an external Ed25519 provider.
///
/// Construction pins the provider's key to the public authority manifest. Every returned signature
/// is then verified locally before it is admitted to a transaction, so a wrong key, altered message,
/// algorithm substitution or corrupt provider response fails before submission.
pub struct ConsensusSigner<B> {
    backend: B,
    key_reference: String,
    verifying_key: VerifyingKey,
}

impl<B: ConsensusSignerBackend> ConsensusSigner<B> {
    pub fn connect(
        backend: B,
        key_reference: impl Into<String>,
        expected_public_key: [u8; 32],
    ) -> Result<Self, HardwareSignerError> {
        let key_reference = key_reference.into();
        validate_key_reference(&key_reference)?;
        let verifying_key = VerifyingKey::from_bytes(&expected_public_key)
            .map_err(|_| HardwareSignerError::InvalidPublicKey)?;
        let provider_public_key = backend.public_key(&key_reference)?;
        if provider_public_key != expected_public_key {
            return Err(HardwareSignerError::PublicKeyMismatch);
        }
        Ok(Self {
            backend,
            key_reference,
            verifying_key,
        })
    }

    pub fn authority(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }
}

impl<B: ConsensusSignerBackend> Signer for ConsensusSigner<B> {
    fn try_pubkey(&self) -> Result<Pubkey, SignerError> {
        Ok(Pubkey::from(self.authority()))
    }

    fn try_sign_message(&self, message: &[u8]) -> Result<Signature, SignerError> {
        let signature = self
            .backend
            .sign_ed25519(&self.key_reference, message)
            .map_err(HardwareSignerError::from)
            .and_then(|signature| {
                verify_with_key(&self.verifying_key, message, &signature)?;
                Ok(signature)
            })
            .map_err(|error| SignerError::Custom(format!("consensus signer: {error}")))?;
        Ok(Signature::from(signature))
    }

    fn is_interactive(&self) -> bool {
        self.backend.is_interactive()
    }
}

/// Verify an offline HSM/KMS possession challenge against the pinned authority identity.
pub fn verify_consensus_signature(
    public_key: &[u8; 32],
    message: &[u8],
    signature: &[u8; 64],
) -> Result<(), HardwareSignerError> {
    let verifying_key =
        VerifyingKey::from_bytes(public_key).map_err(|_| HardwareSignerError::InvalidPublicKey)?;
    verify_with_key(&verifying_key, message, signature)
}

fn verify_with_key(
    verifying_key: &VerifyingKey,
    message: &[u8],
    signature: &[u8; 64],
) -> Result<(), HardwareSignerError> {
    let signature = DalekSignature::from_bytes(signature);
    verifying_key
        .verify_strict(message, &signature)
        .map_err(|_| HardwareSignerError::InvalidSignature)
}

fn validate_key_reference(key_reference: &str) -> Result<(), HardwareSignerError> {
    if key_reference.is_empty() {
        return Err(HardwareSignerError::EmptyKeyReference);
    }
    if key_reference.len() > MAX_KEY_REFERENCE_BYTES {
        return Err(HardwareSignerError::KeyReferenceTooLong);
    }
    if key_reference.chars().any(char::is_control) {
        return Err(HardwareSignerError::KeyReferenceContainsControl);
    }
    Ok(())
}

impl<B> fmt::Debug for ConsensusSigner<B> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConsensusSigner")
            .field("authority", &self.verifying_key.to_bytes())
            .field("key_reference", &"[redacted]")
            .finish_non_exhaustive()
    }
}
