// SPDX-License-Identifier: MIT OR Apache-2.0
//! KAT-02 (§4.1): Ed25519 against RFC 8032 §7.1's own vectors (D-45).
//!
//! The vectors are the RFC's, vendored with their provenance, never the crate's own test data. The
//! verifier under test is the one the engine uses for condition (c).

#![cfg(feature = "native")]

mod kat02;

use certimining_core::{DalekVerifier, RegistryError, Verifier};
use ed25519_dalek::{Signer, SigningKey};

#[test]
fn kat02_every_vector_verifies() {
    let cases = kat02::cases();
    assert_eq!(cases.len(), 5);
    for case in &cases {
        assert_eq!(
            DalekVerifier::verify(&case.public_key, &case.message, &case.signature),
            Ok(()),
            "{}",
            case.name
        );
    }
}

/// Ed25519 is deterministic, so signing the RFC's message with the RFC's secret key has to
/// reproduce the RFC's signature byte for byte. This also checks the signing path the state tests
/// use to build valid records.
#[test]
fn kat02_signing_reproduces_the_published_signature() {
    for case in kat02::cases() {
        let key = SigningKey::from_bytes(&case.secret_key);
        assert_eq!(
            key.verifying_key().to_bytes(),
            case.public_key,
            "{}: the secret key derives a different public key",
            case.name
        );
        assert_eq!(
            key.sign(&case.message).to_bytes(),
            case.signature,
            "{}",
            case.name
        );
    }
}

/// One flipped bit anywhere fails, and fails with `0x07` rather than a panic.
#[test]
fn kat02_a_tampered_vector_is_0x07() {
    for case in kat02::cases() {
        let mut signature = case.signature;
        signature[0] ^= 0x01;
        assert_eq!(
            DalekVerifier::verify(&case.public_key, &case.message, &signature),
            Err(RegistryError::AttestationInvalid),
            "{}: a flipped signature byte",
            case.name
        );

        let mut message = case.message.clone();
        message.push(0x00);
        assert_eq!(
            DalekVerifier::verify(&case.public_key, &message, &case.signature),
            Err(RegistryError::AttestationInvalid),
            "{}: a lengthened message",
            case.name
        );

        let mut key = case.public_key;
        key[0] ^= 0x01;
        assert_eq!(
            DalekVerifier::verify(&key, &case.message, &case.signature),
            Err(RegistryError::AttestationInvalid),
            "{}: a different public key",
            case.name
        );
    }
}

/// A signature made for one vector must not verify under another vector's key or message, which is
/// what V-N-06 turns into at the record level.
#[test]
fn kat02_vectors_do_not_cross_verify() {
    let cases = kat02::cases();
    for (i, case) in cases.iter().enumerate() {
        for (j, other) in cases.iter().enumerate() {
            if i == j {
                continue;
            }
            assert_eq!(
                DalekVerifier::verify(&other.public_key, &case.message, &case.signature),
                Err(RegistryError::AttestationInvalid),
                "{} verified under {}'s key",
                case.name,
                other.name
            );
        }
    }
}

/// A key that is not a point on the curve cannot verify anything, and returns `0x07` rather than
/// panicking.
#[test]
fn kat02_a_malformed_key_is_0x07() {
    let case = kat02::cases().remove(0);
    assert_eq!(
        DalekVerifier::verify(&[0xFF; 32], &case.message, &case.signature),
        Err(RegistryError::AttestationInvalid)
    );
}
