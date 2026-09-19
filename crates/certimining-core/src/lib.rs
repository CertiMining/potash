//! `certimining-core`: digests and state rules for the CertiMining anchored log (TCU-02).
//!
//! E-01 provides the error space (§2.1), the digest types (§2.2) and the Keccak-256 hashers (§1.1).
//! E-02 adds canonical tenure identifiers and the asset commitment (§1.3). The crate is `no_std`
//! and has no Solana dependency outside the `solana` feature (§2).

// no_std everywhere except the unit-test harness, which needs std.
#![cfg_attr(not(test), no_std)]
// INV-ERR-01: no unsafe code, unwrap, expect, unchecked indexing or wrapping arithmetic.
#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod error;
mod hash;
mod identity;

pub use error::RegistryError;
pub use hash::Hasher;
#[cfg(feature = "native")]
pub use hash::NativeKeccak;
#[cfg(feature = "solana")]
pub use hash::SolanaKeccak;
pub use identity::{
    AssetId, AssetIdentity, CanonicalTenure, MAX_RAW_TENURE_LEN, MAX_TENURE_LEN, TAG_ASSET,
};

/// A 32-byte digest (§2.2).
pub type Digest = [u8; 32];

/// The result of every fallible operation in the engine (§2.2).
pub type Result<T> = core::result::Result<T, RegistryError>;
