//! Canonical tenure identifiers and the asset commitment (TCU-02 §1.3; D-22 to D-26).
//!
//! A tenure identifier is canonicalized by Unicode NFKD, then uppercasing of a to z only, then
//! removal of every character other than A–Z and 0–9; the result is 1 to 64 bytes. The asset
//! commitment is `Keccak256(TAG_ASSET ‖ J ‖ R ‖ len(T) ‖ T)`, a local identifier that never leaves
//! the issuer's control (INV-STATE-03).

use core::marker::PhantomData;

use unicode_normalization::UnicodeNormalization;

use crate::preimage::{AssetPreimage, Preimage};
use crate::{Digest, Hasher, RegistryError, Result};

/// Domain tag of the asset commitment (§1.2).
pub const TAG_ASSET: [u8; 8] = *b"CMv1ASST";

/// Longest canonical tenure identifier, in bytes (§1.8).
pub const MAX_TENURE_LEN: usize = 64;

/// Longest raw tenure identifier accepted, in bytes (§1.8, D-25).
pub const MAX_RAW_TENURE_LEN: usize = 256;

/// A canonical tenure identifier: 1 to 64 bytes, each A–Z or 0–9.
pub type CanonicalTenure = heapless::Vec<u8, MAX_TENURE_LEN>;

/// Canonical asset identity (§2.2). Every failure is `CanonicalizationFailed` (0x11).
pub trait AssetIdentity {
    /// Canonicalizes a tenure identifier given as text.
    fn canonicalize(tenure_raw: &str) -> Result<CanonicalTenure>;

    /// Canonicalizes raw bytes, which may not be valid UTF-8 (D-24).
    fn canonicalize_bytes(tenure_raw: &[u8]) -> Result<CanonicalTenure>;

    /// The asset commitment `c`. Refuses a tenure that is not already canonical (D-26).
    fn commitment(j: &[u8; 4], r: &[u8; 8], tenure: &[u8]) -> Result<Digest>;
}

/// [`AssetIdentity`] with its Keccak-256 hasher named explicitly (D-20). Only `commitment` hashes.
pub struct AssetId<H>(PhantomData<H>);

impl<H: Hasher> AssetIdentity for AssetId<H> {
    fn canonicalize(tenure_raw: &str) -> Result<CanonicalTenure> {
        Self::canonicalize_bytes(tenure_raw.as_bytes())
    }

    fn canonicalize_bytes(tenure_raw: &[u8]) -> Result<CanonicalTenure> {
        // The input is bounded before any normalization work (D-25).
        if tenure_raw.len() > MAX_RAW_TENURE_LEN {
            return Err(RegistryError::CanonicalizationFailed);
        }
        let text =
            core::str::from_utf8(tenure_raw).map_err(|_| RegistryError::CanonicalizationFailed)?;
        let mut out = CanonicalTenure::new();
        // NFKD separates accents from their letters (D-22); only a to z are uppercased (D-23).
        for ch in text.nfkd().map(|c| c.to_ascii_uppercase()) {
            if ch.is_ascii_uppercase() || ch.is_ascii_digit() {
                let byte = u8::try_from(ch).map_err(|_| RegistryError::CanonicalizationFailed)?;
                // A 65th byte does not fit: the canonical form is at most 64 bytes (§1.8).
                out.push(byte)
                    .map_err(|_| RegistryError::CanonicalizationFailed)?;
            }
        }
        if out.is_empty() {
            return Err(RegistryError::CanonicalizationFailed);
        }
        Ok(out)
    }

    fn commitment(j: &[u8; 4], r: &[u8; 8], tenure: &[u8]) -> Result<Digest> {
        // One writer builds this preimage, here and at every other call site (E-03). It refuses a
        // non-canonical tenure with 0x11, as D-26 requires.
        AssetPreimage {
            jurisdiction: j,
            registry: r,
            tenure,
        }
        .digest::<H>()
    }
}

/// True when `tenure` is 1 to 64 bytes, each A–Z or 0–9 (D-26). The asset preimage writer of E-03
/// applies the same rule, from this one definition.
pub(crate) fn is_canonical(tenure: &[u8]) -> bool {
    !tenure.is_empty()
        && tenure.len() <= MAX_TENURE_LEN
        && tenure
            .iter()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
}
