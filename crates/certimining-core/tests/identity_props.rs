// SPDX-License-Identifier: MIT OR Apache-2.0
//! E-02's property tests (§3 E-02): canonicalization is total, never panics on any input,
//! including invalid UTF-8, is idempotent, and gives the same answer through either entry point.

use certimining_core::{AssetId, AssetIdentity, Digest, Hasher, RegistryError};
use proptest::prelude::*;

/// Canonicalization never hashes, so a stand-in hasher keeps these tests in every feature set.
struct NoHash;

impl Hasher for NoHash {
    fn hashv(_parts: &[&[u8]]) -> Digest {
        [0; 32]
    }
}

type Id = AssetId<NoHash>;

/// Fewer cases under Miri, which interprets every instruction; no regression files are written.
fn config() -> ProptestConfig {
    ProptestConfig {
        cases: if cfg!(miri) { 8 } else { 1024 },
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

proptest! {
    #![proptest_config(config())]

    /// Total: any bytes, including invalid UTF-8 and input over the 256-byte limit, give either a
    /// canonical form (1 to 64 bytes of A–Z and 0–9) or 0x11, and never a panic.
    #[test]
    fn total_on_any_bytes(raw in prop::collection::vec(any::<u8>(), 0..320)) {
        match Id::canonicalize_bytes(&raw) {
            Ok(t) => prop_assert!(
                !t.is_empty() && t.len() <= 64 && t.iter().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
            ),
            Err(e) => prop_assert_eq!(e, RegistryError::CanonicalizationFailed),
        }
    }

    /// Idempotent: canonicalizing a canonical form returns it unchanged.
    #[test]
    fn idempotent(raw in any::<String>()) {
        if let Ok(t) = Id::canonicalize(&raw) {
            prop_assert_eq!(Id::canonicalize_bytes(&t).map(|u| u.to_vec()), Ok(t.to_vec()));
        }
    }

    /// The text and bytes entry points agree on every string (D-24).
    #[test]
    fn both_entry_points_agree(raw in any::<String>()) {
        prop_assert_eq!(
            Id::canonicalize(&raw).map(|t| t.to_vec()),
            Id::canonicalize_bytes(raw.as_bytes()).map(|t| t.to_vec())
        );
    }
}
