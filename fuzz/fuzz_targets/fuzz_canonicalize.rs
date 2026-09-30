//! F-02: arbitrary bytes and invalid UTF-8 into canonicalization.
//!
//! §4.5 asks for a million iterations with output no longer than 64 bytes or a clean `0x11`. §1.3
//! fixes the rule: NFKD, then uppercasing of a to z only, then removal of everything outside A–Z and
//! 0–9, with raw input over 256 bytes, invalid UTF-8, or an empty or over-long result returning
//! `0x11`.
//!
//! What this asserts on every input, rather than only that it did not panic:
//!
//! 1. The result is `Ok` or `0x11`, never another code and never a panic.
//! 2. An accepted result is 1 to 64 bytes.
//! 3. An accepted result is already canonical — feeding it back returns itself. A canonicalization
//!    that is not idempotent would make one tenure hash two ways depending on how often it had been
//!    through, which is the defect INV-ENC-01 exists to prevent.
//! 4. An accepted result contains only A–Z and 0–9.
#![no_main]

use certimining_core::{AssetId, AssetIdentity, NativeKeccak, RegistryError};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let first = match AssetId::<NativeKeccak>::canonicalize_bytes(data) {
        Ok(t) => t,
        Err(RegistryError::CanonicalizationFailed) => return,
        Err(other) => panic!("canonicalize returned {other:?}, and §1.3 allows only 0x11"),
    };

    let bytes = first.as_slice();
    assert!(
        (1..=64).contains(&bytes.len()),
        "accepted a canonical tenure of {} bytes; §1.3 fixes 1 to 64",
        bytes.len()
    );
    assert!(
        bytes
            .iter()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit()),
        "accepted {:?}, which carries something outside A-Z and 0-9",
        core::str::from_utf8(bytes)
    );

    let again = AssetId::<NativeKeccak>::canonicalize_bytes(bytes)
        .expect("a canonical tenure canonicalizes to itself");
    assert_eq!(
        again.as_slice(),
        bytes,
        "canonicalization is not idempotent: one tenure would hash two ways"
    );
});
