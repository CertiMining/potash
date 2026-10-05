// SPDX-License-Identifier: MIT OR Apache-2.0
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

/// §1.3's canonical alphabet, and the examples `docs/canonicalization.md` publishes — transcribed from
/// that document rather than read out of the implementation, so a defect in the rules cannot agree with
/// the oracle about what they are (M-02's lesson, applied here before it was reported).
const SPEC_EXAMPLES: &[(&str, &str)] = &[
    ("bc-tenure 1043-a", "BCTENURE1043A"),
    ("BC_TENURE1043A", "BCTENURE1043A"),
    ("Mine Élan 12", "MINEELAN12"),
    ("Ｂ①ﬁ", "B1FI"),
    ("Cœur 7", "CUR7"),
    ("straße 3", "STRAE3"),
];

/// Arbitrary bytes reduced to something the rules **must** accept: A–Z and 0–9 only, 1 to 64 of them.
///
/// Returns `None` when nothing survives, which is a refusal the rules require rather than a gap.
fn a_valid_tenure(data: &[u8]) -> Option<Vec<u8>> {
    let kept: Vec<u8> = data
        .iter()
        .copied()
        .map(|b| b.to_ascii_uppercase())
        .filter(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
        .take(64)
        .collect();
    (!kept.is_empty()).then_some(kept)
}

fuzz_target!(|data: &[u8]| {
    // **The positive obligation (M-03).** Every assertion in this target used to sit downstream of a
    // successful canonicalization, and `Err(CanonicalizationFailed) => return` meant a rules engine that
    // refused *everything* passed 100,000 iterations. §1.3's rules accept the alphabet they define, and a
    // target that cannot notice them refusing it is not a gate.
    for (raw, expected) in SPEC_EXAMPLES {
        let got = AssetId::<NativeKeccak>::canonicalize_bytes(raw.as_bytes()).unwrap_or_else(|e| {
            panic!("docs/canonicalization.md says {raw:?} canonicalizes to {expected:?}, and the rules returned {e:?}")
        });
        assert_eq!(
            core::str::from_utf8(got.as_slice()).expect("canonical output is ASCII"),
            *expected,
            "{raw:?} did not canonicalize to the form the specification publishes"
        );
    }

    // And the same obligation over arbitrary content rather than six constants: anything already in the
    // canonical alphabet must be accepted and must be its own canonical form.
    if let Some(already_canonical) = a_valid_tenure(data) {
        let got =
            AssetId::<NativeKeccak>::canonicalize_bytes(&already_canonical).unwrap_or_else(|e| {
                panic!(
                    "{:?} is A-Z and 0-9 within §1.3's bounds and was refused with {e:?}",
                    core::str::from_utf8(&already_canonical)
                )
            });
        assert_eq!(
            got.as_slice(),
            &already_canonical[..],
            "a tenure already in canonical form did not canonicalize to itself"
        );
    }

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
