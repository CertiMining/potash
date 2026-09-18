//! The §2.1 error codes, checked one by one against the spec (S2), and the D-03 privacy property:
//! an error value is a bare two-byte code with no room for record or asset content.

use certimining_core::RegistryError::{self, *};

/// Every variant, in code order.
const ALL: [RegistryError; 19] = [
    HeadMismatch,
    SequenceOutOfOrder,
    MalformedPayload,
    AttestationMissing,
    AttestationInvalid,
    AttestationKeyMismatch,
    CategorySequenceUnsupported,
    NonMonotonicEffectiveAt,
    DomainTagMismatch,
    RecordTooLarge,
    EpochOutOfOrder,
    CheckpointAlreadyWritten,
    UnsupportedSchemaVersion,
    ArithmeticOverflow,
    CanonicalizationFailed,
    EpochCapacityExceeded,
    InclusionProofInvalid,
    MergeDelayExceeded,
    ReceiptAlreadyAttached,
];

/// Transcribed from TCU-02 §2.1. The match is exhaustive, so a new variant fails to compile here
/// until its code is checked against the spec.
fn spec_code(e: RegistryError) -> u16 {
    match e {
        HeadMismatch => 0x03,
        SequenceOutOfOrder => 0x04,
        MalformedPayload => 0x05,
        AttestationMissing => 0x06,
        AttestationInvalid => 0x07,
        AttestationKeyMismatch => 0x08,
        CategorySequenceUnsupported => 0x09,
        NonMonotonicEffectiveAt => 0x0A,
        DomainTagMismatch => 0x0B,
        RecordTooLarge => 0x0C,
        EpochOutOfOrder => 0x0D,
        CheckpointAlreadyWritten => 0x0E,
        UnsupportedSchemaVersion => 0x0F,
        ArithmeticOverflow => 0x10,
        CanonicalizationFailed => 0x11,
        EpochCapacityExceeded => 0x12,
        InclusionProofInvalid => 0x13,
        MergeDelayExceeded => 0x14,
        ReceiptAlreadyAttached => 0x15,
    }
}

#[test]
fn every_code_matches_the_spec() {
    for e in ALL {
        assert_eq!(e.code(), spec_code(e), "{e:?}");
    }
}

#[test]
fn the_codes_are_exactly_0x03_to_0x15_including_reserved_0x09() {
    let codes: Vec<u16> = ALL.iter().map(|e| e.code()).collect();
    assert_eq!(codes, (0x03..=0x15).collect::<Vec<u16>>());
    assert_eq!(CategorySequenceUnsupported.code(), 0x09);
}

/// D-03, proven by a test rather than by review: a fieldless `#[repr(u16)]` enum is exactly two
/// bytes, so a variant that carried any data would change this size and fail here.
#[test]
fn an_error_is_a_bare_two_byte_code() {
    assert_eq!(core::mem::size_of::<RegistryError>(), 2);
}
