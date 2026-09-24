/// The engine's error codes (TCU-02 §2.1).
///
/// Codes are stable across versions; a new condition takes a new code, never a changed one.
/// The enum carries no data, so no error value can hold record or asset content (D-03).
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryError {
    HeadMismatch = 0x03,
    SequenceOutOfOrder = 0x04,
    MalformedPayload = 0x05,
    AttestationMissing = 0x06,
    AttestationInvalid = 0x07,
    AttestationKeyMismatch = 0x08,
    /// Reserved: never returned under schema 1 (INV-STATE-06).
    CategorySequenceUnsupported = 0x09,
    NonMonotonicEffectiveAt = 0x0A,
    DomainTagMismatch = 0x0B,
    RecordTooLarge = 0x0C,
    EpochOutOfOrder = 0x0D,
    CheckpointAlreadyWritten = 0x0E,
    UnsupportedSchemaVersion = 0x0F,
    ArithmeticOverflow = 0x10,
    CanonicalizationFailed = 0x11,
    EpochCapacityExceeded = 0x12,
    InclusionProofInvalid = 0x13,
    MergeDelayExceeded = 0x14,
    ReceiptAlreadyAttached = 0x15,
    /// An epoch was asked for a proof of a submission it does not hold (D-67).
    SubmissionNotInEpoch = 0x16,
}

impl RegistryError {
    /// The stable numeric code from §2.1. On-chain, the program reports it as 6000 plus this code.
    pub const fn code(self) -> u16 {
        self as u16
    }
}
