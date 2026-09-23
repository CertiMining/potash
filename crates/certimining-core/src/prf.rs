//! E-06: §1.1's PRF and the three inputs §1.4 puts it to (§1.1, §1.2, D-59).
//!
//! **STUB. This module has no implementation yet (D-65).** Issue #6 requires the §4.4 privacy tests
//! to be written before the construction they test, and the padding whose indistinguishability
//! V-Z-02 measures is this PRF's output. Every entry point here refuses until the next commit.
//!
//! `PRF(k, x) = Keccak256(TAG_PRF ‖ k ‖ len(x) ‖ x)`. The tag lives inside the construction and is
//! never repeated in `x`; each `x` carries its use code first. `len(x)` is a `u16` little-endian
//! (INV-ENC-04, D-59).

use crate::{Digest, Hasher, Preimage, PreimageSink, RegistryError, Result, SubmissionId};

/// STUB (D-65): what every entry point in this module returns until the implementation lands.
const STUB_REFUSAL: RegistryError = RegistryError::MalformedPayload;

/// The PRF's own domain tag (§1.2).
pub const TAG_PRF: [u8; 8] = *b"CMv1PRF0";

/// §1.1's use code for deriving an epoch key from the master key.
pub const PRF_USE_EPOCH_KEY: u8 = 0x01;
/// §1.1's use code for seeding a slot.
pub const PRF_USE_SLOT: u8 = 0x02;
/// §1.1's use code for filling a padding leaf.
pub const PRF_USE_PADDING: u8 = 0x03;

/// The longest `x` schema 1 uses: a use code and a sixteen-byte submission identifier (D-59). A
/// longer input is refused rather than hashed, so a fourth use cannot arrive without a decision.
pub const MAX_PRF_INPUT_LEN: usize = 17;

/// `PRF(k, x)`'s preimage (§1.1). `input` is `x` complete, use code first.
#[derive(Debug, Clone, Copy)]
pub struct PrfPreimage<'a> {
    /// The key: `k_master` under `0x01`, and the epoch key `k_e` under `0x02` and `0x03`.
    pub key: &'a Digest,
    /// `x`, which is the use code followed by that use's one field.
    pub input: &'a [u8],
}

impl Preimage for PrfPreimage<'_> {
    const TAG: [u8; 8] = TAG_PRF;

    fn write_preimage(&self, out: &mut dyn PreimageSink) -> Result<()> {
        // STUB (D-65).
        let _ = out;
        Err(STUB_REFUSAL)
    }
}

/// `k_e = PRF(k_master, 0x01 ‖ e_le)` (INV-TREE-05). The epoch is a `u64` little-endian (D-59).
pub fn epoch_key<H: Hasher>(k_master: &Digest, epoch: u64) -> Result<Digest> {
    // STUB (D-65).
    let _ = (k_master, epoch);
    Err(STUB_REFUSAL)
}

/// `PRF(k_e, 0x02 ‖ submission_id)`, the seed a slot is chosen from (§1.4).
pub fn slot_seed<H: Hasher>(k_e: &Digest, submission_id: &SubmissionId) -> Result<Digest> {
    // STUB (D-65).
    let _ = (k_e, submission_id);
    Err(STUB_REFUSAL)
}

/// `PRF(k_e, 0x03 ‖ slot_index_le)`, what a padding leaf commits to (§1.4). The slot index is a
/// `u16` little-endian (D-59).
pub fn padding_prf<H: Hasher>(k_e: &Digest, slot_index: u16) -> Result<Digest> {
    // STUB (D-65).
    let _ = (k_e, slot_index);
    Err(STUB_REFUSAL)
}
