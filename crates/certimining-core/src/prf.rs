// SPDX-License-Identifier: MIT OR Apache-2.0
//! E-06: §1.1's PRF and the three inputs §1.4 puts it to (§1.1, §1.2, D-59).
//!
//! `PRF(k, x) = Keccak256(TAG_PRF ‖ k ‖ len(x) ‖ x)`. The tag lives inside the construction and is
//! never repeated in `x`; each `x` carries its use code first, so the three uses cannot collide
//! however their fields line up. `len(x)` is a `u16` little-endian, as INV-ENC-04 requires of every
//! length prefix here, and `k` is 32 bytes (D-59).
//!
//! The PRF is here rather than in `certimining-log` because it is a §1.1 primitive with a §1.2 tag
//! and allocates nothing (D-61). What it is for is in the log crate: slot assignment and padding
//! leaves, both under an epoch key that INV-TREE-05 keeps off every wire.

use crate::preimage::staged;
use crate::{Digest, Hasher, Preimage, PreimageSink, RegistryError, Result, SubmissionId};

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
        // Every `x` in §1.1 begins with a use code, so an empty one is not an input this PRF has.
        if self.input.is_empty() {
            return Err(RegistryError::MalformedPayload);
        }
        if self.input.len() > MAX_PRF_INPUT_LEN {
            return Err(RegistryError::RecordTooLarge);
        }
        let length = u16::try_from(self.input.len()).map_err(|_| RegistryError::RecordTooLarge)?;
        staged(out, |p| {
            p.write(&Self::TAG)?;
            p.write(self.key)?;
            p.write(&length.to_le_bytes())?;
            p.write(self.input)
        })
    }
}

/// `k_e = PRF(k_master, 0x01 ‖ e_le)` (INV-TREE-05). The epoch is a `u64` little-endian (D-59).
///
/// The epoch key never leaves the batcher: it is not published, not carried in a disclosure package
/// and not sent to a counterparty. Count-hiding rests on that, which the specification names as a
/// trust assumption in RES-03 rather than a property of this code.
pub fn epoch_key<H: Hasher>(k_master: &Digest, epoch: u64) -> Result<Digest> {
    let mut input = [0u8; 9];
    let (code, rest) = input.split_at_mut(1);
    code.copy_from_slice(&[PRF_USE_EPOCH_KEY]);
    rest.copy_from_slice(&epoch.to_le_bytes());
    PrfPreimage {
        key: k_master,
        input: &input,
    }
    .digest::<H>()
}

/// `PRF(k_e, 0x02 ‖ submission_id)`, the seed a slot is chosen from (§1.4).
pub fn slot_seed<H: Hasher>(k_e: &Digest, submission_id: &SubmissionId) -> Result<Digest> {
    let mut input = [0u8; 17];
    let (code, rest) = input.split_at_mut(1);
    code.copy_from_slice(&[PRF_USE_SLOT]);
    rest.copy_from_slice(submission_id);
    PrfPreimage {
        key: k_e,
        input: &input,
    }
    .digest::<H>()
}

/// `PRF(k_e, 0x03 ‖ slot_index_le)`, what a padding leaf commits to (§1.4). The slot index is a
/// `u16` little-endian (D-59).
pub fn padding_prf<H: Hasher>(k_e: &Digest, slot_index: u16) -> Result<Digest> {
    let mut input = [0u8; 3];
    let (code, rest) = input.split_at_mut(1);
    code.copy_from_slice(&[PRF_USE_PADDING]);
    rest.copy_from_slice(&slot_index.to_le_bytes());
    PrfPreimage {
        key: k_e,
        input: &input,
    }
    .digest::<H>()
}
