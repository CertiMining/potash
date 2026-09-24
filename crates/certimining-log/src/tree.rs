//! The fixed-capacity epoch tree (§1.4, §2.3).
//!
//! Every epoch is a complete tree of the same height. Real leaves sit in slots chosen by a PRF under
//! the epoch key, every remaining slot carries PRF padding, and the root is published whatever the
//! record count was: an epoch holding one filing and an epoch holding two hundred are identical in
//! leaf count, proof length and root distribution (INV-TREE-01, INV-TREE-02).
//!
//! What this does not carry: the batcher's queue and the overflow discipline of INV-TREE-04, which
//! are E-07's. `build` refuses more submissions than `C` with `0x12` and leaves the queueing to its
//! caller.

use alloc::vec;
use alloc::vec::Vec;

use certimining_core::{
    epoch_key, padding_prf, slot_seed, Digest, Hasher, NodePreimage, PaddingPreimage, Preimage,
    RealLeafPreimage, RegistryError, Result, SubmissionId,
};

use crate::{InclusionProof, MAX_SIBLINGS};

/// §1.8's range for the tree height, fixed at `initialize` and immutable thereafter (INV-TREE-06).
pub const MIN_HEIGHT: u8 = 4;
/// The upper end of §1.8's range.
pub const MAX_HEIGHT: u8 = 16;

/// What one sealed epoch carries (§2.3, D-62).
///
/// Nothing here marks a slot real or padding. That distinction is what V-Z-02 tries to recover from
/// a root and a leaf set, so it is not written down where a later caller could reach it.
#[derive(Debug, Clone)]
pub struct BuiltEpoch {
    /// The epoch this tree is for, a UTC day index (§1.4).
    pub epoch: u64,
    /// The height every epoch of this log uses (INV-TREE-06).
    pub height: u8,
    /// The root the checkpoint publishes.
    pub root: Digest,
    /// Every slot's leaf digest, in slot order, exactly `C` of them.
    pub leaves: Vec<Digest>,
    /// Submission identifier to slot, ascending by identifier (D-60).
    pub assignment: Vec<(SubmissionId, u16)>,
    /// Levels 1 to `H` concatenated, `C - 1` digests, so a proof costs `H` lookups rather than a
    /// rebuild. An implementation detail of the builder rather than part of the contract (D-62).
    nodes: Vec<Digest>,
}

/// §1.4's tree, built once per epoch (§2.3).
pub trait EpochTree {
    /// The height this tree was built at.
    fn height(&self) -> u8;
    /// `C`, which is `1 << height()`.
    fn capacity(&self) -> usize;
    /// Builds one epoch. `key` is `k_master`: the epoch key is derived here from the epoch, so no
    /// caller can reuse one `k_e` across epochs (INV-TREE-05, D-63). The hasher is named at the call
    /// site, as it is for every digest in §2.2.
    fn build<H: Hasher>(
        epoch: u64,
        height: u8,
        key: &Digest,
        real: &[(SubmissionId, Digest)],
    ) -> Result<BuiltEpoch>;
    /// The epoch root.
    fn root(&self) -> Digest;
    /// The inclusion proof for a submission this epoch holds. A submission it does not hold is
    /// `0x16`, which is its own condition and so takes its own code (D-67).
    fn proof(&self, id: &SubmissionId) -> Result<InclusionProof>;
}

impl EpochTree for BuiltEpoch {
    fn height(&self) -> u8 {
        self.height
    }

    fn capacity(&self) -> usize {
        self.leaves.len()
    }

    fn build<H: Hasher>(
        epoch: u64,
        height: u8,
        key: &Digest,
        real: &[(SubmissionId, Digest)],
    ) -> Result<BuiltEpoch> {
        let capacity = capacity_of(height)?;
        if real.len() > capacity {
            return Err(RegistryError::EpochCapacityExceeded);
        }

        // The epoch key, derived from the master key and this epoch (INV-TREE-05).
        let k_e = epoch_key::<H>(key, epoch)?;

        // Ascending by identifier, so one set of submissions gives one tree whatever order the
        // caller supplied them in (D-60). Two submissions under one identifier make the set
        // malformed: a proof could be answered for neither.
        let mut ordered: Vec<(SubmissionId, Digest)> = real.to_vec();
        ordered.sort_unstable_by_key(|entry| entry.0);
        if ordered
            .windows(2)
            .any(|pair| matches!(pair, [left, right] if left.0 == right.0))
        {
            return Err(RegistryError::MalformedPayload);
        }

        let mut slots: Vec<Option<Digest>> = vec![None; capacity];
        let mut assignment: Vec<(SubmissionId, u16)> = Vec::new();
        for (id, leaf) in &ordered {
            let seed = slot_seed::<H>(&k_e, id)?;
            let slot = probe(&slots, slot_from_seed(&seed, height)?, capacity)?;
            let digest = RealLeafPreimage { leaf: *leaf }.digest::<H>()?;
            let cell = slots
                .get_mut(usize::from(slot))
                .ok_or(RegistryError::ArithmeticOverflow)?;
            *cell = Some(digest);
            assignment.push((*id, slot));
        }

        // Padding fills every slot the assignment left empty, each committing to the PRF output for
        // its own index (§1.4).
        let mut leaves: Vec<Digest> = Vec::new();
        for (index, slot) in slots.iter().enumerate() {
            match slot {
                Some(digest) => leaves.push(*digest),
                None => {
                    let index =
                        u16::try_from(index).map_err(|_| RegistryError::ArithmeticOverflow)?;
                    let prf_output = padding_prf::<H>(&k_e, index)?;
                    leaves.push(PaddingPreimage { prf_output }.digest::<H>()?);
                }
            }
        }

        let (nodes, root) = levels_above::<H>(&leaves)?;
        Ok(BuiltEpoch {
            epoch,
            height,
            root,
            leaves,
            assignment,
            nodes,
        })
    }

    fn root(&self) -> Digest {
        self.root
    }

    fn proof(&self, id: &SubmissionId) -> Result<InclusionProof> {
        let slot = self
            .assignment
            .iter()
            .find(|(candidate, _)| candidate == id)
            .map(|(_, slot)| *slot)
            .ok_or(RegistryError::SubmissionNotInEpoch)?;
        let capacity = self.leaves.len();
        let mut siblings: heapless::Vec<Digest, MAX_SIBLINGS> = heapless::Vec::new();
        let mut index = usize::from(slot);
        for level in 0..usize::from(self.height) {
            // The sibling shares every bit above this level and differs in this one (D-64).
            let sibling = index ^ 1;
            let digest = if level == 0 {
                self.leaves.get(sibling)
            } else {
                let offset = level_offset(level, capacity)?;
                self.nodes.get(
                    offset
                        .checked_add(sibling)
                        .ok_or(RegistryError::ArithmeticOverflow)?,
                )
            };
            siblings
                .push(*digest.ok_or(RegistryError::InclusionProofInvalid)?)
                .map_err(|_| RegistryError::InclusionProofInvalid)?;
            index = index
                .checked_shr(1)
                .ok_or(RegistryError::ArithmeticOverflow)?;
        }
        Ok(InclusionProof {
            height: self.height,
            siblings,
            slot_index: slot,
            epoch: self.epoch,
        })
    }
}

/// §1.4's reduction (D-60): the seed read as a little-endian integer and reduced modulo `C`. Because
/// `C` is a power of two this is the low `H` bits, which lie in the digest's first two bytes.
pub fn slot_from_seed(seed: &Digest, height: u8) -> Result<u16> {
    if !(MIN_HEIGHT..=MAX_HEIGHT).contains(&height) {
        return Err(RegistryError::MalformedPayload);
    }
    let low: [u8; 2] = seed
        .get(..2)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(RegistryError::MalformedPayload)?;
    let value = u16::from_le_bytes(low);
    if height == MAX_HEIGHT {
        // Every bit of the pair is in range, and `1 << 16` does not fit a `u16`.
        return Ok(value);
    }
    let mask = 1u16
        .checked_shl(u32::from(height))
        .and_then(|bound| bound.checked_sub(1))
        .ok_or(RegistryError::ArithmeticOverflow)?;
    Ok(value & mask)
}

/// `C` for a height inside §1.8's range.
fn capacity_of(height: u8) -> Result<usize> {
    if !(MIN_HEIGHT..=MAX_HEIGHT).contains(&height) {
        return Err(RegistryError::MalformedPayload);
    }
    1usize
        .checked_shl(u32::from(height))
        .ok_or(RegistryError::ArithmeticOverflow)
}

/// The first free slot at or after `start`, stepping upward by one and wrapping at `C` (D-60).
fn probe(slots: &[Option<Digest>], start: u16, capacity: usize) -> Result<u16> {
    let start = usize::from(start);
    for step in 0..capacity {
        let index = start
            .checked_add(step)
            .and_then(|sum| sum.checked_rem(capacity))
            .ok_or(RegistryError::ArithmeticOverflow)?;
        if slots
            .get(index)
            .ok_or(RegistryError::ArithmeticOverflow)?
            .is_none()
        {
            return u16::try_from(index).map_err(|_| RegistryError::ArithmeticOverflow);
        }
    }
    // Unreachable while the caller has refused a set larger than `C`, and the right answer if it
    // ever does not.
    Err(RegistryError::EpochCapacityExceeded)
}

/// Every level above the leaves, concatenated, and the root (§1.4).
fn levels_above<H: Hasher>(leaves: &[Digest]) -> Result<(Vec<Digest>, Digest)> {
    let mut nodes: Vec<Digest> = Vec::new();
    let mut current: Vec<Digest> = leaves.to_vec();
    while current.len() > 1 {
        let mut parents: Vec<Digest> = Vec::new();
        for pair in current.chunks(2) {
            match pair {
                [left, right] => parents.push(
                    NodePreimage {
                        left: *left,
                        right: *right,
                    }
                    .digest::<H>()?,
                ),
                // A complete tree over a power-of-two leaf count always pairs.
                _ => return Err(RegistryError::MalformedPayload),
            }
        }
        nodes.extend_from_slice(&parents);
        current = parents;
    }
    let root = *current.first().ok_or(RegistryError::MalformedPayload)?;
    Ok((nodes, root))
}

/// Where level `level` begins inside `nodes`. Level 1 holds `C / 2` digests, level 2 holds `C / 4`,
/// and everything below level `L` sums to `C − C / 2^(L−1)`.
fn level_offset(level: usize, capacity: usize) -> Result<usize> {
    let shift = level
        .checked_sub(1)
        .and_then(|below| u32::try_from(below).ok())
        .ok_or(RegistryError::ArithmeticOverflow)?;
    let remaining = capacity
        .checked_shr(shift)
        .ok_or(RegistryError::ArithmeticOverflow)?;
    capacity
        .checked_sub(remaining)
        .ok_or(RegistryError::ArithmeticOverflow)
}
