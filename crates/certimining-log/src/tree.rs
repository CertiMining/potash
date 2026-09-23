//! The fixed-capacity epoch tree (§1.4, §2.3).
//!
//! **STUB. This module has no implementation yet (D-65).** Issue #6 requires the §4.4 privacy tests
//! to be written before the tree they test, so this commit carries the tests and every entry point
//! here refuses with one fixed error. The tests below it fail, deliberately, and CI is red on this
//! commit. The next commit replaces these bodies and turns them green. `STUB_REFUSAL` is not a
//! specification code for any condition and nothing may depend on it.

use alloc::vec::Vec;
use certimining_core::{Digest, Hasher, RegistryError, Result, SubmissionId};

/// STUB (D-65): what every entry point in this module returns until the implementation lands.
const STUB_REFUSAL: RegistryError = RegistryError::MalformedPayload;

/// §1.8's range for the tree height, fixed at `initialize` and immutable thereafter (INV-TREE-06).
pub const MIN_HEIGHT: u8 = 4;
/// The upper end of §1.8's range.
pub const MAX_HEIGHT: u8 = 16;

/// What one sealed epoch carries (§2.3, D-62).
#[derive(Debug, Clone)]
pub struct BuiltEpoch {
    /// The epoch this tree is for, a UTC day index (§1.4).
    pub epoch: u64,
    /// The height every epoch of this log uses (INV-TREE-06).
    pub height: u8,
    /// The root the checkpoint publishes.
    pub root: Digest,
    /// Every slot's leaf digest, in slot order, exactly `C` of them. Nothing here says which are
    /// real: that is what V-Z-02 tries to recover and must not (D-62).
    pub leaves: Vec<Digest>,
    /// Submission identifier to slot, ascending by identifier (D-60).
    pub assignment: Vec<(SubmissionId, u16)>,
}

/// §1.4's tree, built once per epoch (§2.3).
pub trait EpochTree {
    /// The height this tree was built at.
    fn height(&self) -> u8;
    /// `C`, which is `1 << height()`.
    fn capacity(&self) -> usize;
    /// Builds one epoch. `key` is `k_master`: the epoch key is derived here from the epoch, so no
    /// caller can reuse one `k_e` across epochs (INV-TREE-05, D-63). The hasher is named at the
    /// call site, as it is for every digest in §2.2.
    fn build<H: Hasher>(
        epoch: u64,
        height: u8,
        key: &Digest,
        real: &[(SubmissionId, Digest)],
    ) -> Result<BuiltEpoch>;
    /// The epoch root.
    fn root(&self) -> Digest;
    /// The inclusion proof for a submission this epoch holds. A submission it does not hold is
    /// `0x13`: there is no such proof (D-64).
    fn proof(&self, id: &SubmissionId) -> Result<crate::InclusionProof>;
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
        // STUB (D-65).
        let _ = (epoch, height, key, real);
        Err(STUB_REFUSAL)
    }

    fn root(&self) -> Digest {
        self.root
    }

    fn proof(&self, id: &SubmissionId) -> Result<crate::InclusionProof> {
        // STUB (D-65).
        let _ = id;
        Err(STUB_REFUSAL)
    }
}

/// §1.4's reduction (D-60): the seed read as a little-endian integer and reduced modulo `C`.
pub fn slot_from_seed(seed: &Digest, height: u8) -> Result<u16> {
    // STUB (D-65).
    let _ = (seed, height);
    Err(STUB_REFUSAL)
}
