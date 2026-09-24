//! The batcher: submission intake, promises, epoch sealing and the overflow queue (§1.6, §2.3).
//!
//! **STUB. This module has no implementation yet (D-65).**
//!
//! The batcher holds three things a counterparty never sees: the master key it seals with, its current
//! epoch, and its queues. It holds no clock: the caller owns the calendar and advances the epoch by
//! sealing (D-70).

use alloc::vec::Vec;

use certimining_core::{Digest, Hasher, RegistryError, Result, Signer, SubmissionId};

use crate::{BuiltEpoch, SignedPromise};

/// STUB (D-65).
const STUB_REFUSAL: RegistryError = RegistryError::MalformedPayload;

/// §1.6's intake, as §2.3 states it.
pub trait Batcher {
    /// Mints an identifier, queues the leaf and returns its promise. A full epoch does not refuse: the
    /// promise names the next epoch inside the merge delay that has room, and the leaf waits in the
    /// overflow queue (D-71). `0x12` only when no epoch inside the delay can hold it, because a promise
    /// the batcher cannot keep would manufacture its own accusation later.
    fn submit<H: Hasher, S: Signer>(&mut self, leaf: Digest, signer: &S) -> Result<SignedPromise>;
    /// Builds the tree for `epoch`, which must be the batcher's current one, then advances and pulls
    /// what it can from the overflow queue. An epoch out of order is `0x0D`.
    fn seal<H: Hasher>(&mut self, epoch: u64) -> Result<BuiltEpoch>;
    /// How many submissions are waiting for an epoch after the current one.
    fn overflow_queue_len(&self) -> usize;
}

/// What a batcher must carry across a restart, so no identifier is ever issued twice (D-69).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatcherSnapshot {
    /// The epoch the batcher is filling.
    pub epoch: u64,
    /// The next identifier it will mint.
    pub next_submission: u64,
    /// The current epoch's submissions, in the order they arrived.
    pub pending: Vec<(SubmissionId, Digest)>,
    /// Everything promised a later epoch, in the order it arrived.
    pub overflow: Vec<(SubmissionId, Digest)>,
}

/// The batcher this crate provides.
#[derive(Debug, Clone)]
pub struct EpochBatcher {
    master_key: Digest,
    height: u8,
    epoch: u64,
    next_submission: u64,
    pending: Vec<(SubmissionId, Digest)>,
    overflow: Vec<(SubmissionId, Digest)>,
}

impl EpochBatcher {
    /// A batcher starting at `epoch` with nothing queued. `master_key` is `k_master`: it comes from
    /// outside this repository and nothing here ever writes it down (S6, D-63).
    pub fn start(master_key: &Digest, height: u8, epoch: u64) -> Result<Self> {
        let _ = (master_key, height, epoch);
        Err(STUB_REFUSAL)
    }

    /// A batcher continuing from a snapshot.
    pub fn resume(master_key: &Digest, height: u8, snapshot: BatcherSnapshot) -> Result<Self> {
        let _ = (master_key, height, snapshot);
        Err(STUB_REFUSAL)
    }

    /// Everything a restart needs.
    pub fn snapshot(&self) -> BatcherSnapshot {
        BatcherSnapshot {
            epoch: self.epoch,
            next_submission: self.next_submission,
            pending: self.pending.clone(),
            overflow: self.overflow.clone(),
        }
    }

    /// The epoch being filled.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// How many submissions the current epoch holds.
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }
}

impl Batcher for EpochBatcher {
    fn submit<H: Hasher, S: Signer>(&mut self, leaf: Digest, signer: &S) -> Result<SignedPromise> {
        let _ = (leaf, signer, &self.master_key, self.height);
        Err(STUB_REFUSAL)
    }

    fn seal<H: Hasher>(&mut self, epoch: u64) -> Result<BuiltEpoch> {
        let _ = epoch;
        Err(STUB_REFUSAL)
    }

    fn overflow_queue_len(&self) -> usize {
        self.overflow.len()
    }
}
