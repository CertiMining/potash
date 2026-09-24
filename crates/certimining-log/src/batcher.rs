//! The batcher: submission intake, promises, epoch sealing and the overflow queue (§1.6, §2.3).
//!
//! The batcher holds three things a counterparty never sees: the master key it seals with, the epoch it
//! is filling, and its queues. It holds no clock. The caller owns the calendar and advances the epoch by
//! sealing it (D-70), which keeps time out of a crate that builds for bare metal and keeps every test's
//! epoch a stated input rather than a reading that changes overnight.
//!
//! What it never does is drop a submission. A full epoch is promised the next epoch inside the merge
//! delay that has room, because a submitter holding no promise has no evidence of having submitted, and
//! that is the censorship the promise exists to make provable (D-71). It refuses only when no epoch
//! inside the delay can hold the submission at all: a promise the batcher knows it cannot keep would
//! manufacture its own accusation three epochs later.

use alloc::vec::Vec;

use certimining_core::{Digest, Hasher, RegistryError, Result, Signer, SubmissionId};

use crate::{
    promise_digest, BuiltEpoch, EpochTree, SignedPromise, MAX_HEIGHT, MAX_MERGE_DELAY, MIN_HEIGHT,
};

/// §1.6's intake, as §2.3 states it.
pub trait Batcher {
    /// Mints an identifier, queues the leaf and returns its promise. A full epoch does not refuse: the
    /// promise names the next epoch inside the merge delay that has room, and the leaf waits in the
    /// overflow queue (D-71). `0x12` only when no epoch inside the delay can hold it.
    fn submit<H: Hasher, S: Signer>(&mut self, leaf: Digest, signer: &S) -> Result<SignedPromise>;
    /// Builds the tree for `epoch`, which must be the batcher's current one, then advances and pulls
    /// what it can from the overflow queue. An epoch out of order is `0x0D`.
    fn seal<H: Hasher>(&mut self, epoch: u64) -> Result<BuiltEpoch>;
    /// How many submissions are waiting for an epoch after the current one.
    fn overflow_queue_len(&self) -> usize;
}

/// What a batcher must carry across a restart (D-69).
///
/// **What carrying the counter here does and does not buy.** `resume` checks every invariant a single
/// snapshot can be checked against: identifiers unique and all below the counter, the current epoch no
/// fuller than `C`, and the queue no longer than the merge delay can absorb. It cannot detect a
/// complete rollback to an older snapshot that was internally consistent when it was taken, because
/// nothing in the value says which of two snapshots is later. Rollback resistance is a property of how
/// the service persists this, atomically and without reverting, and that belongs to E-09 (M-01).
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
        if !(MIN_HEIGHT..=MAX_HEIGHT).contains(&height) {
            return Err(RegistryError::MalformedPayload);
        }
        Ok(Self {
            master_key: *master_key,
            height,
            epoch,
            next_submission: 0,
            pending: Vec::new(),
            overflow: Vec::new(),
        })
    }

    /// A batcher continuing from a snapshot, which is checked before it is trusted.
    ///
    /// A snapshot arrives from storage and its fields are public, so it is input rather than state:
    /// every invariant one snapshot can be checked against is checked here, and a snapshot that fails
    /// is `0x05`. What no check can see is a rollback to an older consistent snapshot (M-01).
    pub fn resume(master_key: &Digest, height: u8, snapshot: BatcherSnapshot) -> Result<Self> {
        let mut batcher = Self::start(master_key, height, snapshot.epoch)?;
        let capacity = batcher.capacity()?;
        if snapshot.pending.len() > capacity {
            return Err(RegistryError::MalformedPayload);
        }
        let queue_bound = capacity
            .checked_mul(usize::from(MAX_MERGE_DELAY))
            .ok_or(RegistryError::ArithmeticOverflow)?;
        if snapshot.overflow.len() > queue_bound {
            return Err(RegistryError::MalformedPayload);
        }

        // Overflow begins only once the current epoch is full, so a queue beside a half-empty epoch
        // never came from a batcher.
        if !snapshot.overflow.is_empty() && snapshot.pending.len() != capacity {
            return Err(RegistryError::MalformedPayload);
        }

        // The live submissions are the identifiers this batcher minted and has not yet sealed, so they
        // are a strictly increasing, contiguous run ending at `next_submission - 1`, with the current
        // epoch's ahead of the queue's. Checked in arrival order, before sorting could hide it: a gap
        // means a minted submission was lost, and losing one silently is worse than refusing to
        // resume, because the batcher would seal an epoch without a leaf it had promised.
        let ordinals: Vec<u64> = snapshot
            .pending
            .iter()
            .chain(snapshot.overflow.iter())
            .map(|(id, _)| ordinal_of(id))
            .collect::<Result<Vec<u64>>>()?;
        if let Some(first) = ordinals.first() {
            let last = ordinals.last().ok_or(RegistryError::MalformedPayload)?;
            let expected_last = snapshot
                .next_submission
                .checked_sub(1)
                .ok_or(RegistryError::MalformedPayload)?;
            if *last != expected_last {
                return Err(RegistryError::MalformedPayload);
            }
            let span = last
                .checked_sub(*first)
                .and_then(|span| span.checked_add(1))
                .ok_or(RegistryError::MalformedPayload)?;
            if span != ordinals.len() as u64 {
                return Err(RegistryError::MalformedPayload);
            }
            if ordinals.windows(2).any(|pair| match pair {
                [left, right] => right.checked_sub(*left) != Some(1),
                _ => true,
            }) {
                return Err(RegistryError::MalformedPayload);
            }
        } else if !snapshot.overflow.is_empty() {
            return Err(RegistryError::MalformedPayload);
        }

        batcher.next_submission = snapshot.next_submission;
        batcher.pending = snapshot.pending;
        batcher.overflow = snapshot.overflow;
        Ok(batcher)
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

    /// `C` for this batcher's height.
    fn capacity(&self) -> Result<usize> {
        1usize
            .checked_shl(u32::from(self.height))
            .ok_or(RegistryError::ArithmeticOverflow)
    }

    /// The identifier for the next submission: a counter, little-endian, in sixteen bytes (D-69).
    fn mint_identifier(&mut self) -> Result<SubmissionId> {
        let ordinal = self.next_submission;
        self.next_submission = ordinal
            .checked_add(1)
            .ok_or(RegistryError::ArithmeticOverflow)?;
        let mut id = [0u8; 16];
        let (low, _) = id.split_at_mut(8);
        low.copy_from_slice(&ordinal.to_le_bytes());
        Ok(id)
    }

    /// Which epoch a submission arriving now can be promised, given what is already queued.
    ///
    /// The current epoch takes the first `C`; everything after waits in the overflow queue and is
    /// sealed a whole epoch at a time, so the submission at queue position `k` lands in
    /// `epoch + 1 + k / C`. That epoch must be inside the merge delay, or there is no honest promise.
    fn promised_epoch(&self) -> Result<u64> {
        let capacity = self.capacity()?;
        if self.pending.len() < capacity {
            return Ok(self.epoch);
        }
        let epochs_ahead = self
            .overflow
            .len()
            .checked_div(capacity)
            .ok_or(RegistryError::ArithmeticOverflow)?
            .checked_add(1)
            .ok_or(RegistryError::ArithmeticOverflow)?;
        if epochs_ahead > usize::from(MAX_MERGE_DELAY) {
            return Err(RegistryError::EpochCapacityExceeded);
        }
        let ahead = u64::try_from(epochs_ahead).map_err(|_| RegistryError::ArithmeticOverflow)?;
        self.epoch
            .checked_add(ahead)
            .ok_or(RegistryError::ArithmeticOverflow)
    }
}

/// The counter an identifier was minted from (D-69): the low eight bytes, little-endian.
fn ordinal_of(id: &SubmissionId) -> Result<u64> {
    let low: [u8; 8] = id
        .get(..8)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(RegistryError::MalformedPayload)?;
    // The high half is zero in every identifier this batcher mints, and a snapshot carrying anything
    // else did not come from one.
    if id.get(8..).is_some_and(|rest| rest.iter().any(|b| *b != 0)) {
        return Err(RegistryError::MalformedPayload);
    }
    Ok(u64::from_le_bytes(low))
}

impl Batcher for EpochBatcher {
    fn submit<H: Hasher, S: Signer>(&mut self, leaf: Digest, signer: &S) -> Result<SignedPromise> {
        // The epoch is decided before the identifier is minted, so a refusal consumes nothing.
        let promised_epoch = self.promised_epoch()?;
        let capacity = self.capacity()?;
        let submission_id = self.mint_identifier()?;

        let promise = SignedPromise {
            leaf,
            submission_id,
            accepted_epoch: self.epoch,
            promised_epoch,
            max_merge_delay: MAX_MERGE_DELAY,
            batcher_key: signer.public_key(),
            signature: [0u8; 64],
        };
        let digest = promise_digest::<H>(&promise)?;
        let signature = signer.sign(&digest)?;

        if self.pending.len() < capacity {
            self.pending.push((submission_id, leaf));
        } else {
            self.overflow.push((submission_id, leaf));
        }
        Ok(SignedPromise {
            signature,
            ..promise
        })
    }

    fn seal<H: Hasher>(&mut self, epoch: u64) -> Result<BuiltEpoch> {
        if epoch != self.epoch {
            return Err(RegistryError::EpochOutOfOrder);
        }
        let built = BuiltEpoch::build::<H>(epoch, self.height, &self.master_key, &self.pending)?;

        // Only once the tree is built does the batcher move: a refused build leaves it where it was.
        let capacity = self.capacity()?;
        self.epoch = epoch
            .checked_add(1)
            .ok_or(RegistryError::ArithmeticOverflow)?;
        let moving = core::cmp::min(capacity, self.overflow.len());
        self.pending = self.overflow.drain(..moving).collect();
        Ok(built)
    }

    fn overflow_queue_len(&self) -> usize {
        self.overflow.len()
    }
}
