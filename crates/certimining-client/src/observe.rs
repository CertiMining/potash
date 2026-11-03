// SPDX-License-Identifier: MIT OR Apache-2.0
//! What the worker can see, as one function both it and its tests call (H-108, issue #332).
//!
//! **Why this module exists.** `observe` was a private function in `anchor-b-worker` taking a
//! concrete `Cluster`, so nothing could call it without a network. The harness in
//! `tests/worker_recovery.rs` had an `observe` of its own that copied its own fields into [`Observed`]
//! and performed no observation at all, and every test of the worker's recovery ran against that
//! one. The binary's observer and the tested observer were different code, and only one of them
//! carried the defect the 2 November 2026 audit found.
//!
//! **The defect.** Both `last_submitted` and `awaiting_attach` were set only inside
//! `if receipt_path(epoch).exists()`, and `Path::exists` is false both for an absent receipt and for
//! one whose metadata cannot be read. So a deleted or unreadable receipt left `awaiting_attach` as
//! `None` — the guard `alerts()` read before it could emit `ReceiptUnconfirmed`, so the alert H-97
//! added to surface exactly that state was silenced by it.
//!
//! **Why the guard stays.** The owner's first ruling removed it, deriving `awaiting_attach` from
//! `AnchorStatus::Single` alone. That halts the worker on every epoch, and the ruling is superseded
//! for that reason: `Single` means a root is on Solana and anchor B has not attached, which is true
//! from the instant of publication. The cycle is publish, submit, attach, so every epoch passes
//! through `Single` with no receipt on its way to being submitted, and `next_step` puts attaching
//! ahead of submitting. Derived from the chain alone, a freshly published epoch routes to `Attach`
//! with nothing to attach instead of to `Submit`. The receipt's presence is the only evidence in the
//! system that an epoch reached the calendars, which is what makes it the routing's discriminator
//! and why issue #337's durable journal is what finally replaces it.
//!
//! **So the alert reads the chain instead.** `oldest_single` is the lowest epoch the chain calls
//! `Single`, recorded whatever is on disk. An epoch that has been `Single` past the receipt budget is
//! an operator's business whether its receipt was lost or never written, and that is a question the
//! chain and the clock answer between them. The routing keeps the guard; the alert no longer needs
//! it.

use crate::anchor::AnchorStatus;
use crate::fetch::{sequence_lag, RootSource, Unreachable};
use crate::worker::Observed;
use anchor_lang::prelude::Pubkey;

/// What the worker asks the chain about one epoch's anchoring state.
///
/// **One method, because one is what the observation needs.** `sequence_lag` already takes a
/// [`RootSource`], so the configuration and the published range were reachable without a cluster
/// before this; the epoch status was the only question answered solely by a concrete one.
pub trait EpochStatus {
    /// Whether `epoch` is unpublished, published without a receipt digest, or both (D-112).
    fn status(&self, epoch: u64) -> Result<AnchorStatus, Unreachable>;
}

/// Where this deployment keeps anchor B's receipts.
///
/// Separate from [`crate::AnchorB`] deliberately: observing asks only where a receipt would be, and a
/// fake that answers that should not have to implement submitting and upgrading as well.
pub trait ReceiptLocation {
    /// Where `epoch`'s receipt lives, whether or not it is there.
    fn receipt_path(&self, epoch: u64) -> std::path::PathBuf;
}

/// Why an observation could not be made.
///
/// Two cases rather than one string, so a caller can say which question went unanswered and a test
/// can assert it. The worker treats either as a transport failure and retries under its policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObserveFailed {
    /// The log's own configuration could not be read, so the published range is unknown.
    Configuration(Unreachable),
    /// One epoch's anchoring state could not be read.
    Status { epoch: u64, cause: Unreachable },
}

/// The log's configuration, which epochs it has submitted and attached, and how long one has waited.
///
/// `now` is the caller's clock; [`Observed`] derives the calendar from it (H-101). `today` bounds the
/// configuration read.
pub fn observe<S, R>(
    source: &S,
    receipts: &R,
    program_id: &Pubkey,
    now: i64,
    today: u64,
) -> Result<Observed, ObserveFailed>
where
    S: RootSource + EpochStatus,
    R: ReceiptLocation,
{
    let lag =
        sequence_lag(source, program_id, today, today).map_err(ObserveFailed::Configuration)?;

    let mut last_submitted = None;
    let mut awaiting_attach = None;
    let mut oldest_single = None;
    let mut epoch = lag.start_epoch;
    while epoch <= lag.last_published {
        let status = source
            .status(epoch)
            .map_err(|cause| ObserveFailed::Status { epoch, cause })?;
        // **Recorded from the chain alone, for the alert.** No receipt is consulted: an epoch stuck
        // in `Single` is the operator's business whether its receipt was lost or never written.
        if status == AnchorStatus::Single && oldest_single.is_none() {
            oldest_single = Some(epoch);
        }
        // **And the routing keeps the receipt as its evidence.** A receipt is what says this epoch
        // reached the calendars; the chain cannot say it. See the module note above for why removing
        // this halts the worker, and issue #337 for what replaces it.
        if receipts.receipt_path(epoch).exists() {
            last_submitted = Some(epoch);
            if awaiting_attach.is_none() && status == AnchorStatus::Single {
                awaiting_attach = Some(epoch);
            }
        }
        epoch = match epoch.checked_add(1) {
            Some(next) => next,
            None => break,
        };
    }

    Ok(Observed {
        now,
        start_epoch: lag.start_epoch,
        last_epoch: lag.last_published,
        awaiting_attach,
        last_submitted,
        oldest_single,
    })
}
