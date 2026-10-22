// SPDX-License-Identifier: MIT OR Apache-2.0
//! Independently timestamped promise receipts, for transfer to a party that observed nothing
//! (H-02, issue #30).
//!
//! §1.6's promise is checked against **the counterparty's own observation of the checkpoint sequence
//! when it arrived** (D-74). That closes the case for the party who received it and nobody else: a
//! promise passed onward carries an acceptance epoch the next holder has no way to judge, which
//! Appendix A's RES-10 states rather than hiding.
//!
//! What closes it is a timestamp over the promise itself. The receiving counterparty stamps the
//! promise's own 161-octet encoding through the anchor B path of §1.5, and that receipt travels with
//! the promise. A later holder then checks the stamp instead of trusting the batcher's assertion,
//! because a Bitcoin block fixes when the promise existed **in a third party's hands** rather than
//! when the batcher says it was issued.
//!
//! # What the receipt fixes, and what it does not
//!
//! It fixes an **upper bound** on when the promise existed: no later than the block that commits it.
//! That is the direction the attack runs in. Without it, a batcher holding the expected key can name
//! an acceptance epoch in the future and defer its own answerability; the bound refuses that, because
//! a promise cannot have been accepted after the moment it demonstrably already existed.
//!
//! It fixes no lower bound. OpenTimestamps says "this existed by then" and never "this did not exist
//! before then", so a batcher is free to claim an acceptance epoch *earlier* than the real one. That
//! moves the batcher's own deadline earlier and is against its interest, so it is not an attack the
//! bound needs to cover.
//!
//! **The epoch it establishes is a calendar epoch, not a sequence epoch.** §1.6's `observed_epoch` is
//! the counterparty's reading of the published sequence; this is the UTC day index of a Bitcoin
//! block. The two agree while the batcher is current and diverge by exactly its lag when it is not,
//! so under lag this bound is the looser of the two. It does not break the device: `promised_epoch`
//! still has to fall inside `accepted_epoch ..= accepted_epoch + max_merge_delay`, and a lagging
//! batcher has not published the roots that window names, so the accusation still forms.
//!
//! # Why the seam below cannot be used to skip Bitcoin
//!
//! [`judge_against_confirmation`] takes a [`Confirmed`], and **only `bitcoin::confirm` builds one** —
//! it needs a chain of real work running back to a committed checkpoint. So a caller holding one is
//! holding the fact rather than a receipt's assertion about it, and a test exercising the judgment
//! has to produce a real confirmation to get there. The seam exists so the judgment is testable
//! without a calendar, in the same way [`crate::AnchorB`] exists for the worker, and it buys that
//! without letting anything verify a promise against a block nobody checked.

use certimining_core::{Hasher, RegistryError, Verifier};
use certimining_log::{verify_promise, SignedPromise};

use crate::bitcoin::{confirm, Checkpoint, Confirmed, Header, HeaderRefused};
use crate::{day_index, verify_receipt, ReceiptRefused};

/// What a confirmed receipt established about a promise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Established {
    /// The block the receipt names, checked against real work rather than taken from the receipt.
    pub confirmed: Confirmed,
    /// The UTC day index that block's timestamp falls in, which §1.4 makes an epoch.
    ///
    /// The promise existed no later than this epoch. Derived from a miner-chosen timestamp, so it
    /// carries the slack [`Confirmed::time`] describes.
    pub existed_by_epoch: u64,
}

/// Why a transferred promise was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferRefused {
    /// The receipt does not timestamp this promise's encoding.
    ///
    /// Carried separately from the rest because it is the condition that binds a receipt to **one**
    /// promise: a receipt for some other artifact, or for a promise with any field altered, fails
    /// here and never reaches a judgment.
    NotThisPromise(ReceiptRefused),
    /// The receipt's Bitcoin claim did not survive the header chain (H-12).
    NotInBitcoin(HeaderRefused),
    /// The attested block's timestamp falls before 1970 and has no UTC day index.
    ///
    /// Unreachable for any real block and refused rather than saturated, because the alternative is
    /// judging a promise against epoch zero and reporting it established.
    NoDayIndex {
        /// The timestamp the header carried.
        time: u32,
    },
    /// The promise failed §1.6's own checks against the epoch the receipt established.
    Promise(RegistryError),
}

/// Checks a promise against a receipt over its own encoding, and against Bitcoin.
///
/// The whole path, in the order a holder who observed nothing has to run it:
///
/// 1. The receipt must timestamp **exactly** this promise's 161 octets. A receipt for anything else
///    is `NotThisPromise`, so the stamp cannot be lifted from one promise onto another.
/// 2. The block the receipt names must be reachable from `checkpoint` through `headers`, each
///    meeting the target its own `bits` encode (H-12). A receipt naming a block it never reached is
///    `NotInBitcoin`.
/// 3. That block's timestamp gives the epoch the promise existed by.
/// 4. §1.6's checks then run against that epoch rather than against the holder's own observation.
pub fn verify_transferred_promise<H: Hasher, V: Verifier>(
    promise: &SignedPromise,
    expected_batcher_key: &[u8; 32],
    receipt: &[u8],
    checkpoint: Checkpoint,
    headers: &[Header],
) -> Result<Established, TransferRefused> {
    // The binding step. `encode` is the transferable artifact's own octets (L-01), so this asks
    // whether the receipt covers this promise and not whether it covers something that hashes alike.
    let claim =
        verify_receipt(receipt, &promise.encode()).map_err(TransferRefused::NotThisPromise)?;
    let confirmed = confirm(claim, checkpoint, headers).map_err(TransferRefused::NotInBitcoin)?;
    judge_against_confirmation::<H, V>(promise, expected_batcher_key, &confirmed)
}

/// §1.6's checks against the epoch a confirmed block establishes.
///
/// Split out so the judgment is testable from a real confirmation without reaching a calendar. It
/// cannot be reached without a [`Confirmed`], which only `bitcoin::confirm` builds.
pub fn judge_against_confirmation<H: Hasher, V: Verifier>(
    promise: &SignedPromise,
    expected_batcher_key: &[u8; 32],
    confirmed: &Confirmed,
) -> Result<Established, TransferRefused> {
    let existed_by_epoch =
        day_index(i64::from(confirmed.time)).ok_or(TransferRefused::NoDayIndex {
            time: confirmed.time,
        })?;
    // The same function the original counterparty ran, given the epoch the receipt established in
    // place of the one only that party could observe. Nothing about §1.6's policy is re-decided
    // here: a second implementation of those checks would be a second thing to keep in agreement.
    verify_promise::<H, V>(promise, expected_batcher_key, existed_by_epoch)
        .map_err(TransferRefused::Promise)?;
    Ok(Established {
        confirmed: *confirmed,
        existed_by_epoch,
    })
}
