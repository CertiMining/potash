// SPDX-License-Identifier: MIT OR Apache-2.0
//! §2.3's `AnchorClient`, the parts this unit owns (D-110).
//!
//! The trait names three operations. `publish` and `status` belong to anchor A and are here;
//! `timestamp` is OpenTimestamps, which is anchor B and E-10's unit, so it is not implemented here
//! and this module does not pretend otherwise. Codex round one, finding 3: two module headers in
//! this crate claimed to be §2.3's `AnchorClient` while the crate implemented none of it.
//!
//! What is decided here is decided without a network, so it can be tested without one.

use crate::fetch::Fetched;

/// §2.3's `AnchorStatus`. INV-ANCH-05 makes a client say which of the two anchors an epoch has, and
/// say `Single` until anchor B attaches rather than degrading silently to a dual-anchor claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchorStatus {
    /// No checkpoint for this epoch, or none this client will accept.
    Pending,
    /// A root is on Solana. Anchor B has not attached.
    Single,
    /// A root is on Solana and a receipt digest is attached.
    Dual,
}

/// Where a published root can be found, which is what §2.3's `publish` returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorRef {
    pub epoch: u64,
    pub signature: String,
    pub published_slot: u64,
}

/// The status of one epoch, given what the cluster answered for it.
///
/// A refusal is `Pending` rather than `Single`: an account this client will not accept is not a root
/// it has, and reporting it as anchored would be the silent degradation INV-ANCH-05 forbids, pointed
/// the other way.
pub fn status_of(fetched: &Fetched) -> AnchorStatus {
    match fetched {
        Fetched::Placed(checkpoint) => {
            if checkpoint.receipt_digest == [0u8; 32] {
                AnchorStatus::Single
            } else {
                AnchorStatus::Dual
            }
        }
        Fetched::Absent | Fetched::Refused(_) => AnchorStatus::Pending,
    }
}
