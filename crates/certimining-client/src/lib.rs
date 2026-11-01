// SPDX-License-Identifier: MIT OR Apache-2.0
//! `certimining-client`: publishing checkpoints on the epoch cadence, and fetching a root by epoch
//! without an indexer (§1.5, §2.3).
//!
//! This is the only crate here that speaks to a cluster, which is why it is a crate of its own: the
//! engine builds for bare metal and an RPC client ends that (D-84). The cluster itself sits behind a
//! trait, so every test below runs without a network and the one implementation that does reach a
//! cluster is the service's.
//!
//! Two properties live here rather than in the program, and both are things a reader should be able
//! to check rather than take:
//!
//! - **A root fetched from an RPC is not believed until it is placed.** The account must be owned by
//!   the program, carry the program's discriminator, carry schema version 1, and carry the epoch that
//!   was asked for (D-82). INV-ANCH-06 eliminates log equivocation only because every verifier
//!   resolves the same root, which holds only if each verifier checks what it resolved.
//! - **Publication time is a function of the epoch, not of the build** (D-83, INV-ANCH-01). Publishing
//!   when the tree happens to be ready leaks build time, and build time tracks record count.

#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

pub mod alert;
mod anchor;
#[cfg(feature = "ots")]
pub mod bitcoin;
#[cfg(feature = "cluster")]
pub mod cluster;
#[cfg(feature = "cluster")]
pub mod crypto;
mod fetch;
mod handoff;
mod ots;
#[cfg(feature = "ots")]
mod promise_receipt;
mod publish;
mod schedule;
mod separation;
mod worker;

pub use alert::{alerts, Alert, Supervision, Thresholds};
pub use anchor::{
    lineage_of, provenance_in, status_of, AnchorRef, AnchorStatus, Lineage, Touched, WhereItLanded,
};
#[cfg(feature = "cluster")]
pub use cluster::PublishFailed;
pub use fetch::{
    checkpoint_address, checkpoint_bump, config_address, decode_checkpoint, decode_config,
    root_for_epoch, sequence_lag, Fetched, Lag, Observation, OneView, PublishedCheckpoint, Refused,
    RootSource, Unreachable, ONE_VIEW_LIMIT,
};
pub use handoff::{refuse_to_write, Handoff, HandoffRefused, HandoffWriteRefused, HANDOFF_LEN};
pub use ots::{receipt_digest, refuse_a_readable_key, AnchorB, PendingReceipt, ReceiptRefused};
#[cfg(feature = "ots")]
pub use ots::{verify_receipt, BitcoinClaim, ReferenceClient};
#[cfg(feature = "ots")]
pub use promise_receipt::{
    judge_against_confirmation, verify_transferred_promise, Established, TransferRefused,
};
pub use publish::{
    classify, settle, should_retry, Outcome, Settlement, CHECKPOINT_ALREADY_WRITTEN,
};
pub use schedule::{build_start, publication_time, Schedule, EPOCH_SECONDS};
pub use separation::{verify_role_separation, KeyCollision, KeyRole};
pub use worker::{
    day_index, next_step, next_step_with_policy, Observed, Refusal, Step, WorkerPolicy,
};
