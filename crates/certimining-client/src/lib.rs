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

#[cfg(feature = "cluster")]
pub mod cluster;
mod fetch;
mod publish;
mod schedule;

pub use fetch::{
    checkpoint_address, config_address, decode_checkpoint, missing_epochs, root_for_epoch, Fetched,
    PublishedCheckpoint, Refused, RootSource, Unreachable,
};
pub use publish::{classify, should_retry, Outcome, CHECKPOINT_ALREADY_WRITTEN};
pub use schedule::{build_start, publication_time, Schedule, EPOCH_SECONDS};
