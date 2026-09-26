// SPDX-License-Identifier: MIT OR Apache-2.0
//! `certimining-log`: the fixed-capacity epoch tree, its inclusion proofs and the pure inclusion
//! verifier (§1.4, §2.3).
//!
//! E-06 provides the tree, the proof and the verifier; E-07 adds the batcher and its promises. The crate is `no_std` with an allocator, because a tree at `H = 16`
//! holds 65,536 leaves and no fixed-capacity type carries that, while the verifier itself allocates
//! nothing and builds for a bare-metal target (D-61). The batcher of §1.6 joins at E-07.
//!
//! What the tree is for: every epoch is a complete tree of the same height, with real leaves in
//! pseudorandom slots and every other slot filled by PRF padding, so an epoch holding one filing
//! and an epoch holding two hundred are identical in shape, proof length and root distribution
//! (INV-TREE-01, INV-TREE-02). Hiding rests on the epoch key staying with the batcher, which is a
//! trust assumption named in the specification's RES-03 rather than a property of this code.

// no_std everywhere except the unit-test harness, which needs std.
#![cfg_attr(not(test), no_std)]
// INV-ERR-01: no unsafe code, unwrap, expect, unchecked indexing or wrapping arithmetic.
#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

extern crate alloc;

mod batcher;
mod promise;
mod proof;
mod tree;

pub use batcher::{Batcher, BatcherSnapshot, EpochBatcher};
pub use promise::{
    promise_digest, promise_kept, verify_promise, PublishedRoot, SignedPromise, MAX_MERGE_DELAY,
    PROMISE_ENCODED_LEN,
};
pub use proof::{InclusionProof, InclusionVerifier, ProofVerifier, MAX_SIBLINGS};
pub use tree::{slot_from_seed, BuiltEpoch, EpochTree, MAX_HEIGHT, MIN_HEIGHT};
