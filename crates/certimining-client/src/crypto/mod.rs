// SPDX-License-Identifier: MIT OR Apache-2.0
//! Signing boundaries for keys that never enter the anchoring process.

mod signer;

pub use signer::{
    verify_consensus_signature, ConsensusSigner, ConsensusSignerBackend, HardwareSignerError,
    HardwareSignerProviderError,
};
