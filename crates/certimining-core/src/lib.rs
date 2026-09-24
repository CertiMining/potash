//! `certimining-core`: digests and state rules for the CertiMining anchored log (TCU-02).
//!
//! E-01 provides the error space (§2.1), the digest types (§2.2) and the Keccak-256 hashers (§1.1).
//! E-02 adds canonical tenure identifiers and the asset commitment (§1.3). E-03 adds the
//! domain-tagged preimage writers every digest is built from (§1.2). E-04 adds the supersession
//! state machine and its flags (§1.3). E-06 adds §1.1's PRF, which the epoch tree of
//! `certimining-log` uses for slot assignment and padding (D-61). The crate is `no_std` and has no Solana dependency outside
//! the `solana` feature (§2).

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

mod error;
mod hash;
mod identity;
mod preimage;
mod prf;
mod state;
mod verify;

pub use error::RegistryError;
pub use hash::Hasher;
#[cfg(feature = "native")]
pub use hash::NativeKeccak;
#[cfg(feature = "solana")]
pub use hash::SolanaKeccak;
pub use identity::{
    AssetId, AssetIdentity, CanonicalTenure, MAX_RAW_TENURE_LEN, MAX_TENURE_LEN, TAG_ASSET,
};
pub use preimage::{
    check_tag, read_tag, AssetPreimage, GenesisHeadPreimage, LeafPreimage, NodePreimage,
    PaddingPreimage, Preimage, PreimageBuf, PreimageSink, RealLeafPreimage, SpiPreimage,
    StepHeadPreimage, SubmissionId, MAX_PREIMAGE_LEN, TAG_HEAD, TAG_LEAF, TAG_MTL0, TAG_MTN1,
    TAG_PAD, TAG_SPI,
};
pub use prf::{
    epoch_key, padding_prf, slot_seed, PrfPreimage, MAX_PRF_INPUT_LEN, PRF_USE_EPOCH_KEY,
    PRF_USE_PADDING, PRF_USE_SLOT, TAG_PRF,
};
pub use state::{
    payload_uri_is_well_formed, Applied, AssetChain, ChainSnapshot, ChainState, PayloadUri,
    RecordLeafInput, FLAG_CATEGORY_DOWNGRADE, FLAG_RESERVE_WITHOUT_PRIOR_RESOURCE,
    MAX_PAYLOAD_URI_LEN, SCHEMA_VERSION,
};
#[cfg(feature = "native")]
pub use verify::DalekVerifier;
pub use verify::{Signer, Verifier};

/// A 32-byte digest (§2.2).
pub type Digest = [u8; 32];

/// The result of every fallible operation in the engine (§2.2).
pub type Result<T> = core::result::Result<T, RegistryError>;
