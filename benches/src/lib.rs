// SPDX-License-Identifier: MIT OR Apache-2.0
//! The fixtures §4.4a's measures are taken over, in one place.
//!
//! Criterion reports distributions (`chain.rs`, `epoch.rs`), `thresholds.rs` measures §4.4a's figures
//! and reports them with the machine named (D-137), and `band.rs` holds the CI runner to its own previous
//! numbers. All three measure the same thing, which is only true if they build the same inputs, so the
//! inputs live here rather than in four copies.
//!
//! **`band.rs` and `thresholds.rs` pin these constants against literals before they measure**, because a
//! row named "256 leaves" that times a smaller tree is a false figure (PR #59, round two). Changing
//! `HEIGHT` or `RECORDS` here therefore fails those two rather than silently relabelling their output.
//!
//! Nothing in this crate ships: it is a workspace member so that `cargo deny` covers it and
//! `cargo clippy --workspace --all-targets` lints it, and nothing depends on it.

use certimining_core::{
    AssetChain, ChainState, Digest, LeafPreimage, NativeKeccak, PayloadUri, Preimage, PreimageBuf,
    RecordLeafInput, RegistryError, StepHeadPreimage, SubmissionId, Verifier,
};
use ed25519_dalek::{Signer as _, SigningKey};

/// RFC 8032 §7.1's TEST 1 secret key, whose private half that document publishes. The same key the
/// fuzz targets sign with, so one published value serves both rather than two.
pub const RFC8032_SECRET: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];

pub const ASSET: Digest = [0x11; 32];
/// §4.4a's chain-walk row is over 10,000 records.
pub const RECORDS: usize = 10_000;
/// The deployed height, so the figures describe the log that is announced (D-02).
pub const HEIGHT: u8 = 8;
pub const MASTER: Digest = [0x5a; 32];
pub const EPOCH: u64 = 20_728;

/// Accepts every signature, so a walk measures hashing and nothing else. This is the instrument
/// §4.4a's "hash recomputation only" asks for. It is not a verifier and nothing outside this crate
/// can reach it.
pub struct HashOnly;

impl Verifier for HashOnly {
    fn verify(
        _key: &[u8; 32],
        _message: &[u8],
        _signature: &[u8; 64],
    ) -> Result<(), RegistryError> {
        Ok(())
    }
}

/// The 161 bytes §1.3 signs.
fn leaf_bytes(r: &RecordLeafInput) -> Vec<u8> {
    let mut buf = PreimageBuf::new();
    LeafPreimage {
        asset_commitment: ASSET,
        seq: r.seq,
        payload_digest: r.payload_digest,
        assessment_digest: r.assessment_digest,
        qp_key: r.qp_key,
        category: r.category,
        effective_at: r.effective_at,
        change_identified_at: r.change_identified_at,
    }
    .write_preimage(&mut buf)
    .expect("the preimage fits");
    buf.as_bytes().to_vec()
}

/// A chain of `RECORDS` records that each commit to the head before them, so the whole thing applies.
///
/// `signed` decides whether the signatures are real. The heads are a function of the leaves alone, so
/// the same sequence replays identically against a fresh chain, which is what lets a measured closure
/// start from `start` instead of carrying state between samples.
pub fn chain_of(signed: bool) -> Vec<RecordLeafInput> {
    let key = SigningKey::from_bytes(&RFC8032_SECRET);
    let qp_key = key.verifying_key().to_bytes();
    let mut chain = AssetChain::<NativeKeccak, HashOnly>::start(&ASSET, 1).expect("starts");
    let mut out = Vec::with_capacity(RECORDS);
    for i in 0..RECORDS {
        let mut record = RecordLeafInput {
            prev_head: chain.head(),
            seq: (i as u64) + 1,
            payload_digest: [(i as u8).wrapping_mul(7); 32],
            assessment_digest: [0x33; 32],
            qp_key,
            expected_qp_key: None,
            signature: Some([0x55; 64]),
            category: (i % 5) as u8,
            // Flat, so INV-STATE-04's non-decreasing rule cannot refuse a record for a reason that has
            // nothing to do with what is being measured.
            effective_at: 1_700_000_000,
            change_identified_at: 1_700_000_000,
            payload_uri: PayloadUri::from_slice(b"ipfs://bafybench").expect("fits"),
            ext_commitment: None,
        };
        if signed {
            record.signature = Some(key.sign(&leaf_bytes(&record)).to_bytes());
        }
        let _ = chain
            .apply(&record)
            .expect("a record built against the current head applies");
        out.push(record);
    }
    out
}

/// The genesis head every walk below starts from.
pub fn genesis() -> Digest {
    <AssetChain<NativeKeccak, HashOnly> as ChainState>::genesis(&ASSET, 1).expect("genesis")
}

/// **§4.4a's measure.** The hash chain alone: for each record the leaf digest, then the step head
/// digest. Two Keccak-256 invocations per record and no condition judged, because a verifier
/// recomputing a chain checks that the heads follow from the leaves rather than re-running the
/// issuer's state machine.
pub fn hash_chain(records: &[RecordLeafInput], from: Digest) -> Digest {
    let mut head = from;
    for r in records {
        let leaf = LeafPreimage {
            asset_commitment: ASSET,
            seq: r.seq,
            payload_digest: r.payload_digest,
            assessment_digest: r.assessment_digest,
            qp_key: r.qp_key,
            category: r.category,
            effective_at: r.effective_at,
            change_identified_at: r.change_identified_at,
        }
        .digest::<NativeKeccak>()
        .expect("the leaf digest");
        head = StepHeadPreimage {
            prev_head: head,
            leaf,
        }
        .digest::<NativeKeccak>()
        .expect("the head digest");
    }
    head
}

/// The issuer's path: the same two hashes per record plus every §1.3 condition. No §4.4a row.
pub fn walk<V: Verifier>(records: &[RecordLeafInput]) -> Digest {
    let mut chain = AssetChain::<NativeKeccak, V>::start(&ASSET, 1).expect("starts");
    for r in records {
        let _ = chain.apply(r).expect("applies");
    }
    chain.head()
}

/// A full epoch: `count` real leaves, the rest padding, as a real publisher's would be.
pub fn real_leaves(count: usize) -> Vec<(SubmissionId, Digest)> {
    (0..count)
        .map(|i| {
            let mut id = [0u8; 16];
            id[..8].copy_from_slice(&(i as u64).to_le_bytes());
            let mut leaf = [0u8; 32];
            leaf[..8].copy_from_slice(&(i as u64 ^ 0xa5a5_a5a5_a5a5_a5a5).to_le_bytes());
            leaf[8] = 0x11;
            (id, leaf)
        })
        .collect()
}
