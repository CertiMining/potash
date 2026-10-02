// SPDX-License-Identifier: MIT OR Apache-2.0
//! §4.4a's chain-walk measures (E-13, D-132), and the distinction the threshold turns on.
//!
//! §4.4a's row is "Chain-walk verification, 10,000 records — **hash recomputation only**", under 5 ms,
//! and its own note says the figure "is achievable only for the hash chain". That is what a *verifier*
//! does: recompute `leafₙ` and `hₙ = Keccak256(TAG_HEAD ‖ hₙ₋₁ ‖ leafₙ)` and compare. Two Keccaks per
//! record and nothing else.
//!
//! `AssetChain::apply` is the *issuer's* path. It judges every §1.3 condition — the URI's length, the
//! category sequence, non-decreasing effective dates, the attestation — on top of the same two hashes.
//! Measuring it against §4.4a's 5 ms would be measuring the wrong thing, and the first version of this
//! file did exactly that and reported 7.73 ms as a threshold miss. Both figures are below, named for
//! what they are.
//!
//! The third is the full path with real Ed25519 verification per record. §4.4a sets **no threshold** on
//! it in v0.1 and asks only that it be measured and reported.

use certimining_core::{
    AssetChain, ChainState, DalekVerifier, Digest, LeafPreimage, NativeKeccak, PayloadUri,
    Preimage, PreimageBuf, RecordLeafInput, RegistryError, StepHeadPreimage, Verifier,
};
use criterion::{criterion_group, criterion_main, Criterion};
use ed25519_dalek::{Signer as _, SigningKey};
use std::hint::black_box;

/// RFC 8032 §7.1's TEST 1 secret key, whose private half that document publishes. The same key the
/// fuzz targets use, so a bench and a target are signing with one published value rather than two.
const RFC8032_SECRET: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];

const ASSET: Digest = [0x11; 32];
const RECORDS: usize = 10_000;

/// Accepts every signature, so the walk measures hashing and nothing else. This is the instrument
/// §4.4a's "hash recomputation only" asks for; it is not a verifier and never leaves this file.
struct HashOnly;

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
/// the same sequence replays identically against a fresh chain every iteration — which is what lets
/// the measured closure start from `start` rather than carrying state between samples.
fn chain_of(signed: bool) -> Vec<RecordLeafInput> {
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
            // Flat, so INV-STATE-04's non-decreasing rule cannot refuse a record for a reason that
            // has nothing to do with what is being measured.
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

fn walk<H: certimining_core::Hasher, V: Verifier>(records: &[RecordLeafInput]) -> Digest {
    let mut chain = AssetChain::<H, V>::start(&ASSET, 1).expect("starts");
    for r in records {
        let _ = chain.apply(r).expect("applies");
    }
    chain.head()
}

/// The hash chain alone, which is what §4.4a's 5 ms is a threshold on: for each record, the leaf
/// digest and then the step head digest. No condition is judged, because a verifier recomputing a
/// chain does not re-run the issuer's state machine — it checks that the heads follow from the leaves.
fn hash_chain(records: &[RecordLeafInput], genesis: Digest) -> Digest {
    let mut head = genesis;
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

fn benches(c: &mut Criterion) {
    let unsigned = chain_of(false);

    // §4.4a's threshold: 10,000 records, single thread, hash recomputation only, under 5 ms.
    let genesis =
        <AssetChain<NativeKeccak, HashOnly> as ChainState>::genesis(&ASSET, 1).expect("genesis");
    // The recomputation must reach the same head the chain did, or it is not a chain walk.
    assert_eq!(
        hash_chain(&unsigned, genesis),
        walk::<NativeKeccak, HashOnly>(&unsigned),
        "the hash chain and the state machine disagree on the head, so one of them is wrong"
    );
    c.bench_function("chain_walk_10000_hash_chain_only", |b| {
        b.iter(|| black_box(hash_chain(black_box(&unsigned), black_box(genesis))))
    });

    // The issuer's path: the same two hashes per record plus every §1.3 condition. No §4.4a row, and
    // it is reported so the cost of judging a record is visible next to the cost of recomputing one.
    c.bench_function("chain_walk_10000_apply_no_signatures", |b| {
        b.iter(|| black_box(walk::<NativeKeccak, HashOnly>(black_box(&unsigned))))
    });

    // §4.4a: the same walk with per-record Ed25519 verification. Measured and reported; no threshold
    // in v0.1, which §4.4a states outright and D-132 keeps.
    let signed = chain_of(true);
    c.bench_function("chain_walk_10000_with_ed25519", |b| {
        b.iter(|| black_box(walk::<NativeKeccak, DalekVerifier>(black_box(&signed))))
    });
}

criterion_group!(chain, benches);
criterion_main!(chain);
