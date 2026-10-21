// SPDX-License-Identifier: MIT OR Apache-2.0
//! What the preimage path costs per call, against hashing the same bytes directly (H-19, issue #58).
//!
//! **The question.** §4.4a's chain walk is two Keccak-256 invocations per record — about 350 ns each
//! for 10,000 records in 7.1 ms. Each digest builds its preimage into a `PreimageBuf`, a
//! `heapless::Vec<u8, MAX_PREIMAGE_LEN>`, through `staged` writes that enforce INV-ENC-01's tag
//! placement, and then hashes it. That construction is why no caller can omit a tag (D-36, D-64).
//! Whether it also costs measurably per call was never measured.
//!
//! **Why a Criterion bench and not a timing loop.** The first attempt at this used a hand-rolled
//! harness and reported the full path as *faster* than hashing alone — three times, by 162, 372 and
//! 381 ns. That is not a result, it is an instrument reading its own noise, and no figure was
//! published from it. The difference being looked for is a fraction of 350 ns, which is below what a
//! loop around `Instant::now()` can resolve on a machine with a scheduler. Criterion samples,
//! reports a confidence interval, and says when it cannot distinguish two things.
//!
//! **What each arm does.** Both hash the same bytes and return the digest, so neither can be
//! optimised away and nothing is timed that produces no value.
//!
//! - `through the preimage path` is what the engine does: build the preimage through `staged`, then
//!   hash it.
//! - `the same bytes, already contiguous` hashes a buffer built once outside the measured region.
//!
//! Their difference is the construction cost: the bounds checks, the staging and the copy. It is not
//! an argument for removing any of them — INV-ENC-01's guarantee is worth more than the nanoseconds,
//! and the issue says so — it is the figure that was missing.

use certimining_core::{
    Digest, Hasher, LeafPreimage, NativeKeccak, Preimage, PreimageBuf, StepHeadPreimage,
};
use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;

/// §1.3's record fields, as the chain walk hashes them. Values are arbitrary and fixed.
const ASSET: Digest = [0x11; 32];
const PAYLOAD: Digest = [0x22; 32];
const ASSESSMENT: Digest = [0x33; 32];
const QP: [u8; 32] = [0x44; 32];
const PREV: Digest = [0x66; 32];

fn leaf() -> LeafPreimage {
    LeafPreimage {
        asset_commitment: ASSET,
        seq: 1,
        payload_digest: PAYLOAD,
        assessment_digest: ASSESSMENT,
        qp_key: QP,
        category: 0,
        effective_at: 1_700_259_200,
        change_identified_at: 1_700_172_800,
    }
}

/// The bytes a preimage writes, built once so an arm can hash them without building them.
fn bytes_of<P: Preimage>(p: &P) -> Vec<u8> {
    let mut buf = PreimageBuf::new();
    match p.write_preimage(&mut buf) {
        Ok(()) => buf.as_bytes().to_vec(),
        Err(e) => panic!("the bench's own preimage does not encode: {e:?}"),
    }
}

fn benches(c: &mut Criterion) {
    let leaf = leaf();
    let leaf_bytes = bytes_of(&leaf);
    assert_eq!(
        leaf_bytes.len(),
        161,
        "§1.3's leaf preimage is 161 bytes; a bench measuring another length measures another thing"
    );

    let head = StepHeadPreimage {
        prev_head: PREV,
        leaf: ASSET,
    };
    let head_bytes = bytes_of(&head);
    assert_eq!(head_bytes.len(), 72, "§1.3's head preimage is 72 bytes");

    let mut group = c.benchmark_group("leaf, 161 bytes");
    group.bench_function("through the preimage path", |b| {
        b.iter(|| {
            let mut buf = PreimageBuf::new();
            match black_box(&leaf).write_preimage(&mut buf) {
                Ok(()) => {}
                Err(e) => panic!("{e:?}"),
            }
            black_box(NativeKeccak::hashv(&[buf.as_bytes()]))
        })
    });
    group.bench_function("the same bytes, already contiguous", |b| {
        b.iter(|| black_box(NativeKeccak::hashv(&[black_box(leaf_bytes.as_slice())])))
    });
    group.finish();

    let mut group = c.benchmark_group("head, 72 bytes");
    group.bench_function("through the preimage path", |b| {
        b.iter(|| {
            let mut buf = PreimageBuf::new();
            match black_box(&head).write_preimage(&mut buf) {
                Ok(()) => {}
                Err(e) => panic!("{e:?}"),
            }
            black_box(NativeKeccak::hashv(&[buf.as_bytes()]))
        })
    });
    group.bench_function("the same bytes, already contiguous", |b| {
        b.iter(|| black_box(NativeKeccak::hashv(&[black_box(head_bytes.as_slice())])))
    });
    group.finish();

    // **Does the slice-of-slices interface cost anything?** The second question the issue asks.
    // `hashv` takes `&[&[u8]]`; every caller in the engine passes one slice. This measures the same
    // bytes handed over as one slice and as two halves.
    let mut group = c.benchmark_group("hashv's interface, 161 bytes");
    let (first, second) = leaf_bytes.split_at(80);
    group.bench_function("one slice", |b| {
        b.iter(|| black_box(NativeKeccak::hashv(&[black_box(leaf_bytes.as_slice())])))
    });
    group.bench_function("two slices", |b| {
        b.iter(|| black_box(NativeKeccak::hashv(&[black_box(first), black_box(second)])))
    });
    group.finish();
}

criterion_group!(preimage, benches);
criterion_main!(preimage);
