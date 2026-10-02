// SPDX-License-Identifier: MIT OR Apache-2.0
//! §4.4a's two epoch measures (E-13, D-132): building a full epoch's root, and verifying one
//! inclusion proof against it.
//!
//! Both are at the deployed height, `H = 8`, so the figures describe the log that is announced rather
//! than a shape it does not run. The tree is full either way (INV-TREE-02), so "256 leaves" is the
//! capacity and the record count only decides how many of them are real.

use certimining_core::{Digest, NativeKeccak, SubmissionId};
use certimining_log::{BuiltEpoch, EpochTree, InclusionVerifier, ProofVerifier};
use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;

const HEIGHT: u8 = 8;
const MASTER: Digest = [0x5a; 32];
const EPOCH: u64 = 20_728;

/// A full epoch: `count` real leaves, the rest padding, as a real publisher's would be.
fn real_leaves(count: usize) -> Vec<(SubmissionId, Digest)> {
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

fn benches(c: &mut Criterion) {
    // §4.4a: an epoch root at 256 leaves. Threshold < 10 ms. The epoch is full of real leaves, which
    // is the dearest case for the builder's open addressing: the last submission has one free slot.
    let full = real_leaves(1 << HEIGHT);
    c.bench_function("epoch_root_256_leaves", |b| {
        b.iter(|| {
            black_box(
                <BuiltEpoch as EpochTree>::build::<NativeKeccak>(
                    EPOCH,
                    HEIGHT,
                    &MASTER,
                    black_box(&full),
                )
                .expect("the engine builds a full epoch"),
            )
        })
    });

    // §4.4a: one inclusion proof verified. Threshold < 1 ms. Built outside the closure, because what
    // is measured is verification and not proof production.
    let built = <BuiltEpoch as EpochTree>::build::<NativeKeccak>(EPOCH, HEIGHT, &MASTER, &full)
        .expect("builds");
    let id = full[full.len() / 2].0;
    let leaf = full
        .iter()
        .find(|(i, _)| *i == id)
        .map(|(_, leaf)| *leaf)
        .expect("the identifier is in the set");
    let proof = built.proof(&id).expect("a proof for a real submission");
    let root = built.root;
    // A bench that measured a refusal would be measuring the wrong path, so this asserts the proof
    // verifies before it is timed.
    ProofVerifier::verify::<NativeKeccak>(&leaf, &proof, &root).expect("the proof verifies");
    c.bench_function("inclusion_proof_verify", |b| {
        b.iter(|| {
            // The `Result` itself goes through `black_box`, not the `()` inside it: unwrapping first
            // and boxing a unit value tells the optimiser nothing and clippy says so.
            black_box(ProofVerifier::verify::<NativeKeccak>(
                black_box(&leaf),
                black_box(&proof),
                black_box(&root),
            ))
        })
    });
}

criterion_group!(epoch, benches);
criterion_main!(epoch);
