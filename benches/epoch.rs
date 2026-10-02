// SPDX-License-Identifier: MIT OR Apache-2.0
//! §4.4a's two epoch measures (E-13, D-132), as distributions.
//!
//! Both at the deployed height, `H = 8`, so the figures describe the log that is announced. The tree is
//! full either way (INV-TREE-02), so 256 is the capacity and the record count decides only how many of
//! those leaves are real.

use certimining_benches::{real_leaves, EPOCH, HEIGHT, MASTER};
use certimining_core::NativeKeccak;
use certimining_log::{BuiltEpoch, EpochTree, InclusionVerifier, ProofVerifier};
use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;

fn benches(c: &mut Criterion) {
    // §4.4a: an epoch root at 256 leaves. An epoch full of real leaves is the dearest case for the
    // builder's open addressing — the last submission has one free slot left to probe.
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

    // §4.4a: one inclusion proof verified. Built outside the closure, because what is measured is
    // verification and not proof production.
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
    // A bench that measured a refusal would measure the wrong path, so this asserts the proof verifies
    // before it is timed.
    ProofVerifier::verify::<NativeKeccak>(&leaf, &proof, &root).expect("the proof verifies");
    c.bench_function("inclusion_proof_verify", |b| {
        b.iter(|| {
            // The `Result` goes through `black_box`, not the `()` inside it: unwrapping first and
            // boxing a unit value tells the optimiser nothing.
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
