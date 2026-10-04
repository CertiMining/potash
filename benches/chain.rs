// SPDX-License-Identifier: MIT OR Apache-2.0
//! §4.4a's chain-walk measures (E-13, D-132, D-136), as distributions.
//!
//! §4.4a carries no wall-clock threshold on these any more (D-137); `thresholds.rs` reports the same
//! figures as medians with the machine named, and this file reports their distributions. The three
//! measures are kept apart because §4.4a distinguishes them: its row is "hash recomputation only",
//! `apply` is the issuer's path, and the Ed25519 path is measured and reported in v0.1 by §4.4a's own
//! wording.

use certimining_benches::{chain_of, genesis, hash_chain, walk, HashOnly};
use certimining_core::DalekVerifier;
use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;

fn benches(c: &mut Criterion) {
    let unsigned = chain_of(false);
    let from = genesis();

    // The recomputation must reach the head the state machine reached, or it is not a chain walk.
    assert_eq!(
        hash_chain(&unsigned, from),
        walk::<HashOnly>(&unsigned),
        "the hash chain and the state machine disagree on the head, so one of them is wrong"
    );

    // §4.4a: 10,000 records, single thread, hash recomputation only. D-136's threshold.
    c.bench_function("chain_walk_10000_hash_chain_only", |b| {
        b.iter(|| black_box(hash_chain(black_box(&unsigned), black_box(from))))
    });

    // The issuer's path. No §4.4a row; reported so the cost of judging a record is visible beside the
    // cost of recomputing one.
    c.bench_function("chain_walk_10000_apply_no_signatures", |b| {
        b.iter(|| black_box(walk::<HashOnly>(black_box(&unsigned))))
    });

    // §4.4a: measured and reported, no threshold in v0.1.
    let signed = chain_of(true);
    c.bench_function("chain_walk_10000_with_ed25519", |b| {
        b.iter(|| black_box(walk::<DalekVerifier>(black_box(&signed))))
    });
}

criterion_group!(chain, benches);
criterion_main!(chain);
