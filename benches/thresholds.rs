// SPDX-License-Identifier: MIT OR Apache-2.0
//! §4.4a's absolute wall-clock figures, asserted (E-13, D-132, D-136).
//!
//! D-132 splits §4.4a's thresholds by what kind of number they are. Compute units are deterministic, so
//! they are asserted absolutely in CI and already are, by
//! `programs/certimining-checkpoint/tests/compute.rs` in the `kat01-onchain` group. Wall-clock is not
//! deterministic, so a shared runner cannot assert it: §4.4a's absolute figures are asserted **on the
//! reference machine §4.4a names**, which is what this file does, and CI compares against a committed
//! baseline with a band instead.
//!
//! **`#[ignore]`d, and run before submission**, the way V-Z-04's full 10,000-epoch run is. It is not a
//! push gate because the machine it asserts about is not the machine CI runs on.
//!
//! ```text
//! cargo test --release -p certimining-benches --test thresholds -- --ignored --nocapture
//! ```

use certimining_benches::{
    chain_of, genesis, hash_chain, real_leaves, walk, HashOnly, EPOCH, HEIGHT, MASTER, RECORDS,
};
use certimining_core::{DalekVerifier, NativeKeccak};
use certimining_log::{BuiltEpoch, EpochTree, InclusionVerifier, ProofVerifier};
use std::time::{Duration, Instant};

/// Samples per measure. Enough for a median to mean something without making the run long.
const SAMPLES: usize = 7;

/// Discarded runs before sampling starts.
///
/// Without them this instrument disagreed with Criterion by 30%: 9.3 ms median against 7.1 ms, because
/// seven cold samples measure cache and branch-predictor state as much as the code. Criterion warms up
/// for seconds before it records anything, and §4.4a's figure describes steady state, so this has to as
/// well or the assertion is about a different quantity than the row it cites.
const WARM_UP: usize = 5;

/// §4.4a's thresholds, each named once so the check and its failure message cannot drift apart. A
/// mutation run proved they could: the message read "bounded at 10 ms" while the assertion had been
/// changed to 7, which is a message that lies about the rule it is enforcing.
const CHAIN_WALK_MS: f64 = 10.0; // D-136, amended from 5 ms; measured 7.1 ms
const EPOCH_ROOT_MS: f64 = 10.0;
const PROOF_VERIFY_MS: f64 = 1.0;

/// Best, median and worst of `SAMPLES` runs of `f`.
///
/// The assertion is on the **median**. The best of N flatters the implementation by reporting only its
/// unpreempted moments, and the worst reports the operating system's; the median is the figure that
/// moves when the code moves, which is what a threshold is for. All three are printed, because a
/// threshold reported without its spread is the single-sample problem D-132 rejected.
fn measure<T>(mut f: impl FnMut() -> T) -> (Duration, Duration, Duration) {
    for _ in 0..WARM_UP {
        drop(std::hint::black_box(f()));
    }
    let mut times: Vec<Duration> = Vec::with_capacity(SAMPLES);
    for _ in 0..SAMPLES {
        let start = Instant::now();
        let out = f();
        times.push(start.elapsed());
        drop(std::hint::black_box(out));
    }
    times.sort_unstable();
    (times[0], times[SAMPLES / 2], times[SAMPLES - 1])
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1_000.0
}

#[test]
#[ignore = "§4.4a's wall-clock figures are asserted on the reference machine, not on CI's runner"]
fn section_4_4a_wall_clock_figures_hold_on_the_reference_machine() {
    // Constant by design: the point is to refuse a debug run, where the figures would be several times
    // over and the failure would say nothing. Written as a conditional panic rather than an assertion,
    // because `assert!` on a compile-time constant is a clippy error and a cfg-gated `panic!` makes the
    // rest of the function unreachable in clippy's own debug build.
    if cfg!(debug_assertions) {
        panic!(
            "build this with --release: cargo test --release -p certimining-benches --test thresholds -- --ignored --nocapture"
        );
    }

    println!(
        "target {} {}, {} logical cores. §4.4a names the reference machine; this prints what the \
         build saw, which is not the same claim.",
        std::env::consts::ARCH,
        std::env::consts::OS,
        std::thread::available_parallelism().map_or(0, |n| n.get()),
    );

    // §4.4a, D-136: 10,000 records, hash recomputation only, < 10 ms. Measured 7.1 ms.
    let unsigned = chain_of(false);
    let from = genesis();
    assert_eq!(
        hash_chain(&unsigned, from),
        walk::<HashOnly>(&unsigned),
        "the hash chain and the state machine disagree on the head, so the measure is not a chain walk"
    );
    let (best, median, worst) = measure(|| hash_chain(&unsigned, from));
    println!(
        "chain walk, {RECORDS} records, hash recomputation only: best {:.2} ms, median {:.2} ms, \
         worst {:.2} ms (§4.4a: < {CHAIN_WALK_MS} ms)",
        ms(best),
        ms(median),
        ms(worst)
    );
    assert!(
        ms(median) < CHAIN_WALK_MS,
        "§4.4a (D-136): the hash chain over {RECORDS} records is bounded at {CHAIN_WALK_MS} ms and the \
         median was {:.2} ms. The threshold follows the measurement (D-136); if this is a real regression the code \
         moved, and if the figure has genuinely changed the row changes with it rather than the \
         assertion being loosened.",
        ms(median)
    );

    // §4.4a: an epoch root at 256 leaves, < 10 ms.
    let full = real_leaves(1 << HEIGHT);
    let (best, median, worst) = measure(|| {
        <BuiltEpoch as EpochTree>::build::<NativeKeccak>(EPOCH, HEIGHT, &MASTER, &full)
            .expect("builds")
    });
    println!(
        "epoch root, 256 leaves: best {:.3} ms, median {:.3} ms, worst {:.3} ms (§4.4a: < {EPOCH_ROOT_MS} ms)",
        ms(best),
        ms(median),
        ms(worst)
    );
    assert!(
        ms(median) < EPOCH_ROOT_MS,
        "§4.4a: an epoch root at 256 leaves is bounded at {EPOCH_ROOT_MS} ms and the median was \
         {:.3} ms",
        ms(median)
    );

    // §4.4a: one inclusion proof verified, < 1 ms.
    let built = <BuiltEpoch as EpochTree>::build::<NativeKeccak>(EPOCH, HEIGHT, &MASTER, &full)
        .expect("builds");
    let id = full[full.len() / 2].0;
    let leaf = full
        .iter()
        .find(|(i, _)| *i == id)
        .map(|(_, l)| *l)
        .expect("the identifier is in the set");
    let proof = built.proof(&id).expect("a proof");
    let root = built.root;
    ProofVerifier::verify::<NativeKeccak>(&leaf, &proof, &root).expect("the proof verifies");
    let (best, median, worst) =
        measure(|| ProofVerifier::verify::<NativeKeccak>(&leaf, &proof, &root));
    println!(
        "inclusion proof verification: best {:.4} ms, median {:.4} ms, worst {:.4} ms (§4.4a: < {PROOF_VERIFY_MS} ms)",
        ms(best),
        ms(median),
        ms(worst)
    );
    assert!(
        ms(median) < PROOF_VERIFY_MS,
        "§4.4a: an inclusion proof is bounded at {PROOF_VERIFY_MS} ms and the median was {:.4} ms",
        ms(median)
    );

    // §4.4a: measured and reported, **no threshold in v0.1**. Printed and not asserted, because the
    // specification says a threshold here is set in v0.2 from real data rather than guessed now — which
    // is the same discipline D-136 applied to the row above.
    let signed = chain_of(true);
    let (best, median, worst) = measure(|| walk::<DalekVerifier>(&signed));
    println!(
        "full verification including per-record Ed25519, {RECORDS} records: best {:.1} ms, \
         median {:.1} ms, worst {:.1} ms (§4.4a: measured and reported, no threshold in v0.1)",
        ms(best),
        ms(median),
        ms(worst)
    );
}
