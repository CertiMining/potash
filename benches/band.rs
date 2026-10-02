// SPDX-License-Identifier: MIT OR Apache-2.0
//! The CI half of §4.4a's wall-clock thresholds (E-13, D-132): a committed baseline and a band.
//!
//! §4.4a's absolute figures are asserted on the reference machine by `thresholds.rs`. This is the other
//! half of D-132's split: a shared runner cannot be held to those numbers, so it is held to its own
//! previous numbers instead. A measure that drifts above its baseline by more than `band_percent`
//! fails the build.
//!
//! **A baseline nobody measured would be a gate that cannot fail.** So an absent entry is a failure that
//! prints what it measured, and the figure is committed from that run's output. Nothing here invents a
//! number.

use certimining_benches::{chain_of, genesis, hash_chain, real_leaves, EPOCH, HEIGHT, MASTER};
use certimining_core::NativeKeccak;
use certimining_log::{BuiltEpoch, EpochTree, InclusionVerifier, ProofVerifier};
use std::time::{Duration, Instant};

const WARM_UP: usize = 5;
const SAMPLES: usize = 7;

/// Warm up, then the median of `SAMPLES`. The same instrument `thresholds.rs` uses, for the same reason:
/// without warm-up this reads 30% high and measures cache state rather than code.
fn median_ms<T>(mut f: impl FnMut() -> T) -> f64 {
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
    times[SAMPLES / 2].as_secs_f64() * 1_000.0
}

/// `band_percent` and the `[measures]` table, read from the committed file rather than restated here.
fn baseline() -> (f64, Vec<(String, f64)>) {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("BASELINE.toml");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let mut band = None;
    let mut measures = Vec::new();
    let mut in_measures = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        if line == "[measures]" {
            in_measures = true;
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let (key, value) = (key.trim(), value.trim());
        let parsed: f64 = value
            .parse()
            .unwrap_or_else(|_| panic!("{key}: {value} is not a number"));
        if in_measures {
            measures.push((key.to_string(), parsed));
        } else if key == "band_percent" {
            band = Some(parsed);
        }
    }
    (band.expect("band_percent"), measures)
}

#[test]
fn wall_clock_measures_stay_inside_their_band() {
    // Constant by design: the point is to refuse a debug run, where the figures would be several times
    // over and the failure would say nothing. Written as a conditional panic rather than an assertion,
    // because `assert!` on a compile-time constant is a clippy error and a cfg-gated `panic!` makes the
    // rest of the function unreachable in clippy's own debug build.
    if cfg!(debug_assertions) {
        panic!(
            "build this with --release: cargo test --release -p certimining-benches --test band"
        );
    }

    let (band, committed) = baseline();

    let unsigned = chain_of(false);
    let from = genesis();
    let full = real_leaves(1 << HEIGHT);
    let built = <BuiltEpoch as EpochTree>::build::<NativeKeccak>(EPOCH, HEIGHT, &MASTER, &full)
        .expect("builds");
    let id = full[full.len() / 2].0;
    let leaf = full
        .iter()
        .find(|(i, _)| *i == id)
        .map(|(_, l)| *l)
        .expect("in the set");
    let proof = built.proof(&id).expect("a proof");
    let root = built.root;

    let measured: Vec<(&str, f64)> = vec![
        (
            "chain_walk_hash_chain_only",
            median_ms(|| hash_chain(&unsigned, from)),
        ),
        (
            "epoch_root_256_leaves",
            median_ms(|| {
                <BuiltEpoch as EpochTree>::build::<NativeKeccak>(EPOCH, HEIGHT, &MASTER, &full)
                    .expect("builds")
            }),
        ),
        (
            "inclusion_proof_verify",
            median_ms(|| ProofVerifier::verify::<NativeKeccak>(&leaf, &proof, &root)),
        ),
    ];

    let mut missing: Vec<String> = Vec::new();
    let mut over: Vec<String> = Vec::new();
    for (name, now) in &measured {
        match committed.iter().find(|(k, _)| k == name) {
            None => missing.push(format!("{name} = {now:.4}")),
            Some((_, was)) => {
                let limit = was * (1.0 + band / 100.0);
                println!("{name}: {now:.4} ms, baseline {was:.4} ms, limit {limit:.4} ms");
                if now > &limit {
                    over.push(format!(
                        "{name}: {now:.4} ms against a baseline of {was:.4} ms, which is more than \
                         {band}% above it"
                    ));
                }
            }
        }
    }

    assert!(
        missing.is_empty(),
        "benches/BASELINE.toml has no figure for {} measure(s) on this machine, so there is nothing to \
         compare against and this gate would otherwise pass without checking anything. Measured now — \
         commit these under [measures] if this run is the runner the baseline is for:\n{}",
        missing.len(),
        missing.join("\n")
    );
    assert!(
        over.is_empty(),
        "§4.4a, D-132: a wall-clock measure drifted past its band:\n{}\nThis is a regression detector \
         and not §4.4a's threshold — that one is asserted on the reference machine by thresholds.rs. \
         If the slowdown is real, find it; if the runner changed, the baseline is re-measured and \
         re-committed with the reason.",
        over.join("\n")
    );
}
