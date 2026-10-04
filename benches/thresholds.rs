// SPDX-License-Identifier: MIT OR Apache-2.0
//! §4.4a's wall-clock figures, measured and reported (E-13, D-132, D-136, D-137).
//!
//! **This asserted three absolute bounds and no longer does.** §4.4a's chain-walk row carried `< 5 ms`,
//! then `< 10 ms` after E-13 measured 7.1 ms (D-136). An independent review then ran that assertion on a
//! different machine satisfying the same description in §4.4a — Apple M2, 8 cores, macOS 26.6.2 — and
//! measured medians of 17.92, 16.65 and 19.52 ms. The author's own machine, which had measured 7 ms
//! idle, measured 13.77 ms with another test suite running beside it. One figure, four values spanning
//! seven to nineteen and a half milliseconds, all on hardware matching the specification's own words.
//!
//! So the owner ruled (D-137) that the wall-clock absolutes leave §4.4a: a bound stated against a machine
//! description that does not determine the figure is not a property of this system. What holds the line
//! instead is what can: the compute-unit figures, which are deterministic and confirmed against the
//! announced deployment's own transactions, asserted absolutely in CI; and `band.rs`, which holds one
//! runner to its own previous numbers so a change in the *code* still shows up.
//!
//! What this file does now is **measure and report, with the machine named**. It asserts no performance
//! threshold, so no figure here can fail on a loaded laptop; its correctness controls still can, and do
//! — the chain-walk cross-check, the proof verification and the pinned workload below all fail loudly.
//! What that split means in practice is that its output has to be read rather than trusted to a
//! green tick. It stays `#[ignore]`d and runs before submission, on CONTRIBUTING's checklist.
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

/// What `ts/test/perf.test.ts:110-116` prints, in Rust and without a dependency: enough of the machine
/// that a reader can tell whether a figure came from theirs (PR #59, round two, Medium 1).
///
/// Every field is read from the running system or declared absent. `std::env::consts` and
/// `available_parallelism` come from the standard library; the CPU model, kernel release and memory
/// size have no portable standard-library source, so they are read from the platform's own interface
/// — `sysctl` and `uname` on macOS, `/proc` on Linux — and print as `unknown` where that fails.
/// Nothing here is guessed from another field.
fn probe(command: &str, args: &[&str]) -> Option<String> {
    let out = std::process::Command::new(command)
        .args(args)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8(out.stdout).ok()?;
    let trimmed = text.trim().to_string();
    (!trimmed.is_empty()).then_some(trimmed)
}

/// The first value of a `/proc` line, e.g. `model name\t: Xeon` or `MemTotal:  16305236 kB`.
fn proc_field(path: &str, key: &str) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    text.lines()
        .find(|line| line.starts_with(key))
        .and_then(|line| line.split(':').nth(1))
        .map(|value| value.trim().to_string())
}

fn cpu_model() -> String {
    probe("sysctl", &["-n", "machdep.cpu.brand_string"])
        .or_else(|| probe("sysctl", &["-n", "hw.model"]))
        .or_else(|| proc_field("/proc/cpuinfo", "model name"))
        .unwrap_or_else(|| "unknown CPU".to_string())
}

/// Printed in binary gigabytes, the unit the TypeScript report already uses.
fn memory_gib() -> String {
    if let Some(bytes) = probe("sysctl", &["-n", "hw.memsize"]).and_then(|v| v.parse::<u64>().ok())
    {
        return format!("{} GiB", bytes / (1 << 30));
    }
    if let Some(kb) = proc_field("/proc/meminfo", "MemTotal")
        .and_then(|v| v.split_whitespace().next()?.parse::<u64>().ok())
    {
        return format!("{} GiB", kb / (1 << 20));
    }
    "unknown memory".to_string()
}

/// `rustc` as found on `PATH` when the test runs. That is **not necessarily the compiler that built this
/// binary**, which is why the label says so rather than claiming the build's version.
fn rustc_on_path() -> String {
    probe("rustc", &["--version"]).unwrap_or_else(|| "rustc unknown".to_string())
}

fn machine() -> String {
    let label = std::env::var("CERTIMINING_MACHINE").unwrap_or_default();
    let named = if label.is_empty() {
        "unlabelled (set CERTIMINING_MACHINE to name this machine in the record)".to_string()
    } else {
        label
    };
    format!(
        "{named}\n           {}, {} {} {}, {} available parallelism, {}\n           {} on PATH, {} profile",
        cpu_model(),
        std::env::consts::OS,
        probe("uname", &["-r"]).unwrap_or_else(|| "unknown release".to_string()),
        std::env::consts::ARCH,
        std::thread::available_parallelism()
            .map_or_else(|_| "unknown".to_string(), |n| n.get().to_string()),
        memory_gib(),
        rustc_on_path(),
        if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        },
    )
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1_000.0
}

#[test]
#[ignore = "§4.4a's wall-clock figures are reported, not asserted; run before submission and record them"]
fn section_4_4a_wall_clock_figures_are_measured_and_reported() {
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
        "\n§4.4a measurements\n  machine: {}\n  §4.4a names a reference machine; the above is the one \
         this run saw, which is not the same claim.\n",
        machine()
    );

    // **The row names are literals and the fixtures are not (PR #59, round two, High 1).** That finding
    // was against `band.rs`, where a mutable `HEIGHT` let a 16-leaf build pass as `epoch_root_256_leaves`.
    // The same gap reaches this file: it prints "256 leaves" and "{RECORDS} records" as text. Here it
    // produces a false record rather than a false pass, which §4.4a's figures are recorded from, so the
    // workload is pinned to what the rows claim before anything is timed.
    assert_eq!(HEIGHT, 8, "§4.4a's figures are at the deployed height");
    assert_eq!(
        RECORDS, 10_000,
        "§4.4a's chain rows are over 10,000 records"
    );

    // **Round two pinned the fixtures this function happened to build first, and the signed chain was
    // built sixty lines later (PR #59, round three, High).** `chain_of` takes a `signed` flag, so a
    // helper can agree with `RECORDS` on one branch and disagree on the other: a review made the signed
    // branch a hundredth of the size, every existing pin passed, and the Ed25519 row printed 4.1 ms
    // under a label reading 10,000 records. Pinning per row is pinning what you happen to be looking
    // at. Every fixture is built and checked here, before the first `measure`, so that claim is literal.
    let unsigned = chain_of(false);
    let signed = chain_of(true);
    let full = real_leaves(1 << HEIGHT);
    assert_eq!(
        unsigned.len(),
        10_000,
        "the unsigned chain fixture is not the 10,000 records its row names"
    );
    assert_eq!(
        signed.len(),
        10_000,
        "the signed chain fixture is not the 10,000 records its row names"
    );
    assert_eq!(
        full.len(),
        256,
        "the epoch fixture is not the 256 leaves its rows name"
    );

    // §4.4a: 10,000 records, hash recomputation only. Reported, no threshold (D-137); D-136's 10 ms
    // gate was removed after two machines matching §4.4a's description measured 7 ms and 17.6-19.5 ms.
    let from = genesis();
    assert_eq!(
        hash_chain(&unsigned, from),
        walk::<HashOnly>(&unsigned),
        "the hash chain and the state machine disagree on the head, so the measure is not a chain walk"
    );
    let (best, median, worst) = measure(|| hash_chain(&unsigned, from));
    println!(
        "chain walk, {RECORDS} records, hash recomputation only: best {:.2} ms, median {:.2} ms, \
         worst {:.2} ms (§4.4a: reported, no threshold)",
        ms(best),
        ms(median),
        ms(worst)
    );

    // §4.4a: an epoch root at 256 leaves. Reported, no threshold (D-137).
    let (best, median, worst) = measure(|| {
        <BuiltEpoch as EpochTree>::build::<NativeKeccak>(EPOCH, HEIGHT, &MASTER, &full)
            .expect("builds")
    });
    println!(
        "epoch root, 256 leaves: best {:.3} ms, median {:.3} ms, worst {:.3} ms (§4.4a: reported, no threshold)",
        ms(best),
        ms(median),
        ms(worst)
    );

    // §4.4a: one inclusion proof verified. Reported, no threshold (D-137).
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
        "inclusion proof verification: best {:.4} ms, median {:.4} ms, worst {:.4} ms (§4.4a: reported, no threshold)",
        ms(best),
        ms(median),
        ms(worst)
    );

    // §4.4a: measured and reported, **no threshold in v0.1**. Printed and not asserted, because the
    // specification says a threshold here is set in v0.2 from real data rather than guessed now — which
    // is the same discipline D-136 applied to the row above.
    let (best, median, worst) = measure(|| walk::<DalekVerifier>(&signed));
    println!(
        "full verification including per-record Ed25519, {RECORDS} records: best {:.1} ms, \
         median {:.1} ms, worst {:.1} ms (§4.4a: measured and reported, no threshold in v0.1)",
        ms(best),
        ms(median),
        ms(worst)
    );
}
