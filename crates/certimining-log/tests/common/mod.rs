// SPDX-License-Identifier: MIT OR Apache-2.0
//! Helpers the epoch-tree tests share: the published test key, deterministic inputs, and the
//! classifier and statistics §4.4 specifies for V-Z-02 and V-Z-04.
//!
//! Each test file is its own crate, so anything one file does not use looks dead from that file.
//! The allow below is that and nothing more.
#![allow(dead_code)]

use certimining_core::{Digest, Hasher, SubmissionId};
use certimining_log::{BuiltEpoch, EpochTree};

/// D-63's published specification test master key. Its bytes spell out what it is, so no reader can
/// mistake it for a real one, and `k_e` is always derived from it through the specification's own
/// `0x01 ‖ e_le` path. A real `k_master` never appears in this repository (INV-TREE-05).
pub const TEST_MASTER_KEY: Digest = *b"CMv1 TEST MASTER KEY, NOT SECRET";

/// A stand-in hasher: not cryptographic, but distinct inputs give distinct digests, which is all the
/// structural cases need. It keeps them running in every feature set. Nothing about privacy is ever
/// measured with it.
pub struct MixHash;

impl Hasher for MixHash {
    fn hashv(parts: &[&[u8]]) -> Digest {
        let mut state: u64 = 0xcbf2_9ce4_8422_2325;
        for part in parts {
            for byte in *part {
                state ^= u64::from(*byte);
                state = state.wrapping_mul(0x0000_0100_0000_01b3);
            }
        }
        let mut out = [0u8; 32];
        for (i, chunk) in out.chunks_mut(8).enumerate() {
            chunk.copy_from_slice(&(state ^ (i as u64)).to_le_bytes());
        }
        out
    }
}

/// A deterministic generator. Every statistical test in this suite is reproducible to the bit, so a
/// failure is a finding rather than a bad draw, and nothing here can flake.
pub struct SplitMix(pub u64);

impl SplitMix {
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// A value below `bound`, by rejection-free reduction. The bias is far below anything these
    /// tests measure.
    pub fn below(&mut self, bound: usize) -> usize {
        if bound == 0 {
            return 0;
        }
        (self.next_u64() % bound as u64) as usize
    }

    pub fn shuffle<T>(&mut self, items: &mut [T]) {
        for i in (1..items.len()).rev() {
            let j = self.below(i + 1);
            items.swap(i, j);
        }
    }
}

/// A submission identifier from a counter, which is the hard case: an identifier that carries the
/// submission's order is exactly what V-Z-04 must show the slot does not follow.
pub fn sequential_id(n: u64) -> SubmissionId {
    let mut id = [0u8; 16];
    id[..8].copy_from_slice(&n.to_le_bytes());
    id
}

/// A submission identifier with no structure a reader could exploit.
pub fn scattered_id(seed: u64) -> SubmissionId {
    let mut mix = SplitMix(seed);
    let mut id = [0u8; 16];
    id[..8].copy_from_slice(&mix.next_u64().to_le_bytes());
    id[8..].copy_from_slice(&mix.next_u64().to_le_bytes());
    id
}

/// A stand-in chain leaf. The tree takes a digest and never looks inside it, so these need only be
/// distinct.
pub fn leaf_digest(n: u64) -> Digest {
    let mut mix = SplitMix(n ^ 0x1eaf_1eaf_1eaf_1eaf);
    let mut out = [0u8; 32];
    for chunk in out.chunks_mut(8) {
        chunk.copy_from_slice(&mix.next_u64().to_le_bytes());
    }
    out
}

/// `count` submissions under sequential identifiers.
pub fn submissions(count: usize) -> Vec<(SubmissionId, Digest)> {
    (0..count as u64)
        .map(|n| (sequential_id(n), leaf_digest(n)))
        .collect()
}

/// Builds one epoch of `real_count` submissions at `height`, with the published test key.
pub fn epoch<H: Hasher>(epoch_number: u64, height: u8, real_count: usize) -> BuiltEpoch {
    let real: Vec<(SubmissionId, Digest)> = (0..real_count as u64)
        .map(|n| {
            (
                scattered_id(epoch_number.wrapping_mul(1_000_003).wrapping_add(n)),
                leaf_digest(epoch_number.wrapping_mul(7_919).wrapping_add(n)),
            )
        })
        .collect();
    BuiltEpoch::build::<H>(epoch_number, height, &TEST_MASTER_KEY, &real)
        .expect("these inputs are within capacity")
}

/// Which slots hold real leaves, which is ground truth the classifier never sees.
pub fn real_slots(built: &BuiltEpoch) -> Vec<u16> {
    let mut slots: Vec<u16> = built.assignment.iter().map(|(_, slot)| *slot).collect();
    slots.sort_unstable();
    slots
}

/// Which slots hold padding.
pub fn padding_slots(built: &BuiltEpoch) -> Vec<u16> {
    let real = real_slots(built);
    (0..built.leaves.len() as u16)
        .filter(|slot| real.binary_search(slot).is_err())
        .collect()
}

// ------------------------------------------------------------------ V-Z-02's classifier (§4.4)

/// The features §4.4 names. Each is scored on its own and the combination is scored as well, so a
/// leak in any one of them fails the test rather than being averaged away.
pub const FEATURE_NAMES: [&str; 9] = [
    "per-position byte deviation",
    "population count",
    "zero bytes",
    "leading zero bits",
    "longest equal run",
    "distinct byte values",
    "nibble chi-squared",
    "hamming distance to the adjacent slots",
    "hamming distance to the root",
];

pub const FEATURE_COUNT: usize = FEATURE_NAMES.len();

fn hamming(a: &Digest, b: &Digest) -> u32 {
    a.iter().zip(b).map(|(x, y)| (x ^ y).count_ones()).sum()
}

fn leading_zero_bits(d: &Digest) -> u32 {
    let mut count = 0;
    for byte in d {
        count += byte.leading_zeros();
        if *byte != 0 {
            break;
        }
    }
    count
}

fn longest_equal_run(d: &Digest) -> usize {
    let mut best = 1;
    let mut run = 1;
    for pair in d.windows(2) {
        if pair[0] == pair[1] {
            run += 1;
            best = best.max(run);
        } else {
            run = 1;
        }
    }
    best
}

fn distinct_bytes(d: &Digest) -> usize {
    let mut seen = [false; 256];
    let mut count = 0;
    for byte in d {
        if !seen[*byte as usize] {
            seen[*byte as usize] = true;
            count += 1;
        }
    }
    count
}

fn nibble_chi_squared(d: &Digest) -> f64 {
    let mut counts = [0f64; 16];
    for byte in d {
        counts[(*byte >> 4) as usize] += 1.0;
        counts[(*byte & 0x0f) as usize] += 1.0;
    }
    let expected = 64.0 / 16.0;
    counts
        .iter()
        .map(|c| (c - expected) * (c - expected) / expected)
        .sum()
}

/// The classifier §4.4 specifies: given the root and every leaf digest in slot order and no key, it
/// scores each slot on each feature. The adversary is computationally bounded, specifically the named
/// battery below: an adversary who could search the key space would derive `k_e` and answer exactly,
/// so what this establishes is that these statistics do not distinguish, never that none can (RES-09).
pub fn feature_matrix(leaves: &[Digest], root: &Digest) -> Vec<[f64; FEATURE_COUNT]> {
    let n = leaves.len();
    let mut mean = [0f64; 32];
    for leaf in leaves {
        for (m, byte) in mean.iter_mut().zip(leaf) {
            *m += f64::from(*byte);
        }
    }
    for m in mean.iter_mut() {
        *m /= n as f64;
    }

    leaves
        .iter()
        .enumerate()
        .map(|(index, leaf)| {
            let previous = leaves[(index + n - 1) % n];
            let next = leaves[(index + 1) % n];
            [
                leaf.iter()
                    .zip(&mean)
                    .map(|(byte, m)| (f64::from(*byte) - m).abs())
                    .sum(),
                f64::from(leaf.iter().map(|b| b.count_ones()).sum::<u32>()),
                leaf.iter().filter(|b| **b == 0).count() as f64,
                f64::from(leading_zero_bits(leaf)),
                longest_equal_run(leaf) as f64,
                distinct_bytes(leaf) as f64,
                nibble_chi_squared(leaf),
                f64::from(hamming(leaf, &previous) + hamming(leaf, &next)),
                f64::from(hamming(leaf, root)),
            ]
        })
        .collect()
}

/// One score per slot: every feature standardised across the epoch's leaf set and summed, which is
/// the strongest single guess the listed features support.
pub fn combined_scores(matrix: &[[f64; FEATURE_COUNT]]) -> Vec<f64> {
    let n = matrix.len() as f64;
    let mut totals = [0f64; FEATURE_COUNT];
    for row in matrix {
        for (total, value) in totals.iter_mut().zip(row) {
            *total += value;
        }
    }
    let means: Vec<f64> = totals.iter().map(|t| t / n).collect();
    let mut variances = [0f64; FEATURE_COUNT];
    for row in matrix {
        for (index, value) in row.iter().enumerate() {
            let d = value - means[index];
            variances[index] += d * d;
        }
    }
    let deviations: Vec<f64> = variances.iter().map(|v| (v / n).sqrt()).collect();

    matrix
        .iter()
        .map(|row| {
            row.iter()
                .enumerate()
                .map(|(index, value)| {
                    if deviations[index] == 0.0 {
                        0.0
                    } else {
                        (value - means[index]) / deviations[index]
                    }
                })
                .sum()
        })
        .collect()
}

/// D-60's assignment, transcribed from §1.4 into the test rather than called from the engine: the tag
/// as a literal, the PRF's preimage assembled here, its output read as a little-endian integer and
/// reduced to the low `H` bits, then the first free slot upward with wrapping, over submissions taken
/// in ascending identifier order.
///
/// This is what closes a count channel through `slot_index`, which the second review found V-Z-03's
/// field checks could not see: if any slot depends on how many records an epoch holds, the engine's
/// assignment cannot equal this one. Regenerated vectors cannot serve here, because the generator runs
/// the engine under test.
pub fn assignment_oracle<H: Hasher>(
    epoch_number: u64,
    height: u8,
    k_master: &Digest,
    real: &[(SubmissionId, Digest)],
) -> Vec<(SubmissionId, u16)> {
    /// §1.2's tag, written out rather than read from the crate.
    const SPEC_TAG_PRF: [u8; 8] = *b"CMv1PRF0";

    // `PRF(k, x) = Keccak256(TAG_PRF ‖ k ‖ len(x) ‖ x)` with a `u16` length (§1.1, D-59).
    let prf = |key: &Digest, input: &[u8]| -> Digest {
        let mut preimage = Vec::new();
        preimage.extend_from_slice(&SPEC_TAG_PRF);
        preimage.extend_from_slice(key);
        preimage.extend_from_slice(&(input.len() as u16).to_le_bytes());
        preimage.extend_from_slice(input);
        H::hashv(&[&preimage])
    };

    let mut epoch_input = vec![0x01u8];
    epoch_input.extend_from_slice(&epoch_number.to_le_bytes());
    let k_e = prf(k_master, &epoch_input);

    let capacity = 1usize << height;
    let mut taken = vec![false; capacity];
    let mut ordered: Vec<(SubmissionId, Digest)> = real.to_vec();
    ordered.sort_unstable_by_key(|entry| entry.0);

    let mut assignment: Vec<(SubmissionId, u16)> = Vec::new();
    for (id, _) in &ordered {
        let mut slot_input = vec![0x02u8];
        slot_input.extend_from_slice(id);
        let seed = prf(&k_e, &slot_input);
        let start = usize::from(u16::from_le_bytes([seed[0], seed[1]])) & (capacity - 1);
        let slot = (0..capacity)
            .map(|step| (start + step) % capacity)
            .find(|candidate| !taken[*candidate])
            .expect("a set inside capacity always finds a slot");
        taken[slot] = true;
        assignment.push((*id, slot as u16));
    }
    assignment
}

// ------------------------------------------------------------------ statistics

/// The two-sided critical value at α = 0.001 (D-66).
pub const Z_ALPHA_0_001: f64 = 3.2905;

/// The band a fair coin's successes stay inside at α = 0.001.
pub fn binomial_band(trials: usize) -> (f64, f64) {
    let n = trials as f64;
    let half = n / 2.0;
    let spread = Z_ALPHA_0_001 * n.sqrt() / 2.0;
    (half - spread, half + spread)
}

/// Fails with the numbers in the message, because a privacy blocker that fails must say by how much.
pub fn assert_indistinguishable(label: &str, successes: usize, trials: usize) {
    let (low, high) = binomial_band(trials);
    let rate = successes as f64 / trials as f64;
    assert!(
        (successes as f64) >= low && (successes as f64) <= high,
        "{label}: {successes} of {trials} ({rate:.4}) leaves the α = 0.001 band [{low:.1}, {high:.1}]"
    );
}

pub fn pearson(xs: &[f64], ys: &[f64]) -> f64 {
    let n = xs.len() as f64;
    let mean_x = xs.iter().sum::<f64>() / n;
    let mean_y = ys.iter().sum::<f64>() / n;
    let mut covariance = 0.0;
    let mut variance_x = 0.0;
    let mut variance_y = 0.0;
    for (x, y) in xs.iter().zip(ys) {
        let dx = x - mean_x;
        let dy = y - mean_y;
        covariance += dx * dy;
        variance_x += dx * dx;
        variance_y += dy * dy;
    }
    if variance_x == 0.0 || variance_y == 0.0 {
        return 0.0;
    }
    covariance / (variance_x.sqrt() * variance_y.sqrt())
}
