//! F-05: arbitrary real-leaf sets and arbitrary height bytes.
//!
//! §4.5: a valid height always produces a complete tree of that height, an invalid one returns `0x05`,
//! and nothing panics. §1.8 bounds the height at 4 to 16, so the arbitrary byte spends most of its range
//! outside the valid set, which is the half that matters — a build that accepted height 200 would try to
//! allocate 2^200 leaves.
//!
//! **Two defects a review found in the first version of this target (PR #55, E12-01 and E12-03), both of
//! which made it quieter than it looked.**
//!
//! The refusal branch accepted `MalformedPayload` for *any* input and only required it when the height
//! was invalid. A fresh engine defect that refused a valid, unique, one-leaf tree at `H = 8` therefore
//! completed 25,000 iterations green while the ordinary positive test failed at once. §4.5's obligation
//! is positive — a valid height *always* produces a tree — and a target that only checks which code a
//! refusal carries never tests it. The match below now decides what the engine owes for every input and
//! requires exactly that, including `Ok`.
//!
//! And the leaf set could not reach the domain §4.5 names. `0..=C` is 0 to 65,536 at `H = 16`, each
//! element is 48 bytes before container overhead, and libFuzzer's default `-max_len` is 4,096 — so about
//! 85 elements were representable and the old 300-element source cap was never the binding constraint.
//! Its comment claimed to sit "a little above the largest capacity this bound allows", which was true
//! only of `H = 8`. The set is now assembled from a small arbitrary part and a **derived** count, so any
//! count up to capacity costs two input bytes while the leaves themselves stay fuzzed.

#![no_main]

use arbitrary::Arbitrary;
use certimining_core::{Digest, NativeKeccak, RegistryError, SubmissionId};
use certimining_log::{BuiltEpoch, EpochTree};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct Input {
    epoch: u64,
    height: u8,
    key: [u8; 32],
    /// Leaves whose bytes the fuzzer chooses, so content is searched rather than generated. Kept small
    /// because each costs 48 input bytes; the count comes from `derived`.
    explicit: Vec<([u8; 16], [u8; 32])>,
    /// Further leaves to derive, so a set at or near capacity is reachable in two bytes rather than in
    /// tens of kilobytes of input.
    derived: u16,
    seed: u64,
}

/// The set the engine is asked to build: the fuzzer's own leaves, then derived ones.
///
/// Derived identifiers carry their index, so they are unique among themselves. They may still collide
/// with an explicit identifier, which is why the caller computes whether the assembled set has
/// duplicates rather than assuming it does not.
///
/// **The count is clamped to `MAX_DERIVED`, and that bound is a real limit on this target.** Left at the
/// full `u16`, a unit could ask for 65,536 leaves at `H = 16`, and that build under a sanitizer exceeded
/// the 10-second per-unit timeout — libFuzzer aborted the run, which fails the group. So the fuzzer
/// reaches capacity for heights 4 through 12 and cannot for 13 through 16. Those four heights' boundary
/// counts are covered deterministically instead, by
/// `the_leaf_count_boundaries_hold_at_every_height_class` in `crates/certimining-log/tests/tree.rs`,
/// which does 0, 1, C-1, C and C+1 at every height class in under two seconds. Content search is what
/// this target is for; the boundaries are pinned where they do not depend on a mutation finding them.
const MAX_DERIVED: u16 = 4_096;

fn assemble(input: &Input) -> Vec<(SubmissionId, Digest)> {
    let mut real: Vec<(SubmissionId, Digest)> = input
        .explicit
        .iter()
        .take(64)
        .map(|(id, leaf)| (*id, *leaf))
        .collect();
    for i in 0..input.derived.min(MAX_DERIVED) {
        let mut id = [0u8; 16];
        id[..8].copy_from_slice(&input.seed.to_le_bytes());
        id[8..10].copy_from_slice(&i.to_le_bytes());
        let mut leaf = [0u8; 32];
        leaf[..8].copy_from_slice(&(input.seed ^ u64::from(i)).to_le_bytes());
        leaf[8] = 0x11;
        real.push((id, leaf));
    }
    real
}

fn has_duplicate_ids(real: &[(SubmissionId, Digest)]) -> bool {
    let mut ids: Vec<&SubmissionId> = real.iter().map(|(id, _)| id).collect();
    ids.sort_unstable();
    ids.windows(2).any(|w| w[0] == w[1])
}

fuzz_target!(|input: Input| {
    let real = assemble(&input);
    let height_is_valid = (4..=16).contains(&input.height);
    // `capacity_of` is the engine's; this is the same arithmetic stated independently, so a disagreement
    // about capacity is itself a finding rather than something both sides share.
    let capacity = if height_is_valid {
        Some(1usize << input.height)
    } else {
        None
    };
    let over_capacity = capacity.is_some_and(|c| real.len() > c);
    let duplicates = has_duplicate_ids(&real);

    let outcome =
        <BuiltEpoch as EpochTree>::build::<NativeKeccak>(input.epoch, input.height, &input.key, &real);

    match outcome {
        Ok(built) => {
            assert!(
                height_is_valid,
                "built a tree at height {}, which §1.8 does not allow",
                input.height
            );
            assert!(
                !over_capacity,
                "built a tree from {} leaves at height {}, where capacity is {:?}",
                real.len(),
                input.height,
                capacity
            );
            assert!(
                !duplicates,
                "built a tree from a set with duplicate identifiers, which §1.4 makes malformed"
            );
            assert_eq!(
                built.height(),
                input.height,
                "the tree's height is not the one asked for"
            );
            assert_eq!(
                built.capacity(),
                1usize << input.height,
                "a complete tree at height {} has {} leaves",
                input.height,
                1usize << input.height
            );

            // INV-TREE-01: proof length is constant at `H` siblings, whatever the record count.
            for (id, _) in &real {
                if let Ok(proof) = built.proof(id) {
                    assert_eq!(
                        proof.siblings.len(),
                        input.height as usize,
                        "a proof carried {} siblings at height {}",
                        proof.siblings.len(),
                        input.height
                    );
                }
            }
        }
        Err(e) => {
            // **The positive obligation, which is what E12-01 was missing.** For every input the engine
            // owes one specific answer, and a refusal is only permitted where one of these holds.
            assert!(
                matches!(
                    e,
                    RegistryError::MalformedPayload | RegistryError::EpochCapacityExceeded
                ),
                "build refused with {e:?}, which is not a code §1.4 or §1.8 gives it"
            );
            if !height_is_valid {
                assert_eq!(
                    e,
                    RegistryError::MalformedPayload,
                    "height {} is outside §1.8's range and must be 0x05",
                    input.height
                );
            } else if over_capacity {
                assert_eq!(
                    e,
                    RegistryError::EpochCapacityExceeded,
                    "{} leaves at height {} exceeds capacity and must be 0x12",
                    real.len(),
                    input.height
                );
            } else {
                // A valid height, a set that fits, and no duplicate identifiers. §4.5 says a valid
                // height always produces a complete tree, so there is nothing left for the engine to
                // refuse, and `duplicates` is the only refusal this case may carry.
                assert!(
                    duplicates,
                    "build refused {} unique leaves at valid height {} with {e:?}, and §4.5 says a valid \
                     height always produces a complete tree of that height",
                    real.len(),
                    input.height
                );
                assert_eq!(
                    e,
                    RegistryError::MalformedPayload,
                    "duplicate identifiers are 0x05, not {e:?}"
                );
            }
        }
    }
});
