// SPDX-License-Identifier: MIT OR Apache-2.0
//! E-04's property tests: `apply` is total on any record, a refused record never moves the chain,
//! and the flags only ever carry the two bits schema 1 defines.
//!
//! E-12 adds §4.5's **P-01** and **P-02**. P-01 is the chain's whole point stated as a property —
//! removing or reordering any leaf changes the head — and P-02 is determinism, which every other
//! property here quietly assumes.

use certimining_core::{
    AssetChain, ChainSnapshot, ChainState, Digest, Hasher, PayloadUri, RecordLeafInput,
    RegistryError, Verifier,
};
use proptest::prelude::*;

/// The stand-in hasher of `state.rs`: deterministic, distinct outputs, no cryptography, so these
/// properties run in every feature set and stay quick under Miri.
struct MixHash;

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

struct AlwaysValid;

impl Verifier for AlwaysValid {
    fn verify(
        _key: &[u8; 32],
        _message: &[u8],
        _signature: &[u8; 64],
    ) -> Result<(), RegistryError> {
        Ok(())
    }
}

type Chain = AssetChain<MixHash, AlwaysValid>;

fn config() -> ProptestConfig {
    ProptestConfig {
        cases: if cfg!(miri) { 8 } else { 512 },
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

prop_compose! {
    /// Any record at all, valid or not: arbitrary head, sequence, category, dates and URI bytes.
    fn any_record()(
        prev_head in any::<[u8; 32]>(),
        seq in any::<u64>(),
        payload_digest in any::<[u8; 32]>(),
        assessment_digest in any::<[u8; 32]>(),
        qp_key in any::<[u8; 32]>(),
        expected in proptest::option::of(any::<[u8; 32]>()),
        signature in proptest::option::of(any::<[u8; 64]>()),
        category in any::<u8>(),
        effective_at in any::<i64>(),
        change_identified_at in any::<i64>(),
        // At most what the type holds: a longer value would be silently replaced by an
        // empty one, and the 129-byte boundary is checked directly in state.rs instead.
        uri in prop::collection::vec(any::<u8>(), 0..=128),
        ext in proptest::option::of(any::<[u8; 32]>()),
    ) -> RecordLeafInput {
        RecordLeafInput {
            prev_head,
            seq,
            payload_digest,
            assessment_digest,
            qp_key,
            expected_qp_key: expected,
            signature,
            category,
            effective_at,
            change_identified_at,
            payload_uri: PayloadUri::from_slice(&uri).expect("128 bytes or fewer always fit"),
            ext_commitment: ext,
        }
    }
}

/// A chain of `count` records that each commit to the head before them, so the whole thing applies.
///
/// P-01 is about accepted leaves: a chain of refusals has no head to compare. The records differ by
/// `seed` so the property is not tested against one fixed shape.
fn valid_chain(count: usize, seed: u64) -> Vec<RecordLeafInput> {
    let mut chain = Chain::start(&[0x11; 32], 1).expect("starts");
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let mut record = RecordLeafInput {
            prev_head: chain.head(),
            seq: (i as u64) + 1,
            payload_digest: [(seed as u8).wrapping_add(i as u8); 32],
            assessment_digest: [0x33; 32],
            qp_key: [0x44; 32],
            expected_qp_key: None,
            signature: Some([0x55; 64]),
            category: ((seed.wrapping_add(i as u64)) % 5) as u8,
            effective_at: 1_700_000_000 + (i as i64) * 86_400,
            change_identified_at: 1_700_000_000,
            payload_uri: PayloadUri::from_slice(b"ipfs://bafyprop").expect("fits"),
            ext_commitment: None,
        };
        // Effective dates are non-decreasing (INV-STATE-04), so a swap must not be refused for that
        // reason rather than for the one P-01 is about. Flat dates keep the comparison honest.
        record.effective_at = 1_700_000_000;
        let _ = chain
            .apply(&record)
            .expect("a record built against the current head applies");
        out.push(record);
    }
    out
}

/// Re-point each record at the head before it, so a shortened or reordered chain still applies and
/// the only thing that changed is which leaves are in it and in what order.
fn relink(records: &[RecordLeafInput]) -> Vec<RecordLeafInput> {
    let mut chain = Chain::start(&[0x11; 32], 1).expect("starts");
    let mut out = Vec::with_capacity(records.len());
    for (i, r) in records.iter().enumerate() {
        let mut record = r.clone();
        record.prev_head = chain.head();
        record.seq = (i as u64) + 1;
        if chain.apply(&record).is_err() {
            return out;
        }
        out.push(record);
    }
    out
}

/// The head after applying all of `records` in order, or `None` if any is refused.
fn head_after(records: &[RecordLeafInput]) -> Option<Digest> {
    let mut chain = Chain::start(&[0x11; 32], 1).expect("starts");
    for r in records {
        let _ = chain.apply(r).ok()?;
    }
    Some(chain.head())
}

proptest! {
    #![proptest_config(config())]

    /// Total: any record gives an accepted transition or a documented code, and never a panic.
    #[test]
    fn apply_is_total(r in any_record()) {
        let mut chain = Chain::start(&[0x11; 32], 1).expect("starts");
        match chain.apply(&r) {
            Ok(applied) => {
                prop_assert_eq!(chain.seq(), 1);
                prop_assert_eq!(chain.head(), applied.head);
                prop_assert_eq!(applied.flags & !0b11, 0);
            }
            Err(e) => {
                prop_assert!(matches!(
                    e,
                    RegistryError::HeadMismatch
                        | RegistryError::SequenceOutOfOrder
                        | RegistryError::MalformedPayload
                        | RegistryError::AttestationMissing
                        | RegistryError::AttestationKeyMismatch
                        | RegistryError::NonMonotonicEffectiveAt
                        | RegistryError::UnsupportedSchemaVersion
                ), "unexpected code: {:?}", e);
                prop_assert_eq!(chain.seq(), 0, "a refused record moved the chain");
            }
        }
    }

    /// A refused record leaves every part of the chain's state untouched (INV-STATE-01).
    #[test]
    fn a_refusal_never_changes_the_chain(first in any_record(), second in any_record()) {
        let mut chain = Chain::start(&[0x11; 32], 1).expect("starts");
        let _ = chain.apply(&first);
        let before = chain.snapshot();
        if chain.apply(&second).is_err() {
            prop_assert_eq!(chain.snapshot(), before);
        }
    }

    /// `0x09` is never the answer, whatever the record says (INV-STATE-06, D-01).
    #[test]
    fn code_0x09_is_unreachable(r in any_record()) {
        let mut chain = Chain::start(&[0x11; 32], 1).expect("starts");
        prop_assert_ne!(chain.apply(&r).err(), Some(RegistryError::CategorySequenceUnsupported));
    }

    /// **P-01.** Removing or reordering any leaf in a chain of n changes `hₙ`.
    ///
    /// This is INV-STATE-02 from the other side: the invariant says a later head is recomputable from
    /// an earlier one and the leaves between, and the property says no *other* sequence of leaves
    /// reaches the same head. A chain that failed this would let an issuer drop a record and present
    /// a head that still verified.
    ///
    /// The records are built valid by construction — each committing to the head before it — because
    /// a chain of refused records has no head to compare, and the property is about accepted ones.
    #[test]
    fn p01_removing_or_reordering_a_leaf_changes_the_head(
        count in 2usize..=6,
        seed in any::<u64>(),
    ) {
        let records = valid_chain(count, seed);
        let whole = head_after(&records).expect("a valid chain applies");

        // Remove each leaf in turn. Every shorter chain must reach a different head.
        for drop in 0..records.len() {
            let mut shorter: Vec<RecordLeafInput> = records.clone();
            shorter.remove(drop);
            let relinked = relink(&shorter);
            if let Some(head) = head_after(&relinked) {
                prop_assert_ne!(
                    head, whole,
                    "dropping leaf {} reached the same head as the whole chain", drop
                );
            }
        }

        // Swap each adjacent pair. Order is part of what the head commits to.
        for i in 0..records.len().saturating_sub(1) {
            let mut swapped: Vec<RecordLeafInput> = records.clone();
            swapped.swap(i, i + 1);
            let relinked = relink(&swapped);
            if let Some(head) = head_after(&relinked) {
                prop_assert_ne!(
                    head, whole,
                    "swapping leaves {} and {} reached the same head", i, i + 1
                );
            }
        }
    }

    /// **P-02.** `apply` is deterministic: the same record against the same starting state gives the
    /// same answer, every time.
    ///
    /// Every other property in this file assumes it. §4.5 asks for 10,000 generated cases, which is
    /// `PROPTEST_CASES=10000` against this test; the default run is `config()`'s 512, and the full
    /// count runs before submission the way V-Z-04's does.
    #[test]
    fn p02_apply_is_deterministic(
        r in any_record(),
        head in any::<[u8; 32]>(),
        seq in any::<u64>(),
        last_effective_at in any::<i64>(),
        saw_resource in any::<bool>(),
        previous_category in proptest::option::of(0u8..=4),
    ) {
        let snapshot = ChainSnapshot { head, seq, last_effective_at, saw_resource, previous_category };
        let mut first = Chain::resume(&[0x11; 32], 1, snapshot).expect("resumes");
        let mut second = Chain::resume(&[0x11; 32], 1, snapshot).expect("resumes");

        let a = first.apply(&r);
        let b = second.apply(&r);

        match (a, b) {
            (Ok(x), Ok(y)) => {
                prop_assert_eq!(x.head, y.head, "two applications gave different heads");
                prop_assert_eq!(x.leaf, y.leaf, "two applications gave different leaves");
                prop_assert_eq!(x.flags, y.flags, "two applications gave different flags");
            }
            (Err(x), Err(y)) => prop_assert_eq!(x, y, "two applications gave different codes"),
            (x, y) => prop_assert!(false, "one application succeeded and the other did not: {:?} and {:?}", x, y),
        }
        prop_assert_eq!(first.snapshot(), second.snapshot(), "the two chains ended in different states");
    }

    /// A chain resumed from a snapshot reports exactly that snapshot back.
    #[test]
    fn resume_round_trips_a_snapshot(
        head in any::<[u8; 32]>(),
        seq in any::<u64>(),
        last_effective_at in any::<i64>(),
        saw_resource in any::<bool>(),
        previous_category in proptest::option::of(0u8..=4),
    ) {
        let snapshot = ChainSnapshot { head, seq, last_effective_at, saw_resource, previous_category };
        let chain = Chain::resume(&[0x11; 32], 1, snapshot).expect("resumes");
        prop_assert_eq!(chain.snapshot(), snapshot);
        prop_assert_eq!(chain.head(), head);
        prop_assert_eq!(chain.seq(), seq);
    }
}
