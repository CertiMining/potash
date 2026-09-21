//! E-04's property tests: `apply` is total on any record, a refused record never moves the chain,
//! and the flags only ever carry the two bits schema 1 defines.

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
        uri in prop::collection::vec(any::<u8>(), 0..140),
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
            payload_uri: PayloadUri::from_slice(&uri).unwrap_or_default(),
            ext_commitment: ext,
        }
    }
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
