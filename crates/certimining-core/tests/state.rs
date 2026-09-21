//! E-04: the transition conditions of §1.3, the flags of INV-STATE-06 and INV-STATE-06a, and the
//! positive and negative vectors of §4.2 and §4.3 that belong to this unit.
//!
//! Most cases need no cryptography, so they run in every feature set against stand-in types: a
//! hasher that mixes its input deterministically and a verifier that accepts or refuses on demand.
//! The cases that turn on a real signature live in the `with_real_crypto` module, which uses the
//! engine's own hasher and verifier and signs with RFC 8032's keys.

use certimining_core::{
    payload_uri_is_well_formed, AssetChain, ChainSnapshot, ChainState, Digest, Hasher,
    LeafPreimage, PayloadUri, Preimage, PreimageBuf, RecordLeafInput, RegistryError, Verifier,
    FLAG_CATEGORY_DOWNGRADE, FLAG_RESERVE_WITHOUT_PRIOR_RESOURCE,
};

const C: Digest = [0x11; 32];
const PAYLOAD: Digest = [0x22; 32];
const QP: [u8; 32] = [0x44; 32];

/// A stand-in hasher: not cryptographic, but distinct inputs give distinct digests, which is all
/// the structural tests need. It keeps these cases running under every feature set.
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

/// Accepts every signature, so the tests that are not about signatures can use any bytes.
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

/// Refuses every signature, which is what a wrong one looks like to the engine.
struct NeverValid;

impl Verifier for NeverValid {
    fn verify(
        _key: &[u8; 32],
        _message: &[u8],
        _signature: &[u8; 64],
    ) -> Result<(), RegistryError> {
        Err(RegistryError::AttestationInvalid)
    }
}

type Chain = AssetChain<MixHash, AlwaysValid>;

fn uri(text: &str) -> PayloadUri {
    PayloadUri::from_slice(text.as_bytes()).expect("the URI fits")
}

/// A record that satisfies every condition, for a chain at `prev_head` and `seq`.
fn record(prev_head: Digest, seq: u64, category: u8, effective_at: i64) -> RecordLeafInput {
    RecordLeafInput {
        prev_head,
        seq,
        payload_digest: PAYLOAD,
        assessment_digest: [0x33; 32],
        qp_key: QP,
        expected_qp_key: None,
        signature: Some([0x55; 64]),
        category,
        effective_at,
        change_identified_at: effective_at - 100,
        payload_uri: uri("ipfs://bafyexamplepayload"),
        ext_commitment: None,
    }
}

fn start() -> Chain {
    Chain::start(&C, 1).expect("schema 1 starts")
}

/// V-P-02: genesis is fixed by `c` and the schema version, and by nothing else.
#[test]
fn v_p_02_genesis_is_deterministic() {
    let first = Chain::genesis(&C, 1).expect("schema 1");
    let again = Chain::genesis(&C, 1).expect("schema 1");
    assert_eq!(first, again);
    assert_ne!(first, Chain::genesis(&[0x12; 32], 1).expect("schema 1"));
    assert_eq!(start().head(), first);
    assert_eq!(start().seq(), 0);
}

/// V-N-13: any schema but 1 is `0x0F`, at genesis and on resume.
#[test]
fn v_n_13_another_schema_version_is_0x0f() {
    for version in [0, 2, 65_535] {
        assert_eq!(
            Chain::genesis(&C, version),
            Err(RegistryError::UnsupportedSchemaVersion),
            "{version}"
        );
        assert!(Chain::start(&C, version).is_err(), "{version}");
    }
}

/// V-P-03: a chain of five records, categories 0 to 4, advances deterministically.
#[test]
fn v_p_03_a_five_record_chain_is_deterministic() {
    let run = || {
        let mut chain = start();
        let mut heads = Vec::new();
        for (n, category) in (0..5u8).enumerate() {
            let seq = n as u64 + 1;
            let applied = chain
                .apply(&record(
                    chain.head(),
                    seq,
                    category,
                    1_700_000_000 + seq as i64,
                ))
                .expect("accepted");
            heads.push((applied.leaf, applied.head, applied.flags));
        }
        (heads, chain.head(), chain.seq())
    };
    let (first, head, seq) = run();
    let (again, head_again, _) = run();
    assert_eq!(first, again, "the same records give the same chain");
    assert_eq!(head, head_again);
    assert_eq!(seq, 5);
    // Every head and every leaf along the way is distinct.
    let mut seen: Vec<Digest> = Vec::new();
    for (leaf, h, _) in &first {
        assert!(!seen.contains(leaf));
        assert!(!seen.contains(h));
        seen.push(*leaf);
        seen.push(*h);
    }
}

/// V-P-04: recomputing from `h₂` forward gives the same `h₅` (INV-STATE-02).
#[test]
fn v_p_04_recomputing_from_a_later_head_gives_the_same_chain() {
    let mut chain = start();
    let mut snapshot_at_two = None;
    for seq in 1..=5u64 {
        let category = (seq - 1) as u8;
        let _ = chain
            .apply(&record(
                chain.head(),
                seq,
                category,
                1_700_000_000 + seq as i64,
            ))
            .expect("accepted");
        if seq == 2 {
            snapshot_at_two = Some(chain.snapshot());
        }
    }
    let full_head = chain.head();

    let mut resumed =
        Chain::resume(&C, 1, snapshot_at_two.expect("a snapshot at seq 2")).expect("resumes");
    for seq in 3..=5u64 {
        let category = (seq - 1) as u8;
        let _ = resumed
            .apply(&record(
                resumed.head(),
                seq,
                category,
                1_700_000_000 + seq as i64,
            ))
            .expect("accepted");
    }
    assert_eq!(resumed.head(), full_head);
    assert_eq!(resumed.seq(), 5);
}

/// V-P-09: zeros for the memo's digest and date are a record of absence, not a rejection
/// (INV-STATE-05).
#[test]
fn v_p_09_absent_memo_values_are_accepted() {
    let mut chain = start();
    let mut r = record(chain.head(), 1, 2, 1_700_000_000);
    r.assessment_digest = [0; 32];
    r.change_identified_at = 0;
    assert!(chain.apply(&r).is_ok());
    assert_eq!(chain.seq(), 1);
}

/// V-P-11 and V-N-07: a reserve category with no earlier resource record is accepted and flagged,
/// never rejected, and the flag does not change the leaf digest (INV-STATE-06, INV-STATE-06a).
#[test]
fn v_p_11_a_reserve_without_a_prior_resource_is_flagged_not_rejected() {
    let mut flagged = start();
    let applied = flagged
        .apply(&record(flagged.head(), 1, 4, 1_700_000_000))
        .expect("accepted");
    assert_eq!(applied.flags, FLAG_RESERVE_WITHOUT_PRIOR_RESOURCE);

    // The same record on a chain that already holds a Measured resource is not flagged, and its
    // leaf digest is identical, because flags are outside the preimage.
    let mut unflagged = start();
    let _ = unflagged
        .apply(&record(unflagged.head(), 1, 2, 1_699_999_000))
        .expect("accepted");
    let second = unflagged
        .apply(&record(unflagged.head(), 2, 4, 1_700_000_000))
        .expect("accepted");
    assert_eq!(second.flags, 0);
}

/// The acceptance criterion of issue #4: identical fields give an identical leaf digest whether the
/// record is flagged or not, because flags never enter the preimage (INV-STATE-06a).
#[test]
fn a_flag_never_changes_the_leaf_digest() {
    // Two chains standing at the same head and sequence. They differ only in history: one has
    // already seen a Measured resource, the other has not.
    let head = [0x5A; 32];
    let base = ChainSnapshot {
        head,
        seq: 1,
        last_effective_at: 1_699_000_000,
        saw_resource: false,
        previous_category: None,
    };
    let mut without_resource = Chain::resume(&C, 1, base).expect("resumes");
    let mut with_resource = Chain::resume(
        &C,
        1,
        ChainSnapshot {
            saw_resource: true,
            ..base
        },
    )
    .expect("resumes");

    let r = record(head, 2, 4, 1_700_000_000);
    let flagged = without_resource.apply(&r).expect("accepted");
    let unflagged = with_resource.apply(&r).expect("accepted");

    assert_eq!(flagged.flags, FLAG_RESERVE_WITHOUT_PRIOR_RESOURCE);
    assert_eq!(unflagged.flags, 0);
    assert_eq!(
        flagged.leaf, unflagged.leaf,
        "the flag changed the leaf digest, so it reached the preimage"
    );
    assert_eq!(flagged.head, unflagged.head);
}

/// D-42: the downgrade flag follows the previous record's category, and never fires first.
#[test]
fn d42_a_lower_category_than_the_previous_record_is_flagged() {
    let mut chain = start();
    let first = chain
        .apply(&record(chain.head(), 1, 3, 1_700_000_000))
        .expect("accepted");
    assert_eq!(
        first.flags, FLAG_RESERVE_WITHOUT_PRIOR_RESOURCE,
        "no downgrade on the first record"
    );

    let second = chain
        .apply(&record(chain.head(), 2, 2, 1_700_000_100))
        .expect("accepted");
    assert_eq!(
        second.flags, FLAG_CATEGORY_DOWNGRADE,
        "Probable back to Measured"
    );

    let third = chain
        .apply(&record(chain.head(), 3, 3, 1_700_000_200))
        .expect("accepted");
    assert_eq!(
        third.flags, 0,
        "Measured to Probable is a conversion, not a downgrade"
    );
}

/// The flag bits are the two schema 1 defines, and nothing else is ever set.
#[test]
fn only_the_two_schema_1_flag_bits_are_used() {
    let mut chain = start();
    for seq in 1..=5u64 {
        let category = 4 - ((seq - 1) as u8 % 5);
        let applied = chain
            .apply(&record(
                chain.head(),
                seq,
                category,
                1_700_000_000 + seq as i64,
            ))
            .expect("accepted");
        assert_eq!(applied.flags & !(0b11), 0, "reserved bits stay zero");
    }
}

/// V-N-01: a record that does not commit against the current head is `0x03`.
#[test]
fn v_n_01_a_wrong_prev_head_is_0x03() {
    let mut chain = start();
    assert_eq!(
        chain.apply(&record([0xAB; 32], 1, 0, 1_700_000_000)),
        Err(RegistryError::HeadMismatch)
    );
    assert_eq!(chain.seq(), 0, "a refused record changes nothing");
}

/// V-N-02: a gap and a replay both give `0x04`.
#[test]
fn v_n_02_a_sequence_gap_or_replay_is_0x04() {
    let mut chain = start();
    assert_eq!(
        chain.apply(&record(chain.head(), 2, 0, 1_700_000_000)),
        Err(RegistryError::SequenceOutOfOrder),
        "a gap"
    );
    let _ = chain
        .apply(&record(chain.head(), 1, 0, 1_700_000_000))
        .expect("accepted");
    let head_after = chain.head();
    assert_eq!(
        chain.apply(&record(head_after, 1, 0, 1_700_000_100)),
        Err(RegistryError::SequenceOutOfOrder),
        "a replay"
    );
    assert_eq!(chain.seq(), 1);
}

/// V-N-03: a URI that is too long, not ASCII, or of an unknown scheme is `0x05` (D-43).
#[test]
fn v_n_03_a_malformed_payload_uri_is_0x05() {
    let mut chain = start();
    let long = format!("ipfs://{}", "a".repeat(122));
    assert_eq!(long.len(), 129);
    for bad in [
        long.as_str(),
        "ipfs://payload\u{00e9}",
        "ftp://example.com/payload",
        "ipfs://",
        "",
        "ipfs://payload with spaces",
    ] {
        let mut r = record(chain.head(), 1, 0, 1_700_000_000);
        r.payload_uri = PayloadUri::from_slice(bad.as_bytes()).unwrap_or_default();
        assert_eq!(
            chain.apply(&r),
            Err(RegistryError::MalformedPayload),
            "{bad:?}"
        );
    }
    // The three schemes §1.8 names are accepted.
    for good in ["ipfs://bafyexample", "https://example.com/a", "ar://abc123"] {
        assert!(payload_uri_is_well_formed(good.as_bytes()), "{good}");
    }
}

/// V-N-07b: a category outside 0 to 4 is `0x05`, and `0x09` is never the answer.
#[test]
fn v_n_07b_a_category_outside_the_range_is_0x05() {
    let mut chain = start();
    for category in [5u8, 6, 200, 255] {
        assert_eq!(
            chain.apply(&record(chain.head(), 1, category, 1_700_000_000)),
            Err(RegistryError::MalformedPayload),
            "category {category}"
        );
    }
}

/// V-N-08: an effective date earlier than its predecessor's is `0x0A` (INV-STATE-04).
#[test]
fn v_n_08_a_non_monotonic_effective_date_is_0x0a() {
    let mut chain = start();
    let _ = chain
        .apply(&record(chain.head(), 1, 0, 1_700_000_000))
        .expect("accepted");
    assert_eq!(
        chain.apply(&record(chain.head(), 2, 0, 1_699_999_999)),
        Err(RegistryError::NonMonotonicEffectiveAt)
    );
    // The same date is allowed: the rule is non-decreasing.
    assert!(chain
        .apply(&record(chain.head(), 2, 0, 1_700_000_000))
        .is_ok());
}

/// V-N-20: a chain with nowhere left to count is `0x10`, not a wrap (INV-STATE-07).
#[test]
fn v_n_20_a_sequence_at_the_limit_is_0x10() {
    let mut chain = Chain::resume(
        &C,
        1,
        ChainSnapshot {
            head: [0x77; 32],
            seq: u64::MAX,
            last_effective_at: 0,
            saw_resource: true,
            previous_category: Some(2),
        },
    )
    .expect("resumes");
    assert_eq!(
        chain.apply(&record([0x77; 32], u64::MAX, 2, 1_700_000_000)),
        Err(RegistryError::ArithmeticOverflow)
    );
    assert_eq!(chain.seq(), u64::MAX, "the chain did not move");
}

/// The acceptance criterion of issue #4: `0x09` is never returned, whatever the category order.
#[test]
fn code_0x09_is_never_returned() {
    let mut refused = Vec::new();
    for categories in [
        [4u8, 3, 2, 1, 0],
        [0, 4, 0, 4, 0],
        [3, 3, 3, 3, 3],
        [2, 4, 1, 3, 0],
    ] {
        let mut chain = start();
        for (n, category) in categories.iter().enumerate() {
            let seq = n as u64 + 1;
            if let Err(e) = chain.apply(&record(
                chain.head(),
                seq,
                *category,
                1_700_000_000 + seq as i64,
            )) {
                refused.push(e);
            }
        }
    }
    assert!(
        !refused.contains(&RegistryError::CategorySequenceUnsupported),
        "0x09 must never be returned under schema 1 (INV-STATE-06)"
    );
    assert_eq!(RegistryError::CategorySequenceUnsupported.code(), 0x09);
}

/// D-40: the §2.6 hook carries nothing under schema 1, and a record that sets it is refused rather
/// than silently accepted with the field dropped.
#[test]
fn a_record_carrying_the_extension_hook_is_refused() {
    let mut chain = start();
    let mut r = record(chain.head(), 1, 0, 1_700_000_000);
    r.ext_commitment = Some([0x99; 32]);
    assert_eq!(
        chain.apply(&r),
        Err(RegistryError::UnsupportedSchemaVersion)
    );
}

/// A refused record leaves the chain exactly as it was, whatever refused it (INV-STATE-01).
#[test]
fn a_refused_record_never_moves_the_chain() {
    let mut chain = start();
    let _ = chain
        .apply(&record(chain.head(), 1, 2, 1_700_000_000))
        .expect("accepted");
    let before = chain.snapshot();

    let mut wrong_head = record([0x01; 32], 2, 2, 1_700_000_100);
    wrong_head.seq = 2;
    let refusals: Vec<RecordLeafInput> = vec![
        wrong_head,
        record(chain.head(), 9, 2, 1_700_000_100),
        record(chain.head(), 2, 200, 1_700_000_100),
        record(chain.head(), 2, 2, 1_600_000_000),
    ];
    for r in refusals {
        assert!(chain.apply(&r).is_err());
        assert_eq!(chain.snapshot(), before, "the chain moved on a refusal");
    }
}

/// `leaf` computes what `apply` would commit, without committing it.
#[test]
fn leaf_matches_what_apply_commits() {
    let mut chain = start();
    let r = record(chain.head(), 1, 1, 1_700_000_000);
    let expected = chain.leaf(&r).expect("a leaf");
    let before = chain.snapshot();
    assert_eq!(chain.snapshot(), before, "leaf changed nothing");
    assert_eq!(chain.apply(&r).expect("accepted").leaf, expected);
}

/// A verifier that refuses turns into `0x07` at the record level (V-N-05's shape).
#[test]
fn a_refused_signature_is_0x07() {
    let mut chain = AssetChain::<MixHash, NeverValid>::start(&C, 1).expect("starts");
    assert_eq!(
        chain.apply(&record(chain.head(), 1, 0, 1_700_000_000)),
        Err(RegistryError::AttestationInvalid)
    );
}

/// V-N-04: no signature at all is `0x06`, which is a different code from an invalid one (D-41).
#[test]
fn v_n_04_a_missing_signature_is_0x06() {
    let mut chain = start();
    let mut r = record(chain.head(), 1, 0, 1_700_000_000);
    r.signature = None;
    assert_eq!(chain.apply(&r), Err(RegistryError::AttestationMissing));
}

/// V-N-06: a record whose key is not the one the caller expected is `0x08`, decided before any
/// verification runs (D-41).
#[test]
fn v_n_06_an_unexpected_qp_key_is_0x08() {
    let mut chain = AssetChain::<MixHash, NeverValid>::start(&C, 1).expect("starts");
    let mut r = record(chain.head(), 1, 0, 1_700_000_000);
    r.expected_qp_key = Some([0x66; 32]);
    assert_eq!(
        chain.apply(&r),
        Err(RegistryError::AttestationKeyMismatch),
        "the key is judged before the signature, so a refusing verifier is not reached"
    );

    // The same record with the expected key matching reaches verification.
    let mut r = record(chain.head(), 1, 0, 1_700_000_000);
    r.expected_qp_key = Some(QP);
    assert_eq!(chain.apply(&r), Err(RegistryError::AttestationInvalid));
}

#[cfg(feature = "native")]
mod with_real_crypto {
    use super::*;
    use certimining_core::{DalekVerifier, NativeKeccak};
    use ed25519_dalek::{Signer, SigningKey};

    type RealChain = AssetChain<NativeKeccak, DalekVerifier>;

    /// RFC 8032 §7.1's first secret key, so the tests sign with a published key rather than a
    /// generated one.
    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
            0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03,
            0x1c, 0xae, 0x7f, 0x60,
        ])
    }

    /// The bytes the QP signs: the leaf preimage, not the digest (D-37).
    fn leaf_preimage(chain: &RealChain, r: &RecordLeafInput) -> Vec<u8> {
        let preimage = LeafPreimage {
            asset_commitment: chain.asset_commitment(),
            seq: r.seq,
            payload_digest: r.payload_digest,
            assessment_digest: r.assessment_digest,
            qp_key: r.qp_key,
            category: r.category,
            effective_at: r.effective_at,
            change_identified_at: r.change_identified_at,
        };
        let mut buf = PreimageBuf::new();
        preimage.write_preimage(&mut buf).expect("fits");
        buf.as_bytes().to_vec()
    }

    fn signed(chain: &RealChain, mut r: RecordLeafInput) -> RecordLeafInput {
        let key = signing_key();
        r.qp_key = key.verifying_key().to_bytes();
        let bytes = leaf_preimage(chain, &r);
        r.signature = Some(key.sign(&bytes).to_bytes());
        r
    }

    /// A record signed over its own preimage is accepted, end to end, with the engine's own
    /// hasher and verifier.
    #[test]
    fn a_properly_signed_record_is_accepted() {
        let mut chain = RealChain::start(&C, 1).expect("starts");
        let r = signed(&chain, record(chain.head(), 1, 2, 1_700_000_000));
        let applied = chain.apply(&r).expect("accepted");
        assert_eq!(chain.head(), applied.head);
        assert_eq!(chain.seq(), 1);
        assert_eq!(applied.flags, 0);
    }

    /// V-N-05: a signature over anything other than the preimage is `0x07`, and JSON is the case
    /// the spec names.
    #[test]
    fn v_n_05_a_signature_over_json_is_0x07() {
        let mut chain = RealChain::start(&C, 1).expect("starts");
        let mut r = record(chain.head(), 1, 2, 1_700_000_000);
        let key = signing_key();
        r.qp_key = key.verifying_key().to_bytes();
        let json = br#"{"seq":1,"category":2,"effective_at":1700000000}"#;
        r.signature = Some(key.sign(json).to_bytes());
        assert_eq!(chain.apply(&r), Err(RegistryError::AttestationInvalid));
    }

    /// V-N-05 again, from the other side: a signature over the leaf *digest* rather than the
    /// preimage is also `0x07`. This is the case D-37 settled.
    #[test]
    fn a_signature_over_the_digest_rather_than_the_preimage_is_0x07() {
        let mut chain = RealChain::start(&C, 1).expect("starts");
        let mut r = record(chain.head(), 1, 2, 1_700_000_000);
        let key = signing_key();
        r.qp_key = key.verifying_key().to_bytes();
        let digest = chain.leaf(&r).expect("a leaf");
        r.signature = Some(key.sign(&digest).to_bytes());
        assert_eq!(chain.apply(&r), Err(RegistryError::AttestationInvalid));
    }

    /// V-N-06: signed by a key that is not the record's `qp_key`.
    #[test]
    fn v_n_06_a_signature_by_another_key_is_refused() {
        let mut chain = RealChain::start(&C, 1).expect("starts");
        let mut r = signed(&chain, record(chain.head(), 1, 2, 1_700_000_000));
        // Keep the signature, claim a different key: verification fails under the claimed key.
        r.qp_key = [0x21; 32];
        assert_eq!(chain.apply(&r), Err(RegistryError::AttestationInvalid));

        // With an expected key recorded, the mismatch is caught first and named (D-41).
        let mut r = signed(&chain, record(chain.head(), 1, 2, 1_700_000_000));
        r.expected_qp_key = Some([0x21; 32]);
        assert_eq!(chain.apply(&r), Err(RegistryError::AttestationKeyMismatch));
    }

    /// One byte changed anywhere in the record breaks the signature: the leaf covers every field.
    #[test]
    fn one_changed_field_breaks_the_signature() {
        let mut chain = RealChain::start(&C, 1).expect("starts");
        let base = signed(&chain, record(chain.head(), 1, 2, 1_700_000_000));
        for tamper in 0..4 {
            let mut r = base.clone();
            match tamper {
                0 => r.category = 3,
                1 => r.effective_at += 1,
                2 => r.payload_digest = [0x23; 32],
                _ => r.change_identified_at += 1,
            }
            assert_eq!(
                chain.apply(&r),
                Err(RegistryError::AttestationInvalid),
                "tamper {tamper}"
            );
        }
        // The untouched record still applies.
        assert!(chain.apply(&base).is_ok());
    }

    /// The head advances as §1.3 says: `hₙ₊₁ = Keccak256( TAG_HEAD ‖ hₙ ‖ leafₙ₊₁ )`, written out
    /// here from the spec rather than taken from the crate.
    #[test]
    fn the_head_advances_as_the_spec_says() {
        let mut chain = RealChain::start(&C, 1).expect("starts");
        let previous = chain.head();
        let r = signed(&chain, record(previous, 1, 2, 1_700_000_000));
        let applied = chain.apply(&r).expect("accepted");

        let mut expected = Vec::new();
        expected.extend_from_slice(b"CMv1HEAD");
        expected.extend_from_slice(&previous);
        expected.extend_from_slice(&applied.leaf);
        assert_eq!(applied.head, NativeKeccak::hashv(&[&expected]));
        assert_eq!(expected.len(), 72);
    }

    /// Genesis is what §1.3 says: `h₀ = Keccak256( TAG_HEAD ‖ c ‖ schema_version )`.
    #[test]
    fn genesis_is_what_the_spec_says() {
        let mut expected = Vec::new();
        expected.extend_from_slice(b"CMv1HEAD");
        expected.extend_from_slice(&C);
        expected.extend_from_slice(&1u16.to_le_bytes());
        assert_eq!(expected.len(), 42);
        assert_eq!(
            RealChain::genesis(&C, 1),
            Ok(NativeKeccak::hashv(&[&expected]))
        );
    }
}
