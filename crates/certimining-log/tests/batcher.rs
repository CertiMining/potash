//! E-07: the batcher, its promises, the overflow queue, and §4.2's V-P-10.
//!
//! Written before the implementation (D-65, S4): the batcher seals epoch trees, so the rule that
//! covers anything touching the tree covers this.
//!
//! The signer here is RFC 8032 §7.1's published key behind §2.2's `Signer`. Its private half is
//! public, so every signature is reproducible, and nothing resembling a real batcher key enters this
//! repository — the engine has no place to keep one.

mod common;

use certimining_core::{Digest, RegistryError, Result, Signer, SubmissionId};
use certimining_log::{
    Batcher, BatcherSnapshot, BuiltEpoch, EpochBatcher, EpochTree, MAX_MERGE_DELAY,
    PROMISE_ENCODED_LEN,
};
use common::{assignment_oracle, leaf_digest, MixHash, TEST_MASTER_KEY};

/// RFC 8032 §7.1's first secret key, transcribed from the specification.
const RFC8032_SECRET_KEY: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];

/// RFC 8032 §7.1's second secret key, for the case where a counterparty expects another batcher.
const RFC8032_SECOND_KEY: [u8; 32] = [
    0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e, 0x0f,
    0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8, 0xa6, 0xfb,
];

/// A published specification test key behind the trait the engine names (D-73).
struct SpecTestSigner(ed25519_dalek::SigningKey);

impl SpecTestSigner {
    fn from(secret: &[u8; 32]) -> Self {
        Self(ed25519_dalek::SigningKey::from_bytes(secret))
    }
}

impl Signer for SpecTestSigner {
    fn sign(&self, message: &[u8]) -> Result<[u8; 64]> {
        use ed25519_dalek::Signer as _;
        Ok(self.0.sign(message).to_bytes())
    }

    fn public_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }
}

const HEIGHT: u8 = 4;
const CAPACITY: usize = 1 << HEIGHT;

fn batcher(epoch: u64) -> EpochBatcher {
    EpochBatcher::start(&TEST_MASTER_KEY, HEIGHT, epoch).expect("starts")
}

#[test]
fn a_promise_names_the_current_epoch_while_the_epoch_has_room() {
    let signer = SpecTestSigner::from(&RFC8032_SECRET_KEY);
    let mut batcher = batcher(100);
    let promise = batcher
        .submit::<MixHash, _>(leaf_digest(1), &signer)
        .expect("accepted");
    assert_eq!(promise.promised_epoch, 100);
    assert_eq!(
        promise.accepted_epoch, 100,
        "D-74: the epoch it was accepted in, signed"
    );
    assert_eq!(promise.max_merge_delay, MAX_MERGE_DELAY);
    assert_eq!(promise.leaf, leaf_digest(1), "INV-SPI-02: the exact leaf");
    assert_eq!(promise.batcher_key, signer.public_key());
    assert_eq!(batcher.overflow_queue_len(), 0);
}

#[test]
fn identifiers_are_an_ordinal_counter_and_never_repeat() {
    let signer = SpecTestSigner::from(&RFC8032_SECRET_KEY);
    let mut batcher = batcher(100);
    let mut seen: Vec<SubmissionId> = Vec::new();
    for n in 0..5u64 {
        let promise = batcher
            .submit::<MixHash, _>(leaf_digest(n), &signer)
            .expect("accepted");
        let mut expected = [0u8; 16];
        expected[..8].copy_from_slice(&n.to_le_bytes());
        assert_eq!(promise.submission_id, expected, "D-69: an ordinal counter");
        seen.push(promise.submission_id);
    }
    let mut unique = seen.clone();
    unique.dedup();
    assert_eq!(seen.len(), unique.len());
}

#[test]
fn a_rolled_back_counter_is_refused_rather_than_reissuing_an_identifier() {
    // M-01: a snapshot comes from storage, so it is input and not state. This is the review's probe.
    let signer = SpecTestSigner::from(&RFC8032_SECRET_KEY);
    let mut honest = batcher(110);
    honest
        .submit::<MixHash, _>(leaf_digest(1), &signer)
        .expect("accepted");
    let taken = honest.snapshot();
    assert_eq!(taken.next_submission, 1);

    let mut rolled_back = taken.clone();
    rolled_back.next_submission = 0;
    assert_eq!(
        EpochBatcher::resume(&TEST_MASTER_KEY, HEIGHT, rolled_back).err(),
        Some(RegistryError::MalformedPayload),
        "a counter behind a queued identifier would reissue it"
    );

    let mut doubled = taken.clone();
    doubled.pending.push(taken.pending[0]);
    doubled.next_submission = 2;
    assert_eq!(
        EpochBatcher::resume(&TEST_MASTER_KEY, HEIGHT, doubled).err(),
        Some(RegistryError::MalformedPayload),
        "two submissions under one identifier would fail the seal with 0x05"
    );

    let overfull = BatcherSnapshot {
        epoch: 110,
        next_submission: 999,
        pending: (0..=CAPACITY as u64)
            .map(|n| {
                let mut id = [0u8; 16];
                id[..8].copy_from_slice(&n.to_le_bytes());
                (id, leaf_digest(n))
            })
            .collect(),
        overflow: Vec::new(),
    };
    assert_eq!(
        EpochBatcher::resume(&TEST_MASTER_KEY, HEIGHT, overfull).err(),
        Some(RegistryError::MalformedPayload),
        "an epoch fuller than C never came from a batcher"
    );

    assert!(
        EpochBatcher::resume(&TEST_MASTER_KEY, HEIGHT, taken).is_ok(),
        "and the honest snapshot still resumes"
    );
}

#[test]
fn a_snapshot_that_lost_a_live_submission_is_refused_rather_than_resumed() {
    // M-01, round two: three states a batcher cannot reach, each visible inside the value. The first
    // is the one that matters: the snapshot proves a minted submission was lost, and resuming would
    // seal an epoch without a leaf the batcher had already promised.
    let entry = |n: u64| {
        let mut id = [0u8; 16];
        id[..8].copy_from_slice(&n.to_le_bytes());
        (id, leaf_digest(n))
    };

    let gap = BatcherSnapshot {
        epoch: 120,
        next_submission: 3,
        pending: vec![entry(0), entry(2)],
        overflow: Vec::new(),
    };
    assert_eq!(
        EpochBatcher::resume(&TEST_MASTER_KEY, HEIGHT, gap).err(),
        Some(RegistryError::MalformedPayload),
        "identifier 1 was minted and is gone"
    );

    let reordered = BatcherSnapshot {
        epoch: 120,
        next_submission: 3,
        pending: vec![entry(1), entry(0)],
        overflow: vec![entry(2)],
    };
    assert_eq!(
        EpochBatcher::resume(&TEST_MASTER_KEY, HEIGHT, reordered).err(),
        Some(RegistryError::MalformedPayload),
        "arrival order is the order a batcher queues in"
    );

    let premature_queue = BatcherSnapshot {
        epoch: 120,
        next_submission: 1,
        pending: Vec::new(),
        overflow: vec![entry(0)],
    };
    assert_eq!(
        EpochBatcher::resume(&TEST_MASTER_KEY, HEIGHT, premature_queue).err(),
        Some(RegistryError::MalformedPayload),
        "a queue beside a half-empty epoch never came from a batcher"
    );

    // And the shape a real batcher does reach: a full epoch with a queue behind it.
    let signer = SpecTestSigner::from(&RFC8032_SECRET_KEY);
    let mut real = batcher(120);
    for n in 0..(CAPACITY as u64 + 2) {
        real.submit::<MixHash, _>(leaf_digest(n), &signer)
            .expect("accepted");
    }
    let honest = real.snapshot();
    assert_eq!(honest.overflow.len(), 2);
    assert!(EpochBatcher::resume(&TEST_MASTER_KEY, HEIGHT, honest).is_ok());

    // As does a sealed one, whose live identifiers are the queue that survived.
    let mut sealed = batcher(121);
    for n in 0..(CAPACITY as u64 + 2) {
        sealed
            .submit::<MixHash, _>(leaf_digest(n), &signer)
            .expect("accepted");
    }
    sealed.seal::<MixHash>(121).expect("seals");
    let after = sealed.snapshot();
    assert_eq!(after.pending.len(), 2);
    assert!(EpochBatcher::resume(&TEST_MASTER_KEY, HEIGHT, after).is_ok());
}

#[test]
fn a_snapshot_resumes_without_reissuing_an_identifier() {
    let signer = SpecTestSigner::from(&RFC8032_SECRET_KEY);
    let mut before = batcher(100);
    for n in 0..3u64 {
        before
            .submit::<MixHash, _>(leaf_digest(n), &signer)
            .expect("accepted");
    }
    let snapshot = before.snapshot();
    let mut after =
        EpochBatcher::resume(&TEST_MASTER_KEY, HEIGHT, snapshot.clone()).expect("resumes");
    let next = after
        .submit::<MixHash, _>(leaf_digest(99), &signer)
        .expect("accepted");
    let mut expected = [0u8; 16];
    expected[..8].copy_from_slice(&3u64.to_le_bytes());
    assert_eq!(
        next.submission_id, expected,
        "D-69: a restart continues the counter"
    );
    assert_eq!(after.epoch(), snapshot.epoch);
}

#[test]
fn a_full_epoch_promises_the_next_one_and_queues_rather_than_dropping() {
    let signer = SpecTestSigner::from(&RFC8032_SECRET_KEY);
    let mut batcher = batcher(200);
    for n in 0..CAPACITY as u64 {
        let promise = batcher
            .submit::<MixHash, _>(leaf_digest(n), &signer)
            .expect("accepted");
        assert_eq!(promise.promised_epoch, 200);
    }
    let spilled = batcher
        .submit::<MixHash, _>(leaf_digest(999), &signer)
        .expect("V-N-14: queued, not dropped");
    assert_eq!(
        spilled.promised_epoch, 201,
        "D-71: the next epoch it can meet"
    );
    assert_eq!(batcher.overflow_queue_len(), 1);
}

#[test]
fn beyond_the_merge_delay_the_batcher_refuses_rather_than_promise_what_it_cannot_keep() {
    let signer = SpecTestSigner::from(&RFC8032_SECRET_KEY);
    let mut batcher = batcher(300);
    let holds = CAPACITY * (1 + usize::from(MAX_MERGE_DELAY));
    for n in 0..holds as u64 {
        batcher
            .submit::<MixHash, _>(leaf_digest(n), &signer)
            .expect("inside the window");
    }
    assert_eq!(batcher.overflow_queue_len(), holds - CAPACITY);
    assert_eq!(
        batcher
            .submit::<MixHash, _>(leaf_digest(u64::MAX), &signer)
            .err(),
        Some(RegistryError::EpochCapacityExceeded),
        "D-71: no epoch inside the delay can hold it, so there is no honest promise"
    );
}

#[test]
fn sealing_builds_the_tree_the_specification_prescribes() {
    let signer = SpecTestSigner::from(&RFC8032_SECRET_KEY);
    let mut batcher = batcher(400);
    let mut real: Vec<(SubmissionId, Digest)> = Vec::new();
    for n in 0..5u64 {
        let promise = batcher
            .submit::<MixHash, _>(leaf_digest(n), &signer)
            .expect("accepted");
        real.push((promise.submission_id, promise.leaf));
    }
    let sealed = batcher.seal::<MixHash>(400).expect("seals");
    let directly =
        BuiltEpoch::build::<MixHash>(400, HEIGHT, &TEST_MASTER_KEY, &real).expect("builds");
    assert_eq!(sealed.root, directly.root, "sealing is building");
    assert_eq!(
        sealed.assignment,
        assignment_oracle::<MixHash>(400, HEIGHT, &TEST_MASTER_KEY, &real),
        "every slot is the one §1.4 prescribes"
    );
}

#[test]
fn sealing_advances_the_epoch_and_pulls_from_the_queue() {
    let signer = SpecTestSigner::from(&RFC8032_SECRET_KEY);
    let mut batcher = batcher(500);
    for n in 0..(CAPACITY as u64 + 3) {
        batcher
            .submit::<MixHash, _>(leaf_digest(n), &signer)
            .expect("accepted");
    }
    assert_eq!(batcher.overflow_queue_len(), 3);
    let sealed = batcher.seal::<MixHash>(500).expect("seals");
    assert_eq!(sealed.assignment.len(), CAPACITY, "a full epoch");
    assert_eq!(batcher.epoch(), 501);
    assert_eq!(
        batcher.pending_len(),
        3,
        "the queue moved into the new epoch"
    );
    assert_eq!(batcher.overflow_queue_len(), 0);
}

#[test]
fn sealing_an_epoch_out_of_order_is_0x0d() {
    let mut batcher = batcher(600);
    assert_eq!(
        batcher.seal::<MixHash>(601).err(),
        Some(RegistryError::EpochOutOfOrder),
        "INV-ANCH-02's discipline at the batcher: one epoch at a time, in order"
    );
    assert_eq!(
        batcher.seal::<MixHash>(599).err(),
        Some(RegistryError::EpochOutOfOrder)
    );
    assert!(batcher.seal::<MixHash>(600).is_ok());
}

#[test]
fn an_empty_epoch_seals_like_any_other() {
    let mut batcher = batcher(700);
    let sealed = batcher.seal::<MixHash>(700).expect("seals");
    assert_eq!(sealed.leaves.len(), CAPACITY);
    assert_eq!(sealed.assignment.len(), 0);
    assert_eq!(batcher.epoch(), 701, "INV-ANCH-01: no epoch is skipped");
}

/// §1.6's construction, under the engine's own hasher and verifier.
#[cfg(feature = "native")]
mod with_real_crypto {
    use super::*;
    use certimining_core::{
        epoch_key, DalekVerifier, NativeKeccak, Preimage, SpiPreimage, Verifier,
    };
    use certimining_log::{
        promise_digest, promise_kept, verify_promise, InclusionVerifier, ProofVerifier,
        PublishedRoot,
    };

    /// Ed25519 verification for these cases, the implementation the engine offers under `native`.
    struct DalekCheck;

    impl Verifier for DalekCheck {
        fn verify(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> Result<()> {
            DalekVerifier::verify(public_key, message, signature)
        }
    }

    fn real_batcher(epoch: u64) -> EpochBatcher {
        EpochBatcher::start(&TEST_MASTER_KEY, HEIGHT, epoch).expect("starts")
    }

    #[test]
    fn the_promise_signs_the_spi_digest_that_the_specification_writes() {
        let signer = SpecTestSigner::from(&RFC8032_SECRET_KEY);
        let mut batcher = real_batcher(800);
        let promise = batcher
            .submit::<NativeKeccak, _>(leaf_digest(7), &signer)
            .expect("accepted");

        // §1.6 signs Keccak256( TAG_SPI ‖ leaf ‖ submission_id ‖ accepted_epoch ‖ promised_epoch
        // ‖ max_merge_delay ),
        // so the message is the digest and not the preimage. Built here from the specification's own
        // field order rather than read back from the promise's own helper.
        let expected = SpiPreimage {
            leaf: promise.leaf,
            submission_id: promise.submission_id,
            accepted_epoch: promise.accepted_epoch,
            promised_epoch: promise.promised_epoch,
            max_merge_delay: promise.max_merge_delay,
        }
        .digest::<NativeKeccak>()
        .expect("a digest");
        assert_eq!(promise_digest::<NativeKeccak>(&promise), Ok(expected));
        assert_eq!(
            DalekCheck::verify(&promise.batcher_key, &expected, &promise.signature),
            Ok(()),
            "§1.6: the signature is over the digest"
        );
        assert_eq!(
            verify_promise::<NativeKeccak, DalekCheck>(&promise, &signer.public_key()),
            Ok(())
        );
    }

    #[test]
    fn a_promise_from_another_key_is_0x08_before_anything_is_verified() {
        let signer = SpecTestSigner::from(&RFC8032_SECRET_KEY);
        let other = SpecTestSigner::from(&RFC8032_SECOND_KEY);
        let mut batcher = real_batcher(801);
        let promise = batcher
            .submit::<NativeKeccak, _>(leaf_digest(8), &signer)
            .expect("accepted");
        assert_eq!(
            verify_promise::<NativeKeccak, DalekCheck>(&promise, &other.public_key()),
            Err(RegistryError::AttestationKeyMismatch),
            "D-68: the key inside a promise is never the authority"
        );
    }

    #[test]
    fn a_promise_whose_signature_covers_other_bytes_is_0x07() {
        let signer = SpecTestSigner::from(&RFC8032_SECRET_KEY);
        let mut batcher = real_batcher(802);
        let mut promise = batcher
            .submit::<NativeKeccak, _>(leaf_digest(9), &signer)
            .expect("accepted");
        promise.promised_epoch += 1;
        assert_eq!(
            verify_promise::<NativeKeccak, DalekCheck>(&promise, &signer.public_key()),
            Err(RegistryError::AttestationInvalid),
            "the promise binds every field it names"
        );

        let mut altered = batcher
            .submit::<NativeKeccak, _>(leaf_digest(10), &signer)
            .expect("accepted");
        altered.leaf[0] ^= 0x01;
        assert_eq!(
            verify_promise::<NativeKeccak, DalekCheck>(&altered, &signer.public_key()),
            Err(RegistryError::AttestationInvalid),
            "INV-SPI-02: the promise binds the exact leaf"
        );
    }

    #[test]
    fn v_p_10_a_promise_is_kept_inside_the_window_and_0x14_after_it() {
        let signer = SpecTestSigner::from(&RFC8032_SECRET_KEY);
        let mut batcher = real_batcher(900);
        let promise = batcher
            .submit::<NativeKeccak, _>(leaf_digest(11), &signer)
            .expect("accepted");

        // The leaf lands two epochs late, which §1.6 still satisfies.
        let late = 900 + u64::from(MAX_MERGE_DELAY);
        let real = vec![(promise.submission_id, promise.leaf)];
        let epoch = BuiltEpoch::build::<NativeKeccak>(late, HEIGHT, &TEST_MASTER_KEY, &real)
            .expect("builds");
        let proof = epoch.proof(&promise.submission_id).expect("holds it");
        assert_eq!(
            ProofVerifier::verify::<NativeKeccak>(&promise.leaf, &proof, &epoch.root),
            Ok(())
        );
        assert_eq!(
            promise_kept::<NativeKeccak>(
                &promise,
                &proof,
                &PublishedRoot {
                    epoch: late,
                    root: epoch.root
                }
            ),
            Ok(()),
            "V-P-10: satisfied at promised_epoch + 2"
        );

        // One epoch later, the same proof confirms the breach rather than rebutting it.
        let after = late + 1;
        let epoch = BuiltEpoch::build::<NativeKeccak>(after, HEIGHT, &TEST_MASTER_KEY, &real)
            .expect("builds");
        let proof = epoch.proof(&promise.submission_id).expect("holds it");
        assert_eq!(
            promise_kept::<NativeKeccak>(
                &promise,
                &proof,
                &PublishedRoot {
                    epoch: after,
                    root: epoch.root
                }
            ),
            Err(RegistryError::MergeDelayExceeded),
            "V-P-10, and D-72: a root published after the window confirms the breach"
        );

        // The review's H-02 probe: the same late proof and root, relabelled with an epoch inside the
        // window. A label beside a root is not the authority, and a proof carries its own epoch.
        assert_eq!(
            promise_kept::<NativeKeccak>(
                &promise,
                &proof,
                &PublishedRoot {
                    epoch: 900,
                    root: epoch.root
                }
            ),
            Err(RegistryError::InclusionProofInvalid),
            "H-02: a proof for one epoch presented beside another epoch's label"
        );
    }

    #[test]
    fn a_rebuttal_must_be_for_the_promised_leaf_and_must_verify() {
        let signer = SpecTestSigner::from(&RFC8032_SECRET_KEY);
        let mut batcher = real_batcher(910);
        let promise = batcher
            .submit::<NativeKeccak, _>(leaf_digest(12), &signer)
            .expect("accepted");
        let real = vec![(promise.submission_id, leaf_digest(13))];
        let epoch = BuiltEpoch::build::<NativeKeccak>(910, HEIGHT, &TEST_MASTER_KEY, &real)
            .expect("builds");
        let proof = epoch.proof(&promise.submission_id).expect("holds it");
        assert_eq!(
            promise_kept::<NativeKeccak>(
                &promise,
                &proof,
                &PublishedRoot {
                    epoch: 910,
                    root: epoch.root
                }
            ),
            Err(RegistryError::InclusionProofInvalid),
            "a proof of some other leaf rebuts nothing"
        );
    }

    #[test]
    fn a_promise_carrying_a_merge_delay_the_specification_does_not_allow_is_refused() {
        // H-01: a signature proves authorship, not compliance. The key holder does not choose the
        // policy its own promise is judged against.
        let signer = SpecTestSigner::from(&RFC8032_SECRET_KEY);
        let mut batcher = real_batcher(930);
        let honest = batcher
            .submit::<NativeKeccak, _>(leaf_digest(15), &signer)
            .expect("accepted");

        let mut lax = honest.clone();
        lax.max_merge_delay = MAX_MERGE_DELAY + 1;
        let digest = promise_digest::<NativeKeccak>(&lax).expect("a digest");
        lax.signature = signer.sign(&digest).expect("signs");
        assert_eq!(
            DalekCheck::verify(&lax.batcher_key, &digest, &lax.signature),
            Ok(()),
            "the signature is genuine, which is the whole point of the case"
        );
        assert_eq!(
            verify_promise::<NativeKeccak, DalekCheck>(&lax, &signer.public_key()),
            Err(RegistryError::PromisePolicyInvalid),
            "INV-SPI-01 fixes the delay at 2, and a correctly signed 3 is still refused"
        );
    }

    #[test]
    fn a_promise_deferred_past_the_window_its_acceptance_allows_is_refused() {
        // D-74's second half: without a signed acceptance epoch, a batcher could name any promised
        // epoch and stay answerable to nobody. With one, the promise is judged against it.
        let signer = SpecTestSigner::from(&RFC8032_SECRET_KEY);
        let mut batcher = real_batcher(950);
        let honest = batcher
            .submit::<NativeKeccak, _>(leaf_digest(17), &signer)
            .expect("accepted");
        assert_eq!(honest.accepted_epoch, 950);

        for deferred in [951u64, 952] {
            let mut later = honest.clone();
            later.promised_epoch = deferred;
            let digest = promise_digest::<NativeKeccak>(&later).expect("a digest");
            later.signature = signer.sign(&digest).expect("signs");
            assert_eq!(
                verify_promise::<NativeKeccak, DalekCheck>(&later, &signer.public_key()),
                Ok(()),
                "a promise inside the delay is what an overflowing batcher issues"
            );
        }

        for deferred in [953u64, 1_000, u64::MAX - 2] {
            let mut far = honest.clone();
            far.promised_epoch = deferred;
            let digest = promise_digest::<NativeKeccak>(&far).expect("a digest");
            far.signature = signer.sign(&digest).expect("signs");
            assert_eq!(
                DalekCheck::verify(&far.batcher_key, &digest, &far.signature),
                Ok(()),
                "the signature is genuine, which is the point of the case"
            );
            assert_eq!(
                verify_promise::<NativeKeccak, DalekCheck>(&far, &signer.public_key()),
                Err(RegistryError::PromisePolicyInvalid),
                "epoch {deferred} is past what acceptance in 950 allows"
            );
        }

        // L-01: the boundary is a policy question, so it reports the policy code rather than an
        // arithmetic one. The window is measured by subtraction for exactly this case.
        let mut terminal = honest.clone();
        terminal.accepted_epoch = u64::MAX;
        terminal.promised_epoch = 0;
        let digest = promise_digest::<NativeKeccak>(&terminal).expect("a digest");
        terminal.signature = signer.sign(&digest).expect("signs");
        assert_eq!(
            verify_promise::<NativeKeccak, DalekCheck>(&terminal, &signer.public_key()),
            Err(RegistryError::PromisePolicyInvalid),
            "a promise pointing backwards from the last epoch is policy, not overflow"
        );

        let mut terminal_ok = honest.clone();
        terminal_ok.accepted_epoch = u64::MAX;
        terminal_ok.promised_epoch = u64::MAX;
        let digest = promise_digest::<NativeKeccak>(&terminal_ok).expect("a digest");
        terminal_ok.signature = signer.sign(&digest).expect("signs");
        assert_eq!(
            verify_promise::<NativeKeccak, DalekCheck>(&terminal_ok, &signer.public_key()),
            Ok(()),
            "and one accepted and promised at the last epoch is policy-valid"
        );

        let mut backwards = honest.clone();
        backwards.promised_epoch = 949;
        let digest = promise_digest::<NativeKeccak>(&backwards).expect("a digest");
        backwards.signature = signer.sign(&digest).expect("signs");
        assert_eq!(
            verify_promise::<NativeKeccak, DalekCheck>(&backwards, &signer.public_key()),
            Err(RegistryError::PromisePolicyInvalid),
            "a promise cannot be kept by a root published before it was made"
        );
    }

    #[test]
    fn a_promise_encodes_to_the_octets_the_notes_claim() {
        // L-01: the Rust value carries padding and says nothing about what travels between parties.
        let signer = SpecTestSigner::from(&RFC8032_SECRET_KEY);
        let mut batcher = real_batcher(940);
        let promise = batcher
            .submit::<NativeKeccak, _>(leaf_digest(16), &signer)
            .expect("accepted");
        let encoded = promise.encode();
        assert_eq!(encoded.len(), PROMISE_ENCODED_LEN);
        assert_eq!(&encoded[..32], &promise.leaf[..]);
        assert_eq!(&encoded[32..48], &promise.submission_id[..]);
        assert_eq!(&encoded[48..56], &promise.accepted_epoch.to_le_bytes()[..]);
        assert_eq!(&encoded[56..64], &promise.promised_epoch.to_le_bytes()[..]);
        assert_eq!(encoded[64], promise.max_merge_delay);
        assert_eq!(&encoded[65..97], &promise.batcher_key[..]);
        assert_eq!(&encoded[97..], &promise.signature[..]);
    }

    #[test]
    fn a_promise_carries_nothing_but_the_seven_fields_the_specification_names() {
        let signer = SpecTestSigner::from(&RFC8032_SECRET_KEY);
        let mut batcher = real_batcher(920);
        let promise = batcher
            .submit::<NativeKeccak, _>(leaf_digest(14), &signer)
            .expect("accepted");

        let bytes = promise.encode();
        assert_eq!(
            bytes.len(),
            PROMISE_ENCODED_LEN,
            "32 + 16 + 8 + 8 + 1 + 32 + 64 octets, and nothing else"
        );

        // Nothing that identifies an asset may appear, and neither may the epoch key the batcher used.
        let k_e = epoch_key::<NativeKeccak>(&TEST_MASTER_KEY, 920).expect("derives");
        for (what, needle) in [
            ("the master key", &TEST_MASTER_KEY[..]),
            ("the epoch key", &k_e[..]),
            ("a tenure identifier", &b"BCTENURE1043A"[..]),
            ("a jurisdiction code", &b"CABC"[..]),
            ("a payload URI", &b"ipfs://"[..]),
        ] {
            assert!(
                !bytes.windows(needle.len()).any(|w| w == needle),
                "INV-DISC-01's discipline applied to a promise: {what} must not appear in one"
            );
        }
    }
}
