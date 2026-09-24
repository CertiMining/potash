//! E-07: the batcher, its promises, the overflow queue, and §4.2's V-P-10.
//!
//! Written before the implementation (D-65, S4): the batcher seals epoch trees, so the rule that
//! covers anything touching the tree covers this.
//!
//! The signer here is RFC 8032 §7.1's published key behind §2.2's `Signer`. Its private half is
//! public, so every signature is reproducible, and nothing resembling a real batcher key enters this
//! repository — the engine has no place to keep one.

mod common;

use certimining_core::{
    epoch_key, Digest, NativeKeccak, Preimage, RegistryError, Result, Signer, SpiPreimage,
    SubmissionId, Verifier,
};
use certimining_log::{
    promise_digest, promise_kept, verify_promise, Batcher, BuiltEpoch, EpochBatcher, EpochTree,
    InclusionVerifier, ProofVerifier, MAX_MERGE_DELAY,
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

/// Ed25519 verification for the tests, the same implementation the engine offers under `native`.
struct DalekCheck;

impl Verifier for DalekCheck {
    fn verify(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> Result<()> {
        certimining_core::DalekVerifier::verify(public_key, message, signature)
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

        // §1.6 signs Keccak256( TAG_SPI ‖ leaf ‖ submission_id ‖ promised_epoch ‖ max_merge_delay ),
        // so the message is the digest and not the preimage. Built here from the specification's own
        // field order rather than read back from the promise's own helper.
        let expected = SpiPreimage {
            leaf: promise.leaf,
            submission_id: promise.submission_id,
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
            promise_kept::<NativeKeccak>(&promise, &proof, &epoch.root, late),
            Ok(()),
            "V-P-10: satisfied at promised_epoch + 2"
        );

        // One epoch later, the same proof confirms the breach rather than rebutting it.
        let after = late + 1;
        let epoch = BuiltEpoch::build::<NativeKeccak>(after, HEIGHT, &TEST_MASTER_KEY, &real)
            .expect("builds");
        let proof = epoch.proof(&promise.submission_id).expect("holds it");
        assert_eq!(
            promise_kept::<NativeKeccak>(&promise, &proof, &epoch.root, after),
            Err(RegistryError::MergeDelayExceeded),
            "V-P-10, and D-72: a root published after the window confirms the breach"
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
            promise_kept::<NativeKeccak>(&promise, &proof, &epoch.root, 910),
            Err(RegistryError::InclusionProofInvalid),
            "a proof of some other leaf rebuts nothing"
        );
    }

    #[test]
    fn a_promise_carries_nothing_but_the_six_fields_the_specification_names() {
        let signer = SpecTestSigner::from(&RFC8032_SECRET_KEY);
        let mut batcher = real_batcher(920);
        let promise = batcher
            .submit::<NativeKeccak, _>(leaf_digest(14), &signer)
            .expect("accepted");

        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(&promise.leaf);
        bytes.extend_from_slice(&promise.submission_id);
        bytes.extend_from_slice(&promise.promised_epoch.to_le_bytes());
        bytes.push(promise.max_merge_delay);
        bytes.extend_from_slice(&promise.batcher_key);
        bytes.extend_from_slice(&promise.signature);
        assert_eq!(
            bytes.len(),
            153,
            "32 + 16 + 8 + 1 + 32 + 64, and nothing else"
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
