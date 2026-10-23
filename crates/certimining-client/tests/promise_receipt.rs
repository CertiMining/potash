// SPDX-License-Identifier: MIT OR Apache-2.0
//! H-02's transfer check: a promise judged against a Bitcoin-confirmed receipt over its own bytes.
//!
//! **Where the trust is arranged.** The headers below are real mainnet headers, committed as bytes,
//! and the block these cases turn on is the one this repository's own first anchor is attested in.
//! So the epoch the judgment runs against is not a number this file chose: it is the UTC day index
//! of a real Bitcoin block's own timestamp, reached through `confirm`, which needs a chain of real
//! work running back to a committed checkpoint.
//!
//! **That block predates the log's first published epoch**, which is why this file is built on a
//! repository anchor rather than on an epoch receipt: the epochs around it are days the log did not
//! exist for, so no value here is one the announced deployment holds. An earlier version of this
//! file was built on a published epoch's receipt, and `check-live-values` refused it. It was right
//! to, and the rule is why these cases read a block from before the log existed.
//!
//! The keys are published values too. `TEST_MASTER_KEY` says in its own bytes that it is not
//! secret, and the signing keys are RFC 8032 §7.1's first and second.

#![cfg(feature = "ots")]

use certimining_client::bitcoin::{
    confirm, merkle_root_at, target_from_bits, Checkpoint, Confirmation, Header,
};
use certimining_client::{
    day_index, judge_against_confirmation, verify_transferred_promise, BitcoinClaim,
    ReceiptRefused, TransferRefused,
};
use certimining_core::{
    DalekVerifier, Digest, NativeKeccak, RegistryError, Result, Signer, Verifier,
};
use certimining_log::{Batcher, EpochBatcher, SignedPromise};

/// Blocks 967485 to 967489, the window anchor `0001`'s receipt is attested in.
const HEADERS: &[u8] = include_bytes!("data/mainnet-headers-967485-967495.bin");
/// The checkpoint those headers run from, as `anchor_b_confirmed.rs` commits it.
const CHECKPOINT_HEIGHT: u32 = 967_484;
const CHECKPOINT_HASH: &str = "00000000000000000000d89a58cbb4687852251e9753f847d06c1c417b2e80ed";
const CHECKPOINT_BITS: u32 = 0x1702_355e;
/// The height that receipt names.
const ATTESTED_HEIGHT: u32 = 967_489;
/// That block's own timestamp, and the epoch it falls in. Bitcoin's values, not this file's.
const ATTESTED_TIME: u32 = 1_789_699_899;
const ESTABLISHED_EPOCH: u64 = 20_714;

/// Anchor `0001`'s committed receipt, which timestamps this repository's own manifest digest.
///
/// A real Bitcoin-carrying receipt over something that is plainly not a promise, which is what the
/// binding case needs.
const REPOSITORY_RECEIPT: &[u8] = include_bytes!("../../../anchors/0001-0258f51.txt.ots");

/// A master key that says in its own bytes that it is not one (D-50).
const TEST_MASTER_KEY: Digest = *b"CMv1 TEST MASTER KEY, NOT SECRET";

/// RFC 8032 §7.1's first secret key, a published value.
const RFC8032_SECRET_KEY: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];

/// RFC 8032 §7.1's second, for the case where a counterparty expects another batcher.
const RFC8032_SECOND_KEY: [u8; 32] = [
    0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda, 0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e, 0x0f,
    0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24, 0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8, 0xa6, 0xfb,
];

const HEIGHT: u8 = 8;

struct TestSigner(ed25519_dalek::SigningKey);

impl From<&[u8; 32]> for TestSigner {
    fn from(seed: &[u8; 32]) -> Self {
        Self(ed25519_dalek::SigningKey::from_bytes(seed))
    }
}

impl Signer for TestSigner {
    fn sign(&self, message: &[u8]) -> Result<[u8; 64]> {
        use ed25519_dalek::Signer as _;
        Ok(self.0.sign(message).to_bytes())
    }

    fn public_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }
}

struct Check;

impl Verifier for Check {
    fn verify(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> Result<()> {
        DalekVerifier::verify(public_key, message, signature)
    }
}

fn headers() -> Vec<Header> {
    assert!(
        HEADERS.len().is_multiple_of(80) && !HEADERS.is_empty(),
        "{} bytes is not a whole number of 80-byte headers",
        HEADERS.len()
    );
    HEADERS
        .chunks_exact(80)
        .map(|chunk| match <[u8; 80]>::try_from(chunk) {
            Ok(raw) => Header(raw),
            Err(e) => panic!("{e}"),
        })
        .collect()
}

/// A hash as an explorer prints it, in the order a header stores it.
fn from_displayed(text: &str) -> [u8; 32] {
    assert_eq!(text.len(), 64, "a block hash is 64 hex characters");
    let mut out = [0u8; 32];
    for (i, pair) in text.as_bytes().chunks_exact(2).enumerate() {
        let hex = match std::str::from_utf8(pair) {
            Ok(hex) => hex,
            Err(e) => panic!("{text:?}: {e}"),
        };
        match (u8::from_str_radix(hex, 16), out.get_mut(i)) {
            (Ok(byte), Some(slot)) => *slot = byte,
            (Err(e), _) => panic!("{hex:?}: {e}"),
            (_, None) => panic!("{text:?} is longer than 32 bytes"),
        }
    }
    out.reverse();
    out
}

fn checkpoint() -> Checkpoint {
    Checkpoint {
        height: CHECKPOINT_HEIGHT,
        hash: from_displayed(CHECKPOINT_HASH),
        // Four headers inside one retarget period, so no boundary is crossed and no timestamp is
        // needed (H-53, #195).
        time: None,
        target: match target_from_bits(CHECKPOINT_BITS) {
            Some(target) => target,
            None => panic!("the committed bits do not decode to a target"),
        },
    }
}

/// A real confirmation of the attested block, which is the only way to reach a judgment.
///
/// The claim's digest is read out of the chain rather than stated here, because what this file is
/// about is the block's **timestamp**; whether a receipt's operations reach that block's merkle root
/// is H-12's question and `anchor_b_confirmed.rs` answers it over every committed receipt.
fn confirmed() -> certimining_client::bitcoin::Confirmed {
    let chain = headers();
    let merkle_root = match merkle_root_at(checkpoint(), &chain, ATTESTED_HEIGHT) {
        Ok(root) => root,
        Err(e) => panic!("the committed headers do not cover {ATTESTED_HEIGHT}: {e:?}"),
    };
    let claim = BitcoinClaim {
        height: ATTESTED_HEIGHT,
        attested_digest: merkle_root,
    };
    match confirm(claim, checkpoint(), &chain) {
        Ok(Confirmation::Confirmed(confirmed)) => confirmed,
        // The committed window carries `CONFIRMATION_DEPTH` headers above the attested block since
        // H-56 (#222), so a `Pending` here means the fixture was shortened rather than that the
        // rule changed.
        other => panic!("the block at {ATTESTED_HEIGHT} does not confirm: {other:?}"),
    }
}

/// A promise from a batcher whose current epoch is `accepted`.
fn promise_accepted_in(accepted: u64, signer: &TestSigner) -> SignedPromise {
    let mut batcher =
        EpochBatcher::start(&TEST_MASTER_KEY, HEIGHT, accepted).expect("a batcher starts");
    let promise = batcher
        .submit::<NativeKeccak, _>([7u8; 32], signer)
        .expect("the submission is accepted");
    assert_eq!(
        promise.accepted_epoch, accepted,
        "§1.6: the batcher signs the epoch it accepted in"
    );
    promise
}

/// **The epoch comes out of the block, and the block's timestamp is Bitcoin's.**
///
/// This is the whole of what `Confirmed::time` adds, checked against a value nobody here chose.
#[test]
fn the_confirmed_block_supplies_its_own_timestamp_and_the_epoch_follows_from_it() {
    let confirmed = confirmed();
    assert_eq!(
        confirmed.time, ATTESTED_TIME,
        "block {ATTESTED_HEIGHT}'s header states this timestamp"
    );
    assert_eq!(
        day_index(i64::from(confirmed.time)),
        Some(ESTABLISHED_EPOCH),
        "§1.4 makes an epoch the UTC day index a Unix time falls in"
    );
    // The epoch this establishes is a day the log did not exist for, which is the point twice over:
    // the judgment reads a calendar rather than the sequence, and `check-live-values` is what holds
    // this file to a block from before the log's first epoch. Asserting that here would mean naming
    // a published epoch to compare against, which is the value the gate exists to keep out.
}

#[test]
fn a_promise_accepted_in_the_epoch_the_block_establishes_is_judged() {
    let signer = TestSigner::from(&RFC8032_SECRET_KEY);
    let promise = promise_accepted_in(ESTABLISHED_EPOCH, &signer);
    let established = judge_against_confirmation::<NativeKeccak, Check>(
        &promise,
        &signer.public_key(),
        &confirmed(),
    );
    match established {
        Ok(established) => {
            assert_eq!(established.existed_by_epoch, ESTABLISHED_EPOCH);
            assert_eq!(established.confirmed.height, ATTESTED_HEIGHT);
        }
        Err(e) => panic!("the promise should be judged: {e:?}"),
    }
}

/// §1.6 allows one epoch behind, because a promise can arrive across an epoch boundary.
#[test]
fn a_promise_accepted_the_epoch_before_is_still_judged() {
    let signer = TestSigner::from(&RFC8032_SECRET_KEY);
    let promise = promise_accepted_in(ESTABLISHED_EPOCH - 1, &signer);
    assert!(
        judge_against_confirmation::<NativeKeccak, Check>(
            &promise,
            &signer.public_key(),
            &confirmed()
        )
        .is_ok(),
        "one epoch behind is inside §1.6's tolerance"
    );
}

/// **The attack the receipt exists to refuse**, now refusable by a party that observed nothing.
///
/// A batcher naming an acceptance epoch later than the moment the promise demonstrably already
/// existed is deferring its own answerability. Before H-02 only the receiving counterparty could
/// see this, because only that party held an observation to compare against.
#[test]
fn a_promise_accepted_after_the_block_that_proves_it_existed_is_refused() {
    let signer = TestSigner::from(&RFC8032_SECRET_KEY);
    let promise = promise_accepted_in(ESTABLISHED_EPOCH + 1, &signer);
    assert_eq!(
        judge_against_confirmation::<NativeKeccak, Check>(
            &promise,
            &signer.public_key(),
            &confirmed()
        ),
        Err(TransferRefused::Promise(
            RegistryError::PromisePolicyInvalid
        )),
        "§1.6: an acceptance epoch later than the epoch judged against is 0x17"
    );
}

#[test]
fn a_promise_accepted_two_epochs_before_is_refused() {
    let signer = TestSigner::from(&RFC8032_SECRET_KEY);
    let promise = promise_accepted_in(ESTABLISHED_EPOCH - 2, &signer);
    assert_eq!(
        judge_against_confirmation::<NativeKeccak, Check>(
            &promise,
            &signer.public_key(),
            &confirmed()
        ),
        Err(TransferRefused::Promise(
            RegistryError::PromisePolicyInvalid
        )),
        "§1.6 allows one epoch behind and no more"
    );
}

/// The expected key still decides first, on this path as on §1.6's own.
#[test]
fn a_promise_from_another_key_is_refused_before_the_epoch_is_consulted() {
    let signer = TestSigner::from(&RFC8032_SECRET_KEY);
    let other = TestSigner::from(&RFC8032_SECOND_KEY);
    // Accepted in an epoch that would otherwise be judged, so the key is the only thing wrong.
    let promise = promise_accepted_in(ESTABLISHED_EPOCH, &signer);
    assert_eq!(
        judge_against_confirmation::<NativeKeccak, Check>(
            &promise,
            &other.public_key(),
            &confirmed()
        ),
        Err(TransferRefused::Promise(
            RegistryError::AttestationKeyMismatch
        )),
        "§1.3's condition (c) shape: a key that is not the expected one is 0x08"
    );
}

/// **A receipt is bound to the artifact it timestamps.**
///
/// Anchor `0001`'s receipt is a real Bitcoin-carrying receipt over this repository's own manifest
/// digest. Offered as a promise receipt it must fail at the binding step and never reach a
/// judgment, because otherwise any receipt anyone ever published would vouch for any promise.
#[test]
fn a_receipt_over_another_artifact_does_not_timestamp_a_promise() {
    let signer = TestSigner::from(&RFC8032_SECRET_KEY);
    let promise = promise_accepted_in(ESTABLISHED_EPOCH, &signer);
    assert_eq!(
        verify_transferred_promise::<NativeKeccak, Check>(
            &promise,
            &signer.public_key(),
            REPOSITORY_RECEIPT,
            checkpoint(),
            &headers(),
        ),
        Err(TransferRefused::NotThisPromise(ReceiptRefused::WrongRoot)),
        "the receipt timestamps a root, and the promise's 161 octets are not it"
    );
}
