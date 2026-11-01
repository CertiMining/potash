// SPDX-License-Identifier: MIT OR Apache-2.0
//! Offline staging rehearsal for D-143's split anchoring cycle.
//!
//! LiteSVM executes the real SBF program. The receipt is deliberately synthetic: this test proves
//! handoff/root/sequence/prefix reconciliation, not OpenTimestamps or Bitcoin consensus. Committed
//! receipt/header tests cover those separately, and the devnet reconciler refuses an unparseable or
//! pending receipt.

use anchor_lang::{InstructionData, ToAccountMetas};
use certimining_client::{
    checkpoint_address, receipt_digest, root_for_epoch, sequence_lag, status_of,
    verify_role_separation, AnchorStatus, Fetched, Handoff, KeyCollision, KeyRole, RootSource,
    Unreachable,
};
use certimining_core::{
    DalekVerifier, HandoffPreimage, NativeKeccak, Preimage, PreimageBuf, TAG_RCPT,
};
use certimining_log::{BuiltEpoch, EpochTree};
use ed25519_dalek::{Signer as _, SigningKey};
use litesvm::LiteSVM;
use sha3::{Digest as _, Keccak256};
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_signer::Signer;
use solana_transaction::Transaction;

const PROGRAM_SO: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../target/deploy/certimining_checkpoint.so"
);
const EPOCH: u64 = 41_001;
const HEIGHT: u8 = 8;

struct Runtime {
    svm: LiteSVM,
}

impl RootSource for Runtime {
    fn account_at(
        &self,
        address: &anchor_lang::prelude::Pubkey,
    ) -> Result<certimining_client::Observation, Unreachable> {
        let key = solana_pubkey::Pubkey::from(address.to_bytes());
        Ok(certimining_client::Observation {
            slot: None,
            account: self.svm.get_account(&key).map(|account| {
                (
                    anchor_lang::prelude::Pubkey::from(account.owner.to_bytes()),
                    account.data,
                )
            }),
        })
    }

    fn accounts_at(
        &self,
        addresses: &[anchor_lang::prelude::Pubkey],
    ) -> Result<certimining_client::OneView, Unreachable> {
        Ok(certimining_client::OneView {
            slot: None,
            accounts: addresses
                .iter()
                .map(|address| {
                    self.svm
                        .get_account(&solana_pubkey::Pubkey::from(address.to_bytes()))
                        .map(|account| {
                            (
                                anchor_lang::prelude::Pubkey::from(account.owner.to_bytes()),
                                account.data,
                            )
                        })
                })
                .collect(),
        })
    }
}

fn metas(accounts: Vec<anchor_lang::prelude::AccountMeta>) -> Vec<solana_instruction::AccountMeta> {
    accounts
        .into_iter()
        .map(|meta| solana_instruction::AccountMeta {
            pubkey: solana_pubkey::Pubkey::from(meta.pubkey.to_bytes()),
            is_signer: meta.is_signer,
            is_writable: meta.is_writable,
        })
        .collect()
}

struct Log {
    runtime: Runtime,
    payer: Keypair,
    authority: Keypair,
}

impl Log {
    fn new() -> Self {
        let program = std::fs::read(PROGRAM_SO)
            .unwrap_or_else(|error| panic!("{PROGRAM_SO}: {error}; run scripts/build-sbf.sh"));
        let mut svm = LiteSVM::new();
        svm.add_program(certimining_checkpoint::ID, &program)
            .expect("load SBF program");
        let mut clock: anchor_lang::prelude::Clock = svm.get_sysvar();
        clock.unix_timestamp = (EPOCH * certimining_checkpoint::SECONDS_PER_DAY) as i64;
        svm.set_sysvar(&clock);
        let payer = Keypair::new();
        let authority = Keypair::new();
        svm.airdrop(&payer.pubkey(), 100_000_000_000)
            .expect("fund worker payer");
        let mut log = Self {
            runtime: Runtime { svm },
            payer,
            authority,
        };
        let ok = log.send(
            certimining_checkpoint::accounts::Initialize {
                config: certimining_client::config_address(&certimining_checkpoint::ID),
                payer: anchor_lang::prelude::Pubkey::from(log.payer.pubkey().to_bytes()),
                system_program: anchor_lang::system_program::ID,
            }
            .to_account_metas(None),
            certimining_checkpoint::instruction::Initialize {
                authority: anchor_lang::prelude::Pubkey::from(log.authority.pubkey().to_bytes()),
                tree_height: HEIGHT,
                start_epoch: EPOCH,
            }
            .data(),
            false,
            true,
        );
        assert!(ok, "initialization succeeds");
        log
    }

    fn send(
        &mut self,
        accounts: Vec<anchor_lang::prelude::AccountMeta>,
        data: Vec<u8>,
        authority: bool,
        deliver: bool,
    ) -> bool {
        let message = Message::new(
            &[Instruction {
                program_id: certimining_checkpoint::ID,
                accounts: metas(accounts),
                data,
            }],
            Some(&self.payer.pubkey()),
        );
        let blockhash = self.runtime.svm.latest_blockhash();
        let transaction = if authority {
            Transaction::new(&[&self.payer, &self.authority], message, blockhash)
        } else {
            Transaction::new(&[&self.payer], message, blockhash)
        };
        if !deliver {
            return false;
        }
        self.runtime.svm.send_transaction(transaction).is_ok()
    }

    fn publish_at(&mut self, epoch: u64, observed_day: u64, root: [u8; 32], deliver: bool) -> bool {
        let mut clock: anchor_lang::prelude::Clock = self.runtime.svm.get_sysvar();
        clock.unix_timestamp = (observed_day * certimining_checkpoint::SECONDS_PER_DAY) as i64;
        self.runtime.svm.set_sysvar(&clock);
        self.send(
            certimining_checkpoint::accounts::Publish {
                config: certimining_client::config_address(&certimining_checkpoint::ID),
                checkpoint: checkpoint_address(&certimining_checkpoint::ID, epoch),
                authority: anchor_lang::prelude::Pubkey::from(self.authority.pubkey().to_bytes()),
                payer: anchor_lang::prelude::Pubkey::from(self.payer.pubkey().to_bytes()),
                system_program: anchor_lang::system_program::ID,
            }
            .to_account_metas(None),
            certimining_checkpoint::instruction::PublishCheckpoint {
                epoch,
                root,
                checkpoint_bump: certimining_client::checkpoint_bump(
                    &certimining_checkpoint::ID,
                    epoch,
                ),
                end: certimining_checkpoint::NothingFollows,
            }
            .data(),
            true,
            deliver,
        )
    }

    fn publish(&mut self, epoch: u64, root: [u8; 32]) -> bool {
        self.publish_at(epoch, epoch, root, true)
    }

    fn attach(&mut self, epoch: u64, digest: [u8; 32]) -> bool {
        self.send(
            certimining_checkpoint::accounts::Attach {
                config: certimining_client::config_address(&certimining_checkpoint::ID),
                checkpoint: checkpoint_address(&certimining_checkpoint::ID, epoch),
                authority: anchor_lang::prelude::Pubkey::from(self.authority.pubkey().to_bytes()),
            }
            .to_account_metas(None),
            certimining_checkpoint::instruction::AttachAnchorReceipt {
                epoch,
                receipt_digest: digest,
                kind: 1,
            }
            .data(),
            true,
            true,
        )
    }
}

fn signed_handoff(root: [u8; 32], signer: &SigningKey) -> Handoff {
    let mut bytes = PreimageBuf::new();
    HandoffPreimage {
        epoch: EPOCH,
        height: HEIGHT,
        root,
    }
    .write_preimage(&mut bytes)
    .expect("valid handoff preimage");
    Handoff {
        epoch: EPOCH,
        height: HEIGHT,
        root,
        batcher_key: signer.verifying_key().to_bytes(),
        signature: signer.sign(bytes.as_bytes()).to_bytes(),
    }
}

#[test]
fn split_cycle_reconciles_root_receipt_prefix_and_epoch() {
    let batcher = SigningKey::from_bytes(&[0x52; 32]);
    let built = <BuiltEpoch as EpochTree>::build::<NativeKeccak>(EPOCH, HEIGHT, &[0x61; 32], &[])
        .expect("build epoch");
    let handoff = signed_handoff(built.root, &batcher);
    let root = handoff
        .verify::<DalekVerifier>(&batcher.verifying_key().to_bytes(), EPOCH)
        .expect("signed batcher handoff");

    let mut log = Log::new();
    let public = [
        (
            KeyRole::ProgramAddress,
            certimining_checkpoint::ID.to_bytes(),
        ),
        (KeyRole::DeployAuthority, [2; 32]),
        (KeyRole::WorkerPayer, log.payer.pubkey().to_bytes()),
        (
            KeyRole::CheckpointAuthority,
            log.authority.pubkey().to_bytes(),
        ),
        (KeyRole::BatcherSigning, batcher.verifying_key().to_bytes()),
    ];
    assert_eq!(verify_role_separation(&public, &[]), Ok(()));
    assert!(log.publish(EPOCH, root));

    let receipt = b"staging receipt bytes; not an OpenTimestamps proof";
    let digest = receipt_digest::<NativeKeccak>(receipt).expect("short receipt");
    let mut preimage = Vec::new();
    preimage.extend_from_slice(&TAG_RCPT);
    preimage.extend_from_slice(&(receipt.len() as u16).to_le_bytes());
    preimage.extend_from_slice(receipt);
    assert_eq!(digest, <[u8; 32]>::from(Keccak256::digest(&preimage)));
    assert!(log.attach(EPOCH, digest));

    let fetched =
        root_for_epoch(&log.runtime, &certimining_checkpoint::ID, EPOCH).expect("runtime read");
    let checkpoint = match &fetched {
        Fetched::Placed(checkpoint) => checkpoint,
        other => panic!("expected placed checkpoint, found {other:?}"),
    };
    assert_eq!(checkpoint.root, handoff.root);
    assert_eq!(checkpoint.receipt_digest, digest);
    assert_eq!(checkpoint.anchor_kind, 1);
    assert_eq!(status_of(&fetched), AnchorStatus::Dual);
    let lag = sequence_lag(&log.runtime, &certimining_checkpoint::ID, EPOCH, EPOCH)
        .expect("one-view continuity check");
    assert!(lag.is_empty());
    assert!(!lag.configuration_moved);
    assert_eq!(lag.last_published, EPOCH);
}

#[test]
fn negative_mutations_are_observed_by_load_bearing_controls() {
    let batcher = SigningKey::from_bytes(&[0x52; 32]);
    let handoff = signed_handoff([0x33; 32], &batcher);
    let mut altered = handoff;
    altered.root = [0x34; 32];
    assert!(
        altered
            .verify::<DalekVerifier>(&batcher.verifying_key().to_bytes(), EPOCH)
            .is_err(),
        "altering the signed root must invalidate the handoff"
    );

    let collision = [
        (KeyRole::WorkerPayer, [7; 32]),
        (KeyRole::CheckpointAuthority, [7; 32]),
    ];
    assert_eq!(
        verify_role_separation(&collision, &[]),
        Err(KeyCollision::Public {
            left: KeyRole::WorkerPayer,
            right: KeyRole::CheckpointAuthority,
        })
    );

    let receipt = b"receipt";
    let canonical = receipt_digest::<NativeKeccak>(receipt).expect("short receipt");
    let mut wrong_prefix = Vec::from(*b"CMv1BAD!");
    wrong_prefix.extend_from_slice(&(receipt.len() as u16).to_le_bytes());
    wrong_prefix.extend_from_slice(receipt);
    assert_ne!(
        canonical,
        <[u8; 32]>::from(Keccak256::digest(&wrong_prefix))
    );

    let mut log = Log::new();
    assert!(log.publish(EPOCH, [0x11; 32]));
    assert!(
        !log.publish(EPOCH + 2, [0x22; 32]),
        "the program must reject a missed epoch instead of silently skipping it"
    );
}

#[test]
fn anchor_a_dropout_and_restart_leave_no_partial_checkpoint() {
    let root = [0xa1; 32];
    let mut log = Log::new();
    assert_eq!(
        root_for_epoch(&log.runtime, &certimining_checkpoint::ID, EPOCH),
        Ok(Fetched::Absent),
        "before Anchor-A acts, the checkpoint is absent"
    );

    assert!(
        !log.publish_at(EPOCH, EPOCH, root, false),
        "a signed transaction dropped before delivery cannot create a partial publication"
    );
    assert_eq!(
        root_for_epoch(&log.runtime, &certimining_checkpoint::ID, EPOCH),
        Ok(Fetched::Absent),
        "a failed transaction leaves no checkpoint account to mistake for progress"
    );

    assert!(
        log.publish(EPOCH, root),
        "a restarted worker can publish once"
    );
    let recovered = root_for_epoch(&log.runtime, &certimining_checkpoint::ID, EPOCH)
        .expect("read restarted publication");
    match recovered {
        Fetched::Placed(checkpoint) => {
            assert_eq!(checkpoint.root, root);
            assert_eq!(checkpoint.receipt_digest, [0; 32]);
            assert_eq!(checkpoint.anchor_kind, 0);
        }
        other => panic!("expected the restarted Anchor-A publication, found {other:?}"),
    }
}

#[test]
fn delayed_anchor_b_after_dropout_transitions_single_to_dual_without_changing_root() {
    let root = [0xb2; 32];
    let receipt = b"deterministic delayed anchor-b receipt";
    let digest = receipt_digest::<NativeKeccak>(receipt).expect("short receipt");
    let mut log = Log::new();
    assert!(log.publish(EPOCH, root));

    let before = root_for_epoch(&log.runtime, &certimining_checkpoint::ID, EPOCH)
        .expect("single-anchor checkpoint");
    assert_eq!(status_of(&before), AnchorStatus::Single);
    let before_root = match before {
        Fetched::Placed(checkpoint) => checkpoint.root,
        other => panic!("expected a placed checkpoint, found {other:?}"),
    };

    // Anchor-B is disconnected here: no attachment transaction is submitted. A later fresh cycle
    // attaches the verified digest to the already-published epoch.
    assert!(log.attach(EPOCH, digest));
    let recovered = root_for_epoch(&log.runtime, &certimining_checkpoint::ID, EPOCH)
        .expect("dual-anchor checkpoint");
    let checkpoint = match recovered {
        Fetched::Placed(checkpoint) => checkpoint,
        other => panic!("expected a placed checkpoint, found {other:?}"),
    };
    assert_eq!(
        checkpoint.root, before_root,
        "Anchor-B cannot rewrite Anchor-A"
    );
    assert_eq!(checkpoint.receipt_digest, digest);
    assert_eq!(checkpoint.anchor_kind, 1);
    assert!(
        !log.attach(EPOCH, [0xff; 32]),
        "the write-once barrier rejects a second, Byzantine receipt transition"
    );
    let after_rejected = root_for_epoch(&log.runtime, &certimining_checkpoint::ID, EPOCH)
        .expect("checkpoint after rejected transition");
    assert_eq!(status_of(&after_rejected), AnchorStatus::Dual);
    match after_rejected {
        Fetched::Placed(found) => {
            assert_eq!(found.root, root);
            assert_eq!(found.receipt_digest, digest);
        }
        other => panic!("expected an unchanged checkpoint, found {other:?}"),
    }
}

#[test]
fn delayed_and_byzantine_epoch_transitions_preserve_the_contiguous_barrier() {
    let mut log = Log::new();
    let first = [0xc3; 32];
    assert!(
        log.publish_at(EPOCH, EPOCH + 1, first, true),
        "a delayed but still contiguous checkpoint is recoverable"
    );
    assert!(
        !log.publish_at(EPOCH + 2, EPOCH + 2, [0xd4; 32], true),
        "a Byzantine worker cannot skip the epoch barrier"
    );
    assert_eq!(
        root_for_epoch(&log.runtime, &certimining_checkpoint::ID, EPOCH + 1),
        Ok(Fetched::Absent),
        "the rejected jump creates no partial intermediate account"
    );
    let original = root_for_epoch(&log.runtime, &certimining_checkpoint::ID, EPOCH)
        .expect("original checkpoint remains readable");
    match original {
        Fetched::Placed(checkpoint) => assert_eq!(checkpoint.root, first),
        other => panic!("expected the original checkpoint, found {other:?}"),
    }
}
