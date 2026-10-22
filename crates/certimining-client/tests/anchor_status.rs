// SPDX-License-Identifier: MIT OR Apache-2.0
//! INV-ANCH-05's transitions, on the runtime rather than on a map (E-10, D-118).
//!
//! `tests/fetch.rs` checks `status_of` against a stand-in cluster, which settles the decision. This
//! file checks that the decision is fed the truth: the program is loaded into LiteSVM, an epoch is
//! published and a receipt attached, and the status is read back from the accounts the program
//! actually wrote.
//!
//! Issue #10 makes silent degradation a review failure, so the last test here is the one that gives
//! that sentence teeth: a client that reported `Dual` for an epoch with no receipt would pass every
//! other test in this repository.

use anchor_lang::{Discriminator, InstructionData, ToAccountMetas};
use certimining_checkpoint::{CheckpointAccount, LogConfig};
use certimining_client::{
    checkpoint_address, root_for_epoch, status_of, AnchorStatus, Fetched, RootSource, Unreachable,
};
use litesvm::LiteSVM;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_signer::Signer;
use solana_transaction::Transaction;

const PROGRAM_SO: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../target/deploy/certimining_checkpoint.so"
);
const HEIGHT: u8 = 8;
/// **The day is 40_001, which is not a date any deployment published (H-20, #60).** It used to be the
/// first epoch the program superseded on 25 September holds, and four harnesses carried that live
/// value for no reason: a pinned clock needs a well-formed day index, not a real one. The old value is
/// not repeated here, because naming it would put it back.
///
/// **Why 40_001 and not 40_000, said rather than left to look arbitrary.** `publish_checkpoint`'s
/// compute cost depends on the canonical bump of the epoch's checkpoint PDA — Anchor searches downward
/// from 255 and each rejected candidate costs a `create_program_address` syscall — so the epoch a
/// harness pins changes the figure. 40_000's bump is 252 and 40_001's is 255, which is what every
/// recorded figure in this repository was measured at. Measured and filed as H-52 (#193); a pinned
/// clock is not the place to change what the compute harness is measuring.
const START: u64 = 40_001;

/// The runtime, read through the same trait a cluster is read through.
struct Runtime {
    svm: LiteSVM,
}

impl RootSource for Runtime {
    fn account_at(
        &self,
        address: &anchor_lang::prelude::Pubkey,
    ) -> Result<certimining_client::Observation, Unreachable> {
        let key = solana_pubkey::Pubkey::from(address.to_bytes());
        // litesvm answers every read from one state, so every read here is one view by construction.
        let observation = certimining_client::Observation {
            slot: None,
            account: self.svm.get_account(&key).map(|a| {
                (
                    anchor_lang::prelude::Pubkey::from(a.owner.to_bytes()),
                    a.data,
                )
            }),
        };
        Ok(observation)
    }

    /// litesvm answers every read from one state, so a batch is one view by construction.
    fn accounts_at(
        &self,
        addresses: &[anchor_lang::prelude::Pubkey],
    ) -> Result<certimining_client::OneView, Unreachable> {
        Ok(certimining_client::OneView {
            slot: None,
            accounts: addresses
                .iter()
                .map(|address| {
                    let key = solana_pubkey::Pubkey::from(address.to_bytes());
                    self.svm.get_account(&key).map(|a| {
                        (
                            anchor_lang::prelude::Pubkey::from(a.owner.to_bytes()),
                            a.data,
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
        .map(|m| solana_instruction::AccountMeta {
            pubkey: solana_pubkey::Pubkey::from(m.pubkey.to_bytes()),
            is_signer: m.is_signer,
            is_writable: m.is_writable,
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
            .unwrap_or_else(|e| panic!("{PROGRAM_SO}: {e}. Build it with scripts/build-sbf.sh"));
        let mut svm = LiteSVM::new();
        svm.add_program(certimining_checkpoint::ID, &program)
            .expect("load");
        let mut clock: anchor_lang::prelude::Clock = svm.get_sysvar();
        clock.unix_timestamp = (START * certimining_checkpoint::SECONDS_PER_DAY) as i64;
        svm.set_sysvar(&clock);
        let payer = Keypair::new();
        let authority = Keypair::new();
        svm.airdrop(&payer.pubkey(), 100_000_000_000).expect("fund");
        let mut log = Self {
            runtime: Runtime { svm },
            payer,
            authority,
        };
        log.send(
            certimining_checkpoint::accounts::Initialize {
                config: certimining_client::config_address(&certimining_checkpoint::ID),
                payer: anchor_lang::prelude::Pubkey::from(log.payer.pubkey().to_bytes()),
                system_program: anchor_lang::system_program::ID,
            }
            .to_account_metas(None),
            certimining_checkpoint::instruction::Initialize {
                authority: anchor_lang::prelude::Pubkey::from(log.authority.pubkey().to_bytes()),
                tree_height: HEIGHT,
                start_epoch: START,
            }
            .data(),
            false,
        );
        log
    }

    fn send(
        &mut self,
        accounts: Vec<anchor_lang::prelude::AccountMeta>,
        data: Vec<u8>,
        sign_with_authority: bool,
    ) {
        let ix = Instruction {
            program_id: certimining_checkpoint::ID,
            accounts: metas(accounts),
            data,
        };
        let message = Message::new(&[ix], Some(&self.payer.pubkey()));
        let blockhash = self.runtime.svm.latest_blockhash();
        let tx = if sign_with_authority {
            Transaction::new(&[&self.payer, &self.authority], message, blockhash)
        } else {
            Transaction::new(&[&self.payer], message, blockhash)
        };
        self.runtime
            .svm
            .send_transaction(tx)
            .expect("the instruction succeeds");
    }

    fn publish(&mut self, epoch: u64, root: [u8; 32]) {
        // Every epoch publishes on its own day (H-11, V-N-27). `publish_checkpoint` refuses an epoch
        // ahead of the chain's own day index, and this harness published a run of them against one
        // clock — the compressed run the program accepted until that check existed.
        let mut clock: anchor_lang::prelude::Clock = self.runtime.svm.get_sysvar();
        clock.unix_timestamp = (epoch * certimining_checkpoint::SECONDS_PER_DAY) as i64;
        self.runtime.svm.set_sysvar(&clock);

        let authority = anchor_lang::prelude::Pubkey::from(self.authority.pubkey().to_bytes());
        let payer = anchor_lang::prelude::Pubkey::from(self.payer.pubkey().to_bytes());
        self.send(
            certimining_checkpoint::accounts::Publish {
                config: certimining_client::config_address(&certimining_checkpoint::ID),
                checkpoint: checkpoint_address(&certimining_checkpoint::ID, epoch),
                authority,
                payer,
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
            }
            .data(),
            true,
        );
    }

    fn attach(&mut self, epoch: u64, digest: [u8; 32]) {
        let authority = anchor_lang::prelude::Pubkey::from(self.authority.pubkey().to_bytes());
        self.send(
            certimining_checkpoint::accounts::Attach {
                config: certimining_client::config_address(&certimining_checkpoint::ID),
                checkpoint: checkpoint_address(&certimining_checkpoint::ID, epoch),
                authority,
            }
            .to_account_metas(None),
            certimining_checkpoint::instruction::AttachAnchorReceipt {
                epoch,
                receipt_digest: digest,
                kind: 1,
            }
            .data(),
            true,
        );
    }

    fn status(&self, epoch: u64) -> AnchorStatus {
        status_of(
            &root_for_epoch(&self.runtime, &certimining_checkpoint::ID, epoch)
                .expect("the runtime answered"),
        )
    }
}

#[test]
fn pending_then_single_then_dual() {
    let mut log = Log::new();
    assert_eq!(
        log.status(START),
        AnchorStatus::Pending,
        "nothing is published yet"
    );

    log.publish(START, *b"certimining fixture root   00001");
    assert_eq!(
        log.status(START),
        AnchorStatus::Single,
        "a root on Solana and no receipt is single, which is what INV-ANCH-04's latency looks like"
    );

    log.attach(START, [0x44; 32]);
    assert_eq!(
        log.status(START),
        AnchorStatus::Dual,
        "only an attached receipt digest makes it dual"
    );
}

#[test]
fn an_epoch_whose_worker_never_ran_stays_single_however_long_it_waits() {
    // The failure issue #10 calls silent degradation: an epoch that will never receive a receipt
    // must not drift to dual because time passed or because a worker believes it submitted one.
    let mut log = Log::new();
    log.publish(START, *b"certimining fixture root   00001");
    log.publish(START + 1, [0xcd; 32]);
    log.attach(START + 1, [0x44; 32]);

    assert_eq!(log.status(START), AnchorStatus::Single);
    assert_eq!(log.status(START + 1), AnchorStatus::Dual);
    assert_eq!(
        log.status(START),
        AnchorStatus::Single,
        "a neighbour's receipt is not this epoch's"
    );
}

#[test]
fn status_reads_the_account_and_not_the_workers_opinion() {
    // `status` takes no worker handle and cannot be told what to believe: it decodes the checkpoint
    // account. An epoch with a zero receipt digest is single whatever any other process thinks.
    let mut log = Log::new();
    log.publish(START, *b"certimining fixture root   00001");
    let fetched = root_for_epoch(&log.runtime, &certimining_checkpoint::ID, START)
        .expect("the runtime answered");
    match fetched {
        Fetched::Placed(checkpoint) => {
            assert_eq!(checkpoint.receipt_digest, [0u8; 32]);
            assert_eq!(checkpoint.anchor_kind, 0);
        }
        other => panic!("the epoch was published: {other:?}"),
    }
    assert_eq!(log.status(START), AnchorStatus::Single);

    // And the discriminator check is what keeps a foreign account from answering at all.
    assert_eq!(
        &log.runtime
            .account(&checkpoint_address(&certimining_checkpoint::ID, START))
            .expect("answered")
            .expect("present")
            .1[..8],
        CheckpointAccount::DISCRIMINATOR
    );
    let _ = LogConfig::LEN;
}
