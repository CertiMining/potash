//! E-08: §4.3's program vectors, written before the program (D-65, and issue #8's own task).
//!
//! Under LiteSVM rather than a validator (D-87): deterministic, in-process, and byte-deterministic in
//! the way V-Z-01's closed-list comparison needs. Build the program first with `scripts/build-sbf.sh`.
//!
//! Every key here is generated fresh for the run. Nothing in this file is a real authority.

use anchor_lang::{AnchorDeserialize, Discriminator, InstructionData, ToAccountMetas};
use certimining_checkpoint::{CheckpointAccount, LogConfig};
use litesvm::LiteSVM;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;

const PROGRAM: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../target/deploy/certimining_checkpoint.so"
);

/// §2.1's codes as the chain reports them: Anchor's offset plus the specification's number.
const ANCHOR_OFFSET: u32 = 6000;
const MALFORMED_PAYLOAD: u32 = ANCHOR_OFFSET + 0x05;
const EPOCH_OUT_OF_ORDER: u32 = ANCHOR_OFFSET + 0x0D;
const CHECKPOINT_ALREADY_WRITTEN: u32 = ANCHOR_OFFSET + 0x0E;
const UNSUPPORTED_SCHEMA_VERSION: u32 = ANCHOR_OFFSET + 0x0F;
const RECEIPT_ALREADY_ATTACHED: u32 = ANCHOR_OFFSET + 0x15;

const DEPLOYED_HEIGHT: u8 = 8;

/// §1.4's epoch clock. Every test below runs on one fixed day, so `start_epoch` is a constant rather
/// than whatever the runner's wall clock says (D-109).
const START: u64 = 20_721;

fn pin_the_clock(svm: &mut LiteSVM) {
    let mut clock: anchor_lang::prelude::Clock = svm.get_sysvar();
    clock.unix_timestamp = (START * certimining_checkpoint::SECONDS_PER_DAY) as i64;
    svm.set_sysvar(&clock);
}

struct Log {
    svm: LiteSVM,
    program_id: Pubkey,
    payer: Keypair,
    authority: Keypair,
    config: Pubkey,
}

impl Log {
    /// A loaded program with a funded payer, and no log initialized yet.
    fn new() -> Self {
        let program = std::fs::read(PROGRAM)
            .unwrap_or_else(|e| panic!("{PROGRAM}: {e}. Build it first with scripts/build-sbf.sh"));
        let mut svm = LiteSVM::new();
        let program_id = certimining_checkpoint::ID;
        svm.add_program(program_id, &program)
            .expect("load the checkpoint program");
        pin_the_clock(&mut svm);
        let payer = Keypair::new();
        let authority = Keypair::new();
        svm.airdrop(&payer.pubkey(), 10_000_000_000)
            .expect("fund the test payer");
        let (config, _) = Pubkey::find_program_address(&[LogConfig::SEED], &program_id);
        Self {
            svm,
            program_id,
            payer,
            authority,
            config,
        }
    }

    fn checkpoint(&self, epoch: u64) -> Pubkey {
        Pubkey::find_program_address(
            &[CheckpointAccount::SEED, &epoch.to_le_bytes()],
            &self.program_id,
        )
        .0
    }

    fn send(&mut self, ix: Instruction, signers: &[&Keypair]) -> Result<(), u32> {
        let message = Message::new(&[ix], Some(&self.payer.pubkey()));
        let mut all: Vec<&Keypair> = vec![&self.payer];
        for s in signers {
            if s.pubkey() != self.payer.pubkey() {
                all.push(s);
            }
        }
        let tx = Transaction::new(&all, message, self.svm.latest_blockhash());
        match self.svm.send_transaction(tx) {
            Ok(_) => Ok(()),
            Err(failed) => Err(custom_code(&format!("{:?}", failed.err))),
        }
    }

    fn initialize(&mut self, height: u8) -> Result<(), u32> {
        self.initialize_with(height, START)
    }

    /// `initialize` with a chosen `start_epoch`, for the one condition that judges it (V-N-26).
    fn initialize_with(&mut self, height: u8, start_epoch: u64) -> Result<(), u32> {
        let ix = Instruction {
            program_id: self.program_id,
            accounts: certimining_checkpoint::accounts::Initialize {
                config: self.config,
                payer: self.payer.pubkey(),
                system_program: solana_pubkey::Pubkey::from(
                    anchor_lang::system_program::ID.to_bytes(),
                ),
            }
            .to_account_metas(None)
            .into_iter()
            .map(convert_meta)
            .collect(),
            data: certimining_checkpoint::instruction::Initialize {
                authority: anchor_lang::prelude::Pubkey::from(self.authority.pubkey().to_bytes()),
                tree_height: height,
                start_epoch,
            }
            .data(),
        };
        self.send(ix, &[])
    }

    fn publish(&mut self, epoch: u64, root: [u8; 32], signer: &Keypair) -> Result<(), u32> {
        let checkpoint = self.checkpoint(epoch);
        let ix = Instruction {
            program_id: self.program_id,
            accounts: certimining_checkpoint::accounts::Publish {
                config: self.config,
                checkpoint,
                authority: anchor_lang::prelude::Pubkey::from(signer.pubkey().to_bytes()),
                payer: anchor_lang::prelude::Pubkey::from(self.payer.pubkey().to_bytes()),
                system_program: anchor_lang::system_program::ID,
            }
            .to_account_metas(None)
            .into_iter()
            .map(convert_meta)
            .collect(),
            data: certimining_checkpoint::instruction::PublishCheckpoint { epoch, root }.data(),
        };
        self.send(ix, &[signer])
    }

    fn attach(&mut self, epoch: u64, digest: [u8; 32], kind: u8) -> Result<(), u32> {
        let checkpoint = self.checkpoint(epoch);
        let ix = Instruction {
            program_id: self.program_id,
            accounts: certimining_checkpoint::accounts::Attach {
                config: self.config,
                checkpoint,
                authority: anchor_lang::prelude::Pubkey::from(self.authority.pubkey().to_bytes()),
            }
            .to_account_metas(None)
            .into_iter()
            .map(convert_meta)
            .collect(),
            data: certimining_checkpoint::instruction::AttachAnchorReceipt {
                epoch,
                receipt_digest: digest,
                kind,
            }
            .data(),
        };
        let authority = self.authority.insecure_clone();
        self.send(ix, &[&authority])
    }

    fn config_account(&self) -> LogConfig {
        let raw = self.svm.get_account(&self.config).expect("the log exists");
        LogConfig::deserialize(&mut &raw.data[8..]).expect("a LogConfig")
    }

    fn checkpoint_account(&self, epoch: u64) -> CheckpointAccount {
        let raw = self
            .svm
            .get_account(&self.checkpoint(epoch))
            .expect("the checkpoint exists");
        CheckpointAccount::deserialize(&mut &raw.data[8..]).expect("a CheckpointAccount")
    }
}

/// Anchor's account metas carry its own `Pubkey`; LiteSVM's instruction carries the client one.
fn convert_meta(m: anchor_lang::prelude::AccountMeta) -> solana_instruction::AccountMeta {
    solana_instruction::AccountMeta {
        pubkey: Pubkey::from(m.pubkey.to_bytes()),
        is_signer: m.is_signer,
        is_writable: m.is_writable,
    }
}

/// The custom error number out of a failed transaction, or `u32::MAX` when it failed some other way,
/// which keeps a constraint violation distinguishable from a program error.
fn custom_code(rendered: &str) -> u32 {
    rendered
        .split("Custom(")
        .nth(1)
        .and_then(|rest| rest.split(')').next())
        .and_then(|n| n.trim().parse().ok())
        .unwrap_or(u32::MAX)
}

#[test]
fn a_log_initializes_once_and_writes_what_it_was_given() {
    let mut log = Log::new();
    log.initialize(DEPLOYED_HEIGHT).expect("initializes");
    let config = log.config_account();
    assert_eq!(config.tree_height, DEPLOYED_HEIGHT, "D-78: written once");
    assert_eq!(config.schema_version, 1);
    // D-109: the log begins at the day it was initialized, so the first publication is START and
    // `last_epoch` is the day before it.
    assert_eq!(config.start_epoch, START);
    assert_eq!(config.last_epoch, START - 1);
    assert_eq!(
        config.authority.to_bytes(),
        log.authority.pubkey().to_bytes()
    );

    assert!(
        log.initialize(DEPLOYED_HEIGHT).is_err(),
        "D-79: the PDA is its own guard against a second call"
    );
}

#[test]
fn v_n_22_a_height_outside_the_range_is_0x05() {
    for height in [0u8, 3, 17, 255] {
        let mut log = Log::new();
        assert_eq!(
            log.initialize(height),
            Err(MALFORMED_PAYLOAD),
            "§1.8: H is in [4, 16], and {height} is not"
        );
    }
    for height in [4u8, 8, 16] {
        let mut log = Log::new();
        assert!(log.initialize(height).is_ok(), "H = {height} is allowed");
    }
}

#[test]
fn v_n_10_an_epoch_that_is_not_the_next_one_is_0x0d() {
    let mut log = Log::new();
    log.initialize(DEPLOYED_HEIGHT).expect("initializes");
    assert_eq!(
        log.publish(START + 1, [0x11; 32], &log.authority.insecure_clone()),
        Err(EPOCH_OUT_OF_ORDER),
        "INV-ANCH-02: a gap is refused"
    );
    let authority = log.authority.insecure_clone();
    log.publish(START, [0x11; 32], &authority).expect("epoch 1");
    assert_eq!(
        log.publish(START + 2, [0x22; 32], &authority),
        Err(EPOCH_OUT_OF_ORDER),
        "and so is a jump"
    );
}

#[test]
fn v_n_11_a_second_checkpoint_for_one_epoch_is_0x0e() {
    let mut log = Log::new();
    log.initialize(DEPLOYED_HEIGHT).expect("initializes");
    let authority = log.authority.insecure_clone();
    log.publish(START, [0x11; 32], &authority).expect("epoch 1");
    assert_eq!(
        log.publish(START, [0x99; 32], &authority),
        Err(CHECKPOINT_ALREADY_WRITTEN),
        "D-80: existence is decided before monotonicity, so this is 0x0E and not 0x0D"
    );
    assert_eq!(
        log.checkpoint_account(START).root,
        [0x11; 32],
        "INV-ANCH-03: and the first root stands"
    );
}

#[test]
fn v_n_12_a_second_receipt_for_one_epoch_is_0x15() {
    let mut log = Log::new();
    log.initialize(DEPLOYED_HEIGHT).expect("initializes");
    let authority = log.authority.insecure_clone();
    log.publish(START, [0x11; 32], &authority).expect("epoch 1");
    log.attach(START, [0x33; 32], 1).expect("the first receipt");
    assert_eq!(
        log.attach(START, [0x44; 32], 1),
        Err(RECEIPT_ALREADY_ATTACHED),
        "INV-ANCH-03: zero to value, once"
    );
    assert_eq!(log.checkpoint_account(START).receipt_digest, [0x33; 32]);
}

#[test]
fn an_anchor_kind_the_specification_does_not_have_is_0x05() {
    let mut log = Log::new();
    log.initialize(DEPLOYED_HEIGHT).expect("initializes");
    let authority = log.authority.insecure_clone();
    log.publish(START, [0x11; 32], &authority).expect("epoch 1");
    for kind in [0u8, 2, 255] {
        assert_eq!(
            log.attach(START, [0x33; 32], kind),
            Err(MALFORMED_PAYLOAD),
            "D-81: one kind, and {kind} is not it"
        );
    }
    assert!(log.attach(START, [0x33; 32], 1).is_ok());
}

#[test]
fn v_n_19_a_signer_that_is_not_the_authority_is_refused() {
    let mut log = Log::new();
    log.initialize(DEPLOYED_HEIGHT).expect("initializes");
    let stranger = Keypair::new();
    log.svm
        .airdrop(&stranger.pubkey(), 1_000_000_000)
        .expect("fund");
    assert!(
        log.publish(START, [0x11; 32], &stranger).is_err(),
        "V-N-19: the has_one constraint refuses a signer that is not the authority"
    );
    let authority = log.authority.insecure_clone();
    assert!(
        log.publish(START, [0x11; 32], &authority).is_ok(),
        "and the authority is accepted"
    );
}

#[test]
fn v_n_13_a_config_written_under_another_schema_is_0x0f() {
    // The only way to reach this is to put an account there that this program did not write, which is
    // what a later schema would look like to this one.
    let mut log = Log::new();
    log.initialize(DEPLOYED_HEIGHT).expect("initializes");
    let mut raw = log.svm.get_account(&log.config).expect("the log exists");
    raw.data[8..10].copy_from_slice(&2u16.to_le_bytes());
    log.svm
        .set_account(log.config, raw)
        .expect("rewrite the config");
    let authority = log.authority.insecure_clone();
    assert_eq!(
        log.publish(START, [0x11; 32], &authority),
        Err(UNSUPPORTED_SCHEMA_VERSION),
        "V-N-13: schema 2 is not a schema this program writes"
    );
}

#[test]
fn the_account_layouts_are_the_ones_2_4_states() {
    assert_eq!(LogConfig::LEN, 68, "§2.4's LogConfig");
    assert_eq!(CheckpointAccount::LEN, 106, "§2.4's CheckpointAccount");
    assert_eq!(LogConfig::DISCRIMINATOR.len(), 8);
    assert_eq!(CheckpointAccount::DISCRIMINATOR.len(), 8);

    let mut log = Log::new();
    log.initialize(DEPLOYED_HEIGHT).expect("initializes");
    let authority = log.authority.insecure_clone();
    log.publish(START, [0x11; 32], &authority).expect("epoch 1");
    assert_eq!(
        log.svm.get_account(&log.config).expect("config").data.len(),
        LogConfig::LEN
    );
    assert_eq!(
        log.svm
            .get_account(&log.checkpoint(START))
            .expect("checkpoint")
            .data
            .len(),
        CheckpointAccount::LEN
    );
}

#[test]
fn a_published_checkpoint_carries_what_the_epoch_fixes_and_nothing_else() {
    let mut log = Log::new();
    log.initialize(DEPLOYED_HEIGHT).expect("initializes");
    let authority = log.authority.insecure_clone();
    log.publish(START + 6, [0x11; 32], &authority).err();
    log.publish(START, [0xab; 32], &authority)
        .expect("the log's first epoch");
    let checkpoint = log.checkpoint_account(START);
    assert_eq!(checkpoint.epoch, START);
    assert_eq!(checkpoint.root, [0xab; 32]);
    assert_eq!(checkpoint.schema_version, 1);
    assert_eq!(
        checkpoint.receipt_digest, [0u8; 32],
        "INV-ANCH-03: zero until a receipt is attached"
    );
    assert_eq!(checkpoint.anchor_kind, 0);
    assert_eq!(log.config_account().last_epoch, START);
}

/// Codex round one, finding 2. A checkpoint address is derived from a public seed, so anyone can
/// send lamports to the next one before the authority publishes it. Reading a lamport balance as
/// "already written" turned that into a permanent stop: the epoch was refused, `last_epoch` never
/// advanced, and every later epoch failed `0x0D` behind it (D-104).
#[test]
fn a_funded_checkpoint_address_does_not_stop_the_log() {
    let mut log = Log::new();
    log.initialize(DEPLOYED_HEIGHT).expect("initialize");

    // A stranger funds the address epoch 1 will use. `airdrop` places exactly the account a
    // system transfer would leave: owned by the system program, no data, non-zero lamports.
    let target = log.checkpoint(START);
    log.svm
        .airdrop(&target, 5_000_000)
        .expect("a stranger funds the next checkpoint address");
    assert!(
        log.svm
            .get_account(&target)
            .map(|a| a.lamports)
            .unwrap_or(0)
            > 0,
        "the address is funded before the authority ever touches it"
    );

    // The epoch publishes anyway, and the account holds what the epoch fixes.
    let authority = log.authority.insecure_clone();
    log.publish(START, [0x11; 32], &authority)
        .expect("a funded address is an empty slot, not a written checkpoint");
    let raw = log.svm.get_account(&target).expect("the checkpoint exists");
    assert_eq!(raw.data.len(), CheckpointAccount::LEN);
    let written = CheckpointAccount::deserialize(&mut &raw.data[8..]).expect("decodes");
    assert_eq!(written.root, [0x11; 32]);
    assert_eq!(written.epoch, START);

    // And the log keeps going, which is what the attack was trying to prevent.
    log.publish(START + 1, [0x22; 32], &authority)
        .expect("the next epoch still publishes");
}

/// Codex round one, finding 2, the other half. Once the program owns the account and it holds data,
/// a second publish is `0x0E` exactly as before: the narrower existence test did not weaken it.
#[test]
fn a_written_checkpoint_is_still_0x0e_on_a_second_publish() {
    let mut log = Log::new();
    log.initialize(DEPLOYED_HEIGHT).expect("initialize");
    let authority = log.authority.insecure_clone();
    log.publish(START, [0x11; 32], &authority).expect("first");
    assert_eq!(
        log.publish(START, [0x99; 32], &authority),
        Err(CHECKPOINT_ALREADY_WRITTEN),
        "D-80: existence is decided before monotonicity, so this is 0x0E"
    );
}

/// Codex round one, finding 6. A zero digest is the sentinel, not a value: attaching one left the
/// sentinel in place and let a second attachment through, which is the rule INV-ANCH-03 states
/// (D-105).
#[test]
fn an_all_zero_receipt_digest_is_refused_so_the_write_happens_once() {
    let mut log = Log::new();
    log.initialize(DEPLOYED_HEIGHT).expect("initialize");
    let authority = log.authority.insecure_clone();
    log.publish(START, [0x11; 32], &authority).expect("publish");

    assert_eq!(
        log.attach(START, [0u8; 32], 1),
        Err(MALFORMED_PAYLOAD),
        "a zero digest is not a receipt"
    );
    log.attach(START, [0x44; 32], 1)
        .expect("a real digest attaches");
    assert_eq!(
        log.attach(START, [0x55; 32], 1),
        Err(RECEIPT_ALREADY_ATTACHED),
        "zero to a value, exactly once"
    );
}

/// V-N-26. §1.4 makes an epoch a UTC day index and §2.4 holds `initialize` to the day index the
/// on-chain clock reports, so `start_epoch` is stated by the operator and decided by the chain
/// (D-109). E-11's independent implementation noticed that this condition had no test and no vector
/// while the `tree_height` condition beside it has V-N-22, which is how a refusal path ships untested.
#[test]
fn v_n_26_a_start_epoch_that_is_not_todays_day_index_is_0x05() {
    for wrong in [0u64, START - 1, START + 1, u64::MAX] {
        let mut log = Log::new();
        assert_eq!(
            log.initialize_with(DEPLOYED_HEIGHT, wrong),
            Err(MALFORMED_PAYLOAD),
            "start_epoch {wrong} is not the day the chain reports, and the operator does not choose it"
        );
    }
    // And the day the chain does report is accepted, so the refusal is about the value and not about
    // the argument existing.
    let mut log = Log::new();
    log.initialize_with(DEPLOYED_HEIGHT, START)
        .expect("today's day index is the one value this accepts");
}
