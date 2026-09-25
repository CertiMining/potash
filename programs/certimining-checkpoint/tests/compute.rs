//! §1.8's compute limits, and the LiteSVM column of D-86's comparison table.
//!
//! Issue #8 makes these acceptance criteria, so they are assertions rather than measurements: the
//! figures are printed for the table and the test fails if either instruction crosses its bound.

use anchor_lang::{InstructionData, ToAccountMetas};
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

/// §1.8's limits.
const PUBLISH_LIMIT: u64 = 15_000;

/// §1.4's epoch clock. Every test below runs on one fixed day, so `start_epoch` is a constant rather
/// than whatever the runner's wall clock says (D-109).
const START: u64 = 20_721;

fn pin_the_clock(svm: &mut LiteSVM) {
    let mut clock: anchor_lang::prelude::Clock = svm.get_sysvar();
    clock.unix_timestamp = (START * certimining_checkpoint::SECONDS_PER_DAY) as i64;
    svm.set_sysvar(&clock);
}

const ATTACH_LIMIT: u64 = 12_000;

fn metas(accounts: Vec<anchor_lang::prelude::AccountMeta>) -> Vec<solana_instruction::AccountMeta> {
    accounts
        .into_iter()
        .map(|m| solana_instruction::AccountMeta {
            pubkey: Pubkey::from(m.pubkey.to_bytes()),
            is_signer: m.is_signer,
            is_writable: m.is_writable,
        })
        .collect()
}

#[test]
fn both_instructions_stay_inside_the_limits_1_8_gives() {
    let program = std::fs::read(PROGRAM)
        .unwrap_or_else(|e| panic!("{PROGRAM}: {e}. Build it first with scripts/build-sbf.sh"));
    let mut svm = LiteSVM::new();
    let program_id = certimining_checkpoint::ID;
    svm.add_program(program_id, &program).expect("load");
    pin_the_clock(&mut svm);
    let payer = Keypair::new();
    let authority = Keypair::new();
    svm.airdrop(&payer.pubkey(), 100_000_000_000).expect("fund");

    let (config, _) = Pubkey::find_program_address(&[LogConfig::SEED], &program_id);
    let send = |svm: &mut LiteSVM, ix: Instruction, signers: &[&Keypair]| -> u64 {
        let message = Message::new(&[ix], Some(&payer.pubkey()));
        let tx = Transaction::new(signers, message, svm.latest_blockhash());
        svm.send_transaction(tx)
            .expect("the instruction succeeds")
            .compute_units_consumed
    };

    let initialize = Instruction {
        program_id,
        accounts: metas(
            certimining_checkpoint::accounts::Initialize {
                config: anchor_lang::prelude::Pubkey::from(config.to_bytes()),
                payer: anchor_lang::prelude::Pubkey::from(payer.pubkey().to_bytes()),
                system_program: anchor_lang::system_program::ID,
            }
            .to_account_metas(None),
        ),
        data: certimining_checkpoint::instruction::Initialize {
            authority: anchor_lang::prelude::Pubkey::from(authority.pubkey().to_bytes()),
            tree_height: 8,
            start_epoch: START,
        }
        .data(),
    };
    let initialize_cu = send(&mut svm, initialize, &[&payer]);

    let (checkpoint, _) = Pubkey::find_program_address(
        &[CheckpointAccount::SEED, &START.to_le_bytes()],
        &program_id,
    );
    let publish = Instruction {
        program_id,
        accounts: metas(
            certimining_checkpoint::accounts::Publish {
                config: anchor_lang::prelude::Pubkey::from(config.to_bytes()),
                checkpoint: anchor_lang::prelude::Pubkey::from(checkpoint.to_bytes()),
                authority: anchor_lang::prelude::Pubkey::from(authority.pubkey().to_bytes()),
                payer: anchor_lang::prelude::Pubkey::from(payer.pubkey().to_bytes()),
                system_program: anchor_lang::system_program::ID,
            }
            .to_account_metas(None),
        ),
        data: certimining_checkpoint::instruction::PublishCheckpoint {
            epoch: START,
            root: [0xab; 32],
        }
        .data(),
    };
    let publish_cu = send(&mut svm, publish, &[&payer, &authority]);

    let attach = Instruction {
        program_id,
        accounts: metas(
            certimining_checkpoint::accounts::Attach {
                config: anchor_lang::prelude::Pubkey::from(config.to_bytes()),
                checkpoint: anchor_lang::prelude::Pubkey::from(checkpoint.to_bytes()),
                authority: anchor_lang::prelude::Pubkey::from(authority.pubkey().to_bytes()),
            }
            .to_account_metas(None),
        ),
        data: certimining_checkpoint::instruction::AttachAnchorReceipt {
            epoch: START,
            receipt_digest: [0x33; 32],
            kind: 1,
        }
        .data(),
    };
    let attach_cu = send(&mut svm, attach, &[&payer, &authority]);

    println!("compute, LiteSVM: initialize {initialize_cu}, publish_checkpoint {publish_cu}, attach_anchor_receipt {attach_cu}");
    assert!(
        publish_cu <= PUBLISH_LIMIT,
        "§1.8: publish_checkpoint is bounded at {PUBLISH_LIMIT} CU and used {publish_cu}"
    );
    assert!(
        attach_cu <= ATTACH_LIMIT,
        "§1.8: attach_anchor_receipt is bounded at {ATTACH_LIMIT} CU and used {attach_cu}"
    );
}
