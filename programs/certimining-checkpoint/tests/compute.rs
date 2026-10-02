// SPDX-License-Identifier: MIT OR Apache-2.0
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

/// **The measured figures, recorded (E-13, §4.4a).** §4.4a says "CU figures are recorded per commit in
/// CI; a regression past threshold fails the build". The bounds below did the second half; nothing did
/// the first, because the numbers only ever reached a log line that disappears with the run — which let
/// `publish_checkpoint` drift anywhere from 4,000 to 14,999 without anyone seeing it.
///
/// So they are asserted **exactly**, and a change to the program changes a committed line in the diff.
/// Compute units are deterministic — the same instruction against the same program costs the same CU on
/// any machine (D-132) — and three consecutive runs gave byte-identical figures, which is what makes
/// equality the right assertion rather than a tolerance.
///
/// A runtime bump may legitimately move these: `litesvm` is pinned at `=0.16.0` against Agave 4.2.2
/// (D-16, D-87), and if that pin moves these numbers are re-measured and re-committed **with the
/// version that moved them named in the commit**. That is the point. A silent change is the failure.
const INITIALIZE_CU: u64 = 13_735;
const PUBLISH_CU: u64 = 8_810;
const ATTACH_CU: u64 = 5_687;

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

    // Recorded, not merely bounded. The message says what to do rather than only what went wrong,
    // because the right response to a changed figure depends on what changed.
    for (name, measured, recorded) in [
        ("initialize", initialize_cu, INITIALIZE_CU),
        ("publish_checkpoint", publish_cu, PUBLISH_CU),
        ("attach_anchor_receipt", attach_cu, ATTACH_CU),
    ] {
        assert_eq!(
            measured, recorded,
            "{name} used {measured} CU and this file records {recorded}. Compute units are \
             deterministic, so this changed because the program changed or because the pinned runtime \
             did. If the program changed, that is the diff to look at; if `litesvm` or the Agave pin \
             moved, re-measure all three and commit them naming the version that moved them. Do not \
             widen this into a bound: §1.8's bounds are the two assertions below, and this one exists \
             because a figure inside its bound can still drift a long way unseen."
        );
    }
    assert!(
        publish_cu <= PUBLISH_LIMIT,
        "§1.8: publish_checkpoint is bounded at {PUBLISH_LIMIT} CU and used {publish_cu}"
    );
    assert!(
        attach_cu <= ATTACH_LIMIT,
        "§1.8: attach_anchor_receipt is bounded at {ATTACH_LIMIT} CU and used {attach_cu}"
    );
}
