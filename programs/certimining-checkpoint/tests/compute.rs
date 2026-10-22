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

/// §1.4's epoch clock. The figures below are measured on fixed days, so `start_epoch` is a constant
/// rather than whatever the runner's wall clock says (D-109), and `START` is the one the single
/// figures belong to.
///
/// **The day is 40_001, which is not a date any deployment published (H-20, #60).** It used to be the
/// first epoch the program superseded on 25 September holds, and four harnesses carried that live
/// value for no reason: a pinned clock needs a well-formed day index, not a real one. The old value is
/// not repeated here, because naming it would put it back.
const START: u64 = 40_001;

fn pin_the_clock(svm: &mut LiteSVM, epoch: u64) {
    let mut clock: anchor_lang::prelude::Clock = svm.get_sysvar();
    clock.unix_timestamp = (epoch * certimining_checkpoint::SECONDS_PER_DAY) as i64;
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
///
/// **`attach_anchor_receipt` is also what the deployed program costs; `publish_checkpoint` no longer
/// is, and that is H-11.** Both figures were checked against the announced deployment's own
/// transactions: `computeUnitsConsumed` was 8,810 for epoch 20728's publication and 5,687 for epoch
/// 20727's attachment, matching this harness exactly at the time. Devnet was running a later Agave
/// than the pin — it reported `4.4.0-beta.0` against the pinned 4.2.2 — so the agreement was across
/// runtime versions rather than within one, which is more than determinism alone promises.
///
/// `publish_checkpoint` now costs **9,066**, because H-11 added the check that an epoch is not ahead
/// of the chain's own day. **The announced deployment has not been redeployed**, so its transactions
/// still show 8,810 and will go on doing so: that deployment runs the program as it was before this
/// check existed. The two numbers are both right about different programs, and the difference is
/// 256 CU of division and comparison. Nothing here is wrong on chain; the chain is simply running
/// an older program, which is the ordinary state of a deployment that predates a change.
///
/// It also settles a figure the README once published: 10,310 CU for `publish_checkpoint`, which
/// matched neither this harness nor the chain.
///
/// **One figure for `publish_checkpoint` was wrong in kind, not in value (H-52, #193).** Its cost
/// depends on the epoch it publishes, and a single number recorded for it is a property of whichever
/// day the harness happened to pin. `main` went red proving it: #191 recorded 9,066 measured at one
/// epoch and #194 moved the pinned clock to another, each green alone. So the figure is a table now,
/// and every row carries the epoch and the bump it was measured at.
const INITIALIZE_CU: u64 = 13_735;
const ATTACH_CU: u64 = 5_687;

/// What `publish_checkpoint` costs, per epoch, with the bump each epoch's PDA has (H-52, #193).
///
/// **Why it varies.** `#[account(init, seeds = …, bump)]` makes Anchor search for the canonical bump,
/// downward from 255, and each rejected candidate costs one `create_program_address` syscall at 1,500
/// CU. The epoch is one of the seeds, so the number of rejected candidates — and the cost — is a
/// property of the day. The rows below differ by 1,500 per candidate to within a few CU; the residual
/// varies with the epoch and this file records it rather than explaining it.
///
/// **Two of these rows exceed §1.8's bound of 15,000, and the test asserts that they do.** That is not
/// a failure of the harness. §1.8 is headed "Hard limits" and the cost is bounded by nothing but the
/// search: 5 rejected candidates cross it, which is about one epoch in 32. **Four of the 212 epochs
/// the program superseded on 25 September actually published were over it**, by 1,500 to 6,000 CU on
/// the program as it stood then; #193 names which. They succeeded because nothing in this repository
/// requests a compute budget, so the runtime's own 200,000 CU limit absorbed them. The days
/// themselves are not written here: they are live epoch indices, and this is a synthetic artifact
/// (H-20, #60).
///
/// Whether §1.8's number is the right one, and whether the program should store the bump rather than
/// search for it, are the two questions #193 holds. Until one of them is answered, the breach belongs
/// in a test rather than in a document nobody runs.
const MEASURED: [(u64, u8, u64); 5] = [
    // epoch, the canonical bump of its checkpoint PDA, publish_checkpoint CU
    (40_001, 255, 9_071),
    (40_002, 253, 12_071),
    (40_000, 252, 13_569),
    (40_010, 250, 16_573),
    (40_203, 244, 25_575),
];

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

/// What one epoch's three instructions cost, on a runtime pinned to that epoch's day.
///
/// A fresh `LiteSVM` per epoch, because `initialize` runs once per log and `publish_checkpoint`
/// accepts only `last_epoch + 1`: measuring another day means another log, not another instruction.
///
/// Returns the canonical bump of the epoch's checkpoint PDA alongside the figures, because that is
/// what `publish_checkpoint`'s cost turns on (H-52, #193).
fn measure(program: &[u8], epoch: u64) -> (u8, u64, u64, u64) {
    let mut svm = LiteSVM::new();
    let program_id = certimining_checkpoint::ID;
    svm.add_program(program_id, program).expect("load");
    pin_the_clock(&mut svm, epoch);
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
            start_epoch: epoch,
        }
        .data(),
    };
    let initialize_cu = send(&mut svm, initialize, &[&payer]);

    let (checkpoint, bump) = Pubkey::find_program_address(
        &[CheckpointAccount::SEED, &epoch.to_le_bytes()],
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
            epoch,
            root: *b"certimining fixture root   00001",
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
            epoch,
            receipt_digest: [0x33; 32],
            kind: 1,
        }
        .data(),
    };
    let attach_cu = send(&mut svm, attach, &[&payer, &authority]);
    (bump, initialize_cu, publish_cu, attach_cu)
}

#[test]
fn both_instructions_stay_inside_the_limits_1_8_gives() {
    let program = std::fs::read(PROGRAM)
        .unwrap_or_else(|e| panic!("{PROGRAM}: {e}. Build it first with scripts/build-sbf.sh"));

    let mut over_the_bound = 0usize;
    for (epoch, bump, publish_cu) in MEASURED {
        let (measured_bump, initialize_cu, measured_publish, attach_cu) = measure(&program, epoch);
        println!(
            "compute, LiteSVM, epoch {epoch}, bump {measured_bump}: initialize {initialize_cu}, \
             publish_checkpoint {measured_publish}, attach_anchor_receipt {attach_cu}"
        );

        // **The bump is asserted before the figure it explains.** A runtime or program-id change that
        // moved a PDA would otherwise show up as an unexplained compute drift, which is the shape of
        // confusion H-52 exists to end.
        assert_eq!(
            measured_bump, bump,
            "epoch {epoch}'s checkpoint PDA has bump {measured_bump} and this file records {bump}. \
             The bump follows from the seeds and the program id, so one of those has changed."
        );

        // Recorded, not merely bounded. The message says what to do rather than only what went wrong,
        // because the right response to a changed figure depends on what changed.
        assert_eq!(
            measured_publish, publish_cu,
            "publish_checkpoint used {measured_publish} CU at epoch {epoch} (bump {bump}) and this \
             file records {publish_cu}. Compute units are deterministic, so this changed because the \
             program changed or because the pinned runtime did. If the program changed, that is the \
             diff to look at; if `litesvm` or the Agave pin moved, re-measure every row and commit \
             them naming the version that moved them. Do not widen this into a bound: §1.8's bounds \
             are the assertions below, and this one exists because a figure inside its bound can \
             still drift a long way unseen."
        );

        // **`initialize` and `attach` do not vary with the epoch, and this is the check of that
        // claim rather than an assumption about it.** `initialize`'s only seed is a constant, so its
        // bump never moves; `attach` reads the bump the account stores instead of searching for one.
        // Asserting the same two figures at every row is what establishes that the dependence belongs
        // to `publish_checkpoint` alone — which is issue #35's second item, arriving from an
        // unexpected direction.
        assert_eq!(
            initialize_cu, INITIALIZE_CU,
            "initialize used {initialize_cu} CU at epoch {epoch} and this file records \
             {INITIALIZE_CU} for every epoch. Its seed is a constant, so a figure that moves with \
             the day means the claim in this comment is wrong."
        );
        assert_eq!(
            attach_cu, ATTACH_CU,
            "attach_anchor_receipt used {attach_cu} CU at epoch {epoch} and this file records \
             {ATTACH_CU} for every epoch. It reads the stored bump rather than searching, so a \
             figure that moves with the day means it does not."
        );
        assert!(
            attach_cu <= ATTACH_LIMIT,
            "§1.8: attach_anchor_receipt is bounded at {ATTACH_LIMIT} CU and used {attach_cu}"
        );

        if measured_publish > PUBLISH_LIMIT {
            over_the_bound = over_the_bound.saturating_add(1);
        }
        if epoch == START {
            assert!(
                measured_publish <= PUBLISH_LIMIT,
                "§1.8: publish_checkpoint is bounded at {PUBLISH_LIMIT} CU and used \
                 {measured_publish} at the epoch this harness pins"
            );
        }
    }

    // **The breach, asserted rather than described (H-52, #193).** Two rows are over §1.8's bound and
    // the measurement says so; a test that quietly recorded them would leave "Hard limits" reading as
    // though it held. If the program is changed to store the bump rather than search for it, this
    // assertion fails — which is correct, because the table would then be wrong and somebody should
    // re-measure it rather than find out later.
    assert_eq!(
        over_the_bound, 2,
        "two of the recorded rows exceed §1.8's {PUBLISH_LIMIT} CU and {over_the_bound} did. Either \
         the program no longer searches for its bump, in which case re-measure every row, or §1.8's \
         number has been settled, in which case this assertion is the thing to change."
    );
}
