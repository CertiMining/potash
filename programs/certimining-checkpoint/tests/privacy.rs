// SPDX-License-Identifier: MIT OR Apache-2.0
//! **§4.4's on-chain privacy tests. V-Z-01 and V-Z-06 are release blockers.**
//!
//! Under LiteSVM, which is deterministic (D-85, D-87): the closed list of bytes §4.4 permits to differ
//! can only be checked where the same inputs give the same bytes every time. The other half of
//! V-Z-01 — whether landing delay tracks epoch content on a real network — cannot be shown here and
//! runs on devnet over 200 epochs against a bound below 0.2, fixed before publication and recorded on
//! issue #9.
//!
//! What this file compares is what an observer sees: the instruction, the transaction, and the account
//! the program wrote, across epochs holding 0, 1, 128 and 255 records, published in more than one
//! order, with build time varied deliberately.

use anchor_lang::{AnchorDeserialize, InstructionData, ToAccountMetas};
use certimining_checkpoint::{CheckpointAccount, LogConfig};
use certimining_core::{Digest, NativeKeccak, SubmissionId};
use certimining_log::{BuiltEpoch, EpochTree};
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

/// §4.4's closed list, in the checkpoint account: the offsets a byte may differ at between two
/// epochs. Anything else that differs is a failure, and adding an offset here without amending §4.4
/// is the edit the specification forbids.
///
/// `epoch` 10..18, `published_slot` 50..58, `published_unix` 58..66, `root` 18..50, `bump` 99, and
/// `receipt_digest` 66..98 once one is attached.
const DEPLOYED_HEIGHT: u8 = 8;

/// §1.4's epoch clock. Every test below runs on one fixed day, so `start_epoch` is a constant rather
/// than whatever the runner's wall clock says (D-109).
const START: u64 = 20_721;

fn pin_the_clock(svm: &mut LiteSVM) {
    let mut clock: anchor_lang::prelude::Clock = svm.get_sysvar();
    clock.unix_timestamp = (START * certimining_checkpoint::SECONDS_PER_DAY) as i64;
    svm.set_sysvar(&clock);
}

fn permitted_account_offsets() -> Vec<usize> {
    let mut offsets: Vec<usize> = Vec::new();
    offsets.extend(10..18); // epoch
    offsets.extend(18..50); // root, a pseudorandom digest
    offsets.extend(50..58); // published_slot, the publication schedule
    offsets.extend(58..66); // published_unix, the publication schedule
    offsets.extend(66..98); // receipt_digest, pseudorandom once attached
    offsets.push(99); // bump, derived from the epoch through the PDA seeds
    offsets
}

struct Published {
    instruction_data: Vec<u8>,
    /// The serialized transaction, in full. Codex round one, finding 4: this used to be its length
    /// alone, which let any fixed-width byte outside the account carry a record count past a test
    /// whose own name said "byte-exact".
    transaction: Vec<u8>,
    /// The bytes of the transaction §4.4's closed list permits to differ, located in this
    /// transaction rather than assumed at fixed offsets.
    permitted: Vec<std::ops::Range<usize>>,
    account: Vec<u8>,
}

/// Publishes `count` epochs' worth of records into one epoch and returns what an observer sees.
///
/// The record count reaches the chain only through the root, which is a digest of the tree the
/// batcher sealed. Everything else an observer can see is produced here.
fn publish_epoch(
    svm: &mut LiteSVM,
    authority: &Keypair,
    payer: &Keypair,
    epoch: u64,
    root: [u8; 32],
) -> Published {
    let program_id = certimining_checkpoint::ID;
    let (config, _) = Pubkey::find_program_address(&[LogConfig::SEED], &program_id);
    let (checkpoint, _) = Pubkey::find_program_address(
        &[CheckpointAccount::SEED, &epoch.to_le_bytes()],
        &program_id,
    );
    let data = certimining_checkpoint::instruction::PublishCheckpoint { epoch, root }.data();
    let metas = certimining_checkpoint::accounts::Publish {
        config: anchor_lang::prelude::Pubkey::from(config.to_bytes()),
        checkpoint: anchor_lang::prelude::Pubkey::from(checkpoint.to_bytes()),
        authority: anchor_lang::prelude::Pubkey::from(authority.pubkey().to_bytes()),
        payer: anchor_lang::prelude::Pubkey::from(payer.pubkey().to_bytes()),
        system_program: anchor_lang::system_program::ID,
    }
    .to_account_metas(None)
    .into_iter()
    .map(|m| solana_instruction::AccountMeta {
        pubkey: Pubkey::from(m.pubkey.to_bytes()),
        is_signer: m.is_signer,
        is_writable: m.is_writable,
    })
    .collect();
    let ix = Instruction {
        program_id,
        accounts: metas,
        data: data.clone(),
    };
    let blockhash = svm.latest_blockhash();
    let message = Message::new(&[ix], Some(&payer.pubkey()));
    let tx = Transaction::new(&[payer, authority], message, blockhash);
    let serialized = bincode_serialize(&tx);
    let permitted = permitted_transaction_ranges(
        &serialized,
        tx.signatures.len(),
        &checkpoint.to_bytes(),
        blockhash.as_ref(),
        &data,
    );
    svm.send_transaction(tx).expect("publishes");
    let account = svm.get_account(&checkpoint).expect("the checkpoint").data;
    Published {
        instruction_data: data,
        transaction: serialized,
        permitted,
        account,
    }
}

/// §4.4's closed list, for the transaction, located in the bytes rather than assumed.
///
/// The list names the checkpoint address, the recent blockhash, the signature, and the `epoch` and
/// `root` arguments. Each is found by its own value, so a layout change moves the permitted window
/// with it instead of silently exposing a byte the list does not cover. Everything outside these
/// ranges must be identical across record counts, which is what "byte-exact" has to mean.
fn permitted_transaction_ranges(
    serialized: &[u8],
    signatures: usize,
    checkpoint: &[u8; 32],
    blockhash: &[u8],
    instruction_data: &[u8],
) -> Vec<std::ops::Range<usize>> {
    let mut ranges = Vec::new();
    // The signatures sit immediately after their one-byte count, and every message difference
    // changes them.
    ranges.push(1..1 + 64 * signatures);
    ranges.push(find(serialized, checkpoint, "the checkpoint address"));
    ranges.push(find(serialized, blockhash, "the recent blockhash"));
    // Inside the instruction data, the eight discriminator bytes are not permitted to differ; the
    // arguments after them are `epoch` and `root`.
    assert_eq!(
        instruction_data.len(),
        48,
        "§1.8: 8 discriminator, 8 epoch, 32 root, and nothing else"
    );
    let data = find(serialized, instruction_data, "the instruction data");
    ranges.push(data.start + 8..data.start + 48);
    ranges
}

fn find(haystack: &[u8], needle: &[u8], what: &str) -> std::ops::Range<usize> {
    let at = haystack
        .windows(needle.len())
        .position(|w| w == needle)
        .unwrap_or_else(|| panic!("{what} is not in the serialized transaction"));
    at..at + needle.len()
}

fn bincode_serialize(tx: &Transaction) -> Vec<u8> {
    // The wire form is the message plus its signatures; length is all this test needs and it is
    // computed the same way for every epoch.
    let mut out = Vec::new();
    out.push(tx.signatures.len() as u8);
    for sig in &tx.signatures {
        out.extend_from_slice(sig.as_ref());
    }
    out.extend_from_slice(&tx.message.serialize());
    out
}

fn fresh_log(height: u8) -> (LiteSVM, Keypair, Keypair) {
    let program = std::fs::read(PROGRAM)
        .unwrap_or_else(|e| panic!("{PROGRAM}: {e}. Build it first with scripts/build-sbf.sh"));
    let mut svm = LiteSVM::new();
    svm.add_program(certimining_checkpoint::ID, &program)
        .expect("load the program");
    pin_the_clock(&mut svm);
    let payer = Keypair::new();
    let authority = Keypair::new();
    svm.airdrop(&payer.pubkey(), 100_000_000_000).expect("fund");
    let program_id = certimining_checkpoint::ID;
    let (config, _) = Pubkey::find_program_address(&[LogConfig::SEED], &program_id);
    let metas = certimining_checkpoint::accounts::Initialize {
        config: anchor_lang::prelude::Pubkey::from(config.to_bytes()),
        payer: anchor_lang::prelude::Pubkey::from(payer.pubkey().to_bytes()),
        system_program: anchor_lang::system_program::ID,
    }
    .to_account_metas(None)
    .into_iter()
    .map(|m| solana_instruction::AccountMeta {
        pubkey: Pubkey::from(m.pubkey.to_bytes()),
        is_signer: m.is_signer,
        is_writable: m.is_writable,
    })
    .collect();
    let ix = Instruction {
        program_id,
        accounts: metas,
        data: certimining_checkpoint::instruction::Initialize {
            authority: anchor_lang::prelude::Pubkey::from(authority.pubkey().to_bytes()),
            tree_height: height,
            start_epoch: START,
        }
        .data(),
    };
    let message = Message::new(&[ix], Some(&payer.pubkey()));
    let tx = Transaction::new(&[&payer], message, svm.latest_blockhash());
    svm.send_transaction(tx).expect("initializes");
    (svm, authority, payer)
}

/// The root of a **real** epoch holding `records` real leaves, built by the engine at `H = 8`.
///
/// Codex round one, finding 4. This was a deterministic PRNG over the record count, which made the
/// comparison below a test of the program and not of a publisher: a pseudorandom 32-byte value
/// differs everywhere for any two counts by construction, so it could not have leaked a count even
/// if a real root did. It also meant V-P-07's "a zero-record epoch publishes a valid root" was never
/// established here, because no zero-record tree was ever built. The engine is a dev-dependency of
/// this test and not of the program.
fn root_for(records: usize) -> [u8; 32] {
    let key: Digest = [0x5a; 32];
    let real: Vec<(SubmissionId, Digest)> = (0..records)
        .map(|i| {
            let mut id = [0u8; 16];
            id[..8].copy_from_slice(&(i as u64).to_le_bytes());
            let mut leaf = [0u8; 32];
            leaf[..8].copy_from_slice(&(i as u64 ^ 0xa5a5_a5a5_a5a5_a5a5).to_le_bytes());
            leaf[8] = 0x11;
            (id, leaf)
        })
        .collect();
    let built = <BuiltEpoch as EpochTree>::build::<NativeKeccak>(1, DEPLOYED_HEIGHT, &key, &real)
        .expect("the engine builds an epoch of this size");
    assert_eq!(
        built.leaves.len(),
        1usize << DEPLOYED_HEIGHT,
        "every epoch is full, whatever the record count (INV-TREE-02)"
    );
    built.root
}

#[test]
fn v_z_01_an_epochs_footprint_does_not_move_with_its_record_count() {
    let counts = [0usize, 1, 128, 255];
    let (mut svm, authority, payer) = fresh_log(8);

    let mut seen: Vec<(usize, Published)> = Vec::new();
    for (index, records) in counts.iter().enumerate() {
        let epoch = START + index as u64;
        seen.push((
            *records,
            publish_epoch(&mut svm, &authority, &payer, epoch, root_for(*records)),
        ));
    }

    // In a second order, on a second log, because an order-dependent footprint is still a footprint.
    let (mut svm2, authority2, payer2) = fresh_log(8);
    let reversed: Vec<usize> = counts.iter().rev().copied().collect();
    let mut seen_reversed: Vec<(usize, Published)> = Vec::new();
    for (index, records) in reversed.iter().enumerate() {
        let epoch = START + index as u64;
        seen_reversed.push((
            *records,
            publish_epoch(&mut svm2, &authority2, &payer2, epoch, root_for(*records)),
        ));
    }

    let permitted = permitted_account_offsets();
    for group in [&seen, &seen_reversed] {
        let first = &group[0].1;
        for (records, published) in group.iter() {
            assert_eq!(
                published.instruction_data.len(),
                first.instruction_data.len(),
                "§1.8: the instruction is 48 bytes whatever the record count, and {records} is not"
            );
            assert_eq!(
                published.transaction.len(),
                first.transaction.len(),
                "the transaction's length does not move with the record count ({records})"
            );
            // The byte-exact half, for the transaction as well as the account. Every byte that
            // differs must lie inside a window §4.4's list names.
            for (offset, (a, b)) in first
                .transaction
                .iter()
                .zip(published.transaction.iter())
                .enumerate()
            {
                if a != b {
                    assert!(
                        first.permitted.iter().any(|r| r.contains(&offset))
                            && published.permitted.iter().any(|r| r.contains(&offset)),
                        "V-Z-01: transaction byte {offset} differs between an epoch of {} records \
                         and one of {records}, and §4.4's list does not permit it",
                        group[0].0
                    );
                }
            }
            assert_eq!(
                published.account.len(),
                CheckpointAccount::LEN,
                "§2.4: 106 bytes, always"
            );

            // The closed list: every byte that differs must be one §4.4 permits.
            for (offset, (a, b)) in first
                .account
                .iter()
                .zip(published.account.iter())
                .enumerate()
            {
                if a != b {
                    assert!(
                        permitted.contains(&offset),
                        "V-Z-01: byte {offset} differs between an epoch of {} records and one of \
                         {records}, and §4.4's list does not permit it",
                        group[0].0
                    );
                }
            }
        }
    }

    // The instruction data differs only where the epoch and the root do, which are the arguments
    // §4.4 names.
    let a = &seen[0].1.instruction_data;
    let b = &seen[3].1.instruction_data;
    let differing: Vec<usize> = a
        .iter()
        .zip(b.iter())
        .enumerate()
        .filter(|(_, (x, y))| x != y)
        .map(|(i, _)| i)
        .collect();
    assert!(
        differing.iter().all(|i| *i >= 8),
        "only the epoch and root arguments may differ, never the discriminator: {differing:?}"
    );
}

#[test]
fn v_z_01_an_empty_epoch_is_published_like_any_other() {
    // V-P-07, and INV-ANCH-01's "including epochs with zero real submissions".
    let (mut svm, authority, payer) = fresh_log(8);
    let empty = publish_epoch(&mut svm, &authority, &payer, START, root_for(0));
    let full = publish_epoch(&mut svm, &authority, &payer, START + 1, root_for(255));
    assert_eq!(empty.account.len(), full.account.len());
    assert_eq!(empty.instruction_data.len(), full.instruction_data.len());
    assert_eq!(empty.transaction.len(), full.transaction.len());
    let decoded = CheckpointAccount::deserialize(&mut &empty.account[8..]).expect("decodes");
    assert_eq!(decoded.epoch, START);
    assert_ne!(
        decoded.root, [0u8; 32],
        "an empty epoch publishes a real root"
    );
}

#[test]
fn v_z_06_a_daily_filer_and_a_twice_yearly_filer_look_the_same() {
    // Two issuers, two filing rhythms, one chain. What an observer sees is a checkpoint per epoch
    // either way, because the cadence belongs to the schedule and not to the filers.
    let daily: Vec<usize> = (0..30).map(|d| 1 + d % 3).collect();
    let twice_yearly: Vec<usize> = (0..30)
        .map(|d| if d == 0 || d == 15 { 1 } else { 0 })
        .collect();

    let (mut busy_svm, busy_authority, busy_payer) = fresh_log(8);
    let (mut quiet_svm, quiet_authority, quiet_payer) = fresh_log(8);

    let mut busy: Vec<Published> = Vec::new();
    let mut quiet: Vec<Published> = Vec::new();
    for day in 0..30u64 {
        let epoch = START + day;
        busy.push(publish_epoch(
            &mut busy_svm,
            &busy_authority,
            &busy_payer,
            epoch,
            root_for(daily[day as usize]),
        ));
        quiet.push(publish_epoch(
            &mut quiet_svm,
            &quiet_authority,
            &quiet_payer,
            epoch,
            root_for(twice_yearly[day as usize]),
        ));
    }

    assert_eq!(
        busy.len(),
        quiet.len(),
        "one checkpoint per epoch, both ways"
    );
    let permitted = permitted_account_offsets();
    for (day, (b, q)) in busy.iter().zip(quiet.iter()).enumerate() {
        assert_eq!(
            b.instruction_data.len(),
            q.instruction_data.len(),
            "day {day}"
        );
        assert_eq!(b.transaction.len(), q.transaction.len(), "day {day}");
        assert_eq!(b.account.len(), q.account.len(), "day {day}");
        for (offset, (x, y)) in b.account.iter().zip(q.account.iter()).enumerate() {
            if x != y {
                assert!(
                    permitted.contains(&offset),
                    "V-Z-06: byte {offset} differs between a daily filer and a twice-yearly one on \
                     day {day}, and §4.4's list does not permit it"
                );
            }
        }
    }
}
