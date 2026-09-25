//! D-86's devnet column: the same assertions the LiteSVM suite makes, against a real cluster.
//!
//! **Ignored by default and never part of CI.** It needs a deployed program, a funded key and a
//! network, and it exists to answer one question the pinned toolchain cannot: does Agave 4.3 on the
//! cluster behave as Agave 4.2.2 does locally. Any divergence stops the unit and goes to the owner as
//! a decision rather than a fix.
//!
//! ```text
//! cargo test -p certimining-client --features cluster -- --ignored --nocapture
//! ```
//!
//! The keys are read from outside this repository, where S6 keeps them. Nothing here prints a secret.
#![cfg(feature = "cluster")]

use anchor_lang::{AnchorDeserialize, Discriminator, InstructionData, ToAccountMetas};
use certimining_checkpoint::{CheckpointAccount, LogConfig};
use certimining_client::cluster::Cluster;
use certimining_client::{checkpoint_address, config_address, Fetched};
use solana_keypair::Keypair;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;

const URL: &str = "https://api.devnet.solana.com";
const TREE_HEIGHT: u8 = 8;

/// §1.4's epoch clock. `initialize` refuses anything but the day index the chain reports, so this is
/// the value to offer it (D-109).
fn today_utc() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock after 1970")
        .as_secs()
        / 86_400
}

/// A keypair from the path S6 keeps it at. The file is a JSON array of 64 bytes; only the public half
/// is ever printed.
fn key(name: &str) -> Keypair {
    let home = std::env::var("HOME").expect("HOME");
    let path = format!("{home}/.config/certimining/{name}");
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!("{path}: {e}. The deploy keys live outside the repository (S6)")
    });
    let bytes: Vec<u8> = serde_json_bytes(&raw);
    Keypair::try_from(&bytes[..]).expect("a 64-byte keypair")
}

/// The file is a plain JSON array of integers; parsing it here avoids a dependency for one line.
fn serde_json_bytes(raw: &str) -> Vec<u8> {
    raw.trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .split(',')
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.trim().parse::<u8>().expect("a byte"))
        .collect()
}

/// The announced deployment is named in exactly one file, and this harness may not touch it.
///
/// It publishes a placeholder root and attaches a receipt digest standing for no OpenTimestamps
/// receipt. `receipt_digest` is write-once, so running this against the announced program leaves an
/// epoch permanently claiming an anchor it does not have — which is what happened on 24 September
/// (Codex round one, finding 10). Deploy a throwaway program id for this comparison.
fn refuse_the_announced_deployment(program_id: &str) {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../ANNOUNCED_PROGRAM_ID");
    let announced = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("{path}: {e}"))
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with('#'))
        .expect("the file names one address")
        .to_string();
    assert_ne!(
        program_id, announced,
        "this harness writes placeholder anchor data and must never target the announced \
         deployment. Deploy a throwaway program id and point declare_id! at it for this run."
    );
}

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

fn anchor_key(k: &Pubkey) -> anchor_lang::prelude::Pubkey {
    anchor_lang::prelude::Pubkey::from(k.to_bytes())
}

#[test]
#[ignore = "needs devnet, a deployed program and a funded key (D-86)"]
fn the_devnet_column_matches_the_litesvm_column() {
    let payer = key("deploy-keypair.json");
    let authority = key("checkpoint-authority.json");
    let program_id = Pubkey::from(certimining_checkpoint::ID.to_bytes());
    refuse_the_announced_deployment(&program_id.to_string());
    let cluster = Cluster::new(URL.to_string(), certimining_checkpoint::ID);
    // Every send below confirms at the commitment `Cluster::new` set, which is `confirmed`:
    // the level a counterparty reads at, so the column records what a counterparty would see.
    let rpc = cluster.rpc();

    println!("program:   {program_id}");
    println!("payer:     {}", payer.pubkey());
    println!("authority: {}", authority.pubkey());

    let program_account = rpc
        .get_account(&program_id)
        .expect("the program is deployed; run scripts/deploy-devnet.sh first");
    assert!(
        program_account.executable,
        "the program account must be executable"
    );

    let config = Pubkey::from(config_address(&certimining_checkpoint::ID).to_bytes());

    // `initialize`, once. A second run finds the log already there, which is the PDA doing its job.
    let mut initialize_cu: Option<u64> = None;
    if rpc.get_account(&config).is_err() {
        let ix = solana_instruction::Instruction {
            program_id,
            accounts: metas(
                certimining_checkpoint::accounts::Initialize {
                    config: anchor_key(&config),
                    payer: anchor_key(&payer.pubkey()),
                    system_program: anchor_lang::system_program::ID,
                }
                .to_account_metas(None),
            ),
            data: certimining_checkpoint::instruction::Initialize {
                authority: anchor_key(&authority.pubkey()),
                tree_height: TREE_HEIGHT,
                start_epoch: today_utc(),
            }
            .data(),
        };
        let message = Message::new(&[ix], Some(&payer.pubkey()));
        let tx = Transaction::new(
            &[&payer],
            message,
            rpc.get_latest_blockhash().expect("hash"),
        );
        let simulated = rpc.simulate_transaction(&tx).expect("simulates");
        initialize_cu = simulated.value.units_consumed;
        let signature = rpc
            .send_and_confirm_transaction(&tx)
            .expect("initialize lands");
        println!("initialize: {signature}");
    } else {
        // Only the run that creates the log can measure it; a later run leaves the cell empty rather
        // than reporting a figure it did not take.
        println!("initialize: already done, the PDA holds the log");
    }

    // The config, as the program wrote it.
    let raw = rpc.get_account(&config).expect("the log exists");
    let decoded = LogConfig::deserialize(&mut &raw.data[8..]).expect("a LogConfig");
    let config_bytes = raw.data.len();
    println!("LogConfig bytes on chain: {config_bytes}");
    assert_eq!(config_bytes, LogConfig::LEN, "§2.4's 68 bytes");
    assert_eq!(decoded.tree_height, TREE_HEIGHT);
    assert_eq!(decoded.schema_version, 1);
    assert_eq!(
        decoded.authority.to_bytes(),
        authority.pubkey().to_bytes(),
        "the checkpoint authority is the separate key (D-88)"
    );

    // One epoch published for real, then measured.
    let epoch = decoded.last_epoch + 1;
    let checkpoint =
        Pubkey::from(checkpoint_address(&certimining_checkpoint::ID, epoch).to_bytes());
    let publish = solana_instruction::Instruction {
        program_id,
        accounts: metas(
            certimining_checkpoint::accounts::Publish {
                config: anchor_key(&config),
                checkpoint: anchor_key(&checkpoint),
                authority: anchor_key(&authority.pubkey()),
                payer: anchor_key(&payer.pubkey()),
                system_program: anchor_lang::system_program::ID,
            }
            .to_account_metas(None),
        ),
        data: certimining_checkpoint::instruction::PublishCheckpoint {
            epoch,
            root: [0xab; 32],
        }
        .data(),
    };
    let message = Message::new(std::slice::from_ref(&publish), Some(&payer.pubkey()));
    let tx = Transaction::new(
        &[&payer, &authority],
        message,
        rpc.get_latest_blockhash().expect("hash"),
    );
    let simulated = rpc.simulate_transaction(&tx).expect("simulates");
    let publish_cu = simulated.value.units_consumed.unwrap_or_default();
    let signature = rpc
        .send_and_confirm_transaction(&tx)
        .expect("publish lands");
    println!("publish_checkpoint: epoch {epoch}, {publish_cu} CU, {signature}");
    assert!(
        publish_cu <= 15_000,
        "§1.8: publish_checkpoint is bounded at 15,000 CU and devnet used {publish_cu}"
    );

    let raw = rpc.get_account(&checkpoint).expect("the checkpoint exists");
    let checkpoint_bytes = raw.data.len();
    println!("CheckpointAccount bytes on chain: {checkpoint_bytes}");
    assert_eq!(checkpoint_bytes, CheckpointAccount::LEN, "§2.4's 106 bytes");
    assert_eq!(
        &raw.data[..8],
        CheckpointAccount::DISCRIMINATOR,
        "the discriminator the client checks for"
    );

    // The client's own read path, against a real RPC rather than a map.
    let fetched = certimining_client::root_for_epoch(&cluster, &certimining_checkpoint::ID, epoch)
        .expect("the cluster answered");
    match fetched {
        Fetched::Placed(found) => {
            assert_eq!(found.root, [0xab; 32]);
            assert_eq!(found.epoch, epoch);
            println!("root_for_epoch: placed, slot {}", found.published_slot);
        }
        other => panic!("the client refused a root it published: {other:?}"),
    }

    // The error codes, by simulation, so nothing is spent proving a refusal.
    let duplicate = Transaction::new(
        &[&payer, &authority],
        Message::new(&[publish], Some(&payer.pubkey())),
        rpc.get_latest_blockhash().expect("hash"),
    );
    let refused = rpc.simulate_transaction(&duplicate).expect("simulates");
    println!("duplicate publish: {:?}", refused.value.err);
    let rendered = format!("{:?}", refused.value.err);
    assert!(
        rendered.contains(&format!("{}", 6000 + 0x0E)),
        "D-80: a republished epoch is 0x0E on devnet as it is under LiteSVM, and this said {rendered}"
    );

    // The receipt, for real, and its compute.
    let attach = solana_instruction::Instruction {
        program_id,
        accounts: metas(
            certimining_checkpoint::accounts::Attach {
                config: anchor_key(&config),
                checkpoint: anchor_key(&checkpoint),
                authority: anchor_key(&authority.pubkey()),
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
    let tx = Transaction::new(
        &[&payer, &authority],
        Message::new(&[attach], Some(&payer.pubkey())),
        rpc.get_latest_blockhash().expect("hash"),
    );
    let simulated = rpc.simulate_transaction(&tx).expect("simulates");
    let attach_cu = simulated.value.units_consumed.unwrap_or_default();
    let signature = rpc.send_and_confirm_transaction(&tx).expect("attach lands");
    println!("attach_anchor_receipt: {attach_cu} CU, {signature}");
    assert!(
        attach_cu <= 12_000,
        "§1.8: attach_anchor_receipt is bounded at 12,000 CU and devnet used {attach_cu}"
    );

    // Every figure below was read back from the cluster. Nothing here prints a constant: a column
    // that reported §2.4's numbers rather than devnet's would agree with LiteSVM by construction.
    println!("--- devnet column ---");
    match initialize_cu {
        Some(cu) => println!("initialize             {cu} CU"),
        None => println!("initialize             not measured: the log was already open"),
    }
    println!("publish_checkpoint     {publish_cu} CU");
    println!("attach_anchor_receipt  {attach_cu} CU");
    println!("LogConfig              {config_bytes} bytes");
    println!("CheckpointAccount      {checkpoint_bytes} bytes");
}
