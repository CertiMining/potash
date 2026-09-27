// SPDX-License-Identifier: MIT OR Apache-2.0
//! The one thing that may touch the announced deployment: `initialize`, once (D-79).
//!
//! Every other cluster harness in this crate refuses the announced program id, and for good reason —
//! `devnet.rs` writes placeholder anchor data into a write-once field, and `correlation.rs` spends one
//! epoch number per minute against a numbering that is a UTC day index. Neither belongs near a log
//! anyone will read. But D-79 puts `initialize` in the deploy procedure, because whoever calls it
//! first owns the log, and something has to be able to call it.
//!
//! So this file exists to do that and nothing else. **It publishes no epoch and attaches no receipt.**
//! It is `#[ignore]`d, behind the `cluster` feature, and never part of CI.
//!
//! ```text
//! CERTIMINING_RPC=… cargo test -p certimining-client --features cluster \
//!     --test initialize -- --ignored --nocapture
//! ```
#![cfg(feature = "cluster")]

use anchor_lang::{AnchorDeserialize, InstructionData, ToAccountMetas};
use certimining_checkpoint::LogConfig;
use certimining_client::cluster::Cluster;
use certimining_client::config_address;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;

const TREE_HEIGHT: u8 = 8;

/// A key from the path S6 keeps it at, refused unless only its owner can read it.
///
/// D-88 makes the checkpoint authority the one key that runs unattended, which is why the mode is
/// checked here rather than assumed. E-10 lifts this into `refuse_a_readable_key` for the worker to
/// share; until that unit merges, the check lives where it is used.
fn key(name: &str) -> Keypair {
    let home = std::env::var("HOME").expect("HOME");
    let path = std::path::PathBuf::from(format!("{home}/.config/certimining/{name}"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path)
            .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode,
            0o600,
            "{}: mode {mode:o}, and these keys are read only at 0600 (S6, D-88)",
            path.display()
        );
    }
    let raw = std::fs::read_to_string(&path).expect("the key file");
    let bytes: Vec<u8> = raw
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .split(',')
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.trim().parse::<u8>().expect("a byte"))
        .collect();
    Keypair::try_from(&bytes[..]).expect("a 64-byte keypair")
}

/// §1.4's epoch clock. `initialize` refuses anything but the day index the chain reports, so this is
/// the value to offer it (D-109).
fn today_utc() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock after 1970")
        .as_secs()
        / 86_400
}

#[test]
#[ignore = "initializes a freshly deployed log, once (D-79)"]
fn initialize_the_announced_log() {
    let url = std::env::var("CERTIMINING_RPC").expect("CERTIMINING_RPC");
    let payer = key("deploy-keypair.json");
    let authority = key("checkpoint-authority.json");
    let cluster = Cluster::new(url.clone(), certimining_checkpoint::ID);
    let rpc = cluster.rpc();
    let program_id = Pubkey::from(certimining_checkpoint::ID.to_bytes());
    let config = Pubkey::from(config_address(&certimining_checkpoint::ID).to_bytes());

    println!("program:   {program_id}");
    println!("endpoint:  {url}");
    println!("authority: {}", authority.pubkey());

    let program = rpc
        .get_account(&program_id)
        .expect("the program is deployed; run scripts/deploy-devnet.sh first");
    assert!(program.executable, "the program account must be executable");

    // Once. A second call finds the PDA there, which is the PDA doing its job, and this refuses rather
    // than reporting success: an already-owned log is not something to be quiet about.
    assert!(
        rpc.get_account(&config).is_err(),
        "this log is already initialized. Whoever called first owns it (D-79); if that was not you, \
         the remedy is a redeploy to a new program id, not another call here."
    );

    let today = today_utc();
    let ix = solana_instruction::Instruction {
        program_id,
        accounts: certimining_checkpoint::accounts::Initialize {
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
        .collect(),
        data: certimining_checkpoint::instruction::Initialize {
            authority: anchor_lang::prelude::Pubkey::from(authority.pubkey().to_bytes()),
            tree_height: TREE_HEIGHT,
            start_epoch: today,
        }
        .data(),
    };
    let message = Message::new(&[ix], Some(&payer.pubkey()));
    let tx = Transaction::new(
        &[&payer],
        message,
        rpc.get_latest_blockhash().expect("blockhash"),
    );
    let signature = rpc
        .send_and_confirm_transaction(&tx)
        .expect("initialize lands");
    println!("initialize: {signature}");

    // Read back what the program wrote, rather than reporting what was sent.
    let raw = rpc.get_account(&config).expect("the log exists now");
    let decoded = LogConfig::deserialize(&mut &raw.data[8..]).expect("a LogConfig");
    assert_eq!(raw.data.len(), LogConfig::LEN, "§2.4's 68 bytes");
    assert_eq!(decoded.schema_version, 1);
    assert_eq!(decoded.tree_height, TREE_HEIGHT);
    assert_eq!(decoded.start_epoch, today, "§1.4: the log begins today");
    assert_eq!(
        decoded.last_epoch,
        today - 1,
        "so the first publication is today's epoch"
    );
    assert_eq!(
        decoded.authority.to_bytes(),
        authority.pubkey().to_bytes(),
        "the checkpoint authority is the separate key (D-88)"
    );
    println!(
        "LogConfig: start_epoch {}, last_epoch {}, tree_height {}",
        decoded.start_epoch, decoded.last_epoch, decoded.tree_height
    );
}
