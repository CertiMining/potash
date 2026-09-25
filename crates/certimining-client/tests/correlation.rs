//! §4.4's V-Z-01, the half that cannot run under LiteSVM: does an epoch's content move the slot its
//! checkpoint lands in (D-85, D-111)?
//!
//! The byte-exact half runs in CI against a deterministic runtime. This half needs a public network,
//! because what it measures is scheduling on one — and a deterministic runtime has none. It is
//! `#[ignore]`d and behind the `cluster` feature, so no CI run ever waits on it.
//!
//! **This harness publishes real roots from real trees and attaches no receipts.** It is therefore
//! safe against the announced deployment, unlike `devnet.rs`, which writes placeholder anchor data
//! into a write-once field and refuses to run there at all.
//!
//! ```text
//! CERTIMINING_RPC=https://… cargo test -p certimining-client --features cluster \
//!     --test correlation -- --ignored --nocapture
//! ```
#![cfg(feature = "cluster")]

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anchor_lang::{AnchorDeserialize, InstructionData, ToAccountMetas};
use certimining_checkpoint::LogConfig;
use certimining_client::cluster::Cluster;
use certimining_client::{config_address, AnchorStatus};
use certimining_core::{Digest, NativeKeccak, SubmissionId};
use certimining_log::{BuiltEpoch, EpochTree};
use solana_keypair::Keypair;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;

/// D-85 fixes these before any epoch is published, and they are not adjusted afterwards.
const EPOCHS: usize = 200;
const BOUND: f64 = 0.2;
/// The compressed cadence (owner's ruling, 25 Sep 2026). D-111 records why it is not a day.
const CADENCE: Duration = Duration::from_secs(60);
const TREE_HEIGHT: u8 = 8;

fn key(name: &str) -> Keypair {
    let home = std::env::var("HOME").expect("HOME");
    let path = format!("{home}/.config/certimining/{name}");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{path}: {e}. The keys live outside the repository (S6)"));
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

fn today_utc() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("a clock after 1970")
        .as_secs()
        / 86_400
}

/// A real epoch at `H = 8` holding `records` real leaves, and how long it took to build.
fn build(epoch: u64, records: usize) -> (Digest, Duration) {
    let key: Digest = [0x5a; 32];
    let real: Vec<(SubmissionId, Digest)> = (0..records)
        .map(|i| {
            let mut id = [0u8; 16];
            id[..8].copy_from_slice(&(i as u64).to_le_bytes());
            let mut leaf = [0u8; 32];
            leaf[..8].copy_from_slice(&(i as u64 ^ 0x5a5a_5a5a_5a5a_5a5a).to_le_bytes());
            leaf[8] = 0x22;
            (id, leaf)
        })
        .collect();
    let started = Instant::now();
    let built = <BuiltEpoch as EpochTree>::build::<NativeKeccak>(epoch, TREE_HEIGHT, &key, &real)
        .expect("the engine builds an epoch");
    (built.root, started.elapsed())
}

/// Retries a cluster read through a transient fault.
///
/// A 200-minute run on a public endpoint meets DNS failures, rate limits and dropped connections.
/// The first attempt at this gate died at epoch 13 of 200 on a name-resolution error, which measured
/// nothing and cost the run. A fault here is not evidence about the property under test, so it is
/// retried rather than recorded; a fault that outlasts the retries stops the run, because a gap in
/// the series would bias exactly what the series is measuring.
fn with_retry<T>(what: &str, mut attempt: impl FnMut() -> Result<T, String>) -> T {
    let mut waited = Duration::from_secs(1);
    for _ in 0..6 {
        match attempt() {
            Ok(value) => return value,
            Err(e) => {
                println!("  {what}: {e}; retrying in {} s", waited.as_secs());
                std::thread::sleep(waited);
                waited = (waited * 2).min(Duration::from_secs(30));
            }
        }
    }
    panic!("{what}: still failing after six attempts, so the run stops rather than skip an epoch");
}

/// Pearson's r. Returns 0.0 when a sample has no variance, which is the honest answer: a constant
/// carries no correlation with anything.
fn pearson(xs: &[f64], ys: &[f64]) -> f64 {
    let n = xs.len() as f64;
    let mx = xs.iter().sum::<f64>() / n;
    let my = ys.iter().sum::<f64>() / n;
    let mut num = 0.0;
    let mut dx = 0.0;
    let mut dy = 0.0;
    for (x, y) in xs.iter().zip(ys.iter()) {
        num += (x - mx) * (y - my);
        dx += (x - mx) * (x - mx);
        dy += (y - my) * (y - my);
    }
    if dx == 0.0 || dy == 0.0 {
        return 0.0;
    }
    num / (dx.sqrt() * dy.sqrt())
}

#[test]
#[ignore = "200 epochs at one a minute on a public network (D-85, D-111)"]
fn v_z_01_landing_delay_does_not_follow_epoch_content() {
    let url = std::env::var("CERTIMINING_RPC").expect(
        "CERTIMINING_RPC must name the endpoint this run uses, and it is recorded with the result",
    );
    let payer = key("deploy-keypair.json");
    let authority = key("checkpoint-authority.json");
    let cluster = Cluster::new(url.clone(), certimining_checkpoint::ID);
    let rpc = cluster.rpc();
    let program_id = Pubkey::from(certimining_checkpoint::ID.to_bytes());
    let config = Pubkey::from(config_address(&certimining_checkpoint::ID).to_bytes());

    println!("program:  {program_id}");
    println!("endpoint: {url}");
    println!(
        "cadence:  one epoch per {} seconds, {EPOCHS} epochs",
        CADENCE.as_secs()
    );

    // `initialize`, once, with the authority and height the deployment uses.
    if rpc.get_account(&config).is_err() {
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
        let ix = solana_instruction::Instruction {
            program_id,
            accounts: metas,
            data: certimining_checkpoint::instruction::Initialize {
                authority: anchor_lang::prelude::Pubkey::from(authority.pubkey().to_bytes()),
                tree_height: TREE_HEIGHT,
                start_epoch: today_utc(),
            }
            .data(),
        };
        let message = Message::new(&[ix], Some(&payer.pubkey()));
        let tx = Transaction::new(
            &[&payer],
            message,
            rpc.get_latest_blockhash().expect("blockhash"),
        );
        let sig = rpc.send_and_confirm_transaction(&tx).expect("initialize");
        println!("initialize: {sig}");
    }

    let raw = rpc.get_account(&config).expect("the log exists");
    let decoded = LogConfig::deserialize(&mut &raw.data[8..]).expect("a LogConfig");
    assert_eq!(decoded.tree_height, TREE_HEIGHT);
    assert_eq!(
        decoded.authority.to_bytes(),
        authority.pubkey().to_bytes(),
        "the checkpoint authority is the key this run intends (D-88)"
    );
    println!(
        "start_epoch {}, last_epoch {}",
        decoded.start_epoch, decoded.last_epoch
    );

    // The three series the bound is computed over.
    let mut counts: Vec<f64> = Vec::with_capacity(EPOCHS);
    let mut builds: Vec<f64> = Vec::with_capacity(EPOCHS);
    let mut delays: Vec<f64> = Vec::with_capacity(EPOCHS);

    let first_epoch = decoded.last_epoch + 1;
    for (i, next_epoch) in (first_epoch..).take(EPOCHS).enumerate() {
        let due = Instant::now() + CADENCE;

        // The record count moves over the whole range, and an empty epoch appears as often as a full
        // one: a count that never varies could not correlate with anything.
        let records = (i * 37 + 11) % 256;
        let (root, build_time) = build(next_epoch, records);

        // Publication is at a fixed time whatever the build took (INV-ANCH-01), so the delay measured
        // below is the network's and not the builder's.
        let before = with_retry("get_slot", || rpc.get_slot().map_err(|e| e.to_string()));
        let reference = Instant::now();
        let anchored = with_retry("publish", || {
            cluster
                .publish(next_epoch, root, &payer, &authority, 3)
                .map_err(|e| format!("{e:?}"))
        });
        let wall = reference.elapsed();
        let landed = anchored.published_slot.saturating_sub(before);

        counts.push(records as f64);
        builds.push(build_time.as_secs_f64() * 1_000.0);
        delays.push(landed as f64);
        println!(
            "epoch {next_epoch}: {records} records, build {:.2} ms, landed {} slots later, {:.2} s wall",
            build_time.as_secs_f64() * 1_000.0,
            landed,
            wall.as_secs_f64()
        );

        assert_eq!(
            with_retry("status", || cluster
                .status(next_epoch)
                .map_err(|e| format!("{e:?}"))),
            AnchorStatus::Single,
            "a root is anchored once and has no receipt: this harness attaches none"
        );

        if i + 1 < EPOCHS {
            let now = Instant::now();
            if due > now {
                std::thread::sleep(due - now);
            }
        }
    }

    let r_count = pearson(&counts, &delays);
    let r_build = pearson(&builds, &delays);
    println!("--- V-Z-01, landing-delay correlation ---");
    println!("epochs                     {EPOCHS}");
    println!("cadence                    one per {} s", CADENCE.as_secs());
    println!("endpoint                   {url}");
    println!("r(record count, delay)     {r_count:+.4}");
    println!("r(build time, delay)       {r_build:+.4}");
    println!("bound                      |r| < {BOUND}");

    assert!(
        r_count.abs() < BOUND,
        "V-Z-01: landing delay follows the record count, r = {r_count:+.4}"
    );
    assert!(
        r_build.abs() < BOUND,
        "V-Z-01: landing delay follows the build time, r = {r_build:+.4}"
    );
}
