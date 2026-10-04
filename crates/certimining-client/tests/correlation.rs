// SPDX-License-Identifier: MIT OR Apache-2.0
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

/// The announced deployment is named in one file and this harness may not touch it.
///
/// **Why a measurement harness is as dangerous here as one that writes placeholder data.** This
/// publishes one epoch per minute, and §1.4 makes an epoch a UTC day index, so 200 epochs spends 200
/// days of numbering in 200 minutes. The first compressed run went against the announced deployment
/// and left its sequence 209 days ahead of the calendar, which violates INV-ANCH-01's cadence on a
/// live log and cannot be undone: `publish_checkpoint` is monotone and never goes back. The refusal
/// `devnet.rs` already carried is therefore this harness's too — every compressed run targets a
/// throwaway program id (owner's ruling, 27 Sep 2026).
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
        "this harness spends one epoch number per minute and must never target the announced \
         deployment. Deploy a throwaway program id and point declare_id! at it for this run."
    );
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

/// Pearson's r for V-Z-01, with the two roles kept apart (PR #69, M-01).
///
/// **This returned 0.0 whenever either series was constant, called "the honest answer".** It is not:
/// r is undefined when a variance is zero, and 0.0 is the *best* score against §4.4's bound, so an
/// unmeasurable run passed as a clean one. A review found it while checking the same defect in V-Z-04's
/// helper, and noted that the prose claiming V-Z-04 was the only instance was therefore wrong.
///
/// The two series are not symmetric here, which is why they are named rather than positional:
///
///   * A constant **feature** — record count, or build time — means the comparison was never run. The
///     run varies the record count deliberately, so a flat one is a defect in the harness, and a flat
///     build time means 200 publications all quantised to one millisecond and the build-time half of
///     V-Z-01 established nothing. Both refuse.
///   * A constant **observation** — the landing delay — is different. If every epoch landed in the same
///     time, delay did not follow record count or build time, which is the property V-Z-01 asserts.
///     That is a degenerate sample and a favourable one. It is reported as such and permitted, rather
///     than smuggled through as a correlation of zero.
fn pearson(feature: &[f64], feature_name: &str, delays: &[f64]) -> Option<f64> {
    let n = feature.len() as f64;
    let mf = feature.iter().sum::<f64>() / n;
    let md = delays.iter().sum::<f64>() / n;
    let mut num = 0.0;
    let mut df = 0.0;
    let mut dd = 0.0;
    for (x, y) in feature.iter().zip(delays.iter()) {
        num += (x - mf) * (y - md);
        df += (x - mf) * (x - mf);
        dd += (y - md) * (y - md);
    }
    assert!(
        df > 0.0,
        "V-Z-01: the {feature_name} series is constant over {} epochs, so this half of the test \
         compared nothing. The run varies the record count on purpose, and a flat build time means every \
         publication quantised to one value — either way the comparison did not happen.",
        feature.len()
    );
    if dd == 0.0 {
        // Reported, not scored. The caller prints this and treats it as the property holding, because a
        // delay that never varied cannot have followed anything.
        return None;
    }
    Some(num / (df.sqrt() * dd.sqrt()))
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

    refuse_the_announced_deployment(&program_id.to_string());

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

    let r_count = pearson(&counts, "record count", &delays);
    let r_build = pearson(&builds, "build time", &delays);
    println!("--- V-Z-01, landing-delay correlation ---");
    println!("epochs                     {EPOCHS}");
    println!("cadence                    one per {} s", CADENCE.as_secs());
    println!("endpoint                   {url}");
    // `None` means the landing delay never varied: unmeasurable as a correlation, and favourable as a
    // result, so it is printed as what it is rather than as a number.
    match r_count {
        Some(r) => println!("r(record count, delay)     {r:+.4}"),
        None => println!("r(record count, delay)     n/a — the landing delay was constant"),
    }
    match r_build {
        Some(r) => println!("r(build time, delay)       {r:+.4}"),
        None => println!("r(build time, delay)       n/a — the landing delay was constant"),
    }
    println!("bound                      |r| < {BOUND}");

    assert!(
        r_count.is_none_or(|r| r.abs() < BOUND),
        "V-Z-01: landing delay follows the record count, r = {:+.4}",
        r_count.unwrap_or(0.0)
    );
    assert!(
        r_build.is_none_or(|r| r.abs() < BOUND),
        "V-Z-01: landing delay follows the build time, r = {:+.4}",
        r_build.unwrap_or(0.0)
    );
}
