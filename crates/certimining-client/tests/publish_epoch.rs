// SPDX-License-Identifier: MIT OR Apache-2.0
//! One epoch published on the announced log, which is what a batcher does daily (§1.5).
//!
//! The other cluster harnesses refuse the announced program id, for reasons that are about *how* they
//! write: `devnet.rs` puts placeholder anchor data in a write-once field, and `correlation.rs` spends
//! an epoch number a minute. This one writes the way the log is meant to be written — one epoch, at
//! `last_epoch + 1`, with a root from a real epoch tree — so it is the harness that may touch it.
//!
//! **It carries issue #45's check client-side.** `publish_checkpoint` accepts `last_epoch + 1` without
//! asking what day it is, which is how a compressed run put an earlier deployment 209 days ahead of
//! the calendar and cost it (D-88). The program will refuse an epoch ahead of its own clock when #45
//! lands; until then this refuses to submit one, so the mistake cannot be repeated from here.
//!
//! ```text
//! CERTIMINING_RPC=… cargo test -p certimining-client --features cluster \
//!     --test publish_epoch -- --ignored --nocapture
//! ```
#![cfg(feature = "cluster")]

use anchor_lang::AnchorDeserialize;
use certimining_checkpoint::LogConfig;
use certimining_client::cluster::Cluster;
use certimining_client::{config_address, refuse_a_readable_key, AnchorStatus};
use certimining_core::{Digest, NativeKeccak, SubmissionId};
use certimining_log::{BuiltEpoch, EpochTree};
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;

const TREE_HEIGHT: u8 = 8;

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
            "{}: mode {mode:o}, not 0600 (S6, D-88)",
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

/// `k_master`, read from outside the repository (D-138).
///
/// **This was `[0x5a; 32]`, written in this file.** The announced log's epochs 20723 to 20730 were
/// built with it, and the same constant was the demo's, so the demo rebuilt real published roots
/// whenever its record count matched. INV-TREE-05 makes count-hiding rest on this value, and a value
/// in a public repository rests on nothing.
///
/// The bytes are never returned as text, never printed and never logged. The file holds exactly
/// thirty-two raw bytes at mode 0600, and anything else is refused rather than padded or truncated —
/// a short read here would silently weaken every epoch built after it.
fn master_key() -> Digest {
    let home = std::env::var("HOME").expect("HOME");
    let path = std::path::PathBuf::from(format!("{home}/.config/certimining/master-key.bin"));
    refuse_a_readable_key(&path).unwrap_or_else(|e| panic!("the master key's mode: {e}"));
    let bytes = std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "{}: {e}. The announced log's k_master lives outside the repository (D-138); generate \
             thirty-two random bytes into that path at mode 0600.",
            path.display()
        )
    });
    let key: Digest = bytes.as_slice().try_into().unwrap_or_else(|_| {
        panic!(
            "{}: {} bytes, and k_master is exactly 32 (INV-TREE-05)",
            path.display(),
            bytes.len()
        )
    });
    // The value this file used to carry. It is in this repository's history and cannot be unpublished,
    // so the only thing left to do with it is refuse it. Naming it here discloses nothing new and stops
    // the exposed key being restored by a copy-paste.
    assert_ne!(
        key, EXPOSED_MASTER_KEY,
        "the master key file holds the value this repository published; generate a new one (D-138)"
    );
    key
}

/// The master key that was committed in this file until D-138, kept only so `master_key` can refuse it.
const EXPOSED_MASTER_KEY: Digest = [0x5a; 32];

fn today_utc() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock after 1970")
        .as_secs()
        / 86_400
}

/// A real epoch at `H = 8`. The submissions are this harness's own, because the announced deployment
/// is a demonstration log and has no issuer feeding it; what matters is that the root is a tree's root
/// and not a placeholder, so anchor B timestamps something that means what it says.
fn build(epoch: u64, records: usize, master: &Digest) -> Digest {
    let real: Vec<(SubmissionId, Digest)> = (0..records)
        .map(|i| {
            let mut id = [0u8; 16];
            id[..8].copy_from_slice(&(i as u64).to_le_bytes());
            let mut leaf = [0u8; 32];
            leaf[..8].copy_from_slice(&(i as u64 ^ 0x3c3c_3c3c_3c3c_3c3c).to_le_bytes());
            leaf[8] = 0x77;
            (id, leaf)
        })
        .collect();
    <BuiltEpoch as EpochTree>::build::<NativeKeccak>(epoch, TREE_HEIGHT, master, &real)
        .expect("the engine builds an epoch")
        .root
}

#[test]
#[ignore = "publishes one epoch on the announced log"]
fn publish_the_next_epoch() {
    let url = std::env::var("CERTIMINING_RPC").expect("CERTIMINING_RPC");
    let payer = key("deploy-keypair.json");
    let authority = key("checkpoint-authority.json");
    let cluster = Cluster::new(url.clone(), certimining_checkpoint::ID);
    let rpc = cluster.rpc();
    let config = Pubkey::from(config_address(&certimining_checkpoint::ID).to_bytes());

    let raw = rpc.get_account(&config).expect("the log is initialized");
    let log = LogConfig::deserialize(&mut &raw.data[8..]).expect("a LogConfig");
    let epoch = log.last_epoch + 1;
    let today = today_utc();

    println!("program:     {}", certimining_checkpoint::ID);
    println!(
        "log:         start_epoch {}, last_epoch {}",
        log.start_epoch, log.last_epoch
    );
    println!("publishing:  epoch {epoch} (today is day {today})");

    // Issue #45's rule, enforced here until the program enforces it.
    assert!(
        epoch <= today,
        "epoch {epoch} is ahead of today's day index {today}. §1.4 makes an epoch a UTC day index, and \
         publishing ahead of the calendar is what cost an earlier deployment (D-88). The program does \
         not refuse this yet (issue #45); this does."
    );

    // The number of records is this log's own business and is not disclosed by the publication:
    // INV-ANCH-01 makes every epoch's footprint identical whatever it held.
    let root = build(epoch, 3, &master_key());
    println!(
        "root:        0x{}",
        root.iter().map(|b| format!("{b:02x}")).collect::<String>()
    );

    let anchored = cluster
        .publish(epoch, root, &payer, &authority, 3)
        .unwrap_or_else(|e| panic!("epoch {epoch}: {e:?}"));
    println!(
        "published:   slot {}, signature {}",
        anchored.published_slot, anchored.signature
    );

    assert_eq!(
        cluster.status(epoch).expect("the cluster answered"),
        AnchorStatus::Single,
        "INV-ANCH-05: a root on Solana and no receipt yet is single, and single is the truth until \
         Bitcoin carries one"
    );
    println!(
        "status:      Single — anchor B has not attached, which is INV-ANCH-04's budgeted wait"
    );
}
