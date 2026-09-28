// SPDX-License-Identifier: MIT OR Apache-2.0
//! E-10's devnet half: a real epoch root, a real OpenTimestamps receipt, a real attachment.
//!
//! **Two stages, hours apart, and that is the design rather than a limitation.** D-112 spends the
//! one write-once opportunity on the receipt that carries a Bitcoin attestation, so stage one submits
//! and stage two attaches once a block confirms. INV-ANCH-04 declares that latency to be inside the
//! operational envelope; here it is, arriving as described.
//!
//! Both stages are `#[ignore]`d and need `--features cluster,ots`, a funded payer and the checkpoint
//! authority. Neither runs in CI.
//!
//! ```text
//! CERTIMINING_RPC=… CERTIMINING_EPOCH=20932 \
//!   cargo test -p certimining-client --features cluster,ots --test anchor_b_devnet -- --ignored
//! ```
#![cfg(all(feature = "cluster", feature = "ots"))]

// The instruction is no longer built here: `Cluster::attach` builds it, after reading the receipt.
// The imports that are gone from this list are the ones that let a pending receipt through.
use certimining_client::cluster::Cluster;
use certimining_client::{
    receipt_digest, refuse_a_readable_key, AnchorB, AnchorStatus, Fetched, PendingReceipt,
    ReferenceClient,
};
use certimining_core::{Digest, NativeKeccak};
use solana_keypair::Keypair;

fn key(name: &str) -> Keypair {
    let home = std::env::var("HOME").expect("HOME");
    let path = std::path::PathBuf::from(format!("{home}/.config/certimining/{name}"));
    // D-117, enforced on the real key rather than only in a unit test.
    refuse_a_readable_key(&path).expect("the key's mode");
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

fn worker() -> ReferenceClient {
    let home = std::env::var("HOME").expect("HOME");
    ReferenceClient {
        executable: std::path::PathBuf::from(format!(
            "{home}/.local/share/potash/ots-venv/bin/ots"
        )),
        // Outside the repository; a person commits them (D-116).
        receipts: std::path::PathBuf::from(format!("{home}/.local/share/potash/receipts")),
    }
}

fn epoch() -> u64 {
    std::env::var("CERTIMINING_EPOCH")
        .expect("CERTIMINING_EPOCH names the epoch to anchor")
        .parse()
        .expect("an epoch number")
}

fn cluster() -> Cluster {
    Cluster::new(
        std::env::var("CERTIMINING_RPC").expect("CERTIMINING_RPC"),
        certimining_checkpoint::ID,
    )
}

/// The root the program recorded, read back rather than recomputed: what anchor B timestamps is what
/// anchor A published.
fn published_root(cluster: &Cluster, epoch: u64) -> Digest {
    match certimining_client::root_for_epoch(cluster, &certimining_checkpoint::ID, epoch)
        .expect("the cluster answered")
    {
        Fetched::Placed(c) => c.root,
        other => panic!("epoch {epoch} has no usable root: {other:?}"),
    }
}

#[test]
#[ignore = "stage one: submits a real root to the calendars (D-112)"]
fn stage_one_submit_the_published_root() {
    let cluster = cluster();
    let epoch = epoch();
    let root = published_root(&cluster, epoch);
    println!("epoch {epoch} root 0x{}", hex(&root));

    let pending = worker()
        .submit(epoch, &root)
        .expect("the calendars answered");
    println!("receipt: {}", pending.path.display());

    // Immediately after submission the receipt exists and carries no Bitcoin attestation. That is
    // what `single` means for this epoch, and it is the honest state rather than a fault.
    assert_eq!(
        worker().upgrade(&pending).expect("upgrade ran"),
        None,
        "a receipt minutes old cannot carry a Bitcoin attestation, and must not claim one"
    );
    assert_eq!(
        cluster.status(epoch).expect("the cluster answered"),
        AnchorStatus::Single,
        "INV-ANCH-05: single until anchor B is attached"
    );
}

#[test]
#[ignore = "stage two: attaches once Bitcoin has confirmed, hours later (D-112)"]
fn stage_two_attach_once_bitcoin_confirms() {
    let cluster = cluster();
    let epoch = epoch();
    let root = published_root(&cluster, epoch);
    let w = worker();
    let pending = PendingReceipt {
        epoch,
        root,
        path: w.receipts.join(format!("{epoch}.root.ots")),
    };

    let digest = match w.upgrade(&pending).expect("upgrade ran") {
        Some(digest) => digest,
        None => {
            println!(
                "epoch {epoch}: still pending. Bitcoin has not confirmed; nothing is attached."
            );
            return;
        }
    };

    // The digest is recomputed here from the file on disk, so what is attached is a digest of bytes
    // that exist rather than one the worker remembered.
    let bytes = std::fs::read(&pending.path).expect("the receipt");
    assert_eq!(
        receipt_digest::<NativeKeccak>(&bytes).expect("encodes"),
        digest
    );

    let payer = key("deploy-keypair.json");
    let authority = key("checkpoint-authority.json");
    // Through `Cluster::attach`, which reads the receipt and refuses one Bitcoin has not carried.
    // Building the instruction here by hand is what let a pending receipt reach a write-once field:
    // the rule D-112 states was only ever the order this harness called things in.
    let (attached, claim) = cluster
        .attach(epoch, &root, &bytes, &payer, &authority)
        .unwrap_or_else(|e| panic!("epoch {epoch}: {e:?}"));
    assert_eq!(
        attached, digest,
        "the guarded path digested different bytes"
    );
    let signature = format!("Bitcoin block {}", claim.height);
    println!("attached 0x{} for epoch {epoch}: {signature}", hex(&digest));

    assert_eq!(
        cluster.status(epoch).expect("the cluster answered"),
        AnchorStatus::Dual,
        "INV-ANCH-05: dual once anchor B is attached, and not before"
    );
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
