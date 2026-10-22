// SPDX-License-Identifier: MIT OR Apache-2.0
//! The three committed anchor-B receipts, confirmed against Bitcoin (H-12, issue #48).
//!
//! **What changed, and it is not a small thing.** Every anchor row in `docs/anchoring.md` has said
//! that nothing checks the heights the receipts name. `verify_receipt` established that a receipt
//! parses, commits to the epoch's root, and carries a Bitcoin attestation rather than a calendar's
//! promise; whether the block it named contained anything was unverified, so a receipt naming a
//! block it never reached passed. This file is the check, run against the real chain.
//!
//! **How the trust is arranged.** The headers below are real mainnet headers, committed as bytes.
//! Each one must meet the target its own `bits` encode and name its predecessor, so an altered header
//! fails arithmetic rather than a comparison with an authority — the test at the end alters one and
//! watches it fail. What a reader has to take on this repository's word is the **checkpoint hash**,
//! one block before each range, and that is a single query to any Bitcoin node or explorer. Nothing
//! else here is trusted, which is the whole design: a header is believed for its work, not for who
//! served it.
//!
//! **What this still does not establish (H-53, #195).** That each header's declared difficulty is the
//! one Bitcoin's rules require at that height. A chain fabricated from the checkpoint by mining at
//! the minimum difficulty would be accepted, which costs far less than the real history. So these
//! confirmations rest on the checkpoint being right, and the retarget rule is what would let them
//! rest on the work alone.
#![cfg(feature = "ots")]

use certimining_client::bitcoin::{confirm, Checkpoint, Header, HeaderRefused, POW_LIMIT};
use certimining_client::verify_receipt;

/// One anchor: the stamped file, its receipt, and the chain that answers for it.
struct Anchor {
    /// What `anchors/` calls it.
    name: &'static str,
    stamped: &'static str,
    receipt: &'static str,
    headers: &'static [u8],
    /// The block one below the first header, as an explorer displays its hash.
    checkpoint_height: u32,
    checkpoint_hash: &'static str,
    /// The height the receipt names, which this test confirms rather than accepts.
    height: u32,
    /// That block's merkle root, as an explorer displays it.
    merkle_root: &'static str,
}

const ANCHORS: [Anchor; 3] = [
    Anchor {
        name: "0001",
        stamped: "anchors/0001-0258f51.txt",
        receipt: "anchors/0001-0258f51.txt.ots",
        headers: include_bytes!("data/mainnet-headers-967485-967489.bin"),
        checkpoint_height: 967_484,
        checkpoint_hash: "00000000000000000000d89a58cbb4687852251e9753f847d06c1c417b2e80ed",
        height: 967_489,
        merkle_root: "c683aa304a7cdfae5583717197ca43b85303a2ab585b02933cd6e20b4475b7ef",
    },
    Anchor {
        name: "0002",
        stamped: "anchors/0002-62abe20.txt",
        receipt: "anchors/0002-62abe20.txt.ots",
        headers: include_bytes!("data/mainnet-headers-971043-971047.bin"),
        checkpoint_height: 971_042,
        checkpoint_hash: "0000000000000000000109d7cd146fc01e07641ad63fc80428ae80df5ed6a46b",
        height: 971_047,
        merkle_root: "33918556ce05fd459bbee9a5d80dc4e6affb6cdf24b6e4eb0d3be39305cf1d64",
    },
    Anchor {
        name: "0003",
        stamped: "anchors/0003-13ee278.txt",
        receipt: "anchors/0003-13ee278.txt.ots",
        headers: include_bytes!("data/mainnet-headers-971179-971188.bin"),
        checkpoint_height: 971_178,
        checkpoint_hash: "00000000000000000000d64c47fb082a1a974e06279a62881b116994f992bd8f",
        height: 971_188,
        merkle_root: "f9f976cc012a0358a3d68ca0870e0492f83a034c5887daeb026711ef724cc098",
    },
];

fn repo(path: &str) -> Vec<u8> {
    let root = match std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
    {
        Some(root) => root.to_path_buf(),
        None => panic!("the crate sits two levels below the repository root"),
    };
    let full = root.join(path);
    match std::fs::read(&full) {
        Ok(bytes) => bytes,
        Err(e) => panic!("{}: {e}", full.display()),
    }
}

/// A hash as an explorer prints it, in the order a header stores it.
fn from_displayed(text: &str) -> [u8; 32] {
    assert_eq!(
        text.len(),
        64,
        "a block hash is 64 hex characters: {text:?}"
    );
    let mut out = [0u8; 32];
    for (i, pair) in text.as_bytes().chunks_exact(2).enumerate() {
        let hex = match std::str::from_utf8(pair) {
            Ok(hex) => hex,
            Err(e) => panic!("{text:?}: {e}"),
        };
        match (u8::from_str_radix(hex, 16), out.get_mut(i)) {
            (Ok(byte), Some(slot)) => *slot = byte,
            (Err(e), _) => panic!("{hex:?}: {e}"),
            (_, None) => panic!("{text:?} is longer than 32 bytes"),
        }
    }
    out.reverse();
    out
}

fn displayed(bytes: &[u8; 32]) -> String {
    let mut reversed = *bytes;
    reversed.reverse();
    reversed.iter().map(|b| format!("{b:02x}")).collect()
}

fn headers_of(blob: &[u8]) -> Vec<Header> {
    assert!(
        blob.len().is_multiple_of(80) && !blob.is_empty(),
        "{} bytes is not a whole number of 80-byte headers",
        blob.len()
    );
    blob.chunks_exact(80)
        .map(|chunk| match <[u8; 80]>::try_from(chunk) {
            Ok(raw) => Header(raw),
            Err(e) => panic!("{e}"),
        })
        .collect()
}

fn checkpoint_of(anchor: &Anchor) -> Checkpoint {
    Checkpoint {
        height: anchor.checkpoint_height,
        hash: from_displayed(anchor.checkpoint_hash),
        easiest_target: POW_LIMIT,
    }
}

/// **The claim each receipt makes, which until now was all anybody had.**
#[test]
fn each_receipt_names_the_height_this_file_records() {
    for anchor in &ANCHORS {
        let claim = match verify_receipt(&repo(anchor.receipt), &repo(anchor.stamped)) {
            Ok(claim) => claim,
            Err(e) => panic!("{}: {e:?}", anchor.name),
        };
        assert_eq!(
            claim.height, anchor.height,
            "{}: the receipt names another block",
            anchor.name
        );
    }
}

/// **The confirmation.** The digest the receipt's operations reach is that block's merkle root.
#[test]
fn every_committed_receipt_is_confirmed_by_the_block_it_names() {
    for anchor in &ANCHORS {
        let claim = match verify_receipt(&repo(anchor.receipt), &repo(anchor.stamped)) {
            Ok(claim) => claim,
            Err(e) => panic!("{}: {e:?}", anchor.name),
        };
        let headers = headers_of(anchor.headers);
        match confirm(claim, checkpoint_of(anchor), &headers) {
            Ok(confirmed) => {
                assert_eq!(confirmed.height, anchor.height);
                assert_eq!(
                    displayed(&confirmed.merkle_root),
                    anchor.merkle_root,
                    "{}: the confirmed merkle root is not the one this file records",
                    anchor.name
                );
            }
            Err(e) => panic!(
                "{}: the block at {} does not confirm this receipt: {e:?}",
                anchor.name, anchor.height
            ),
        }
    }
}

/// **A pass means nothing until the same chain fails for the right reason.**
///
/// One bit of the first header's nonce. It still names the checkpoint, it is still 80 bytes, and
/// every header after it still names its predecessor's old hash — so this is a chain in every
/// respect but the one that matters, and the digest in the last block is untouched and correct.
#[test]
fn a_chain_with_one_bit_of_work_undone_refuses_the_same_receipt() {
    let Some(anchor) = ANCHORS.get(2) else {
        panic!("three anchors")
    };
    let claim = match verify_receipt(&repo(anchor.receipt), &repo(anchor.stamped)) {
        Ok(claim) => claim,
        Err(e) => panic!("{e:?}"),
    };
    let mut headers = headers_of(anchor.headers);
    let Some(first) = headers.get_mut(0) else {
        panic!("the chain is not empty")
    };
    if let Some(slot) = first.0.get_mut(76) {
        *slot ^= 0x01;
    }
    match confirm(claim, checkpoint_of(anchor), &headers) {
        Err(HeaderRefused::InsufficientWork { at, .. }) => {
            assert_eq!(at, anchor.checkpoint_height.saturating_add(1));
        }
        other => panic!("a header whose work was undone must be refused: {other:?}"),
    }
}
