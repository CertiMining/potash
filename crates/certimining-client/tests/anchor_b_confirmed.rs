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

use certimining_client::bitcoin::{confirm, target_from_bits, Checkpoint, Header, HeaderRefused};
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
    /// The compact target in force in the checkpoint's retarget period, as a header spells it.
    ///
    /// **Every header in the window must declare exactly this (H-53, #195).** It is committed beside
    /// the checkpoint's height and hash because it is part of the same trusted input: a reader checks
    /// all three against any node with one query, and everything after them is believed for its work.
    checkpoint_bits: u32,
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
        checkpoint_bits: 0x1702_355e,
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
        checkpoint_bits: 0x1702_1ef0,
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
        checkpoint_bits: 0x1702_1ef0,
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
        // Not on a retarget boundary and no timestamp, so each window is verified inside one
        // period and a range leaving it would be refused (H-53, #195). Every window here is four to
        // ten headers, all inside one.
        time: None,
        target: match target_from_bits(anchor.checkpoint_bits) {
            Some(target) => target,
            None => panic!("the committed bits do not decode to a target"),
        },
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

/// One of the log's own epochs: its receipt, and the chain that answers for the height it names.
///
/// **The root is not written here.** It is read from `LIVE-VALUES.txt`, which is the repository's
/// record of what the chain holds, so there is one copy of each published root rather than two —
/// and reading it means this test also checks that record against the receipts. A wrong root there
/// makes `verify_receipt` answer `WrongRoot` and fails this file.
struct EpochAnchor {
    epoch: u64,
    headers: &'static [u8],
    checkpoint_height: u32,
    checkpoint_hash: &'static str,
    /// The compact target in force in the checkpoint's retarget period (H-53, #195).
    checkpoint_bits: u32,
    /// The Bitcoin height the receipt names, which this test confirms rather than accepts.
    height: u32,
}

/// The fourteen epochs with an attached receipt.
///
/// **Twelve distinct heights for fourteen receipts**, and that is the calendar rather than an error:
/// epochs 20726 and 20727 were stamped into block 969474, and 20732 and 20733 into 970294. Two
/// submissions can reach one Bitcoin block, which is what a calendar aggregating digests does.
const EPOCH_ANCHORS: [EpochAnchor; 14] = [
    EpochAnchor {
        epoch: 20723,
        headers: include_bytes!("data/mainnet-headers-968914-968917.bin"),
        checkpoint_height: 968913,
        checkpoint_hash: "0000000000000000000020c010c4fbf57615dacaceac0da5941ded710f9bcbb0",
        checkpoint_bits: 0x1702_1ec5,
        height: 968917,
    },
    EpochAnchor {
        epoch: 20724,
        headers: include_bytes!("data/mainnet-headers-968920-968923.bin"),
        checkpoint_height: 968919,
        checkpoint_hash: "00000000000000000001db6aca70ede91b51b6d351eceff6d1517199bea85b36",
        checkpoint_bits: 0x1702_1ec5,
        height: 968923,
    },
    EpochAnchor {
        epoch: 20725,
        headers: include_bytes!("data/mainnet-headers-969170-969173.bin"),
        checkpoint_height: 969169,
        checkpoint_hash: "000000000000000000001913077c626d1e143fbd41054f700245dc15ba5f6153",
        checkpoint_bits: 0x1702_1ec5,
        height: 969173,
    },
    EpochAnchor {
        epoch: 20726,
        headers: include_bytes!("data/mainnet-headers-969471-969474.bin"),
        checkpoint_height: 969470,
        checkpoint_hash: "000000000000000000015f8ae7f77d172dc90a46bac7b69f24db317ce6ee7ab6",
        checkpoint_bits: 0x1702_1ec5,
        height: 969474,
    },
    EpochAnchor {
        epoch: 20727,
        headers: include_bytes!("data/mainnet-headers-969471-969474.bin"),
        checkpoint_height: 969470,
        checkpoint_hash: "000000000000000000015f8ae7f77d172dc90a46bac7b69f24db317ce6ee7ab6",
        checkpoint_bits: 0x1702_1ec5,
        height: 969474,
    },
    EpochAnchor {
        epoch: 20728,
        headers: include_bytes!("data/mainnet-headers-969629-969632.bin"),
        checkpoint_height: 969628,
        checkpoint_hash: "000000000000000000015e6ca9cc235bffa7a52aa5689c77e14232bfd889bf28",
        checkpoint_bits: 0x1702_1ec5,
        height: 969632,
    },
    EpochAnchor {
        epoch: 20729,
        headers: include_bytes!("data/mainnet-headers-969806-969809.bin"),
        checkpoint_height: 969805,
        checkpoint_hash: "00000000000000000001bbc2841099e501d370266206aac3f30ac64976f59117",
        checkpoint_bits: 0x1702_1ef0,
        height: 969809,
    },
    EpochAnchor {
        epoch: 20730,
        headers: include_bytes!("data/mainnet-headers-969866-969869.bin"),
        checkpoint_height: 969865,
        checkpoint_hash: "00000000000000000000faadee7fca154253ae78aec00f51101d40ac615bedbc",
        checkpoint_bits: 0x1702_1ef0,
        height: 969869,
    },
    EpochAnchor {
        epoch: 20731,
        headers: include_bytes!("data/mainnet-headers-969965-969968.bin"),
        checkpoint_height: 969964,
        checkpoint_hash: "000000000000000000004f94bcc7e1cd2d5c23b11f63533244b67e5fe58294a6",
        checkpoint_bits: 0x1702_1ef0,
        height: 969968,
    },
    EpochAnchor {
        epoch: 20732,
        headers: include_bytes!("data/mainnet-headers-970291-970294.bin"),
        checkpoint_height: 970290,
        checkpoint_hash: "0000000000000000000193abbc886e0c016074cd1075a9b97a5dd8491d4a7b59",
        checkpoint_bits: 0x1702_1ef0,
        height: 970294,
    },
    EpochAnchor {
        epoch: 20733,
        headers: include_bytes!("data/mainnet-headers-970291-970294.bin"),
        checkpoint_height: 970290,
        checkpoint_hash: "0000000000000000000193abbc886e0c016074cd1075a9b97a5dd8491d4a7b59",
        checkpoint_bits: 0x1702_1ef0,
        height: 970294,
    },
    EpochAnchor {
        epoch: 20734,
        headers: include_bytes!("data/mainnet-headers-970579-970582.bin"),
        checkpoint_height: 970578,
        checkpoint_hash: "000000000000000000018595d41b4c02d96d24dc1939b9d857a01fa750ffd28b",
        checkpoint_bits: 0x1702_1ef0,
        height: 970582,
    },
    EpochAnchor {
        epoch: 20735,
        headers: include_bytes!("data/mainnet-headers-970569-970572.bin"),
        checkpoint_height: 970568,
        checkpoint_hash: "00000000000000000001d62038106eb14d0843d95b5f19a878cb3a144eec8c27",
        checkpoint_bits: 0x1702_1ef0,
        height: 970572,
    },
    EpochAnchor {
        epoch: 20736,
        headers: include_bytes!("data/mainnet-headers-970854-970857.bin"),
        checkpoint_height: 970853,
        checkpoint_hash: "000000000000000000012e5db3d4ec26d50091ecab13eb7abd6359eb39728dea",
        checkpoint_bits: 0x1702_1ef0,
        height: 970857,
    },
];

/// The published root for an epoch, read from the repository's record of what the chain holds.
fn published_root(epoch: u64) -> [u8; 32] {
    let text = String::from_utf8_lossy(&repo("LIVE-VALUES.txt")).into_owned();
    let want = format!("published root, epoch {epoch}");
    for line in text.lines() {
        let Some((value, what)) = line.split_once("  ") else {
            continue;
        };
        if what.trim() != want {
            continue;
        }
        let bare = value.trim().strip_prefix("0x").unwrap_or(value.trim());
        return from_hex(bare);
    }
    panic!("LIVE-VALUES.txt holds no published root for epoch {epoch}");
}

/// 64 hexadecimal characters as the 32 bytes they spell, in the order written.
fn from_hex(text: &str) -> [u8; 32] {
    assert_eq!(text.len(), 64, "a root is 64 hex characters: {text:?}");
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
    out
}

/// **Every epoch the log attached a receipt to, confirmed by the block the receipt names.**
///
/// `docs/anchoring.md` has said of every epoch row that the height is the one the receipt carries and
/// that nothing checks it against Bitcoin. This is the check, over all fourteen.
#[test]
fn every_attached_epoch_receipt_is_confirmed_by_the_block_it_names() {
    for anchor in &EPOCH_ANCHORS {
        let receipt = repo(&format!("anchors/epochs/{}.ots", anchor.epoch));
        let stamped = published_root(anchor.epoch);
        let claim = match verify_receipt(&receipt, &stamped) {
            Ok(claim) => claim,
            Err(e) => panic!("epoch {}: {e:?}", anchor.epoch),
        };
        assert_eq!(
            claim.height, anchor.height,
            "epoch {}: the receipt names another block",
            anchor.epoch
        );
        let checkpoint = Checkpoint {
            height: anchor.checkpoint_height,
            hash: from_displayed(anchor.checkpoint_hash),
            // Not on a retarget boundary and no timestamp, so each window is verified inside one
            // period and a range leaving it would be refused (H-53, #195). Every window here is four to
            // ten headers, all inside one.
            time: None,
            target: match target_from_bits(anchor.checkpoint_bits) {
                Some(target) => target,
                None => panic!("the committed bits do not decode to a target"),
            },
        };
        match confirm(claim, checkpoint, &headers_of(anchor.headers)) {
            Ok(confirmed) => assert_eq!(confirmed.height, anchor.height),
            Err(e) => panic!(
                "epoch {}: the block at {} does not confirm this receipt: {e:?}",
                anchor.epoch, anchor.height
            ),
        }
    }
}

/// The control, over the whole set: one bit undone in each chain and every receipt must be refused.
#[test]
fn every_epoch_chain_with_one_bit_of_work_undone_refuses_its_receipt() {
    for anchor in &EPOCH_ANCHORS {
        let receipt = repo(&format!("anchors/epochs/{}.ots", anchor.epoch));
        let claim = match verify_receipt(&receipt, &published_root(anchor.epoch)) {
            Ok(claim) => claim,
            Err(e) => panic!("epoch {}: {e:?}", anchor.epoch),
        };
        let mut headers = headers_of(anchor.headers);
        let Some(first) = headers.get_mut(0) else {
            panic!("epoch {}: the chain is empty", anchor.epoch)
        };
        if let Some(slot) = first.0.get_mut(76) {
            *slot ^= 0x01;
        }
        let checkpoint = Checkpoint {
            height: anchor.checkpoint_height,
            hash: from_displayed(anchor.checkpoint_hash),
            // Not on a retarget boundary and no timestamp, so each window is verified inside one
            // period and a range leaving it would be refused (H-53, #195). Every window here is four to
            // ten headers, all inside one.
            time: None,
            target: match target_from_bits(anchor.checkpoint_bits) {
                Some(target) => target,
                None => panic!("the committed bits do not decode to a target"),
            },
        };
        match confirm(claim, checkpoint, &headers) {
            Err(HeaderRefused::InsufficientWork { at, .. }) => {
                assert_eq!(at, anchor.checkpoint_height.saturating_add(1));
            }
            other => panic!(
                "epoch {}: a header whose work was undone must be refused: {other:?}",
                anchor.epoch
            ),
        }
    }
}
