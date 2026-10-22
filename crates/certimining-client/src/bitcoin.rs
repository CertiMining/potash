// SPDX-License-Identifier: MIT OR Apache-2.0
//! Bitcoin block headers, verified against their own work (H-12, issue #48).
//!
//! **What this is for.** `verify_receipt` establishes that a receipt parses, commits to the epoch's
//! root, and carries a Bitcoin attestation rather than only a calendar's promise. It does not check
//! that the named block commits the computed digest, so a forged receipt naming a block it never
//! reached passes. Every anchor row in `docs/anchoring.md` says so.
//!
//! **Why headers and not a block explorer.** The owner ruled the header source on 21 October 2026.
//! The difference is what a counterparty ends up trusting. Asking an explorer whether a block
//! contains a digest replaces "nothing checks this" with "that explorer checks this", which is a
//! smaller caveat and still a caveat. A header carries its own proof: its hash must meet the target
//! its own `bits` encode, and it must name its predecessor. A chain of them running back to a
//! checkpoint this repository commits cannot be fabricated without doing the work, whoever served
//! the bytes.
//!
//! **So the source of headers is untrusted on purpose.** A node, an explorer, a file a colleague
//! sent: it does not matter, because nothing here believes a header for being delivered. That is the
//! property that makes this verification against Bitcoin rather than against a party.
//!
//! **What this module does not do yet**, stated so the gap is not mistaken for coverage: it verifies
//! a header chain and reads a block's merkle root. Replaying an OpenTimestamps receipt's operations
//! to the digest that root must equal is the other half of H-12, and `verify_receipt` still returns
//! the height the receipt claims rather than one this has confirmed.

use bitcoin_hashes::{sha256d, Hash};

/// A raw 80-byte Bitcoin block header.
///
/// Held as bytes rather than parsed fields because the hash is over exactly these bytes, and a
/// round-trip through parsed fields is a chance to serialise them back differently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header(pub [u8; 80]);

/// Why a header or a chain of them was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderRefused {
    /// The chain does not begin at the committed checkpoint.
    NotFromTheCheckpoint { expected: String, found: String },
    /// A header does not name its predecessor, so these are not one chain.
    Broken {
        at: u32,
        expected: String,
        found: String,
    },
    /// A header's hash does not meet the target its own `bits` encode.
    InsufficientWork { at: u32, hash: String },
    /// The `bits` field encodes a target no header can meet, or none at all.
    MalformedTarget { at: u32, bits: u32 },
    /// No header was supplied for the height asked about.
    HeightNotCovered { wanted: u32, covered: u32 },
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

impl Header {
    /// The header's own hash: SHA-256 applied twice over all 80 bytes.
    ///
    /// Returned in internal byte order, which is what the next header's `prev_hash` field carries.
    /// Bitcoin displays a block hash reversed; nothing here displays one to a user, so nothing here
    /// reverses it, and a comparison against a displayed hash has to reverse one side.
    pub fn block_hash(&self) -> [u8; 32] {
        sha256d::Hash::hash(&self.0).to_byte_array()
    }

    /// The predecessor this header names, bytes 4 to 36.
    pub fn prev_hash(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        if let (Some(slot), Some(field)) = (out.get_mut(..), self.0.get(4..36)) {
            slot.copy_from_slice(field);
        }
        out
    }

    /// The merkle root of the block's transactions, bytes 36 to 68.
    ///
    /// This is what an OpenTimestamps Bitcoin attestation claims a receipt's operations reach.
    pub fn merkle_root(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        if let (Some(slot), Some(field)) = (out.get_mut(..), self.0.get(36..68)) {
            slot.copy_from_slice(field);
        }
        out
    }

    /// The compact difficulty encoding, bytes 72 to 76, little-endian.
    pub fn bits(&self) -> u32 {
        let mut raw = [0u8; 4];
        if let (Some(slot), Some(field)) = (raw.get_mut(..), self.0.get(72..76)) {
            slot.copy_from_slice(field);
        }
        u32::from_le_bytes(raw)
    }

    /// Whether the header's own hash meets the target its `bits` encode.
    ///
    /// This is the whole of why a header is self-authenticating: producing one that passes costs the
    /// work the target names, and no amount of serving bytes substitutes for it.
    pub fn meets_its_target(&self) -> Result<bool, HeaderRefused> {
        let target = target_from_bits(self.bits()).ok_or(HeaderRefused::MalformedTarget {
            at: 0,
            bits: self.bits(),
        })?;
        let hash = self.block_hash();
        // The hash is compared as a 256-bit big-endian number, and it is stored little-endian.
        Ok(less_than_or_equal_reversed(&hash, &target))
    }
}

/// Expands Bitcoin's compact target encoding into 32 big-endian bytes.
///
/// `bits` is an exponent in its top byte and a 24-bit mantissa below it: the target is
/// `mantissa * 256^(exponent - 3)`. `None` for an encoding no header can legitimately carry — a set
/// sign bit, a zero mantissa, or a shift past the end of 32 bytes — because a target nothing can
/// meet and a target everything meets are both ways for this check to stop checking.
pub fn target_from_bits(bits: u32) -> Option<[u8; 32]> {
    let exponent = (bits >> 24) as usize;
    let mantissa = bits & 0x007f_ffff;
    if bits & 0x0080_0000 != 0 || mantissa == 0 {
        return None;
    }
    let mut out = [0u8; 32];
    // The mantissa's least significant byte sits at position `exponent - 1` from the end.
    if exponent <= 3 {
        let shifted =
            mantissa.checked_shr(8u32.checked_mul(3u32.checked_sub(exponent as u32)?)?)?;
        let bytes = shifted.to_be_bytes();
        out.get_mut(28..32)?.copy_from_slice(&bytes);
        return Some(out);
    }
    if exponent > 32 {
        return None;
    }
    let end = 32usize.checked_sub(exponent.checked_sub(3)?)?;
    let start = end.checked_sub(3)?;
    let be = mantissa.to_be_bytes();
    out.get_mut(start..end)?.copy_from_slice(be.get(1..4)?);
    Some(out)
}

/// Whether a little-endian hash is numerically at or below a big-endian target.
fn less_than_or_equal_reversed(hash_le: &[u8; 32], target_be: &[u8; 32]) -> bool {
    for i in 0..32 {
        let Some(h) = hash_le.get(31usize.saturating_sub(i)) else {
            return false;
        };
        let Some(t) = target_be.get(i) else {
            return false;
        };
        if h != t {
            return h < t;
        }
    }
    true
}

/// A height and the hash of the header at it, committed in this repository.
///
/// The chain is trusted from here outward, and only here. A checkpoint is the one input a reader has
/// to take on this repository's word, which is why it is a constant in the source rather than
/// something fetched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Checkpoint {
    pub height: u32,
    /// The header's hash in internal byte order, as `prev_hash` carries it.
    pub hash: [u8; 32],
}

/// Verifies that `headers` is one chain of real work beginning at `checkpoint`'s successor.
///
/// Returns the headers' hashes, so a caller can name a block without recomputing them. Every header
/// must name the previous one and meet its own target; the first must name the checkpoint.
///
/// **What it does not establish.** That this is the chain with the most work — only that it is *a*
/// chain of valid work from the checkpoint. Two competing chains both pass; choosing between them
/// needs the work summed across each, which matters at a reorganisation and not for a block buried
/// under months of it. A receipt's attestation is hours old at the earliest and usually older.
pub fn verify_chain(
    checkpoint: Checkpoint,
    headers: &[Header],
) -> Result<Vec<[u8; 32]>, HeaderRefused> {
    let mut previous = checkpoint.hash;
    let mut hashes = Vec::with_capacity(headers.len());
    for (offset, header) in headers.iter().enumerate() {
        let height = checkpoint
            .height
            .saturating_add(u32::try_from(offset).unwrap_or(u32::MAX))
            .saturating_add(1);
        let named = header.prev_hash();
        if named != previous {
            return Err(if offset == 0 {
                HeaderRefused::NotFromTheCheckpoint {
                    expected: hex(&previous),
                    found: hex(&named),
                }
            } else {
                HeaderRefused::Broken {
                    at: height,
                    expected: hex(&previous),
                    found: hex(&named),
                }
            });
        }
        let target = target_from_bits(header.bits()).ok_or(HeaderRefused::MalformedTarget {
            at: height,
            bits: header.bits(),
        })?;
        let hash = header.block_hash();
        if !less_than_or_equal_reversed(&hash, &target) {
            return Err(HeaderRefused::InsufficientWork {
                at: height,
                hash: hex(&hash),
            });
        }
        previous = hash;
        hashes.push(hash);
    }
    Ok(hashes)
}

/// The merkle root of the block at `height`, from a chain already verified against `checkpoint`.
///
/// This is what an OpenTimestamps Bitcoin attestation at that height claims a receipt's operations
/// reach. Comparing the two is the other half of H-12 and is not done here.
pub fn merkle_root_at(
    checkpoint: Checkpoint,
    headers: &[Header],
    height: u32,
) -> Result<[u8; 32], HeaderRefused> {
    verify_chain(checkpoint, headers)?;
    let covered = checkpoint
        .height
        .saturating_add(u32::try_from(headers.len()).unwrap_or(u32::MAX));
    let offset = height
        .checked_sub(checkpoint.height)
        .and_then(|d| d.checked_sub(1))
        .and_then(|d| usize::try_from(d).ok())
        .ok_or(HeaderRefused::HeightNotCovered {
            wanted: height,
            covered,
        })?;
    headers
        .get(offset)
        .map(Header::merkle_root)
        .ok_or(HeaderRefused::HeightNotCovered {
            wanted: height,
            covered,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a header that names `prev`, carries `root`, and is mined until it meets `bits`.
    ///
    /// A low difficulty, so the test mines in milliseconds. The arithmetic under test is the same at
    /// any difficulty: nothing here special-cases how hard the target is.
    fn mined(prev: [u8; 32], root: [u8; 32], bits: u32) -> Header {
        let mut raw = [0u8; 80];
        if let Some(slot) = raw.get_mut(4..36) {
            slot.copy_from_slice(&prev);
        }
        if let Some(slot) = raw.get_mut(36..68) {
            slot.copy_from_slice(&root);
        }
        if let Some(slot) = raw.get_mut(72..76) {
            slot.copy_from_slice(&bits.to_le_bytes());
        }
        for nonce in 0u32..u32::MAX {
            if let Some(slot) = raw.get_mut(76..80) {
                slot.copy_from_slice(&nonce.to_le_bytes());
            }
            let header = Header(raw);
            if header.meets_its_target() == Ok(true) {
                return header;
            }
        }
        panic!("no nonce met a target this easy, which means the target decoding is wrong");
    }

    /// `bits` for a target of roughly 2^240: easy enough to mine in a test, hard enough that a
    /// random header does not pass by accident.
    const EASY: u32 = 0x1f00_ffff;

    fn chain(len: usize, from: [u8; 32]) -> Vec<Header> {
        let mut out = Vec::new();
        let mut prev = from;
        for i in 0..len {
            let mut root = [0u8; 32];
            if let Some(b) = root.get_mut(0) {
                *b = u8::try_from(i).unwrap_or(0);
            }
            let header = mined(prev, root, EASY);
            prev = header.block_hash();
            out.push(header);
        }
        out
    }

    #[test]
    fn a_chain_of_real_work_from_the_checkpoint_verifies() {
        let checkpoint = Checkpoint {
            height: 100,
            hash: [0x42; 32],
        };
        let headers = chain(4, checkpoint.hash);
        match verify_chain(checkpoint, &headers) {
            Ok(hashes) => assert_eq!(hashes.len(), 4),
            Err(e) => panic!("a mined chain must verify: {e:?}"),
        }
    }

    /// **The property the whole module rests on.** A header that has not done the work is refused
    /// however correctly it is formed and whoever served it.
    #[test]
    fn a_header_that_has_not_done_the_work_is_refused() {
        let checkpoint = Checkpoint {
            height: 100,
            hash: [0x42; 32],
        };
        let mut headers = chain(2, checkpoint.hash);
        // Change the nonce of the first header: it still names the checkpoint and is still 80 bytes.
        let Some(first) = headers.get_mut(0) else {
            panic!("the chain has two headers")
        };
        if let Some(slot) = first.0.get_mut(76..80) {
            slot.copy_from_slice(&0u32.to_le_bytes());
        }
        match verify_chain(checkpoint, &headers) {
            Err(HeaderRefused::InsufficientWork { at, .. }) => assert_eq!(at, 101),
            other => panic!("an unmined header must be refused, got {other:?}"),
        }
    }

    #[test]
    fn a_chain_that_does_not_begin_at_the_checkpoint_is_refused() {
        let checkpoint = Checkpoint {
            height: 100,
            hash: [0x42; 32],
        };
        let headers = chain(2, [0x99; 32]);
        match verify_chain(checkpoint, &headers) {
            Err(HeaderRefused::NotFromTheCheckpoint { .. }) => {}
            other => panic!("a chain from elsewhere must be refused, got {other:?}"),
        }
    }

    #[test]
    fn a_chain_with_a_hole_in_it_is_refused() {
        let checkpoint = Checkpoint {
            height: 100,
            hash: [0x42; 32],
        };
        let mut headers = chain(3, checkpoint.hash);
        headers.remove(1);
        match verify_chain(checkpoint, &headers) {
            Err(HeaderRefused::Broken { at, .. }) => assert_eq!(at, 102),
            other => panic!("a missing header must break the chain, got {other:?}"),
        }
    }

    #[test]
    fn a_blocks_merkle_root_is_read_at_its_own_height() {
        let checkpoint = Checkpoint {
            height: 100,
            hash: [0x42; 32],
        };
        let headers = chain(3, checkpoint.hash);
        for (offset, header) in headers.iter().enumerate() {
            let height = 101u32.saturating_add(u32::try_from(offset).unwrap_or(0));
            assert_eq!(
                merkle_root_at(checkpoint, &headers, height),
                Ok(header.merkle_root()),
                "height {height} is the header at offset {offset}"
            );
        }
        assert!(matches!(
            merkle_root_at(checkpoint, &headers, 104),
            Err(HeaderRefused::HeightNotCovered { .. })
        ));
        assert!(
            matches!(
                merkle_root_at(checkpoint, &headers, 100),
                Err(HeaderRefused::HeightNotCovered { .. })
            ),
            "the checkpoint's own height is not covered: no header for it was supplied"
        );
    }

    /// Bitcoin's genesis block, which is the one header every implementation can check itself
    /// against. Its hash and its target are published facts, not values this repository chose.
    #[test]
    fn the_genesis_header_hashes_and_meets_its_target() {
        let raw: [u8; 80] = [
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3b, 0xa3, 0xed, 0xfd, 0x7a, 0x7b,
            0x12, 0xb2, 0x7a, 0xc7, 0x2c, 0x3e, 0x67, 0x76, 0x8f, 0x61, 0x7f, 0xc8, 0x1b, 0xc3,
            0x88, 0x8a, 0x51, 0x32, 0x3a, 0x9f, 0xb8, 0xaa, 0x4b, 0x1e, 0x5e, 0x4a, 0x29, 0xab,
            0x5f, 0x49, 0xff, 0xff, 0x00, 0x1d, 0x1d, 0xac, 0x2b, 0x7c,
        ];
        let header = Header(raw);
        // Displayed reversed, this is 000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f.
        let mut displayed = header.block_hash();
        displayed.reverse();
        assert_eq!(
            hex(&displayed),
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
            "the genesis block's hash is a published fact, and this is the check that the byte \
             order and the double hash are both right"
        );
        assert_eq!(header.meets_its_target(), Ok(true));
        assert_eq!(header.bits(), 0x1d00_ffff);
    }

    #[test]
    fn a_malformed_target_is_refused_rather_than_treated_as_easy() {
        assert_eq!(target_from_bits(0x0000_0000), None, "a zero mantissa");
        assert_eq!(target_from_bits(0x1d80_ffff), None, "a set sign bit");
        assert_eq!(target_from_bits(0xff00_ffff), None, "a shift past 32 bytes");
    }
}
