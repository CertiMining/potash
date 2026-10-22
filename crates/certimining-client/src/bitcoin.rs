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
//! **Both halves are here now.** `verify_chain` establishes that a chain of real work runs back to a
//! committed checkpoint; `confirm` compares the digest a receipt's operations reach with the merkle
//! root of the block at the height the receipt names, and returns a `Confirmed` that nothing else can
//! build. A `BitcoinClaim` is what a receipt says; a `Confirmed` is what a block shows.
//!
//! **The difficulty is the one in force, not merely a floor (H-53, issue #195).** A header declares
//! its own target, so the first version of this module checked only that no header was *easier* than a
//! floor — and a chain fabricated from the checkpoint by mining at that floor would have been
//! accepted. The checkpoint now carries the target in force at its height and every header must
//! declare exactly that, which is what makes a fabricated chain cost what the real one cost.
//!
//! **A chain crossing a retarget boundary is refused rather than guessed at.** Bitcoin moves the
//! target every 2016 blocks, and computing where it moves to needs the period's timespan and a
//! 256-bit multiply. Until that lands, a chain is verified inside one period and a range that leaves
//! it is refused, which is the honest shape: every confirmation this repository performs is four to
//! ten headers inside one period, and a longer one says so instead of accepting easy work.

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
    /// The header declares a target other than the one in force at the checkpoint.
    ///
    /// A header states its own difficulty, so a chain of trivially-mined headers passes every other
    /// test here. Requiring the target in force is what costs a forger the real chain's work.
    TargetNotTheOneInForce {
        at: u32,
        bits: u32,
        expected: String,
    },
    /// The range leaves the retarget period the checkpoint sits in.
    ///
    /// Bitcoin moves the target every 2016 blocks and this module does not yet compute where to.
    /// Refusing is the only answer that does not accept whatever the headers claim.
    CrossesARetargetBoundary {
        checkpoint_period: u32,
        tip_period: u32,
    },
    /// No header was supplied for the height asked about.
    HeightNotCovered { wanted: u32, covered: u32 },
    /// The block at that height does not commit the digest the receipt's operations reach.
    ///
    /// **This is the refusal the whole module exists to be able to make.** A receipt naming a block
    /// it never reached parses, carries a Bitcoin attestation, and fails here.
    DigestNotInTheBlock {
        at: u32,
        attested: String,
        merkle_root: String,
    },
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

/// The easiest target Bitcoin's consensus rules permit, which is `0x1d00ffff` expanded.
///
/// **A header states its own difficulty, so without this nothing bounds how easy it may be.** A
/// chain whose headers each declare a target of `0x1f00ffff` is a chain of "real work" by
/// `verify_chain`'s own test and costs almost nothing to produce. The test below ties this constant
/// to `target_from_bits(0x1d00ffff)` rather than leaving 32 transcribed bytes to be trusted.
pub const POW_LIMIT: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Bitcoin's retarget interval: the target is fixed for 2016 blocks at a time.
pub const RETARGET_INTERVAL: u32 = 2016;

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
    /// The target in force at `height`, big-endian, which every header in the chain must declare.
    ///
    /// **Exactly, not as a floor (H-53, issue #195).** A floor leaves a chain minable at the minimum,
    /// and reaching a recent height that way costs a fraction of what Bitcoin's history cost. The
    /// target in force makes each header cost what a real one cost, which is the property the whole
    /// module is for.
    ///
    /// It belongs to the checkpoint because the checkpoint is where trust sits here: a reader who
    /// accepts the committed checkpoint accepts its height, its hash and its difficulty together, and
    /// checks all three with one query to any node.
    pub target: [u8; 32],
}

/// Verifies that `headers` is one chain of real work beginning at `checkpoint`'s successor.
///
/// Returns the headers' hashes, so a caller can name a block without recomputing them. Every header
/// must name the previous one and meet its own target; the first must name the checkpoint.
///
/// **What this establishes about work, and what it does not.** Every header must declare the target in
/// force at the checkpoint and meet it, so producing one costs what a real block at that difficulty
/// cost — about `2^79` hashes on the chain this repository anchors to. An earlier version required
/// only that no header be *easier* than a floor, which left a chain minable from the checkpoint at
/// `2^32` a header: the floor was never the point, the target in force is.
///
/// Two things remain, and neither is the fabrication above:
///
/// * **A range leaving the checkpoint's retarget period is refused**, because the target moves every
///   2016 blocks and nothing here computes where to. Every confirmation this repository performs is
///   four to ten headers inside one period. A light client walking from genesis would need the
///   retarget arithmetic, which is the rest of H-53 (#195).
/// * **This is not the chain with the most work**, only a chain of the right work from the
///   checkpoint. Two competing chains at the same difficulty both pass, which matters at a
///   reorganisation and not for a block buried under months of it.
pub fn verify_chain(
    checkpoint: Checkpoint,
    headers: &[Header],
) -> Result<Vec<[u8; 32]>, HeaderRefused> {
    // **One retarget period, or nothing (H-53, issue #195).** The target in force belongs to the
    // period the checkpoint sits in, so a range that leaves it is a range this cannot answer for.
    let span = u32::try_from(headers.len()).unwrap_or(u32::MAX);
    let checkpoint_period = checkpoint.height / RETARGET_INTERVAL;
    let tip_period = checkpoint.height.saturating_add(span) / RETARGET_INTERVAL;
    if tip_period != checkpoint_period {
        return Err(HeaderRefused::CrossesARetargetBoundary {
            checkpoint_period,
            tip_period,
        });
    }
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
        if target != checkpoint.target {
            return Err(HeaderRefused::TargetNotTheOneInForce {
                at: height,
                bits: header.bits(),
                expected: hex(&checkpoint.target),
            });
        }
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

/// Bitcoin's genesis block: the one checkpoint this repository can commit without vouching for
/// anything.
///
/// A checkpoint is the single input a reader has to take on trust, so *which* one is committed is a
/// question about what this repository is willing to assert. Genesis needs no assertion — its hash is
/// a published fact older than any party to this — and the test below derives it from the header's own
/// 80 bytes rather than trusting the constant beneath it.
///
/// **What using it costs, stated here rather than discovered by someone waiting.** Confirming a
/// receipt attested at a recent height against this checkpoint means supplying every header from
/// block 1 to that height: around 900,000 of them for a 2026 block, about 72 MB at 80 bytes each. The
/// verification is linear and runs in seconds; the bytes still have to come from somewhere. A nearer
/// checkpoint turns that into a few thousand headers, and committing one is a decision about what
/// this repository vouches for.
pub const GENESIS: Checkpoint = Checkpoint {
    height: 0,
    // Period 0's target is the maximum Bitcoin allows, which is where the chain started.
    target: POW_LIMIT,
    // Internal byte order. Reversed for display this is
    // 000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f.
    hash: [
        0x6f, 0xe2, 0x8c, 0x0a, 0xb6, 0xf1, 0xb3, 0x72, 0xc1, 0xa6, 0xa2, 0x46, 0xae, 0x63, 0xf7,
        0x4f, 0x93, 0x1e, 0x83, 0x65, 0xe1, 0x5a, 0x08, 0x9c, 0x68, 0xd6, 0x19, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ],
};

/// A block this code has seen commit a receipt's digest — which a `BitcoinClaim` is not.
///
/// **Only `confirm` builds one.** `confirm` needs a chain of real work running back to a committed
/// checkpoint, so holding a `Confirmed` is holding the fact rather than the receipt's assertion about
/// it. That is the entire purpose of the type: the two are not interchangeable, and the compiler will
/// not let a caller treat one as the other, which is the mistake `docs/anchoring.md` has been warning
/// readers about in prose since the first anchor row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Confirmed {
    /// The height, now a checked fact rather than a claim.
    pub height: u32,
    /// The block's merkle root, equal to the digest the receipt's operations reach.
    pub merkle_root: [u8; 32],
}

/// Confirms a receipt's Bitcoin attestation against a chain of headers.
///
/// `headers` runs from `checkpoint`'s successor upward and must cover `claim.height`. Where the bytes
/// came from does not matter: a node, an explorer, a file a colleague sent. Each header must meet the
/// target its own `bits` encode and name its predecessor, so a server that invents one has to do the
/// work, which is the property that makes this verification against Bitcoin rather than against
/// whoever answered.
///
/// **What it does not establish**, beyond what `verify_chain` already disclaims about competing
/// chains: that the receipt's *operations* are the ones the calendar performed. It establishes that
/// executing them from this epoch's root reaches a digest that this block commits, which is what an
/// OpenTimestamps attestation asserts and all it asserts.
pub fn confirm(
    claim: crate::BitcoinClaim,
    checkpoint: Checkpoint,
    headers: &[Header],
) -> Result<Confirmed, HeaderRefused> {
    let merkle_root = merkle_root_at(checkpoint, headers, claim.height)?;
    if merkle_root != claim.attested_digest {
        return Err(HeaderRefused::DigestNotInTheBlock {
            at: claim.height,
            attested: hex(&claim.attested_digest),
            merkle_root: hex(&merkle_root),
        });
    }
    Ok(Confirmed {
        height: claim.height,
        merkle_root,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Bitcoin's genesis header, the one expected value in this file that nobody here chose.
    const GENESIS_HEADER: [u8; 80] = [
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3b, 0xa3, 0xed, 0xfd, 0x7a, 0x7b, 0x12, 0xb2, 0x7a,
        0xc7, 0x2c, 0x3e, 0x67, 0x76, 0x8f, 0x61, 0x7f, 0xc8, 0x1b, 0xc3, 0x88, 0x8a, 0x51, 0x32,
        0x3a, 0x9f, 0xb8, 0xaa, 0x4b, 0x1e, 0x5e, 0x4a, 0x29, 0xab, 0x5f, 0x49, 0xff, 0xff, 0x00,
        0x1d, 0x1d, 0xac, 0x2b, 0x7c,
    ];

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

    /// A checkpoint whose target in force is `EASY`, because no test can mine at Bitcoin's own.
    ///
    /// **This is why the target lives on the checkpoint.** A constant would make every test here
    /// either impossible or a test of something else; a field makes the difficulty part of the
    /// trusted input, which is what it is.
    fn easy_checkpoint() -> Checkpoint {
        Checkpoint {
            height: 100,
            hash: [0x42; 32],
            target: match target_from_bits(EASY) {
                Some(t) => t,
                None => panic!("the test's own difficulty does not decode"),
            },
        }
    }

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
        let checkpoint = easy_checkpoint();
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
        let checkpoint = easy_checkpoint();
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
        let checkpoint = easy_checkpoint();
        let headers = chain(2, [0x99; 32]);
        match verify_chain(checkpoint, &headers) {
            Err(HeaderRefused::NotFromTheCheckpoint { .. }) => {}
            other => panic!("a chain from elsewhere must be refused, got {other:?}"),
        }
    }

    #[test]
    fn a_chain_with_a_hole_in_it_is_refused() {
        let checkpoint = easy_checkpoint();
        let mut headers = chain(3, checkpoint.hash);
        headers.remove(1);
        match verify_chain(checkpoint, &headers) {
            Err(HeaderRefused::Broken { at, .. }) => assert_eq!(at, 102),
            other => panic!("a missing header must break the chain, got {other:?}"),
        }
    }

    #[test]
    fn a_blocks_merkle_root_is_read_at_its_own_height() {
        let checkpoint = easy_checkpoint();
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
        let header = Header(GENESIS_HEADER);
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

    /// **The committed checkpoint is checked against the header, not trusted.**
    ///
    /// A constant transcribed by hand is a second opinion about a published fact, and this is the one
    /// value in the module a reader cannot check by doing the work. So it is derived here from the 80
    /// bytes above, which the test alongside ties to the published hash.
    #[test]
    fn the_committed_genesis_checkpoint_is_the_genesis_header() {
        assert_eq!(GENESIS.height, 0);
        assert_eq!(
            GENESIS.hash,
            Header(GENESIS_HEADER).block_hash(),
            "the committed checkpoint is not the genesis header's own hash"
        );
    }

    /// A claim for a digest the block at that height really commits.
    fn claim_for(height: u32, digest: [u8; 32]) -> crate::BitcoinClaim {
        crate::BitcoinClaim {
            height,
            attested_digest: digest,
        }
    }

    #[test]
    fn a_digest_the_named_block_commits_is_confirmed() {
        let checkpoint = easy_checkpoint();
        let attested = [0x99; 32];
        // Four blocks; the third carries the digest the receipt's operations reach.
        let mut headers = Vec::new();
        let mut prev = checkpoint.hash;
        for i in 0..4 {
            let root = if i == 2 { attested } else { [i; 32] };
            let header = mined(prev, root, EASY);
            prev = header.block_hash();
            headers.push(header);
        }
        match confirm(claim_for(103, attested), checkpoint, &headers) {
            Ok(confirmed) => {
                assert_eq!(confirmed.height, 103);
                assert_eq!(confirmed.merkle_root, attested);
            }
            Err(e) => panic!("the block at 103 commits this digest: {e:?}"),
        }
    }

    /// **The refusal H-12 was filed for.** A receipt naming a block it never reached.
    #[test]
    fn a_digest_the_named_block_does_not_commit_is_refused() {
        let checkpoint = easy_checkpoint();
        let headers = chain(4, checkpoint.hash);
        match confirm(claim_for(103, [0x99; 32]), checkpoint, &headers) {
            Err(HeaderRefused::DigestNotInTheBlock { at, .. }) => assert_eq!(at, 103),
            other => panic!("a block that commits something else must be refused: {other:?}"),
        }
    }

    /// **A confirmation rests on the work, not on the block.**
    ///
    /// The block at 103 carries exactly the right digest, and the chain reaching it has a header that
    /// has not been mined. That must refuse: otherwise anybody could hand over a fabricated chain
    /// whose last block commits whatever they liked, which is the whole attack this module answers.
    #[test]
    fn a_block_committing_the_digest_on_a_chain_without_the_work_is_refused() {
        let checkpoint = easy_checkpoint();
        let attested = [0x99; 32];
        let mut headers = Vec::new();
        let mut prev = checkpoint.hash;
        for i in 0..4 {
            let root = if i == 2 { attested } else { [i; 32] };
            let header = mined(prev, root, EASY);
            prev = header.block_hash();
            headers.push(header);
        }
        // Undo the first header's work. Every later header still names its predecessor's hash, so
        // this is a chain in every respect except the one that matters.
        let Some(first) = headers.get_mut(0) else {
            panic!("the chain has four headers")
        };
        if let Some(slot) = first.0.get_mut(76..80) {
            slot.copy_from_slice(&0u32.to_le_bytes());
        }
        match confirm(claim_for(103, attested), checkpoint, &headers) {
            Err(HeaderRefused::InsufficientWork { at, .. }) => assert_eq!(at, 101),
            other => panic!("a chain missing its work must be refused: {other:?}"),
        }
    }

    #[test]
    fn a_height_no_header_covers_is_refused_rather_than_confirmed() {
        let checkpoint = easy_checkpoint();
        let headers = chain(2, checkpoint.hash);
        match confirm(claim_for(900_000, [0x99; 32]), checkpoint, &headers) {
            Err(HeaderRefused::HeightNotCovered { wanted, covered }) => {
                assert_eq!((wanted, covered), (900_000, 102));
            }
            other => panic!("a height outside the chain is not confirmed: {other:?}"),
        }
    }

    /// **The target in force, and the constant tied to the encoding rather than transcribed.**
    ///
    /// This is the assertion that costs a forger the real chain's work: a header declaring anything
    /// but the target in force is refused, so a chain cannot be mined from the checkpoint at a
    /// difficulty of the forger's choosing.
    #[test]
    fn a_target_other_than_the_one_in_force_is_refused() {
        assert_eq!(
            target_from_bits(0x1d00_ffff),
            Some(POW_LIMIT),
            "POW_LIMIT must be what Bitcoin's own maximum-difficulty encoding expands to"
        );
        // A checkpoint stating Bitcoin's own maximum target, against a chain mined at 2^240.
        let strict = Checkpoint {
            target: POW_LIMIT,
            ..easy_checkpoint()
        };
        let headers = chain(2, strict.hash);
        match verify_chain(strict, &headers) {
            Err(HeaderRefused::TargetNotTheOneInForce { at, bits, .. }) => {
                assert_eq!((at, bits), (101, EASY));
            }
            other => panic!(
                "a chain mined at 2^240 is not Bitcoin, and accepting it is what makes a fabricated \
                 chain cheap: {other:?}"
            ),
        }
    }

    /// **A range that leaves the checkpoint's retarget period is refused, not guessed at.**
    #[test]
    fn a_chain_crossing_a_retarget_boundary_is_refused() {
        // The checkpoint is the last block of its period, so its successor starts the next one.
        let at_the_edge = Checkpoint {
            height: RETARGET_INTERVAL.saturating_sub(1),
            ..easy_checkpoint()
        };
        let headers = chain(2, at_the_edge.hash);
        match verify_chain(at_the_edge, &headers) {
            Err(HeaderRefused::CrossesARetargetBoundary {
                checkpoint_period,
                tip_period,
            }) => assert_eq!((checkpoint_period, tip_period), (0, 1)),
            other => {
                panic!("the target moves at a boundary and this cannot say where to: {other:?}")
            }
        }
    }

    /// The control: a range inside one period is verified, which is what every confirmation here is.
    #[test]
    fn a_chain_inside_one_retarget_period_is_verified() {
        let inside = Checkpoint {
            height: RETARGET_INTERVAL.saturating_mul(3),
            ..easy_checkpoint()
        };
        let headers = chain(4, inside.hash);
        assert!(
            verify_chain(inside, &headers).is_ok(),
            "four headers after a period's first block are inside it"
        );
    }

    #[test]
    fn a_malformed_target_is_refused_rather_than_treated_as_easy() {
        assert_eq!(target_from_bits(0x0000_0000), None, "a zero mantissa");
        assert_eq!(target_from_bits(0x1d80_ffff), None, "a set sign bit");
        assert_eq!(target_from_bits(0xff00_ffff), None, "a shift past 32 bytes");
    }
}
