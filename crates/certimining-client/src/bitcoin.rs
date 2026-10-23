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
//! **And a chain can cross a retarget boundary now (H-53, issue #195).** Bitcoin moves the target
//! every 2016 blocks, by the ratio of the period's measured timespan to two weeks, clamped to a factor
//! of four. `retarget` computes it, against Bitcoin's own two most recent boundaries as the expected
//! values, and `verify_chain` walks across one — **when the checkpoint sits on a boundary and carries
//! its timestamp**, which is what the arithmetic needs: the period's first block is then the
//! checkpoint itself. Off a boundary, a range leaving the period is still refused rather than taken on
//! the headers' word, which is what every window this repository commits does.

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
    /// A target easier than the network's proof-of-work limit (H-57, issue #223).
    EasierThanThePowLimit {
        /// The checkpoint's own height, or the height of the header that declared it.
        at: u32,
        /// The target offered.
        target: String,
        /// The limit it is easier than.
        limit: String,
        /// Whose limit, so the refusal names the rules it was judged against.
        network: &'static str,
    },
    /// A compact difficulty that is not the canonical encoding of the target it expands to
    /// (H-59, issue #225).
    DifficultyNotCanonical {
        /// The height of the header that declared it.
        at: u32,
        /// What the header carried.
        bits: u32,
        /// The encoding Bitcoin would have produced for the same target.
        canonical: u32,
    },
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

    /// The block's own timestamp, bytes 68 to 72, little-endian.
    ///
    /// Bitcoin's timestamps are not monotonic — a block may carry one earlier than its predecessor's —
    /// which is why the retarget arithmetic computes its timespan as a signed difference and clamps it.
    pub fn time(&self) -> u32 {
        let mut raw = [0u8; 4];
        if let (Some(slot), Some(field)) = (raw.get_mut(..), self.0.get(68..72)) {
            slot.copy_from_slice(field);
        }
        u32::from_le_bytes(raw)
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

/// Two weeks, the timespan 2016 blocks are meant to take.
pub const TARGET_TIMESPAN: i64 = 14 * 24 * 60 * 60;

/// Compresses a 32-byte big-endian target into the compact encoding a header carries.
///
/// The inverse of [`target_from_bits`], and needed because a retarget produces a full 256-bit number
/// while a header stores 24 bits of mantissa: comparing the two directly would reject every
/// legitimate boundary over the truncation. `None` for zero, which no header can carry.
///
/// **The sign-bit shift is consensus, not tidiness.** A mantissa whose top byte is 0x80 or above would
/// set the bit Bitcoin reads as a sign, so the mantissa moves down a byte and the exponent up one.
pub fn bits_from_target(target: &[u8; 32]) -> Option<u32> {
    let first = target.iter().position(|b| *b != 0)?;
    let mut size = u32::try_from(32usize.checked_sub(first)?).ok()?;
    // The top three significant bytes, padded with zeros past the end — which is `target >> 8(size-3)`
    // when the target has three or more significant bytes and `target << 8(3-size)` when it has fewer.
    let mut mantissa: u32 = 0;
    for i in 0..3usize {
        let byte = first
            .checked_add(i)
            .and_then(|idx| target.get(idx))
            .copied()
            .unwrap_or(0);
        mantissa = mantissa.checked_shl(8)?.checked_add(u32::from(byte))?;
    }
    if mantissa & 0x0080_0000 != 0 {
        mantissa >>= 8;
        size = size.checked_add(1)?;
    }
    size.checked_shl(24)?.checked_add(mantissa)
}

/// `value * mul / div` on a 32-byte big-endian number, truncating, or `None` if it needs 256 bits.
///
/// **The product is formed in 320 bits and only the quotient has to fit in 256.** A first version
/// multiplied inside 32 bytes and treated an overflow as "easier than the limit", which capped the
/// result at the pow limit. For Bitcoin's own targets, around `2^176`, times a timespan under `2^23`,
/// that never happens — and the test that crosses a boundary at a target of `2^240` found it at once,
/// which is why the test exists at a difficulty a test can mine rather than at Bitcoin's.
fn mul_div(value: &[u8; 32], mul: u64, div: u64) -> Option<[u8; 32]> {
    if div == 0 {
        return None;
    }
    // 40 bytes: 32 for the value and 8 for anything a `u64` multiplier carries above it.
    let mut wide = [0u8; 40];
    let mut carry: u128 = 0;
    for i in (0..32usize).rev() {
        let v = u128::from(*value.get(i)?)
            .checked_mul(u128::from(mul))?
            .checked_add(carry)?;
        *wide.get_mut(i.checked_add(8)?)? = (v & 0xff) as u8;
        carry = v >> 8;
    }
    for i in (0..8usize).rev() {
        *wide.get_mut(i)? = (carry & 0xff) as u8;
        carry >>= 8;
    }
    if carry != 0 {
        return None;
    }

    let mut quotient = [0u8; 40];
    let mut remainder: u128 = 0;
    for i in 0..40usize {
        let current = remainder
            .checked_shl(8)?
            .checked_add(u128::from(*wide.get(i)?))?;
        let divisor = u128::from(div);
        *quotient.get_mut(i)? = (current.checked_div(divisor)?) as u8;
        remainder = current.checked_rem(divisor)?;
    }
    // Anything in the top eight bytes is a result past 256 bits, which no target can be.
    if quotient.get(..8)?.iter().any(|b| *b != 0) {
        return None;
    }
    let mut out = [0u8; 32];
    out.get_mut(..)?.copy_from_slice(quotient.get(8..40)?);
    Some(out)
}

/// The target in force after a retarget, from the one before it and the period's measured timespan.
///
/// Bitcoin's rule: scale the previous target by the ratio of the period's actual timespan to two
/// weeks, clamp that ratio to a factor of four either way, and never go easier than the pow limit.
///
/// **The timespan is measured across 2015 intervals and not 2016, which is consensus rather than an
/// error to fix.** It is the difference between the timestamps of the period's first and last blocks,
/// and a period of 2016 blocks has 2015 gaps between them. An implementation that used 2016 would
/// compute a different target from Bitcoin's and reject every boundary.
///
/// The result is round-tripped through the compact encoding before being returned, because that is
/// what a header can carry: a target with more than 24 bits of mantissa is not a target any block
/// declares, and comparing against one would reject every legitimate boundary.
pub fn retarget(previous: &[u8; 32], actual_timespan: i64) -> Option<[u8; 32]> {
    retarget_in(previous, actual_timespan, MAINNET)
}

/// The two consensus constants this module enforces, as a parameter so the walk can be tested.
///
/// **A test can reach neither of them.** 2016 headers at Bitcoin's difficulty is tens of millions of
/// hashes, and a target at the pow limit is `2^32` per header — so with both fixed, the walk across a
/// boundary and the retarget it computes would be the only parts of this module nothing exercised, and
/// an untested branch in a consensus rule is worse than a missing one.
///
/// **`Network` is private and `MAINNET` is the only value any public function passes**, so nothing a
/// caller does can vary either number. A test names the network it means, which is why the type
/// carries one: a refusal says which network's rules refused it rather than quoting a bare limit
/// (H-57, issue #223).
#[derive(Debug, Clone, Copy)]
struct Network {
    interval: u32,
    /// The easiest target the network allows. **A target easier than this describes no block of it**,
    /// however much work was done for the header carrying it.
    pow_limit: [u8; 32],
    name: &'static str,
}

const MAINNET: Network = Network {
    interval: RETARGET_INTERVAL,
    pow_limit: POW_LIMIT,
    name: "mainnet",
};

fn retarget_in(previous: &[u8; 32], actual_timespan: i64, rules: Network) -> Option<[u8; 32]> {
    let clamped = actual_timespan.clamp(TARGET_TIMESPAN / 4, TARGET_TIMESPAN.saturating_mul(4));
    let scaled = u64::try_from(clamped).ok()?;
    let computed = match mul_div(previous, scaled, u64::try_from(TARGET_TIMESPAN).ok()?) {
        // An overflow or a target easier than the rules allow both land on the limit, which is the
        // rule: the difficulty never falls below the one the chain started at.
        Some(t) if t <= rules.pow_limit => t,
        _ => rules.pow_limit,
    };
    target_from_bits(bits_from_target(&computed)?)
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
    /// The checkpoint's own timestamp, where it is known (H-53, issue #195).
    ///
    /// **Only a checkpoint on a retarget boundary can carry a chain across one**, and this is the
    /// field that makes it possible. A retarget at height `h` needs the timestamps of the period's
    /// first and last blocks: the last is a header in the chain, and the first is the block at
    /// `h - 2016`, which is the checkpoint itself when `height % 2016 == 0`.
    ///
    /// `None`, or a checkpoint off a boundary, and a range leaving the period is refused instead —
    /// which is what every window this repository commits does, each being four to ten headers inside
    /// one period.
    pub time: Option<u32>,
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
/// * **A range leaving the period is refused unless the checkpoint sits on a boundary and carries its
///   timestamp.** The retarget needs the timespan of the period that closed, whose first block is the
///   checkpoint exactly when the checkpoint's height is a multiple of 2016. `GENESIS` qualifies; the
///   windows this repository commits do not and do not need to, being four to ten headers inside one
///   period.
/// * **This is not the chain with the most work**, only a chain of the right work from the
///   checkpoint. Two competing chains at the same difficulty both pass, which matters at a
///   reorganisation and not for a block buried under months of it.
pub fn verify_chain(
    checkpoint: Checkpoint,
    headers: &[Header],
) -> Result<Vec<[u8; 32]>, HeaderRefused> {
    verify_chain_in(checkpoint, headers, MAINNET)
}

/// `verify_chain`, with the retarget interval as a parameter so the crossing can be tested.
///
/// **This exists because 2016 headers cannot be mined in a test.** At a difficulty a test can reach,
/// a chain long enough to cross a real boundary is tens of millions of hashes, so the walk across one
/// would be the only part of this module nothing exercised — and an untested branch in a consensus
/// rule is worse than a missing one. The tests call this with an interval of 4.
///
/// It is private, and `verify_chain` is the only way in from outside: nothing a caller does can vary
/// Bitcoin's own constants. Since H-57 (#223) the network is also what the proof-of-work floor is
/// taken from, so a test that mines at an easy target says which network's limit it means instead of
/// slipping past one.
fn verify_chain_in(
    checkpoint: Checkpoint,
    headers: &[Header],
    rules: Network,
) -> Result<Vec<[u8; 32]>, HeaderRefused> {
    let interval = rules.interval;
    // **The checkpoint's target is held to the network's limit before anything is walked**
    // (H-57, issue #223). It is the caller's value and it seeds `in_force`, so an unchecked one sets
    // the difficulty every header is then measured against. `0x207fffff` is minutes of mining and
    // would have carried a whole chain past every other condition here — an independent review of
    // 22 October did exactly that and reached a `Confirmed`.
    //
    // **Why the gap was easy to miss**: `retarget_in` clamps a *computed* target to this limit, so
    // the limit looked enforced. The one target nothing clamped was the one arriving from outside.
    if checkpoint.target > rules.pow_limit {
        return Err(HeaderRefused::EasierThanThePowLimit {
            at: checkpoint.height,
            target: hex(&checkpoint.target),
            limit: hex(&rules.pow_limit),
            network: rules.name,
        });
    }
    // **A boundary is crossed by computing the retarget, or it is refused (H-53, issue #195).**
    // Bitcoin moves the target every 2016 blocks, and the arithmetic needs the timestamps of the
    // period's first and last blocks. The last is a header in this chain. The first is the block at
    // `h - 2016`, which is *the checkpoint itself* exactly when the checkpoint sits on a boundary — so
    // that is the condition under which this can walk across one, and otherwise a range leaving the
    // period is refused rather than taken on the headers' word.
    let span = u32::try_from(headers.len()).unwrap_or(u32::MAX);
    // `interval` is a constant of the rules and never zero; the fallbacks keep the arithmetic
    // checked rather than trusting that, because a zero here would divide by it.
    let checkpoint_period = checkpoint.height.checked_div(interval).unwrap_or(0);
    let tip_period = checkpoint
        .height
        .saturating_add(span)
        .checked_div(interval)
        .unwrap_or(0);
    let on_a_boundary = interval != 0 && checkpoint.height.is_multiple_of(interval);
    if tip_period != checkpoint_period && !(on_a_boundary && checkpoint.time.is_some()) {
        return Err(HeaderRefused::CrossesARetargetBoundary {
            checkpoint_period,
            tip_period,
        });
    }
    let mut previous = checkpoint.hash;
    // The target in force, and the timestamp of the current period's first block.
    let mut in_force = checkpoint.target;
    let mut period_began = checkpoint.time;
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
        // Per header, as Bitcoin checks the range of each header's own target. Every target here must
        // equal `in_force`, which is checked below and is already held to the limit, so this is
        // redundant today — and it is here because a later path that set `in_force` by some other
        // route would otherwise reopen the gap in silence.
        if target > rules.pow_limit {
            return Err(HeaderRefused::EasierThanThePowLimit {
                at: height,
                target: hex(&target),
                limit: hex(&rules.pow_limit),
                network: rules.name,
            });
        }
        // At a boundary the period that just closed sets the new target. Its first block's timestamp
        // is `period_began`; its last is the header one below this one, which is the checkpoint when
        // this is the chain's first header and a header already walked otherwise.
        if interval != 0 && height.is_multiple_of(interval) {
            let began = period_began.ok_or(HeaderRefused::CrossesARetargetBoundary {
                checkpoint_period,
                tip_period,
            })?;
            let closed = match offset.checked_sub(1).and_then(|i| headers.get(i)) {
                Some(before) => before.time(),
                // `offset == 0`, so the block below this one is the checkpoint, which is only on a
                // boundary itself when the interval is 1 — not Bitcoin's. Refused rather than guessed.
                None => {
                    return Err(HeaderRefused::CrossesARetargetBoundary {
                        checkpoint_period,
                        tip_period,
                    })
                }
            };
            let elapsed = i64::from(closed).saturating_sub(i64::from(began));
            in_force =
                retarget_in(&in_force, elapsed, rules).ok_or(HeaderRefused::MalformedTarget {
                    at: height,
                    bits: header.bits(),
                })?;
            period_began = Some(header.time());
        }
        // **The encoding, not only the number it expands to (H-59, issue #225).** Two different
        // compact values can expand to one target — `0x1f7f0000` and `0x20007f00` do — so comparing
        // expanded targets treats both as the target in force. Bitcoin compares the header's `nBits`
        // against the exact value its own arithmetic produces and refuses anything else as
        // `bad-diffbits`. Checked by round-trip rather than against a stored encoding: `bits_from_target`
        // *is* that arithmetic, so a field equal to its own re-encoding is canonical by construction
        // and the checkpoint needs to carry nothing new.
        //
        // The header still does the same work either way, so this costs a forger nothing. What it
        // refuses is a header Bitcoin would not have accepted.
        let canonical = bits_from_target(&target).ok_or(HeaderRefused::MalformedTarget {
            at: height,
            bits: header.bits(),
        })?;
        if canonical != header.bits() {
            return Err(HeaderRefused::DifficultyNotCanonical {
                at: height,
                bits: header.bits(),
                canonical,
            });
        }
        if target != in_force {
            return Err(HeaderRefused::TargetNotTheOneInForce {
                at: height,
                bits: header.bits(),
                expected: hex(&in_force),
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

/// The header of the block at `height`, from a chain already verified against `checkpoint`.
///
/// Returning the header rather than one field of it means a caller needing two facts about the same
/// block — its merkle root and its timestamp, which is what H-02 needs — walks the chain once and
/// reads both out of the same 80 bytes. Two calls would leave a later refactor free to answer them
/// from different blocks.
pub fn header_at(
    checkpoint: Checkpoint,
    headers: &[Header],
    height: u32,
) -> Result<Header, HeaderRefused> {
    header_at_in(checkpoint, headers, height, MAINNET)
}

/// `header_at`, against a named network, so a test mining at an easy target says which (H-57, #223).
fn header_at_in(
    checkpoint: Checkpoint,
    headers: &[Header],
    height: u32,
    rules: Network,
) -> Result<Header, HeaderRefused> {
    verify_chain_in(checkpoint, headers, rules)?;
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
        .copied()
        .ok_or(HeaderRefused::HeightNotCovered {
            wanted: height,
            covered,
        })
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
    merkle_root_at_in(checkpoint, headers, height, MAINNET)
}

/// `merkle_root_at`, against a named network (H-57, #223).
fn merkle_root_at_in(
    checkpoint: Checkpoint,
    headers: &[Header],
    height: u32,
    rules: Network,
) -> Result<[u8; 32], HeaderRefused> {
    header_at_in(checkpoint, headers, height, rules).map(|at| at.merkle_root())
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
    // Height 0 is a retarget boundary, so this checkpoint can carry a chain across one. The timestamp
    // is the genesis header's own, and the test below derives it from those 80 bytes.
    time: Some(1_231_006_505),
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
    /// The block's own timestamp, as its header states it.
    ///
    /// **A Bitcoin timestamp is not a clock.** The miner chooses it; consensus asks only that it
    /// exceed the median of the preceding eleven blocks and sit no more than two hours ahead of
    /// network-adjusted time, and it is not monotone from one block to the next. So it bounds when
    /// the attested digest existed to within hours rather than seconds, and a UTC day index derived
    /// from it can be one too high near a midnight boundary, or — needing a block whose timestamp
    /// runs behind its predecessor's, which is rarer — one too low. Whatever depends on this says
    /// what that costs rather than treating the value as exact.
    pub time: u32,
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
    confirm_in(claim, checkpoint, headers, MAINNET)
}

/// `confirm`, against a named network (H-57, #223).
fn confirm_in(
    claim: crate::BitcoinClaim,
    checkpoint: Checkpoint,
    headers: &[Header],
    rules: Network,
) -> Result<Confirmed, HeaderRefused> {
    let at = header_at_in(checkpoint, headers, claim.height, rules)?;
    let merkle_root = at.merkle_root();
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
        time: at.time(),
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
        mined_at(prev, root, bits, 0)
    }

    /// `mined`, with the block's timestamp set, which the retarget arithmetic reads.
    ///
    /// The time is written **before** the nonce search rather than after it, because changing any
    /// header byte invalidates the nonce: setting it afterwards would mean mining the block twice.
    fn mined_at(prev: [u8; 32], root: [u8; 32], bits: u32, time: u32) -> Header {
        let mut raw = [0u8; 80];
        if let Some(slot) = raw.get_mut(68..72) {
            slot.copy_from_slice(&time.to_le_bytes());
        }
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
            // No timestamp and not on a boundary, so a range leaving the period is refused. The
            // retarget tests build their own checkpoint.
            time: None,
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
        match verify_chain_in(checkpoint, &headers, testnet()) {
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
        match verify_chain_in(checkpoint, &headers, testnet()) {
            Err(HeaderRefused::InsufficientWork { at, .. }) => assert_eq!(at, 101),
            other => panic!("an unmined header must be refused, got {other:?}"),
        }
    }

    #[test]
    fn a_chain_that_does_not_begin_at_the_checkpoint_is_refused() {
        let checkpoint = easy_checkpoint();
        let headers = chain(2, [0x99; 32]);
        match verify_chain_in(checkpoint, &headers, testnet()) {
            Err(HeaderRefused::NotFromTheCheckpoint { .. }) => {}
            other => panic!("a chain from elsewhere must be refused, got {other:?}"),
        }
    }

    #[test]
    fn a_chain_with_a_hole_in_it_is_refused() {
        let checkpoint = easy_checkpoint();
        let mut headers = chain(3, checkpoint.hash);
        headers.remove(1);
        match verify_chain_in(checkpoint, &headers, testnet()) {
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
                merkle_root_at_in(checkpoint, &headers, height, testnet()),
                Ok(header.merkle_root()),
                "height {height} is the header at offset {offset}"
            );
        }
        assert!(matches!(
            merkle_root_at_in(checkpoint, &headers, 104, testnet()),
            Err(HeaderRefused::HeightNotCovered { .. })
        ));
        assert!(
            matches!(
                merkle_root_at_in(checkpoint, &headers, 100, testnet()),
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
        match confirm_in(claim_for(103, attested), checkpoint, &headers, testnet()) {
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
        match confirm_in(claim_for(103, [0x99; 32]), checkpoint, &headers, testnet()) {
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
        match confirm_in(claim_for(103, attested), checkpoint, &headers, testnet()) {
            Err(HeaderRefused::InsufficientWork { at, .. }) => assert_eq!(at, 101),
            other => panic!("a chain missing its work must be refused: {other:?}"),
        }
    }

    #[test]
    fn a_height_no_header_covers_is_refused_rather_than_confirmed() {
        let checkpoint = easy_checkpoint();
        let headers = chain(2, checkpoint.hash);
        match confirm_in(
            claim_for(900_000, [0x99; 32]),
            checkpoint,
            &headers,
            testnet(),
        ) {
            Err(HeaderRefused::HeightNotCovered { wanted, covered }) => {
                assert_eq!((wanted, covered), (900_000, 102));
            }
            other => panic!("a height outside the chain is not confirmed: {other:?}"),
        }
    }

    /// **A checkpoint easier than mainnet's limit is refused by the public entry point** (H-57, #223).
    ///
    /// `0x207fffff` is minutes of mining on a laptop. Before the floor it seeded `in_force`, every
    /// header was measured against it and passed, and a chain produced for nothing reached a
    /// `Confirmed` — which the independent review of 22 October exhibited. The checkpoint is the one
    /// input a reader takes on this repository's word, and that word is that it names a real block,
    /// not a licence for it to name an impossible difficulty.
    ///
    /// Asserted through `verify_chain`, the mainnet entry point, because that is the path a caller
    /// outside this crate has: `Network`'s fields are private and `MAINNET` is the only value such a
    /// caller can reach, so the floor is not something they can opt out of.
    #[test]
    fn a_mainnet_checkpoint_easier_than_the_pow_limit_is_refused() {
        let easy = match target_from_bits(0x207f_ffff) {
            Some(target) => target,
            None => panic!("0x207fffff is a structurally valid compact target"),
        };
        assert!(
            easy > POW_LIMIT,
            "this case tests nothing unless 0x207fffff is easier than Bitcoin's limit"
        );
        let checkpoint = Checkpoint {
            height: 700,
            hash: [9u8; 32],
            target: easy,
            time: None,
        };
        // Mined to meet the easy target, so the refusal is about the difficulty being impossible for
        // this network rather than about the work being absent.
        let header = mined([9u8; 32], [0x62u8; 32], 0x207f_ffff);
        assert_eq!(
            header.meets_its_target(),
            Ok(true),
            "the header does meet the target it declares"
        );
        match verify_chain(checkpoint, &[header]) {
            Err(HeaderRefused::EasierThanThePowLimit { at, network, .. }) => {
                assert_eq!(at, 700, "the refusal names the checkpoint's own height");
                assert_eq!(network, "mainnet", "and whose limit refused it");
            }
            other => {
                panic!("a checkpoint below Bitcoin's difficulty floor is not a chain: {other:?}")
            }
        }
    }

    /// **A target exactly at the limit is accepted**, which makes the case above a floor rather than
    /// an exclusion. Bitcoin's own genesis carries the limit itself.
    ///
    /// Run under the test network, because mining at Bitcoin's real floor — `0x1d00ffff`, the easiest
    /// target the network allows — is about 2^32 hashes and would make this a test of patience. The
    /// comparison under test is the same one either way.
    #[test]
    fn a_target_at_the_networks_limit_is_accepted() {
        assert_eq!(
            GENESIS.target, POW_LIMIT,
            "genesis carries the limit itself, so the comparison must not be strict against it"
        );
        let rules = testnet();
        let checkpoint = Checkpoint {
            height: 700,
            hash: [9u8; 32],
            target: rules.pow_limit,
            time: None,
        };
        let header = mined([9u8; 32], [0x62u8; 32], EASY);
        assert!(
            verify_chain_in(checkpoint, &[header], rules).is_ok(),
            "a target equal to the limit is the easiest the rules allow, not one they forbid"
        );
    }

    /// **A compact difficulty that is not its target's canonical encoding is refused** (H-59, #225).
    ///
    /// The pair the independent review of 22 October exhibited. Both expand to one target, so a
    /// comparison of expanded targets accepts either; Bitcoin produces exactly one of them and
    /// refuses the other as `bad-diffbits`.
    #[test]
    fn a_non_canonical_compact_difficulty_is_refused() {
        let canonical = 0x1f7f_0000;
        let other = 0x2000_7f00;
        assert_eq!(
            target_from_bits(canonical),
            target_from_bits(other),
            "this case tests nothing unless the two encodings expand to one target"
        );
        assert_ne!(canonical, other, "and unless they are different encodings");

        let checkpoint = Checkpoint {
            height: 100,
            hash: [0x42; 32],
            time: None,
            target: match target_from_bits(canonical) {
                Some(t) => t,
                None => panic!("the canonical encoding decodes"),
            },
        };
        // Mined against the easy target the non-canonical value expands to, so the refusal is about
        // the encoding and not about absent work.
        let header = mined([0x42; 32], [0x62; 32], other);
        // **A network whose limit is exactly the target under test** (H-57, #223). `0x1f7f0000` is
        // easier than `testnet()`'s own limit, so judging it there would refuse the case for being
        // out of range and never reach the encoding — which is the whole point of it. Naming a
        // network for the case is the honest way to say what rules it is being judged against.
        let for_the_encoding = Network {
            interval: RETARGET_INTERVAL,
            pow_limit: match target_from_bits(canonical) {
                Some(t) => t,
                None => panic!("the canonical encoding decodes"),
            },
            name: "testnet, limit at the target under test",
        };
        match verify_chain_in(checkpoint, &[header], for_the_encoding) {
            Err(HeaderRefused::DifficultyNotCanonical {
                at,
                bits,
                canonical: c,
            }) => {
                assert_eq!((at, bits, c), (101, other, canonical));
            }
            other => panic!("a non-canonical compact field is not the target in force: {other:?}"),
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
        match verify_chain_in(strict, &headers, testnet()) {
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
        match verify_chain_in(at_the_edge, &headers, testnet()) {
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
            verify_chain_in(inside, &headers, testnet()).is_ok(),
            "four headers after a period's first block are inside it"
        );
    }

    /// **Bitcoin's own retargets, as the expected values** (H-53, issue #195).
    ///
    /// Two real mainnet boundaries. Every input is read from a real header — the previous period's
    /// declared difficulty and the timestamps of its first and last blocks — and the expected output
    /// is the difficulty the boundary block itself declares. Nothing in these four rows is a value
    /// this repository chose, which is what makes them a check on the arithmetic rather than on my
    /// transcription of it.
    ///
    ///     boundary   previous bits   period timespan   declared at the boundary
    ///     969,696    0x1702_1ec5     1,209,975 s       0x1702_1ef0   (14.00 days, barely easier)
    ///     971,712    0x1702_1ef0     1,141,962 s       0x1702_0093   (13.22 days, harder)
    #[test]
    fn the_retarget_reproduces_two_real_bitcoin_boundaries() {
        for (previous, timespan, expected) in [
            (0x1702_1ec5u32, 1_209_975i64, 0x1702_1ef0u32),
            (0x1702_1ef0, 1_141_962, 0x1702_0093),
        ] {
            let before = match target_from_bits(previous) {
                Some(t) => t,
                None => panic!("{previous:#010x} does not decode"),
            };
            let after = match retarget(&before, timespan) {
                Some(t) => t,
                None => panic!("the retarget produced nothing for {previous:#010x}"),
            };
            assert_eq!(
                bits_from_target(&after),
                Some(expected),
                "a {timespan}-second period after {previous:#010x} is {expected:#010x} on the chain \
                 itself, and this computed something else"
            );
        }
    }

    /// **The arithmetic's own edges**, including the one the boundary test found.
    #[test]
    fn the_scaling_refuses_a_result_that_does_not_fit_in_a_target() {
        let limit = match target_from_bits(0x1d00_ffff) {
            Some(t) => t,
            None => panic!("the pow limit does not decode"),
        };
        // Doubling a target near 2^240 stays inside 256 bits; multiplying it by 2^20 does not, and the
        // wide product is what makes the first case work — an implementation multiplying inside 32
        // bytes loses both.
        let high = match target_from_bits(EASY) {
            Some(t) => t,
            None => panic!("EASY does not decode"),
        };
        assert!(
            mul_div(&high, 1_209_000, 1_209_600).is_some(),
            "a ratio just under one must survive a target of 2^240, which is what a 320-bit product \
             is for"
        );
        assert_eq!(
            mul_div(&high, 1_000_000, 1),
            None,
            "a million times 2^240 is not a 256-bit number and saying so beats capping it quietly"
        );
        assert_eq!(mul_div(&limit, 4, 0), None, "a zero divisor has no answer");
        assert_eq!(
            mul_div(&limit, 1, 1),
            Some(limit),
            "the identity, without which the two above could pass on a function that never works"
        );
    }

    /// The compact encoding round-trips, which is what lets a computed target be compared with a
    /// declared one at all — and, since H-59 (#225), what makes a header's own field checkable for
    /// canonicality: a field equal to its re-encoding is the one Bitcoin would have produced.
    ///
    /// **Bitcoin's own limit is the case to keep in mind here.** `0x1d00ffff`'s mantissa carries a
    /// leading zero byte, because `GetCompact` shifts right and raises the exponent rather than let
    /// the mantissa's top bit be read as a sign. So "the top mantissa byte is non-zero" is *not* the
    /// canonical rule, and a check written from that intuition would refuse the real network's floor.
    /// The round-trip is the rule, which is why it is asserted over real difficulties rather than
    /// described.
    #[test]
    fn the_compact_encoding_round_trips_for_every_real_difficulty_here() {
        for bits in [
            0x1d00_ffffu32,
            0x1702_1ec5,
            0x1702_1ef0,
            0x1702_0093,
            // The third difficulty the committed anchor windows were mined at, which this list was
            // missing (H-59, #225).
            0x1702_355e,
            0x1f00_ffff,
        ] {
            let target = match target_from_bits(bits) {
                Some(t) => t,
                None => panic!("{bits:#010x} does not decode"),
            };
            assert_eq!(bits_from_target(&target), Some(bits));
        }
        assert_eq!(bits_from_target(&[0u8; 32]), None, "zero is not a target");
    }

    /// **A chain walked across a boundary, with the new target enforced** (H-53, issue #195).
    ///
    /// The interval is 4 rather than 2016, because 2016 headers cannot be mined in a test; the walk is
    /// the same code. The period's measured timespan is seconds rather than weeks, so the clamp takes
    /// it to a quarter of two weeks and the target becomes four times harder — a value this test does
    /// not choose either, since it asks `retarget` what it is and then mines to it.
    /// The rules these tests can reach: a four-block period and a limit at the difficulty they mine.
    /// **A test network, named rather than a relaxed mainnet** (H-57, #223). Its limit is `EASY`, so
    /// a header costs milliseconds to mine; its retarget interval is Bitcoin's, so every test that is
    /// not about boundaries runs under the real period length.
    ///
    /// The point of naming it: before this, these cases mined easy headers and asked *mainnet's*
    /// entry point to accept them, which it did because nothing held the checkpoint's target to a
    /// floor. A chain of that difficulty is not a mainnet chain, and the tests now say so.
    fn testnet() -> Network {
        Network {
            interval: RETARGET_INTERVAL,
            pow_limit: match target_from_bits(EASY) {
                Some(t) => t,
                None => panic!("EASY does not decode"),
            },
            name: "testnet",
        }
    }

    /// The same test network with a four-block retarget period, for the boundary cases: 2016 headers
    /// at any difficulty is more than a test can mine.
    fn testnet_short_period() -> Network {
        Network {
            interval: 4,
            pow_limit: match target_from_bits(EASY) {
                Some(t) => t,
                None => panic!("EASY does not decode"),
            },
            name: "testnet, four-block period",
        }
    }

    #[test]
    fn a_chain_crossing_a_boundary_is_verified_against_the_computed_target() {
        let began = 1_700_000_000u32;
        let checkpoint = Checkpoint {
            height: 100,
            hash: [0x42; 32],
            target: match target_from_bits(EASY) {
                Some(t) => t,
                None => panic!("EASY does not decode"),
            },
            time: Some(began),
        };
        // 101, 102, 103 under the old target.
        let mut headers = Vec::new();
        let mut prev = checkpoint.hash;
        // The period runs 1,209,000 seconds, a shade under two weeks, so the target gets harder by
        // a factor of 1.0005 — one step of the compact mantissa, which is visible in the bits and
        // costs nothing to mine. A larger move would be a slower test and not a better one.
        let times = [1u32, 2, 1_209_000];
        for (i, offset) in times.iter().enumerate() {
            let label = u8::try_from(i).unwrap_or(0);
            let header = mined_at(prev, [label; 32], EASY, began.saturating_add(*offset));
            prev = header.block_hash();
            headers.push(header);
        }
        // 104 is the boundary. The period that closed ran from the checkpoint to 103.
        let closed = match headers.get(2) {
            Some(h) => h.time(),
            None => panic!("three headers"),
        };
        let elapsed = i64::from(closed).saturating_sub(i64::from(began));
        let next_target = match retarget_in(&checkpoint.target, elapsed, testnet_short_period()) {
            Some(t) => t,
            None => panic!("the retarget produced nothing"),
        };
        let next_bits = match bits_from_target(&next_target) {
            Some(b) => b,
            None => panic!("the computed target has no compact form"),
        };
        assert_ne!(next_bits, EASY, "a four-second period must move the target");

        let boundary = mined_at(prev, [0x9a; 32], next_bits, closed.saturating_add(1));
        headers.push(boundary);
        match verify_chain_in(checkpoint, &headers, testnet_short_period()) {
            Ok(hashes) => assert_eq!(hashes.len(), 4),
            Err(e) => panic!("a chain declaring the computed target must verify: {e:?}"),
        }

        // **The control.** The same chain with the boundary block keeping the old difficulty.
        let mut stale = headers.clone();
        if let Some(last) = stale.get_mut(3) {
            *last = mined_at(prev, [0x9a; 32], EASY, closed.saturating_add(1));
        }
        match verify_chain_in(checkpoint, &stale, testnet_short_period()) {
            Err(HeaderRefused::TargetNotTheOneInForce { at, bits, .. }) => {
                assert_eq!((at, bits), (104, EASY));
            }
            other => panic!("a boundary block keeping the old target must be refused: {other:?}"),
        }
    }

    /// A checkpoint off a boundary still refuses a crossing, because the arithmetic needs a timestamp
    /// it does not have: the first block of its period is not the checkpoint.
    #[test]
    fn a_checkpoint_off_a_boundary_still_refuses_a_crossing() {
        let checkpoint = Checkpoint {
            height: 101,
            time: Some(1_700_000_000),
            ..easy_checkpoint()
        };
        let headers = chain(4, checkpoint.hash);
        match verify_chain_in(checkpoint, &headers, testnet_short_period()) {
            Err(HeaderRefused::CrossesARetargetBoundary { .. }) => {}
            other => panic!("101 is not a multiple of 4, so this cannot answer for 104: {other:?}"),
        }
    }

    /// And a boundary checkpoint with no timestamp refuses one too, for the same reason.
    #[test]
    fn a_boundary_checkpoint_without_its_timestamp_refuses_a_crossing() {
        let headers = chain(4, easy_checkpoint().hash);
        match verify_chain_in(easy_checkpoint(), &headers, testnet_short_period()) {
            Err(HeaderRefused::CrossesARetargetBoundary { .. }) => {}
            other => panic!("100 is a multiple of 4 but carries no time: {other:?}"),
        }
    }

    /// The genesis checkpoint's timestamp is the genesis header's own, not a transcribed number.
    #[test]
    fn the_committed_genesis_checkpoint_carries_the_genesis_timestamp() {
        assert_eq!(
            GENESIS.time,
            Some(Header(GENESIS_HEADER).time()),
            "the committed timestamp is not the genesis header's own"
        );
        assert_eq!(
            GENESIS.height % RETARGET_INTERVAL,
            0,
            "genesis is a retarget boundary, which is what lets it carry a chain across one"
        );
    }

    #[test]
    fn a_malformed_target_is_refused_rather_than_treated_as_easy() {
        assert_eq!(target_from_bits(0x0000_0000), None, "a zero mantissa");
        assert_eq!(target_from_bits(0x1d80_ffff), None, "a set sign bit");
        assert_eq!(target_from_bits(0xff00_ffff), None, "a shift past 32 bytes");
    }
}
