// SPDX-License-Identifier: MIT OR Apache-2.0
//! Confirms an anchor-B receipt against Bitcoin (H-12, issue #48).
//!
//! **Why this binary exists and not only the library.** `verify_receipt` has always said what it does
//! not do, and `bitcoin::confirm` now does it — but a capability nothing can invoke is a capability
//! nobody runs. This is the way to run it: a receipt, the bytes it stamped, and a chain of headers
//! covering the height it names.
//!
//! **Where the headers come from does not matter, which is the point.** Each one must meet the target
//! its own `bits` encode and name its predecessor, back to a checkpoint this repository commits, so a
//! node, an explorer and a file a colleague sent are equally acceptable. Nothing here believes a
//! header for being delivered.
//!
//! ```text
//! CERTIMINING_RECEIPT=anchors/0003-epoch-20738.ots \
//! CERTIMINING_STAMPED=/tmp/root.bin \
//! CERTIMINING_HEADERS=/tmp/headers.bin \
//!     cargo run -p certimining-client --features ots --bin confirm-anchor-b
//! ```
//!
//! `CERTIMINING_HEADERS` is raw 80-byte headers, concatenated, from the checkpoint's **successor**
//! upward with no gaps. `CERTIMINING_CHECKPOINT_HEIGHT` and `CERTIMINING_CHECKPOINT_HASH` override the
//! committed genesis checkpoint; the hash is given the way an explorer displays it, and this reverses
//! it, because a hash pasted from a browser in the order a header stores it is the mistake worth
//! designing out rather than documenting. `CERTIMINING_CHECKPOINT_BITS` is that period's compact
//! target, which every header must declare exactly; all three are set together or none is.
//! `CERTIMINING_CHECKPOINT_TIME` is the checkpoint's own timestamp, and setting it on a checkpoint
//! whose height is a multiple of 2016 is what lets a chain cross a retarget boundary (H-53, #195).
//!
//! **What a success here means, and where it stops (H-53, #195).** Every header declares the target
//! in force and meets it, so producing one costs what a real block at that difficulty cost. The chain
//! must lie inside the checkpoint's retarget period — the target moves every 2016 blocks and nothing
//! here computes where to — so a longer range is refused rather than accepted on whatever difficulty
//! the headers happen to claim.
#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use certimining_client::bitcoin::{confirm, target_from_bits, Checkpoint, Header, GENESIS};
use certimining_client::verify_receipt;
use std::process::ExitCode;

/// One header is 80 bytes, and a file whose length is not a multiple of that is not a chain.
const HEADER_LEN: usize = 80;

fn env(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|_| format!("{name} is not set"))
}

fn read(name: &str) -> Result<Vec<u8>, String> {
    let path = env(name)?;
    std::fs::read(&path).map_err(|e| format!("{name}={path}: {e}"))
}

/// A block hash the way an explorer displays it, as the bytes a header carries.
fn hash_from_displayed(text: &str) -> Result<[u8; 32], String> {
    let trimmed = text.trim();
    if trimmed.len() != 64 {
        return Err(format!(
            "a block hash is 64 hexadecimal characters and this is {}",
            trimmed.len()
        ));
    }
    let mut out = [0u8; 32];
    for (i, pair) in trimmed.as_bytes().chunks_exact(2).enumerate() {
        let hex = std::str::from_utf8(pair).map_err(|e| e.to_string())?;
        let byte = u8::from_str_radix(hex, 16).map_err(|e| format!("{hex:?}: {e}"))?;
        match out.get_mut(i) {
            Some(slot) => *slot = byte,
            None => return Err("more than 32 bytes".to_string()),
        }
    }
    // Displayed reversed, which is how every explorer and every person writes one down.
    out.reverse();
    Ok(out)
}

fn checkpoint() -> Result<Checkpoint, String> {
    let height = std::env::var("CERTIMINING_CHECKPOINT_HEIGHT").ok();
    let hash = std::env::var("CERTIMINING_CHECKPOINT_HASH").ok();
    let bits = std::env::var("CERTIMINING_CHECKPOINT_BITS").ok();
    match (height, hash, bits) {
        (None, None, None) => Ok(GENESIS),
        (Some(height), Some(hash), Some(bits)) => {
            let raw = bits.trim().trim_start_matches("0x");
            let parsed = u32::from_str_radix(raw, 16)
                .map_err(|e| format!("CERTIMINING_CHECKPOINT_BITS={bits}: {e}"))?;
            Ok(Checkpoint {
                height: height
                    .trim()
                    .parse()
                    .map_err(|e| format!("CERTIMINING_CHECKPOINT_HEIGHT={height}: {e}"))?,
                hash: hash_from_displayed(&hash)?,
                // **The target in force, not a floor (H-53, #195).** Every header in the chain must
                // declare exactly this. An operator supplying an easier one would accept a chain
                // mined for less than the real one cost, which is why it belongs to the checkpoint:
                // the whole checkpoint is the trusted input, and one query to a node checks all of it.
                target: target_from_bits(parsed).ok_or_else(|| {
                    format!("{parsed:#010x} is not a target any header can carry")
                })?,
                // **Set only for a checkpoint on a retarget boundary (H-53, #195).** It is what lets a
                // chain cross one: the retarget at `h` needs the timestamp of the block at `h - 2016`,
                // which is the checkpoint when its height is a multiple of 2016. Off a boundary it
                // would be read for nothing, and a range leaving the period is refused instead.
                time: std::env::var("CERTIMINING_CHECKPOINT_TIME")
                    .ok()
                    .map(|raw| {
                        raw.trim()
                            .parse::<u32>()
                            .map_err(|e| format!("CERTIMINING_CHECKPOINT_TIME={raw}: {e}"))
                    })
                    .transpose()?,
            })
        }
        // **A partial checkpoint is worse than none.** A height with the wrong hash, or the right
        // hash with another period's difficulty, describes no block, and the chain would be refused
        // for a reason that reads like a problem with the headers.
        _ => Err(
            "CERTIMINING_CHECKPOINT_HEIGHT, CERTIMINING_CHECKPOINT_HASH and \
             CERTIMINING_CHECKPOINT_BITS are set together, or none is and the committed genesis \
             checkpoint is used"
                .to_string(),
        ),
    }
}

fn headers(bytes: &[u8]) -> Result<Vec<Header>, String> {
    // A trailing partial header is refused rather than dropped: a truncated download would otherwise
    // shorten the chain silently, and a chain that stops early reads as a height nobody attested.
    if !bytes.len().is_multiple_of(HEADER_LEN) {
        return Err(format!(
            "{} bytes is not a whole number of 80-byte headers",
            bytes.len()
        ));
    }
    let mut out = Vec::new();
    for chunk in bytes.chunks_exact(HEADER_LEN) {
        let raw = <[u8; HEADER_LEN]>::try_from(chunk).map_err(|e| e.to_string())?;
        out.push(Header(raw));
    }
    if out.is_empty() {
        return Err(
            "CERTIMINING_HEADERS is empty, and a confirmation against no headers would be \
                    a confirmation against nothing"
                .to_string(),
        );
    }
    Ok(out)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn run() -> Result<String, String> {
    let receipt = read("CERTIMINING_RECEIPT")?;
    let stamped = read("CERTIMINING_STAMPED")?;
    let chain = headers(&read("CERTIMINING_HEADERS")?)?;
    let checkpoint = checkpoint()?;

    let claim = verify_receipt(&receipt, &stamped).map_err(|e| format!("{e:?}"))?;
    let confirmed = confirm(claim, checkpoint, &chain).map_err(|e| format!("{e:?}"))?;

    let mut displayed = confirmed.merkle_root;
    displayed.reverse();
    Ok(format!(
        "confirmed: the receipt's operations reach {}, which is the merkle root of the block at \
         height {}, on a chain of {} header(s) of real work from the checkpoint at height {}",
        hex(&displayed),
        confirmed.height,
        chain.len(),
        checkpoint.height
    ))
}

fn main() -> ExitCode {
    match run() {
        Ok(line) => {
            println!("confirm-anchor-b: {line}");
            ExitCode::SUCCESS
        }
        Err(why) => {
            eprintln!("confirm-anchor-b: {why}");
            ExitCode::FAILURE
        }
    }
}
