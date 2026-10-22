// SPDX-License-Identifier: MIT OR Apache-2.0
//! The batcher, which builds an epoch and signs the handoff the worker publishes (H-13, D-117, D-139).
//!
//! **This is the half D-139 divided the cycle into and nothing implemented.** `anchor-b-worker`
//! refuses to start without a valid handoff, and until this binary existed nothing wrote one — so the
//! worker could not run and D-117 described a process that was not there. The two now exist and the
//! division is real rather than described.
//!
//! **This process holds the two keys the worker must not.** `k_master`, from which every epoch key is
//! derived, and a dedicated batcher signing key. RES-03 rests count-hiding entirely on `k_master`'s
//! custody, which is why D-139 keeps it out of the process that runs unattended: compromising the
//! worker buys a wrong root, and compromising this buys the retrospective record count of every epoch
//! the log has published.
//!
//! **The batcher signing key is not the checkpoint authority** (owner, 22 October 2026). D-88
//! separates the authority from anything structural because it is the one key that runs unattended;
//! making it also the key that authorises what gets published would undo that. This refuses to start
//! if its own key path is the authority's, and it never reads the authority at all — which is the
//! stronger property and the reason the check here is only about paths.
//!
//! Neither key is printed or logged. The batcher's **public** half is printed, because the worker has
//! to be configured with it and a public key is not key material.
//!
//! ```text
//! CERTIMINING_MASTER_KEY=$HOME/.config/certimining/k-master \
//! CERTIMINING_BATCHER_SIGNING_KEY=$HOME/.config/certimining/batcher-signing-key \
//! CERTIMINING_HANDOFFS=$HOME/.local/share/potash/handoffs \
//! CERTIMINING_EPOCH=20739 \
//!     cargo run -p certimining-client --features cluster,ots --bin batcher-handoff
//! ```
//!
//! `CERTIMINING_HEIGHT` defaults to 8, §1.8's deployed default. `CERTIMINING_SUBMISSIONS` is a file of
//! `<32 hex submission id> <64 hex leaf digest>` lines; without it the epoch holds no records, which
//! §1.4 permits and V-P-07 covers — a quiet day is a real epoch and not a missing one.
//!
//! **Behind `cluster,ots` like the worker**, although it reaches no network and no calendar. The point
//! of the gate is that the default build and every test above it stay free of keys and of a network,
//! and this is a process that holds two keys.
#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use certimining_client::{day_index, refuse_a_readable_key, refuse_to_write, Handoff, HANDOFF_LEN};
use certimining_core::{
    Digest, HandoffPreimage, NativeKeccak, Preimage, PreimageBuf, SubmissionId,
};
use certimining_log::{BuiltEpoch, EpochTree};
use ed25519_dalek::{Signer as _, SigningKey};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

/// §1.8's deployed default.
const DEFAULT_HEIGHT: u8 = 8;

/// Where D-117 puts the one key that runs unattended. This process refuses to be configured with it.
const AUTHORITY: &str = ".config/certimining/checkpoint-authority.json";

fn env(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|_| format!("{name} is not set"))
}

/// 64 hexadecimal characters as the 32 bytes they spell.
fn hex32(text: &str) -> Result<[u8; 32], String> {
    let trimmed = text.trim();
    if trimmed.len() != 64 {
        return Err(format!(
            "expected 64 hexadecimal characters, found {}",
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
    Ok(out)
}

/// 32 bytes read from a file this process refuses to read at any mode but 0600.
///
/// **The mode is checked before the bytes are opened** (D-117). The error names the path and never
/// the contents, which is the whole point of the helper being shared with the worker.
fn secret_at(path: &Path) -> Result<[u8; 32], String> {
    // The helper's message already names the path, so prefixing it again would print it twice.
    refuse_a_readable_key(path)?;
    let raw = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    hex32(&raw).map_err(|e| format!("{}: {e}", path.display()))
}

/// Refuses a batcher key that is the checkpoint authority's own file.
///
/// **Paths, because this process never reads the authority.** Comparing public keys would mean
/// opening it, and a batcher that reads the unattended key has given up the separation this check
/// exists to keep. `canonicalize` is what makes a symlink or a relative path fail the comparison the
/// same way the direct path does.
fn refuse_the_authoritys_key(path: &Path) -> Result<(), String> {
    let home = std::env::var("HOME").map_err(|_| "HOME is not set".to_string())?;
    let authority = PathBuf::from(&home).join(AUTHORITY);
    // Both comparisons, because each misses what the other catches. Canonicalising resolves a
    // symlink or a relative path to the same file; comparing the paths as written catches the case
    // where neither exists yet, which is a machine being set up and the easiest moment to point the
    // batcher at the wrong file.
    let same = path == authority
        || match (path.canonicalize(), authority.canonicalize()) {
            (Ok(a), Ok(b)) => a == b,
            // The authority not being there is the ordinary case on a machine that only batches.
            _ => false,
        };
    if same {
        return Err(format!(
            "the batcher signing key is {}, which is the checkpoint authority. D-88 separates the \
             one key that runs unattended from anything structural, and signing what gets published \
             with it would undo that.",
            path.display()
        ));
    }
    Ok(())
}

/// `<32 hex submission id> <64 hex leaf digest>` per line, or no file and no records.
fn submissions(path: Option<&Path>) -> Result<Vec<(SubmissionId, Digest)>, String> {
    let Some(path) = path else {
        return Ok(Vec::new());
    };
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut out = Vec::new();
    for (line_number, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let at = line_number.saturating_add(1);
        let mut fields = line.split_whitespace();
        let (Some(id), Some(leaf)) = (fields.next(), fields.next()) else {
            return Err(format!(
                "{}:{at}: a line is a submission id and a leaf digest",
                path.display()
            ));
        };
        if fields.next().is_some() {
            return Err(format!("{}:{at}: more than two fields", path.display()));
        }
        if id.len() != 32 {
            return Err(format!(
                "{}:{at}: a submission id is 32 hexadecimal characters, found {}",
                path.display(),
                id.len()
            ));
        }
        let mut submission = [0u8; 16];
        for (i, pair) in id.as_bytes().chunks_exact(2).enumerate() {
            let hex = std::str::from_utf8(pair).map_err(|e| e.to_string())?;
            let byte = u8::from_str_radix(hex, 16).map_err(|e| format!("{hex:?}: {e}"))?;
            match submission.get_mut(i) {
                Some(slot) => *slot = byte,
                None => return Err(format!("{}:{at}: more than 16 bytes", path.display())),
            }
        }
        let digest = hex32(leaf).map_err(|e| format!("{}:{at}: {e}", path.display()))?;
        out.push((submission, digest));
    }
    Ok(out)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn run() -> Result<String, String> {
    let epoch: u64 = {
        let raw = env("CERTIMINING_EPOCH")?;
        raw.trim()
            .parse()
            .map_err(|e| format!("CERTIMINING_EPOCH={raw}: {e}"))?
    };
    let height: u8 = match std::env::var("CERTIMINING_HEIGHT") {
        Ok(raw) => raw
            .trim()
            .parse()
            .map_err(|e| format!("CERTIMINING_HEIGHT={raw}: {e}"))?,
        Err(_) => DEFAULT_HEIGHT,
    };
    let handoffs = PathBuf::from(env("CERTIMINING_HANDOFFS")?);
    let signing_path = PathBuf::from(env("CERTIMINING_BATCHER_SIGNING_KEY")?);
    refuse_the_authoritys_key(&signing_path)?;

    // **The day index this process believes it is, from its own clock.** `publish_checkpoint` reads
    // the chain's, and v0.2.4 refuses an epoch ahead of it; refusing here costs nothing instead.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("the clock is before the unix epoch: {e}"))?;
    let seconds = i64::try_from(now.as_secs()).map_err(|e| format!("the clock: {e}"))?;
    let today = day_index(seconds).ok_or_else(|| "the clock has no day index".to_string())?;

    let records = submissions(
        std::env::var("CERTIMINING_SUBMISSIONS")
            .ok()
            .map(PathBuf::from)
            .as_deref(),
    )?;

    // The keys, last: everything that can fail without one has failed by now.
    let master = secret_at(&PathBuf::from(env("CERTIMINING_MASTER_KEY")?))?;
    let signing = SigningKey::from_bytes(&secret_at(&signing_path)?);

    let built = <BuiltEpoch as EpochTree>::build::<NativeKeccak>(epoch, height, &master, &records)
        .map_err(|e| format!("the epoch does not build: {e:?}"))?;
    let root = built.root();

    let mut buf = PreimageBuf::new();
    HandoffPreimage {
        epoch,
        height,
        root,
    }
    .write_preimage(&mut buf)
    .map_err(|e| format!("the handoff preimage does not encode: {e:?}"))?;
    let handoff = Handoff {
        epoch,
        height,
        root,
        batcher_key: signing.verifying_key().to_bytes(),
        signature: signing.sign(buf.as_bytes()).to_bytes(),
    };
    let bytes: [u8; HANDOFF_LEN] = handoff.encode();

    let destination = handoffs.join(format!("{epoch}.handoff"));
    let existing = std::fs::read(&destination).ok();
    refuse_to_write(epoch, today, existing.as_deref(), &bytes)
        .map_err(|e| format!("{}: {e:?}", destination.display()))?;
    std::fs::create_dir_all(&handoffs).map_err(|e| format!("{}: {e}", handoffs.display()))?;
    std::fs::write(&destination, bytes).map_err(|e| format!("{}: {e}", destination.display()))?;

    Ok(format!(
        "epoch {epoch} at height {height}, {} record(s), root {}, written to {}. The worker verifies \
         it against CERTIMINING_BATCHER_KEY={}, which is the public half and the only part of either \
         key this prints.",
        records.len(),
        hex(&root),
        destination.display(),
        hex(&handoff.batcher_key)
    ))
}

fn main() -> ExitCode {
    match run() {
        Ok(line) => {
            println!("batcher-handoff: {line}");
            ExitCode::SUCCESS
        }
        Err(why) => {
            eprintln!("batcher-handoff: {why}");
            ExitCode::FAILURE
        }
    }
}
