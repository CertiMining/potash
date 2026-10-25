// SPDX-License-Identifier: MIT OR Apache-2.0
//! Read-only reconciliation of one devnet split-anchoring epoch (D-142).

#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use certimining_client::{
    cluster::Cluster, receipt_digest, root_for_epoch, sequence_lag, verify_receipt, AnchorStatus,
    Fetched, Handoff,
};
use certimining_core::{DalekVerifier, NativeKeccak};
use solana_pubkey::Pubkey;
use std::path::PathBuf;
use std::process::ExitCode;
use std::str::FromStr;

fn env(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|_| format!("{name} is not set"))
}

fn hex32(text: &str) -> Result<[u8; 32], String> {
    let text = text.trim();
    if text.len() != 64 {
        return Err(format!(
            "expected 64 hexadecimal characters, found {}",
            text.len()
        ));
    }
    let mut out = [0u8; 32];
    for (index, pair) in text.as_bytes().chunks_exact(2).enumerate() {
        let pair = std::str::from_utf8(pair).map_err(|e| e.to_string())?;
        *out.get_mut(index).ok_or("more than 32 bytes")? =
            u8::from_str_radix(pair, 16).map_err(|e| format!("{pair:?}: {e}"))?;
    }
    Ok(out)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn run() -> Result<String, String> {
    let epoch_raw = env("CERTIMINING_EPOCH")?;
    let epoch = epoch_raw
        .parse::<u64>()
        .map_err(|e| format!("CERTIMINING_EPOCH={epoch_raw}: {e}"))?;
    let program = Pubkey::from_str(&env("CERTIMINING_PROGRAM_ID")?)
        .map_err(|e| format!("CERTIMINING_PROGRAM_ID: {e}"))?;
    if program.to_bytes() != certimining_checkpoint::ID.to_bytes() {
        return Err("CERTIMINING_PROGRAM_ID is not the program compiled into this checkout".into());
    }
    let batcher = hex32(&env("CERTIMINING_BATCHER_KEY")?)
        .map_err(|e| format!("CERTIMINING_BATCHER_KEY: {e}"))?;
    let handoff_path = PathBuf::from(env("CERTIMINING_HANDOFFS")?).join(format!("{epoch}.handoff"));
    let handoff_bytes =
        std::fs::read(&handoff_path).map_err(|e| format!("{}: {e}", handoff_path.display()))?;
    let handoff = Handoff::decode(&handoff_bytes)
        .map_err(|e| format!("{}: {e:?}", handoff_path.display()))?;
    let root = handoff
        .verify::<DalekVerifier>(&batcher, epoch)
        .map_err(|e| format!("{}: {e:?}", handoff_path.display()))?;

    let receipt_path =
        PathBuf::from(env("CERTIMINING_RECEIPTS")?).join(format!("{epoch}.root.ots"));
    let receipt =
        std::fs::read(&receipt_path).map_err(|e| format!("{}: {e}", receipt_path.display()))?;
    let claim = verify_receipt(&receipt, &root)
        .map_err(|e| format!("{}: {e:?}", receipt_path.display()))?;
    let digest = receipt_digest::<NativeKeccak>(&receipt).ok_or_else(|| {
        format!(
            "{}: receipt is longer than u16::MAX",
            receipt_path.display()
        )
    })?;

    let cluster = Cluster::new(env("CERTIMINING_RPC")?, certimining_checkpoint::ID);
    let checkpoint = match root_for_epoch(&cluster, &certimining_checkpoint::ID, epoch)
        .map_err(|e| format!("checkpoint read: {e:?}"))?
    {
        Fetched::Placed(checkpoint) => checkpoint,
        other => {
            return Err(format!(
                "epoch {epoch} is not a placed checkpoint: {other:?}"
            ))
        }
    };
    if checkpoint.root != root {
        return Err("on-chain root differs from the signed batcher handoff".into());
    }
    if checkpoint.anchor_kind != 1 || checkpoint.receipt_digest != digest {
        return Err(format!(
            "on-chain receipt fields do not match TAG_RCPT || u16_le(len) || receipt; kind={}, chain={}, local={}",
            checkpoint.anchor_kind,
            hex(&checkpoint.receipt_digest),
            hex(&digest)
        ));
    }
    let status = cluster
        .status(epoch)
        .map_err(|e| format!("status read: {e:?}"))?;
    if status != AnchorStatus::Dual {
        return Err(format!("epoch {epoch} status is {status:?}, not Dual"));
    }
    let lag = sequence_lag(&cluster, &certimining_checkpoint::ID, epoch, epoch)
        .map_err(|e| format!("epoch continuity: {e:?}"))?;
    if !lag.is_empty()
        || lag.configuration_moved
        || epoch < lag.start_epoch
        || epoch > lag.last_published
    {
        return Err(format!(
            "epoch {epoch} is outside the contiguous publication range: {lag:?}"
        ));
    }
    Ok(format!(
        "epoch {epoch} reconciled: signed root {}, receipt digest {}, Bitcoin claim height {} (claim only; run confirm-anchor-b with headers for Bitcoin consensus)",
        hex(&root),
        hex(&digest),
        claim.height
    ))
}

fn main() -> ExitCode {
    match run() {
        Ok(message) => {
            println!("reconcile-anchor-cycle: {message}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("reconcile-anchor-cycle: {error}");
            ExitCode::FAILURE
        }
    }
}
