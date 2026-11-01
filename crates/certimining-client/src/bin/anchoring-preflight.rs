// SPDX-License-Identifier: MIT OR Apache-2.0
//! Offline preflight for the split anchoring hosts (D-143).
//!
//! Every host receives the same public identity manifest and only its own private keys. This command
//! proves the public roles are distinct, proves locally held keys match the manifest, rejects secret
//! reuse, and rejects configuration for another role's private key. It never reaches an RPC.

#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use certimining_client::crypto::verify_consensus_signature;
use certimining_client::{refuse_a_readable_key, verify_role_separation, KeyCollision, KeyRole};
use ed25519_dalek::SigningKey;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use std::io::Read;
use std::path::Path;
use std::process::ExitCode;
use std::str::FromStr;

const PRIVATE_ENV: &[&str] = &[
    "CERTIMINING_PROGRAM_KEY",
    "CERTIMINING_DEPLOY_AUTHORITY",
    "CERTIMINING_WORKER_PAYER",
    "CERTIMINING_CHECKPOINT_AUTHORITY",
    "CERTIMINING_BATCHER_SIGNING_KEY",
    "CERTIMINING_MASTER_KEY",
];

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
        let byte = u8::from_str_radix(pair, 16).map_err(|e| format!("{pair:?}: {e}"))?;
        let slot = out.get_mut(index).ok_or("more than 32 bytes")?;
        *slot = byte;
    }
    Ok(out)
}

fn hex64(text: &str) -> Result<[u8; 64], String> {
    let text = text.trim();
    if text.len() != 128 {
        return Err(format!(
            "expected 128 hexadecimal characters, found {}",
            text.len()
        ));
    }
    let mut out = [0u8; 64];
    for (index, pair) in text.as_bytes().chunks_exact(2).enumerate() {
        let pair = std::str::from_utf8(pair).map_err(|e| e.to_string())?;
        let byte = u8::from_str_radix(pair, 16).map_err(|e| format!("{pair:?}: {e}"))?;
        let slot = out.get_mut(index).ok_or("more than 64 bytes")?;
        *slot = byte;
    }
    Ok(out)
}

fn public_id(name: &str) -> Result<[u8; 32], String> {
    Pubkey::from_str(&env(name)?)
        .map(|key| key.to_bytes())
        .map_err(|e| format!("{name}: {e}"))
}

fn read_keypair(name: &str) -> Result<(Keypair, [u8; 32]), String> {
    let path = env(name)?;
    let path = Path::new(&path);
    refuse_a_readable_key(path)?;
    let raw = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut bytes = Vec::new();
    for field in raw
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .split(',')
        .filter(|field| !field.trim().is_empty())
    {
        bytes.push(
            field
                .trim()
                .parse::<u8>()
                .map_err(|e| format!("{}: {e}", path.display()))?,
        );
    }
    let seed = bytes
        .get(..32)
        .and_then(|slice| <[u8; 32]>::try_from(slice).ok())
        .ok_or_else(|| format!("{}: keypair has no 32-byte seed", path.display()))?;
    let keypair =
        Keypair::try_from(bytes.as_slice()).map_err(|e| format!("{}: {e:?}", path.display()))?;
    Ok((keypair, seed))
}

fn read_secret(name: &str) -> Result<[u8; 32], String> {
    let path = env(name)?;
    let path = Path::new(&path);
    refuse_a_readable_key(path)?;
    let raw = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    hex32(&raw).map_err(|e| format!("{}: {e}", path.display()))
}

fn require_match(name: &str, found: [u8; 32], wanted: [u8; 32]) -> Result<(), String> {
    if found == wanted {
        Ok(())
    } else {
        Err(format!(
            "{name} does not match the public identity manifest"
        ))
    }
}

fn forbid_except(allowed: &[&str]) -> Result<(), String> {
    for name in PRIVATE_ENV {
        if !allowed.contains(name) && std::env::var_os(name).is_some() {
            return Err(format!(
                "{name} is configured on this host, but belongs to another anchoring role"
            ));
        }
    }
    Ok(())
}

fn collision(error: KeyCollision) -> String {
    match error {
        KeyCollision::Public { left, right } => {
            format!("public identities for {left:?} and {right:?} are the same")
        }
        KeyCollision::Secret { left, right } => {
            format!("private seeds for {left:?} and {right:?} are the same")
        }
    }
}

fn verify_hardware_possession(authority: &[u8; 32]) -> Result<(), String> {
    const MAX_CHALLENGE_BYTES: u64 = 4_096;
    let challenge_path = env("CERTIMINING_HSM_CHALLENGE")?;
    let challenge_path = Path::new(&challenge_path);
    let challenge_file = std::fs::File::open(challenge_path)
        .map_err(|e| format!("{}: {e}", challenge_path.display()))?;
    let metadata = challenge_file
        .metadata()
        .map_err(|e| format!("{}: {e}", challenge_path.display()))?;
    if !metadata.is_file() {
        return Err(format!(
            "{}: HSM challenge is not a regular file",
            challenge_path.display()
        ));
    }
    if metadata.len() == 0 || metadata.len() > MAX_CHALLENGE_BYTES {
        return Err(format!(
            "{}: HSM challenge length must be 1..={MAX_CHALLENGE_BYTES} bytes",
            challenge_path.display()
        ));
    }
    let mut challenge = Vec::new();
    challenge_file
        .take(MAX_CHALLENGE_BYTES.saturating_add(1))
        .read_to_end(&mut challenge)
        .map_err(|e| format!("{}: {e}", challenge_path.display()))?;
    if challenge.len() > usize::try_from(MAX_CHALLENGE_BYTES).unwrap_or(usize::MAX) {
        return Err(format!(
            "{}: HSM challenge length must be 1..={MAX_CHALLENGE_BYTES} bytes",
            challenge_path.display()
        ));
    }

    let signature_path = env("CERTIMINING_HSM_SIGNATURE")?;
    let signature_path = Path::new(&signature_path);
    let signature_file = std::fs::File::open(signature_path)
        .map_err(|e| format!("{}: {e}", signature_path.display()))?;
    let signature_metadata = signature_file
        .metadata()
        .map_err(|e| format!("{}: {e}", signature_path.display()))?;
    if !signature_metadata.is_file() || signature_metadata.len() > 129 {
        return Err(format!(
            "{}: HSM signature must be a regular file of at most 129 bytes",
            signature_path.display()
        ));
    }
    let mut signature_bytes = Vec::new();
    signature_file
        .take(130)
        .read_to_end(&mut signature_bytes)
        .map_err(|e| format!("{}: {e}", signature_path.display()))?;
    let signature_text = std::str::from_utf8(&signature_bytes)
        .map_err(|e| format!("{}: {e}", signature_path.display()))?;
    let signature =
        hex64(signature_text).map_err(|e| format!("{}: {e}", signature_path.display()))?;
    verify_consensus_signature(authority, &challenge, &signature)
        .map_err(|error| format!("HSM possession challenge failed: {error}"))
}

fn run() -> Result<String, String> {
    let role = std::env::args()
        .nth(1)
        .ok_or("usage: anchoring-preflight deployment|batcher|worker|worker-hsm")?;
    let program = public_id("CERTIMINING_PROGRAM_ID")?;
    require_match(
        "CERTIMINING_PROGRAM_ID",
        program,
        certimining_checkpoint::ID.to_bytes(),
    )?;
    let deploy = public_id("CERTIMINING_DEPLOY_AUTHORITY_ID")?;
    let worker = public_id("CERTIMINING_WORKER_PAYER_ID")?;
    let authority = public_id("CERTIMINING_CHECKPOINT_AUTHORITY_ID")?;
    let batcher = hex32(&env("CERTIMINING_BATCHER_KEY")?)
        .map_err(|e| format!("CERTIMINING_BATCHER_KEY: {e}"))?;
    let public = [
        (KeyRole::ProgramAddress, program),
        (KeyRole::DeployAuthority, deploy),
        (KeyRole::WorkerPayer, worker),
        (KeyRole::CheckpointAuthority, authority),
        (KeyRole::BatcherSigning, batcher),
    ];
    verify_role_separation(&public, &[]).map_err(collision)?;

    let mut secrets = Vec::new();
    match role.as_str() {
        "deployment" => {
            forbid_except(&["CERTIMINING_PROGRAM_KEY", "CERTIMINING_DEPLOY_AUTHORITY"])?;
            let (program_key, program_seed) = read_keypair("CERTIMINING_PROGRAM_KEY")?;
            let (deploy_key, deploy_seed) = read_keypair("CERTIMINING_DEPLOY_AUTHORITY")?;
            require_match(
                "CERTIMINING_PROGRAM_KEY",
                program_key.pubkey().to_bytes(),
                program,
            )?;
            require_match(
                "CERTIMINING_DEPLOY_AUTHORITY",
                deploy_key.pubkey().to_bytes(),
                deploy,
            )?;
            secrets.push((KeyRole::ProgramAddress, program_seed));
            secrets.push((KeyRole::DeployAuthority, deploy_seed));
        }
        "batcher" => {
            forbid_except(&["CERTIMINING_BATCHER_SIGNING_KEY", "CERTIMINING_MASTER_KEY"])?;
            let signing = read_secret("CERTIMINING_BATCHER_SIGNING_KEY")?;
            let derived = SigningKey::from_bytes(&signing).verifying_key().to_bytes();
            require_match("CERTIMINING_BATCHER_SIGNING_KEY", derived, batcher)?;
            secrets.push((KeyRole::BatcherSigning, signing));
            secrets.push((KeyRole::MasterKey, read_secret("CERTIMINING_MASTER_KEY")?));
        }
        "worker" => {
            forbid_except(&[
                "CERTIMINING_WORKER_PAYER",
                "CERTIMINING_CHECKPOINT_AUTHORITY",
            ])?;
            let (worker_key, worker_seed) = read_keypair("CERTIMINING_WORKER_PAYER")?;
            let (authority_key, authority_seed) = read_keypair("CERTIMINING_CHECKPOINT_AUTHORITY")?;
            require_match(
                "CERTIMINING_WORKER_PAYER",
                worker_key.pubkey().to_bytes(),
                worker,
            )?;
            require_match(
                "CERTIMINING_CHECKPOINT_AUTHORITY",
                authority_key.pubkey().to_bytes(),
                authority,
            )?;
            secrets.push((KeyRole::WorkerPayer, worker_seed));
            secrets.push((KeyRole::CheckpointAuthority, authority_seed));
        }
        "worker-hsm" => {
            forbid_except(&["CERTIMINING_WORKER_PAYER"])?;
            let (worker_key, worker_seed) = read_keypair("CERTIMINING_WORKER_PAYER")?;
            require_match(
                "CERTIMINING_WORKER_PAYER",
                worker_key.pubkey().to_bytes(),
                worker,
            )?;
            verify_hardware_possession(&authority)?;
            secrets.push((KeyRole::WorkerPayer, worker_seed));
        }
        _ => {
            return Err(format!(
                "unknown role {role:?}; use deployment, batcher, worker, or worker-hsm"
            ))
        }
    }
    verify_role_separation(&public, &secrets).map_err(collision)?;
    Ok(format!(
        "{role} role passed: five public identities are distinct, local keys match the manifest, and no foreign private-key variable is configured"
    ))
}

fn main() -> ExitCode {
    match run() {
        Ok(message) => {
            println!("anchoring-preflight: {message}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("anchoring-preflight: {error}");
            ExitCode::FAILURE
        }
    }
}
