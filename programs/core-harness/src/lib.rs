//! `core-harness`: a test-only Solana program. It returns the Keccak-256 of its instruction data,
//! computed by certimining-core's `SolanaKeccak`, so KAT-01 can check the on-chain path (D-08).
//! It is test infrastructure and is never deployed (D-17).

// INV-ERR-01 holds here with no exception (D-17).
#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use certimining_core::{Hasher, SolanaKeccak};
use solana_account_info::AccountInfo;
use solana_program_error::ProgramResult;
use solana_pubkey::Pubkey;

solana_program_entrypoint::entrypoint!(process_instruction);

/// Hashes the whole instruction data and hands the 32-byte digest back as return data.
pub fn process_instruction(
    _program_id: &Pubkey,
    _accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    let digest = SolanaKeccak::hashv(&[data]);
    solana_cpi::set_return_data(&digest);
    Ok(())
}
