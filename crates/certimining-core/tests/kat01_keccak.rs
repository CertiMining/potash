// SPDX-License-Identifier: MIT OR Apache-2.0
//! KAT-01 off-chain (§4.1, D-08): both off-chain Keccak-256 paths against the Keccak team's
//! published values. The on-chain path is tested in `programs/core-harness/tests/kat01_onchain.rs`.

// With no hasher feature there is nothing to check, so the reader is not compiled either.
#[cfg(any(feature = "native", feature = "solana"))]
mod kat;

#[cfg(any(feature = "native", feature = "solana"))]
use certimining_core::Hasher;

/// Every published case hashes to its published digest. The message is also split in two at
/// several points, including the 136-byte rate boundary, and must hash the same (D-05).
#[cfg(any(feature = "native", feature = "solana"))]
fn matches_published_values<H: Hasher>(name: &str) {
    for c in kat::cases() {
        assert_eq!(H::hashv(&[&c.msg]), c.md, "{name}, Len = {} bits", c.bits);
        let len = c.msg.len();
        for cut in [0, 1.min(len), len / 2, 136.min(len), len] {
            let (a, b) = c.msg.split_at(cut);
            assert_eq!(
                H::hashv(&[a, b]),
                c.md,
                "{name}, Len = {} bits, split at byte {cut}",
                c.bits
            );
        }
    }
}

#[cfg(feature = "native")]
#[test]
fn kat01_native_keccak() {
    matches_published_values::<certimining_core::NativeKeccak>("NativeKeccak");
}

/// Off-chain, this runs `solana-keccak-hasher`'s software path. The syscall path is on-chain only.
#[cfg(feature = "solana")]
#[test]
fn kat01_solana_keccak_off_chain() {
    matches_published_values::<certimining_core::SolanaKeccak>("SolanaKeccak (off-chain)");
}
