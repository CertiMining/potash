use crate::Digest;

/// Keccak-256 over the concatenation of `parts`, without allocating (D-05).
///
/// Each implementation is its own named type (D-20). Code names the hasher it uses; nothing picks
/// one implicitly.
pub trait Hasher {
    fn hashv(parts: &[&[u8]]) -> Digest;
}

/// Keccak-256 in software, through RustCrypto `sha3` 0.10.8 (D-06). Off-chain only.
#[cfg(feature = "native")]
#[derive(Debug, Clone, Copy)]
pub struct NativeKeccak;

#[cfg(feature = "native")]
impl Hasher for NativeKeccak {
    fn hashv(parts: &[&[u8]]) -> Digest {
        use sha3::{Digest as _, Keccak256};
        let mut hasher = Keccak256::new();
        for part in parts {
            hasher.update(part);
        }
        hasher.finalize().into()
    }
}

/// Keccak-256 through Solana's `solana-keccak-hasher` 3.1.0 (D-07). Inside a Solana program this is
/// the `sol_keccak256` syscall; off-chain it is the same `sha3` 0.10.8 in software (D-08).
#[cfg(feature = "solana")]
#[derive(Debug, Clone, Copy)]
pub struct SolanaKeccak;

#[cfg(feature = "solana")]
impl Hasher for SolanaKeccak {
    fn hashv(parts: &[&[u8]]) -> Digest {
        solana_keccak_hasher::hashv(parts).to_bytes()
    }
}
