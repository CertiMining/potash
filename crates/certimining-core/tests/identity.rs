//! E-02: canonical tenure identifiers and the asset commitment (§1.3; D-22 to D-26), including
//! V-P-01 and V-N-21. Canonicalization never hashes, so most tests use a stand-in hasher and run
//! in every feature set; the commitment tests use the real hashers.

use certimining_core::{AssetId, AssetIdentity, Digest, Hasher, RegistryError, MAX_RAW_TENURE_LEN};

const FAILED: RegistryError = RegistryError::CanonicalizationFailed;

/// A stand-in hasher for tests that never reach `commitment`'s hashing.
struct NoHash;

impl Hasher for NoHash {
    fn hashv(_parts: &[&[u8]]) -> Digest {
        [0; 32]
    }
}

type Id = AssetId<NoHash>;

fn canon(raw: &str) -> Result<Vec<u8>, RegistryError> {
    Id::canonicalize(raw).map(|t| t.to_vec())
}

#[test]
fn v_p_01_two_spellings_give_one_canonical_form() {
    assert_eq!(canon("bc-tenure 1043-a"), Ok(b"BCTENURE1043A".to_vec()));
    assert_eq!(canon("BC_TENURE1043A"), Ok(b"BCTENURE1043A".to_vec()));
}

#[test]
fn v_n_21_an_empty_canonical_form_is_0x11() {
    for raw in ["", "   ", "-_./", "œæß", "ı"] {
        assert_eq!(canon(raw), Err(FAILED), "{raw:?}");
    }
}

/// D-22: NFKD keeps the base letter of an accented one, so both spellings are one identity.
#[test]
fn d22_an_accented_letter_keeps_its_base_letter() {
    assert_eq!(canon("Mine Élan 12"), Ok(b"MINEELAN12".to_vec()));
    assert_eq!(canon("Mine Élan 12"), canon("Mine Elan 12"));
}

/// D-22: compatibility forms fold to ASCII: full-width B, circled one, the fi ligature.
#[test]
fn d22_compatibility_forms_fold_to_ascii() {
    assert_eq!(canon("Ｂ①ﬁ"), Ok(b"B1FI".to_vec()));
}

/// D-22's named limitation: letters with no decomposition are removed, not transliterated.
#[test]
fn d22_letters_without_a_decomposition_are_removed() {
    assert_eq!(canon("Cœur 7"), Ok(b"CUR7".to_vec()));
    assert_eq!(canon("straße 3"), Ok(b"STRAE3".to_vec()));
}

/// D-23: only a to z are uppercased. Dotless ı would become I under Unicode rules; here the
/// filter removes it.
#[test]
fn d23_only_a_to_z_are_uppercased() {
    assert_eq!(canon("ıd 1"), Ok(b"D1".to_vec()));
}

#[test]
fn d24_invalid_utf8_is_0x11() {
    assert_eq!(Id::canonicalize_bytes(&[0x41, 0xFF, 0x42]), Err(FAILED));
}

#[test]
fn d25_raw_input_is_capped_at_256_bytes() {
    let at_limit = format!("A{}", " ".repeat(MAX_RAW_TENURE_LEN - 1));
    assert_eq!(at_limit.len(), 256);
    assert_eq!(canon(&at_limit), Ok(b"A".to_vec()));
    let over = format!("A{}", " ".repeat(MAX_RAW_TENURE_LEN));
    assert_eq!(canon(&over), Err(FAILED));
}

#[test]
fn the_canonical_form_is_at_most_64_bytes() {
    assert_eq!(canon(&"A".repeat(64)).map(|t| t.len()), Ok(64));
    assert_eq!(canon(&"A".repeat(65)), Err(FAILED));
}

#[test]
fn d26_commitment_refuses_a_non_canonical_tenure() {
    let too_long = [b'A'; 65];
    for tenure in [
        &b""[..],
        b"bctenure",
        b"BC-TENURE",
        b"BC TENURE",
        &too_long[..],
    ] {
        assert_eq!(
            Id::commitment(b"CABC", b"MTO00001", tenure),
            Err(FAILED),
            "{tenure:?}"
        );
    }
}

#[cfg(feature = "native")]
mod with_native_keccak {
    use super::*;
    use certimining_core::{NativeKeccak, TAG_ASSET};

    type N = AssetId<NativeKeccak>;
    const J: &[u8; 4] = b"CABC";
    const R: &[u8; 8] = b"MTO00001";

    /// The commitment is Keccak-256 over TAG_ASSET ‖ J ‖ R ‖ len(T) as a little-endian u16 ‖ T
    /// (§1.3, INV-ENC-01, INV-ENC-02, INV-ENC-04), built here byte by byte.
    #[test]
    fn the_commitment_hashes_the_tagged_preimage() {
        let tenure = b"BCTENURE1043A";
        let mut preimage = Vec::new();
        preimage.extend_from_slice(&TAG_ASSET);
        preimage.extend_from_slice(J);
        preimage.extend_from_slice(R);
        preimage.extend_from_slice(&13u16.to_le_bytes());
        preimage.extend_from_slice(tenure);
        assert_eq!(preimage.len(), 8 + 4 + 8 + 2 + 13);
        assert_eq!(
            N::commitment(J, R, tenure),
            Ok(NativeKeccak::hashv(&[&preimage]))
        );
    }

    #[test]
    fn v_p_01_two_spellings_give_one_commitment() {
        let a = N::canonicalize("bc-tenure 1043-a").expect("canonical");
        let b = N::canonicalize("BC_TENURE1043A").expect("canonical");
        assert_eq!(N::commitment(J, R, &a), N::commitment(J, R, &b));
    }

    #[test]
    fn a_different_jurisdiction_or_registry_gives_a_different_commitment() {
        let t = b"BCTENURE1043A";
        let base = N::commitment(J, R, t);
        assert_ne!(base, N::commitment(b"CAON", R, t));
        assert_ne!(base, N::commitment(J, b"MTO00002", t));
    }
}

/// Both hashers must produce the same commitment for the same input (D-20).
#[cfg(all(feature = "native", feature = "solana"))]
#[test]
fn both_hashers_give_the_same_commitment() {
    use certimining_core::{NativeKeccak, SolanaKeccak};
    let t = b"BCTENURE1043A";
    assert_eq!(
        AssetId::<NativeKeccak>::commitment(b"CABC", b"MTO00001", t),
        AssetId::<SolanaKeccak>::commitment(b"CABC", b"MTO00001", t)
    );
}
