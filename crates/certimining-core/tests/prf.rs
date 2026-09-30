// SPDX-License-Identifier: MIT OR Apache-2.0
//! E-06: §1.1's PRF, its three use codes and the widths D-59 fixes.
//!
//! Every expected preimage here is assembled from the specification's own literals: the tag as
//! `*b"CMv1PRF0"` rather than the crate's constant, and the length as two little-endian bytes rather
//! than whatever the writer chose. A test that took either from the engine would stay green while
//! the engine drifted, which is what E-02's first review found.
//!
//! These cases need no cryptography, so they run in every feature set against a stand-in hasher.
//! The real construction is measured where it matters, in the epoch tree's privacy tests.

use certimining_core::{
    epoch_key, padding_prf, read_tag, slot_seed, Digest, Hasher, Preimage, PreimageBuf,
    PreimageSink, PrfPreimage, RegistryError, SubmissionId, MAX_PRF_INPUT_LEN, PRF_USE_EPOCH_KEY,
    PRF_USE_PADDING, PRF_USE_SLOT,
};

/// §1.2's tag, transcribed here rather than read from the crate.
const SPEC_TAG_PRF: [u8; 8] = *b"CMv1PRF0";

const KEY: Digest = [0x5a; 32];
const ID: SubmissionId = [0x77; 16];

/// A stand-in hasher: not cryptographic, but distinct inputs give distinct digests, which is all
/// these structural cases need. It keeps them running under every feature set.
struct MixHash;

impl Hasher for MixHash {
    fn hashv(parts: &[&[u8]]) -> Digest {
        let mut state: u64 = 0xcbf2_9ce4_8422_2325;
        for part in parts {
            for byte in *part {
                state ^= u64::from(*byte);
                state = state.wrapping_mul(0x0000_0100_0000_01b3);
            }
        }
        let mut out = [0u8; 32];
        for (i, chunk) in out.chunks_mut(8).enumerate() {
            chunk.copy_from_slice(&(state ^ (i as u64)).to_le_bytes());
        }
        out
    }
}

/// `TAG_PRF ‖ k ‖ len(x) ‖ x`, built from the specification's text (§1.1, D-59).
fn expected_preimage(key: &Digest, input: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&SPEC_TAG_PRF);
    out.extend_from_slice(key);
    out.extend_from_slice(&(input.len() as u16).to_le_bytes());
    out.extend_from_slice(input);
    out
}

fn written(key: &Digest, input: &[u8]) -> PreimageBuf {
    let mut buf = PreimageBuf::new();
    PrfPreimage { key, input }
        .write_preimage(&mut buf)
        .expect("this input is one schema 1 uses");
    buf
}

#[test]
fn the_use_codes_are_the_specifications() {
    assert_eq!(PRF_USE_EPOCH_KEY, 0x01, "§1.1: epoch-key derivation");
    assert_eq!(PRF_USE_SLOT, 0x02, "§1.1: slot assignment");
    assert_eq!(PRF_USE_PADDING, 0x03, "§1.1: padding");
}

#[test]
fn the_preimage_is_the_tag_the_key_the_length_and_the_input() {
    for input in [
        vec![PRF_USE_EPOCH_KEY, 1, 0, 0, 0, 0, 0, 0, 0],
        {
            let mut x = vec![PRF_USE_SLOT];
            x.extend_from_slice(&ID);
            x
        },
        vec![PRF_USE_PADDING, 0x0d, 0x00],
    ] {
        assert_eq!(
            written(&KEY, &input).as_bytes(),
            expected_preimage(&KEY, &input),
            "§1.1's construction for use code {:#04x}",
            input.first().copied().unwrap_or_default()
        );
    }
}

#[test]
fn the_three_preimages_are_the_lengths_d59_states() {
    let mut slot_input = vec![PRF_USE_SLOT];
    slot_input.extend_from_slice(&ID);
    assert_eq!(
        written(&KEY, &[PRF_USE_EPOCH_KEY, 0, 0, 0, 0, 0, 0, 0, 0]).len(),
        51,
        "epoch key: 8 + 32 + 2 + 9"
    );
    assert_eq!(
        written(&KEY, &slot_input).len(),
        59,
        "slot: 8 + 32 + 2 + 17"
    );
    assert_eq!(
        written(&KEY, &[PRF_USE_PADDING, 0, 0]).len(),
        45,
        "padding: 8 + 32 + 2 + 3"
    );
}

#[test]
fn the_length_prefix_is_a_u16_little_endian() {
    let mut input = vec![PRF_USE_SLOT];
    input.extend_from_slice(&ID);
    let bytes = written(&KEY, &input);
    assert_eq!(
        &bytes.as_bytes()[40..42],
        &[0x11, 0x00],
        "INV-ENC-04: seventeen bytes of input, prefixed little-endian in two"
    );
}

#[test]
fn the_tag_opens_the_preimage_and_never_appears_in_the_input() {
    let bytes = written(&KEY, &[PRF_USE_PADDING, 0, 0]);
    assert_eq!(
        read_tag(bytes.as_bytes()),
        Ok(SPEC_TAG_PRF),
        "INV-ENC-01: the tag is first"
    );
    let input_starts_at = 8 + 32 + 2;
    assert_eq!(
        bytes.as_bytes()[input_starts_at],
        PRF_USE_PADDING,
        "§1.1: x begins with its use code, and the tag is never repeated in it"
    );
}

#[test]
fn the_epoch_key_is_the_prf_of_the_use_code_and_the_epoch() {
    let epoch = 19_989u64;
    let mut input = vec![PRF_USE_EPOCH_KEY];
    input.extend_from_slice(&epoch.to_le_bytes());
    assert_eq!(
        epoch_key::<MixHash>(&KEY, epoch),
        Ok(MixHash::hashv(&[&expected_preimage(&KEY, &input)])),
        "INV-TREE-05: k_e = PRF(k_master, 0x01 ‖ e_le)"
    );
}

#[test]
fn every_epoch_gets_its_own_key() {
    let first = epoch_key::<MixHash>(&KEY, 1).expect("derives");
    let second = epoch_key::<MixHash>(&KEY, 2).expect("derives");
    assert_ne!(first, second, "INV-TREE-05: one key per epoch");
}

#[test]
fn the_slot_seed_is_the_prf_of_the_use_code_and_the_identifier() {
    let mut input = vec![PRF_USE_SLOT];
    input.extend_from_slice(&ID);
    assert_eq!(
        slot_seed::<MixHash>(&KEY, &ID),
        Ok(MixHash::hashv(&[&expected_preimage(&KEY, &input)])),
        "§1.4: PRF(k_e, 0x02 ‖ submission_id)"
    );
}

#[test]
fn padding_is_the_prf_of_the_use_code_and_the_slot_index() {
    let slot = 0x0102u16;
    let mut input = vec![PRF_USE_PADDING];
    input.extend_from_slice(&slot.to_le_bytes());
    assert_eq!(
        padding_prf::<MixHash>(&KEY, slot),
        Ok(MixHash::hashv(&[&expected_preimage(&KEY, &input)])),
        "§1.4: PRF(k_e, 0x03 ‖ slot_index_le)"
    );
    assert_ne!(
        padding_prf::<MixHash>(&KEY, 1),
        padding_prf::<MixHash>(&KEY, 2),
        "every slot's padding is its own"
    );
}

#[test]
fn the_use_codes_separate_inputs_that_would_otherwise_collide() {
    let payload = [0u8; 8];
    let mut first = vec![PRF_USE_EPOCH_KEY];
    first.extend_from_slice(&payload);
    let mut second = vec![PRF_USE_SLOT];
    second.extend_from_slice(&payload);
    assert_ne!(
        written(&KEY, &first).as_bytes(),
        written(&KEY, &second).as_bytes(),
        "§1.1: the use code is what separates the three"
    );
}

#[test]
fn an_input_without_a_use_code_is_refused() {
    let mut buf = PreimageBuf::new();
    assert_eq!(
        PrfPreimage {
            key: &KEY,
            input: &[]
        }
        .write_preimage(&mut buf),
        Err(RegistryError::MalformedPayload),
        "§1.1: x carries a use code, so an empty x is not an input this PRF has"
    );
    assert_eq!(buf.len(), 0, "a refusal writes nothing");
}

#[test]
fn an_input_longer_than_schema_one_uses_is_refused() {
    let long = vec![PRF_USE_SLOT; MAX_PRF_INPUT_LEN + 1];
    let mut buf = PreimageBuf::new();
    assert_eq!(
        PrfPreimage {
            key: &KEY,
            input: &long
        }
        .write_preimage(&mut buf),
        Err(RegistryError::RecordTooLarge),
        "D-59: seventeen bytes is the longest x schema 1 has, and a fourth use needs a decision"
    );
}

#[test]
fn a_refused_write_leaves_the_sink_as_it_was() {
    let mut buf = PreimageBuf::new();
    buf.write(&[0xab; 16]).expect("room for sixteen bytes");
    let long = vec![PRF_USE_SLOT; MAX_PRF_INPUT_LEN + 1];
    assert!(PrfPreimage {
        key: &KEY,
        input: &long
    }
    .write_preimage(&mut buf)
    .is_err());
    assert_eq!(
        buf.as_bytes(),
        &[0xab; 16],
        "D-03: a refusal leaves no fragment of a preimage behind"
    );
}
