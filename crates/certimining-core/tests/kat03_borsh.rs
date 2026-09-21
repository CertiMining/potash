//! KAT-03 (§4.1): every writer's bytes equal Borsh's encoding of the same fields, in the same
//! order.
//!
//! Borsh is a test-only oracle (D-34): the digest path holds no Borsh dependency, so this test is
//! what keeps the two in step. Each expected value is built from the spec's field order with the
//! tag written as a literal, never read from the crate's constants.
//!
//! The committed fixtures under `vectors/`, with their manifest, arrive with the generator at E-05
//! (D-35); until then the expected bytes are built here.

use borsh::to_vec;
use certimining_core::{
    AssetPreimage, Digest, GenesisHeadPreimage, LeafPreimage, NodePreimage, PaddingPreimage,
    Preimage, PreimageBuf, RealLeafPreimage, SpiPreimage, StepHeadPreimage,
};

const C: Digest = [0x11; 32];
const PAYLOAD: Digest = [0x22; 32];
const ASSESSMENT: Digest = [0x33; 32];
const QP: [u8; 32] = [0x44; 32];
const LEAF: Digest = [0x55; 32];
const PREV: Digest = [0x66; 32];
const PRF_OUT: Digest = [0x77; 32];
const J: &[u8; 4] = b"CABC";
const R: &[u8; 8] = b"MTO00001";
const SUBMISSION: [u8; 16] = [0x88; 16];

fn bytes_of<P: Preimage>(p: &P) -> Vec<u8> {
    let mut buf = PreimageBuf::new();
    p.write_preimage(&mut buf).expect("the preimage fits");
    buf.as_bytes().to_vec()
}

/// Borsh-encodes each field and concatenates them, which is what Borsh does for a struct.
fn borsh_fields(fields: &[Vec<u8>]) -> Vec<u8> {
    fields.concat()
}

#[test]
fn kat03_the_asset_preimage_is_borsh_of_its_fields() {
    let tenure = b"BCTENURE1043A";
    let want = borsh_fields(&[
        to_vec(b"CMv1ASST").unwrap(),
        to_vec(J).unwrap(),
        to_vec(R).unwrap(),
        to_vec(&13u16).unwrap(),
        tenure.to_vec(),
    ]);
    let p = AssetPreimage {
        jurisdiction: J,
        registry: R,
        tenure,
    };
    assert_eq!(bytes_of(&p), want);
}

#[test]
fn kat03_the_head_preimages_are_borsh_of_their_fields() {
    let genesis = borsh_fields(&[
        to_vec(b"CMv1HEAD").unwrap(),
        to_vec(&C).unwrap(),
        to_vec(&1u16).unwrap(),
    ]);
    assert_eq!(
        bytes_of(&GenesisHeadPreimage {
            asset_commitment: C,
            schema_version: 1
        }),
        genesis
    );

    let step = borsh_fields(&[
        to_vec(b"CMv1HEAD").unwrap(),
        to_vec(&PREV).unwrap(),
        to_vec(&LEAF).unwrap(),
    ]);
    assert_eq!(
        bytes_of(&StepHeadPreimage {
            prev_head: PREV,
            leaf: LEAF
        }),
        step
    );
}

#[test]
fn kat03_the_leaf_preimage_is_borsh_of_its_fields() {
    let want = borsh_fields(&[
        to_vec(b"CMv1LEAF").unwrap(),
        to_vec(&C).unwrap(),
        to_vec(&7u64).unwrap(),
        to_vec(&PAYLOAD).unwrap(),
        to_vec(&ASSESSMENT).unwrap(),
        to_vec(&QP).unwrap(),
        to_vec(&2u8).unwrap(),
        to_vec(&1_760_000_000i64).unwrap(),
        to_vec(&(-3i64)).unwrap(),
    ]);
    assert_eq!(want.len(), 161);
    let p = LeafPreimage {
        asset_commitment: C,
        seq: 7,
        payload_digest: PAYLOAD,
        assessment_digest: ASSESSMENT,
        qp_key: QP,
        category: 2,
        effective_at: 1_760_000_000,
        change_identified_at: -3,
    };
    assert_eq!(bytes_of(&p), want);
}

#[test]
fn kat03_the_tree_preimages_are_borsh_of_their_fields() {
    assert_eq!(
        bytes_of(&RealLeafPreimage { leaf: LEAF }),
        borsh_fields(&[to_vec(b"CMv1MTL0").unwrap(), to_vec(&LEAF).unwrap()])
    );
    assert_eq!(
        bytes_of(&PaddingPreimage {
            prf_output: PRF_OUT
        }),
        borsh_fields(&[to_vec(b"CMv1PADD").unwrap(), to_vec(&PRF_OUT).unwrap()])
    );
    assert_eq!(
        bytes_of(&NodePreimage {
            left: PREV,
            right: LEAF
        }),
        borsh_fields(&[
            to_vec(b"CMv1MTN1").unwrap(),
            to_vec(&PREV).unwrap(),
            to_vec(&LEAF).unwrap()
        ])
    );
}

#[test]
fn kat03_the_spi_preimage_is_borsh_of_its_fields() {
    let want = borsh_fields(&[
        to_vec(b"CMv1SPI0").unwrap(),
        to_vec(&LEAF).unwrap(),
        to_vec(&SUBMISSION).unwrap(),
        to_vec(&20_361u64).unwrap(),
        to_vec(&2u8).unwrap(),
    ]);
    assert_eq!(want.len(), 65);
    let p = SpiPreimage {
        leaf: LEAF,
        submission_id: SUBMISSION,
        promised_epoch: 20_361,
        max_merge_delay: 2,
    };
    assert_eq!(bytes_of(&p), want);
}

/// D-34: Borsh frames a byte string with a `u32`; INV-ENC-04 uses a `u16`, and INV-ENC-04 governs.
/// This is the one place the two rules differ, and the tenure is the only variable-length field in
/// schema 1.
#[test]
fn kat03_the_tenure_carries_inv_enc_04s_u16_not_borshs_u32() {
    let tenure = b"BCTENURE1043A".to_vec();
    let borsh_vector = to_vec(&tenure).unwrap();
    assert_eq!(
        borsh_vector[..4],
        13u32.to_le_bytes(),
        "Borsh frames with a u32"
    );

    let p = AssetPreimage {
        jurisdiction: J,
        registry: R,
        tenure: &tenure,
    };
    let ours = bytes_of(&p);
    // 8 tag + 4 jurisdiction + 8 registry = 20 bytes before the length.
    assert_eq!(ours[20..22], 13u16.to_le_bytes());
    assert_eq!(ours.len(), 8 + 4 + 8 + 2 + 13);
    assert_ne!(ours.len(), 8 + 4 + 8 + 4 + 13, "not Borsh's u32 framing");
}

/// Borsh writes a fixed-size array as its raw bytes, with no length in front, which is what
/// INV-ENC-02 requires of a digest.
#[test]
fn kat03_borsh_writes_a_digest_as_thirty_two_raw_bytes() {
    assert_eq!(to_vec(&C).unwrap(), C.to_vec());
    assert_eq!(to_vec(&C).unwrap().len(), 32);
}
