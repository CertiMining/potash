//! E-03: the byte layout of every preimage writer (§1.2, §1.3, §1.4, §1.6), the tag check behind
//! V-N-09, and the sink's limit.
//!
//! Expected bytes are written out from the spec, never taken from the crate's own constants, so a
//! wrong tag or a wrong width in the crate fails these tests.

use certimining_core::{
    check_tag, read_tag, AssetPreimage, Digest, GenesisHeadPreimage, LeafPreimage, NodePreimage,
    PaddingPreimage, Preimage, PreimageBuf, PreimageSink, RealLeafPreimage, RegistryError,
    SpiPreimage, StepHeadPreimage,
};

const C: Digest = [0x11; 32];
const PAYLOAD: Digest = [0x22; 32];
const ASSESSMENT: Digest = [0x33; 32];
const QP: [u8; 32] = [0x44; 32];
const LEAF: Digest = [0x55; 32];
const PREV: Digest = [0x66; 32];
const PRF_OUT: Digest = [0x77; 32];
const TENURE: &[u8] = b"BCTENURE1043A";
const J: &[u8; 4] = b"CABC";
const R: &[u8; 8] = b"MTO00001";
const SUBMISSION: [u8; 16] = [0x88; 16];

fn bytes_of<P: Preimage>(p: &P) -> Vec<u8> {
    let mut buf = PreimageBuf::new();
    p.write_preimage(&mut buf).expect("the preimage fits");
    buf.as_bytes().to_vec()
}

fn asset() -> AssetPreimage<'static> {
    AssetPreimage {
        jurisdiction: J,
        registry: R,
        tenure: TENURE,
    }
}

fn leaf() -> LeafPreimage {
    LeafPreimage {
        asset_commitment: C,
        seq: 7,
        payload_digest: PAYLOAD,
        assessment_digest: ASSESSMENT,
        qp_key: QP,
        category: 2,
        effective_at: 1_760_000_000,
        change_identified_at: -3,
    }
}

#[test]
fn the_asset_preimage_has_the_layout_of_1_3() {
    let mut want = Vec::new();
    want.extend_from_slice(b"CMv1ASST");
    want.extend_from_slice(J);
    want.extend_from_slice(R);
    want.extend_from_slice(&13u16.to_le_bytes());
    want.extend_from_slice(TENURE);
    assert_eq!(want.len(), 8 + 4 + 8 + 2 + 13);
    assert_eq!(bytes_of(&asset()), want);
}

#[test]
fn the_genesis_head_preimage_has_the_layout_of_1_3() {
    let mut want = Vec::new();
    want.extend_from_slice(b"CMv1HEAD");
    want.extend_from_slice(&C);
    want.extend_from_slice(&1u16.to_le_bytes());
    assert_eq!(want.len(), 42);
    let p = GenesisHeadPreimage {
        asset_commitment: C,
        schema_version: 1,
    };
    assert_eq!(bytes_of(&p), want);
}

/// D-28 fixes the three widths §1.3 left unwritten: `category` a byte, both times signed 64-bit.
#[test]
fn the_leaf_preimage_has_the_layout_of_1_3() {
    let mut want = Vec::new();
    want.extend_from_slice(b"CMv1LEAF");
    want.extend_from_slice(&C);
    want.extend_from_slice(&7u64.to_le_bytes());
    want.extend_from_slice(&PAYLOAD);
    want.extend_from_slice(&ASSESSMENT);
    want.extend_from_slice(&QP);
    want.push(2);
    want.extend_from_slice(&1_760_000_000i64.to_le_bytes());
    want.extend_from_slice(&(-3i64).to_le_bytes());
    assert_eq!(want.len(), 161);
    assert_eq!(bytes_of(&leaf()), want);
}

#[test]
fn the_step_head_preimage_has_the_layout_of_1_3() {
    let mut want = Vec::new();
    want.extend_from_slice(b"CMv1HEAD");
    want.extend_from_slice(&PREV);
    want.extend_from_slice(&LEAF);
    assert_eq!(want.len(), 72);
    let p = StepHeadPreimage {
        prev_head: PREV,
        leaf: LEAF,
    };
    assert_eq!(bytes_of(&p), want);
}

/// The two preimages under `TAG_HEAD` cannot be confused: their lengths differ (§1.3, v0.1.4).
#[test]
fn the_two_head_preimages_have_different_lengths() {
    let genesis = GenesisHeadPreimage {
        asset_commitment: C,
        schema_version: 1,
    };
    let step = StepHeadPreimage {
        prev_head: PREV,
        leaf: LEAF,
    };
    assert_eq!(bytes_of(&genesis).len(), 42);
    assert_eq!(bytes_of(&step).len(), 72);
}

#[test]
fn the_tree_preimages_have_the_layout_of_1_4() {
    let mut real = Vec::new();
    real.extend_from_slice(b"CMv1MTL0");
    real.extend_from_slice(&LEAF);
    assert_eq!(real.len(), 40);
    assert_eq!(bytes_of(&RealLeafPreimage { leaf: LEAF }), real);

    let mut padding = Vec::new();
    padding.extend_from_slice(b"CMv1PADD");
    padding.extend_from_slice(&PRF_OUT);
    assert_eq!(padding.len(), 40);
    assert_eq!(
        bytes_of(&PaddingPreimage {
            prf_output: PRF_OUT
        }),
        padding
    );

    let mut node = Vec::new();
    node.extend_from_slice(b"CMv1MTN1");
    node.extend_from_slice(&PREV);
    node.extend_from_slice(&LEAF);
    assert_eq!(node.len(), 72);
    assert_eq!(
        bytes_of(&NodePreimage {
            left: PREV,
            right: LEAF
        }),
        node
    );
}

/// D-29 fixes the two types §1.6 left unnamed: a 16-byte identifier and a one-byte delay.
#[test]
fn the_spi_preimage_has_the_layout_of_1_6() {
    let mut want = Vec::new();
    want.extend_from_slice(b"CMv1SPI0");
    want.extend_from_slice(&LEAF);
    want.extend_from_slice(&SUBMISSION);
    want.extend_from_slice(&20_361u64.to_le_bytes());
    want.push(2);
    assert_eq!(want.len(), 65);
    let p = SpiPreimage {
        leaf: LEAF,
        submission_id: SUBMISSION,
        promised_epoch: 20_361,
        max_merge_delay: 2,
    };
    assert_eq!(bytes_of(&p), want);
}

/// INV-ENC-01: exactly one tag, first, and it is the tag §1.2 gives.
#[test]
fn every_writer_starts_with_its_spec_tag() {
    let cases: Vec<(&str, Vec<u8>, [u8; 8])> = vec![
        ("asset", bytes_of(&asset()), *b"CMv1ASST"),
        (
            "genesis head",
            bytes_of(&GenesisHeadPreimage {
                asset_commitment: C,
                schema_version: 1,
            }),
            *b"CMv1HEAD",
        ),
        ("leaf", bytes_of(&leaf()), *b"CMv1LEAF"),
        (
            "step head",
            bytes_of(&StepHeadPreimage {
                prev_head: PREV,
                leaf: LEAF,
            }),
            *b"CMv1HEAD",
        ),
        (
            "real leaf",
            bytes_of(&RealLeafPreimage { leaf: LEAF }),
            *b"CMv1MTL0",
        ),
        (
            "padding",
            bytes_of(&PaddingPreimage {
                prf_output: PRF_OUT,
            }),
            *b"CMv1PADD",
        ),
        (
            "node",
            bytes_of(&NodePreimage {
                left: PREV,
                right: LEAF,
            }),
            *b"CMv1MTN1",
        ),
        (
            "spi",
            bytes_of(&SpiPreimage {
                leaf: LEAF,
                submission_id: SUBMISSION,
                promised_epoch: 20_361,
                max_merge_delay: 2,
            }),
            *b"CMv1SPI0",
        ),
    ];
    assert_eq!(cases.len(), 8);
    for (name, bytes, tag) in &cases {
        assert_eq!(read_tag(bytes), Ok(*tag), "{name}");
        // The tag appears once, at the front: nothing else in the preimage repeats it.
        assert_eq!(
            bytes.windows(8).filter(|w| *w == tag.as_slice()).count(),
            1,
            "{name}"
        );
    }
}

/// V-N-09: a preimage read under the wrong tag is `0x0B` (D-36).
#[test]
fn v_n_09_a_wrong_tag_is_0x0b() {
    let bytes = bytes_of(&leaf());
    assert_eq!(check_tag(&bytes, *b"CMv1LEAF"), Ok(()));
    for wrong in [
        *b"CMv1HEAD",
        *b"CMv1ASST",
        *b"CMv1MTL0",
        *b"CMv1CKPT",
        *b"cmv1leaf",
    ] {
        assert_eq!(
            check_tag(&bytes, wrong),
            Err(RegistryError::DomainTagMismatch),
            "{wrong:?}"
        );
    }
}

/// V-N-18: every truncation of the tag is `0x05`, and none of them panics (D-36).
#[test]
fn a_buffer_shorter_than_a_tag_is_0x05() {
    let bytes = bytes_of(&NodePreimage {
        left: PREV,
        right: LEAF,
    });
    for n in 0..8 {
        assert_eq!(
            read_tag(&bytes[..n]),
            Err(RegistryError::MalformedPayload),
            "{n}"
        );
        assert_eq!(
            check_tag(&bytes[..n], *b"CMv1MTN1"),
            Err(RegistryError::MalformedPayload),
            "{n}"
        );
    }
    assert_eq!(check_tag(&bytes[..8], *b"CMv1MTN1"), Ok(()));
}

/// D-33: the sink stops at 256 bytes with `0x0C`, and every writer fits well inside that.
#[test]
fn the_sink_refuses_a_preimage_over_256_bytes() {
    let mut buf = PreimageBuf::new();
    assert!(buf.is_empty());
    assert_eq!(buf.write(&[0; 256]), Ok(()));
    assert_eq!(buf.len(), 256);
    assert_eq!(buf.write(&[0]), Err(RegistryError::RecordTooLarge));
    assert_eq!(buf.len(), 256);
}

#[test]
fn the_largest_preimage_is_the_leaf_at_161_bytes() {
    let lengths = [
        bytes_of(&asset()).len(),
        bytes_of(&GenesisHeadPreimage {
            asset_commitment: C,
            schema_version: 1,
        })
        .len(),
        bytes_of(&leaf()).len(),
        bytes_of(&StepHeadPreimage {
            prev_head: PREV,
            leaf: LEAF,
        })
        .len(),
        bytes_of(&RealLeafPreimage { leaf: LEAF }).len(),
        bytes_of(&PaddingPreimage {
            prf_output: PRF_OUT,
        })
        .len(),
        bytes_of(&NodePreimage {
            left: PREV,
            right: LEAF,
        })
        .len(),
        bytes_of(&SpiPreimage {
            leaf: LEAF,
            submission_id: SUBMISSION,
            promised_epoch: 20_361,
            max_merge_delay: 2,
        })
        .len(),
    ];
    assert_eq!(lengths.iter().copied().max(), Some(161));
    // A 64-byte tenure is the longest asset preimage the limits of §1.8 allow.
    let longest_tenure = [b'A'; 64];
    let longest = AssetPreimage {
        jurisdiction: J,
        registry: R,
        tenure: &longest_tenure,
    };
    assert_eq!(bytes_of(&longest).len(), 86);
}

/// D-26 holds through the writer as well, so no call site can commit a raw spelling.
#[test]
fn the_asset_writer_refuses_a_non_canonical_tenure() {
    let too_long = [b'A'; 65];
    for tenure in [&b""[..], b"bctenure", b"BC-TENURE", &too_long[..]] {
        let p = AssetPreimage {
            jurisdiction: J,
            registry: R,
            tenure,
        };
        let mut buf = PreimageBuf::new();
        assert_eq!(
            p.write_preimage(&mut buf),
            Err(RegistryError::CanonicalizationFailed),
            "{tenure:?}"
        );
    }
}

/// D-03 for E-03: a refused write returns the bare code, carrying nothing from its input.
#[test]
fn d03_a_refused_write_leaves_no_trace_in_the_error() {
    let secret = b"secret-tenure-7731";
    let p = AssetPreimage {
        jurisdiction: J,
        registry: R,
        tenure: secret,
    };
    let mut buf = PreimageBuf::new();
    let refused = p.write_preimage(&mut buf).expect_err("not canonical");
    assert_eq!(format!("{refused:?}"), "CanonicalizationFailed");
    assert!(buf.is_empty(), "nothing of the refused input was written");

    let mut full = PreimageBuf::new();
    full.write(&[0; 256]).expect("fits");
    let over = full.write(secret).expect_err("over capacity");
    assert_eq!(format!("{over:?}"), "RecordTooLarge");
}

/// The acceptance criterion of issue #3: nothing under the digest path formats a string.
#[test]
fn the_digest_path_formats_no_strings() {
    let source = include_str!("../src/preimage.rs");
    for banned in ["format!", "to_string", "write!", "String", "serde", "json"] {
        assert!(
            !source.contains(banned),
            "`{banned}` appears in src/preimage.rs"
        );
    }
}

#[cfg(feature = "native")]
mod with_native_keccak {
    use super::*;
    use certimining_core::{AssetId, AssetIdentity, Hasher, NativeKeccak};

    /// The digest is Keccak-256 over exactly the bytes the writer produced.
    #[test]
    fn digest_hashes_the_written_bytes() {
        let p = leaf();
        assert_eq!(
            p.digest::<NativeKeccak>(),
            Ok(NativeKeccak::hashv(&[&bytes_of(&p)]))
        );
    }

    /// E-02's commitment and E-03's asset writer are the same preimage, byte for byte.
    #[test]
    fn the_asset_writer_matches_the_e_02_commitment() {
        for tenure in [&b"A"[..], b"BCTENURE1043A", &[b'Z'; 64][..]] {
            let p = AssetPreimage {
                jurisdiction: J,
                registry: R,
                tenure,
            };
            assert_eq!(
                p.digest::<NativeKeccak>(),
                AssetId::<NativeKeccak>::commitment(J, R, tenure),
                "{tenure:?}"
            );
        }
    }

    /// Distinct tags give distinct digests for the same payload: that is what §1.2 buys.
    #[test]
    fn the_tag_separates_two_otherwise_identical_preimages() {
        let real = RealLeafPreimage { leaf: LEAF }.digest::<NativeKeccak>();
        let padding = PaddingPreimage { prf_output: LEAF }.digest::<NativeKeccak>();
        assert_ne!(real, padding);
    }
}

/// D-20: the two hashers agree on every writer.
#[cfg(all(feature = "native", feature = "solana"))]
#[test]
fn both_hashers_give_the_same_digest() {
    use certimining_core::{NativeKeccak, SolanaKeccak};
    assert_eq!(
        leaf().digest::<NativeKeccak>(),
        leaf().digest::<SolanaKeccak>()
    );
    assert_eq!(
        asset().digest::<NativeKeccak>(),
        asset().digest::<SolanaKeccak>()
    );
    let spi = SpiPreimage {
        leaf: LEAF,
        submission_id: SUBMISSION,
        promised_epoch: 20_361,
        max_merge_delay: 2,
    };
    assert_eq!(spi.digest::<NativeKeccak>(), spi.digest::<SolanaKeccak>());
}
