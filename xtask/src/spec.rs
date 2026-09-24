//! TCU-02's own values, transcribed by hand from the specification.
//!
//! Nothing in this file is read from `certimining-core`. That is its purpose: the generator checks
//! the engine against these values and **fails generation on any disagreement**, so an engine that
//! has drifted cannot write its drift into the committed vectors as the correct answer. The rule it
//! serves is the owner's: a spec-derived value comes from the spec, not from the implementation.
//!
//! Every constant here carries the section it was copied from. When the specification changes, this
//! file is edited by hand from the new text, never regenerated.

/// §1.2's domain tags, byte for byte. `TAG_CKPT` is transcribed for completeness: no preimage uses
/// it, because the checkpoint preimage is undefined (D-30). It is here so the table is the whole of
/// §1.2 rather than a convenient part.
pub const TAG_ASSET: &[u8; 8] = b"CMv1ASST";
pub const TAG_LEAF: &[u8; 8] = b"CMv1LEAF";
pub const TAG_HEAD: &[u8; 8] = b"CMv1HEAD";
pub const TAG_MTL0: &[u8; 8] = b"CMv1MTL0";
pub const TAG_MTN1: &[u8; 8] = b"CMv1MTN1";
pub const TAG_PAD: &[u8; 8] = b"CMv1PADD";
#[allow(dead_code)]
pub const TAG_CKPT: &[u8; 8] = b"CMv1CKPT";
pub const TAG_PRF: &[u8; 8] = b"CMv1PRF0";
pub const TAG_SPI: &[u8; 8] = b"CMv1SPI0";

/// §4.2's V-P-01: what both spellings of the tenure identifier canonicalize to.
pub const V_P_01_CANONICAL: &str = "BCTENURE1043A";

/// §1.8's limits.
pub const MAX_TENURE_LEN: usize = 64;
pub const MAX_RAW_TENURE_LEN: usize = 256;
pub const MAX_PAYLOAD_URI_LEN: usize = 128;
pub const MAX_MERGE_DELAY: u8 = 2;

/// §1.1's use codes, which separate the three things the PRF is used for.
pub const PRF_USE_EPOCH_KEY: u8 = 0x01;
pub const PRF_USE_SLOT: u8 = 0x02;
pub const PRF_USE_PADDING: u8 = 0x03;

/// §1.8's range for the tree height, and the height this deployment ships (D-02).
pub const MIN_HEIGHT: u8 = 4;
pub const MAX_HEIGHT: u8 = 16;
pub const DEPLOYED_HEIGHT: u8 = 8;
pub const DEPLOYED_CAPACITY: usize = 256;

/// §1.3's schema version for this engine.
pub const SCHEMA_VERSION: u16 = 1;

/// §1.3's category range: 0 to 2 are resources, 3 and 4 reserves.
pub const MAX_CATEGORY: u8 = 4;

/// A preimage's shape as §1.2, §1.3, §1.4 and §1.6 write it: the tag, then each field with the
/// width the specification gives it, and the total the table states.
pub struct Layout {
    pub name: &'static str,
    pub tag: &'static [u8; 8],
    /// Field names and widths after the tag, in the specification's order.
    pub fields: &'static [(&'static str, usize)],
    /// The total length §1.3's table states, where it is fixed.
    pub total: Option<usize>,
}

/// The layouts this unit can check. `c` has no fixed total because `T` varies from 1 to 64 bytes,
/// and the PRF's has none because `x` varies with the use; their field widths still pin everything
/// else.
pub const LAYOUTS: &[Layout] = &[
    Layout {
        name: "asset",
        tag: TAG_ASSET,
        fields: &[("J", 4), ("R", 8), ("len(T)", 2), ("T", 0)],
        total: None,
    },
    Layout {
        name: "genesis_head",
        tag: TAG_HEAD,
        fields: &[("c", 32), ("schema_version", 2)],
        total: Some(42),
    },
    Layout {
        name: "leaf",
        tag: TAG_LEAF,
        fields: &[
            ("c", 32),
            ("seq", 8),
            ("payload_digest", 32),
            ("assessment_digest", 32),
            ("qp_key", 32),
            ("category", 1),
            ("effective_at", 8),
            ("change_identified_at", 8),
        ],
        total: Some(161),
    },
    Layout {
        name: "step_head",
        tag: TAG_HEAD,
        fields: &[("h_n", 32), ("leaf", 32)],
        total: Some(72),
    },
    Layout {
        name: "real_leaf",
        tag: TAG_MTL0,
        fields: &[("leaf", 32)],
        total: Some(40),
    },
    Layout {
        name: "prf",
        tag: TAG_PRF,
        fields: &[("k", 32), ("len(x)", 2), ("x", 0)],
        total: None,
    },
    Layout {
        name: "padding",
        tag: TAG_PAD,
        fields: &[("prf_output", 32)],
        total: Some(40),
    },
    Layout {
        name: "node",
        tag: TAG_MTN1,
        fields: &[("left", 32), ("right", 32)],
        total: Some(72),
    },
    Layout {
        name: "spi",
        tag: TAG_SPI,
        fields: &[
            ("leaf", 32),
            ("submission_id", 16),
            ("promised_epoch", 8),
            ("max_merge_delay", 1),
        ],
        total: Some(65),
    },
];

pub fn layout(name: &str) -> &'static Layout {
    LAYOUTS
        .iter()
        .find(|l| l.name == name)
        .unwrap_or_else(|| panic!("no layout named {name} in the transcribed table"))
}

/// Checks a preimage the engine produced against the layout the specification states: the tag it
/// must open with, each field at the offset the widths imply, and the total length.
///
/// `values` are the field values in the specification's order. Generation stops on any disagreement.
pub fn check_layout(name: &str, produced: &[u8], values: &[&[u8]]) {
    let layout = layout(name);
    assert_eq!(
        &produced[..8],
        &layout.tag[..],
        "{name}: the preimage does not open with the tag §1.2 gives"
    );
    assert_eq!(
        values.len(),
        layout.fields.len(),
        "{name}: the table lists {} fields and {} were supplied",
        layout.fields.len(),
        values.len()
    );

    let mut expected = Vec::with_capacity(produced.len());
    expected.extend_from_slice(&layout.tag[..]);
    for ((field, width), value) in layout.fields.iter().zip(values) {
        if *width != 0 {
            assert_eq!(
                value.len(),
                *width,
                "{name}: §1.3 gives {field} {width} bytes and the value is {}",
                value.len()
            );
        }
        expected.extend_from_slice(value);
    }
    assert_eq!(
        produced, expected,
        "{name}: the engine's preimage differs from the layout the specification states"
    );
    if let Some(total) = layout.total {
        assert_eq!(
            produced.len(),
            total,
            "{name}: §1.3's table states {total} bytes"
        );
    }
}
