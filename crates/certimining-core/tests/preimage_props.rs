//! E-03's property tests: the writers are total, their lengths are fixed by the field widths of
//! §1.3 and §1.6, the tag reader never panics on any buffer, and the sink never exceeds its
//! capacity.

use certimining_core::{
    check_tag, read_tag, AssetPreimage, LeafPreimage, Preimage, PreimageBuf, PreimageSink,
    RegistryError, SpiPreimage,
};
use proptest::prelude::*;

/// Fewer cases under Miri, which interprets every instruction; no regression files are written.
fn config() -> ProptestConfig {
    ProptestConfig {
        cases: if cfg!(miri) { 8 } else { 1024 },
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

fn bytes_of<P: Preimage>(p: &P) -> Result<Vec<u8>, RegistryError> {
    let mut buf = PreimageBuf::new();
    p.write_preimage(&mut buf)?;
    Ok(buf.as_bytes().to_vec())
}

proptest! {
    #![proptest_config(config())]

    /// Whatever the field values, a leaf preimage is 161 bytes and never fails (§1.3, D-28).
    #[test]
    fn a_leaf_preimage_is_always_161_bytes(
        c in any::<[u8; 32]>(),
        seq in any::<u64>(),
        payload in any::<[u8; 32]>(),
        assessment in any::<[u8; 32]>(),
        qp in any::<[u8; 32]>(),
        category in any::<u8>(),
        effective in any::<i64>(),
        identified in any::<i64>(),
    ) {
        let p = LeafPreimage {
            asset_commitment: c,
            seq,
            payload_digest: payload,
            assessment_digest: assessment,
            qp_key: qp,
            category,
            effective_at: effective,
            change_identified_at: identified,
        };
        prop_assert_eq!(bytes_of(&p).map(|b| b.len()), Ok(161));
    }

    /// The same for an inclusion promise: 65 bytes for any values (§1.6, D-29).
    #[test]
    fn an_spi_preimage_is_always_65_bytes(
        leaf in any::<[u8; 32]>(),
        id in any::<[u8; 16]>(),
        epoch in any::<u64>(),
        delay in any::<u8>(),
    ) {
        let p = SpiPreimage { leaf, submission_id: id, promised_epoch: epoch, max_merge_delay: delay };
        prop_assert_eq!(bytes_of(&p).map(|b| b.len()), Ok(65));
    }

    /// The asset writer is total: any tenure bytes give either `0x11` or a preimage whose length
    /// is 22 plus the tenure (§1.3, D-26).
    #[test]
    fn the_asset_writer_is_total(tenure in prop::collection::vec(any::<u8>(), 0..100)) {
        let p = AssetPreimage { jurisdiction: b"CABC", registry: b"MTO00001", tenure: &tenure };
        match bytes_of(&p) {
            Ok(bytes) => {
                prop_assert!(!tenure.is_empty() && tenure.len() <= 64);
                prop_assert_eq!(bytes.len(), 22 + tenure.len());
                prop_assert_eq!(&bytes[..8], b"CMv1ASST");
            }
            Err(e) => prop_assert_eq!(e, RegistryError::CanonicalizationFailed),
        }
    }

    /// The tag reader is total: any buffer gives its first eight bytes or `0x05`, never a panic
    /// (D-36, V-N-18).
    #[test]
    fn the_tag_reader_is_total(bytes in prop::collection::vec(any::<u8>(), 0..64)) {
        match read_tag(&bytes) {
            Ok(tag) => {
                prop_assert!(bytes.len() >= 8);
                prop_assert_eq!(&tag[..], &bytes[..8]);
                prop_assert_eq!(check_tag(&bytes, tag), Ok(()));
            }
            Err(e) => {
                prop_assert!(bytes.len() < 8);
                prop_assert_eq!(e, RegistryError::MalformedPayload);
            }
        }
    }

    /// A tag that differs anywhere is `0x0B`, never accepted (V-N-09).
    #[test]
    fn a_tag_that_differs_anywhere_is_rejected(
        bytes in prop::collection::vec(any::<u8>(), 8..64),
        expected in any::<[u8; 8]>(),
    ) {
        let matches = bytes[..8] == expected[..];
        prop_assert_eq!(
            check_tag(&bytes, expected),
            if matches { Ok(()) } else { Err(RegistryError::DomainTagMismatch) }
        );
    }

    /// The sink holds at most 256 bytes and reports `0x0C` rather than growing (D-33).
    #[test]
    fn the_sink_never_exceeds_its_capacity(chunks in prop::collection::vec(0usize..80, 0..12)) {
        let mut buf = PreimageBuf::new();
        let mut written = 0usize;
        for size in chunks {
            let chunk = vec![0u8; size];
            match buf.write(&chunk) {
                Ok(()) => {
                    written += size;
                    prop_assert!(written <= 256);
                }
                Err(e) => {
                    prop_assert_eq!(e, RegistryError::RecordTooLarge);
                    prop_assert!(written + size > 256);
                }
            }
            prop_assert_eq!(buf.len(), written);
        }
    }
}
