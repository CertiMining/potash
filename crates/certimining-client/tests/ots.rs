// SPDX-License-Identifier: MIT OR Apache-2.0
//! Anchor B: the receipt digest, and a receipt checked by something that did not write it (E-10).
//!
//! The fixture is real. `tests/data/bitcoin-confirmed.ots` is the OpenTimestamps receipt this
//! repository already committed under `anchors/` for its own specification, upgraded on
//! 18 September and carrying `BitcoinBlockHeaderAttestation(967489)`. Nothing here reaches a
//! network: the receipt is on disk and the Bitcoin attestation inside it is what is read.

use certimining_client::receipt_digest;
use certimining_core::{Digest, NativeKeccak, TAG_RCPT};

const RECEIPT: &[u8] = include_bytes!("data/bitcoin-confirmed.ots");
#[cfg(feature = "ots")]
const STAMPED: &[u8] = include_bytes!("data/bitcoin-confirmed.stamped");

/// §2.4's construction, transcribed from the specification rather than called from the code under
/// test: `Keccak256(TAG_RCPT ‖ len(receipt) ‖ receipt)`, the tag first and a `u16` length.
fn expected_digest(receipt: &[u8]) -> Digest {
    use sha3::{Digest as _, Keccak256};
    let mut h = Keccak256::new();
    h.update(TAG_RCPT);
    h.update((receipt.len() as u16).to_le_bytes());
    h.update(receipt);
    h.finalize().into()
}

#[test]
fn the_receipt_digest_is_the_construction_2_4_states() {
    let computed = receipt_digest::<NativeKeccak>(RECEIPT).expect("a receipt this size encodes");
    assert_eq!(computed, expected_digest(RECEIPT));
}

#[test]
fn a_receipt_too_long_for_a_u16_length_is_refused_rather_than_truncated() {
    // INV-ENC-04 makes the length prefix a `u16`. A receipt that cannot be described by one has no
    // encoding here, and silently truncating the length would produce a digest over bytes nobody
    // committed to.
    let huge = vec![0u8; usize::from(u16::MAX) + 1];
    assert!(receipt_digest::<NativeKeccak>(&huge).is_none());
    let largest = vec![0u8; usize::from(u16::MAX)];
    assert!(receipt_digest::<NativeKeccak>(&largest).is_some());
}

#[test]
fn a_one_byte_change_moves_the_digest() {
    let mut altered = RECEIPT.to_vec();
    let last = altered.len() - 1;
    altered[last] ^= 0x01;
    assert_ne!(
        receipt_digest::<NativeKeccak>(RECEIPT),
        receipt_digest::<NativeKeccak>(&altered),
        "the digest is what lets a counterparty tell one receipt from another"
    );
}

#[cfg(feature = "ots")]
mod verified_by_another_implementation {
    use super::*;
    use certimining_client::{verify_receipt, ReceiptRefused};

    /// The digest this receipt was made over. The reference client stamps a *file*, so a receipt
    /// commits to `SHA-256(file)` and never to a raw digest handed to it (D-119). Here that file is
    /// the specification's own manifest; in the worker it is the 32 root bytes.

    #[test]
    fn a_bitcoin_confirmed_receipt_verifies_against_what_it_stamped() {
        // D-115: the receipt was produced by the reference client and is read here by the
        // OpenTimestamps project's own Rust library, which cannot create one.
        assert_eq!(verify_receipt(RECEIPT, STAMPED), Ok(()));
    }

    #[test]
    fn a_receipt_for_another_digest_is_refused() {
        assert_eq!(
            verify_receipt(RECEIPT, &[0x11; 32]),
            Err(ReceiptRefused::WrongRoot),
            "a receipt parses perfectly well and attests to nothing about an epoch it never saw"
        );
    }

    #[test]
    fn bytes_that_are_not_a_receipt_are_refused_rather_than_hashed() {
        match verify_receipt(b"not a receipt", &[0u8; 32]) {
            Err(ReceiptRefused::Unparsable(_)) => {}
            other => panic!("expected an unparsable receipt, got {other:?}"),
        }
    }
}

/// D-117, S6. The checkpoint authority is the only key that runs unattended, so the worker refuses
/// to read one anybody else can.
#[cfg(unix)]
mod key_handling {
    use certimining_client::refuse_a_readable_key;
    use std::os::unix::fs::PermissionsExt;

    fn key_at(mode: u32) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("certimining-key-{mode:o}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("a directory");
        let path = dir.join("checkpoint-authority.json");
        std::fs::write(&path, b"[1,2,3]").expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("chmod");
        path
    }

    #[test]
    fn a_key_at_0600_is_accepted() {
        assert!(refuse_a_readable_key(&key_at(0o600)).is_ok());
    }

    #[test]
    fn a_key_anyone_can_read_is_refused() {
        let refused = refuse_a_readable_key(&key_at(0o644));
        assert!(
            refused.is_err(),
            "0644 is readable by every account on the host"
        );
        assert!(refused.unwrap_err().contains("0600"));
    }

    #[test]
    fn a_key_that_is_not_there_is_refused_rather_than_assumed_fine() {
        assert!(refuse_a_readable_key(std::path::Path::new("/nonexistent/key.json")).is_err());
    }
}
