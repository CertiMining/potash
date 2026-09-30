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
        let claim = verify_receipt(RECEIPT, STAMPED).expect("this receipt carries Bitcoin");
        assert!(
            claim.height > 0,
            "a Bitcoin attestation names a block height"
        );
    }

    #[test]
    fn the_returned_height_is_the_receipts_claim_and_not_a_checked_fact() {
        // The type is the whole point of this test. Verifying an attestation would mean recomputing
        // the operations to that block's merkle root, which needs a header source this crate does not
        // have, so a receipt naming a block it never reached passes. `BitcoinClaim` exists so that a
        // caller receives the claim labelled as one; a review found this function reading as though it
        // had consulted Bitcoin.
        let claim = verify_receipt(RECEIPT, STAMPED).expect("carries Bitcoin");
        // Nothing in this crate can contradict the height, which is exactly what is being recorded.
        assert_eq!(
            claim,
            verify_receipt(RECEIPT, STAMPED).expect("carries Bitcoin"),
            "the claim is read from the receipt and is stable"
        );
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

    /// Every mode, because "0600 and nothing else" is the claim and two samples do not make it.
    ///
    /// D-117's record said this sweep existed before it did: the sentence was written from a
    /// reviewer's own verification and described their work as though it described these tests. The
    /// test is here now so the record is true rather than trimmed to fit.
    #[test]
    fn exactly_0600_is_accepted_across_every_mode() {
        let mut accepted = Vec::new();
        for mode in 0o000..=0o777u32 {
            if refuse_a_readable_key(&key_at(mode)).is_ok() {
                accepted.push(mode);
            }
        }
        assert_eq!(
            accepted,
            vec![0o600],
            "modes accepted: {:?}",
            accepted
                .iter()
                .map(|m| format!("{m:o}"))
                .collect::<Vec<_>>()
        );
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

/// D-113's pin, enforced rather than assumed.
///
/// The executable is whatever the configured path points at. A review built a fake reporting
/// `v9.9.9` and completed a submission with it, because nothing ever asked the client what it was.
#[cfg(feature = "ots")]
mod the_pinned_client {
    use certimining_client::ReferenceClient;
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;

    /// A fake whose output is `echo`ed, so it always ends in a newline. Kept for the cases where the
    /// framing is not what is under test.
    fn fake(dir: &std::path::Path, prints: &str) -> std::path::PathBuf {
        raw_fake(dir, &format!("{prints}\n"), "")
    }

    /// A fake that writes **exactly** these bytes to stdout and stderr.
    ///
    /// `echo` appends a newline and cannot omit one, which is why the earlier tests could not see
    /// that the check `trim()`ed its input: every fake they built was already correctly framed. This
    /// writes the bytes through `printf '%b'` with the octal escapes spelled out, so a test can say
    /// "no trailing newline", "CRLF", "a tab in front" or "on stderr instead".
    fn raw_fake(dir: &std::path::Path, stdout: &str, stderr: &str) -> std::path::PathBuf {
        let path = dir.join("ots");
        let escape = |s: &str| -> String {
            s.bytes()
                .map(|b| format!("\\{:03o}", b))
                .collect::<String>()
        };
        let mut f = std::fs::File::create(&path).expect("the fake can be written");
        writeln!(
            f,
            "#!/bin/sh\nprintf '%b' '{}'\nprintf '%b' '{}' >&2",
            escape(stdout),
            escape(stderr)
        )
        .expect("script");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("mode");
        path
    }

    fn client(exe: std::path::PathBuf, receipts: std::path::PathBuf) -> ReferenceClient {
        ReferenceClient {
            executable: exe,
            receipts,
        }
    }

    #[test]
    fn a_client_reporting_another_version_is_refused() {
        let dir = std::env::temp_dir().join(format!("cm-ots-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("a temporary directory");
        let c = client(fake(&dir, "v9.9.9"), dir.join("receipts"));
        let err = c
            .check_version()
            .expect_err("a fake version must be refused");
        assert!(err.contains("9.9.9"), "{err}");
        assert!(err.contains(ReferenceClient::PINNED_VERSION), "{err}");

        let ok = client(fake(&dir, "v0.7.2"), dir.join("receipts"));
        assert!(
            ok.check_version().is_ok(),
            "the pinned version must be accepted"
        );

        // A report that merely *contains* the pinned version is not the pinned version. The first
        // parser split on whitespace and accepted any matching token, so `v9.9.9 v0.7.2` passed: a
        // pin asking to be told what it wanted to hear.
        // Every shape a looser check let through. The first version split the report on whitespace,
        // so mixed tokens passed; the second stripped leading `v` characters, so a bare number and a
        // doubled prefix passed. A review found the second set after the first was fixed.
        for smuggled in [
            "v9.9.9 v0.7.2",
            "v0.7.2 v9.9.9",
            "not-ots v0.7.2",
            "v0.7.2-modified",
            "0.7.2",
            "vv0.7.2",
            "V0.7.2",
            "v0.7.2 extra",
        ] {
            let c = client(fake(&dir, smuggled), dir.join("receipts"));
            assert!(
                c.check_version().is_err(),
                "{smuggled:?} was accepted as the pinned client"
            );
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The framing, which a review found the previous check discarded.
    ///
    /// `check_version` compared `printed.trim()`, so every one of these passed, and none of them is
    /// the pinned client: the bytes it writes are `v0.7.2\n` on stdout and nothing on stderr.
    #[test]
    fn only_the_exact_bytes_on_stdout_are_accepted() {
        let dir = std::env::temp_dir().join(format!("cm-ots-raw-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("a temporary directory");

        let exact = client(raw_fake(&dir, "v0.7.2\n", ""), dir.join("receipts"));
        assert!(
            exact.check_version().is_ok(),
            "the pinned client's own output must be accepted"
        );

        for (stdout, stderr, what) in [
            ("v0.7.2", "", "no trailing newline"),
            ("v0.7.2\r\n", "", "CRLF"),
            ("v0.7.2\n\n", "", "two trailing newlines"),
            ("\nv0.7.2\n", "", "a leading newline"),
            (" v0.7.2\n", "", "a leading space"),
            ("v0.7.2 \n", "", "a trailing space"),
            ("\tv0.7.2\n", "", "a leading tab"),
            ("v0.7.2\t\n", "", "a trailing tab"),
            ("\u{b}v0.7.2\n", "", "a vertical tab"),
            ("\u{c}v0.7.2\n", "", "a form feed"),
            ("\u{a0}v0.7.2\n", "", "a non-breaking space"),
            ("", "v0.7.2\n", "the report on stderr instead"),
            ("v0.7.", "2\n", "the report split across both streams"),
        ] {
            let c = client(raw_fake(&dir, stdout, stderr), dir.join("receipts"));
            assert!(
                c.check_version().is_err(),
                "{what}: stdout {stdout:?}, stderr {stderr:?} was accepted as the pinned client"
            );
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_executable_that_is_not_there_is_refused_rather_than_ignored() {
        let c = client(
            std::path::PathBuf::from("/nonexistent/ots"),
            std::env::temp_dir(),
        );
        assert!(c.check_version().is_err(), "a missing client is not a pass");
    }
}
