// SPDX-License-Identifier: MIT OR Apache-2.0
//! Anchor B: the receipt digest, and a receipt checked by something that did not write it (E-10).
//!
//! The fixture is real. `tests/data/bitcoin-confirmed.ots` is the OpenTimestamps receipt this
//! repository already committed under `anchors/` for its own specification, upgraded on
//! 18 September and carrying `BitcoinBlockHeaderAttestation(967489)`. Nothing here reaches a
//! network: the receipt is on disk and the Bitcoin attestation inside it is what is read.

/// **One thread at a time may write a fake and run one (ETXTBSY).**
///
/// Linux refuses to `execve` a file that any process holds open for writing. The test harness runs
/// tests in threads, and `Command::output` forks: the child inherits every descriptor open at that
/// instant, and the kernel's deny-write check happens *during* the exec, before `O_CLOEXEC` closes
/// them. So one thread writing a fake can make another thread's exec fail with "text file busy",
/// whichever files each is touching.
///
/// Two earlier attempts treated the symptom. PR #104 gave each fake its own path, which removed
/// rewriting-while-running; PR #109 closed and synced the handle before the file became executable,
/// which removed the single-threaded window. Neither could help, because the descriptor that breaks
/// the exec belongs to a *different* thread. A CI runner then failed with the error named outright:
/// `/tmp/cm-h14-wrong-22227/ots-0: Text file busy (os error 26)`.
///
/// Serialising is the fix rather than a retry: a retry would hide a race that is real, and these
/// tests take under a second between them.
pub(crate) static FAKES: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Taken by every test below that writes a fake or runs one. A poisoned lock is another test having
/// failed, which is not a reason for this one to stop reporting its own result.
pub(crate) fn serial() -> std::sync::MutexGuard<'static, ()> {
    FAKES.lock().unwrap_or_else(|e| e.into_inner())
}

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

/// **A file is not a submission (H-14).**
///
/// `submit` is idempotent per epoch by file existence, which is right: only one digest can ever be
/// attached (INV-ANCH-03), so a restarting worker must not stamp twice. It read existence as
/// success. A `stamp` that left a partial `.ots` and exited non-zero produced a file that every
/// later call accepted as "already done", every `upgrade` then failed to parse, and the epoch never
/// anchored with nothing saying why.
#[cfg(feature = "ots")]
mod an_existing_receipt_is_parsed_before_it_is_believed {
    use super::the_pinned_client::{client, fake};
    use certimining_client::{AnchorB, ReferenceClient};

    /// A document and a receipt that timestamps it, carrying a calendar's pending attestation and no
    /// Bitcoin one — the ordinary state of a receipt between `stamp` and confirmation.
    ///
    /// Generated once with `opentimestamps` 0.2.0's own writer over the bytes `00..1f`, which is why
    /// it parses: it is that library's output, not a hand-built guess at the format. The crate is a
    /// dependency of this one behind `ots` and not a dev-dependency, so the bytes are recorded here
    /// rather than rebuilt in the test, which would add it to every test build.
    const DOCUMENT: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    const PENDING_RECEIPT: &str = "004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e892940108630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd0083dfe30d2ef90c8e2e2d68747470733a2f2f616c6963652e6274632e63616c656e6461722e6f70656e74696d657374616d70732e6f7267";

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// A client over a fresh directory, with an epoch already stamped: the root beside the receipt
    /// bytes the caller supplies.
    fn with_existing(
        tag: &str,
        receipt_bytes: &[u8],
        stamped: &[u8; 32],
    ) -> (ReferenceClient, u64) {
        let dir = std::env::temp_dir().join(format!("cm-h14-{tag}-{}", std::process::id()));
        let receipts = dir.join("receipts");
        std::fs::create_dir_all(&receipts).expect("a temporary directory");
        let epoch = 20_000u64;
        std::fs::write(receipts.join(format!("{epoch}.root")), stamped).expect("the root");
        std::fs::write(receipts.join(format!("{epoch}.root.ots")), receipt_bytes)
            .expect("the receipt");
        (client(fake(&dir, "v0.7.2"), receipts), epoch)
    }

    /// The control. Without it a `submit` that refused every existing receipt would pass the two
    /// tests below, which is the failure those tests exist to catch one level down.
    #[test]
    fn a_receipt_that_parses_and_awaits_bitcoin_is_accepted() {
        let _serial = crate::serial();
        let (c, epoch) = with_existing("ok", &hex(PENDING_RECEIPT), &DOCUMENT);
        let pending = c
            .submit(epoch, &DOCUMENT)
            .expect("a pending receipt is the ordinary state between stamp and confirmation");
        assert_eq!(pending.epoch, epoch);
        assert_eq!(pending.root, DOCUMENT);
    }

    #[test]
    fn a_receipt_that_does_not_parse_is_refused_rather_than_counted_as_done() {
        let _serial = crate::serial();
        let (c, epoch) = with_existing("corrupt", b"not an OpenTimestamps file", &DOCUMENT);
        let err = c
            .submit(epoch, &DOCUMENT)
            .expect_err("a partial stamp must not read as a completed submission");
        assert!(err.contains("does not parse"), "{err}");
        // The remedy belongs in the message: this is met by a person at a terminal, and the file is
        // the only evidence that anything went wrong.
        assert!(err.contains("Remove it and submit again"), "{err}");
    }

    #[test]
    fn a_receipt_over_a_different_document_is_refused() {
        let _serial = crate::serial();
        // The root beside it matches what the caller asked for, so the existing check passes; the
        // receipt timestamps something else, which only parsing can see.
        let other = [0xAAu8; 32];
        let (c, epoch) = with_existing("wrong", &hex(PENDING_RECEIPT), &other);
        let err = c
            .submit(epoch, &other)
            .expect_err("a receipt over another digest attests nothing about this epoch");
        assert!(err.contains("timestamps a digest other than"), "{err}");
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
    pub(super) fn fake(dir: &std::path::Path, prints: &str) -> std::path::PathBuf {
        raw_fake(dir, &format!("{prints}\n"), "")
    }

    /// A fake that writes **exactly** these bytes to stdout and stderr.
    ///
    /// `echo` appends a newline and cannot omit one, which is why the earlier tests could not see
    /// that the check `trim()`ed its input: every fake they built was already correctly framed. This
    /// writes the bytes through `printf '%b'` with the octal escapes spelled out, so a test can say
    /// "no trailing newline", "CRLF", "a tab in front" or "on stderr instead".
    fn raw_fake(dir: &std::path::Path, stdout: &str, stderr: &str) -> std::path::PathBuf {
        // **A fresh name per fake, because the last one may still be running.** Every fake was
        // written to `dir/ots`, so a test that executed one and then rewrote the same path raced the
        // kernel: on Linux, executing a file whose write handle is still open fails with ETXTBSY,
        // "text file busy". `check_version` maps a failure to launch and a wrong version onto the
        // same `Err`, so the test failed saying the pinned version was refused when what actually
        // happened is that the binary could not be run at all. macOS does not enforce ETXTBSY, so
        // this only ever failed on a CI runner, and only under enough load to open the window —
        // once in eight runs here, never in a thousand locally.
        //
        // The fix removes the shared path rather than sleeping until the race closes, because a
        // sleep tuned to one machine is a flake waiting for a slower one.
        static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let path = dir.join(format!(
            "ots-{}",
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let escape = |s: &str| -> String {
            s.bytes()
                .map(|b| format!("\\{:03o}", b))
                .collect::<String>()
        };
        // **Closed and on disk before it is executable, and executable before the path escapes.**
        // Unique names (above) stopped a fake being rewritten while a previous one ran. They did not
        // make this ordering explicit, and the same symptom returned on a Linux runner in a second
        // test: a fake that should be accepted was refused, which is what `check_version` reports
        // when the binary cannot be launched at all. Linux refuses to exec a file that any process
        // holds open for writing, so the handle is closed here rather than at the end of the
        // function, after `sync_all` has put the bytes on disk.
        //
        // Whether that ordering was the cause is not established — it was never reproduced on macOS,
        // which does not enforce ETXTBSY — so this removes the doubt rather than fixing a proven
        // fault. If a Linux runner refuses a fake again, the remaining suspect is the exec itself and
        // not the write.
        {
            let mut f = std::fs::File::create(&path).expect("the fake can be written");
            writeln!(
                f,
                "#!/bin/sh\nprintf '%b' '{}'\nprintf '%b' '{}' >&2",
                escape(stdout),
                escape(stderr)
            )
            .expect("script");
            f.sync_all()
                .expect("the fake reaches the disk before anything executes it");
        }
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("mode");
        path
    }

    pub(super) fn client(exe: std::path::PathBuf, receipts: std::path::PathBuf) -> ReferenceClient {
        ReferenceClient {
            executable: exe,
            receipts,
        }
    }

    #[test]
    fn a_client_reporting_another_version_is_refused() {
        let _serial = crate::serial();
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
        let _serial = crate::serial();
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
        let _serial = crate::serial();
        let c = client(
            std::path::PathBuf::from("/nonexistent/ots"),
            std::env::temp_dir(),
        );
        assert!(c.check_version().is_err(), "a missing client is not a pass");
    }
}
