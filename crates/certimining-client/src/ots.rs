// SPDX-License-Identifier: MIT OR Apache-2.0
//! Anchor B: OpenTimestamps (§1.5, §2.3, D-112 to D-118).
//!
//! Two things happen here and they are kept apart on purpose. A receipt is **created** by the
//! OpenTimestamps reference client, which is the only implementation that both submits to calendars
//! and upgrades once Bitcoin confirms. A receipt is **verified** by the `opentimestamps` crate,
//! which is the OpenTimestamps project's own Rust library and cannot create one. The reason is
//! D-115's, in the owner's words: it makes the receipt checkable by something that did not produce
//! it.
//!
//! Nothing here parses a receipt on behalf of the program. INV-ANCH-04 says the program stores the
//! digest and never parses the receipt, and it does not: this is the client's own check, run before
//! a digest is computed, so that what reaches the chain is the digest of something that parsed.

use certimining_core::{Digest, Hasher, TAG_RCPT};

/// A receipt that exists but carries no Bitcoin attestation yet (§2.3, D-114).
///
/// `submit` returns one at once. It becomes a `ReceiptDigest` only when `upgrade` finds a Bitcoin
/// attestation in the upgraded receipt, which takes hours — the latency INV-ANCH-04 budgets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingReceipt {
    /// The epoch whose root was submitted.
    pub epoch: u64,
    /// The root that was submitted, which is what the receipt timestamps.
    pub root: Digest,
    /// Where the receipt file lives. Outside the repository (D-116).
    pub path: std::path::PathBuf,
}

/// Why a receipt was refused before anything hashed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptRefused {
    /// The bytes are not a receipt this library can parse.
    Unparsable(String),
    /// The receipt parses but timestamps a digest other than the root it should.
    WrongRoot,
    /// The receipt parses and carries no Bitcoin attestation, so it is still pending.
    NotYetConfirmed,
}

/// §2.4's `receipt_digest`, over the **upgraded** receipt (D-112, D-113).
///
/// `Keccak256(TAG_RCPT ‖ len(receipt) ‖ receipt)`: the tag first as INV-ENC-01 requires of every
/// preimage here, and a `u16` length as INV-ENC-04 requires of every variable-length field, which is
/// where Borsh's own `u32` framing is overridden. A receipt longer than `u16::MAX` cannot be
/// encoded and is refused rather than truncated.
pub fn receipt_digest<H: Hasher>(receipt: &[u8]) -> Option<Digest> {
    let len = u16::try_from(receipt.len()).ok()?;
    // INV-ERR-01 forbids unchecked arithmetic on any path; `saturating_add` only sizes the buffer,
    // and the length written into the preimage is the checked `u16` above.
    let mut preimage = Vec::with_capacity(receipt.len().saturating_add(10));
    preimage.extend_from_slice(&TAG_RCPT);
    preimage.extend_from_slice(&len.to_le_bytes());
    preimage.extend_from_slice(receipt);
    Some(H::hashv(&[&preimage]))
}

/// Parses a receipt and checks it timestamps this epoch's root and carries a Bitcoin attestation.
///
/// This is the half D-115 gives to a different implementation from the one that wrote the file.
///
/// **What a receipt actually commits to (D-119).** The reference client stamps a *file* and takes no
/// raw digest, so a receipt's start digest is `SHA-256` of the bytes that were stamped. `stamped` is
/// those bytes — for the worker, the 32 root bytes it wrote to a file — and this function takes them
/// rather than assuming their length, because assuming it is how a fixture stops being usable and a
/// caller stops being checked. This is the second place SHA-256 is unavoidable, after §2.4's address
/// and discriminator derivations, and INV-PRIM-01 still forbids it in terms.
/// The Bitcoin attestation a receipt carries — **the height the receipt names, not a height this
/// code has checked.**
///
/// Verifying an attestation means recomputing the operations from the start digest and comparing the
/// result with that block's merkle root, which needs a source of Bitcoin headers. This crate has
/// none, so what `verify_receipt` establishes is that the receipt parses, commits to this epoch's
/// root, and carries a Bitcoin attestation rather than only a calendar's promise. **A forged receipt
/// naming a block it never reached passes that.** The type exists so a caller cannot mistake one for
/// the other: it hands back the claim, labelled as a claim. Real verification against Bitcoin is
/// filed for after the submission deadline.
#[cfg(feature = "ots")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BitcoinClaim {
    /// The block height the receipt names. Unchecked.
    pub height: u32,
}

#[cfg(feature = "ots")]
pub fn verify_receipt(receipt: &[u8], stamped: &[u8]) -> Result<BitcoinClaim, ReceiptRefused> {
    use opentimestamps::attestation::Attestation;
    use opentimestamps::ser::DetachedTimestampFile;
    use opentimestamps::timestamp::{Step, StepData};

    let parsed = DetachedTimestampFile::from_reader(receipt)
        .map_err(|e| ReceiptRefused::Unparsable(e.to_string()))?;

    // The receipt must timestamp *this* epoch's root. A receipt for some other digest parses
    // perfectly well and attests to nothing about this epoch.
    use bitcoin_hashes::{sha256, Hash};
    let committed = sha256::Hash::hash(stamped);
    if parsed.timestamp.start_digest != committed[..] {
        return Err(ReceiptRefused::WrongRoot);
    }

    // A receipt is a tree of operations ending in attestations. A calendar's `Pending` attestation
    // is a promise; only `Bitcoin` is the anchor (D-112).
    fn confirmed(step: &Step) -> Option<u32> {
        if let StepData::Attestation(Attestation::Bitcoin { height }) = step.data {
            return Some(height as u32);
        }
        step.next.iter().find_map(confirmed)
    }

    match confirmed(&parsed.timestamp.first_step) {
        Some(height) => Ok(BitcoinClaim { height }),
        None => Err(ReceiptRefused::NotYetConfirmed),
    }
}

/// Anchor B's two operations, behind a trait so the worker's logic is testable without a calendar.
///
/// §2.3 declared one synchronous `timestamp`, which cannot exist: the digest it returns does not
/// exist until Bitcoin confirms, hours later (D-114). These are the two halves it splits into.
pub trait AnchorB {
    /// Submits a root and returns at once. The receipt exists and carries calendar attestations.
    fn submit(&self, epoch: u64, root: &Digest) -> Result<PendingReceipt, String>;
    /// `None` while Bitcoin has not confirmed. `Some` is the digest to attach (D-112).
    fn upgrade(&self, pending: &PendingReceipt) -> Result<Option<Digest>, String>;
}

/// The OpenTimestamps reference client, invoked as a process (D-115).
///
/// It is the only implementation that both submits to calendars and upgrades, and it is the one
/// that produced the receipt this repository already committed for its own specification. It is a
/// pinned runtime dependency outside Cargo, so it is outside `cargo deny`: that is named in
/// CONTRIBUTING rather than left for a reader to discover.
///
/// **It is invoked, not linked.** The client is LGPL-3.0; running it as a separate process is not
/// linking against it, and nothing of ours derives from it.
#[cfg(feature = "ots")]
pub struct ReferenceClient {
    /// The `ots` executable. Pinned by path rather than found on `PATH`, so an upgrade elsewhere on
    /// the machine cannot silently change what produces anchor B.
    pub executable: std::path::PathBuf,
    /// Where receipts live. Outside the repository; a person commits them (D-116).
    pub receipts: std::path::PathBuf,
}

#[cfg(feature = "ots")]
impl ReferenceClient {
    fn stamped_path(&self, epoch: u64) -> std::path::PathBuf {
        self.receipts.join(format!("{epoch}.root"))
    }

    fn receipt_path(&self, epoch: u64) -> std::path::PathBuf {
        self.receipts.join(format!("{epoch}.root.ots"))
    }

    /// What the pinned client writes to **stdout**, byte for byte, newline included.
    ///
    /// `~/.local/share/potash/ots-venv/bin/ots --version | od -c` shows `v 0 . 7 . 2 \n`. Four
    /// versions of this check were wrong before this one, each looser than it looked:
    ///
    /// 1. The version was pinned in prose and asked of nothing, so a client reporting `v9.9.9` ran.
    /// 2. The report was split on whitespace and any matching token accepted, so `v9.9.9 v0.7.2`
    ///    passed.
    /// 3. Leading `v` characters were stripped, so `0.7.2` and `vv0.7.2` passed.
    /// 4. The report was `trim()`ed before comparison, so every whitespace framing passed — no
    ///    newline, CRLF, doubled newlines, leading or trailing spaces, tabs, vertical tabs, form
    ///    feeds, non-breaking spaces — **and** the merged stdout/stderr text meant a client could
    ///    write the report entirely to stderr, or split it across the two streams.
    ///
    /// So: the raw bytes of stdout, compared to these. A pin that accepts a family of spellings is a
    /// pin on none of them.
    pub const PINNED_REPORT: &'static [u8] = b"v0.7.2\n";

    /// The version number alone, for messages.
    pub const PINNED_VERSION: &'static str = "0.7.2";

    /// Refuses an executable that is not the pinned version, before it is asked to do anything.
    ///
    /// `ots --version` prints `v0.7.2`. A fake reporting `v9.9.9` previously completed a submission,
    /// because nothing ever asked.
    pub fn check_version(&self) -> Result<String, String> {
        // **stdout alone, unmodified.** `run` merges stderr into its result, which is right for
        // `stamp` and `upgrade`, where the client reports progress on both; it is wrong here,
        // because it lets the version arrive on the wrong stream or across both.
        let out = std::process::Command::new(&self.executable)
            .args([std::ffi::OsStr::new("--version")])
            .output()
            .map_err(|e| format!("{}: {e}", self.executable.display()))?;
        if !out.status.success() {
            return Err(format!(
                "{}: --version exited {}",
                self.executable.display(),
                out.status
            ));
        }
        let found = String::from_utf8_lossy(&out.stdout).into_owned();
        if out.stdout == Self::PINNED_REPORT {
            Ok(found.trim().to_string())
        } else {
            Err(format!(
                "{}: --version wrote {:?} to stdout, and D-113 pins opentimestamps-client v{}, \
                 whose --version writes exactly {:?}",
                self.executable.display(),
                found,
                Self::PINNED_VERSION,
                String::from_utf8_lossy(Self::PINNED_REPORT)
            ))
        }
    }

    fn run(&self, args: &[&std::ffi::OsStr]) -> Result<String, String> {
        let out = std::process::Command::new(&self.executable)
            .args(args)
            .output()
            .map_err(|e| format!("{}: {e}", self.executable.display()))?;
        let merged = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        if out.status.success() {
            Ok(merged)
        } else {
            Err(merged)
        }
    }
}

#[cfg(feature = "ots")]
impl AnchorB for ReferenceClient {
    fn submit(&self, epoch: u64, root: &Digest) -> Result<PendingReceipt, String> {
        self.check_version()?;
        std::fs::create_dir_all(&self.receipts).map_err(|e| e.to_string())?;
        // The client stamps a file and takes no raw digest, so the root is written to one. The file
        // holds the 32 root bytes and nothing else, which is what the receipt then commits to
        // through SHA-256 (D-119).
        let stamped = self.stamped_path(epoch);
        let receipt = self.receipt_path(epoch);
        // A worker that restarts must not resubmit an epoch it has already stamped: the client
        // refuses to overwrite a receipt, and a second submission would produce a second receipt for
        // one epoch when only one digest can ever be attached (INV-ANCH-03). An existing receipt for
        // the same root is the submission already having happened.
        if receipt.exists() {
            let existing = std::fs::read(&stamped).map_err(|e| e.to_string())?;
            if existing != root {
                return Err(format!(
                    "{}: a receipt already exists for epoch {epoch}, over a different root",
                    receipt.display()
                ));
            }
            return Ok(PendingReceipt {
                epoch,
                root: *root,
                path: receipt,
            });
        }
        std::fs::write(&stamped, root).map_err(|e| e.to_string())?;
        self.run(&[std::ffi::OsStr::new("stamp"), stamped.as_os_str()])?;
        Ok(PendingReceipt {
            epoch,
            root: *root,
            path: self.receipt_path(epoch),
        })
    }

    fn upgrade(&self, pending: &PendingReceipt) -> Result<Option<Digest>, String> {
        // The pin is checked here too. Gating only `submit` left the half that decides whether a
        // receipt is Bitcoin-carrying running on whatever executable the path resolved to.
        self.check_version()?;
        // The reference client exits non-zero while a timestamp is merely pending — "Failed!
        // Timestamp not complete" — and that is the expected state for hours rather than a fault.
        // The exit status is therefore not the verdict: the receipt on disk is read and verified, and
        // a receipt that upgraded to nothing yet is `NotYetConfirmed`. Reading the exit code as the
        // answer made every pending epoch an error.
        let _ = self.run(&[std::ffi::OsStr::new("upgrade"), pending.path.as_os_str()]);
        let bytes = std::fs::read(&pending.path).map_err(|e| e.to_string())?;
        // Checked by an implementation that did not write it, before anything hashes it (D-115).
        match verify_receipt(&bytes, &pending.root) {
            Ok(_claim) => receipt_digest::<certimining_core::NativeKeccak>(&bytes)
                .ok_or_else(|| "the receipt is too long to encode a u16 length".to_string())
                .map(Some),
            Err(ReceiptRefused::NotYetConfirmed) => Ok(None),
            Err(other) => Err(format!("{other:?}")),
        }
    }
}

/// Refuses a key file that anyone but its owner can read (D-117, S6).
///
/// The checkpoint authority is the one key that runs unattended, which is why D-88 kept it away from
/// anything structural. A requirement that is documented and not enforced is a requirement until the
/// first hurried afternoon.
pub fn refuse_a_readable_key(path: &std::path::Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)
            .map_err(|e| format!("{}: {e}", path.display()))?
            .permissions()
            .mode()
            & 0o777;
        if mode != 0o600 {
            return Err(format!(
                "{}: mode {mode:o}, and the checkpoint authority is read only at 0600 (D-117)",
                path.display()
            ));
        }
    }
    Ok(())
}
