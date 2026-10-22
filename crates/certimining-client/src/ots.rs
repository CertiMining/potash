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
/// The Bitcoin attestation a receipt carries — **what the receipt asserts, not what has been
/// checked.**
///
/// Both fields come out of the receipt. The height is read from the attestation; the digest is
/// *computed*, by this crate executing the receipt's operations from the start digest, which is why
/// the file cannot assert it. Neither has been compared with Bitcoin: that comparison needs a block
/// header, and `bitcoin::confirm` is the half that does it, returning a `bitcoin::Confirmed` that
/// only that path can build. **A forged receipt naming a block it never reached still passes this
/// function**, which is why the two types are different types (H-12, issue #48).
#[cfg(feature = "ots")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BitcoinClaim {
    /// The block height the receipt names. Unchecked.
    pub height: u32,
    /// The digest the receipt's operations reach, which that block's merkle root must equal.
    ///
    /// **Derived rather than read.** `opentimestamps` executes each operation as it deserialises and
    /// stores the result, so this is the output of appending, prepending and hashing from the start
    /// digest onward — a value a forged file cannot simply state. What it is *not* is a merkle root
    /// anyone has seen: that is `bitcoin::confirm`'s business.
    ///
    /// In Bitcoin's internal byte order, which is how a header stores its merkle root and how
    /// OpenTimestamps compares against it. Reversing it gives the spelling an explorer displays.
    pub attested_digest: [u8; 32],
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
    //
    // **The step's `output` is what the operations reach**, and it is the second half of what a
    // caller needs. `opentimestamps` computes it while deserialising — `op.execute(&input_digest)`
    // per step — so it is derived from the start digest and the operations, not read out of the
    // file. That is what makes it worth comparing with a block.
    fn confirmed(step: &Step) -> Option<(usize, &[u8])> {
        if let StepData::Attestation(Attestation::Bitcoin { height }) = step.data {
            return Some((height, step.output.as_slice()));
        }
        step.next.iter().find_map(confirmed)
    }

    let Some((height, output)) = confirmed(&parsed.timestamp.first_step) else {
        return Err(ReceiptRefused::NotYetConfirmed);
    };
    // **`as u32` was a silent truncation**, and the crate's height is a `usize`. A height above
    // `u32::MAX` is not a Bitcoin height, and a receipt claiming one would have had it wrapped into a
    // plausible small number rather than refused. Nothing produces such a receipt; a cast that
    // quietly invents a credible value out of an incredible one is the shape of defect this file is
    // full of notes about.
    let height = u32::try_from(height).map_err(|_| {
        ReceiptRefused::Unparsable(format!("the attestation names block height {height}"))
    })?;
    let attested_digest = <[u8; 32]>::try_from(output).map_err(|_| {
        ReceiptRefused::Unparsable(format!(
            "the attestation's operations reach {} bytes and a merkle root is 32",
            output.len()
        ))
    })?;
    Ok(BitcoinClaim {
        height,
        attested_digest,
    })
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

    /// Where this epoch's receipt lives. Public because the worker asks whether one exists yet
    /// (H-13): an epoch with a receipt that the chain still calls single is one waiting to attach.
    pub fn receipt_path(&self, epoch: u64) -> std::path::PathBuf {
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

    /// The committed fingerprint of the client's own Python sources, baked in at compile time.
    ///
    /// `include_str!` rather than a path read at runtime: a digest the process reads from disk can be
    /// replaced by whatever replaced the client.
    pub const FINGERPRINT: &'static str = include_str!("../../../OTS-CLIENT.sha256");

    /// Refuses a client whose sources are not the ones this repository pinned (H-17, issue #53).
    ///
    /// **Why this exists beside [`check_version`](Self::check_version).** That asks the tool to
    /// report on itself, and any self-report can be framed: four versions of it were wrong, each
    /// looser than it looked, and the accepted byte-exact comparison is still the same shape. A client
    /// that prints `v0.7.2\n` is not thereby the pinned client, and a wrapper that prints the right
    /// bytes and then shells out elsewhere passes it.
    ///
    /// This reads the files instead. Three things are checked, and the third is the one a manifest
    /// alone would miss:
    ///
    /// 1. Every path in the manifest hashes to its recorded digest.
    /// 2. The entry point still imports `otsclient.ots`'s `main`, and its interpreter is inside this
    ///    virtualenv — the wrapper attack the version check cannot see. Its bytes are not hashed,
    ///    because the shebang carries an absolute path and would differ on every machine.
    /// 3. **No `.py` file exists under those packages that the manifest does not list.** A manifest
    ///    checked only forwards is satisfied by an install with an extra module in it.
    pub fn check_fingerprint(&self) -> Result<usize, String> {
        self.fingerprint_against(Self::FINGERPRINT)
    }

    /// The comparison itself, against a manifest the caller supplies.
    ///
    /// Separated from [`check_fingerprint`](Self::check_fingerprint) so the tests can state an
    /// install and a manifest and drive every refusal, rather than needing the pinned client to be
    /// present and then being unable to make it wrong.
    pub fn fingerprint_against(&self, manifest: &str) -> Result<usize, String> {
        use bitcoin_hashes::{sha256, Hash};

        let venv = self
            .executable
            .parent()
            .and_then(|bin| bin.parent())
            .ok_or_else(|| format!("{}: no virtualenv above it", self.executable.display()))?;
        let lib = venv.join("lib");
        let mut site = None;
        for entry in std::fs::read_dir(&lib).map_err(|e| format!("{}: {e}", lib.display()))? {
            let path = entry.map_err(|e| format!("{}: {e}", lib.display()))?.path();
            let candidate = path.join("site-packages");
            if candidate.is_dir() {
                site = Some(candidate);
                break;
            }
        }
        let site =
            site.ok_or_else(|| format!("{}: no python*/site-packages beneath it", lib.display()))?;

        let mut listed: std::collections::BTreeMap<String, String> =
            std::collections::BTreeMap::new();
        for line in manifest.lines().filter(|l| !l.trim().is_empty()) {
            let (digest, path) = line
                .split_once("  ")
                .ok_or_else(|| format!("OTS-CLIENT.sha256: malformed line {line:?}"))?;
            listed.insert(path.to_string(), digest.to_string());
        }
        if listed.is_empty() {
            return Err(
                "OTS-CLIENT.sha256 lists no files, so this check would pass on any install"
                    .to_string(),
            );
        }

        let mut wrong = Vec::new();
        for (path, want) in &listed {
            let at = site.join(path);
            let bytes = match std::fs::read(&at) {
                Ok(b) => b,
                Err(e) => {
                    wrong.push(format!("{path}: {e}"));
                    continue;
                }
            };
            let got = format!("{}", sha256::Hash::hash(&bytes));
            if &got != want {
                wrong.push(format!("{path}: pinned {want}, found {got}"));
            }
        }

        // The direction a manifest alone misses: a file that is there and is not listed.
        for package in ["opentimestamps", "otsclient"] {
            let mut stack = vec![site.join(package)];
            while let Some(dir) = stack.pop() {
                let entries = match std::fs::read_dir(&dir) {
                    Ok(e) => e,
                    Err(e) => {
                        wrong.push(format!("{}: {e}", dir.display()));
                        continue;
                    }
                };
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        if path.file_name().is_some_and(|n| n != "__pycache__") {
                            stack.push(path);
                        }
                        continue;
                    }
                    if path.extension().is_some_and(|e| e == "py") {
                        let relative = path
                            .strip_prefix(&site)
                            .map(|r| r.to_string_lossy().into_owned())
                            .unwrap_or_default();
                        if !listed.contains_key(&relative) {
                            wrong.push(format!("{relative}: present and not pinned"));
                        }
                    }
                }
            }
        }

        // The entry point, checked for what it does rather than for its bytes.
        let shim = std::fs::read_to_string(&self.executable)
            .map_err(|e| format!("{}: {e}", self.executable.display()))?;
        if !shim.contains("from otsclient.ots import main") {
            wrong.push(format!(
                "{}: does not import otsclient.ots's main, so the pinned sources may not be what runs",
                self.executable.display()
            ));
        }
        let interpreter = shim.lines().next().unwrap_or_default();
        if !interpreter.starts_with("#!") || !interpreter.contains(&*venv.to_string_lossy()) {
            wrong.push(format!(
                "{}: its interpreter is {interpreter:?}, which is not inside {}",
                self.executable.display(),
                venv.display()
            ));
        }

        if wrong.is_empty() {
            Ok(listed.len())
        } else {
            Err(format!(
                "the OpenTimestamps client does not match OTS-CLIENT.sha256:\n  {}",
                wrong.join("\n  ")
            ))
        }
    }

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
            // **A file is not a submission (H-14).** Existence alone was the test, so a `stamp` that
            // left a partial or unreadable `.ots` and exited non-zero produced a file that every
            // later call read as "already done": the epoch never anchored, every `upgrade` found
            // bytes it could not parse, and nothing said why. Existence mapped onto success, which
            // is the shape this repository keeps finding.
            //
            // So the receipt is parsed before it is believed. `NotYetConfirmed` is the ordinary
            // state of a receipt waiting for a Bitcoin block and is accepted; anything that does not
            // parse, or that timestamps something else, is refused here rather than hours later.
            let bytes =
                std::fs::read(&receipt).map_err(|e| format!("{}: {e}", receipt.display()))?;
            match verify_receipt(&bytes, &existing) {
                Ok(_) | Err(ReceiptRefused::NotYetConfirmed) => {}
                Err(ReceiptRefused::Unparsable(why)) => {
                    return Err(format!(
                        "{}: a receipt exists for epoch {epoch} and does not parse ({why}). It was \
                         left by a stamp that did not finish. Nothing can upgrade or attach it. \
                         Remove it and submit again.",
                        receipt.display()
                    ));
                }
                Err(ReceiptRefused::WrongRoot) => {
                    return Err(format!(
                        "{}: a receipt exists for epoch {epoch} and timestamps a digest other than \
                         the root beside it. The pair on disk disagree and neither can be trusted.",
                        receipt.display()
                    ));
                }
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
