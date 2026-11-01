// SPDX-License-Identifier: MIT OR Apache-2.0
//! The one implementation that reaches a cluster: §2.3's `publish` and `status` (D-84, D-110).
//!
//! `timestamp` is not here. It is OpenTimestamps, anchor B, and E-10's unit. Codex round one,
//! finding 3: this header said "§2.3's `AnchorClient`" while the crate implemented none of the
//! trait's three operations, so a reader was told the contract was met by a module carrying a
//! callback loop and an account read.
//!
//! Behind the `cluster` feature, so the default build and every test above it stay free of a network.
//! Nothing here decides anything: the decisions live in `fetch` and `publish`, where they are tested
//! without a cluster, and this module carries them to an RPC and back.

use anchor_lang::prelude::Pubkey;
use solana_commitment_config::CommitmentConfig;
use solana_rpc_client::rpc_client::RpcClient;

use anchor_lang::{InstructionData, ToAccountMetas};
use certimining_core::Digest;
use solana_message::Message;
use solana_signer::Signer;
use solana_transaction::Transaction;
use std::time::Duration;

use crate::anchor::{
    lineage_of, provenance_in, status_of, AnchorRef, AnchorStatus, Lineage, Touched, WhereItLanded,
};
use crate::fetch::{Fetched, RootSource, Unreachable};
use crate::publish::{classify, settle, should_retry, Outcome, Settlement};

/// A cluster, at one endpoint, for one program.
pub struct Cluster {
    rpc: RpcClient,
    program_id: Pubkey,
}

impl Cluster {
    /// A client at `url`, confirming at the commitment a counterparty would use.
    pub fn new(url: String, program_id: Pubkey) -> Self {
        Self::new_with_timeout(url, program_id, Duration::from_secs(30))
    }

    /// A client with an explicit request timeout, used by unattended workers so a partition cannot
    /// leave the state machine blocked forever between observations.
    pub fn new_with_timeout(url: String, program_id: Pubkey, timeout: Duration) -> Self {
        Self {
            rpc: RpcClient::new_with_timeout_and_commitment(
                url,
                timeout,
                CommitmentConfig::confirmed(),
            ),
            program_id,
        }
    }

    /// The program this client reads and writes.
    pub fn program_id(&self) -> Pubkey {
        self.program_id
    }

    /// §2.3's `publish`: one root, one epoch, built, signed, sent and confirmed here.
    ///
    /// The keys belong to the service and this crate holds none, so the payer and the checkpoint
    /// authority are borrowed for the call and never retained. **Every attempt fetches its own
    /// blockhash**, which is what makes a retry a retry rather than a resend of an expired
    /// transaction. `AlreadyPublished` is settled against the chain before it counts as success, so
    /// a late retry succeeds and an epoch carrying somebody else's root does not (D-108).
    pub fn publish(
        &self,
        epoch: u64,
        root: Digest,
        payer: &dyn Signer,
        authority: &dyn Signer,
        attempts: u32,
    ) -> Result<AnchorRef, PublishFailed> {
        let mut left = attempts;
        loop {
            let outcome = match self.send_publish(epoch, root, payer, authority) {
                Ok(signature) => return self.reference(epoch, signature),
                Err(SendPublishFailed::Signing) => return Err(PublishFailed::SigningFailed),
                Err(SendPublishFailed::Submission(code)) => classify(code),
            };
            match outcome {
                Outcome::AlreadyPublished => return self.settle_against_chain(epoch, &root),
                Outcome::Refused(code) => return Err(PublishFailed::Refused(code)),
                _ => {
                    if !should_retry(outcome, left) {
                        return Err(PublishFailed::OutOfAttempts);
                    }
                    left = left.saturating_sub(1);
                }
            }
        }
    }

    /// Attaches a receipt, and refuses one Bitcoin has not carried yet.
    ///
    /// **This is the guard D-112 needed and did not have.** `receipt_digest` is write-once
    /// (INV-ANCH-03), and the program cannot tell an upgraded receipt from a pending one — both are
    /// 32 non-zero bytes. The rule that the single opportunity is spent on a Bitcoin-carrying receipt
    /// is therefore a client rule, and until now it lived only in the order a test harness happened to
    /// call things in. An operator who attached after `submit` and before `upgrade` would have burned
    /// the field on a calendar's promise, permanently, and the epoch would have read `dual` while
    /// nothing outside OpenTimestamps' servers stood behind it.
    ///
    /// The receipt is read here rather than taken as a digest, because a caller who has already
    /// hashed it has already made the decision this function exists to make.
    #[cfg(feature = "ots")]
    pub fn attach(
        &self,
        epoch: u64,
        receipt: &[u8],
        payer: &dyn Signer,
        authority: &dyn Signer,
    ) -> Result<(Digest, crate::BitcoinClaim), AttachRefused> {
        // **The root comes from the chain, not from the caller.** Taking it as an argument checks
        // only that a receipt and a digest agree, not that either is this epoch's: a caller holding
        // a receipt for some other root would attach it here and pass.
        let found = crate::root_for_epoch(self, &self.program_id, epoch)
            .map_err(|e| AttachRefused::Cluster(format!("{e:?}")))?;
        let published = match &found {
            Fetched::Placed(c) => c.root,
            other => return Err(AttachRefused::NotPublished(format!("{other:?}"))),
        };

        // What this establishes: the receipt commits to the root this epoch actually carries, and it
        // carries a Bitcoin attestation rather than only a calendar's promise — which is what D-112
        // spends the single write-once opportunity on.
        //
        // **What it cannot establish**: that the attestation is true. Verifying one means recomputing
        // the operations to that block's merkle root, which needs a source of Bitcoin headers this
        // crate does not have (#48). So this refuses a receipt that does not even claim Bitcoin, and
        // a forged claim would pass. The claim is returned rather than swallowed so a caller sees
        // what it is authorising on.
        let claim = crate::verify_receipt(receipt, &published).map_err(AttachRefused::Receipt)?;
        let digest = crate::receipt_digest::<certimining_core::NativeKeccak>(receipt)
            .ok_or(AttachRefused::TooLong)?;

        // The program this client was pointed at, the way `publish` and `status` do it. Deriving from
        // the compiled-in id instead would have sent a Cluster aimed at a superseded deployment to
        // the announced one.
        let program = solana_pubkey::Pubkey::from(self.program_id.to_bytes());
        let metas = certimining_checkpoint::accounts::Attach {
            config: crate::config_address(&self.program_id),
            checkpoint: crate::checkpoint_address(&self.program_id, epoch),
            authority: Pubkey::from(authority.pubkey().to_bytes()),
        }
        .to_account_metas(None)
        .into_iter()
        .map(|m| solana_instruction::AccountMeta {
            pubkey: solana_pubkey::Pubkey::from(m.pubkey.to_bytes()),
            is_signer: m.is_signer,
            is_writable: m.is_writable,
        })
        .collect();
        let ix = solana_instruction::Instruction {
            program_id: program,
            accounts: metas,
            data: certimining_checkpoint::instruction::AttachAnchorReceipt {
                epoch,
                receipt_digest: digest,
                kind: 1,
            }
            .data(),
        };
        let blockhash = self
            .rpc()
            .get_latest_blockhash()
            .map_err(|e| AttachRefused::Cluster(e.to_string()))?;
        let message = Message::new(&[ix], Some(&payer.pubkey()));
        let mut tx = Transaction::new_unsigned(message);
        tx.try_sign(&[payer, authority], blockhash)
            .map_err(|_| AttachRefused::SigningFailed)?;
        self.rpc()
            .send_and_confirm_transaction(&tx)
            .map_err(|e| AttachRefused::Cluster(e.to_string()))?;
        Ok((digest, claim))
    }

    /// One attempt. `Err(None)` is a submission that never reached the program.
    fn send_publish(
        &self,
        epoch: u64,
        root: Digest,
        payer: &dyn Signer,
        authority: &dyn Signer,
    ) -> Result<String, SendPublishFailed> {
        let program = solana_pubkey::Pubkey::from(self.program_id.to_bytes());
        let checkpoint = crate::checkpoint_address(&self.program_id, epoch);
        let config = crate::config_address(&self.program_id);
        let accounts = certimining_checkpoint::accounts::Publish {
            config,
            checkpoint,
            authority: anchor_lang::prelude::Pubkey::from(authority.pubkey().to_bytes()),
            payer: anchor_lang::prelude::Pubkey::from(payer.pubkey().to_bytes()),
            system_program: anchor_lang::system_program::ID,
        }
        .to_account_metas(None)
        .into_iter()
        .map(|m| solana_instruction::AccountMeta {
            pubkey: solana_pubkey::Pubkey::from(m.pubkey.to_bytes()),
            is_signer: m.is_signer,
            is_writable: m.is_writable,
        })
        .collect();
        let ix = solana_instruction::Instruction {
            program_id: program,
            accounts,
            // The canonical bump, derived here and passed to the program, which makes one
            // `create_program_address` call rather than searching for it (H-52). §1.8 makes
            // canonicality the publisher's, and `checkpoint_bump` is where the publisher derives it.
            data: certimining_checkpoint::instruction::PublishCheckpoint {
                epoch,
                root,
                checkpoint_bump: crate::checkpoint_bump(&self.program_id, epoch),
                end: certimining_checkpoint::NothingFollows,
            }
            .data(),
        };
        // A fresh blockhash per attempt, fetched here rather than promised in a comment.
        let blockhash = self
            .rpc
            .get_latest_blockhash()
            .map_err(|_| SendPublishFailed::Submission(None))?;
        let message = Message::new(&[ix], Some(&payer.pubkey()));
        let mut tx = Transaction::new_unsigned(message);
        tx.try_sign(&[payer, authority], blockhash)
            .map_err(|_| SendPublishFailed::Signing)?;
        match self.rpc.send_and_confirm_transaction(&tx) {
            Ok(signature) => Ok(signature.to_string()),
            Err(e) => Err(SendPublishFailed::Submission(program_error_code(
                &e.to_string(),
            ))),
        }
    }

    fn settle_against_chain(&self, epoch: u64, root: &Digest) -> Result<AnchorRef, PublishFailed> {
        let found = crate::root_for_epoch(self, &self.program_id, epoch)
            .map_err(PublishFailed::Unreachable)?;
        let on_chain = match &found {
            Fetched::Placed(c) => Some(c.root),
            _ => None,
        };
        match settle(root, on_chain.as_ref()) {
            // **The signature is recovered from the chain (H-35, issue #82).** This path used to
            // return a publication with an empty signature, so nothing could bind its slot to a
            // chain and `Lineage::NoSignature` was all a caller could learn. The chain can name the
            // transaction that wrote the account; where it cannot, the empty signature stands and
            // says so.
            Settlement::Matches => {
                let slot = match &found {
                    Fetched::Placed(c) => Some(c.published_slot),
                    _ => None,
                };
                let recovered = slot
                    .and_then(|slot| self.wrote_it(epoch, slot))
                    .unwrap_or_default();
                self.reference(epoch, recovered)
            }
            other => Err(PublishFailed::NotPublished(other)),
        }
    }

    /// The signature the chain says wrote this epoch's checkpoint, for the path that holds none.
    ///
    /// **A failure to ask returns `None`, and that is not a lie here.** The caller's fallback is an
    /// empty signature, which `lineage_of` reports as `NoSignature` — "nothing binds this" — so an
    /// unreachable endpoint and an unnameable transaction both end at the same honest answer rather
    /// than at a borrowed one.
    fn wrote_it(&self, epoch: u64, published_slot: u64) -> Option<String> {
        let address = solana_pubkey::Pubkey::from(
            crate::checkpoint_address(&self.program_id, epoch).to_bytes(),
        );
        let listing = self.rpc.get_signatures_for_address(&address).ok()?;
        let touched: Vec<Touched> = listing
            .into_iter()
            .map(|entry| Touched {
                signature: entry.signature,
                slot: entry.slot,
                succeeded: entry.err.is_none(),
            })
            .collect();
        provenance_in(published_slot, &touched).map(str::to_string)
    }

    /// Where the epoch ended up, read back from the chain rather than assumed from the submission.
    ///
    /// **The lineage is asked for here (H-35, issue #82).** `published_slot` is what the program saw
    /// on the fork where it executed; a caller measuring anything against it needs to know whether the
    /// chain this endpoint serves agrees. So the signature's own landing slot is asked for and the
    /// answer is classified by `lineage_of`, which is pure and tested without a cluster.
    fn reference(&self, epoch: u64, signature: String) -> Result<AnchorRef, PublishFailed> {
        match crate::root_for_epoch(self, &self.program_id, epoch)
            .map_err(PublishFailed::Unreachable)?
        {
            Fetched::Placed(c) => {
                // Not asked for an empty signature: there is nothing to ask about, and a request
                // for one would fail and be recorded as `Unasked` rather than `NoSignature`.
                let landed = if signature.is_empty() {
                    WhereItLanded::NotFound
                } else {
                    self.where_it_landed(&signature)
                };
                Ok(AnchorRef {
                    epoch,
                    lineage: lineage_of(c.published_slot, &signature, &landed),
                    signature,
                    published_slot: c.published_slot,
                })
            }
            _ => Err(PublishFailed::NotPublished(Settlement::Unwritten)),
        }
    }

    /// Asks the endpoint which slot a signature's transaction landed in.
    ///
    /// `getSignatureStatuses` answers from the chain this endpoint serves, which is the whole value
    /// of asking: the account's `published_slot` came from the fork the program ran on, and this is
    /// the other side of the comparison.
    ///
    /// **Its window is bounded and that is why `NotFound` is its own answer.** Solana keeps a
    /// signature's status for a limited number of recent slots, so asking about a transaction that
    /// certainly landed, late enough, gets `NotFound`. That is not evidence against the publication
    /// and `Lineage::Unknown` is not a refusal.
    fn where_it_landed(&self, signature: &str) -> WhereItLanded {
        let parsed = match signature.parse::<solana_signature::Signature>() {
            Ok(parsed) => parsed,
            Err(e) => return WhereItLanded::NotAsked(format!("{signature}: {e}")),
        };
        match self.rpc.get_signature_statuses(&[parsed]) {
            Err(e) => WhereItLanded::NotAsked(e.to_string()),
            Ok(answered) => match answered.value.first() {
                Some(Some(status)) => WhereItLanded::Slot(status.slot),
                Some(None) => WhereItLanded::NotFound,
                None => WhereItLanded::NotAsked(
                    "the endpoint returned no entry for the one signature it was asked about"
                        .to_string(),
                ),
            },
        }
    }

    /// The chain's slot, refused unless the endpoint's own view has reached `min_context_slot`.
    ///
    /// **This is the upper end of V-Z-01's bracket, bound (H-35, issue #82).** `getSlot` takes
    /// `minContextSlot`, and an endpoint whose view is behind it answers with an error instead of an
    /// older slot. A reading taken this way is from a view that already contains the publication,
    /// rather than a number that happens to be larger than another number.
    ///
    /// The typed client has `get_slot_with_commitment` and nothing that carries a context slot, so
    /// the request is sent as itself. `RpcContextConfig` is `getSlot`'s own config type, not a shape
    /// invented here.
    pub fn slot_at_least(&self, min_context_slot: u64) -> Result<u64, Unreachable> {
        let config = solana_rpc_client_api::config::RpcContextConfig {
            commitment: Some(self.rpc.commitment()),
            min_context_slot: Some(min_context_slot),
        };
        self.rpc
            .send(
                solana_rpc_client_api::request::RpcRequest::GetSlot,
                serde_json::json!([config]),
            )
            .map_err(|e| {
                Unreachable(format!(
                    "getSlot with minContextSlot {min_context_slot}: {e}. An endpoint whose view \
                     has not reached the publication's slot cannot answer for a chain containing it."
                ))
            })
    }

    /// Whether a publication's two slot readings agree about one chain.
    ///
    /// Sugar over `AnchorRef::lineage` for a caller that only wants the yes or no, kept here so the
    /// comparison is written once.
    pub fn is_bound(reference: &AnchorRef) -> bool {
        reference.lineage == Lineage::AtItsSlot
    }

    /// §2.3's `status`: `Pending`, `Single` or `Dual` for one epoch (INV-ANCH-05).
    pub fn status(&self, epoch: u64) -> Result<AnchorStatus, Unreachable> {
        Ok(status_of(&crate::root_for_epoch(
            self,
            &self.program_id,
            epoch,
        )?))
    }

    /// The RPC underneath, for a caller that builds and signs its own transaction. The keys belong to
    /// the service and this crate holds none.
    pub fn rpc(&self) -> &RpcClient {
        &self.rpc
    }

    /// Sends through `submit`, re-sending while the outcome says it is safe to.
    ///
    /// `submit` returns the program's own error code when the program refused, and `None` when the
    /// submission never reached it. The retry rule is `publish`'s and is tested there: a submission
    /// that never arrived may be sent again, a refusal is final, and an epoch that already has a
    /// checkpoint is success. A retry re-sends with a fresh blockhash, which §4.4's closed list
    /// already permits to differ, and it never moves the publication time, which belongs to the
    /// schedule (INV-ANCH-01).
    pub fn send_with_retry<F>(&self, mut submit: F, attempts: u32) -> Outcome
    where
        F: FnMut(&RpcClient) -> Result<(), Option<u32>>,
    {
        let mut left = attempts;
        loop {
            let outcome = match submit(&self.rpc) {
                Ok(()) => Outcome::Landed,
                Err(code) => classify(code),
            };
            if !should_retry(outcome, left) {
                return outcome;
            }
            left = left.saturating_sub(1);
        }
    }
}

impl RootSource for Cluster {
    fn account_at(&self, address: &Pubkey) -> Result<crate::Observation, Unreachable> {
        // The two failures are kept apart here rather than merged: an account that is not there is an
        // absence the caller may treat as a gap, and an RPC that will not answer is neither.
        let key = solana_pubkey::Pubkey::from(address.to_bytes());
        match self
            .rpc
            .get_account_with_commitment(&key, self.rpc.commitment())
        {
            // **The response's own slot, which this discarded until H-07.** It is what lets a caller
            // making several reads tell one view of the chain from several.
            Ok(response) => Ok(crate::Observation {
                slot: Some(response.context.slot),
                account: response
                    .value
                    .map(|account| (Pubkey::from(account.owner.to_bytes()), account.data)),
            }),
            Err(e) => Err(Unreachable(e.to_string())),
        }
    }

    /// `getMultipleAccounts`, which is one request and therefore one view (H-54, issue #197).
    ///
    /// The response carries a single context slot for every address in it, so the answers are one
    /// snapshot of the chain by construction. That is the whole reason this method exists: comparing
    /// the slots of several separate reads catches a stale one and cannot catch two served from
    /// different confirmed forks.
    fn accounts_at(&self, addresses: &[Pubkey]) -> Result<crate::OneView, Unreachable> {
        if addresses.len() > crate::ONE_VIEW_LIMIT {
            return Err(Unreachable(format!(
                "{} addresses in one request and getMultipleAccounts takes {}. Splitting them here \
                 would return several views under the name of one, which is what this method exists \
                 to avoid.",
                addresses.len(),
                crate::ONE_VIEW_LIMIT
            )));
        }
        let keys: Vec<solana_pubkey::Pubkey> = addresses
            .iter()
            .map(|a| solana_pubkey::Pubkey::from(a.to_bytes()))
            .collect();
        match self
            .rpc
            .get_multiple_accounts_with_commitment(&keys, self.rpc.commitment())
        {
            Ok(response) => Ok(crate::OneView {
                slot: Some(response.context.slot),
                accounts: response
                    .value
                    .into_iter()
                    .map(|account| account.map(|a| (Pubkey::from(a.owner.to_bytes()), a.data)))
                    .collect(),
            }),
            Err(e) => Err(Unreachable(e.to_string())),
        }
    }
}

/// Why a publication did not produce a reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublishFailed {
    /// The program refused, with §2.1's code plus Anchor's offset.
    Refused(u32),
    /// The epoch reported as already written, and the chain does not agree it holds this root.
    NotPublished(Settlement),
    /// The cluster could not be asked.
    Unreachable(Unreachable),
    /// Every attempt was a submission that never reached the program.
    OutOfAttempts,
    /// A local signer refused or returned an invalid signature; no transaction was submitted.
    SigningFailed,
}

enum SendPublishFailed {
    Signing,
    Submission(Option<u32>),
}

/// The program's own error code, dug out of the RPC's rendering of a failed transaction.
///
/// `None` means the submission never reached the program, which is the one case a resend can fix.
/// The string form is what the RPC gives; parsing it is ugly and it is the only thing offered.
fn program_error_code(rendered: &str) -> Option<u32> {
    const MARKER: &str = "custom program error: ";
    // INV-ERR-01 forbids unchecked arithmetic on any path, and this one runs on whatever an RPC
    // chose to send back.
    let at = rendered.find(MARKER)?.checked_add(MARKER.len())?;
    let rest = rendered.get(at..)?;
    let hex = rest.strip_prefix("0x")?;
    let end = hex
        .find(|c: char| !c.is_ascii_hexdigit())
        .unwrap_or(hex.len());
    u32::from_str_radix(&hex[..end], 16).ok()
}

/// Why an attachment was refused before anything reached the cluster.
#[cfg(feature = "ots")]
#[derive(Debug)]
pub enum AttachRefused {
    /// The receipt does not carry a Bitcoin attestation yet, or does not commit to this root.
    Receipt(crate::ReceiptRefused),
    /// The receipt is longer than the digest's u16 length prefix can encode.
    TooLong,
    /// The epoch carries no root on chain, so there is nothing for a receipt to be about.
    NotPublished(String),
    /// The cluster refused or could not be reached.
    Cluster(String),
    /// A local signer refused or returned an invalid signature; no transaction was submitted.
    SigningFailed,
}
