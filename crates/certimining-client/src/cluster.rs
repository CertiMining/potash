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

use crate::anchor::{status_of, AnchorRef, AnchorStatus};
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
        Self {
            rpc: RpcClient::new_with_commitment(url, CommitmentConfig::confirmed()),
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
                Err(code) => classify(code),
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

    /// One attempt. `Err(None)` is a submission that never reached the program.
    fn send_publish(
        &self,
        epoch: u64,
        root: Digest,
        payer: &dyn Signer,
        authority: &dyn Signer,
    ) -> Result<String, Option<u32>> {
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
            data: certimining_checkpoint::instruction::PublishCheckpoint { epoch, root }.data(),
        };
        // A fresh blockhash per attempt, fetched here rather than promised in a comment.
        let blockhash = self.rpc.get_latest_blockhash().map_err(|_| None)?;
        let message = Message::new(&[ix], Some(&payer.pubkey()));
        let tx = Transaction::new(&[payer, authority], message, blockhash);
        match self.rpc.send_and_confirm_transaction(&tx) {
            Ok(signature) => Ok(signature.to_string()),
            Err(e) => Err(program_error_code(&e.to_string())),
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
            Settlement::Matches => self.reference(epoch, String::new()),
            other => Err(PublishFailed::NotPublished(other)),
        }
    }

    /// Where the epoch ended up, read back from the chain rather than assumed from the submission.
    fn reference(&self, epoch: u64, signature: String) -> Result<AnchorRef, PublishFailed> {
        match crate::root_for_epoch(self, &self.program_id, epoch)
            .map_err(PublishFailed::Unreachable)?
        {
            Fetched::Placed(c) => Ok(AnchorRef {
                epoch,
                signature,
                published_slot: c.published_slot,
            }),
            _ => Err(PublishFailed::NotPublished(Settlement::Unwritten)),
        }
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
    fn account(&self, address: &Pubkey) -> Result<Option<(Pubkey, Vec<u8>)>, Unreachable> {
        // The two failures are kept apart here rather than merged: an account that is not there is an
        // absence the caller may treat as a gap, and an RPC that will not answer is neither.
        let key = solana_pubkey::Pubkey::from(address.to_bytes());
        match self
            .rpc
            .get_account_with_commitment(&key, self.rpc.commitment())
        {
            Ok(response) => Ok(response
                .value
                .map(|account| (Pubkey::from(account.owner.to_bytes()), account.data))),
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
