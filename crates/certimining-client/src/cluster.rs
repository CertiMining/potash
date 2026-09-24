//! The one implementation that reaches a cluster (§2.3's `AnchorClient`, D-84).
//!
//! Behind the `cluster` feature, so the default build and every test above it stay free of a network.
//! Nothing here decides anything: the decisions live in `fetch` and `publish`, where they are tested
//! without a cluster, and this module carries them to an RPC and back.

use anchor_lang::prelude::Pubkey;
use solana_commitment_config::CommitmentConfig;
use solana_rpc_client::rpc_client::RpcClient;

use crate::fetch::{RootSource, Unreachable};
use crate::publish::{classify, should_retry, Outcome};

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
