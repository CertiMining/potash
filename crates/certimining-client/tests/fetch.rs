// SPDX-License-Identifier: MIT OR Apache-2.0
//! E-09: deriving a root by epoch with no indexer, placing what comes back, and surfacing gaps.
//!
//! The cluster is a map here, because `RootSource` is a trait: an RPC that returns the wrong thing is
//! easier to build in a test than to provoke on a network, and those are the cases that matter.

use anchor_lang::prelude::Pubkey;
use anchor_lang::{AnchorSerialize, Discriminator};
use certimining_checkpoint::{CheckpointAccount, LogConfig};
use certimining_client::{
    checkpoint_address, config_address, decode_checkpoint, root_for_epoch, sequence_lag, Fetched,
    Refused, RootSource, Unreachable,
};
use std::collections::HashMap;

const PROGRAM: Pubkey = certimining_checkpoint::ID;

/// A cluster that holds exactly what a test put in it.
#[derive(Default)]
struct Cluster {
    accounts: HashMap<Pubkey, (Pubkey, Vec<u8>)>,
}

impl RootSource for Cluster {
    fn account(&self, address: &Pubkey) -> Result<Option<(Pubkey, Vec<u8>)>, Unreachable> {
        Ok(self.accounts.get(address).cloned())
    }
}

/// A cluster nobody can ask, which is a different thing from one holding nothing.
struct Offline;

impl RootSource for Offline {
    fn account(&self, _address: &Pubkey) -> Result<Option<(Pubkey, Vec<u8>)>, Unreachable> {
        Err(Unreachable("the endpoint refused the connection".into()))
    }
}

impl Cluster {
    fn put(&mut self, address: Pubkey, owner: Pubkey, data: Vec<u8>) {
        self.accounts.insert(address, (owner, data));
    }

    /// A checkpoint with anchor B's receipt attached.
    fn publish_dual(&mut self, epoch: u64, root: [u8; 32], receipt: [u8; 32]) {
        self.publish(epoch, root);
        let address = checkpoint_address(&PROGRAM, epoch);
        let (owner, mut data) = self
            .accounts
            .get(&address)
            .cloned()
            .expect("just published");
        data[66..98].copy_from_slice(&receipt);
        data[98] = 1;
        self.put(address, owner, data);
    }

    /// The log's configuration, as `initialize` writes one.
    fn configure(&mut self, start_epoch: u64, last_epoch: u64) {
        let config = LogConfig {
            schema_version: 1,
            authority: PROGRAM,
            last_epoch,
            tree_height: 8,
            bump: 255,
            start_epoch,
            reserved: [0u8; 8],
        };
        let mut data = LogConfig::DISCRIMINATOR.to_vec();
        config.serialize(&mut data).expect("serializes");
        data.resize(LogConfig::LEN, 0);
        self.put(config_address(&PROGRAM), PROGRAM, data);
    }

    /// A checkpoint as the program writes one.
    fn publish(&mut self, epoch: u64, root: [u8; 32]) {
        let account = CheckpointAccount {
            schema_version: 1,
            epoch,
            root,
            published_slot: 1_000 + epoch,
            published_unix: 1_700_000_000 + epoch as i64,
            receipt_digest: [0u8; 32],
            anchor_kind: 0,
            bump: 255,
            reserved: [0u8; 6],
        };
        self.put(
            checkpoint_address(&PROGRAM, epoch),
            PROGRAM,
            encode(&account),
        );
    }
}

fn encode(account: &CheckpointAccount) -> Vec<u8> {
    let mut data = CheckpointAccount::DISCRIMINATOR.to_vec();
    account.serialize(&mut data).expect("serializes");
    data.resize(CheckpointAccount::LEN, 0);
    data
}

#[test]
fn an_epochs_address_is_derived_and_not_searched_for() {
    // The same seeds the program uses, so the client needs no index and no list of accounts.
    let a = checkpoint_address(&PROGRAM, 20_361);
    let b = Pubkey::find_program_address(
        &[CheckpointAccount::SEED, &20_361u64.to_le_bytes()],
        &PROGRAM,
    )
    .0;
    assert_eq!(a, b);
    assert_ne!(a, checkpoint_address(&PROGRAM, 20_362));
}

#[test]
fn a_published_root_comes_back_with_what_the_program_wrote() {
    let mut cluster = Cluster::default();
    cluster.publish(7, [0xab; 32]);
    let found = root_for_epoch(&cluster, &PROGRAM, 7).expect("the cluster answered");
    let Fetched::Placed(checkpoint) = found else {
        panic!("a published root should be placed, and this was {found:?}")
    };
    assert_eq!(checkpoint.epoch, 7);
    assert_eq!(checkpoint.root, [0xab; 32]);
    assert_eq!(checkpoint.receipt_digest, [0u8; 32]);
}

#[test]
fn an_account_owned_by_someone_else_is_refused() {
    // The shape is right and the owner is not: this is what a look-alike program produces.
    let mut cluster = Cluster::default();
    let account = CheckpointAccount {
        schema_version: 1,
        epoch: 7,
        root: [0x99; 32],
        published_slot: 1,
        published_unix: 1,
        receipt_digest: [0u8; 32],
        anchor_kind: 0,
        bump: 255,
        reserved: [0u8; 6],
    };
    cluster.put(
        checkpoint_address(&PROGRAM, 7),
        Pubkey::new_unique(),
        encode(&account),
    );
    assert_eq!(
        root_for_epoch(&cluster, &PROGRAM, 7).expect("answered"),
        Fetched::Refused(Refused::NotTheProgram),
        "D-82: an RPC can return anything, and ownership is the first thing to check"
    );
}

#[test]
fn an_account_for_another_epoch_is_refused_at_the_epoch_it_claims() {
    // The dangerous case: a real checkpoint, correctly owned, returned for the wrong question.
    let mut cluster = Cluster::default();
    let account = CheckpointAccount {
        schema_version: 1,
        epoch: 9,
        root: [0x11; 32],
        published_slot: 1,
        published_unix: 1,
        receipt_digest: [0u8; 32],
        anchor_kind: 0,
        bump: 255,
        reserved: [0u8; 6],
    };
    cluster.put(checkpoint_address(&PROGRAM, 7), PROGRAM, encode(&account));
    assert_eq!(
        root_for_epoch(&cluster, &PROGRAM, 7).expect("answered"),
        Fetched::Refused(Refused::WrongEpoch),
        "D-82: the stored epoch must be the epoch asked for"
    );
}

#[test]
fn an_account_under_another_schema_or_discriminator_is_refused() {
    let mut cluster = Cluster::default();
    let account = CheckpointAccount {
        schema_version: 2,
        epoch: 7,
        root: [0x11; 32],
        published_slot: 1,
        published_unix: 1,
        receipt_digest: [0u8; 32],
        anchor_kind: 0,
        bump: 255,
        reserved: [0u8; 6],
    };
    cluster.put(checkpoint_address(&PROGRAM, 7), PROGRAM, encode(&account));
    assert_eq!(
        root_for_epoch(&cluster, &PROGRAM, 7).expect("answered"),
        Fetched::Refused(Refused::UnsupportedSchema)
    );

    let mut wrong_discriminator = encode(&CheckpointAccount {
        schema_version: 1,
        ..account
    });
    wrong_discriminator[0] ^= 0xff;
    cluster.put(
        checkpoint_address(&PROGRAM, 7),
        PROGRAM,
        wrong_discriminator,
    );
    assert_eq!(
        root_for_epoch(&cluster, &PROGRAM, 7).expect("answered"),
        Fetched::Refused(Refused::NotACheckpoint)
    );

    cluster.put(checkpoint_address(&PROGRAM, 7), PROGRAM, vec![0u8; 20]);
    assert_eq!(
        root_for_epoch(&cluster, &PROGRAM, 7).expect("answered"),
        Fetched::Refused(Refused::TooShort)
    );
}

/// D-106 as amended, 26 Sep 2026. `publish_checkpoint` accepts `last_epoch + 1` and nothing else, so
/// the published range is contiguous by construction and an interior gap cannot exist. What a stalled
/// batcher shows is a sequence that has not reached the epochs a caller is asking about.
#[test]
fn a_sequence_that_has_not_reached_an_epoch_reports_lag_not_a_gap() {
    let mut cluster = Cluster::default();
    cluster.configure(100, 104);
    for epoch in 100..=104 {
        cluster.publish(epoch, [epoch as u8; 32]);
    }

    let lag = sequence_lag(&cluster, &PROGRAM, 100, 107).expect("the cluster answered");
    assert_eq!(lag.start_epoch, 100);
    assert_eq!(lag.last_published, 104);
    assert_eq!(lag.not_yet_published, vec![105, 106, 107]);
    assert_eq!(
        lag.epochs_behind(),
        3,
        "the number a caller with a clock needs in order to rule"
    );
    assert!(lag.before_log_start.is_empty());
    assert!(lag.refused.is_empty());
}

/// An epoch before the log existed is not a gap and not a lag. A client that could not tell them
/// apart would accuse a batcher of failing to publish before it was deployed (INV-ANCH-02, D-109).
#[test]
fn an_epoch_before_the_log_started_is_neither_a_gap_nor_a_lag() {
    let mut cluster = Cluster::default();
    cluster.configure(100, 102);
    for epoch in 100..=102 {
        cluster.publish(epoch, [epoch as u8; 32]);
    }

    let lag = sequence_lag(&cluster, &PROGRAM, 97, 102).expect("the cluster answered");
    assert_eq!(lag.before_log_start, vec![97, 98, 99]);
    assert!(lag.not_yet_published.is_empty());
    assert_eq!(
        lag.epochs_behind(),
        0,
        "a log that has published everything asked of it"
    );
}

/// An account a third party placed at a derived address is inside the published range and is still
/// not a root this client will use. It is not a gap either: it is evidence about whoever placed it.
#[test]
fn an_epoch_inside_the_range_whose_account_was_refused_is_named_as_that() {
    let mut cluster = Cluster::default();
    cluster.configure(100, 102);
    cluster.publish(100, [1u8; 32]);
    cluster.publish(101, [2u8; 32]);
    cluster.put(
        checkpoint_address(&PROGRAM, 102),
        Pubkey::new_unique(),
        vec![0u8; CheckpointAccount::LEN],
    );

    let lag = sequence_lag(&cluster, &PROGRAM, 100, 102).expect("the cluster answered");
    assert_eq!(lag.refused, vec![(102, Refused::NotTheProgram)]);
    assert!(!lag.is_empty());
}

/// The condition the program's own monotonicity forbids. If an account inside the published range is
/// absent, the configuration is not one this program wrote, and that is reported as a thing nobody
/// can reason from rather than as a gap.
#[test]
fn an_absent_account_inside_the_published_range_is_an_impossible_state() {
    let mut cluster = Cluster::default();
    cluster.configure(100, 104);
    cluster.publish(100, [1u8; 32]);
    // 101 is deliberately not published, which `publish_checkpoint` could never have allowed.
    let refused = sequence_lag(&cluster, &PROGRAM, 100, 104);
    assert!(
        refused.is_err(),
        "the client says it cannot reason from this, rather than inventing a gap"
    );
    assert!(format!("{:?}", refused.unwrap_err()).contains("impossible"));
}

#[test]
fn a_cluster_nobody_can_ask_is_not_a_wall_of_gaps() {
    // The distinction that matters: a gap accuses the batcher, and an unreachable endpoint accuses
    // nothing. Collapsing the two would let an outage produce the accusation.
    assert!(
        root_for_epoch(&Offline, &PROGRAM, 7).is_err(),
        "an endpoint that will not answer is not an absent checkpoint"
    );
    assert!(
        sequence_lag(&Offline, &PROGRAM, 1, 100).is_err(),
        "and a hundred epochs nobody could ask about is not a hundred of anything"
    );
}

#[test]
fn nothing_at_the_address_is_not_the_same_as_a_refusal() {
    let cluster = Cluster::default();
    assert_eq!(
        root_for_epoch(&cluster, &PROGRAM, 7).expect("answered"),
        Fetched::Absent,
        "an unpublished epoch is absence, and absence is a gap rather than a bad root"
    );
    assert_eq!(
        decode_checkpoint(&PROGRAM, &PROGRAM, &[0u8; 106], 7).err(),
        Some(Refused::NotACheckpoint),
        "and a zeroed account is a refusal"
    );
}

/// Codex round one, finding 3. §2.3's `status` is `Pending`, `Single` or `Dual`, and INV-ANCH-05
/// forbids degrading silently to a dual-anchor claim. The decision is made without a network, so it
/// is tested without one (D-110).
mod status {
    use super::*;
    use certimining_client::{status_of, AnchorStatus};

    #[test]
    fn an_epoch_with_no_checkpoint_is_pending() {
        assert_eq!(status_of(&Fetched::Absent), AnchorStatus::Pending);
    }

    #[test]
    fn a_root_without_a_receipt_is_single_and_never_dual() {
        let mut cluster = Cluster::default();
        cluster.publish(1, [1u8; 32]);
        let fetched = root_for_epoch(&cluster, &PROGRAM, 1).expect("answered");
        assert_eq!(status_of(&fetched), AnchorStatus::Single);
    }

    #[test]
    fn a_root_with_a_receipt_attached_is_dual() {
        let mut cluster = Cluster::default();
        cluster.publish_dual(1, [1u8; 32], [0x44; 32]);
        let fetched = root_for_epoch(&cluster, &PROGRAM, 1).expect("answered");
        assert_eq!(status_of(&fetched), AnchorStatus::Dual);
    }

    #[test]
    fn an_account_this_client_refuses_is_pending_rather_than_anchored() {
        // Reporting a refused account as Single would be INV-ANCH-05's silent degradation pointed
        // the other way: a root the client does not have, announced as one it does.
        assert_eq!(
            status_of(&Fetched::Refused(Refused::NotTheProgram)),
            AnchorStatus::Pending
        );
    }
}
