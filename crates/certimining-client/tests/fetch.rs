//! E-09: deriving a root by epoch with no indexer, placing what comes back, and surfacing gaps.
//!
//! The cluster is a map here, because `RootSource` is a trait: an RPC that returns the wrong thing is
//! easier to build in a test than to provoke on a network, and those are the cases that matter.

use anchor_lang::prelude::Pubkey;
use anchor_lang::{AnchorSerialize, Discriminator};
use certimining_checkpoint::CheckpointAccount;
use certimining_client::{
    checkpoint_address, decode_checkpoint, missing_epochs, root_for_epoch, Fetched, Refused,
    RootSource, Unreachable,
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

#[test]
fn a_gap_is_named_rather_than_noted() {
    // INV-ANCH-02: a gap in the sequence is evidence of batcher failure, and the client must surface
    // it. The function returns the epochs, so a caller cannot reduce it to a warning.
    let mut cluster = Cluster::default();
    for epoch in [1u64, 2, 4, 5, 7] {
        cluster.publish(epoch, [epoch as u8; 32]);
    }
    assert_eq!(
        missing_epochs(&cluster, &PROGRAM, 1, 7).expect("the cluster answered"),
        vec![3, 6]
    );
    assert!(missing_epochs(&cluster, &PROGRAM, 1, 2)
        .expect("answered")
        .is_empty());
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
        missing_epochs(&Offline, &PROGRAM, 1, 100).is_err(),
        "and a hundred epochs nobody could ask about is not a hundred gaps"
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
