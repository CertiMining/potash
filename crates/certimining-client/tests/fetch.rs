// SPDX-License-Identifier: MIT OR Apache-2.0
//! E-09: deriving a root by epoch with no indexer, placing what comes back, and reporting lag.
//!
//! The cluster is a map here, because `RootSource` is a trait: an RPC that returns the wrong thing is
//! easier to build in a test than to provoke on a network, and those are the cases that matter.

use anchor_lang::prelude::Pubkey;
use anchor_lang::{AnchorSerialize, Discriminator};
use certimining_checkpoint::{CheckpointAccount, LogConfig};
use certimining_client::{
    checkpoint_address, config_address, decode_checkpoint, root_for_epoch, sequence_lag, Fetched,
    Observation, OneView, Refused, RootSource, Unreachable,
};
use std::collections::HashMap;

const PROGRAM: Pubkey = certimining_checkpoint::ID;

/// A cluster that holds exactly what a test put in it.
#[derive(Default)]
struct Cluster {
    accounts: HashMap<Pubkey, (Pubkey, Vec<u8>)>,
    /// The slot a given address is answered at, where a test needs the reads to disagree (H-07).
    slots: HashMap<Pubkey, u64>,
    /// The slot every other address is answered at. `None` is a source with no notion of one.
    default_slot: Option<u64>,
}

impl RootSource for Cluster {
    fn account_at(&self, address: &Pubkey) -> Result<Observation, Unreachable> {
        Ok(Observation {
            slot: self.slots.get(address).copied().or(self.default_slot),
            account: self.accounts.get(address).cloned(),
        })
    }

    /// One map, read once: every answer is the same state, which is what one view means here.
    ///
    /// The per-address slots this fixture can carry are deliberately **not** consulted. They exist to
    /// make several separate reads disagree, which is H-07's question; a single request has one slot
    /// and this source has one state, so there is nothing for them to disagree about.
    fn accounts_at(&self, addresses: &[Pubkey]) -> Result<OneView, Unreachable> {
        Ok(OneView {
            slot: self.default_slot,
            accounts: addresses
                .iter()
                .map(|address| self.accounts.get(address).cloned())
                .collect(),
        })
    }
}

/// A cluster nobody can ask, which is a different thing from one holding nothing.
struct Offline;

impl RootSource for Offline {
    fn account_at(&self, _address: &Pubkey) -> Result<Observation, Unreachable> {
        Err(Unreachable("the endpoint refused the connection".into()))
    }

    fn accounts_at(&self, _addresses: &[Pubkey]) -> Result<OneView, Unreachable> {
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
    cluster.publish(7, *b"certimining fixture root   00001");
    let found = root_for_epoch(&cluster, &PROGRAM, 7).expect("the cluster answered");
    let Fetched::Placed(checkpoint) = found else {
        panic!("a published root should be placed, and this was {found:?}")
    };
    assert_eq!(checkpoint.epoch, 7);
    assert_eq!(checkpoint.root, *b"certimining fixture root   00001");
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
        Fetched::Refused(Refused::WrongDiscriminator)
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

/// S9-R2-01, **and this test asserted the opposite until H-54 (issue #197).**
///
/// If the configuration says an epoch is published and its account does not come back, one consistent
/// view of the chain cannot produce that: `publish_checkpoint` writes the checkpoint before it
/// advances `last_epoch`. The old version of this test asserted that the error named *the reads*
/// rather than the log, because the configuration and the account were separate requests with no
/// shared response context, so an inconsistency between them was evidence about the responses.
///
/// `sequence_lag` now reads them in one request. They are one view by construction, so the same
/// fixture is a contradiction a single view cannot hold, and the error names the log. The assertion
/// is flipped and the sentence it checks for is the new one, because the fact underneath it changed.
#[test]
fn an_absent_account_inside_the_published_range_is_now_evidence_about_the_log() {
    let mut cluster = Cluster::default();
    cluster.configure(100, 104);
    cluster.publish(100, [1u8; 32]);
    // 101 is deliberately not published, which one view of a real chain cannot show.
    let refused = sequence_lag(&cluster, &PROGRAM, 100, 104);
    assert!(
        refused.is_err(),
        "the client says it cannot reason from this, rather than inventing a gap"
    );
    let message = format!("{:?}", refused.unwrap_err());
    assert!(
        message.contains("same view") && message.contains("about the log"),
        "the error names the log, which is what one view makes it able to say: {message}"
    );
    assert!(
        !message.contains("impossible"),
        "the conclusion these reads cannot support is gone: {message}"
    );
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
        Some(Refused::WrongDiscriminator),
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

/// S9-R2-03. `decode_config` is public and was tested only through `sequence_lag`, which built a
/// valid configuration every time. These are its four refusals, each reached directly.
mod config_decoder {
    use super::*;
    use certimining_client::decode_config;

    fn valid_bytes() -> Vec<u8> {
        let config = LogConfig {
            schema_version: 1,
            authority: PROGRAM,
            last_epoch: 104,
            tree_height: 8,
            bump: 255,
            start_epoch: 100,
            reserved: [0u8; 8],
        };
        let mut data = LogConfig::DISCRIMINATOR.to_vec();
        config.serialize(&mut data).expect("serializes");
        data.resize(LogConfig::LEN, 0);
        data
    }

    #[test]
    fn a_valid_configuration_decodes() {
        let decoded = decode_config(&PROGRAM, &PROGRAM, &valid_bytes()).expect("decodes");
        assert_eq!(decoded.start_epoch, 100);
        assert_eq!(decoded.last_epoch, 104);
        assert_eq!(decoded.tree_height, 8);
    }

    #[test]
    fn an_account_owned_by_someone_else_is_refused() {
        assert_eq!(
            decode_config(&PROGRAM, &Pubkey::new_unique(), &valid_bytes()).err(),
            Some(Refused::NotTheProgram)
        );
    }

    #[test]
    fn data_shorter_than_2_4s_layout_is_refused() {
        let mut short = valid_bytes();
        short.truncate(LogConfig::LEN - 1);
        assert_eq!(
            decode_config(&PROGRAM, &PROGRAM, &short).err(),
            Some(Refused::TooShort)
        );
    }

    /// The finding itself: this reported `NotACheckpoint`, which named the wrong account type.
    #[test]
    fn another_accounts_discriminator_is_a_discriminator_mismatch_and_says_so() {
        let mut wrong = valid_bytes();
        wrong[..8].copy_from_slice(CheckpointAccount::DISCRIMINATOR);
        assert_eq!(
            decode_config(&PROGRAM, &PROGRAM, &wrong).err(),
            Some(Refused::WrongDiscriminator),
            "a malformed configuration is not a checkpoint of the wrong shape"
        );
    }

    #[test]
    fn a_schema_this_client_does_not_read_is_refused() {
        let mut other = valid_bytes();
        other[8..10].copy_from_slice(&2u16.to_le_bytes());
        assert_eq!(
            decode_config(&PROGRAM, &PROGRAM, &other).err(),
            Some(Refused::UnsupportedSchema)
        );
    }
}

/// **H-07's read boundary, and what H-54 did to it** (issues #39 and #197).
///
/// H-07 made `sequence_lag` carry each read's context slot and refuse when a checkpoint came back
/// from before the configuration's own view. That caught a stale replica. It could not catch two
/// reads served from different confirmed forks at compatible slot numbers, which is the hole H-35
/// found in V-Z-01's ordered triple and the one `minContextSlot` does not close either: that
/// guarantees a view's height, not its chain.
///
/// `sequence_lag` now asks once. `getMultipleAccounts` returns a single response context for every
/// address in it, so the configuration and the checkpoints are one view by construction rather than
/// by comparison — which is strictly stronger and makes H-07's comparison **unreachable here**. D-80's
/// rule applies to a client branch as much as to an error code, so the test below asserts what the
/// new strategy does instead of a condition no path reaches.
///
/// `Observation::slot` is unchanged and still public: a caller making several separate reads through
/// `root_for_epoch_at` has the same boundary H-07 gave it. What changed is that this module's one
/// consumer no longer needs it.
mod one_view_of_the_chain {
    use super::*;

    /// H-07's fixture, answered normally now: one request has one slot, so there is nothing to
    /// disagree with.
    #[test]
    fn a_stale_per_address_slot_cannot_split_a_read_that_is_one_request() {
        let mut cluster = Cluster {
            default_slot: Some(500),
            ..Default::default()
        };
        cluster.configure(100, 102);
        cluster.publish(100, [1u8; 32]);
        cluster.publish(101, [2u8; 32]);
        cluster.publish(102, [3u8; 32]);
        // H-07's stale replica. It is ignored, because `accounts_at` does not read per-address slots:
        // a single request cannot be served from two of them.
        cluster.slots.insert(checkpoint_address(&PROGRAM, 101), 499);

        let lag = sequence_lag(&cluster, &PROGRAM, 100, 102).expect("one view, one answer");
        assert!(lag.is_empty(), "every epoch in the range has a usable root");
        assert_eq!(
            lag.views, 1,
            "three epochs and a configuration are one request"
        );
        assert!(!lag.configuration_moved);
    }

    /// The control. Without it the test above would pass on a client that refused everything.
    #[test]
    fn the_same_reads_at_or_after_the_configurations_view_are_answered_normally() {
        for at in [500u64, 501] {
            let mut cluster = Cluster {
                default_slot: Some(500),
                ..Default::default()
            };
            cluster.configure(100, 102);
            cluster.publish(100, [1u8; 32]);
            cluster.publish(101, [2u8; 32]);
            cluster.publish(102, [3u8; 32]);
            cluster.slots.insert(checkpoint_address(&PROGRAM, 101), at);

            let lag = sequence_lag(&cluster, &PROGRAM, 100, 102)
                .expect("reads at or after the configuration's view are one view");
            assert!(lag.is_empty(), "every epoch resolved at slot {at}");
        }
    }

    /// A source with no notion of a slot is not thereby inconsistent, and must not be refused.
    ///
    /// Every other test in this file uses one, so this is also the statement that they still mean
    /// what they meant.
    #[test]
    fn a_source_that_cannot_say_which_slot_it_answered_at_is_not_refused() {
        let mut cluster = Cluster::default();
        assert_eq!(
            cluster.default_slot, None,
            "the default source has no slots"
        );
        cluster.configure(100, 101);
        cluster.publish(100, [1u8; 32]);
        cluster.publish(101, [2u8; 32]);
        let lag =
            sequence_lag(&cluster, &PROGRAM, 100, 101).expect("no slots is not a disagreement");
        assert!(lag.is_empty());
    }

    /// Only one side knowing its slot is not a disagreement either: there is nothing to compare.
    #[test]
    fn one_side_without_a_slot_is_not_a_disagreement() {
        let mut cluster = Cluster {
            default_slot: Some(500),
            ..Default::default()
        };
        cluster.configure(100, 101);
        cluster.publish(100, [1u8; 32]);
        cluster.publish(101, [2u8; 32]);
        // The configuration answers with no slot; the checkpoints answer with one.
        cluster.slots.remove(&config_address(&PROGRAM));
        let lag = sequence_lag(&cluster, &PROGRAM, 100, 101);
        assert!(
            lag.is_ok(),
            "a comparison needs both sides; one of them missing is not evidence"
        );
    }
}

/// **What a range longer than one request does** (H-54, issue #197).
///
/// `getMultipleAccounts` takes 100 addresses and the configuration occupies one of them, so 99 epochs
/// is the most one view can answer for. A longer range is several views, and the answer says so
/// rather than reading as one observation.
mod more_than_one_view {
    use super::*;
    use std::cell::RefCell;

    /// A fixture that records the size of every request, so the chunking is asserted and not assumed.
    struct Recording {
        inner: Cluster,
        sizes: RefCell<Vec<usize>>,
    }

    impl RootSource for Recording {
        fn account_at(&self, address: &Pubkey) -> Result<Observation, Unreachable> {
            self.inner.account_at(address)
        }

        fn accounts_at(&self, addresses: &[Pubkey]) -> Result<OneView, Unreachable> {
            self.sizes.borrow_mut().push(addresses.len());
            self.inner.accounts_at(addresses)
        }
    }

    #[test]
    fn a_range_of_ninety_nine_epochs_is_one_request_and_a_hundred_is_two() {
        for (epochs, requests) in [(99u64, 1usize), (100, 2)] {
            let mut inner = Cluster::default();
            inner.configure(100, 100 + epochs - 1);
            for epoch in 100..100 + epochs {
                inner.publish(epoch, [u8::try_from(epoch % 251).unwrap_or(1); 32]);
            }
            let source = Recording {
                inner,
                sizes: RefCell::new(Vec::new()),
            };
            let lag = sequence_lag(&source, &PROGRAM, 100, 100 + epochs - 1)
                .unwrap_or_else(|e| panic!("{epochs} epochs: {e:?}"));
            assert_eq!(
                lag.views, requests,
                "{epochs} epochs should be {requests} view(s)"
            );
            let sizes = source.sizes.borrow().clone();
            assert_eq!(sizes.len(), requests);
            for size in &sizes {
                assert!(
                    *size <= certimining_client::ONE_VIEW_LIMIT,
                    "a request of {size} addresses is over the RPC's limit, and splitting it \
                     elsewhere would return several views under the name of one"
                );
            }
            // Every request carries the configuration, because every comparison is configuration
            // against epoch and both sides have to come out of one view.
            assert_eq!(
                sizes.iter().sum::<usize>(),
                usize::try_from(epochs).unwrap_or(0) + requests,
                "each request holds its epochs and one configuration"
            );
        }
    }

    /// A source whose configuration advances between requests, which is the log publishing mid-scan.
    struct Shifting {
        early: Cluster,
        late: Cluster,
        asked: RefCell<usize>,
    }

    impl RootSource for Shifting {
        fn account_at(&self, address: &Pubkey) -> Result<Observation, Unreachable> {
            self.early.account_at(address)
        }

        fn accounts_at(&self, addresses: &[Pubkey]) -> Result<OneView, Unreachable> {
            let first = {
                let mut asked = self.asked.borrow_mut();
                *asked = asked.saturating_add(1);
                *asked == 1
            };
            if first {
                self.early.accounts_at(addresses)
            } else {
                self.late.accounts_at(addresses)
            }
        }
    }

    /// **Not an error, and not silent either.**
    ///
    /// Each batch was answered against the configuration read in the same request, so every
    /// comparison holds. What a caller must not do is treat the whole range as one observation, and
    /// the only way it can know is to be told.
    #[test]
    fn a_configuration_that_moves_between_views_is_reported() {
        let build = |last: u64| {
            let mut cluster = Cluster::default();
            cluster.configure(100, last);
            for epoch in 100..=last {
                cluster.publish(epoch, [u8::try_from(epoch % 251).unwrap_or(1); 32]);
            }
            cluster
        };
        let source = Shifting {
            early: build(199),
            late: build(200),
            asked: RefCell::new(0),
        };
        let lag = sequence_lag(&source, &PROGRAM, 100, 200).expect("both views answered");
        assert_eq!(lag.views, 2);
        assert!(
            lag.configuration_moved,
            "the log published between the two requests and the answer has to say so"
        );
        assert_eq!(
            lag.last_published, 200,
            "the bounds reported are the most recent view's"
        );
        assert!(lag.is_empty(), "every epoch asked about had a usable root");
    }
}
