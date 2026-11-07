// SPDX-License-Identifier: MIT OR Apache-2.0
//! A deterministic harness for the worker's recovery behaviour (#252).
//!
//! **What a restart actually is, and why that makes this testable without a process.** The worker
//! holds no state of its own. `next_step` reads `Observed` — the log's config account and the
//! receipt directory — and returns the one thing to do next. A crash therefore loses nothing, and
//! restarting is observing again. So a restart at any point is modelled exactly by re-deriving
//! `Observed` from the world and asking again, and a test that does that is testing the real
//! recovery path rather than a stand-in for it.
//!
//! **What this does not cover, said rather than left to be assumed.** #252 also asks for an
//! unreadable key, an unavailable RPC and an unavailable OpenTimestamps calendar. Those are I/O in
//! `anchor-b-worker` and `batcher-handoff`, not states of this machine, and nothing here exercises
//! them: `refuse_a_readable_key` and `refuse_to_write` carry the key-permission half in
//! `tests/ots.rs`. Of the five conditions the fifth criterion asks for, the three the worker raises
//! are injected below and `ProcessSilent` and `RepeatedRefusal` are not: both are facts about the
//! process rather than the log, both are the service manager's, and both need a host running one
//! (#251). The soak over seven scheduled epochs and the cold-run of the runbook are operational and
//! cannot be met by a test at all.

use anchor_lang::prelude::Pubkey;
use anchor_lang::{AnchorSerialize, Discriminator};
use certimining_checkpoint::{CheckpointAccount, LogConfig};
use certimining_client::{
    alerts, day_index, next_step, observe, publication_time, Alert, AnchorStatus, EpochStatus,
    Observation, Observed, OneView, ReceiptLocation, Refusal, RootSource, Schedule, Step,
    Supervision, Thresholds, Unreachable,
};
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

const PROGRAM: Pubkey = certimining_checkpoint::ID;

/// One receipt directory per `World`, so tests that write receipts cannot see each other's.
static WORLDS: AtomicU32 = AtomicU32::new(0);

const S: Schedule = Schedule::DEPLOYED;
const START: u64 = 20_700;

/// The chain's configuration account, as the program writes it.
///
/// Only the configuration is held: `observe` asks `sequence_lag` about one epoch's checkpoint and
/// uses the range the configuration states, so a checkpoint account is never read here.
impl RootSource for World {
    fn account_at(&self, address: &Pubkey) -> Result<Observation, Unreachable> {
        Ok(Observation {
            slot: Some(1),
            account: self.account(address),
        })
    }

    fn accounts_at(&self, addresses: &[Pubkey]) -> Result<OneView, Unreachable> {
        Ok(OneView {
            slot: Some(1),
            accounts: addresses
                .iter()
                .map(|address| self.account(address))
                .collect(),
        })
    }
}

/// What the chain says about one epoch, from what this world has published and attached.
///
/// **`Single` is true from publication, not from submission**, which is what the chain means by it:
/// a root is on Solana and anchor B has not attached. That is why removing the receipt guard from
/// `observe` halted the worker — every epoch passes through this state on its way to being
/// submitted (H-108, issue #332).
impl EpochStatus for World {
    fn status(&self, epoch: u64) -> Result<AnchorStatus, Unreachable> {
        if epoch < self.start_epoch || epoch > self.last_epoch {
            return Ok(AnchorStatus::Pending);
        }
        if self.attached.contains(&epoch) {
            return Ok(AnchorStatus::Dual);
        }
        Ok(AnchorStatus::Single)
    }
}

impl ReceiptLocation for World {
    fn receipt_path(&self, epoch: u64) -> PathBuf {
        self.receipts.join(format!("{epoch}.root.ots"))
    }
}

/// What a restart sees: the real observer, reading this world.
///
/// **The harness had an `observe` of its own until H-108 (issue #332), and it observed nothing** —
/// it copied `World`'s own fields into `Observed`. Every test of the worker's recovery ran against
/// that, so the `exists()` guard in the binary's observer was invisible to all of them. This calls
/// the one observer the service calls; it performs no observation itself.
fn seen(world: &World, now: i64) -> Observed {
    let today = match day_index(now) {
        Some(d) => d,
        None => panic!("{now} is before 1970, so the test states nothing"),
    };
    match observe(world, world, &PROGRAM, now, today) {
        Ok(observed) => observed,
        Err(e) => panic!("the observation failed: {e:?}"),
    }
}

/// Every durable act the worker can perform, in the order it performed them.
///
/// The sequence is the evidence: a duplicate epoch, a skipped one or a second attachment is a
/// repeated or out-of-order entry here, which no assertion about the final state would catch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Act {
    Published(u64),
    Submitted(u64),
    Attached(u64),
}

/// The state the worker observes, and the only state there is.
#[derive(Debug, Clone)]
struct World {
    start_epoch: u64,
    last_epoch: u64,
    /// Epochs whose receipt digest is attached on chain, which is what makes the chain say `Dual`.
    attached: BTreeSet<u64>,
    /// Epochs Bitcoin has confirmed. An attach of anything else is a no-op, which is what
    /// `Cluster::attach` does when only a calendar stands behind the receipt.
    confirmed: BTreeSet<u64>,
    /// Where this world's receipts live. A receipt on disk is the only evidence that an epoch
    /// reached the calendars, which is why submitting writes one here (H-108, issue #332).
    receipts: PathBuf,
    acts: Vec<Act>,
}

impl World {
    fn fresh() -> Self {
        let mine = WORLDS.fetch_add(1, Ordering::Relaxed);
        let receipts =
            std::env::temp_dir().join(format!("certimining-h108-{}-{mine}", std::process::id()));
        // A previous run's directory would make submission look already done.
        let _ = std::fs::remove_dir_all(&receipts);
        match std::fs::create_dir_all(&receipts) {
            Ok(()) => {}
            Err(e) => panic!("{}: {e}", receipts.display()),
        }
        Self {
            start_epoch: START,
            last_epoch: START - 1,
            attached: BTreeSet::new(),
            confirmed: BTreeSet::new(),
            receipts,
            acts: Vec::new(),
        }
    }

    /// What this world holds at `address`: the configuration, or a checkpoint inside the range.
    ///
    /// **Checkpoints are held because `sequence_lag` demands them.** An epoch inside the published
    /// range whose account is absent from the same view is evidence about the log, not about the
    /// responses, and the real reader refuses it (H-07). A fake that answered only the configuration
    /// passed every test whose `today` sat above the range and refused the one whose did not.
    fn account(&self, address: &Pubkey) -> Option<(Pubkey, Vec<u8>)> {
        let mut epoch = self.start_epoch;
        while epoch <= self.last_epoch {
            if *address == certimining_client::checkpoint_address(&PROGRAM, epoch) {
                return Some((PROGRAM, self.checkpoint_bytes(epoch)));
            }
            epoch = match epoch.checked_add(1) {
                Some(next) => next,
                None => break,
            };
        }
        if *address != certimining_client::config_address(&PROGRAM) {
            return None;
        }
        let config = LogConfig {
            schema_version: 1,
            authority: PROGRAM,
            last_epoch: self.last_epoch,
            tree_height: 8,
            bump: 255,
            start_epoch: self.start_epoch,
            reserved: [0u8; 8],
        };
        let mut data = LogConfig::DISCRIMINATOR.to_vec();
        match config.serialize(&mut data) {
            Ok(()) => {}
            Err(e) => panic!("the configuration does not serialize: {e}"),
        }
        data.resize(LogConfig::LEN, 0);
        Some((PROGRAM, data))
    }

    /// A checkpoint as the program writes one. The anchor fields are not read here: `EpochStatus`
    /// below answers `Single` or `Dual` from what this world has attached.
    fn checkpoint_bytes(&self, epoch: u64) -> Vec<u8> {
        let account = CheckpointAccount {
            schema_version: 1,
            epoch,
            root: [0x5a; 32],
            published_slot: 1_000u64.saturating_add(epoch),
            published_unix: match publication_time(S, epoch) {
                Some(t) => t,
                None => panic!("epoch {epoch} has no publication time"),
            },
            receipt_digest: [0u8; 32],
            anchor_kind: 0,
            bump: 255,
            reserved: [0u8; 6],
        };
        let mut data = CheckpointAccount::DISCRIMINATOR.to_vec();
        match account.serialize(&mut data) {
            Ok(()) => {}
            Err(e) => panic!("the checkpoint does not serialize: {e}"),
        }
        data
    }

    /// Perform one step. Returns the time to observe from next.
    fn apply(&mut self, step: Step, now: i64) -> i64 {
        match step {
            Step::Publish { epoch } => {
                self.last_epoch = epoch;
                self.acts.push(Act::Published(epoch));
                now
            }
            Step::Submit { epoch } => {
                // The receipt is the durable consequence of submitting, and the only evidence the
                // observer has that this epoch reached the calendars.
                let path = ReceiptLocation::receipt_path(self, epoch);
                match std::fs::write(&path, b"not a real receipt, only a file that exists") {
                    Ok(()) => {}
                    Err(e) => panic!("{}: {e}", path.display()),
                }
                self.acts.push(Act::Submitted(epoch));
                now
            }
            Step::Attach { epoch } => {
                // A receipt the chain has not confirmed is not attached, and not a failure either.
                if self.confirmed.contains(&epoch) {
                    self.attached.insert(epoch);
                    self.acts.push(Act::Attached(epoch));
                }
                now
            }
            Step::Wait { until } => until,
            Step::Refuse(r) => panic!("the worker refused: {r:?}"),
        }
    }

    /// Run until `now` passes `horizon`, confirming each receipt one step after it is submitted.
    fn run_to(&mut self, mut now: i64, horizon: i64) {
        let mut guard = 0;
        while now <= horizon {
            guard += 1;
            assert!(guard < 10_000, "the worker did not make progress");
            let step = next_step(S, &seen(self, now));
            if let Step::Submit { epoch } = step {
                // Bitcoin confirms by the time the next observation happens.
                self.confirmed.insert(epoch);
            }
            let next = self.apply(step, now);
            if next == now {
                continue;
            }
            now = next;
        }
    }

    fn published(&self) -> Vec<u64> {
        self.acts
            .iter()
            .filter_map(|a| match a {
                Act::Published(e) => Some(*e),
                _ => None,
            })
            .collect()
    }

    fn attached(&self) -> Vec<u64> {
        self.acts
            .iter()
            .filter_map(|a| match a {
                Act::Attached(e) => Some(*e),
                _ => None,
            })
            .collect()
    }
}

fn at(epoch: u64) -> i64 {
    match publication_time(S, epoch) {
        Some(t) => t,
        None => panic!("epoch {epoch} has no publication time, so the test states nothing"),
    }
}

/// Criterion 4. Over a long run the published sequence is contiguous and strictly increasing, and
/// no epoch is attached twice.
#[test]
fn a_long_run_publishes_each_epoch_once_in_order() {
    let mut w = World::fresh();
    w.run_to(at(START), at(START + 30));

    let published = w.published();
    assert_eq!(published.first(), Some(&START), "it starts at start_epoch");
    for pair in published.windows(2) {
        assert_eq!(
            pair[1],
            pair[0] + 1,
            "no duplicate and no skip: {published:?}"
        );
    }

    let attached = w.attached();
    let unique: BTreeSet<u64> = attached.iter().copied().collect();
    assert_eq!(attached.len(), unique.len(), "no receipt attached twice");
}

/// Criterion 2. A restart at each point of the cycle resumes at the step the world is actually in,
/// and repeats nothing. The four points are the ones the issue names.
#[test]
fn a_restart_at_each_point_of_the_cycle_resumes_without_repeating() {
    // Before publish: nothing done for today.
    let mut w = World::fresh();
    let now = at(START);
    assert_eq!(
        next_step(S, &seen(&w, now)),
        Step::Publish { epoch: START },
        "before publish, a restart publishes"
    );

    // After publish, before submit.
    w.apply(Step::Publish { epoch: START }, now);
    assert_eq!(
        next_step(S, &seen(&w, now)),
        Step::Submit { epoch: START },
        "after publish, a restart submits rather than publishing again"
    );

    // After submit (the OTS stamp), before attachment.
    w.apply(Step::Submit { epoch: START }, now);
    assert_eq!(
        next_step(S, &seen(&w, now)),
        Step::Attach { epoch: START },
        "after the stamp, a restart attaches rather than resubmitting"
    );

    // Before attachment lands, because Bitcoin has not confirmed.
    w.apply(Step::Attach { epoch: START }, now);
    assert_eq!(
        next_step(S, &seen(&w, now)),
        Step::Attach { epoch: START },
        "an unconfirmed receipt is retried, not abandoned and not counted as done"
    );
    assert!(w.attached().is_empty(), "nothing was recorded as attached");

    // And once it confirms, the cycle moves on rather than repeating the epoch.
    w.confirmed.insert(START);
    w.apply(Step::Attach { epoch: START }, now);
    assert_eq!(w.attached(), vec![START]);
    assert!(
        !matches!(next_step(S, &seen(&w, now)), Step::Publish { epoch } if epoch == START),
        "the finished epoch is never published again"
    );
}

/// Criterion 3. Two schedulers firing on the same state agree, and the second finds the work done
/// rather than doing it twice.
#[test]
fn a_duplicate_scheduler_invocation_does_not_duplicate_the_work() {
    let mut w = World::fresh();
    let now = at(START);

    let first = next_step(S, &seen(&w, now));
    let second = next_step(S, &seen(&w, now));
    assert_eq!(
        first, second,
        "the step is a function of state, so both agree"
    );

    w.apply(first, now);
    let after = next_step(S, &seen(&w, now));
    assert_ne!(after, first, "the second invocation observes the work done");
    assert_eq!(w.published(), vec![START], "and it was done once");
}

/// Criterion 3. A receipt Bitcoin has not confirmed holds the cycle at `Attach` for as long as it
/// takes, and never reports success. INV-ANCH-04 budgets the wait.
#[test]
fn a_delayed_bitcoin_confirmation_never_becomes_a_false_success() {
    let mut w = World::fresh();
    let now = at(START);
    w.apply(Step::Publish { epoch: START }, now);
    w.apply(Step::Submit { epoch: START }, now);

    for _ in 0..50 {
        let step = next_step(S, &seen(&w, now));
        assert_eq!(step, Step::Attach { epoch: START }, "it keeps waiting");
        w.apply(step, now);
    }
    assert!(w.attached().is_empty(), "and never records an attachment");
    assert_eq!(w.published(), vec![START], "nor publishes past it");
}

/// Criterion 4. State the worker must not act on is refused, not worked around. A receipt
/// directory claiming an epoch the log never published is the forged-handoff shape.
#[test]
fn state_the_worker_must_not_act_on_is_refused() {
    // **Stated against `next_step` directly, because the observer cannot produce it (H-108, issue
    // #332).** `observe` walks the published range only, so a receipt for an epoch above the log's
    // last published one is never looked at and `last_submitted` cannot run ahead of `last_epoch`.
    // The barrier is still the reducer's to hold — it is what refuses a forged or stale observation
    // handed to it by anything — so the input is built here rather than observed.
    let step = next_step(
        S,
        &Observed {
            now: at(START),
            start_epoch: START,
            last_epoch: START,
            awaiting_attach: None,
            last_submitted: Some(START + 5),
            oldest_single: None,
        },
    );
    assert!(
        matches!(step, Step::Refuse(Refusal::SubmissionAheadOfLog { .. })),
        "a submission ahead of the log is refused, got {step:?}"
    );

    let mut w = World::fresh();
    w.last_epoch = START + 400;
    let step = next_step(S, &seen(&w, at(START)));
    assert!(
        matches!(step, Step::Refuse(Refusal::LogAheadOfCalendar { .. })),
        "a log ahead of the calendar is refused, got {step:?}"
    );
}

/// The one alert a case is expected to raise, rendered the way the journal carries it.
fn only(raised: &[Alert]) -> String {
    match raised {
        [single] => single.to_string(),
        other => panic!("exactly one alert was expected, got {other:?}"),
    }
}

/// Criterion 5, the half a test can meet: inject each condition and observe the alert.
///
/// **Three of the five, and the other two said rather than quietly dropped.**
/// `PublicationMissed`, `SequenceLag` and `ReceiptUnconfirmed` are facts about the log, so the
/// worker derives them from state it already observes, and each is injected into a `World` here and
/// read back out. `ProcessSilent` and `RepeatedRefusal` are facts about the process: a live worker
/// reports neither about itself, which `Supervision::from_worker` makes true by construction rather
/// than by convention. Those two are the service manager's, and injecting them needs a host running
/// one — #251, which carries `systemd-analyze verify` on both units and the deliberate
/// three-refusal run.
///
/// Read through `Display` rather than off the value, because the journal line is what an operator is
/// woken by and it is the part a wrong `match` arm would get wrong silently.
#[test]
fn each_condition_the_worker_raises_is_injected_and_observed() {
    const T: Thresholds = Thresholds::DEPLOYED;

    // **PublicationMissed.** One epoch owed, a minute past its grace, and nothing else wrong — the
    // lag limit is one, so being a single epoch behind is not itself a lag.
    let mut w = World::fresh();
    w.last_epoch = START;
    let now = at(START + 1)
        .saturating_add(T.publication_grace)
        .saturating_add(60);
    let line = only(&alerts(
        S,
        &seen(&w, now),
        &Supervision::from_worker(now),
        T,
    ));
    assert!(
        line.starts_with("PublicationMissed:"),
        "a publication past its grace must be reported: {line}"
    );

    // **SequenceLag.** Three epochs behind. This one cannot be injected alone and that is a
    // property of the thresholds rather than a gap in the test: falling more than one epoch behind
    // means the oldest owed epoch is at least a day overdue, which is past a two-hour grace, so
    // `PublicationMissed` is necessarily raised with it.
    let mut w = World::fresh();
    w.last_epoch = START;
    let now = at(START + 3).saturating_add(60);
    let raised = alerts(S, &seen(&w, now), &Supervision::from_worker(now), T);
    let lines: Vec<String> = raised.iter().map(ToString::to_string).collect();
    assert!(
        lines.iter().any(|l| l.starts_with("SequenceLag:")),
        "a log three epochs behind must be reported as lagging: {lines:?}"
    );
    assert!(
        lines.iter().any(|l| l.starts_with("PublicationMissed:")),
        "and the oldest owed epoch is overdue with it: {lines:?}"
    );

    // **ReceiptUnconfirmed now has its own tests, below**, driven through the real observer rather
    // than through a hand-built `Observed`. See `a_deleted_receipt_is_still_reported` and
    // `a_corrupted_receipt_is_still_reported`.
}

/// **A deleted receipt still reaches the operator (H-108, issue #332; owner's ruling of 3 November
/// 2026).**
///
/// Driven through the real observer with nothing hand-set: the worker publishes and submits, which
/// writes the receipt, and the receipt is then deleted. The test this replaces built the state by
/// assigning `awaiting_attach` and `last_submitted` on the harness — a pairing the real observer
/// cannot produce, because the guard that sets both is the one a missing receipt fails. That is why
/// the defect was invisible to it.
///
/// The alert no longer depends on the receipt at all: an epoch the chain still calls `Single` past
/// the budget is reported from the chain and the clock.
#[test]
fn a_deleted_receipt_is_still_reported() {
    const T: Thresholds = Thresholds::DEPLOYED;
    let mut w = World::fresh();
    let now = at(START).saturating_add(60);

    let publish = next_step(S, &seen(&w, now));
    assert_eq!(publish, Step::Publish { epoch: START }, "the first step");
    w.apply(publish, now);
    let submit = next_step(S, &seen(&w, now));
    assert_eq!(submit, Step::Submit { epoch: START }, "then the calendars");
    w.apply(submit, now);

    let with_receipt = seen(&w, now);
    assert_eq!(
        with_receipt.awaiting_attach,
        Some(START),
        "with its receipt written, the epoch is attachable"
    );
    assert_eq!(
        with_receipt.oldest_single,
        Some(START),
        "and the chain calls it single either way"
    );

    let path = ReceiptLocation::receipt_path(&w, START);
    match std::fs::remove_file(&path) {
        Ok(()) => {}
        Err(e) => panic!("{}: {e}", path.display()),
    }

    let gone = seen(&w, now);
    assert_eq!(
        gone.awaiting_attach, None,
        "the routing keeps the receipt as its evidence, which H-108 (c) leaves unchanged"
    );
    assert_eq!(
        gone.oldest_single,
        Some(START),
        "and the chain still says single, which is what the alert reads"
    );

    let late = at(START)
        .saturating_add(T.receipt_budget)
        .saturating_add(60);
    let raised = alerts(S, &seen(&w, late), &Supervision::from_worker(late), T);
    let lines: Vec<String> = raised.iter().map(ToString::to_string).collect();
    assert!(
        lines.iter().any(|l| l.starts_with("ReceiptUnconfirmed:")),
        "an epoch single past its budget is reported with its receipt gone: {lines:?}"
    );

    // **Inside the budget the routing still submits, and that is correct.** An epoch is single from
    // the moment it is published and before it is ever submitted, so this shape is what every
    // healthy epoch passes through. Refusing here is the trap the superseded first H-108 ruling
    // fell into: it halts the worker on every epoch it publishes.
    assert_eq!(
        next_step(S, &gone),
        Step::Submit { epoch: START },
        "a freshly published epoch with no receipt is work to do, not a fault"
    );

    // **Past the budget it refuses instead (H-110, issue #339).** Same state, later clock. This is
    // the resubmission the 3 November recheck found: the alert fired and the worker submitted again
    // in the same cycle, against a write-once attach field and against what both the executable and
    // the runbook promised.
    let overdue = seen(&w, late);
    assert_eq!(
        next_step(S, &overdue),
        Step::Refuse(Refusal::SubmissionUnknowable {
            epoch: START,
            waiting: T.receipt_budget.saturating_add(60),
            budget: T.receipt_budget,
        }),
        "an epoch single past its budget with no readable receipt stops the worker"
    );

    // And the alert and the refusal name the same epoch, because one expression answers both.
    assert!(
        lines.iter().any(|l| l.contains(&format!("epoch {START}"))),
        "the operator is told about the epoch the worker stopped on: {lines:?}"
    );
}

/// **And a receipt that exists but is corrupt reaches the operator too.**
///
/// The routing sees a file and treats the epoch as submitted, so this is the other half of the pair:
/// the alert fires on the same chain fact whether the receipt is absent or unusable, because it reads
/// neither.
#[test]
fn a_corrupted_receipt_is_still_reported() {
    const T: Thresholds = Thresholds::DEPLOYED;
    let mut w = World::fresh();
    let now = at(START).saturating_add(60);

    let publish = next_step(S, &seen(&w, now));
    w.apply(publish, now);
    let submit = next_step(S, &seen(&w, now));
    w.apply(submit, now);

    let path = ReceiptLocation::receipt_path(&w, START);
    match std::fs::write(&path, b"\x00\x01 not an OpenTimestamps receipt") {
        Ok(()) => {}
        Err(e) => panic!("{}: {e}", path.display()),
    }

    let corrupt = seen(&w, now);
    assert_eq!(
        corrupt.awaiting_attach,
        Some(START),
        "a file that exists is what the routing reads, whatever is in it"
    );
    assert_eq!(corrupt.oldest_single, Some(START));

    let late = at(START)
        .saturating_add(T.receipt_budget)
        .saturating_add(60);
    let raised = alerts(S, &seen(&w, late), &Supervision::from_worker(late), T);
    let lines: Vec<String> = raised.iter().map(ToString::to_string).collect();
    assert!(
        lines.iter().any(|l| l.starts_with("ReceiptUnconfirmed:")),
        "an epoch single past its budget is reported with an unusable receipt: {lines:?}"
    );
}
