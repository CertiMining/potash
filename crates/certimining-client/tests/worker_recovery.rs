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

use certimining_client::{
    alerts, next_step, publication_time, receipt_pending_since, Alert, Observed, Refusal, Schedule,
    Step, Supervision, Thresholds,
};
use std::collections::BTreeSet;

const S: Schedule = Schedule::DEPLOYED;
const START: u64 = 20_700;

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
    last_submitted: Option<u64>,
    awaiting_attach: Option<u64>,
    /// Epochs Bitcoin has confirmed. An attach of anything else is a no-op, which is what
    /// `Cluster::attach` does when only a calendar stands behind the receipt.
    confirmed: BTreeSet<u64>,
    acts: Vec<Act>,
}

impl World {
    fn fresh() -> Self {
        Self {
            start_epoch: START,
            last_epoch: START - 1,
            last_submitted: None,
            awaiting_attach: None,
            confirmed: BTreeSet::new(),
            acts: Vec::new(),
        }
    }

    /// What a restart sees. Nothing is carried across it.
    fn observe(&self, now: i64) -> Observed {
        Observed {
            now,
            today: day(now),
            start_epoch: self.start_epoch,
            last_epoch: self.last_epoch,
            awaiting_attach: self.awaiting_attach,
            last_submitted: self.last_submitted,
        }
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
                self.last_submitted = Some(epoch);
                self.awaiting_attach = Some(epoch);
                self.acts.push(Act::Submitted(epoch));
                now
            }
            Step::Attach { epoch } => {
                // A receipt the chain has not confirmed is not attached, and not a failure either.
                if self.confirmed.contains(&epoch) {
                    self.awaiting_attach = None;
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
            let step = next_step(S, &self.observe(now));
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

/// The UTC day a Unix time falls in, stated the way the tests mean it.
fn day(now: i64) -> u64 {
    match certimining_client::day_index(now) {
        Some(d) => d,
        None => panic!("{now} is before 1970, so the test states nothing"),
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
        next_step(S, &w.observe(now)),
        Step::Publish { epoch: START },
        "before publish, a restart publishes"
    );

    // After publish, before submit.
    w.apply(Step::Publish { epoch: START }, now);
    assert_eq!(
        next_step(S, &w.observe(now)),
        Step::Submit { epoch: START },
        "after publish, a restart submits rather than publishing again"
    );

    // After submit (the OTS stamp), before attachment.
    w.apply(Step::Submit { epoch: START }, now);
    assert_eq!(
        next_step(S, &w.observe(now)),
        Step::Attach { epoch: START },
        "after the stamp, a restart attaches rather than resubmitting"
    );

    // Before attachment lands, because Bitcoin has not confirmed.
    w.apply(Step::Attach { epoch: START }, now);
    assert_eq!(
        next_step(S, &w.observe(now)),
        Step::Attach { epoch: START },
        "an unconfirmed receipt is retried, not abandoned and not counted as done"
    );
    assert!(w.attached().is_empty(), "nothing was recorded as attached");

    // And once it confirms, the cycle moves on rather than repeating the epoch.
    w.confirmed.insert(START);
    w.apply(Step::Attach { epoch: START }, now);
    assert_eq!(w.attached(), vec![START]);
    assert!(
        !matches!(next_step(S, &w.observe(now)), Step::Publish { epoch } if epoch == START),
        "the finished epoch is never published again"
    );
}

/// Criterion 3. Two schedulers firing on the same state agree, and the second finds the work done
/// rather than doing it twice.
#[test]
fn a_duplicate_scheduler_invocation_does_not_duplicate_the_work() {
    let mut w = World::fresh();
    let now = at(START);

    let first = next_step(S, &w.observe(now));
    let second = next_step(S, &w.observe(now));
    assert_eq!(
        first, second,
        "the step is a function of state, so both agree"
    );

    w.apply(first, now);
    let after = next_step(S, &w.observe(now));
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
        let step = next_step(S, &w.observe(now));
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
    let mut w = World::fresh();
    w.last_epoch = START;
    w.last_submitted = Some(START + 5);
    let step = next_step(S, &w.observe(at(START)));
    assert!(
        matches!(step, Step::Refuse(Refusal::SubmissionAheadOfLog { .. })),
        "a submission ahead of the log is refused, got {step:?}"
    );

    let mut w = World::fresh();
    w.last_epoch = START + 400;
    let step = next_step(S, &w.observe(at(START)));
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
        &w.observe(now),
        &Supervision::from_worker(now, None),
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
    let raised = alerts(S, &w.observe(now), &Supervision::from_worker(now, None), T);
    let lines: Vec<String> = raised.iter().map(ToString::to_string).collect();
    assert!(
        lines.iter().any(|l| l.starts_with("SequenceLag:")),
        "a log three epochs behind must be reported as lagging: {lines:?}"
    );
    assert!(
        lines.iter().any(|l| l.starts_with("PublicationMissed:")),
        "and the oldest owed epoch is overdue with it: {lines:?}"
    );

    // **ReceiptUnconfirmed, through the dating the worker actually uses.** The receipt's file is
    // absent, which is the state H-97 (issue #304) found silenced: `receipt_pending_since` dates it
    // by the lower bound its epoch's publication gives instead of reporting no receipt at all.
    let pending = START;
    let mut w = World::fresh();
    let now = at(pending)
        .saturating_add(T.receipt_budget)
        .saturating_add(60);
    w.awaiting_attach = Some(pending);
    w.last_submitted = Some(pending);
    w.last_epoch = day(now).saturating_sub(1);
    let absent = std::env::temp_dir().join(format!(
        "certimining-252-absent-{}/{pending}.ots",
        std::process::id()
    ));
    assert!(!absent.exists(), "the case needs a path that is not there");
    let dated = receipt_pending_since(S, pending, &absent);
    assert_eq!(
        dated,
        at(pending),
        "an undatable receipt is dated by its epoch's publication time"
    );
    let line = only(&alerts(
        S,
        &w.observe(now),
        &Supervision::from_worker(now, Some(dated)),
        T,
    ));
    assert!(
        line.starts_with("ReceiptUnconfirmed:"),
        "a receipt past its budget must be reported even with its file gone: {line}"
    );
}
