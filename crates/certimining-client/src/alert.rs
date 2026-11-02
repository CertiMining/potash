// SPDX-License-Identifier: MIT OR Apache-2.0
//! The conditions an operator is told about, decided from state alone (#252).
//!
//! **Why this is a function and not a monitoring configuration.** The five conditions #252 names are
//! judgements about observed state, and a judgement written into a dashboard query is one nobody can
//! test. Here each is a function of the same `Observed` the worker reads plus the three facts a
//! supervisor already holds — when the process last reported, how long a receipt has been waiting,
//! and how many times in a row the worker refused. Routing and delivery are operational and are not
//! here; what is here is the part that can be wrong in a way a test would catch.
//!
//! **H-90 (#293) is the case for the second condition.** The worker waited for each publication time
//! and refused it, every epoch, and nothing noticed because nothing was watching the clock against
//! the log. `PublicationMissed` is that watch. An alert that fires on a worker which is running,
//! answering, and quietly publishing nothing is the one this deployment most needed.

use crate::worker::Observed;
use crate::{publication_time, Refusal, Schedule};

/// How long each condition is tolerated before it is worth waking somebody.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Thresholds {
    /// A process that has not reported for this long is treated as dead.
    pub heartbeat_grace: i64,
    /// How far past an epoch's publication time the log may still be unpublished.
    pub publication_grace: i64,
    /// How many epochs the log may be behind the newest publishable one.
    pub sequence_lag: u64,
    /// How long a submitted receipt may go unconfirmed. INV-ANCH-04 budgets the wait; this is the
    /// point at which the wait itself is the news.
    pub receipt_budget: i64,
    /// How many consecutive refusals are a stuck worker rather than one bad observation.
    pub consecutive_refusals: u32,
}

impl Thresholds {
    /// The deployment's values.
    ///
    /// `publication_grace` is two hours against a schedule that publishes an hour after the epoch
    /// ends, so a run that is merely slow does not page and a run that has stopped does. The
    /// receipt budget is three days, which is long against Bitcoin's confirmation and short against
    /// a receipt nobody will ever upgrade.
    pub const DEPLOYED: Self = Self {
        heartbeat_grace: 1_800,
        publication_grace: 7_200,
        sequence_lag: 1,
        receipt_budget: 259_200,
        consecutive_refusals: 3,
    };
}

/// What a supervisor knows that the chain does not say.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Supervision {
    /// When the worker process last reported, in Unix seconds.
    pub last_heartbeat: i64,
    /// When the pending receipt was submitted to the calendars, if one is pending.
    pub receipt_submitted_at: Option<i64>,
    /// How many times in a row the worker has refused.
    pub consecutive_refusals: u32,
    /// The refusal it last gave, if it refused.
    pub last_refusal: Option<Refusal>,
}

impl Supervision {
    /// What the worker process itself can honestly report (H-95, issue #300).
    ///
    /// **Three of the five conditions are reachable from this and two are not, by construction, and
    /// that is the point of having it here rather than inline in the binary.** `last_heartbeat` is
    /// `now` because the process filling this in is the one running, so `silent_for` is zero and
    /// `ProcessSilent` cannot arise — a live process cannot report its own silence.
    /// `consecutive_refusals` is zero and `last_refusal` is `None` because a refusal returns from the
    /// worker's `run` and ends the process, so a counter held inside it reaches one at most and
    /// `RepeatedRefusal` cannot arise either.
    ///
    /// Those two are raised by the service manager instead, per the owner's ruling of 1 November
    /// 2026: `WatchdogSec` fed by `sd_notify` for the first, and `Restart=on-failure` with
    /// `StartLimitBurst=3` and `OnFailure=` for the second. `deploy/systemd/` carries the units and
    /// `docs/RUNBOOK-WORKER-RECOVERY.md` maps each of the five to where it is raised.
    ///
    /// The two unreachable arms are left in `alerts()` rather than routed around, so that one
    /// predicate serves both emitters and a supervisor built later needs no second copy of the
    /// thresholds. `only_three_of_five_can_be_raised_by_the_worker_itself` below pins which three.
    #[must_use]
    pub fn from_worker(now: i64, receipt_submitted_at: Option<i64>) -> Self {
        Self {
            last_heartbeat: now,
            receipt_submitted_at,
            consecutive_refusals: 0,
            last_refusal: None,
        }
    }
}

/// What each condition says to an operator reading the journal, in the recovery runbook's own terms.
///
/// **In the library rather than in the binary, because that is where a test can reach it
/// (H-95, issue #300).** The first version of this fix rendered these lines inside
/// `anchor-b-worker.rs`, which has no test target CI names, so the text an operator is woken by would
/// have been the one part of the remedy nothing checked — the same shape as the defect being fixed.
/// The binary now holds one `eprintln!` and one watchdog call, and both the predicate and its
/// rendering are exercised here.
///
/// The last two arms name their real emitter. `Supervision::from_worker` cannot produce either, so
/// reaching one of them from the worker's call site is a defect, and the text says so rather than
/// printing something that reads like a normal alert.
impl std::fmt::Display for Alert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PublicationMissed { epoch, due, now } => write!(
                f,
                "PublicationMissed: epoch {epoch} was due at {due} and it is {now}. The log is \
                 behind its own cadence by more than the grace. RUNBOOK-WORKER-RECOVERY.md names \
                 the steps."
            ),
            Self::SequenceLag {
                last_epoch,
                newest_publishable,
                limit,
            } => write!(
                f,
                "SequenceLag: the log's last epoch is {last_epoch} and {newest_publishable} could \
                 be published, which is further behind than the limit of {limit}. Reconcile the \
                 first missing epoch before replaying a backlog."
            ),
            Self::ReceiptUnconfirmed {
                epoch,
                waiting,
                budget,
            } => write!(
                f,
                "ReceiptUnconfirmed: epoch {epoch}'s receipt has been pending {waiting}s against a \
                 budget of {budget}s. INV-ANCH-04 budgets hours for Bitcoin, so this is a calendar \
                 or a receipt question and not a reason to attach anything."
            ),
            Self::ProcessSilent { since, grace } => write!(
                f,
                "ProcessSilent: last report at {since}, grace {grace}s. The worker cannot raise \
                 this about itself; systemd's WatchdogSec does. Reaching it from the worker is a \
                 defect."
            ),
            Self::RepeatedRefusal {
                refusal,
                consecutive,
            } => write!(
                f,
                "RepeatedRefusal: {consecutive} in a row, last {refusal:?}. The worker exits on its \
                 first refusal, so systemd's StartLimitBurst raises this. Reaching it from the \
                 worker is a defect."
            ),
        }
    }
}

/// A condition worth telling an operator about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alert {
    /// The process has not reported inside the grace period.
    ProcessSilent { since: i64, grace: i64 },
    /// An epoch's publication time has passed and the log has not reached it.
    ///
    /// This is the one that would have caught H-90 (#293): the worker was alive and answering.
    PublicationMissed { epoch: u64, due: i64, now: i64 },
    /// The log is further behind the newest publishable epoch than the threshold allows.
    SequenceLag {
        last_epoch: u64,
        newest_publishable: u64,
        limit: u64,
    },
    /// A submitted receipt has gone unconfirmed past its budget.
    ReceiptUnconfirmed {
        epoch: u64,
        waiting: i64,
        budget: i64,
    },
    /// The worker has refused the same way repeatedly, so it is stuck rather than unlucky.
    RepeatedRefusal { refusal: Refusal, consecutive: u32 },
}

/// Every condition the state satisfies, in the order an operator should read them.
///
/// **All of them, not the first.** A silent process and an unconfirmed receipt are different
/// problems with different remedies, and reporting only the most urgent hides the second until the
/// first is fixed. The order is by how much of the system each implicates.
pub fn alerts(
    schedule: Schedule,
    observed: &Observed,
    supervision: &Supervision,
    thresholds: Thresholds,
) -> Vec<Alert> {
    let mut out = Vec::new();
    let now = observed.now;

    let silent_for = now.saturating_sub(supervision.last_heartbeat);
    if silent_for > thresholds.heartbeat_grace {
        out.push(Alert::ProcessSilent {
            since: supervision.last_heartbeat,
            grace: thresholds.heartbeat_grace,
        });
    }

    // The newest epoch that can be published at `now`: an epoch publishes an hour after it ends, so
    // it is `today - 1` and never `today` (H-90, #293).
    let newest_publishable = observed.today.saturating_sub(1);
    let owed = observed.last_epoch.saturating_add(1);
    if owed <= newest_publishable {
        if let Some(due) = publication_time(schedule, owed) {
            if now.saturating_sub(due) > thresholds.publication_grace {
                out.push(Alert::PublicationMissed {
                    epoch: owed,
                    due,
                    now,
                });
            }
        }
    }

    let behind = newest_publishable.saturating_sub(observed.last_epoch);
    if behind > thresholds.sequence_lag {
        out.push(Alert::SequenceLag {
            last_epoch: observed.last_epoch,
            newest_publishable,
            limit: thresholds.sequence_lag,
        });
    }

    if let (Some(epoch), Some(at)) = (observed.awaiting_attach, supervision.receipt_submitted_at) {
        let waiting = now.saturating_sub(at);
        if waiting > thresholds.receipt_budget {
            out.push(Alert::ReceiptUnconfirmed {
                epoch,
                waiting,
                budget: thresholds.receipt_budget,
            });
        }
    }

    if let Some(refusal) = supervision.last_refusal {
        if supervision.consecutive_refusals >= thresholds.consecutive_refusals {
            out.push(Alert::RepeatedRefusal {
                refusal,
                consecutive: supervision.consecutive_refusals,
            });
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::day_index;

    const S: Schedule = Schedule::DEPLOYED;
    const T: Thresholds = Thresholds::DEPLOYED;

    fn at(epoch: u64) -> i64 {
        match publication_time(S, epoch) {
            Some(t) => t,
            None => panic!("epoch {epoch} has no publication time, so the test states nothing"),
        }
    }

    fn day(now: i64) -> u64 {
        match day_index(now) {
            Some(d) => d,
            None => panic!("{now} is before 1970, so the test states nothing"),
        }
    }

    /// A healthy deployment: caught up, heartbeat fresh, nothing pending.
    fn healthy() -> (Observed, Supervision) {
        let last: u64 = 20_745;
        let now = at(last).saturating_add(60);
        (
            Observed {
                now,
                today: day(now),
                start_epoch: 20_700,
                last_epoch: last,
                awaiting_attach: None,
                last_submitted: Some(last),
            },
            Supervision {
                last_heartbeat: now.saturating_sub(60),
                receipt_submitted_at: None,
                consecutive_refusals: 0,
                last_refusal: None,
            },
        )
    }

    #[test]
    fn a_healthy_deployment_raises_nothing() {
        let (o, s) = healthy();
        assert_eq!(alerts(S, &o, &s, T), Vec::new());
    }

    #[test]
    fn a_silent_process_is_reported() {
        let (o, mut s) = healthy();
        s.last_heartbeat = o.now.saturating_sub(T.heartbeat_grace).saturating_sub(1);
        assert!(matches!(
            alerts(S, &o, &s, T).as_slice(),
            [Alert::ProcessSilent { .. }]
        ));
    }

    /// The condition H-90 (#293) needed. The worker is alive and answering; it is simply not
    /// publishing, and only the clock against the log says so.
    #[test]
    fn a_missed_publication_is_reported_even_though_the_process_is_healthy() {
        let last: u64 = 20_745;
        let now = at(last.saturating_add(1))
            .saturating_add(T.publication_grace)
            .saturating_add(1);
        let o = Observed {
            now,
            today: day(now),
            start_epoch: 20_700,
            last_epoch: last,
            awaiting_attach: None,
            last_submitted: Some(last),
        };
        let s = Supervision {
            last_heartbeat: now.saturating_sub(60),
            receipt_submitted_at: None,
            consecutive_refusals: 0,
            last_refusal: None,
        };
        let raised = alerts(S, &o, &s, T);
        assert!(
            raised
                .iter()
                .any(|a| matches!(a, Alert::PublicationMissed { epoch, .. } if *epoch == last.saturating_add(1))),
            "the epoch that is owed is named: {raised:?}"
        );
    }

    /// And a publication merely inside its grace is not news.
    #[test]
    fn a_publication_inside_its_grace_is_not_reported() {
        let last: u64 = 20_745;
        let now = at(last.saturating_add(1))
            .saturating_add(T.publication_grace)
            .saturating_sub(1);
        let o = Observed {
            now,
            today: day(now),
            start_epoch: 20_700,
            last_epoch: last,
            awaiting_attach: None,
            last_submitted: Some(last),
        };
        let s = Supervision {
            last_heartbeat: now.saturating_sub(60),
            receipt_submitted_at: None,
            consecutive_refusals: 0,
            last_refusal: None,
        };
        assert!(!alerts(S, &o, &s, T)
            .iter()
            .any(|a| matches!(a, Alert::PublicationMissed { .. })));
    }

    #[test]
    fn a_log_behind_the_newest_publishable_epoch_is_reported() {
        let last: u64 = 20_740;
        let now = at(20_745).saturating_add(60);
        let o = Observed {
            now,
            today: day(now),
            start_epoch: 20_700,
            last_epoch: last,
            awaiting_attach: None,
            last_submitted: Some(last),
        };
        let s = Supervision {
            last_heartbeat: now.saturating_sub(60),
            receipt_submitted_at: None,
            consecutive_refusals: 0,
            last_refusal: None,
        };
        assert!(alerts(S, &o, &s, T)
            .iter()
            .any(|a| matches!(a, Alert::SequenceLag { .. })));
    }

    #[test]
    fn a_receipt_past_its_budget_is_reported() {
        let (mut o, mut s) = healthy();
        o.awaiting_attach = Some(20_745);
        s.receipt_submitted_at = Some(o.now.saturating_sub(T.receipt_budget).saturating_sub(1));
        assert!(alerts(S, &o, &s, T)
            .iter()
            .any(|a| matches!(a, Alert::ReceiptUnconfirmed { epoch, .. } if *epoch == 20_745)));
    }

    /// One refusal is an observation; the threshold's worth in a row is a stuck worker.
    #[test]
    fn repeated_refusal_is_reported_and_a_single_one_is_not() {
        let (o, mut s) = healthy();
        s.last_refusal = Some(Refusal::LogAheadOfCalendar {
            last_epoch: 20_745,
            today: 20_740,
        });

        s.consecutive_refusals = 1;
        assert!(!alerts(S, &o, &s, T)
            .iter()
            .any(|a| matches!(a, Alert::RepeatedRefusal { .. })));

        s.consecutive_refusals = T.consecutive_refusals;
        assert!(alerts(S, &o, &s, T)
            .iter()
            .any(|a| matches!(a, Alert::RepeatedRefusal { .. })));
    }

    /// Two problems are two alerts. Reporting only the most urgent hides the second until the
    /// first is fixed.
    #[test]
    fn conditions_are_reported_together_rather_than_one_at_a_time() {
        let (mut o, mut s) = healthy();
        s.last_heartbeat = o.now.saturating_sub(T.heartbeat_grace).saturating_sub(1);
        o.awaiting_attach = Some(20_745);
        s.receipt_submitted_at = Some(o.now.saturating_sub(T.receipt_budget).saturating_sub(1));
        let raised = alerts(S, &o, &s, T);
        assert!(raised
            .iter()
            .any(|a| matches!(a, Alert::ProcessSilent { .. })));
        assert!(raised
            .iter()
            .any(|a| matches!(a, Alert::ReceiptUnconfirmed { .. })));
    }

    /// **The architecture, pinned (H-95, issue #300).** Until 1 November 2026 this module was called
    /// by nothing outside this test file: it computed five conditions, passed eleven tests, and no
    /// operator could ever have been told any of them. The remedy splits the five by who can honestly
    /// raise each, and this test is what stops that split from being a sentence in a comment.
    ///
    /// Three are facts about the log and the worker raises them each cycle. Two are facts about the
    /// process and **cannot** come from a `Supervision` the worker built, whatever the log is doing —
    /// so they are given to systemd. If this test ever fails, either `from_worker` started claiming
    /// something the process cannot know, or a condition moved between the two groups and the unit
    /// files and runbook no longer describe where alerts come from.
    #[test]
    fn only_three_of_five_can_be_raised_by_the_worker_itself() {
        // A log in the worst state this type can describe: far behind, an epoch long overdue, and a
        // receipt well past its budget. If the two process conditions cannot fire here, they cannot
        // fire from this call site at all.
        let last: u64 = 20_700;
        let now = at(20_745)
            .saturating_add(T.receipt_budget)
            .saturating_add(1);
        let observed = Observed {
            now,
            today: day(now),
            start_epoch: 20_690,
            last_epoch: last,
            awaiting_attach: Some(last),
            last_submitted: Some(last),
        };
        let supervision = Supervision::from_worker(now, Some(0));

        let raised = alerts(S, &observed, &supervision, T);
        assert!(
            !raised.is_empty(),
            "a log this far behind must raise something, or the test proves nothing"
        );
        for alert in &raised {
            assert!(
                !matches!(
                    alert,
                    Alert::ProcessSilent { .. } | Alert::RepeatedRefusal { .. }
                ),
                "the worker cannot raise this about itself; systemd does: {alert:?}"
            );
        }
        assert!(
            raised
                .iter()
                .any(|a| matches!(a, Alert::PublicationMissed { .. })),
            "an overdue epoch is the worker's to report: {raised:?}"
        );
        assert!(
            raised
                .iter()
                .any(|a| matches!(a, Alert::SequenceLag { .. })),
            "a backlog is the worker's to report: {raised:?}"
        );
        assert!(
            raised
                .iter()
                .any(|a| matches!(a, Alert::ReceiptUnconfirmed { .. })),
            "a receipt past its budget is the worker's to report: {raised:?}"
        );
    }

    /// `from_worker` says the process is alive at the instant it asks, which is the one thing it can
    /// be sure of and the reason `ProcessSilent` is somebody else's job.
    #[test]
    fn from_worker_reports_itself_alive_now_and_refusing_nothing() {
        let s = Supervision::from_worker(1_792_000_000, None);
        assert_eq!(s.last_heartbeat, 1_792_000_000);
        assert_eq!(s.consecutive_refusals, 0);
        assert_eq!(s.last_refusal, None);
    }

    /// **The text an operator is woken by.** Rendered in the library so this test can reach it; in
    /// the binary it was the one part of the remedy nothing checked.
    #[test]
    fn each_alert_names_itself_and_the_two_process_conditions_name_their_emitter() {
        let rendered = |a: &Alert| a.to_string();

        let missed = rendered(&Alert::PublicationMissed {
            epoch: 20_746,
            due: at(20_746),
            now: at(20_746)
                .saturating_add(T.publication_grace)
                .saturating_add(1),
        });
        assert!(missed.starts_with("PublicationMissed:"), "{missed}");
        assert!(
            missed.contains("20746"),
            "the epoch has to be in it: {missed}"
        );

        let lag = rendered(&Alert::SequenceLag {
            last_epoch: 20_700,
            newest_publishable: 20_745,
            limit: 1,
        });
        assert!(lag.starts_with("SequenceLag:"), "{lag}");
        assert!(lag.contains("20700") && lag.contains("20745"), "{lag}");

        let receipt = rendered(&Alert::ReceiptUnconfirmed {
            epoch: 20_745,
            waiting: 300_000,
            budget: T.receipt_budget,
        });
        assert!(receipt.starts_with("ReceiptUnconfirmed:"), "{receipt}");

        // The two the worker cannot raise must say who does, so that a line reaching the journal
        // from the wrong place is legible as a defect rather than read as a normal alert.
        let silent = rendered(&Alert::ProcessSilent {
            since: 0,
            grace: T.heartbeat_grace,
        });
        assert!(silent.contains("WatchdogSec"), "{silent}");
        assert!(silent.contains("defect"), "{silent}");

        let repeated = rendered(&Alert::RepeatedRefusal {
            refusal: Refusal::LogAheadOfCalendar {
                last_epoch: 20_800,
                today: 20_745,
            },
            consecutive: 3,
        });
        assert!(repeated.contains("StartLimitBurst"), "{repeated}");
        assert!(repeated.contains("defect"), "{repeated}");
    }
}
