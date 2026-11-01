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
}
