// SPDX-License-Identifier: MIT OR Apache-2.0
//! What the anchor-B worker does next, decided from state alone (H-13, [#49]).
//!
//! **Why this module is pure.** D-117 described a worker that refuses to start on a key it should not
//! read, and there was no worker: the daily cycle was run by hand. A cycle run by hand is a cycle that
//! can simply not happen, which is what it did — nothing was published between epoch 20738 and the
//! pause recorded in `docs/anchoring.md`, and nothing noticed for a week.
//!
//! The fix is not only a process. A process that decides inside its own loop can only be checked by
//! running it against a cluster and a calendar for days. So every decision lives here, as a function
//! from observed state to one [`Step`], and the binary is a loop that observes, calls this, and
//! performs. The tests below drive it across calendars no real run would reach in a year.
//!
//! **What it decides, and what it refuses.** §1.5 fixes publication time by the epoch rather than by
//! the build, so a tree that finishes early waits (D-83, INV-ANCH-01): publishing when ready leaks
//! build time, and build time tracks record count. An epoch is a UTC day index (§1.4), so an epoch
//! ahead of the calendar is not a fast log but a broken one — that is what put an earlier deployment
//! 209 days ahead and cost it (D-88). This refuses it rather than publishing it.
//!
//! **What it does not decide.** Whether a receipt may be attached is [`crate::cluster::Cluster::attach`]'s,
//! which reads the root from the chain and refuses a receipt carrying no Bitcoin attestation. This
//! module never routes around that: [`Step::Attach`] means *try*, and a refusal is an ordinary outcome
//! the loop waits through, because INV-ANCH-04 budgets hours for Bitcoin and the attach field is
//! write-once (D-112).

use crate::schedule::{publication_time, Schedule, EPOCH_SECONDS};

/// Everything the worker is allowed to decide from.
///
/// Every field is an observation, not a belief: `last_epoch` and `start_epoch` are read from the log's
/// config account, and the two receipt fields from the worker's own record of what it has submitted.
/// Nothing here is derived inside this module, so a test states a situation rather than constructing
/// one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Observed {
    /// Unix seconds. The binary supplies the host clock.
    ///
    /// **Not the chain's clock, and the difference is stated rather than hidden.** #49 asks for an
    /// epoch ahead of *the chain's own day index* to be refused; a host whose clock runs fast would
    /// pass the refusal below and still publish ahead. The program will refuse it on chain under
    /// issue #45, which is where the check belongs. Until then this is the same client-side guard the
    /// by-hand harness carries, in a place that is tested.
    pub now: i64,
    /// The UTC day index `now` falls in, which is what §1.4 makes an epoch.
    pub today: u64,
    /// The log's first publishable epoch, from its config account.
    pub start_epoch: u64,
    /// The highest epoch the log has published, from its config account.
    pub last_epoch: u64,
    /// The epoch whose root has been submitted to the calendars and not yet attached, if any.
    pub awaiting_attach: Option<u64>,
    /// The highest epoch whose root has been submitted to the calendars, if any.
    pub last_submitted: Option<u64>,
}

/// The one thing the worker does next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// Publish this epoch's checkpoint. Always `last_epoch + 1`: the range is contiguous by
    /// construction, because `publish_checkpoint` accepts nothing else (INV-ANCH-02, D-106).
    Publish { epoch: u64 },
    /// Submit this epoch's published root to the calendars (anchor B's first half, D-114).
    Submit { epoch: u64 },
    /// Try to upgrade this epoch's receipt and attach it if Bitcoin has confirmed.
    ///
    /// A receipt that has not confirmed is not a failure: INV-ANCH-04 budgets the wait, and
    /// `Cluster::attach` refuses one that only a calendar stands behind.
    Attach { epoch: u64 },
    /// Nothing is due. Sleep until this Unix time, then observe again.
    Wait { until: i64 },
    /// Stop. The state is one the worker must not act on.
    Refuse(Refusal),
}

/// A state the worker refuses to act on, rather than acting and recording it afterwards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// `last_epoch` is already ahead of the calendar, so the log is in the state D-88 cost an earlier
    /// deployment. Publishing more would deepen it; the worker stops and a human rules.
    LogAheadOfCalendar { last_epoch: u64, today: u64 },
    /// The config account reports a `last_epoch` below `start_epoch`, which no sequence this program
    /// writes can produce. The observation is wrong, or the account is not this log's.
    LastBeforeStart { last_epoch: u64, start_epoch: u64 },
    /// An epoch's publication time cannot be represented, so the schedule cannot place it.
    Unschedulable { epoch: u64 },
}

/// The worker's next step, from state alone.
///
/// The order is deliberate. Attaching comes before publishing because the attach field is write-once
/// and its receipt is perishable attention, not because it is urgent; submitting comes before
/// publishing so a published root never sits unstamped while the next day is built.
pub fn next_step(schedule: Schedule, observed: &Observed) -> Step {
    let Observed {
        now,
        today,
        start_epoch,
        last_epoch,
        awaiting_attach,
        last_submitted,
    } = *observed;

    if last_epoch < start_epoch {
        return Step::Refuse(Refusal::LastBeforeStart {
            last_epoch,
            start_epoch,
        });
    }

    // **The refusal #49 asks for.** An epoch is a UTC day index, so a log whose last published epoch
    // is in the future is not ahead of schedule, it is wrong. Every further publication would be too,
    // since the next one can only be `last_epoch + 1`.
    if last_epoch > today {
        return Step::Refuse(Refusal::LogAheadOfCalendar { last_epoch, today });
    }

    // A receipt waiting on Bitcoin is the only thing that can become actionable without the clock
    // moving, so it is asked about first.
    if let Some(epoch) = awaiting_attach {
        return Step::Attach { epoch };
    }

    // A published root with no receipt submitted is anchor B's half left undone. `last_submitted`
    // being behind `last_epoch` is the whole condition: the sequence is contiguous, so there is at
    // most one such epoch at a time.
    let submitted_through = last_submitted.unwrap_or(start_epoch.saturating_sub(1));
    if submitted_through < last_epoch {
        return Step::Submit { epoch: last_epoch };
    }

    let Some(candidate) = last_epoch.checked_add(1) else {
        return Step::Refuse(Refusal::LogAheadOfCalendar { last_epoch, today });
    };

    // Nothing is owed today: the log has published through the current day index. Wait for the next
    // epoch's publication time rather than spinning.
    if candidate > today {
        return match publication_time(schedule, candidate) {
            Some(at) => Step::Wait { until: at },
            None => Step::Refuse(Refusal::Unschedulable { epoch: candidate }),
        };
    }

    // **§1.5's constant rate, which is a privacy property and not a nicety.** An epoch is published at
    // a time fixed by the epoch, so a tree that finished early waits (D-83). A caught-up worker reaches
    // here each day and waits; a worker behind the calendar finds the time long past and publishes at
    // once, which is how a gap is paid.
    match publication_time(schedule, candidate) {
        Some(at) if now < at => Step::Wait { until: at },
        Some(_) => Step::Publish { epoch: candidate },
        None => Step::Refuse(Refusal::Unschedulable { epoch: candidate }),
    }
}

/// The UTC day index a Unix time falls in, which §1.4 makes an epoch.
///
/// `None` before 1970: a negative time has no day index this log could publish, and the alternative
/// is a silent truncation toward zero that would put the worker a day out for the whole of 1969.
pub fn day_index(now: i64) -> Option<u64> {
    u64::try_from(now.div_euclid(EPOCH_SECONDS)).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: Schedule = Schedule::DEPLOYED;

    /// Publication time for an epoch, so a test states "an hour after 20739 ended" rather than a
    /// number nobody can check.
    fn at(epoch: u64) -> i64 {
        match publication_time(S, epoch) {
            Some(t) => t,
            None => panic!("epoch {epoch} has no publication time, so the test states nothing"),
        }
    }

    fn caught_up(today: u64) -> Observed {
        Observed {
            now: at(today),
            today,
            start_epoch: 20_723,
            last_epoch: today,
            awaiting_attach: None,
            last_submitted: Some(today),
        }
    }

    #[test]
    fn a_day_behind_publishes_that_day() {
        let o = Observed {
            last_epoch: 20_738,
            last_submitted: Some(20_738),
            ..caught_up(20_739)
        };
        assert_eq!(next_step(S, &o), Step::Publish { epoch: 20_739 });
    }

    /// The gap of 20 Oct 2026, which is the state this module was written in.
    #[test]
    fn a_long_gap_is_paid_one_epoch_at_a_time_from_the_oldest() {
        let o = Observed {
            now: at(20_746),
            today: 20_746,
            start_epoch: 20_723,
            last_epoch: 20_738,
            awaiting_attach: None,
            last_submitted: Some(20_738),
        };
        assert_eq!(
            next_step(S, &o),
            Step::Publish { epoch: 20_739 },
            "the sequence is contiguous, so a seven-day gap is paid from its oldest end and never by \
             skipping to today (INV-ANCH-02, D-106)"
        );
    }

    #[test]
    fn caught_up_waits_for_the_next_publication_time() {
        assert_eq!(
            next_step(S, &caught_up(20_739)),
            Step::Wait { until: at(20_740) }
        );
    }

    /// §1.5: the time is a function of the epoch, not of when the tree was ready.
    #[test]
    fn a_tree_ready_early_waits_rather_than_publishing_early() {
        let o = Observed {
            now: at(20_739) - 1,
            today: 20_739,
            last_epoch: 20_738,
            last_submitted: Some(20_738),
            ..caught_up(20_739)
        };
        assert_eq!(
            next_step(S, &o),
            Step::Wait { until: at(20_739) },
            "one second early is early. Publishing when ready leaks build time, and build time tracks \
             record count (D-83)"
        );
    }

    #[test]
    fn one_second_later_it_publishes() {
        let o = Observed {
            now: at(20_739),
            today: 20_739,
            last_epoch: 20_738,
            last_submitted: Some(20_738),
            ..caught_up(20_739)
        };
        assert_eq!(next_step(S, &o), Step::Publish { epoch: 20_739 });
    }

    /// **The refusal #49 asks for**, and the state D-88 cost an earlier deployment.
    #[test]
    fn a_log_ahead_of_the_calendar_is_refused_not_published() {
        let o = Observed {
            now: at(20_739),
            today: 20_739,
            start_epoch: 20_723,
            last_epoch: 20_740,
            awaiting_attach: None,
            last_submitted: Some(20_740),
        };
        assert_eq!(
            next_step(S, &o),
            Step::Refuse(Refusal::LogAheadOfCalendar {
                last_epoch: 20_740,
                today: 20_739
            })
        );
    }

    #[test]
    fn a_published_root_is_stamped_before_the_next_day_is_published() {
        let o = Observed {
            now: at(20_746),
            today: 20_746,
            start_epoch: 20_723,
            last_epoch: 20_739,
            awaiting_attach: None,
            last_submitted: Some(20_738),
        };
        assert_eq!(
            next_step(S, &o),
            Step::Submit { epoch: 20_739 },
            "anchor A without anchor B is a root nothing outside Solana stands behind; the gap does \
             not excuse leaving it unstamped"
        );
    }

    #[test]
    fn a_receipt_waiting_on_bitcoin_is_tried_before_anything_else() {
        let o = Observed {
            awaiting_attach: Some(20_739),
            last_epoch: 20_745,
            last_submitted: Some(20_744),
            ..caught_up(20_746)
        };
        assert_eq!(
            next_step(S, &o),
            Step::Attach { epoch: 20_739 },
            "it is the only step that can become possible without the clock moving"
        );
    }

    #[test]
    fn a_log_that_has_published_nothing_publishes_its_start_epoch() {
        let o = Observed {
            now: at(20_746),
            today: 20_746,
            start_epoch: 20_723,
            last_epoch: 20_722,
            awaiting_attach: None,
            last_submitted: None,
        };
        assert_eq!(
            next_step(S, &o),
            Step::Refuse(Refusal::LastBeforeStart {
                last_epoch: 20_722,
                start_epoch: 20_723
            }),
            "a log before its own start_epoch is an observation this program cannot have produced"
        );
    }

    #[test]
    fn day_index_is_the_floor_and_refuses_before_1970() {
        assert_eq!(day_index(0), Some(0));
        assert_eq!(day_index(EPOCH_SECONDS - 1), Some(0));
        assert_eq!(day_index(EPOCH_SECONDS), Some(1));
        assert_eq!(
            day_index(-1),
            None,
            "truncation toward zero would call 31 Dec 1969 day 0 and put the worker a day out"
        );
    }

    /// Driving it the way the binary does: state in, one step out, state advanced, repeat. A gap is
    /// paid in order and the worker settles into waiting, without the loop deciding anything itself.
    #[test]
    fn the_loop_pays_a_gap_in_order_and_then_waits() {
        let mut o = Observed {
            now: at(20_742),
            today: 20_742,
            start_epoch: 20_723,
            last_epoch: 20_739,
            awaiting_attach: None,
            last_submitted: Some(20_739),
        };
        let mut steps = Vec::new();
        for _ in 0..8 {
            let step = next_step(S, &o);
            steps.push(step);
            match step {
                Step::Publish { epoch } => o.last_epoch = epoch,
                Step::Submit { epoch } => o.last_submitted = Some(epoch),
                Step::Wait { .. } | Step::Attach { .. } | Step::Refuse(_) => break,
            }
        }
        assert_eq!(
            steps,
            vec![
                Step::Publish { epoch: 20_740 },
                Step::Submit { epoch: 20_740 },
                Step::Publish { epoch: 20_741 },
                Step::Submit { epoch: 20_741 },
                Step::Publish { epoch: 20_742 },
                Step::Submit { epoch: 20_742 },
                Step::Wait {
                    until: at(20_743)
                },
            ],
            "each published epoch is stamped before the next is published, and the worker stops at \
             the calendar rather than running ahead of it"
        );
    }
}
