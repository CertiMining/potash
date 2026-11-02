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
use std::time::Duration;

/// Bounded parameters for the unattended production worker.
///
/// These are deliberately code-reviewed constants rather than environment-controlled values. A
/// deployment cannot turn a partition into an unbounded retry loop, extend an RPC call indefinitely,
/// or silently permit a multi-epoch catch-up by changing process configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkerPolicy {
    /// Maximum duration of one RPC request.
    pub rpc_timeout: Duration,
    /// Longest sleep between fresh observations while the worker is healthy.
    pub poll_interval: Duration,
    /// Total transaction submission attempts, including the first one.
    pub publish_attempts: u32,
    /// Consecutive transport failures allowed before the worker stops for an operator.
    pub partition_retry_limit: u32,
    /// Delay after the first transport failure.
    pub retry_initial: Duration,
    /// Maximum exponential-backoff delay.
    pub retry_max: Duration,
    /// Number of unpublished UTC epochs the worker may recover without an operator ruling.
    pub max_epoch_slip: u64,
}

impl WorkerPolicy {
    /// Production policy: ordinary one-epoch recovery is automatic; a wider history rewrite is not.
    pub const PRODUCTION: Self = Self {
        rpc_timeout: Duration::from_secs(30),
        poll_interval: Duration::from_secs(300),
        publish_attempts: 3,
        partition_retry_limit: 5,
        retry_initial: Duration::from_secs(1),
        retry_max: Duration::from_secs(30),
        max_epoch_slip: 1,
    };

    /// Exponential partition-recovery delay for a one-based consecutive failure count.
    ///
    /// `None` is an explicit stop: zero is not a failure, and a count beyond the reviewed budget is
    /// not converted into an endless daemon loop.
    pub fn partition_retry_delay(self, consecutive_failures: u32) -> Option<Duration> {
        if consecutive_failures == 0 || consecutive_failures > self.partition_retry_limit {
            return None;
        }
        let mut delay = self.retry_initial;
        for _ in 1..consecutive_failures {
            delay = delay.saturating_mul(2).min(self.retry_max);
        }
        Some(delay)
    }

    /// The longest a healthy worker can go without feeding its watchdog (H-98, issue #305).
    ///
    /// **Why this is longer than one cycle.** The worker feeds the watchdog after a *successful*
    /// observation and deliberately does not feed it on the retry path, because a worker that cannot
    /// see the chain should stop reporting itself alive. So the quiet span covers the loop's sleep,
    /// every observation the partition budget allows, and the backoff between them — all of which a
    /// worker recovering exactly as designed will spend.
    ///
    /// One expression with two consumers: `anchor-b-worker` prints this against `WATCHDOG_USEC` at
    /// start, and `tests/supervision_units.rs` asserts the committed `WatchdogSec` exceeds it. The
    /// binary used `poll_interval + rpc_timeout` before this, which is 330s against a real 511s, so
    /// it would have passed a watchdog that killed a recovering worker.
    ///
    /// **A necessary bound and not a sufficient one.** One observation makes a status call per epoch
    /// carrying a receipt, so its cost grows with the backlog and no constant covers an arbitrary
    /// one. `partition_retry_limit + 1` observations is the no-backlog case: the budget's failures
    /// plus the attempt that succeeds.
    #[must_use]
    pub fn longest_quiet_cycle(self) -> Duration {
        let attempts = self.partition_retry_limit.saturating_add(1);
        let observing = self.rpc_timeout.saturating_mul(attempts);
        let mut backoff = Duration::ZERO;
        for failure in 1..=self.partition_retry_limit {
            if let Some(delay) = self.partition_retry_delay(failure) {
                backoff = backoff.saturating_add(delay);
            }
        }
        self.poll_interval
            .saturating_add(observing)
            .saturating_add(backoff)
    }
}

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
    /// The log's first publishable epoch, from its config account.
    pub start_epoch: u64,
    /// The highest epoch the log has published, from its config account.
    pub last_epoch: u64,
    /// The epoch whose root has been submitted to the calendars and not yet attached, if any.
    pub awaiting_attach: Option<u64>,
    /// The highest epoch whose root has been submitted to the calendars, if any.
    pub last_submitted: Option<u64>,
}

impl Observed {
    /// The UTC day index `now` falls in, which is what §1.4 makes an epoch.
    ///
    /// **Derived rather than carried, which is M-04 of the 1 November audit (H-101, issue #310).**
    /// This was a `pub` field beside `now` and nothing checked that the two agreed. The production
    /// loop happened to compute them together, so the invariant held there by construction and
    /// nowhere else — and the unit fixtures broke it: `caught_up(today)` set `now` to
    /// `publication_time(today)`, an hour into day `today + 1`, while labelling the day `today`. Every
    /// test built on it described a legal state under an illegal state's name, which is why the
    /// frontier defect below went unnoticed for as long as it did.
    ///
    /// A field that can disagree with `now` cannot be fixed by checking it at one call site. Deleting
    /// it is what makes the disagreement unrepresentable.
    #[must_use]
    pub fn today(&self) -> Option<u64> {
        day_index(self.now)
    }

    /// The newest epoch that can be published at `now` (H-90, #293).
    ///
    /// An epoch publishes an hour after it ends, so the newest publishable one is `today - 1` and
    /// never `today`. **One expression for the whole crate.** `alert.rs` computed this correctly and
    /// `next_step_with_policy` compared against `today` instead, one day looser, so a log that had
    /// already published the current day read as healthy — two places stating one number with nothing
    /// comparing them, which is H-98's (#305) class. Both call it now.
    #[must_use]
    pub fn newest_publishable(&self) -> Option<u64> {
        self.today()?.checked_sub(1)
    }
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
    LogAheadOfCalendar {
        last_epoch: u64,
        newest_publishable: u64,
    },
    /// `now` has no UTC day index, so no calendar barrier can be applied to it.
    ///
    /// Refused rather than passed over: a barrier that cannot be evaluated must not read as
    /// satisfied. Matches `HandoffWriteRefused::UndatableClock` on the batcher's side.
    UndatableClock { now: i64 },
    /// The config account reports a `last_epoch` more than one below `start_epoch`, which no
    /// sequence this program writes can produce. The observation is wrong, or the account is not
    /// this log's.
    ///
    /// **Exactly one below is the initialised state and is accepted (H-89, #292).** `initialize`
    /// writes `start_epoch - 1` so the first publication is `last + 1` like every other. This
    /// comment used to say any value below `start_epoch` was impossible, which is what let the
    /// barrier reject every new log without anyone noticing.
    LastBeforeStart { last_epoch: u64, start_epoch: u64 },
    /// More than the reviewed number of epochs are absent. Recovery must be explicitly bounded by
    /// an operator rather than letting an unattended worker replay an arbitrary backlog.
    EpochSlipExceeded {
        last_epoch: u64,
        newest_publishable: u64,
        max_epoch_slip: u64,
    },
    /// Receipt state names an epoch the log has not published.
    AwaitingAttachOutsideLog {
        awaiting_attach: u64,
        start_epoch: u64,
        last_epoch: u64,
    },
    /// The receipt directory claims progress beyond the checkpoint log.
    SubmissionAheadOfLog {
        last_submitted: u64,
        last_epoch: u64,
    },
    /// An attachment cannot be pending for an epoch the calendar submission record has not reached.
    AttachmentAheadOfSubmission {
        awaiting_attach: u64,
        last_submitted: Option<u64>,
    },
    /// An epoch's publication time cannot be represented, so the schedule cannot place it.
    Unschedulable { epoch: u64 },
}

/// The worker's next step, from state alone.
///
/// The order is deliberate. Attaching comes before publishing because the attach field is write-once
/// and its receipt is perishable attention, not because it is urgent; submitting comes before
/// publishing so a published root never sits unstamped while the next day is built.
pub fn next_step(schedule: Schedule, observed: &Observed) -> Step {
    next_step_with_policy(schedule, observed, WorkerPolicy::PRODUCTION)
}

/// The worker's next step under an explicit policy.
///
/// Tests use this entry point to prove each production barrier without reading a clock or waiting.
pub fn next_step_with_policy(
    schedule: Schedule,
    observed: &Observed,
    policy: WorkerPolicy,
) -> Step {
    let Observed {
        now,
        start_epoch,
        last_epoch,
        awaiting_attach,
        last_submitted,
    } = *observed;

    // The frontier, derived from `now`. A clock with no day index refuses rather than being waved
    // through, and so does day zero: `newest_publishable` is `today - 1`, so it is `None` in both
    // cases and asking for it alone refuses exactly the same states. The day itself was bound here
    // too until H-107 (issue #328), for the one barrier below that compared against it.
    let Some(newest_publishable) = observed.newest_publishable() else {
        return Step::Refuse(Refusal::UndatableClock { now });
    };

    // **`start_epoch - 1` is the initialised state, not an impossible one (H-89, #292).** The
    // barrier used to refuse `last_epoch < start_epoch`, and `initialize` writes
    // `config.last_epoch = start_epoch - 1` so that the first publication is `last + 1` like every
    // other. The worker therefore refused every new log and could not publish its first epoch; the
    // deployed log was brought up by hand, which is why nothing met it. What remains impossible is
    // a `last_epoch` more than one below `start_epoch`.
    if last_epoch.saturating_add(1) < start_epoch {
        return Step::Refuse(Refusal::LastBeforeStart {
            last_epoch,
            start_epoch,
        });
    }

    // **The refusal #49 asks for, against the frontier rather than the day (H-101, issue #310).** An
    // epoch is a UTC day index and publishes an hour after it ends, so the newest epoch that *can*
    // have been published at `now` is `today - 1`. This compared against `today`, one day looser, so
    // a log whose last epoch was the current day — already ahead of its own schedule, and not
    // walkable back because publication is monotone — returned `Wait` and read as healthy. `alert.rs`
    // had the frontier right the whole time; `Observed::newest_publishable` is now the one expression
    // both use.
    if last_epoch > newest_publishable {
        return Step::Refuse(Refusal::LogAheadOfCalendar {
            last_epoch,
            newest_publishable,
        });
    }

    if let Some(epoch) = awaiting_attach {
        if epoch < start_epoch || epoch > last_epoch {
            return Step::Refuse(Refusal::AwaitingAttachOutsideLog {
                awaiting_attach: epoch,
                start_epoch,
                last_epoch,
            });
        }
        if last_submitted.is_none_or(|submitted| epoch > submitted) {
            return Step::Refuse(Refusal::AttachmentAheadOfSubmission {
                awaiting_attach: epoch,
                last_submitted,
            });
        }
    }

    if let Some(submitted) = last_submitted {
        if submitted > last_epoch {
            return Step::Refuse(Refusal::SubmissionAheadOfLog {
                last_submitted: submitted,
                last_epoch,
            });
        }
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

    // Complete an already-published epoch's Anchor-B work even when the log is far behind. The slip
    // barrier prevents creating another checkpoint; it must not strand a checkpoint that already
    // exists in `Single` state.
    // **The slip is counted from the newest publishable epoch, not from today (H-90, #293).** An
    // epoch publishes an hour after it ends, so epoch `N`'s publication instant falls in day
    // `N + 1` and the newest epoch that can be published at any `now` is `today - 1`. Counting
    // `today - last_epoch` made a caught-up log two behind at the very instant it was due, so with
    // `max_epoch_slip` of one the worker waited for the publication time and then refused it —
    // every epoch, with no value of `N` behaving differently. Nothing met it because nothing
    // schedules the worker and the cycle is run by hand (D-117, D-139).
    // **The third copy of the frontier, now the same expression as the other two.** This read
    // `today.saturating_sub(1)`, which is `newest_publishable` written out again — correct here,
    // while the barrier above was comparing against `today`. The refusal reports the frontier it
    // compared against rather than the day, so an operator does not have to subtract one to see the
    // backlog the number describes (H-101, issue #310).
    let slip = newest_publishable.saturating_sub(last_epoch);
    if slip > policy.max_epoch_slip {
        return Step::Refuse(Refusal::EpochSlipExceeded {
            last_epoch,
            newest_publishable,
            max_epoch_slip: policy.max_epoch_slip,
        });
    }

    let Some(candidate) = last_epoch.checked_add(1) else {
        return Step::Refuse(Refusal::LogAheadOfCalendar {
            last_epoch,
            newest_publishable,
        });
    };

    // **One match, where there were two (H-107, issue #328; owner's ruling of 2 November 2026).** An
    // `if candidate > today` block stood here and answered the caught-up case itself. H-101 (#310)
    // tightened the barrier above from the day to the frontier, which leaves `candidate <= today` for
    // every state that reaches here and made the block unreachable — and left its comment, "the log
    // has published through the current day index", describing the state that barrier now refuses.
    //
    // It was redundant as well as unreachable, which is why deleting it is not a behaviour change.
    // With the pre-#314 barrier restored so it could be entered, 30,208 of 60,264 swept states reached
    // it and none answered differently from the match below: `now` falls in a day the candidate is
    // past, so `now < at` holds and this match returns the same `Wait`. The invariant that makes the
    // deletion safe is asserted by `the_calendar_barrier_admits_no_state_whose_candidate_is_past_today`.
    //
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

    fn at(epoch: u64) -> i64 {
        match publication_time(S, epoch) {
            Some(t) => t,
            None => panic!("epoch {epoch} has no publication time, so the test states nothing"),
        }
    }

    fn caught_up(today: u64) -> Observed {
        Observed {
            now: at(today),
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
            start_epoch: 20_723,
            last_epoch: 20_738,
            awaiting_attach: None,
            last_submitted: Some(20_738),
        };
        assert_eq!(
            next_step(S, &o),
            Step::Refuse(Refusal::EpochSlipExceeded {
                last_epoch: 20_738,
                newest_publishable: 20_746,
                max_epoch_slip: 1,
            }),
            "an unattended worker may recover the ordinary one-epoch slip, not replay an eight-epoch \
             backlog without an operator ruling"
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
            last_epoch: 20_738,
            last_submitted: Some(20_738),
            ..caught_up(20_739)
        };
        assert_eq!(next_step(S, &o), Step::Publish { epoch: 20_739 });
    }

    /// **The refusal #49 asks for**, and the state D-88 cost an earlier deployment.
    ///
    /// **This test passed for the wrong reason, and that is H-02 of the 1 November audit
    /// (H-101, issue #310).** `at(20_739)` is an hour into day 20,740, so the state here is
    /// `last_epoch == day_index(now)` — precisely the state the audit found was being accepted. It
    /// refused anyway, because the fixture it used carried `today: 20_739`, understating the real day
    /// by one and making the old `last_epoch > today` barrier fire on a comparison the real clock
    /// would not have produced.
    ///
    /// With the day derived from `now` the numbers are unchanged and the verdict is not: under the
    /// old barrier this is `20_740 > 20_740`, false, and the worker would have returned `Wait`. Under
    /// the frontier it is `20_740 > 20_739`, true. So the same assertion that used to pass vacuously
    /// now distinguishes the two barriers, which is what it was always supposed to do.
    #[test]
    fn a_log_ahead_of_the_calendar_is_refused_not_published() {
        let o = Observed {
            now: at(20_739),
            start_epoch: 20_723,
            last_epoch: 20_740,
            awaiting_attach: None,
            last_submitted: Some(20_740),
        };
        assert_eq!(
            o.today(),
            Some(20_740),
            "the publication instant is in the next day"
        );
        assert_eq!(
            next_step(S, &o),
            Step::Refuse(Refusal::LogAheadOfCalendar {
                last_epoch: 20_740,
                newest_publishable: 20_739
            })
        );
    }

    #[test]
    fn a_published_root_is_stamped_before_the_next_day_is_published() {
        let o = Observed {
            now: at(20_746),
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
        // **This test's name was right and its body was not (H-89, #292; H-90, #293).** It asserted
        // `LastBeforeStart` on the state `initialize` writes, so the name said publish and the
        // assertion said refuse. Both barriers were off by one against the schedule.
        let start = 20_723;
        let now = at(start);
        let o = Observed {
            now,
            start_epoch: start,
            last_epoch: start - 1,
            awaiting_attach: None,
            last_submitted: None,
        };
        assert_eq!(
            next_step(S, &o),
            Step::Publish { epoch: start },
            "a freshly initialised log publishes its start epoch"
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
            start_epoch: 20_723,
            last_epoch: 20_739,
            awaiting_attach: None,
            last_submitted: Some(20_739),
        };
        let mut steps = Vec::new();
        for _ in 0..8 {
            let step = next_step_with_policy(
                S,
                &o,
                WorkerPolicy {
                    max_epoch_slip: 3,
                    ..WorkerPolicy::PRODUCTION
                },
            );
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

    #[test]
    fn impossible_receipt_and_submission_barriers_fail_closed() {
        let base = caught_up(20_739);
        assert_eq!(
            next_step(
                S,
                &Observed {
                    awaiting_attach: Some(20_740),
                    ..base
                },
            ),
            Step::Refuse(Refusal::AwaitingAttachOutsideLog {
                awaiting_attach: 20_740,
                start_epoch: 20_723,
                last_epoch: 20_739,
            })
        );
        assert_eq!(
            next_step(
                S,
                &Observed {
                    last_submitted: Some(20_740),
                    ..base
                },
            ),
            Step::Refuse(Refusal::SubmissionAheadOfLog {
                last_submitted: 20_740,
                last_epoch: 20_739,
            })
        );
        assert_eq!(
            next_step(
                S,
                &Observed {
                    awaiting_attach: Some(20_739),
                    last_submitted: Some(20_738),
                    ..base
                },
            ),
            Step::Refuse(Refusal::AttachmentAheadOfSubmission {
                awaiting_attach: 20_739,
                last_submitted: Some(20_738),
            })
        );
    }

    #[test]
    fn partition_backoff_is_bounded_and_stops_after_the_budget() {
        let policy = WorkerPolicy::PRODUCTION;
        assert_eq!(policy.partition_retry_delay(0), None);
        assert_eq!(
            policy.partition_retry_delay(1),
            Some(Duration::from_secs(1))
        );
        assert_eq!(
            policy.partition_retry_delay(2),
            Some(Duration::from_secs(2))
        );
        assert_eq!(
            policy.partition_retry_delay(5),
            Some(Duration::from_secs(16))
        );
        assert_eq!(policy.partition_retry_delay(6), None);

        let capped = WorkerPolicy {
            retry_max: Duration::from_secs(3),
            ..policy
        };
        assert_eq!(
            capped.partition_retry_delay(5),
            Some(Duration::from_secs(3))
        );
    }

    /// H-89 (#292). `initialize` writes `last_epoch = start_epoch - 1`, and the barrier refused
    /// exactly that, so the worker could never publish a new log's first epoch.
    #[test]
    fn a_freshly_initialised_log_publishes_its_first_epoch() {
        let start = 20_700;
        let now = at(start);
        let observed = Observed {
            now,
            start_epoch: start,
            last_epoch: start - 1,
            awaiting_attach: None,
            last_submitted: None,
        };
        assert_eq!(next_step(S, &observed), Step::Publish { epoch: start });
    }

    /// And the state that really is impossible is still refused.
    #[test]
    fn a_last_epoch_more_than_one_below_start_is_still_refused() {
        let start = 20_700;
        let now = at(start);
        let observed = Observed {
            now,
            start_epoch: start,
            last_epoch: start - 2,
            awaiting_attach: None,
            last_submitted: None,
        };
        assert!(matches!(
            next_step(S, &observed),
            Step::Refuse(Refusal::LastBeforeStart { .. })
        ));
    }

    /// H-90 (#293). A caught-up log publishes at the instant it waited for, instead of refusing it.
    #[test]
    fn a_caught_up_log_publishes_at_the_publication_time_it_waited_for() {
        let last = 20_745;
        let wake = at(last + 1);
        let observed = Observed {
            now: wake,
            start_epoch: 20_700,
            last_epoch: last,
            awaiting_attach: None,
            last_submitted: Some(last),
        };
        assert_eq!(
            observed.today(),
            Some(last + 2),
            "the publication instant falls in the day after the epoch ends, which is the trap"
        );
        assert_eq!(next_step(S, &observed), Step::Publish { epoch: last + 1 });
    }

    /// And a log genuinely further behind than the policy allows is still refused.
    #[test]
    fn a_log_past_the_slip_allowance_is_still_refused() {
        let last = 20_740;
        let wake = at(20_745);
        let observed = Observed {
            now: wake,
            start_epoch: 20_700,
            last_epoch: last,
            awaiting_attach: None,
            last_submitted: Some(last),
        };
        assert!(matches!(
            next_step(S, &observed),
            Step::Refuse(Refusal::EpochSlipExceeded { .. })
        ));
    }

    /// **The number the unit file is read against, stated once so a policy change surfaces here.**
    ///
    /// 300s of sleep, six observations at a 30s timeout (five failures from the partition budget and
    /// the attempt that succeeds), and 1 + 2 + 4 + 8 + 16 = 31s of backoff. The 30s `retry_max` is
    /// never reached inside a budget of five, which is why the backoff is 31s and not 150s.
    ///
    /// `tests/supervision_units.rs` compares the committed `WatchdogSec` against this. If the policy
    /// changes, this test is where the new span is read off, and that unit file is what has to move.
    #[test]
    fn the_longest_quiet_span_under_the_production_policy_is_511_seconds() {
        let p = WorkerPolicy::PRODUCTION;
        let mut backoff = Duration::ZERO;
        for failure in 1..=p.partition_retry_limit {
            if let Some(delay) = p.partition_retry_delay(failure) {
                backoff = backoff.saturating_add(delay);
            }
        }
        assert_eq!(backoff, Duration::from_secs(31), "1 + 2 + 4 + 8 + 16");
        assert_eq!(p.longest_quiet_cycle(), Duration::from_secs(511));
        assert!(
            p.longest_quiet_cycle() > p.poll_interval.saturating_add(p.rpc_timeout),
            "the bound this replaced was the smaller one, which is the defect H-98 names"
        );
    }

    /// **The frontier at both ends of a day, which is the boundary H-02 lives on.**
    ///
    /// An epoch publishes an hour after it ends, so during day `d` the newest epoch that can have
    /// been published is `d - 1`. A log reporting `last_epoch == d` is ahead of its own schedule at
    /// every instant of day `d`, from one second past midnight to one second before the next, and the
    /// old barrier accepted it at all of them. Both ends are checked because an off-by-one in the day
    /// arithmetic would show at one end only.
    #[test]
    fn a_log_reporting_the_current_day_is_refused_at_every_hour_of_it() {
        let day: u64 = 20_750;
        let midnight = match i64::try_from(day) {
            Ok(d) => d.saturating_mul(86_400),
            Err(_) => panic!("day {day} is beyond i64, so the test states nothing"),
        };
        for (label, now) in [
            ("one second after midnight", midnight.saturating_add(1)),
            ("midday", midnight.saturating_add(43_200)),
            (
                "one second before midnight",
                midnight.saturating_add(86_399),
            ),
        ] {
            let o = Observed {
                now,
                start_epoch: 20_723,
                last_epoch: day,
                awaiting_attach: None,
                last_submitted: Some(day),
            };
            assert_eq!(o.today(), Some(day), "{label} is still day {day}");
            assert_eq!(
                next_step(S, &o),
                Step::Refuse(Refusal::LogAheadOfCalendar {
                    last_epoch: day,
                    newest_publishable: day.saturating_sub(1),
                }),
                "at {label}, a log that has already published day {day} is ahead of the schedule"
            );
        }
    }

    /// And the frontier itself is not refused, at the same three instants.
    ///
    /// The pair matters: a barrier that refused `last_epoch == today - 1` would stop the worker
    /// publishing anything at all, so the test above is only meaningful beside this one.
    #[test]
    fn a_log_at_the_frontier_is_not_refused_at_any_hour_of_the_day() {
        let day: u64 = 20_750;
        let midnight = match i64::try_from(day) {
            Ok(d) => d.saturating_mul(86_400),
            Err(_) => panic!("day {day} is beyond i64, so the test states nothing"),
        };
        for now in [
            midnight.saturating_add(1),
            midnight.saturating_add(43_200),
            midnight.saturating_add(86_399),
        ] {
            let o = Observed {
                now,
                start_epoch: 20_723,
                last_epoch: day.saturating_sub(1),
                awaiting_attach: None,
                last_submitted: Some(day.saturating_sub(1)),
            };
            assert!(
                !matches!(
                    next_step(S, &o),
                    Step::Refuse(Refusal::LogAheadOfCalendar { .. })
                ),
                "the newest publishable epoch is not ahead of anything"
            );
        }
    }

    /// **Every state the calendar barrier admits has `candidate <= today` (H-101 #310, H-107 #328).**
    ///
    /// The invariant that let the `if candidate > today` block go. #314 tightened the frontier barrier
    /// from `last_epoch > today` to `last_epoch > newest_publishable`, and `newest_publishable` is
    /// `today - 1` wherever it is `Some`, so a `last_epoch` the barrier admits cannot make
    /// `last_epoch + 1` exceed the day. If that barrier is ever loosened again, this fails.
    ///
    /// **It reads the barrier rather than restating it.** A test computing
    /// `last_epoch <= newest_publishable` for itself would still pass after such a loosening, because
    /// the test would have moved with the code — the trap of writing a demand and its fixtures from
    /// one model, which is how a wrong gate goes green. So this drives `next_step_with_policy` and
    /// skips only what the three refusals at or before the barrier reject. Every other outcome,
    /// refusal or step, means execution passed it.
    #[test]
    fn the_calendar_barrier_admits_no_state_whose_candidate_is_past_today() {
        let max_day = match day_index(i64::MAX) {
            Some(d) => d,
            None => panic!("i64::MAX falls in some UTC day"),
        };
        let mut checked = 0u32;
        let mut admitted = 0u32;

        // The ordinary calendar, every hour of the day that matters: the first second, the second
        // second, midday and the last second.
        let ordinary: Vec<u64> = (1u64..60).collect();
        // And the edges, where any overflow escape would live.
        let extreme = [
            max_day.saturating_sub(2),
            max_day.saturating_sub(1),
            max_day,
        ];
        let extreme_lasts = [
            0u64,
            1,
            2,
            max_day.saturating_sub(2),
            max_day.saturating_sub(1),
            max_day,
            max_day.saturating_add(1),
            u64::MAX.saturating_sub(1),
            u64::MAX,
        ];

        let visit = |o: Observed, checked: &mut u32, admitted: &mut u32| {
            *checked = checked.saturating_add(1);
            let step = next_step_with_policy(S, &o, WorkerPolicy::PRODUCTION);
            // The three refusals at or before the frontier barrier. A state they reject never
            // reaches the code the invariant is about.
            if matches!(
                step,
                Step::Refuse(
                    Refusal::UndatableClock { .. }
                        | Refusal::LastBeforeStart { .. }
                        | Refusal::LogAheadOfCalendar { .. }
                )
            ) {
                return;
            }
            *admitted = admitted.saturating_add(1);
            let today = match o.today() {
                Some(d) => d,
                None => panic!("UndatableClock would have refused {o:?}"),
            };
            let candidate = match o.last_epoch.checked_add(1) {
                Some(c) => c,
                None => panic!("LogAheadOfCalendar would have refused {o:?}"),
            };
            assert!(
                candidate <= today,
                "the barrier admitted {o:?}, whose candidate {candidate} is past today {today}"
            );
        };

        for today in ordinary {
            let base = match i64::try_from(today)
                .ok()
                .and_then(|d| d.checked_mul(EPOCH_SECONDS))
            {
                Some(n) => n,
                None => continue,
            };
            for last_epoch in 0u64..60 {
                for start_epoch in 0u64..3 {
                    for last_submitted in [None, Some(last_epoch)] {
                        for awaiting_attach in [None, Some(last_epoch)] {
                            for offset in [0i64, 1, 43_200, 86_399] {
                                let now = match base.checked_add(offset) {
                                    Some(n) => n,
                                    None => continue,
                                };
                                visit(
                                    Observed {
                                        now,
                                        start_epoch,
                                        last_epoch,
                                        awaiting_attach,
                                        last_submitted,
                                    },
                                    &mut checked,
                                    &mut admitted,
                                );
                            }
                        }
                    }
                }
            }
        }

        for today in [1u64, 2].into_iter().chain(extreme) {
            let base = match i64::try_from(today)
                .ok()
                .and_then(|d| d.checked_mul(EPOCH_SECONDS))
            {
                Some(n) => n,
                None => continue,
            };
            for last_epoch in extreme_lasts {
                for offset in [0i64, 86_399] {
                    let now = match base.checked_add(offset) {
                        Some(n) => n,
                        None => continue,
                    };
                    // An offset that spills into the next day would describe a different calendar
                    // than the one this iteration names.
                    if day_index(now) != Some(today) {
                        continue;
                    }
                    for last_submitted in [None, Some(last_epoch)] {
                        for start_epoch in [0u64, last_epoch] {
                            visit(
                                Observed {
                                    now,
                                    start_epoch,
                                    last_epoch,
                                    awaiting_attach: None,
                                    last_submitted,
                                },
                                &mut checked,
                                &mut admitted,
                            );
                        }
                    }
                }
            }
        }

        // The count is pinned so the figure cited in issue #328 cannot drift from the sweep that
        // produced it, and so a loop quietly stopping early is a failure rather than a smaller pass.
        assert_eq!(
            checked, 170_244,
            "the sweep is cited at 170,244 states in issue #328"
        );
        assert!(
            admitted > 0,
            "a sweep that admits nothing asserts nothing about the barrier"
        );
    }

    /// A clock with no day index refuses, rather than every calendar barrier reading as satisfied.
    #[test]
    fn a_clock_with_no_day_index_is_refused_rather_than_waved_through() {
        let o = Observed {
            now: -1,
            start_epoch: 20_723,
            last_epoch: 20_740,
            awaiting_attach: None,
            last_submitted: Some(20_740),
        };
        assert_eq!(o.today(), None);
        assert_eq!(
            next_step(S, &o),
            Step::Refuse(Refusal::UndatableClock { now: -1 })
        );
    }
    /// **The arm nothing reached (H-104, issue #322).** `Unschedulable` is constructed twice in this
    /// function and was named by no test, so the one refusal that reports a schedule rather than a
    /// state was asserted by nothing.
    ///
    /// Reached the same way as its counterpart in `handoff.rs`: `publication_time` multiplies the
    /// epoch by a day and adds another, so it leaves `i64` at day index 106_751_991_167_300. A log
    /// caught up to the frontier there makes `candidate` that day, and the schedule cannot place it.
    /// The clock is absurd and the boundary is not — it is what the `checked_mul` in
    /// `publication_time` exists for, and a worker that read `None` as nothing owed would sit still
    /// instead of refusing.
    #[test]
    fn an_epoch_the_schedule_cannot_place_is_refused_rather_than_published() {
        let today = match day_index(i64::MAX) {
            Some(d) => d,
            None => panic!("i64::MAX falls in some UTC day"),
        };
        let last_epoch = match today.checked_sub(1) {
            Some(e) => e,
            None => panic!("day {today} has a predecessor"),
        };
        // Derived, not assumed: if the frontier ever moves, this fails here rather than quietly
        // asserting a different arm.
        assert_eq!(
            publication_time(S, today),
            None,
            "day {today} must be the unschedulable one or the test states nothing"
        );
        let o = Observed {
            now: i64::MAX,
            start_epoch: last_epoch,
            last_epoch,
            awaiting_attach: None,
            last_submitted: Some(last_epoch),
        };
        assert_eq!(
            o.newest_publishable(),
            Some(last_epoch),
            "the log is caught up to the frontier"
        );
        assert_eq!(
            next_step(S, &o),
            Step::Refuse(Refusal::Unschedulable { epoch: today }),
            "an epoch the schedule cannot place is refused, not waited on forever"
        );
    }
}
