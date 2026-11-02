// SPDX-License-Identifier: MIT OR Apache-2.0
//! The numbers the committed units carry, against the numbers the code carries (H-98, issue #305).
//!
//! **Why this exists.** `deploy/systemd/` and `crates/certimining-client/` both state the
//! supervision's numbers and nothing compared them. Each relation below fails quietly, and in the
//! direction that suppresses an alert: a watchdog shorter than a quiet span kills a healthy worker, a
//! start limit above `consecutive_refusals` enforces a threshold the code does not claim, and a
//! restart delay past the limit interval means the limit is never reached and `RepeatedRefusal` is
//! raised by neither emitter while every directive still reads plausibly on its own.
//!
//! **What this does not establish.** Nothing here runs systemd. Whether `OnFailure=` fires once or on
//! every auto-restart, and how many pages a real three-refusal run produces, needs a host — that is
//! #251, and `certimining-alert@.service` says of itself that the count is designed rather than
//! demonstrated until then. This makes the internal consistency demonstrated, which is the half that
//! needs no host.
//!
//! The units are embedded with `include_str!` rather than read at run time, so a moved or renamed
//! file is a compile error instead of a test that quietly checks nothing.

use certimining_client::{Thresholds, WorkerPolicy};
use std::time::Duration;

const WORKER_UNIT: &str =
    include_str!("../../../deploy/systemd/certimining-anchor-b-worker.service");
const ALERT_UNIT: &str = include_str!("../../../deploy/systemd/certimining-alert@.service");

const WORKER: &str = "certimining-anchor-b-worker.service";
const ALERT: &str = "certimining-alert@.service";

/// The value a directive is set to in the section that governs it, once.
///
/// **Comments are stripped before anything is matched, and that is substance rather than
/// housekeeping.** Both units discuss `WatchdogSec` and `StartLimitBurst` at length in prose; a
/// reader that searched the file's text would take a sentence about a number for the number and pass
/// on commentary. That mistake was made and caught in H-96 (#301).
///
/// **The section is checked, for the same reason.** `StartLimitIntervalSec` and `StartLimitBurst` are
/// `[Unit]` options — they moved there in systemd 229, and the worker unit's own comment says a copy
/// left in `[Service]` is not read. systemd ignores a misplaced directive silently, so a reader that
/// took it from anywhere would confirm a number systemd never applies, which is this issue's defect
/// occurring inside the instrument written to prevent it. A copy in another section fails rather than
/// being passed over: that is the state where a reader of the file and systemd disagree.
///
/// Absence fails too. A directive this test asks for and does not find is the case where a relation
/// stops being checked, so it is named rather than skipped.
fn directive(unit: &str, file: &str, section: &str, name: &str) -> String {
    let mut current = "";
    let mut here: Vec<&str> = Vec::new();
    let mut misplaced: Vec<String> = Vec::new();

    for raw in unit.lines() {
        let line = raw.trim();
        if line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            current = line;
            continue;
        }
        let Some(rest) = line.strip_prefix(name) else {
            continue;
        };
        let Some(value) = rest.strip_prefix('=') else {
            continue;
        };
        if current == section {
            here.push(value.trim());
        } else {
            misplaced.push(format!("{current} {name}={}", value.trim()));
        }
    }

    assert!(
        misplaced.is_empty(),
        "{file} sets {name}= outside {section}, where systemd ignores it silently: {misplaced:?}. \
         A reader of this file and systemd would disagree about the supervision."
    );
    match here.as_slice() {
        [only] => (*only).to_owned(),
        [] => panic!(
            "{file} sets no {name}= in {section}, so the relation it carries is checked by nothing"
        ),
        many => panic!(
            "{file} sets {name}= in {section} {} times: {many:?}",
            many.len()
        ),
    }
}

/// A directive's value as a bare count of seconds.
///
/// systemd also accepts `30min` and `1h`. This reads the bare count and refuses every other form
/// rather than guessing at one: a unit written with a suffix is a unit this test cannot check, and
/// saying so is the only honest outcome. Teaching it the suffixes is a change to make deliberately,
/// with its own case.
fn seconds(unit: &str, file: &str, section: &str, name: &str) -> u64 {
    let raw = directive(unit, file, section, name);
    match raw.parse::<u64>() {
        Ok(secs) => secs,
        Err(_) => panic!(
            "{file} sets {name}={raw}, which is not a bare count of seconds. This test reads only \
             bare counts; it does not guess at a unit suffix."
        ),
    }
}

/// `WatchdogSec` has to outlast the longest the worker can go without feeding it.
///
/// **A necessary condition and not a sufficient one.** One observation makes a status call per epoch
/// carrying a receipt, so its cost grows with the backlog and no constant covers an arbitrary one —
/// which the worker unit states of itself. A unit failing this is wrong under any backlog, including
/// none. A unit passing it is not thereby adequate under a large one, and #251's soak is what
/// observes that.
#[test]
fn the_watchdog_outlasts_the_longest_the_worker_can_go_without_feeding_it() {
    let watchdog = Duration::from_secs(seconds(WORKER_UNIT, WORKER, "[Service]", "WatchdogSec"));
    let policy = WorkerPolicy::PRODUCTION;
    let quiet = policy.longest_quiet_cycle();
    assert!(
        watchdog > quiet,
        "{WORKER} sets WatchdogSec={}s, and this worker can go {}s without feeding it (poll {}s, \
         {} retries at a {}s timeout, and the backoff between them). A worker recovering as designed \
         would be killed on schedule. Raise WatchdogSec, or lower the policy.",
        watchdog.as_secs(),
        quiet.as_secs(),
        policy.poll_interval.as_secs(),
        policy.partition_retry_limit,
        policy.rpc_timeout.as_secs(),
    );
}

/// `WatchdogSec` is the grace `ProcessSilent` reports against, so the two have to be one number.
///
/// `alerts()` computes `ProcessSilent` from `heartbeat_grace` and the runbook tells an operator that
/// systemd's watchdog raises it. Diverge, and the runbook describes a grace nothing uses.
#[test]
fn the_watchdog_is_the_grace_the_runbook_names() {
    let watchdog = seconds(WORKER_UNIT, WORKER, "[Service]", "WatchdogSec");
    let grace = Thresholds::DEPLOYED.heartbeat_grace;
    assert_eq!(
        i64::try_from(watchdog).ok(),
        Some(grace),
        "{WORKER} sets WatchdogSec={watchdog}s and Thresholds::DEPLOYED.heartbeat_grace is {grace}s. \
         ProcessSilent is reported against one and enforced by the other."
    );
}

/// `StartLimitBurst` is the refusal count `Thresholds::DEPLOYED` claims.
///
/// H-95 (#300) stated as an assertion: the threshold the code carries has to be the threshold
/// something enforces. Above it the worker is abandoned later than the runbook says, below it
/// earlier, and in neither case does any file read as wrong.
#[test]
fn the_start_limit_is_the_refusal_count_the_thresholds_claim() {
    let burst = seconds(WORKER_UNIT, WORKER, "[Unit]", "StartLimitBurst");
    let refusals = Thresholds::DEPLOYED.consecutive_refusals;
    assert_eq!(
        u32::try_from(burst).ok(),
        Some(refusals),
        "{WORKER} sets StartLimitBurst={burst} and Thresholds::DEPLOYED.consecutive_refusals is \
         {refusals}. RepeatedRefusal is claimed against one and enforced by the other."
    );
}

/// The restarts have to fit inside the interval, or the limit is never reached.
///
/// `StartLimitBurst` failures spaced by `RestartSec` must fall inside `StartLimitIntervalSec`. If
/// they cannot, the start limit is never hit, the unit is restarted for ever, `Result` never becomes
/// `start-limit-hit`, and `certimining-alert@.service` is never entered — `RepeatedRefusal` raised by
/// nothing, with every directive individually plausible.
#[test]
fn the_restarts_fit_inside_the_interval_so_the_limit_can_be_reached() {
    let interval = seconds(WORKER_UNIT, WORKER, "[Unit]", "StartLimitIntervalSec");
    let burst = seconds(WORKER_UNIT, WORKER, "[Unit]", "StartLimitBurst");
    let delay = seconds(WORKER_UNIT, WORKER, "[Service]", "RestartSec");
    let span = delay.saturating_mul(burst);
    assert!(
        span < interval,
        "{WORKER} needs {burst} failures inside StartLimitIntervalSec={interval}s, and \
         RestartSec={delay}s spaces them over {span}s. The start limit would never be reached, so \
         Result would never be start-limit-hit and the alert unit would never be entered."
    );
}

/// The alert unit still gates on what systemd reports rather than on being called.
///
/// `OnFailure=` fires once on some systemd versions and on every auto-restart on others, so the alert
/// unit reads `Result` back and pages only on `start-limit-hit`. Without that gate it pages on the
/// first refusal while every file claims a threshold of three. The gate is one line, and deleting it
/// breaks nothing visible, which is why it is asserted here.
#[test]
fn the_alert_unit_pages_on_the_start_limit_rather_than_on_being_called() {
    let condition = directive(ALERT_UNIT, ALERT, "[Service]", "ExecCondition");
    assert!(
        condition.contains("start-limit-hit"),
        "{ALERT} must gate on Result=start-limit-hit, because how often OnFailure= fires is \
         version-dependent. Its ExecCondition= is {condition:?}."
    );
    assert!(
        condition.contains("-P Result"),
        "the gate has to read Result back from systemd rather than assume it: {condition:?}"
    );
}

/// The reader refuses what it cannot read, rather than passing on an absence.
///
/// Every assertion above is worth exactly as much as this: a parser that returned "not found" as
/// "satisfied" would turn each relation into an instrument that passes by looking at nothing, which
/// is the class of defect this file belongs to. The three ways it can fail to read are exercised
/// here against fixtures, because the committed units are the case where it finds everything.
#[test]
fn the_reader_refuses_an_absence_a_duplicate_and_a_misplaced_directive() {
    let absent = "[Service]\nType=notify\n";
    let panicked =
        std::panic::catch_unwind(|| directive(absent, "fixture", "[Service]", "WatchdogSec"));
    assert!(panicked.is_err(), "a directive that is not set must fail");

    let twice = "[Service]\nWatchdogSec=1800\nWatchdogSec=60\n";
    let panicked =
        std::panic::catch_unwind(|| directive(twice, "fixture", "[Service]", "WatchdogSec"));
    assert!(panicked.is_err(), "a directive set twice must fail");

    // The one that matters: systemd would ignore this and the supervision would be unenforced.
    let misplaced = "[Unit]\nDescription=x\n[Service]\nStartLimitBurst=3\n";
    let panicked =
        std::panic::catch_unwind(|| directive(misplaced, "fixture", "[Unit]", "StartLimitBurst"));
    assert!(
        panicked.is_err(),
        "StartLimitBurst in [Service] is ignored by systemd, so finding it there must fail"
    );

    // And prose naming a directive does not set it.
    let commented = "[Service]\n# WatchdogSec=1800 is what we want\nType=notify\n";
    let panicked =
        std::panic::catch_unwind(|| directive(commented, "fixture", "[Service]", "WatchdogSec"));
    assert!(
        panicked.is_err(),
        "a comment mentioning a directive must not satisfy it"
    );
}
