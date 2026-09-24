//! E-09: the publication schedule (§1.5, INV-ANCH-01, D-83).
//!
//! The property under test is that publication time is a function of the epoch and of nothing else.
//! These are pure functions, so the calendar is an input and there is no clock to make flaky.

use certimining_client::{build_start, publication_time, Schedule, EPOCH_SECONDS};

const S: Schedule = Schedule::DEPLOYED;

#[test]
fn every_epoch_publishes_exactly_one_epoch_after_the_last() {
    let mut previous = publication_time(S, 20_000).expect("a time");
    for epoch in 20_001..20_050u64 {
        let now = publication_time(S, epoch).expect("a time");
        assert_eq!(
            now - previous,
            EPOCH_SECONDS,
            "INV-ANCH-01: the cadence is the schedule's, at epoch {epoch}"
        );
        previous = now;
    }
}

#[test]
fn the_build_starts_a_constant_distance_before_publication() {
    // A lead that tracked the record count would publish the count. It is constant, and that is the
    // property rather than its size.
    for epoch in [0u64, 1, 20_361, 999_999] {
        let publish = publication_time(S, epoch).expect("a time");
        let start = build_start(S, epoch).expect("a time");
        assert_eq!(publish - start, S.build_lead, "at epoch {epoch}");
    }
}

#[test]
fn the_schedule_gives_a_full_tree_four_orders_of_magnitude_of_headroom() {
    // §4.4a bounds a 256-leaf build at 10 ms, and E-06 measured 201 µs in release. The lead is ten
    // minutes, so the margin is not a guess about one machine.
    // Constants, so the compiler checks them: a schedule that lost its headroom would not build.
    const _: () = assert!(Schedule::DEPLOYED.build_lead >= 600);
    const _: () = assert!(Schedule::DEPLOYED.publish_offset > Schedule::DEPLOYED.build_lead);

    // And the figure the headroom is measured against, which is §4.4a's threshold in milliseconds.
    let build_budget_ms = 10i64;
    assert!(
        S.build_lead * 1_000 > build_budget_ms * 1_000,
        "the lead must exceed the build §4.4a allows, by a margin no machine can erase"
    );
}

#[test]
fn an_epoch_at_the_far_end_of_the_calendar_returns_none_rather_than_wrapping() {
    assert_eq!(publication_time(S, u64::MAX), None);
    assert_eq!(build_start(S, u64::MAX), None);
    assert!(
        publication_time(S, 3_000_000).is_some(),
        "year 8200 is fine"
    );
}
