// SPDX-License-Identifier: MIT OR Apache-2.0
//! The publication schedule (§1.5, D-83).
//!
//! INV-ANCH-01 requires a checkpoint every epoch, empty ones included, at a publication time the
//! schedule fixes rather than the build. The functions here are pure: they take an epoch and return a
//! time, so the service that waits owns the clock and the tests own the calendar.

/// An epoch is a UTC day (§1.4).
pub const EPOCH_SECONDS: i64 = 86_400;

/// When each epoch is published, and how long before that its tree starts building.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Schedule {
    /// Seconds after the epoch's own boundary at which its checkpoint is submitted.
    pub publish_offset: i64,
    /// Seconds before that at which the build starts, chosen so a full tree finishes in time.
    pub build_lead: i64,
}

impl Schedule {
    /// The deployment's schedule: an epoch's checkpoint is submitted an hour after the epoch ends,
    /// and its tree starts building ten minutes before that.
    ///
    /// The lead is not a guess about one machine: §4.4a bounds a 256-leaf build at 10 ms, so ten
    /// minutes is four orders of magnitude of headroom. What matters is not the size of the lead but
    /// that it is constant, because a lead that tracked the record count would publish the count.
    pub const DEPLOYED: Self = Self {
        publish_offset: 3_600,
        build_lead: 600,
    };
}

/// The Unix time at which `epoch`'s checkpoint is submitted.
///
/// A function of the epoch and nothing else. Two epochs holding one record and two hundred are
/// submitted the same distance apart, whatever either took to build.
pub fn publication_time(schedule: Schedule, epoch: u64) -> Option<i64> {
    let start = i64::try_from(epoch)
        .ok()?
        .checked_mul(EPOCH_SECONDS)?
        .checked_add(EPOCH_SECONDS)?;
    start.checked_add(schedule.publish_offset)
}

/// When `epoch`'s tree starts building, which is a constant distance before its publication.
pub fn build_start(schedule: Schedule, epoch: u64) -> Option<i64> {
    publication_time(schedule, epoch)?.checked_sub(schedule.build_lead)
}
