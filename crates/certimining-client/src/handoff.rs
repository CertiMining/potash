// SPDX-License-Identifier: MIT OR Apache-2.0
//! The batcher's signed handoff, as the worker reads it (D-139, D-140, H-13).
//!
//! **What this exists to stop.** D-139 keeps `k_master` out of the worker, so the worker does not
//! build a root — it is given one. A process that refuses to invent a root but reads one from a file
//! has moved the question rather than answered it: whatever can write that file chooses what the log
//! publishes. The signature is what makes inducing a publication require the batcher's key instead of
//! a path.
//!
//! **Signed over the preimage, not its digest.** The preimage is 49 bytes (`HandoffPreimage`), small
//! enough to sign whole, and a verifier that reconstructs the fields then verifies exactly the bytes
//! it reconstructed — with no intermediate digest to compute differently. §1.6's promise signs a
//! digest instead and `docs/promises.md` names that as the one place it differs from a record's
//! attestation; this follows the attestation.
//!
//! **The key the artifact carries is not the authority.** `verify` takes the key the worker was
//! configured with and compares it first, the way `verify_promise` does: anyone can sign a handoff,
//! and the carried key only shows which key signed this one.

use certimining_core::{Digest, HandoffPreimage, Preimage, PreimageBuf, Verifier};

use crate::schedule::{build_start, Schedule};
use crate::worker::{day_index, WorkerPolicy};

/// The transferable artifact: D-139's three fields, the key that signed them, and the signature.
///
/// Fixed width throughout, so [`Handoff::decode`] accepts exactly one length and a truncated or
/// padded file is refused rather than read as something.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Handoff {
    /// The epoch the root is for, a UTC day index (§1.4).
    pub epoch: u64,
    /// The tree height the root was built at, which §1.8 bounds to `[4, 16]`.
    pub height: u8,
    /// The epoch root, as the batcher built it.
    pub root: Digest,
    /// The public half of the key that signed, which shows *which* key signed and authorises nothing.
    pub batcher_key: [u8; 32],
    /// Ed25519 over the 49-byte preimage.
    pub signature: [u8; 64],
}

/// The encoded length: 8 epoch, 1 height, 32 root, 32 key, 64 signature.
pub const HANDOFF_LEN: usize = 137;

/// §1.8's bounds on the tree height, repeated here because a handoff naming a height outside them
/// describes a tree this log cannot have built.
const HEIGHT_RANGE: core::ops::RangeInclusive<u8> = 4..=16;

/// Why a handoff was refused, before anything was published.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandoffRefused {
    /// Not exactly [`HANDOFF_LEN`] bytes. Every field is fixed width, so a wrong length is a wrong
    /// file rather than a field to parse leniently.
    WrongLength { found: usize },
    /// The handoff was signed by a key the worker was not configured to accept.
    UnexpectedKey,
    /// The signature does not verify over the preimage the fields reconstruct.
    BadSignature,
    /// The height is outside §1.8's `[4, 16]`.
    HeightOutOfRange { height: u8 },
    /// The epoch is one the worker was not asked about, which means the file on disk is not the one
    /// the worker is acting on.
    WrongEpoch { found: u64, wanted: u64 },
}

impl Handoff {
    /// The 49 bytes the signature covers.
    fn preimage(&self) -> Result<PreimageBuf, HandoffRefused> {
        let mut buf = PreimageBuf::new();
        HandoffPreimage {
            epoch: self.epoch,
            height: self.height,
            root: self.root,
        }
        .write_preimage(&mut buf)
        .map_err(|_| HandoffRefused::HeightOutOfRange {
            height: self.height,
        })?;
        Ok(buf)
    }

    /// Writes the artifact. The order is the struct's, and [`decode`](Self::decode) reads it back.
    pub fn encode(&self) -> [u8; HANDOFF_LEN] {
        let mut out = [0u8; HANDOFF_LEN];
        let mut at = 0usize;
        let mut put = |bytes: &[u8]| {
            if let Some(slot) = out.get_mut(at..at.saturating_add(bytes.len())) {
                slot.copy_from_slice(bytes);
            }
            at = at.saturating_add(bytes.len());
        };
        put(&self.epoch.to_le_bytes());
        put(&[self.height]);
        put(&self.root);
        put(&self.batcher_key);
        put(&self.signature);
        out
    }

    /// Reads the artifact. Length is checked first and exactly: nothing here parses a prefix.
    pub fn decode(bytes: &[u8]) -> Result<Self, HandoffRefused> {
        if bytes.len() != HANDOFF_LEN {
            return Err(HandoffRefused::WrongLength { found: bytes.len() });
        }
        let field = |from: usize, to: usize| bytes.get(from..to);
        let epoch = field(0, 8)
            .and_then(|b| <[u8; 8]>::try_from(b).ok())
            .map(u64::from_le_bytes)
            .ok_or(HandoffRefused::WrongLength { found: bytes.len() })?;
        let height = *bytes
            .get(8)
            .ok_or(HandoffRefused::WrongLength { found: bytes.len() })?;
        let root = field(9, 41)
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .ok_or(HandoffRefused::WrongLength { found: bytes.len() })?;
        let batcher_key = field(41, 73)
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .ok_or(HandoffRefused::WrongLength { found: bytes.len() })?;
        let signature = field(73, 137)
            .and_then(|b| <[u8; 64]>::try_from(b).ok())
            .ok_or(HandoffRefused::WrongLength { found: bytes.len() })?;
        Ok(Self {
            epoch,
            height,
            root,
            batcher_key,
            signature,
        })
    }

    /// The root this handoff carries, once it has earned being believed.
    ///
    /// Checks, in this order: the key is the one the worker expects; the height is one §1.8 allows;
    /// the epoch is the one the worker is acting on; and the signature verifies over the preimage the
    /// fields reconstruct. The key is first for the reason `verify_promise` puts it first — a
    /// signature by the wrong key is not a failed signature, it is a different author.
    pub fn verify<V: Verifier>(
        &self,
        expected_batcher_key: &[u8; 32],
        wanted_epoch: u64,
    ) -> Result<Digest, HandoffRefused> {
        if &self.batcher_key != expected_batcher_key {
            return Err(HandoffRefused::UnexpectedKey);
        }
        if !HEIGHT_RANGE.contains(&self.height) {
            return Err(HandoffRefused::HeightOutOfRange {
                height: self.height,
            });
        }
        if self.epoch != wanted_epoch {
            return Err(HandoffRefused::WrongEpoch {
                found: self.epoch,
                wanted: wanted_epoch,
            });
        }
        let preimage = self.preimage()?;
        V::verify(&self.batcher_key, preimage.as_bytes(), &self.signature)
            .map_err(|_| HandoffRefused::BadSignature)?;
        Ok(self.root)
    }
}

/// Why the batcher refused to write a handoff, before any key was used (H-13, D-117).
///
/// These are the two decisions the writing process makes, kept here and pure because this crate's
/// rule is that a binary performs and does not decide (D-84): a decision tested only by running a
/// process against a cluster is a decision nothing checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandoffWriteRefused {
    /// The epoch is ahead of the chain's own day index, which `publish_checkpoint` refuses anyway.
    ///
    /// **Refused here so it costs nothing rather than a transaction.** v0.2.4 bounds the program to
    /// the calendar (H-11), so a handoff for tomorrow is a root the worker would carry to a refusal.
    EpochAheadOfToday { epoch: u64, today: u64 },
    /// A handoff for this epoch is already on disk and says something else.
    ///
    /// **Not an overwrite, because the worker may already have acted on it.** A second handoff for one
    /// epoch is either a different root — in which case one of the two is wrong and a process should
    /// not pick — or the same bytes, which is a re-run and allowed.
    AlreadyWrittenDifferently { epoch: u64 },
    /// The epoch's scheduled build has not started yet (H-100, issue #309).
    ///
    /// **The barrier that stops a day being frozen while it is still happening.** `Schedule::DEPLOYED`
    /// puts an epoch's build ten minutes before its publication, which is fifty minutes after the
    /// epoch ends. Before this existed the only calendar barrier was `epoch > today`, so the batcher
    /// could build and sign epoch `d` at any point *during* day `d` — before the rest of that day's
    /// submissions had arrived. The handoff is immutable once written, so a later correct root for the
    /// same epoch is refused as a disagreement, and the worker publishes the prematurely frozen one on
    /// schedule. Records that were going to be timely are dropped with no on-chain repair path.
    ///
    /// The schedule was committed, re-exported and tested, and reached no executable: `build_start`'s
    /// only callers were in `tests/schedule.rs`. This refusal is that policy on the path the
    /// deployment runs.
    BeforeBuildStart { epoch: u64, now: i64, start: i64 },
    /// The clock given has no UTC day index, so no calendar barrier can be applied.
    ///
    /// Refused rather than passed: a barrier that cannot be evaluated must not read as satisfied.
    UndatableClock { now: i64 },
    /// The epoch is older than the worker would ever publish it (H-100, issue #309).
    ///
    /// **The upper bound, derived rather than chosen (owner's ruling).** The lower barrier stops an
    /// epoch being frozen before it has finished; this stops one being built so late that the worker
    /// would refuse to publish it anyway. `WorkerPolicy::max_epoch_slip` is how far behind the log may
    /// fall before an unattended worker stops and asks for a ruling, so an epoch may be built on the
    /// day after it ends and for `max_epoch_slip` days after that, and no longer.
    ///
    /// The number comes from the worker's own committed policy and is not set separately here. A bound
    /// written independently would be a second statement of the same quantity with nothing comparing
    /// them, which is the defect class this issue belongs to — and it would let the batcher produce a
    /// handoff the worker is guaranteed to refuse.
    PastTheSlipAllowance {
        epoch: u64,
        today: u64,
        latest_day: u64,
    },
    /// The epoch has no build start under this schedule, so the barrier cannot be applied to it.
    ///
    /// Distinct from `UndatableClock` deliberately. One is a fault in the clock and the other in the
    /// epoch asked for, and reporting either as the other is the conflation H-97 (#304) was about.
    Unschedulable { epoch: u64 },
}

/// Whether the batcher may write this handoff.
///
/// `now` is the caller's clock in Unix seconds and `existing` whatever is already at the destination.
///
/// **It takes `now` and derives the day itself, where it used to take `today`.** The caller passed
/// both a clock and a day index computed from it, and nothing checked that the two agreed — the same
/// conflation M-04 of the 1 November audit names in `Observed`. Derived here, they cannot disagree.
///
/// Four barriers, in order, each refusing for its own reason: an epoch ahead of the calendar, an
/// epoch whose scheduled build has not started, an epoch older than the worker's slip allowance, and
/// a disagreement with what is already on disk. Byte-identical content is a re-run and stays
/// permitted at any time — a replay of what is already there writes nothing and is not bounded.
pub fn refuse_to_write(
    schedule: Schedule,
    policy: WorkerPolicy,
    epoch: u64,
    now: i64,
    existing: Option<&[u8]>,
    bytes: &[u8; HANDOFF_LEN],
) -> Result<(), HandoffWriteRefused> {
    // **An exact re-run is permitted before any calendar barrier is consulted.** Writing the bytes
    // that are already there changes nothing on disk, and the epoch was accepted when the file was
    // first written. Putting this after the barriers would make whether a retry succeeds depend on
    // how long the operator took to retry, which is not a property of the thing being retried.
    if existing == Some(bytes.as_slice()) {
        return Ok(());
    }

    let Some(today) = day_index(now) else {
        return Err(HandoffWriteRefused::UndatableClock { now });
    };
    if epoch > today {
        return Err(HandoffWriteRefused::EpochAheadOfToday { epoch, today });
    }
    let Some(start) = build_start(schedule, epoch) else {
        return Err(HandoffWriteRefused::Unschedulable { epoch });
    };
    if now < start {
        return Err(HandoffWriteRefused::BeforeBuildStart { epoch, now, start });
    }

    // **The upper bound is the worker's own last publishable day (M-08, issue #333).** This read
    // `epoch + 1 + max_epoch_slip`, which is one day looser: the worker counts its allowance from
    // the publishable frontier, and the frontier is already a day behind the calendar, so the `+ 1`
    // was applied twice. An audit asked the two components about the same epoch on the same days and
    // found day `epoch + 2` writable here and refused there — an immutable signed handoff nothing
    // could publish.
    //
    // The quantity now exists once, in `WorkerPolicy::last_publishable_day`, which the worker's slip
    // barrier reads as well. Two statements of one number with nothing comparing them is what
    // produced this, and the cross-component test below is what compares them now.
    let latest_day = policy.last_publishable_day(epoch);
    if today > latest_day {
        return Err(HandoffWriteRefused::PastTheSlipAllowance {
            epoch,
            today,
            latest_day,
        });
    }

    // Anything still on disk at this point differs from what is being written, since the identical
    // case returned above.
    match existing {
        Some(_) => Err(HandoffWriteRefused::AlreadyWrittenDifferently { epoch }),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use certimining_core::DalekVerifier;
    use ed25519_dalek::{Signer as _, SigningKey};

    const ROOT: Digest = [0x5a; 32];

    fn batcher(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn signed_by(key: &SigningKey, epoch: u64, height: u8, root: Digest) -> Handoff {
        let mut buf = PreimageBuf::new();
        match (HandoffPreimage {
            epoch,
            height,
            root,
        })
        .write_preimage(&mut buf)
        {
            Ok(()) => {}
            Err(e) => panic!("the test's own preimage does not encode: {e:?}"),
        }
        Handoff {
            epoch,
            height,
            root,
            batcher_key: key.verifying_key().to_bytes(),
            signature: key.sign(buf.as_bytes()).to_bytes(),
        }
    }

    #[test]
    fn a_handoff_signed_by_the_expected_key_yields_its_root() {
        let k = batcher(1);
        let h = signed_by(&k, 20_739, 8, ROOT);
        assert_eq!(
            h.verify::<DalekVerifier>(&k.verifying_key().to_bytes(), 20_739),
            Ok(ROOT)
        );
    }

    /// **The key the artifact carries is not the authority.** Anyone can sign a handoff.
    #[test]
    fn a_handoff_signed_by_another_key_is_refused_even_though_its_signature_is_good() {
        let theirs = batcher(2);
        let h = signed_by(&theirs, 20_739, 8, ROOT);
        assert_eq!(
            h.verify::<DalekVerifier>(&batcher(1).verifying_key().to_bytes(), 20_739),
            Err(HandoffRefused::UnexpectedKey),
            "the signature verifies against the key in the file, which is the point: the worker \
             compares against the key it was configured with"
        );
    }

    #[test]
    fn one_changed_byte_in_the_root_breaks_the_signature() {
        let k = batcher(1);
        let mut h = signed_by(&k, 20_739, 8, ROOT);
        h.root[0] ^= 1;
        assert_eq!(
            h.verify::<DalekVerifier>(&k.verifying_key().to_bytes(), 20_739),
            Err(HandoffRefused::BadSignature)
        );
    }

    /// The epoch is signed, so moving a valid handoff to another day is not a replay.
    #[test]
    fn a_handoff_for_another_epoch_is_refused() {
        let k = batcher(1);
        let h = signed_by(&k, 20_739, 8, ROOT);
        assert_eq!(
            h.verify::<DalekVerifier>(&k.verifying_key().to_bytes(), 20_740),
            Err(HandoffRefused::WrongEpoch {
                found: 20_739,
                wanted: 20_740
            })
        );
    }

    #[test]
    fn a_height_outside_1_8s_range_is_refused_before_the_signature_is_checked() {
        let k = batcher(1);
        let h = signed_by(&k, 20_739, 3, ROOT);
        assert_eq!(
            h.verify::<DalekVerifier>(&k.verifying_key().to_bytes(), 20_739),
            Err(HandoffRefused::HeightOutOfRange { height: 3 }),
            "a handoff naming a height this log cannot have built is refused whoever signed it"
        );
    }

    #[test]
    fn encode_and_decode_round_trip() {
        let k = batcher(1);
        let h = signed_by(&k, 20_739, 8, ROOT);
        let bytes = h.encode();
        assert_eq!(bytes.len(), 137, "8 + 1 + 32 + 32 + 64");
        assert_eq!(Handoff::decode(&bytes), Ok(h));
    }

    /// Every field is fixed width, so a short or long file is a wrong file.
    #[test]
    fn a_file_of_the_wrong_length_is_refused_rather_than_parsed() {
        let k = batcher(1);
        let bytes = signed_by(&k, 20_739, 8, ROOT).encode();
        for len in [0usize, 1, 136] {
            assert_eq!(
                Handoff::decode(bytes.get(..len).unwrap_or_default()),
                Err(HandoffRefused::WrongLength { found: len })
            );
        }
        let mut long = bytes.to_vec();
        long.push(0);
        assert_eq!(
            Handoff::decode(&long),
            Err(HandoffRefused::WrongLength { found: 138 })
        );
    }

    /// The decoded artifact is what was signed: a byte flipped anywhere in the encoding either fails
    /// to decode or fails to verify, never decodes into something that passes.
    #[test]
    fn no_single_flipped_byte_survives_verification() {
        let k = batcher(1);
        let expected = k.verifying_key().to_bytes();
        let bytes = signed_by(&k, 20_739, 8, ROOT).encode();
        for i in 0..HANDOFF_LEN {
            let mut broken = bytes;
            match broken.get_mut(i) {
                Some(b) => *b ^= 1,
                None => panic!("index {i} is inside a {HANDOFF_LEN}-byte array"),
            }
            let verdict =
                Handoff::decode(&broken).and_then(|h| h.verify::<DalekVerifier>(&expected, 20_739));
            assert!(
                verdict.is_err(),
                "byte {i} was flipped and the handoff still verified"
            );
        }
    }
}

#[cfg(test)]
mod writing {
    use super::*;

    fn bytes(fill: u8) -> [u8; HANDOFF_LEN] {
        [fill; HANDOFF_LEN]
    }

    const S: Schedule = Schedule::DEPLOYED;
    const P: WorkerPolicy = WorkerPolicy::PRODUCTION;

    /// Midday on a UTC day, so the barriers are read against a clock and not a day number.
    fn noon(day: u64) -> i64 {
        match i64::try_from(day) {
            Ok(d) => d.saturating_mul(86_400).saturating_add(43_200),
            Err(_) => panic!("day {day} is beyond i64, so the test states nothing"),
        }
    }

    fn built(epoch: u64) -> i64 {
        match build_start(S, epoch) {
            Some(t) => t,
            None => panic!("epoch {epoch} has no build start, so the test states nothing"),
        }
    }

    #[test]
    fn an_epoch_ahead_of_today_is_refused_before_a_key_is_touched() {
        assert_eq!(
            refuse_to_write(S, P, 20_739, noon(20_738), None, &bytes(1)),
            Err(HandoffWriteRefused::EpochAheadOfToday {
                epoch: 20_739,
                today: 20_738
            }),
            "v0.2.4 bounds publish_checkpoint to the calendar, so this would cost a transaction to \
             learn on chain"
        );
    }

    /// **The defect H-100 (issue #309) was filed for, and the assertion that used to say otherwise.**
    ///
    /// This test read `today_and_any_earlier_epoch_are_allowed` and asserted that building the
    /// current day was fine. It is not: the rest of today's submissions have not arrived, the handoff
    /// is immutable once written, and the worker publishes it on schedule. An epoch becomes buildable
    /// fifty minutes after it ends, which is what the committed schedule has always said and what
    /// nothing on the executable path enforced.
    #[test]
    fn the_current_day_is_refused_because_it_has_not_finished() {
        let now = noon(20_738);
        assert_eq!(
            refuse_to_write(S, P, 20_738, now, None, &bytes(1)),
            Err(HandoffWriteRefused::BeforeBuildStart {
                epoch: 20_738,
                now,
                start: built(20_738)
            }),
            "epoch 20738 is still accepting submissions at midday on day 20738"
        );
    }

    /// **Catching up works inside the slip allowance and not beyond it (owner's ruling on #309).**
    ///
    /// This test asserted that any earlier epoch was allowed, which was true before the upper bound
    /// and is not now. The allowance is `WorkerPolicy::max_epoch_slip`, the same number the worker
    /// uses before it stops and asks for a ruling, so the two components permit exactly the same
    /// window: the batcher cannot produce a handoff the worker is guaranteed to refuse.
    ///
    /// An epoch missed by more than the allowance needs an operator either way. What it no longer
    /// gets is an unattended build whose root nothing will publish.
    #[test]
    fn an_epoch_the_batcher_is_catching_up_on_is_allowed_inside_the_allowance() {
        // **Under PRODUCTION there is no catch-up day, which this test used to claim (M-08, #333).**
        // `max_epoch_slip` of one is spent on the ordinary lag: epoch `e` publishes in day `e + 1`,
        // so on day `e + 2` the worker's slip is already two and it refuses. The day this asserted,
        // `e + 2`, is exactly the one the audit found writable and unusable. Catching up needs a
        // policy that allows it, so the test states the policy rather than a day.
        let roomy = WorkerPolicy {
            max_epoch_slip: 2,
            ..WorkerPolicy::PRODUCTION
        };
        let epoch: u64 = 20_700;
        let one_day_late = epoch.saturating_add(2);
        assert_eq!(one_day_late, roomy.last_publishable_day(epoch));
        assert_eq!(
            refuse_to_write(S, roomy, epoch, noon(one_day_late), None, &bytes(1)),
            Ok(()),
            "with an allowance of two, a day late is past the build start and inside it"
        );
        assert_eq!(
            refuse_to_write(S, P, epoch, noon(one_day_late), None, &bytes(1)),
            Err(HandoffWriteRefused::PastTheSlipAllowance {
                epoch,
                today: one_day_late,
                latest_day: P.last_publishable_day(epoch),
            }),
            "and with PRODUCTION's allowance of one it is past it, because the worker refuses it"
        );
    }

    /// The boundary itself, in both directions, one second apart.
    #[test]
    fn the_second_before_the_build_start_is_refused_and_the_build_start_is_not() {
        let start = built(20_737);
        assert_eq!(
            refuse_to_write(S, P, 20_737, start.saturating_sub(1), None, &bytes(1)),
            Err(HandoffWriteRefused::BeforeBuildStart {
                epoch: 20_737,
                now: start.saturating_sub(1),
                start
            })
        );
        assert_eq!(
            refuse_to_write(S, P, 20_737, start, None, &bytes(1)),
            Ok(()),
            "the schedule names this instant as the build start, so it is not too early"
        );
    }

    /// A barrier that cannot be evaluated refuses, rather than reading as satisfied.
    #[test]
    fn a_clock_with_no_day_index_is_refused_rather_than_waved_through() {
        assert_eq!(
            refuse_to_write(S, P, 20_737, -1, None, &bytes(1)),
            Err(HandoffWriteRefused::UndatableClock { now: -1 })
        );
    }

    /// **A re-run is allowed and a disagreement is not.** The worker may already have acted on what
    /// is there.
    #[test]
    fn the_same_handoff_may_be_rewritten_and_a_different_one_may_not() {
        let same = bytes(7);
        assert_eq!(
            refuse_to_write(S, P, 20_737, noon(20_738), Some(same.as_slice()), &same),
            Ok(()),
            "identical bytes are a re-run, which has no effect and no risk"
        );
        assert_eq!(
            refuse_to_write(S, P, 20_737, noon(20_738), Some(bytes(8).as_slice()), &same),
            Err(HandoffWriteRefused::AlreadyWrittenDifferently { epoch: 20_737 }),
            "two different roots for one epoch is a question a process must not answer"
        );
    }

    /// A file of the wrong length is still a disagreement, not something to parse first.
    #[test]
    fn a_truncated_file_on_disk_counts_as_a_disagreement() {
        assert_eq!(
            refuse_to_write(S, P, 20_737, noon(20_738), Some(&[7u8; 10]), &bytes(7)),
            Err(HandoffWriteRefused::AlreadyWrittenDifferently { epoch: 20_737 })
        );
    }

    /// **Both edges of the upper bound, which is the owner's ruling on #309.**
    ///
    /// `max_epoch_slip` is 1 under `WorkerPolicy::PRODUCTION`, so an epoch may be built on the day
    /// after it ends and on one further day. The day after that, the worker would refuse to publish
    /// the result, so building it writes an immutable file nothing can use.
    ///
    /// The bound is read off the policy rather than written here, so if `max_epoch_slip` changes this
    /// test moves with it instead of contradicting it.
    #[test]
    fn the_last_day_of_the_slip_allowance_is_allowed_and_the_next_is_not() {
        let epoch: u64 = 20_737;
        let latest = P.last_publishable_day(epoch);

        assert_eq!(
            refuse_to_write(S, P, epoch, noon(latest), None, &bytes(1)),
            Ok(()),
            "day {latest} is the last day this bound permits for epoch {epoch}. That it is also the \
             last day the worker can publish it is what the cross-component test below compares"
        );
        let too_late = latest.saturating_add(1);
        assert_eq!(
            refuse_to_write(S, P, epoch, noon(too_late), None, &bytes(1)),
            Err(HandoffWriteRefused::PastTheSlipAllowance {
                epoch,
                today: too_late,
                latest_day: latest,
            }),
            "past the allowance the worker refuses to publish, so the batcher must not build"
        );
    }

    /// **Every day the batcher will write is a day the worker can still publish (M-08, issue #333;
    /// owner's ruling of 2 November 2026).**
    ///
    /// The test above pins this bound against itself, which is what let it be a day out: its own
    /// message claimed the day was "the last on which the worker would still publish" while asking
    /// only the batcher. This asks both components about the same epoch on the same days, so the
    /// sentence is checked rather than asserted.
    #[test]
    fn every_writable_day_is_a_day_the_worker_can_still_publish() {
        use crate::worker::{next_step_with_policy, Observed, Step};
        let epoch: u64 = 20_737;
        let mut writable = 0usize;
        // Several allowances, so the agreement is a property of the shared function and not of
        // PRODUCTION's particular number.
        for slip in 0u64..=3 {
            let policy = WorkerPolicy {
                max_epoch_slip: slip,
                ..WorkerPolicy::PRODUCTION
            };
            for day in epoch..=epoch.saturating_add(6) {
                let now = noon(day);
                if refuse_to_write(S, policy, epoch, now, None, &bytes(1)).is_err() {
                    continue;
                }
                writable = writable.saturating_add(1);
                // A log that has published everything before `epoch`, so `epoch` is its candidate.
                let last_epoch = epoch.saturating_sub(1);
                let observed = Observed {
                    now,
                    start_epoch: last_epoch,
                    last_epoch,
                    awaiting_attach: None,
                    last_submitted: Some(last_epoch),
                    oldest_single: None,
                };
                assert_eq!(
                    next_step_with_policy(S, &observed, policy, crate::Thresholds::DEPLOYED),
                    Step::Publish { epoch },
                    "day {day} is writable under an allowance of {slip}, so the worker must still \
                     select epoch {epoch}"
                );
            }
        }
        assert!(
            writable > 0,
            "no day in the window was writable, so this compares nothing"
        );
    }

    /// An exact re-run is not bounded by the clock, which the barriers above are.
    ///
    /// A retry that would write the bytes already on disk changes nothing. Refusing it past the
    /// allowance would make whether a retry succeeds depend on how long the operator took to retry.
    #[test]
    fn an_identical_rerun_is_allowed_even_past_every_calendar_barrier() {
        let same = bytes(7);
        assert_eq!(
            refuse_to_write(S, P, 20_737, noon(30_000), Some(same.as_slice()), &same),
            Ok(()),
            "writing what is already there is a no-op at any time"
        );
        // The differing case is checked inside the window, so that it is answered as a
        // disagreement rather than by whichever calendar barrier happens to come first.
        assert_eq!(
            refuse_to_write(S, P, 20_737, noon(20_738), Some(bytes(8).as_slice()), &same),
            Err(HandoffWriteRefused::AlreadyWrittenDifferently { epoch: 20_737 }),
            "a differing root is refused as a disagreement, not as a late build"
        );
        // And past the window a differing write is refused by the bound, which is the earlier
        // barrier. Stated rather than left implicit: the order of the refusals is observable.
        assert_eq!(
            refuse_to_write(S, P, 20_737, noon(30_000), Some(bytes(8).as_slice()), &same),
            Err(HandoffWriteRefused::PastTheSlipAllowance {
                epoch: 20_737,
                today: 30_000,
                latest_day: P.last_publishable_day(20_737),
            })
        );
    }
    /// **The arm nothing reached (H-104, issue #322).** `Unschedulable` was constructed in one place
    /// and named by no test, so its fields and its distinction from `UndatableClock` were asserted by
    /// nothing. An arm that has never executed is not known to report what it claims to.
    ///
    /// The one way in is the schedule's own arithmetic. `publication_time` multiplies the epoch by a
    /// day and adds another, so it leaves `i64` at day index 106_751_991_167_300; `day_index` accepts
    /// any non-negative `i64`, so a clock can report that day, and an epoch equal to the day clears
    /// the barrier above it. The clock is absurd and the boundary is not — it is what the `checked_mul`
    /// in `publication_time` exists for, and this is the only state that reaches past it.
    #[test]
    fn an_epoch_the_schedule_cannot_place_is_refused_as_its_own_fault() {
        let today = match day_index(i64::MAX) {
            Some(d) => d,
            None => panic!("i64::MAX falls in some UTC day"),
        };
        // Derived, not assumed: if the frontier ever moves, this fails here rather than quietly
        // asserting a different arm.
        assert_eq!(
            build_start(S, today),
            None,
            "day {today} must be the unschedulable one or the test states nothing"
        );
        assert_eq!(
            refuse_to_write(S, P, today, i64::MAX, None, &bytes(1)),
            Err(HandoffWriteRefused::Unschedulable { epoch: today }),
            "an epoch the schedule cannot place is a fault in the epoch asked for, not in the clock"
        );
    }
}
