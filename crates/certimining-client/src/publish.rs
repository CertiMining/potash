// SPDX-License-Identifier: MIT OR Apache-2.0
//! Submitting a checkpoint, and deciding what its outcome means (§1.5, issue #9).
//!
//! The decision is separated from the network on purpose. What a client should do about a failed
//! submission is a property worth testing, and it is not testable if it only exists inside a call to
//! a cluster.

use certimining_core::Digest;

/// What a submission's outcome means for the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The transaction landed and the checkpoint is written.
    Landed,
    /// The epoch already has a checkpoint. A retry that arrives after the first attempt landed sees
    /// this, and it is success rather than failure: the root is on chain, which is all the caller
    /// wanted. Treating it as an error would make a retry look like a fault and invite a client to
    /// publish twice.
    AlreadyPublished,
    /// Nothing landed and the same transaction may be sent again. A blockhash that expired or an RPC
    /// that did not answer are the ordinary cases.
    Retry,
    /// The program refused for a reason resending cannot change.
    Refused(u32),
}

/// §2.1's codes as the chain reports them.
const ANCHOR_OFFSET: u32 = 6000;
/// `0x0E`, this epoch's checkpoint is already written.
pub const CHECKPOINT_ALREADY_WRITTEN: u32 = ANCHOR_OFFSET + 0x0E;

/// What an outcome means, given the program's own error code if it produced one.
///
/// `None` is a submission that did not reach the program: nothing was written, so sending it again is
/// safe. Everything the program itself refused is final, because the same transaction will be refused
/// the same way — except the one case where the refusal means the work is already done.
pub fn classify(program_error: Option<u32>) -> Outcome {
    match program_error {
        None => Outcome::Retry,
        Some(CHECKPOINT_ALREADY_WRITTEN) => Outcome::AlreadyPublished,
        Some(code) => Outcome::Refused(code),
    }
}

/// What `AlreadyPublished` turns out to mean once the caller has read the epoch back.
///
/// Codex round one, finding 2. `classify` sees an error code and nothing else, so it cannot tell a
/// retry that arrived late from an epoch that already carries somebody else's root. Treating `0x0E`
/// as success on its own is therefore a decision made without the one fact that decides it, and a
/// client that stopped there would report a successful publication of a root that is not on the
/// chain (D-108).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Settlement {
    /// The epoch carries the root that was submitted. The retry arrived after the first attempt
    /// landed, which is the ordinary case and is success.
    Matches,
    /// The epoch carries a different root. Two roots exist for one epoch, which is the condition
    /// INV-ANCH-06 is about, and no client should report it as a successful publication.
    Equivocation { on_chain: Digest },
    /// The program said the epoch was already written and nothing usable is there. A client cannot
    /// assume the program it is talking to carries D-104's fix, so this stays reachable.
    Unwritten,
}

/// Settles an `AlreadyPublished` against what the chain actually holds.
///
/// `on_chain` is `None` when the epoch has no usable root — absent, or refused by D-82's checks.
pub fn settle(requested: &Digest, on_chain: Option<&Digest>) -> Settlement {
    match on_chain {
        None => Settlement::Unwritten,
        Some(found) if found == requested => Settlement::Matches,
        Some(found) => Settlement::Equivocation { on_chain: *found },
    }
}

/// Whether a caller should keep trying, given what happened and how many attempts remain.
///
/// A retry re-sends the same instruction with a fresh blockhash. That changes bytes an observer can
/// see, and §4.4's closed list already permits the recent blockhash to differ, so retrying does not
/// widen what the chain discloses. What it must not do is move the publication time, which belongs to
/// the schedule and not to how many attempts an epoch took (INV-ANCH-01, D-83).
pub fn should_retry(outcome: Outcome, attempts_left: u32) -> bool {
    matches!(outcome, Outcome::Retry) && attempts_left > 0
}
