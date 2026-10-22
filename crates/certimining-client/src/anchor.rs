// SPDX-License-Identifier: MIT OR Apache-2.0
//! §2.3's `AnchorClient`, the parts this unit owns (D-110).
//!
//! The trait names three operations. `publish` and `status` belong to anchor A and are here;
//! `timestamp` is OpenTimestamps, which is anchor B and E-10's unit, so it is not implemented here
//! and this module does not pretend otherwise. Codex round one, finding 3: two module headers in
//! this crate claimed to be §2.3's `AnchorClient` while the crate implemented none of it.
//!
//! What is decided here is decided without a network, so it can be tested without one.

use crate::fetch::Fetched;

/// §2.3's `AnchorStatus`. INV-ANCH-05 makes a client say which of the two anchors an epoch has, and
/// say `Single` until anchor B attaches rather than degrading silently to a dual-anchor claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchorStatus {
    /// No checkpoint for this epoch, or none this client will accept.
    Pending,
    /// A root is on Solana. Anchor B has not attached.
    Single,
    /// A root is on Solana and a receipt digest is attached.
    Dual,
}

/// Where a published root can be found, which is what §2.3's `publish` returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorRef {
    pub epoch: u64,
    pub signature: String,
    pub published_slot: u64,
    /// What ties `published_slot` to a chain rather than to another number (H-35, issue #82).
    pub lineage: Lineage,
}

/// What the endpoint said when asked where a signature's transaction landed.
///
/// Three answers, kept apart because they are different facts. The one that matters is the third:
/// **a failure to look is not a finding**, and folding it into "not found" would make an unreachable
/// endpoint read as a missing transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WhereItLanded {
    /// The endpoint reported this slot.
    Slot(u64),
    /// The endpoint answered and does not know this signature.
    ///
    /// Not a refusal of the publication. A status is kept for a bounded window, so asking late
    /// about a transaction that certainly landed gets this.
    NotFound,
    /// The question could not be put, with the reason.
    NotAsked(String),
}

/// What ties a publication to a chain rather than to a number (H-35, issue #82).
///
/// **The defect this answers.** V-Z-01 brackets its delay observation as
/// `before <= published_slot <= after`, all three read at `confirmed`. Numeric ordering does not
/// establish that the three readings describe one chain: Solana distinguishes `confirmed` from rooted
/// `finalized`, so the middle reading can belong to another confirmed fork and satisfy the predicate
/// anyway. The review of PR #69 demonstrated the predicate's incompleteness with a local probe:
///
/// ```text
/// before=Observation { fork: "A", slot: 100 }  published=Observation { fork: "B", slot: 101 }
/// after=Observation  { fork: "A", slot: 102 }  bracket=true
/// ```
///
/// **What binds them is the signature.** `getSignatureStatuses` answers from the chain the endpoint
/// serves, so a transaction found at the slot the account records is a publication whose two readings
/// agree about one chain. The account's slot comes from `Clock::get()` inside the program, on the fork
/// where it executed; the status comes from the fork the endpoint serves now. Agreement is the fact
/// the bracket was missing.
///
/// **This works because a publication has a signature, and two plain account reads do not.** The same
/// fork question is open for `sequence_lag`'"'"'s reads of the configuration and a checkpoint, where the
/// answer is one request rather than one handle — `getMultipleAccounts` returns a single response
/// context — and that is H-54 (#197).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lineage {
    /// The transaction was found at the slot the account records: the two readings agree.
    AtItsSlot,
    /// The transaction landed at a different slot from the one the account records.
    ///
    /// One of the two readings is from another fork. The root is published either way — this says
    /// that no delay can be measured from these two numbers.
    Disagreed { transaction_slot: u64 },
    /// The endpoint answered and does not know the signature, so nothing binds the slot.
    Unknown,
    /// The question could not be put. Carried rather than collapsed, for the reason `NotAsked` gives.
    Unasked(String),
    /// There is no signature to bind, which is D-108's `AlreadyPublished` path.
    ///
    /// `settle_against_chain` establishes that the epoch holds *this* root, which is what a late
    /// retry needed; it does not name the transaction that wrote it. An observation that needs
    /// lineage cannot use such a publication, and this is how it finds out.
    NoSignature,
}

/// One entry from the chain's own listing of what touched an account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Touched {
    pub signature: String,
    pub slot: u64,
    /// Whether the transaction succeeded.
    ///
    /// **A failed transaction appears in that listing and wrote nothing.** Taking one for provenance
    /// would bind an account's contents to a transaction that did not produce them.
    pub succeeded: bool,
}

/// Recovers the signature that wrote a checkpoint account, where the caller has none.
///
/// **D-108's retry path carried no provenance at all, which is issue #82's fourth item.** When
/// `publish_checkpoint` answers `AlreadyPublished`, `settle_against_chain` establishes that the epoch
/// holds *this* root — what a late retry needed — and cannot name the transaction that wrote it. So
/// the publication came back with an empty signature and nothing could bind its slot to a chain.
///
/// The chain can name it. `getSignaturesForAddress` on the checkpoint account lists what touched it
/// and at which slot, and a successful transaction the chain places at the slot the account records
/// is the transaction that wrote it.
///
/// **Exactly one, or none.** If two successful transactions sit at that slot, which of them wrote the
/// account is a guess, and a guess recorded as provenance is worse than an honest absence.
pub fn provenance_in(published_slot: u64, touched: &[Touched]) -> Option<&str> {
    let mut candidates = touched
        .iter()
        .filter(|t| t.succeeded && t.slot == published_slot && !t.signature.is_empty());
    match (candidates.next(), candidates.next()) {
        (Some(only), None) => Some(only.signature.as_str()),
        _ => None,
    }
}

/// Classifies a publication's lineage from the account's slot and what the endpoint answered.
///
/// Pure, so the decision is tested here rather than against a cluster: this crate's rule is that
/// `cluster` carries observations to and from an RPC and decides nothing (D-84).
pub fn lineage_of(published_slot: u64, signature: &str, landed: &WhereItLanded) -> Lineage {
    if signature.is_empty() {
        return Lineage::NoSignature;
    }
    match landed {
        WhereItLanded::NotAsked(why) => Lineage::Unasked(why.clone()),
        WhereItLanded::NotFound => Lineage::Unknown,
        WhereItLanded::Slot(slot) if *slot == published_slot => Lineage::AtItsSlot,
        WhereItLanded::Slot(slot) => Lineage::Disagreed {
            transaction_slot: *slot,
        },
    }
}

/// The status of one epoch, given what the cluster answered for it.
///
/// A refusal is `Pending` rather than `Single`: an account this client will not accept is not a root
/// it has, and reporting it as anchored would be the silent degradation INV-ANCH-05 forbids, pointed
/// the other way.
pub fn status_of(fetched: &Fetched) -> AnchorStatus {
    match fetched {
        Fetched::Placed(checkpoint) => {
            if checkpoint.receipt_digest == [0u8; 32] {
                AnchorStatus::Single
            } else {
                AnchorStatus::Dual
            }
        }
        Fetched::Absent | Fetched::Refused(_) => AnchorStatus::Pending,
    }
}

#[cfg(test)]
mod lineage_tests {
    use super::*;

    #[test]
    fn a_transaction_at_the_slot_the_account_records_binds_them() {
        assert_eq!(
            lineage_of(504_985_662, "3Qk…", &WhereItLanded::Slot(504_985_662)),
            Lineage::AtItsSlot
        );
    }

    /// **The case the bracket could not see.** Two readings, one chain each.
    #[test]
    fn a_transaction_at_another_slot_is_a_disagreement_and_not_a_delay() {
        assert_eq!(
            lineage_of(101, "3Qk…", &WhereItLanded::Slot(103)),
            Lineage::Disagreed {
                transaction_slot: 103
            },
            "the account says one slot and the served chain says another, so one of them is from \
             another fork and no delay follows from the pair"
        );
    }

    /// **A failure to look is not a finding**, and this is the assertion that keeps them apart.
    #[test]
    fn an_unanswerable_question_is_not_an_unknown_transaction() {
        let unasked = lineage_of(101, "3Qk…", &WhereItLanded::NotAsked("timed out".into()));
        let unknown = lineage_of(101, "3Qk…", &WhereItLanded::NotFound);
        assert_eq!(unasked, Lineage::Unasked("timed out".into()));
        assert_eq!(unknown, Lineage::Unknown);
        assert_ne!(
            unasked, unknown,
            "an endpoint that could not be reached must not read as an endpoint that answered"
        );
    }

    /// D-108's retry path has nothing to bind, whatever the endpoint would have said.
    #[test]
    fn the_already_published_path_reports_that_it_has_no_signature() {
        for landed in [
            WhereItLanded::Slot(101),
            WhereItLanded::NotFound,
            WhereItLanded::NotAsked("whatever".into()),
        ] {
            assert_eq!(
                lineage_of(101, "", &landed),
                Lineage::NoSignature,
                "an empty signature binds nothing, and a slot that happens to match is a \
                 coincidence rather than a binding"
            );
        }
    }

    /// Slot 0 is a slot. A classifier that read "no answer" out of a zero would bind a publication
    /// to a chain nobody asked about, which is this repository's most-repeated defect.
    #[test]
    fn slot_zero_is_a_slot_and_not_an_absence() {
        assert_eq!(
            lineage_of(0, "3Qk…", &WhereItLanded::Slot(0)),
            Lineage::AtItsSlot
        );
    }
}

#[cfg(test)]
mod provenance_tests {
    use super::*;

    fn touched(signature: &str, slot: u64, succeeded: bool) -> Touched {
        Touched {
            signature: signature.to_string(),
            slot,
            succeeded,
        }
    }

    #[test]
    fn the_one_successful_transaction_at_that_slot_is_the_provenance() {
        let listing = [
            touched("wrote-it", 504_985_662, true),
            touched("later", 504_999_000, true),
        ];
        assert_eq!(provenance_in(504_985_662, &listing), Some("wrote-it"));
    }

    /// **A failed transaction wrote nothing**, whatever slot it sat in.
    #[test]
    fn a_failed_transaction_at_that_slot_is_not_provenance() {
        let listing = [touched("it-failed", 101, false)];
        assert_eq!(
            provenance_in(101, &listing),
            None,
            "a transaction that failed did not write this account, and binding the account's \
             contents to it would assert a relationship that does not exist"
        );
    }

    /// Two candidates make it a guess, and a guess recorded as provenance is worse than an absence.
    #[test]
    fn two_successful_transactions_in_one_slot_bind_nothing() {
        let listing = [touched("one", 101, true), touched("two", 101, true)];
        assert_eq!(provenance_in(101, &listing), None);
    }

    #[test]
    fn a_listing_with_nothing_at_that_slot_binds_nothing() {
        let listing = [touched("elsewhere", 99, true), touched("later", 103, true)];
        assert_eq!(provenance_in(101, &listing), None);
    }

    /// An empty listing is the ordinary answer for an account nothing is known to have touched, and
    /// it has to read as an absence rather than panic or match.
    #[test]
    fn an_empty_listing_binds_nothing() {
        assert_eq!(provenance_in(101, &[]), None);
    }
}
