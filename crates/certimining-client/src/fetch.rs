//! Fetching a root by epoch, without an indexer (D-82).
//!
//! This is the read half that §2.3's `status` is built on, and it is not itself `AnchorClient`.
//! Codex round one, finding 3: the header said it was, which told a reader the trait was implemented
//! somewhere in this crate when none of its three operations existed.
//!
//! The address is derived, not searched: `["cm_ckpt", epoch_le]` against the program id. What comes
//! back is then placed before it is believed, because an RPC node can return anything and a root that
//! is believed on sight makes INV-ANCH-06 an assumption rather than a property.

use anchor_lang::{AnchorDeserialize, Discriminator};
use certimining_checkpoint::{CheckpointAccount, LogConfig};
use certimining_core::Digest;

use anchor_lang::prelude::Pubkey;

/// What the client will accept as an epoch's checkpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublishedCheckpoint {
    /// The epoch it belongs to, checked against the one asked for.
    pub epoch: u64,
    /// The root it published.
    pub root: Digest,
    /// The slot the transaction landed in, as the program recorded it.
    pub published_slot: u64,
    /// The block time the program recorded.
    pub published_unix: i64,
    /// Anchor B's receipt digest, zero until one is attached.
    pub receipt_digest: Digest,
    /// Which anchor the receipt is for, zero until one is attached.
    pub anchor_kind: u8,
}

/// Why a fetched account was refused. Each variant is a thing an RPC could hand back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// The account is not owned by the checkpoint program.
    NotTheProgram,
    /// The data is shorter than §2.4's layout.
    TooShort,
    /// The discriminator is not `CheckpointAccount`'s.
    NotACheckpoint,
    /// The schema version is not one this client reads.
    UnsupportedSchema,
    /// The account decodes, but for another epoch than the one asked for.
    WrongEpoch,
    /// The body does not decode.
    Malformed,
}

/// The cluster could not be asked. **Distinct from an absent account on purpose:** a gap in the
/// on-chain sequence is evidence of batcher failure (INV-ANCH-02), and an RPC that is unreachable is
/// evidence of nothing at all. Collapsing the two would let a network outage accuse the batcher.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unreachable(pub String);

/// What asking the cluster for one epoch produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fetched {
    /// An account that passed every check, so it is this epoch's root.
    Placed(PublishedCheckpoint),
    /// An account that came back and was refused, with the reason.
    Refused(Refused),
    /// The cluster holds nothing at the derived address. For an epoch that should have been
    /// published, this is a gap.
    Absent,
}

/// Where raw accounts come from. A cluster implements this; a test implements it with a map.
pub trait RootSource {
    /// The account at `address` with its owner, `Ok(None)` when the cluster holds nothing there, and
    /// an error when the cluster could not be asked.
    fn account(&self, address: &Pubkey) -> Result<Option<(Pubkey, Vec<u8>)>, Unreachable>;
}

/// `["cm_ckpt", epoch_le]` against the program id: the address of an epoch's checkpoint, derived
/// rather than searched for, which is what makes the fetch independent of any index.
pub fn checkpoint_address(program_id: &Pubkey, epoch: u64) -> Pubkey {
    Pubkey::find_program_address(&[CheckpointAccount::SEED, &epoch.to_le_bytes()], program_id).0
}

/// The log's configuration address.
pub fn config_address(program_id: &Pubkey) -> Pubkey {
    Pubkey::find_program_address(&[LogConfig::SEED], program_id).0
}

/// Places a fetched account before believing it (D-82).
///
/// Owner, discriminator, schema version and the epoch itself: an RPC that returns a well-formed
/// account for another epoch, or another program's account of the same shape, is refused here rather
/// than surfacing as a root for the epoch the caller asked about.
pub fn decode_checkpoint(
    owner: &Pubkey,
    program_id: &Pubkey,
    data: &[u8],
    epoch: u64,
) -> Result<PublishedCheckpoint, Refused> {
    if owner != program_id {
        return Err(Refused::NotTheProgram);
    }
    if data.len() < CheckpointAccount::LEN {
        return Err(Refused::TooShort);
    }
    let (discriminator, body) = data.split_at(8);
    if discriminator != CheckpointAccount::DISCRIMINATOR {
        return Err(Refused::NotACheckpoint);
    }
    let account = CheckpointAccount::deserialize(&mut &*body).map_err(|_| Refused::Malformed)?;
    if account.schema_version != certimining_checkpoint::SCHEMA_VERSION {
        return Err(Refused::UnsupportedSchema);
    }
    if account.epoch != epoch {
        return Err(Refused::WrongEpoch);
    }
    Ok(PublishedCheckpoint {
        epoch: account.epoch,
        root: account.root,
        published_slot: account.published_slot,
        published_unix: account.published_unix,
        receipt_digest: account.receipt_digest,
        anchor_kind: account.anchor_kind,
    })
}

/// The root for an epoch: placed, refused, or absent, and an error when the cluster could not be
/// asked at all.
pub fn root_for_epoch<S: RootSource>(
    source: &S,
    program_id: &Pubkey,
    epoch: u64,
) -> Result<Fetched, Unreachable> {
    let address = checkpoint_address(program_id, epoch);
    match source.account(&address)? {
        None => Ok(Fetched::Absent),
        Some((owner, data)) => Ok(match decode_checkpoint(&owner, program_id, &data, epoch) {
            Ok(checkpoint) => Fetched::Placed(checkpoint),
            Err(refused) => Fetched::Refused(refused),
        }),
    }
}

/// Which epochs in `first..=last` the cluster holds no checkpoint for.
///
/// A gap is evidence of batcher failure and INV-ANCH-02 requires the client to surface it. Returning
/// the epochs rather than a boolean is deliberate: a caller that has to name the missing epochs cannot
/// reduce a gap to a warning. **An unreachable cluster returns an error rather than a list**, because
/// a list of epochs nobody could ask about is an accusation built out of a network fault.
pub fn missing_epochs<S: RootSource>(
    source: &S,
    program_id: &Pubkey,
    first: u64,
    last: u64,
) -> Result<Gaps, Unreachable> {
    let mut gaps = Gaps::default();
    for epoch in first..=last {
        match root_for_epoch(source, program_id, epoch)? {
            Fetched::Placed(_) => {}
            Fetched::Absent => gaps.absent.push(epoch),
            Fetched::Refused(reason) => gaps.refused.push((epoch, reason)),
        }
    }
    Ok(gaps)
}

/// Every epoch in a range for which the caller has no usable root, with the two reasons kept apart.
///
/// They are kept apart for the same reason `Unreachable` is not an absence (D-106). An epoch with
/// nothing at its address is a gap in the on-chain sequence and so is evidence about the batcher
/// (INV-ANCH-02). An epoch whose account was refused says something else entirely: a third party can
/// place an account at a derived address, and one that fails the checks of D-82 is evidence about
/// whoever placed it. Counting a refusal as "not missing" was worse than either, because it returned
/// an empty list to a caller holding no root at all.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Gaps {
    /// Epochs with nothing at the derived address.
    pub absent: Vec<u64>,
    /// Epochs whose account came back and failed a check, with the reason.
    pub refused: Vec<(u64, Refused)>,
}

impl Gaps {
    /// Whether every epoch in the range had a usable root.
    pub fn is_empty(&self) -> bool {
        self.absent.is_empty() && self.refused.is_empty()
    }

    /// Every epoch without a usable root, whatever the reason, in ascending order.
    pub fn without_a_root(&self) -> Vec<u64> {
        let mut all: Vec<u64> = self
            .absent
            .iter()
            .copied()
            .chain(self.refused.iter().map(|(e, _)| *e))
            .collect();
        all.sort_unstable();
        all
    }
}
