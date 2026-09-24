//! Fetching a root by epoch, without an indexer (§2.3's `AnchorClient`, D-82).
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

/// Where raw accounts come from. A cluster implements this; a test implements it with a map.
pub trait RootSource {
    /// The account at `address`, with its owner, or `None` when the cluster holds nothing there.
    fn account(&self, address: &Pubkey) -> Option<(Pubkey, Vec<u8>)>;
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

/// The root for an epoch, or the reason it was refused. `None` means the cluster holds nothing at the
/// derived address, which for an epoch that should have been published is a gap and a batcher failure
/// (INV-ANCH-02), not an absence to shrug at.
pub fn root_for_epoch<S: RootSource>(
    source: &S,
    program_id: &Pubkey,
    epoch: u64,
) -> Option<Result<PublishedCheckpoint, Refused>> {
    let address = checkpoint_address(program_id, epoch);
    let (owner, data) = source.account(&address)?;
    Some(decode_checkpoint(&owner, program_id, &data, epoch))
}

/// Which epochs in `first..=last` the cluster holds no checkpoint for.
///
/// A gap in the on-chain sequence is evidence of batcher failure and INV-ANCH-02 requires the client
/// to surface it. Returning the epochs rather than a boolean is deliberate: a caller that has to name
/// the missing epochs cannot report the gap as a warning and move on.
pub fn missing_epochs<S: RootSource>(
    source: &S,
    program_id: &Pubkey,
    first: u64,
    last: u64,
) -> Vec<u64> {
    (first..=last)
        .filter(|epoch| root_for_epoch(source, program_id, *epoch).is_none())
        .collect()
}
