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
    /// The eight-byte discriminator is not the one the account this decoder was asked for carries.
    /// Both decoders reach it, so it is named for the condition rather than for one account type: it
    /// was `NotACheckpoint`, which reported a malformed `LogConfig` as the wrong kind of account
    /// entirely (S9-R2-03).
    WrongDiscriminator,
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
        return Err(Refused::WrongDiscriminator);
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

/// Places the log's configuration before believing it, on the same terms as a checkpoint (D-82).
///
/// A caller needs `start_epoch` and `last_epoch` to say where an epoch sits relative to the log
/// (INV-ANCH-02), and an account that failed a check is not a configuration this client will use.
pub fn decode_config(
    program_id: &Pubkey,
    owner: &Pubkey,
    data: &[u8],
) -> Result<LogConfig, Refused> {
    if owner != program_id {
        return Err(Refused::NotTheProgram);
    }
    if data.len() < LogConfig::LEN {
        return Err(Refused::TooShort);
    }
    let (discriminator, body) = data.split_at(8);
    if discriminator != LogConfig::DISCRIMINATOR {
        return Err(Refused::WrongDiscriminator);
    }
    let config = LogConfig::deserialize(&mut &*body).map_err(|_| Refused::Malformed)?;
    if config.schema_version != certimining_checkpoint::SCHEMA_VERSION {
        return Err(Refused::UnsupportedSchema);
    }
    Ok(config)
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

/// How far the published sequence lags the epochs a caller asked about, and any epoch whose account
/// was refused (D-106, amended 26 Sep 2026).
///
/// **There is no gap arm, because an interior gap cannot happen.** `publish_checkpoint` accepts
/// `last_epoch + 1` and nothing else, so the published range is contiguous from `start_epoch` to
/// `last_epoch` by construction. The previous version of this function reported every absent account
/// as a gap, which meant its only reachable answer was an epoch the sequence had not got to — a
/// lagging batcher, reported under the name of something else. E-11's independent implementation
/// found that from the specification alone, and D-80's rule applies to a client branch as much as to
/// an error code: a condition no path can reach reads as coverage that does not exist.
pub fn sequence_lag<S: RootSource>(
    source: &S,
    program_id: &Pubkey,
    first: u64,
    last: u64,
) -> Result<Lag, Unreachable> {
    let raw = source.account(&config_address(program_id))?;
    let config = match raw {
        Some((owner, data)) => decode_config(program_id, &owner, &data).map_err(|reason| {
            Unreachable(format!("the log's configuration was refused: {reason:?}"))
        })?,
        None => return Err(Unreachable(
            "the log has no configuration account, so nothing can be said about where an epoch \
                 sits relative to it"
                .into(),
        )),
    };

    let mut lag = Lag {
        start_epoch: config.start_epoch,
        last_published: config.last_epoch,
        before_log_start: Vec::new(),
        not_yet_published: Vec::new(),
        refused: Vec::new(),
    };
    for epoch in first..=last {
        if epoch < config.start_epoch {
            // Not a gap: a day the log did not exist for. A client that could not tell the two apart
            // would accuse a batcher of failing to publish before it was deployed (INV-ANCH-02).
            lag.before_log_start.push(epoch);
            continue;
        }
        if epoch > config.last_epoch {
            lag.not_yet_published.push(epoch);
            continue;
        }
        // Inside the published range. The account must be there, and the only thing left to decide is
        // whether it is one this client accepts.
        match root_for_epoch(source, program_id, epoch)? {
            Fetched::Placed(_) => {}
            Fetched::Refused(reason) => lag.refused.push((epoch, reason)),
            Fetched::Absent => {
                // On **one** consistent view of the chain this cannot happen: the configuration says
                // the epoch is published, and `publish_checkpoint` writes the checkpoint before it
                // advances `last_epoch`. But the configuration and this account came back from
                // separate requests with no shared response context (S9-R2-01), so what this proves
                // is that the answers were not one snapshot — not anything about the log. The earlier
                // wording claimed something other than this program had written the configuration,
                // which is a conclusion these reads cannot support.
                return Err(Unreachable(format!(
                    "epoch {epoch} is inside the published range {}..={} and its account did not come \
                     back. These are separate reads with no shared response context, so this is \
                     evidence about the responses and not about the log: ask again against one view.",
                    config.start_epoch, config.last_epoch
                )));
            }
        }
    }
    Ok(lag)
}

/// Where each epoch a caller asked about sits relative to the log, with the reasons kept apart.
///
/// They are kept apart for the same reason `Unreachable` is not an absence. An epoch before the log
/// started is a day it did not exist for. An epoch past `last_published` is the sequence lagging,
/// which is the batcher failure INV-ANCH-02 is about and the only one an on-chain read can show.
/// An epoch whose account was refused is evidence about **the response**, not about the chain.
///
/// **What `refused` does not mean, corrected at S9-R2-01.** This said a third party could place an
/// account at a derived address. That is false for a program-derived address: `allocate` requires the
/// target to sign (`solana-system-program-4.2.2`, `system_processor.rs:82-89`), a PDA is off-curve and
/// has no key, and only the owning program can sign for it with its seeds. A third party can send
/// lamports to one — which is D-104's attack — and can do nothing else. Inside the published range
/// every account was therefore written by this program, so a refusal there means the response did not
/// come from the same view of the chain as the configuration did, or did not come from the chain.
///
/// The arm is kept, at the owner's ruling, with that meaning rather than the one first given for it.
/// **Reading it as third-party interference would accuse someone of something they cannot do.**
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lag {
    /// The first epoch the log publishes, from its configuration.
    pub start_epoch: u64,
    /// The last epoch it has published.
    pub last_published: u64,
    /// Epochs asked about that precede the log's existence.
    pub before_log_start: Vec<u64>,
    /// Epochs asked about that the sequence has not reached.
    pub not_yet_published: Vec<u64>,
    /// Epochs inside the published range whose account failed a check.
    pub refused: Vec<(u64, Refused)>,
}

impl Lag {
    /// Whether every epoch asked about had a usable root.
    pub fn is_empty(&self) -> bool {
        self.before_log_start.is_empty()
            && self.not_yet_published.is_empty()
            && self.refused.is_empty()
    }

    /// How many epochs the sequence is behind the highest epoch asked about, or zero if it is not.
    pub fn epochs_behind(&self) -> u64 {
        self.not_yet_published
            .iter()
            .copied()
            .max()
            .map(|highest| highest.saturating_sub(self.last_published))
            .unwrap_or(0)
    }
}
