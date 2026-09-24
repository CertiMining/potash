//! The CertiMining checkpoint program (§2.4).
//!
//! **STUB. No instruction is implemented yet (D-65).** Issue #8 requires the negative tests to be
//! written before the program, so this commit carries the tests and every instruction refuses. CI is
//! red on this commit by design, and the next commit turns it green.
//!
//! Three instructions and nothing else, ever. There is no update, close, revoke, shred or set-state,
//! and a pull request introducing one is rejected regardless of its guard conditions (§2.4).
//!
//! What the chain holds is a root per epoch and an optional receipt digest. Nothing that identifies an
//! asset reaches it: not `c`, not a tenure identifier, not a category, not a date.

use anchor_lang::prelude::*;

declare_id!("CMcKPT1111111111111111111111111111111111111");

/// §1.8's range for the tree height, written once at `initialize` (INV-TREE-06, D-78).
pub const MIN_TREE_HEIGHT: u8 = 4;
pub const MAX_TREE_HEIGHT: u8 = 16;

/// §1.3's schema version, written into both accounts.
pub const SCHEMA_VERSION: u16 = 1;

/// The one anchor-B kind §1.5 has (D-81).
pub const ANCHOR_KIND_OPENTIMESTAMPS: u8 = 1;

/// STUB (D-65): what every instruction returns until the implementation lands.
const STUB_REFUSAL: CheckpointError = CheckpointError::MalformedPayload;

#[program]
pub mod certimining_checkpoint {
    use super::*;

    /// Writes the authority and the tree height once. The `LogConfig` PDA is its own guard against a
    /// second call, and whoever calls first owns the log, which is why this belongs to the deploy
    /// procedure (D-79).
    pub fn initialize(ctx: Context<Initialize>, authority: Pubkey, tree_height: u8) -> Result<()> {
        let _ = (ctx, authority, tree_height);
        Err(STUB_REFUSAL.into())
    }

    /// Publishes one root for one epoch. Checks in the order §2.4 states: the checkpoint account
    /// already exists is `0x0E`, and only then an epoch that is not `last + 1` is `0x0D` (D-80).
    pub fn publish_checkpoint(ctx: Context<Publish>, epoch: u64, root: [u8; 32]) -> Result<()> {
        let _ = (ctx, epoch, root);
        Err(STUB_REFUSAL.into())
    }

    /// Attaches anchor B's receipt digest, once, zero to value (INV-ANCH-03). The authority's alone,
    /// and `kind` takes one value (D-81).
    pub fn attach_anchor_receipt(
        ctx: Context<Attach>,
        epoch: u64,
        receipt_digest: [u8; 32],
        kind: u8,
    ) -> Result<()> {
        let _ = (ctx, epoch, receipt_digest, kind);
        Err(STUB_REFUSAL.into())
    }
}

/// §2.4's `LogConfig`, 68 bytes.
#[account]
pub struct LogConfig {
    pub schema_version: u16,
    pub authority: Pubkey,
    pub last_epoch: u64,
    pub tree_height: u8,
    pub bump: u8,
    pub reserved: [u8; 16],
}

impl LogConfig {
    /// 8 discriminator, 2 schema, 32 authority, 8 last epoch, 1 height, 1 bump, 16 reserved.
    pub const LEN: usize = 68;
    pub const SEED: &'static [u8] = b"cm_cfg";
}

/// §2.4's `CheckpointAccount`, 106 bytes.
#[account]
pub struct CheckpointAccount {
    pub schema_version: u16,
    pub epoch: u64,
    pub root: [u8; 32],
    pub published_slot: u64,
    pub published_unix: i64,
    pub receipt_digest: [u8; 32],
    pub anchor_kind: u8,
    pub bump: u8,
    pub reserved: [u8; 6],
}

impl CheckpointAccount {
    /// 8 discriminator, 2 schema, 8 epoch, 32 root, 8 slot, 8 unix, 32 receipt, 1 kind, 1 bump,
    /// 6 reserved.
    pub const LEN: usize = 106;
    pub const SEED: &'static [u8] = b"cm_ckpt";
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = payer, space = LogConfig::LEN, seeds = [LogConfig::SEED], bump)]
    pub config: Account<'info, LogConfig>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(epoch: u64)]
pub struct Publish<'info> {
    #[account(mut, seeds = [LogConfig::SEED], bump = config.bump, has_one = authority)]
    pub config: Account<'info, LogConfig>,
    /// Unchecked on purpose: existence is the first thing `publish_checkpoint` decides, and an
    /// account declared with `init` cannot be inspected before Anchor creates it (D-80).
    /// CHECK: the seeds constrain it to this program's checkpoint PDA for `epoch`, and the
    /// instruction refuses it unless it is empty before creating it itself.
    #[account(mut, seeds = [CheckpointAccount::SEED, &epoch.to_le_bytes()], bump)]
    pub checkpoint: UncheckedAccount<'info>,
    pub authority: Signer<'info>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(epoch: u64)]
pub struct Attach<'info> {
    #[account(seeds = [LogConfig::SEED], bump = config.bump, has_one = authority)]
    pub config: Account<'info, LogConfig>,
    #[account(mut, seeds = [CheckpointAccount::SEED, &epoch.to_le_bytes()], bump = checkpoint.bump)]
    pub checkpoint: Account<'info, CheckpointAccount>,
    pub authority: Signer<'info>,
}

/// §2.1's codes, offset by Anchor's 6000. The discriminants are the specification's, so an on-chain
/// error of 6000 + code reverses to the same hex a counterparty reads off-chain.
#[error_code]
pub enum CheckpointError {
    #[msg("0x05: a field carries a value the specification does not allow")]
    MalformedPayload = 0x05,
    #[msg("0x0D: the epoch is not the last published one plus one")]
    EpochOutOfOrder = 0x0D,
    #[msg("0x0E: this epoch's checkpoint is already written")]
    CheckpointAlreadyWritten = 0x0E,
    #[msg("0x0F: the account's schema version is not one this program writes")]
    UnsupportedSchemaVersion = 0x0F,
    #[msg("0x15: this epoch's receipt is already attached")]
    ReceiptAlreadyAttached = 0x15,
}
