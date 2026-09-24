//! The CertiMining checkpoint program (§2.4).
//!
//! Three instructions and nothing else, ever. There is no update, close, revoke, shred or set-state,
//! and a pull request introducing one is rejected regardless of its guard conditions (§2.4).
//!
//! What the chain holds is a root per epoch and an optional receipt digest. Nothing that identifies an
//! asset reaches it: not `c`, not a tenure identifier, not a category, not a date.

use anchor_lang::prelude::*;

// The address this program deploys to. Its keypair was generated off-repo and lives outside this
// repository under mode 0600 (S6, D-79); nothing here has ever held the secret half. Every test on
// this branch therefore verifies the address that actually deploys.
declare_id!("5uxZGvtkipqzLWjyNfFGEMxGFfd3FPveti4uQE7FdCXz");

/// §1.8's range for the tree height, written once at `initialize` (INV-TREE-06, D-78).
pub const MIN_TREE_HEIGHT: u8 = 4;
pub const MAX_TREE_HEIGHT: u8 = 16;

/// §1.3's schema version, written into both accounts.
pub const SCHEMA_VERSION: u16 = 1;

/// The one anchor-B kind §1.5 has (D-81).
pub const ANCHOR_KIND_OPENTIMESTAMPS: u8 = 1;

#[program]
pub mod certimining_checkpoint {
    use super::*;

    /// Writes the authority and the tree height once. The `LogConfig` PDA is its own guard against a
    /// second call, and whoever calls first owns the log, which is why this belongs to the deploy
    /// procedure (D-79).
    pub fn initialize(ctx: Context<Initialize>, authority: Pubkey, tree_height: u8) -> Result<()> {
        require!(
            (MIN_TREE_HEIGHT..=MAX_TREE_HEIGHT).contains(&tree_height),
            CheckpointError::MalformedPayload
        );
        let bump = ctx.bumps.config;
        let config = &mut ctx.accounts.config;
        config.schema_version = SCHEMA_VERSION;
        config.authority = authority;
        config.last_epoch = 0;
        config.tree_height = tree_height;
        config.bump = bump;
        config.reserved = [0u8; 16];
        Ok(())
    }

    /// Publishes one root for one epoch. Checks in the order §2.4 states: the checkpoint account
    /// already exists is `0x0E`, and only then an epoch that is not `last + 1` is `0x0D` (D-80).
    pub fn publish_checkpoint(ctx: Context<Publish>, epoch: u64, root: [u8; 32]) -> Result<()> {
        require!(
            ctx.accounts.config.schema_version == SCHEMA_VERSION,
            CheckpointError::UnsupportedSchemaVersion
        );

        // Existence first, then monotonicity. Both conditions hold when an epoch is republished, and
        // §2.4 names this order so the two codes stay distinguishable (D-80).
        let checkpoint = ctx.accounts.checkpoint.to_account_info();
        require!(
            checkpoint.data_is_empty() && checkpoint.lamports() == 0,
            CheckpointError::CheckpointAlreadyWritten
        );
        let next = ctx
            .accounts
            .config
            .last_epoch
            .checked_add(1)
            .ok_or(CheckpointError::EpochOutOfOrder)?;
        require!(epoch == next, CheckpointError::EpochOutOfOrder);

        // The account `init` would have created, created here so existence could be read first. Same
        // system-program call, same rent, same owner.
        let bump = ctx.bumps.checkpoint;
        let epoch_le = epoch.to_le_bytes();
        let seeds: &[&[u8]] = &[CheckpointAccount::SEED, &epoch_le, &[bump]];
        let rent = Rent::get()?.minimum_balance(CheckpointAccount::LEN);
        anchor_lang::system_program::create_account(
            CpiContext::new(
                ctx.accounts.system_program.key(),
                anchor_lang::system_program::CreateAccount {
                    from: ctx.accounts.payer.to_account_info(),
                    to: checkpoint.clone(),
                },
            )
            .with_signer(&[seeds]),
            rent,
            CheckpointAccount::LEN as u64,
            &crate::ID,
        )?;

        let clock = Clock::get()?;
        let written = CheckpointAccount {
            schema_version: SCHEMA_VERSION,
            epoch,
            root,
            published_slot: clock.slot,
            published_unix: clock.unix_timestamp,
            receipt_digest: [0u8; 32],
            anchor_kind: 0,
            bump,
            reserved: [0u8; 6],
        };
        let mut data = checkpoint.try_borrow_mut_data()?;
        let (discriminator, body) = data.split_at_mut(8);
        discriminator.copy_from_slice(CheckpointAccount::DISCRIMINATOR);
        let mut cursor = &mut *body;
        written.serialize(&mut cursor)?;
        drop(data);

        ctx.accounts.config.last_epoch = epoch;
        Ok(())
    }

    /// Attaches anchor B's receipt digest, once, zero to value (INV-ANCH-03). The authority's alone,
    /// and `kind` takes one value (D-81).
    pub fn attach_anchor_receipt(
        ctx: Context<Attach>,
        epoch: u64,
        receipt_digest: [u8; 32],
        kind: u8,
    ) -> Result<()> {
        require!(
            ctx.accounts.config.schema_version == SCHEMA_VERSION,
            CheckpointError::UnsupportedSchemaVersion
        );
        require!(
            kind == ANCHOR_KIND_OPENTIMESTAMPS,
            CheckpointError::MalformedPayload
        );
        let checkpoint = &mut ctx.accounts.checkpoint;
        require!(checkpoint.epoch == epoch, CheckpointError::EpochOutOfOrder);
        // Zero to a value, exactly once (INV-ANCH-03). Nothing here mutates a non-zero field.
        require!(
            checkpoint.receipt_digest == [0u8; 32],
            CheckpointError::ReceiptAlreadyAttached
        );
        checkpoint.receipt_digest = receipt_digest;
        checkpoint.anchor_kind = kind;
        Ok(())
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
