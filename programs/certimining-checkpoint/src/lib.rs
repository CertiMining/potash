// SPDX-License-Identifier: MIT OR Apache-2.0
//! The CertiMining checkpoint program (§2.4).
//!
//! Three instructions and nothing else, ever. There is no update, close, revoke, shred or set-state,
//! and a pull request introducing one is rejected regardless of its guard conditions (§2.4).
//!
//! What the chain holds is a root per epoch and an optional receipt digest. Nothing that identifies an
//! asset reaches it: not `c`, not a tenure identifier, not a category, not a date.

use anchor_lang::prelude::*;

// The address this program deploys to. Its keypair was generated off-repo and lives outside this
// repository under mode 0600 (S6, D-79); nothing here has ever held the secret half. It is an
// address and never a wallet: nobody funds it, it signs once at deploy and never again, and it is
// not the upgrade authority, which is a separate key (D-88). The only lamports it ever holds are the
// program account's own rent-exemption, placed there by the loader. Every test on this branch
// verifies the address that actually deploys.
declare_id!("By5XeTsCS4Qf17U9EuGUTzEFz29wQdFFeqJtfhnFQkZB");

/// §1.8's range for the tree height, written once at `initialize` (INV-TREE-06, D-78).
/// §1.4's epoch clock: an epoch is a UTC day index, so a day is this many seconds.
pub const SECONDS_PER_DAY: u64 = 86_400;

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
    pub fn initialize(
        ctx: Context<Initialize>,
        authority: Pubkey,
        tree_height: u8,
        start_epoch: u64,
    ) -> Result<()> {
        require!(
            (MIN_TREE_HEIGHT..=MAX_TREE_HEIGHT).contains(&tree_height),
            CheckpointError::MalformedPayload
        );

        // §1.4: an epoch is a UTC day index, and `publish_checkpoint` takes exactly `last + 1`. A log
        // that began at zero could therefore never reach the current day without backfilling every
        // day since 1970, which made the daily cadence INV-ANCH-01 requires impossible from the first
        // deploy (D-109). The log begins at today.
        //
        // The argument is present so the intended value appears in the transaction, and it is
        // checked rather than trusted: the operator states it, the chain decides it. An exact match
        // is required, so a transaction prepared before midnight and landing after it is refused and
        // resubmitted with the new day. That is deliberate — a tolerance would be a choice between
        // two values, and this value is not the operator's to choose.
        let clock = Clock::get()?;
        let today = u64::try_from(clock.unix_timestamp)
            .map_err(|_| error!(CheckpointError::ArithmeticOverflow))?
            / SECONDS_PER_DAY;
        require!(start_epoch == today, CheckpointError::MalformedPayload);

        let bump = ctx.bumps.config;
        let config = &mut ctx.accounts.config;
        config.schema_version = SCHEMA_VERSION;
        config.authority = authority;
        // The first publishable epoch is `start_epoch`, and publication is always `last + 1`.
        config.last_epoch = start_epoch
            .checked_sub(1)
            .ok_or(CheckpointError::ArithmeticOverflow)?;
        config.tree_height = tree_height;
        config.bump = bump;
        config.start_epoch = start_epoch;
        config.reserved = [0u8; 8];
        Ok(())
    }

    /// Publishes one root for one epoch. Checks in the order §2.4 states: the checkpoint account
    /// already exists is `0x0E`, and only then an epoch that is not `last + 1` is `0x0D` (D-80).
    /// §2.4's `publish_checkpoint`, which takes the checkpoint PDA's bump rather than finding it.
    ///
    /// **The bump is instruction data since v0.2.7 (H-52, issue #193), and the reason is compute.**
    /// `#[account(init, seeds = …, bump)]` makes Anchor search downward from 255 for the canonical
    /// bump, and each rejected candidate costs one `create_program_address` syscall at 1,500 CU. The
    /// epoch is one of the seeds, so the cost was a property of the day: `8,810 + 1,500 × (255 − bump)`,
    /// which crossed §1.8's bound for about one epoch in 32 and did cross it for four of the 212 epochs
    /// the program superseded on 25 September published. Given the bump, Anchor makes one call and the
    /// cost is a property of the instruction again.
    ///
    /// `attach_anchor_receipt` has always worked this way — `bump = checkpoint.bump`, read from the
    /// account it is updating — which is why its figure never moved.
    ///
    /// **What this does not check, stated because it cannot be checked cheaply.** That the bump is the
    /// *canonical* one. Proving it is the largest valid bump means showing every larger candidate is
    /// on the curve, which is the search this change removes: there is no algebraic shortcut, because
    /// a PDA is a hash. So canonicality is the publisher's to enforce, and §1.8 says so.
    ///
    /// What a non-canonical bump would do, so the exposure is legible rather than implied: it names a
    /// different valid PDA for the same seeds, so the account would be created somewhere no verifier
    /// looks. Every verifier derives the address canonically, finds nothing, and reports the epoch
    /// absent — while `last_epoch` advanced, which `sequence_lag` surfaces as a published range whose
    /// account is missing from the same view (H-54). And only the checkpoint authority can do it,
    /// because this instruction requires that signature: it is the authority damaging its own log in
    /// a way every reader sees at once, not an attack anyone else can mount.
    pub fn publish_checkpoint(
        ctx: Context<Publish>,
        epoch: u64,
        root: [u8; 32],
        checkpoint_bump: u8,
    ) -> Result<()> {
        require!(
            ctx.accounts.config.schema_version == SCHEMA_VERSION,
            CheckpointError::UnsupportedSchemaVersion
        );

        // Existence first, then monotonicity. Both conditions hold when an epoch is republished, and
        // §2.4 names this order so the two codes stay distinguishable (D-80).
        //
        // What existence means here is narrow on purpose: this program owns the account and it holds
        // data. Reading a lamport balance as existence would hand anyone a way to stop the log, since
        // a checkpoint address is derived from a public seed and anyone may send lamports to it
        // (D-104). An address someone funded is still an empty slot, and this instruction fills it.
        let checkpoint = ctx.accounts.checkpoint.to_account_info();
        require!(
            checkpoint.owner != &crate::ID || checkpoint.data_is_empty(),
            CheckpointError::CheckpointAlreadyWritten
        );
        // Anything else already at the address belongs to a third party, and this program will not
        // write through it.
        require!(
            checkpoint.owner == &anchor_lang::system_program::ID && checkpoint.data_is_empty(),
            CheckpointError::MalformedPayload
        );
        let next = ctx
            .accounts
            .config
            .last_epoch
            .checked_add(1)
            .ok_or(CheckpointError::EpochOutOfOrder)?;
        require!(epoch == next, CheckpointError::EpochOutOfOrder);

        // **The epoch must be the chain's day, or the day before it** (H-11, issue #45).
        //
        // §1.4 makes an epoch a UTC day index. `initialize` is held to the chain's clock exactly
        // (D-109, V-N-26); this instruction was held to nothing. It accepted `last_epoch + 1` and
        // never asked what day it was, so a caller could advance the sequence as fast as it could
        // sign: 200 epochs in 200 minutes is a valid transaction sequence that leaves the log 200
        // days ahead of the calendar, and because the sequence is monotone it cannot be walked back.
        //
        // That happened twice on devnet. The second announced deployment reached `last_epoch` 20932
        // against a calendar index of 20723 — 209 days ahead — and the remedy both times was a new
        // program id (D-88).
        //
        // The day before is accepted because a publication scheduled inside day *d* may land in
        // day *d + 1* when the network is slow. So a log behind the calendar catches up one epoch
        // per transaction, and a log cannot run ahead at all.
        //
        // This bounds the sequence to the calendar in the one direction that was unguarded. A
        // batcher that stops publishing is visible as lag, which a client surfaces; a batcher that
        // publishes too fast was invisible.
        let clock = Clock::get()?;
        let chain_day = clock
            .unix_timestamp
            .checked_div(86_400)
            .ok_or(CheckpointError::EpochOutOfOrder)?;
        let chain_day = u64::try_from(chain_day).map_err(|_| CheckpointError::EpochOutOfOrder)?;
        require!(epoch <= chain_day, CheckpointError::EpochOutOfOrder);

        // The account `init` would have created, created here so existence could be read first, and
        // created the way `init` does it rather than the way that is shorter to write. The system
        // program's `create_account` refuses any address already holding lamports, so an address a
        // third party funded could never be written through it; topping up, allocating and assigning
        // reaches the same account from either starting point (D-104).
        let bump = checkpoint_bump;
        let epoch_le = epoch.to_le_bytes();
        let seeds: &[&[u8]] = &[CheckpointAccount::SEED, &epoch_le, &[bump]];
        let signer: &[&[&[u8]]] = &[seeds];
        let rent = Rent::get()?.minimum_balance(CheckpointAccount::LEN);
        let held = checkpoint.lamports();
        if held == 0 {
            // The ordinary path, and the cheap one: one CPI, exactly what `init` emits. Doing the
            // three-call dance unconditionally cost §1.8's budget about 7,400 CU for a case that
            // only arises when somebody has funded the address on purpose.
            anchor_lang::system_program::create_account(
                CpiContext::new(
                    ctx.accounts.system_program.key(),
                    anchor_lang::system_program::CreateAccount {
                        from: ctx.accounts.payer.to_account_info(),
                        to: checkpoint.clone(),
                    },
                )
                .with_signer(signer),
                rent,
                CheckpointAccount::LEN as u64,
                &crate::ID,
            )?;
        } else {
            // The attacked path. `create_account` refuses a funded address outright, so the account
            // is topped up, allocated and assigned instead, reaching the same state from a start
            // somebody else chose.
            if held < rent {
                anchor_lang::system_program::transfer(
                    CpiContext::new(
                        ctx.accounts.system_program.key(),
                        anchor_lang::system_program::Transfer {
                            from: ctx.accounts.payer.to_account_info(),
                            to: checkpoint.clone(),
                        },
                    ),
                    rent.checked_sub(held)
                        .ok_or(CheckpointError::ArithmeticOverflow)?,
                )?;
            }
            anchor_lang::system_program::allocate(
                CpiContext::new(
                    ctx.accounts.system_program.key(),
                    anchor_lang::system_program::Allocate {
                        account_to_allocate: checkpoint.clone(),
                    },
                )
                .with_signer(signer),
                CheckpointAccount::LEN as u64,
            )?;
            anchor_lang::system_program::assign(
                CpiContext::new(
                    ctx.accounts.system_program.key(),
                    anchor_lang::system_program::Assign {
                        account_to_assign: checkpoint.clone(),
                    },
                )
                .with_signer(signer),
                &crate::ID,
            )?;
        }

        // The same reading the day check above took, so the instruction makes one `Clock::get()`.
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
        // A zero digest is not a value, so attaching one would leave the sentinel in place and let a
        // second attachment through, which is the rule INV-ANCH-03 exists to state (D-105).
        require!(
            receipt_digest != [0u8; 32],
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
    /// The first epoch this log publishes, the UTC day index at `initialize` (D-109). A client needs
    /// it to tell an epoch before the log existed from a gap in the sequence (INV-ANCH-02).
    pub start_epoch: u64,
    pub reserved: [u8; 8],
}

impl LogConfig {
    /// 8 discriminator, 2 schema, 32 authority, 8 last epoch, 1 height, 1 bump, 8 start epoch,
    /// 8 reserved.
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
#[instruction(epoch: u64, root: [u8; 32], checkpoint_bump: u8)]
pub struct Publish<'info> {
    #[account(mut, seeds = [LogConfig::SEED], bump = config.bump, has_one = authority)]
    pub config: Account<'info, LogConfig>,
    /// Unchecked on purpose: existence is the first thing `publish_checkpoint` decides, and an
    /// account declared with `init` cannot be inspected before Anchor creates it (D-80).
    /// CHECK: the seeds and the supplied bump constrain it to a checkpoint PDA of this program for
    /// `epoch`, and the instruction refuses it unless it is empty before creating it itself.
    ///
    /// **`bump = checkpoint_bump` is one `create_program_address` call** where a bare `bump` is a
    /// search from 255 downward (H-52). It still proves the account is a valid PDA for these seeds;
    /// it does not prove the bump is canonical, which the handler's documentation and §1.8 both say.
    #[account(mut, seeds = [CheckpointAccount::SEED, &epoch.to_le_bytes()], bump = checkpoint_bump)]
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
    #[msg("checked arithmetic overflowed")]
    ArithmeticOverflow = 0x10,
}
