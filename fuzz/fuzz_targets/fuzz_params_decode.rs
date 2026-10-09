// SPDX-License-Identifier: MIT OR Apache-2.0
//! F-01: arbitrary bytes into every decoder.
//!
//! §4.5 asks for a million iterations with zero panics, zero out-of-memory and zero timeouts. The
//! decoders a counterparty's bytes actually reach are five:
//!
//! 1. `read_tag`, which §1.2 puts in front of every preimage this system reads.
//! 2. `LogConfig`, which a client decodes to learn a log's height and epoch range.
//! 3. `CheckpointAccount`, which a client decodes to learn an epoch's root.
//! 4. `decode_config`, the client's public placement of an untrusted `LogConfig` account.
//! 5. `decode_checkpoint`, the same for a checkpoint, including the epoch it was asked about, and
//!    **every field it returns** rather than the epoch alone (H-22).
//!
//! **The last two were missing, and that was the serious half (PR #55, round two, E12-04.)** An earlier
//! version of this file said the first three were the only decoders a counterparty's bytes reach, which
//! was false: 2 and 3 are Borsh on a body, while 4 and 5 are the boundary where an RPC response becomes
//! something the client believes — they check owner, length, discriminator, schema and the requested
//! epoch. F-01 did not call them and the fuzz crate did not depend on `certimining-client` at all, so a
//! defect that accepted an account owned by **another program** survived a million iterations while the
//! client's own test failed. Fuzzing the serialization primitives is not fuzzing the trust boundary.
//!
//! The last two are Anchor accounts, so a real client skips the eight-byte discriminator and hands
//! the rest to Borsh; this drives both halves, with and without that skip, because a decoder that
//! panics on a buffer shorter than the discriminator is a decoder a malicious RPC can crash.
//!
//! What it asserts beyond absence of panic: a successful decode round-trips — what was read,
//! re-serialized, is the bytes that were read. That is a decoder's own contract. The *semantic*
//! invariants §1.4 and §2.4 state belong to accounts the program wrote, and arbitrary bytes that
//! happen to parse are not those; asserting them here was wrong and the fuzzer said so.
#![no_main]

use anchor_lang::prelude::Pubkey;
use anchor_lang::{AnchorDeserialize, AnchorSerialize, Discriminator};
use certimining_checkpoint::{CheckpointAccount, LogConfig};
use certimining_client::{decode_checkpoint, decode_config, Refused};
use certimining_core::read_tag;
use libfuzzer_sys::fuzz_target;

/// §2.4's own values, transcribed rather than imported (M-02).
///
/// The oracle below first shared `certimining_checkpoint::SCHEMA_VERSION`, `::LEN` and `::DISCRIMINATOR`
/// with the decoders it checks — so a review changed the program's schema constant from 1 to 2 and both
/// sides accepted a schema-2 account together, green over a million iterations. An oracle that imports
/// the decision it is auditing is not a second opinion.
///
/// The lengths are §2.4's published figures. The discriminators follow §2.4's stated rule, the first
/// eight bytes of `SHA-256("account:" ‖ StructName)`, computed independently of Anchor's derive macro:
///
///   python3 -c "import hashlib; print(hashlib.sha256(b'account:LogConfig').hexdigest()[:16])"
///   python3 -c "import hashlib; print(hashlib.sha256(b'account:CheckpointAccount').hexdigest()[:16])"
const SCHEMA_VERSION: u16 = 1;
const CHECKPOINT_LEN: usize = 106;
const LOG_CONFIG_LEN: usize = 68;
const CHECKPOINT_DISCRIMINATOR: [u8; 8] = [0x4d, 0x11, 0x99, 0xcb, 0x01, 0xec, 0x47, 0x59];
const LOG_CONFIG_DISCRIMINATOR: [u8; 8] = [0x1c, 0xf0, 0x75, 0x7f, 0x1a, 0xa6, 0xbf, 0x37];

/// What `decode_checkpoint` owes for these inputs, decided here rather than read off its own answer.
///
/// This is the point of the target: an oracle that says "one of these errors is fine" would have passed
/// the defect that prompted it. The conditions are in §2.4's order, which is the order the decoder must
/// apply them in, so a reordering is a finding too.
/// Every field §2.4 lays out, in its order. The oracle returned the epoch alone, so five fields
/// came back unchecked: a review made `decode_checkpoint` return `root: [0; 32]` and this target
/// completed a million iterations green (H-22). A client trusting that root would have verified an
/// inclusion proof against a root the chain does not hold, which is the one thing this decoder is
/// for.
type Fields = (u64, [u8; 32], u64, i64, [u8; 32], u8);

fn expected_checkpoint(
    owner: &Pubkey,
    program_id: &Pubkey,
    data: &[u8],
    epoch: u64,
) -> Result<Fields, Refused> {
    if owner != program_id {
        return Err(Refused::NotTheProgram);
    }
    if data.len() < CHECKPOINT_LEN {
        return Err(Refused::TooShort);
    }
    if data[..8] != CHECKPOINT_DISCRIMINATOR {
        return Err(Refused::WrongDiscriminator);
    }
    let account =
        CheckpointAccount::deserialize(&mut &data[8..]).map_err(|_| Refused::Malformed)?;
    if account.schema_version != SCHEMA_VERSION {
        return Err(Refused::UnsupportedSchema);
    }
    if account.epoch != epoch {
        return Err(Refused::WrongEpoch);
    }
    Ok((
        account.epoch,
        account.root,
        account.published_slot,
        account.published_unix,
        account.receipt_digest,
        account.anchor_kind,
    ))
}

/// The same for `decode_config`, which has no epoch to disagree about.
fn expected_config(program_id: &Pubkey, owner: &Pubkey, data: &[u8]) -> Result<u16, Refused> {
    if owner != program_id {
        return Err(Refused::NotTheProgram);
    }
    if data.len() < LOG_CONFIG_LEN {
        return Err(Refused::TooShort);
    }
    if data[..8] != LOG_CONFIG_DISCRIMINATOR {
        return Err(Refused::WrongDiscriminator);
    }
    let config = LogConfig::deserialize(&mut &data[8..]).map_err(|_| Refused::Malformed)?;
    if config.schema_version != SCHEMA_VERSION {
        return Err(Refused::UnsupportedSchema);
    }
    Ok(config.schema_version)
}

fuzz_target!(|data: &[u8]| {
    // §1.2's tag. Eight bytes or nothing, and the bytes it returns are the ones it was given.
    if let Ok(tag) = read_tag(data) {
        // The length is enforced twice inside `read_tag` — the slice and then the array conversion —
        // so asserting it here checks what the type already guarantees and cannot fail. Probed:
        // weakening the slice bound changes nothing, because the conversion still refuses. What can
        // fail, and what a defect would actually look like, is the tag not being the bytes it was
        // handed; making `read_tag` return `bytes[1..9]` fails this in seconds.
        assert_eq!(
            &tag[..],
            &data[..8],
            "read_tag returned bytes it was not given"
        );
    }

    // The two account decoders, from the start and from after the discriminator a client skips.
    for offset in [0usize, 8usize] {
        if data.len() < offset {
            continue;
        }
        let body = &data[offset..];

        // **What a decoder promises, and what it does not.** Borsh reads bytes into fields; it does
        // not establish that the program wrote them. A first version of this target asserted
        // §1.4's relation between `start_epoch` and `last_epoch` on anything that parsed, and the
        // fuzzer refuted it in seconds — correctly, because arbitrary bytes carry arbitrary values
        // and that relation belongs to accounts the program produced. (It also overflowed at
        // `u64::MAX`.) The assertion claimed more than the decoder establishes, which is the same
        // mistake this repository has been correcting in its records all week.
        //
        // What a decoder does promise is fidelity: what it read, re-serialized, is the bytes it read.
        // A decoder that loses or invents a field would fail that, and no semantic guess is needed.
        if let Ok(config) = LogConfig::deserialize(&mut &body[..]) {
            let mut again = Vec::new();
            config
                .serialize(&mut again)
                .expect("a decoded config re-serializes");
            assert!(
                body.len() >= again.len() && body[..again.len()] == again[..],
                "LogConfig did not round-trip: read {} bytes and wrote back something else",
                again.len()
            );
        }

        if let Ok(checkpoint) = CheckpointAccount::deserialize(&mut &body[..]) {
            let mut again = Vec::new();
            checkpoint
                .serialize(&mut again)
                .expect("a decoded checkpoint re-serializes");
            assert!(
                body.len() >= again.len() && body[..again.len()] == again[..],
                "CheckpointAccount did not round-trip: read {} bytes and wrote back something else",
                again.len()
            );
        }
    }

    // **The trust boundary (E12-04).** The owner, the program id and the requested epoch all come out of
    // the same arbitrary bytes, so an iteration exercises a matching owner about as often as a mismatched
    // one, and the epoch is sometimes the account's own and sometimes not.
    let program_id = certimining_checkpoint::ID;
    let owner = if data.len() >= 33 && data[32] & 1 == 0 {
        // Half the time the real owner, so the path past the first check is reached rather than every
        // input being refused at it — the mistake F-03 made three times.
        program_id
    } else if data.len() >= 32 {
        Pubkey::new_from_array(<[u8; 32]>::try_from(&data[..32]).expect("32 bytes"))
    } else {
        Pubkey::new_from_array([0u8; 32])
    };
    let epoch = if data.len() >= 18 {
        u64::from_le_bytes(<[u8; 8]>::try_from(&data[10..18]).expect("8 bytes"))
    } else {
        0
    };

    let got = decode_checkpoint(&owner, &program_id, data, epoch).map(|c| {
        (
            c.epoch,
            c.root,
            c.published_slot,
            c.published_unix,
            c.receipt_digest,
            c.anchor_kind,
        )
    });
    let want = expected_checkpoint(&owner, &program_id, data, epoch);
    assert_eq!(
        got,
        want,
        "decode_checkpoint disagreed with §2.4's conditions for {} bytes, owner {}, epoch {epoch}",
        data.len(),
        owner
    );

    let got = decode_config(&program_id, &owner, data).map(|c| c.schema_version);
    let want = expected_config(&program_id, &owner, data);
    assert_eq!(
        got,
        want,
        "decode_config disagreed with §2.4's conditions for {} bytes, owner {}",
        data.len(),
        owner
    );

    // **The transcribed values are checked against Anchor's, as a thing under test rather than as the
    // oracle's source.** If the derive macro and §2.4's stated rule ever disagree, that is a finding in
    // itself; importing the constant would have hidden it, which is what M-02 was about.
    assert_eq!(
        CHECKPOINT_DISCRIMINATOR,
        CheckpointAccount::DISCRIMINATOR,
        "§2.4's rule and Anchor's derive disagree about CheckpointAccount's discriminator"
    );
    assert_eq!(
        LOG_CONFIG_DISCRIMINATOR,
        LogConfig::DISCRIMINATOR,
        "§2.4's rule and Anchor's derive disagree about LogConfig's discriminator"
    );
    assert_eq!(
        CHECKPOINT_LEN,
        CheckpointAccount::LEN,
        "§2.4 publishes 106 bytes"
    );
    assert_eq!(LOG_CONFIG_LEN, LogConfig::LEN, "§2.4 publishes 68 bytes");

    // **Seeded valid prefixes (M-02).** Raw arbitrary bytes essentially never carry a real
    // discriminator, so a clean run left no evidence that the schema and epoch branches were ever
    // reached. These two candidates carry the right discriminator and a fuzzer-chosen body, so the
    // conditions past it are exercised on every iteration that has bytes to spare.
    for (disc, label) in [
        (CHECKPOINT_DISCRIMINATOR, "checkpoint"),
        (LOG_CONFIG_DISCRIMINATOR, "config"),
    ] {
        let mut candidate = Vec::with_capacity(8 + data.len());
        candidate.extend_from_slice(&disc);
        candidate.extend_from_slice(data);

        let got = decode_checkpoint(&program_id, &program_id, &candidate, epoch).map(|c| {
            (
                c.epoch,
                c.root,
                c.published_slot,
                c.published_unix,
                c.receipt_digest,
                c.anchor_kind,
            )
        });
        let want = expected_checkpoint(&program_id, &program_id, &candidate, epoch);
        assert_eq!(
            got,
            want,
            "decode_checkpoint disagreed on a {label}-seeded candidate of {} bytes, epoch {epoch}",
            candidate.len()
        );

        let got = decode_config(&program_id, &program_id, &candidate).map(|c| c.schema_version);
        let want = expected_config(&program_id, &program_id, &candidate);
        assert_eq!(
            got,
            want,
            "decode_config disagreed on a {label}-seeded candidate of {} bytes",
            candidate.len()
        );
    }
});
