//! F-01: arbitrary bytes into every decoder.
//!
//! §4.5 asks for a million iterations with zero panics, zero out-of-memory and zero timeouts. The
//! decoders a counterparty's bytes actually reach are three:
//!
//! 1. `read_tag`, which §1.2 puts in front of every preimage this system reads.
//! 2. `LogConfig`, which a client decodes to learn a log's height and epoch range.
//! 3. `CheckpointAccount`, which a client decodes to learn an epoch's root.
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

use anchor_lang::{AnchorDeserialize, AnchorSerialize};
use certimining_checkpoint::{CheckpointAccount, LogConfig};
use certimining_core::read_tag;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // §1.2's tag. Eight bytes or nothing, and the bytes it returns are the ones it was given.
    if let Ok(tag) = read_tag(data) {
        // The length is enforced twice inside `read_tag` — the slice and then the array conversion —
        // so asserting it here checks what the type already guarantees and cannot fail. Probed:
        // weakening the slice bound changes nothing, because the conversion still refuses. What can
        // fail, and what a defect would actually look like, is the tag not being the bytes it was
        // handed; making `read_tag` return `bytes[1..9]` fails this in seconds.
        assert_eq!(&tag[..], &data[..8], "read_tag returned bytes it was not given");
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
            config.serialize(&mut again).expect("a decoded config re-serializes");
            assert!(
                body.len() >= again.len() && body[..again.len()] == again[..],
                "LogConfig did not round-trip: read {} bytes and wrote back something else",
                again.len()
            );
        }

        if let Ok(checkpoint) = CheckpointAccount::deserialize(&mut &body[..]) {
            let mut again = Vec::new();
            checkpoint.serialize(&mut again).expect("a decoded checkpoint re-serializes");
            assert!(
                body.len() >= again.len() && body[..again.len()] == again[..],
                "CheckpointAccount did not round-trip: read {} bytes and wrote back something else",
                again.len()
            );
        }
    }
});
