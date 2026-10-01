// SPDX-License-Identifier: MIT OR Apache-2.0
//! V-P-12 against this crate's derivation: the client fetches by address, so the address has to be
//! the one §2.4 states.
//!
//! **Why the vector exists at all.** §2.4 named the seeds for a long time without saying how an
//! address follows from them, and when the paragraph was finally written it printed
//! `… ‖ program_id ‖ bump ‖ …` — the bump and the program id the wrong way round. An implementer
//! following that text could not have fetched the log, and nothing in this repository noticed,
//! because no expected value existed to check the text against. V-P-12 is that expected value, and
//! this file is the side of it that uses the platform's own implementation.
//!
//! Three implementations meet here. The generator wrote the vector from §2.4's printed algorithm and
//! fails generation unless it reproduces the addresses §2.4 publishes. `ts/` derives them from
//! published platform documentation, independently. Below, `config_address` and `checkpoint_address`
//! reach Solana's `find_program_address`. Agreement across the three is worth something precisely
//! because none of them read the others.

use certimining_client::{checkpoint_address, config_address};

/// The vector, read from the committed corpus rather than restated here (D-57 keeps JSON in tools and
/// tests). A value copied into this file would be a fourth opinion, not a check.
fn vector() -> serde_json::Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("the crate sits two levels below the repository root")
        .join("vectors/V-P-12.json");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_str(&text).expect("V-P-12 is JSON")
}

/// `"0x…"` to bytes. The vector's addresses are normative as bytes; base58 is the platform's spelling
/// and is checked on the TypeScript side, which has an implementation of it.
fn bytes32(value: &serde_json::Value) -> [u8; 32] {
    let text = value.as_str().expect("a hex string");
    let hex = text.strip_prefix("0x").expect("a 0x prefix");
    assert_eq!(hex.len(), 64, "{text}: not 32 bytes");
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("two hex digits");
    }
    out
}

fn pubkey(value: &serde_json::Value) -> anchor_lang::prelude::Pubkey {
    anchor_lang::prelude::Pubkey::new_from_array(bytes32(value))
}

#[test]
fn v_p_12_the_client_derives_the_addresses_the_specification_states() {
    let v = vector();
    let program_id = pubkey(&v["inputs"]["program_id"]);

    let config = config_address(&program_id);
    assert_eq!(
        config.to_bytes(),
        bytes32(&v["expected"]["cm_cfg"]["address"]),
        "the log's configuration address disagrees with the one §2.4 publishes"
    );

    // §2.4 publishes the canonical bump as well, and `config_address` does not return it, so the
    // bump comes from the derivation the client's function wraps.
    let (again, bump) = anchor_lang::prelude::Pubkey::find_program_address(
        &[certimining_checkpoint::LogConfig::SEED],
        &program_id,
    );
    assert_eq!(again, config, "two calls to one derivation disagree");
    assert_eq!(
        bump.to_string(),
        v["expected"]["cm_cfg"]["bump"].as_str().expect("a bump"),
        "the canonical bump disagrees with §2.4"
    );

    let epoch: u64 = v["inputs"]["cases"][1]["epoch"]
        .as_str()
        .expect("the epoch")
        .parse()
        .expect("a u64");
    assert_eq!(
        checkpoint_address(&program_id, epoch).to_bytes(),
        bytes32(&v["expected"]["cm_ckpt"]["address"]),
        "epoch {epoch}'s checkpoint address disagrees with the vector"
    );
}

#[test]
fn v_p_12_the_order_the_specification_first_printed_is_not_what_this_derives() {
    // A negative control is only a control if it would have failed before. This is the address the
    // erroneous text produced, and the client must not produce it for the same seeds.
    let v = vector();
    let program_id = pubkey(&v["inputs"]["program_id"]);
    let erroneous = bytes32(&v["expected"]["erroneous_order"]["address"]);
    assert_ne!(
        config_address(&program_id).to_bytes(),
        erroneous,
        "the client derives the address the erroneous paragraph derived"
    );
    assert_ne!(
        checkpoint_address(&program_id, 20_723).to_bytes(),
        erroneous,
        "a checkpoint address collides with the erroneous configuration address"
    );
}
