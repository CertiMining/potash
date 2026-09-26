// SPDX-License-Identifier: MIT OR Apache-2.0
//! KAT-02's five cases, read from RFC 8032 §7.1 (D-45), vendored byte for byte in
//! `../data/rfc8032_7.1.txt`.
//!
//! Each case gives a secret key, the public key it derives, a message and the signature. The file
//! prints hex in 16-byte lines, and a message of length 0 prints nothing at all.

const FILE: &str = include_str!("../data/rfc8032_7.1.txt");

/// How many vectors §7.1 holds: the empty message, one byte, two bytes, 1,023 bytes, and
/// SHA-512("abc").
const EXPECTED_CASES: usize = 5;

pub struct Case {
    pub name: String,
    pub secret_key: [u8; 32],
    pub public_key: [u8; 32],
    pub message: Vec<u8>,
    pub signature: [u8; 64],
}

/// The five cases, read strictly: every field must be present, every length must be what the RFC
/// declares, and the file must hold exactly five vectors.
pub fn cases() -> Vec<Case> {
    let lines: Vec<&str> = FILE.lines().map(|l| l.trim_end_matches('\r')).collect();
    let starts: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, l)| l.trim_start().starts_with("-----TEST"))
        .map(|(i, _)| i)
        .collect();
    assert_eq!(
        starts.len(),
        EXPECTED_CASES,
        "RFC 8032 §7.1 must hold {EXPECTED_CASES} vectors"
    );
    starts
        .iter()
        .enumerate()
        .map(|(n, &start)| {
            let end = starts.get(n + 1).copied().unwrap_or(lines.len());
            case(&lines[start..end])
        })
        .collect()
}

fn case(block: &[&str]) -> Case {
    let name = block[0].trim().trim_start_matches('-').trim().to_string();
    let secret_key = fixed::<32>(&hex_after(block, "SECRET KEY:"), &name, "secret key");
    let public_key = fixed::<32>(&hex_after(block, "PUBLIC KEY:"), &name, "public key");
    let signature = fixed::<64>(&hex_after(block, "SIGNATURE:"), &name, "signature");

    let (declared, message) = message_of(block, &name);
    assert_eq!(
        message.len(),
        declared,
        "{name}: the message is not the length the RFC declares"
    );

    Case {
        name,
        secret_key,
        public_key,
        message,
        signature,
    }
}

/// The hex that follows `label`, joined across the lines the RFC wraps it over.
fn hex_after(block: &[&str], label: &str) -> Vec<u8> {
    let at = block
        .iter()
        .position(|l| l.trim() == label)
        .unwrap_or_else(|| panic!("{label} is missing from a vector"));
    hex_from(block, at)
}

/// Collects hex from the line after `at` until a line that is neither hex nor page furniture.
///
/// The 1,023-byte message runs across a page boundary, so blank lines, the page footer, a form
/// feed and the running header all sit in the middle of it. Those are skipped; the next label ends
/// the field.
fn hex_from(block: &[&str], at: usize) -> Vec<u8> {
    let mut hex = String::new();
    for line in block.iter().skip(at + 1) {
        let text = line.trim();
        let furniture = text.is_empty()
            || text.contains("[Page")
            || text.starts_with("RFC 8032")
            || text.starts_with("Josefsson");
        if furniture {
            continue;
        }
        if !text.chars().all(|c| c.is_ascii_hexdigit()) {
            break;
        }
        hex.push_str(text);
    }
    decode(&hex)
}

/// The message, with the byte count the RFC prints in its label.
fn message_of(block: &[&str], name: &str) -> (usize, Vec<u8>) {
    let at = block
        .iter()
        .position(|l| l.trim().starts_with("MESSAGE (length "))
        .unwrap_or_else(|| panic!("{name}: no MESSAGE label"));
    let label = block[at].trim();
    // The RFC writes "1 byte" and "2 bytes", so read the count rather than trimming a suffix.
    let declared: usize = label
        .trim_start_matches("MESSAGE (length ")
        .split_whitespace()
        .next()
        .unwrap_or_else(|| panic!("{name}: the MESSAGE label carries no length"))
        .parse()
        .unwrap_or_else(|e| panic!("{name}: cannot read the declared length: {e}"));

    (declared, hex_from(block, at))
}

fn decode(hex: &str) -> Vec<u8> {
    assert!(hex.len().is_multiple_of(2), "hex must have an even length");
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex digit"))
        .collect()
}

fn fixed<const N: usize>(bytes: &[u8], name: &str, what: &str) -> [u8; N] {
    <[u8; N]>::try_from(bytes)
        .unwrap_or_else(|_| panic!("{name}: the {what} is {} bytes, not {N}", bytes.len()))
}
