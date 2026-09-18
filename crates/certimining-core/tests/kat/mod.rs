//! KAT-01's five cases, read from the Keccak team's round-3 known-answer file (D-10), which is
//! vendored byte for byte in `../data/ShortMsgKAT_256.txt`. Shared by the off-chain test in this
//! crate and the on-chain test in `programs/core-harness`.
//!
//! In that file `Len` counts bits, and `Len = 0` prints `Msg = 00` although the message is empty.

/// The message lengths, in bits, that KAT-01 names (§4.1): empty, one byte, and the 135-, 136-
/// and 137-byte cases around Keccak-256's 136-byte rate.
const LENGTHS_BITS: [usize; 5] = [0, 8, 1080, 1088, 1096];

const FILE: &str = include_str!("../data/ShortMsgKAT_256.txt");

pub struct Case {
    pub bits: usize,
    pub msg: Vec<u8>,
    pub md: [u8; 32],
}

/// The five cases, read strictly: each length must appear exactly once, with its message and
/// digest on the two lines that follow.
pub fn cases() -> Vec<Case> {
    let lines: Vec<&str> = FILE.lines().map(|l| l.trim_end_matches('\r')).collect();
    LENGTHS_BITS
        .iter()
        .map(|&bits| case(&lines, bits))
        .collect()
}

fn case(lines: &[&str], bits: usize) -> Case {
    let header = format!("Len = {bits}");
    let found: Vec<usize> = (0..lines.len()).filter(|&i| lines[i] == header).collect();
    assert_eq!(
        found.len(),
        1,
        "`{header}` must appear exactly once in the KAT file"
    );
    let msg_hex = lines[found[0] + 1]
        .strip_prefix("Msg = ")
        .expect("a Msg line follows Len");
    let md_hex = lines[found[0] + 2]
        .strip_prefix("MD = ")
        .expect("an MD line follows Msg");
    assert_eq!(bits % 8, 0, "KAT-01 uses byte-aligned lengths only");
    let msg = if bits == 0 {
        // The file prints a placeholder byte for the empty message.
        assert_eq!(msg_hex, "00", "`Len = 0` prints `Msg = 00`");
        Vec::new()
    } else {
        hex(msg_hex)
    };
    assert_eq!(
        msg.len(),
        bits / 8,
        "`{header}`: the message length disagrees with Len"
    );
    let md = hex(md_hex).try_into().expect("an MD is 32 bytes");
    Case { bits, msg, md }
}

fn hex(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0, "a hex string has an even number of digits");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("a hex digit"))
        .collect()
}
