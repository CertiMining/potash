//! §2's vendor-neutrality claim, made testable: inside the Solana runtime, `certimining-core` returns
//! what it returns natively, for every preimage the committed vectors record (issue #8's acceptance
//! criterion).
//!
//! KAT-01 already checks the five published Keccak cases through the syscall. This checks the
//! engine's own bytes: `vectors/KAT-03.txt` holds one line per preimage writer, each a preimage and
//! the digest it produces, so sending each preimage to the harness and comparing what comes back
//! compares the on-chain hasher against the committed answer. A drift in either direction fails here.
//!
//! Build the program first: `scripts/build-sbf.sh`.

use litesvm::LiteSVM;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_signer::Signer;
use solana_transaction::Transaction;

const PROGRAM: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../target/deploy/core_harness.so"
);

/// The committed fixtures, read as the core crate's own tests read them: plain text, because JSON
/// belongs to the generator (D-57).
const FIXTURES: &str = include_str!("../../../vectors/KAT-03.txt");

fn unhex(text: &str) -> Vec<u8> {
    let body = text.strip_prefix("0x").expect("hex carries its 0x prefix");
    (0..body.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&body[i..i + 2], 16).expect("a hex byte"))
        .collect()
}

#[test]
fn every_committed_preimage_hashes_the_same_inside_the_runtime() {
    let program = std::fs::read(PROGRAM)
        .unwrap_or_else(|e| panic!("{PROGRAM}: {e}. Build it first with scripts/build-sbf.sh"));
    let mut svm = LiteSVM::new();
    let program_id = Keypair::new().pubkey();
    let payer = Keypair::new();
    svm.add_program(program_id, &program)
        .expect("load the harness program");
    svm.airdrop(&payer.pubkey(), 1_000_000_000)
        .expect("fund the test payer");

    let mut checked = 0usize;
    for line in FIXTURES.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let mut fields = line.split_whitespace();
        let name = fields.next().expect("a writer's name");
        let preimage = unhex(fields.next().expect("a preimage"));
        let expected = unhex(fields.next().expect("a digest"));

        let ix = Instruction {
            program_id,
            accounts: vec![],
            data: preimage.clone(),
        };
        let message = Message::new(&[ix], Some(&payer.pubkey()));
        let tx = Transaction::new(&[&payer], message, svm.latest_blockhash());
        let result = svm
            .send_transaction(tx)
            .unwrap_or_else(|e| panic!("{name}: the runtime refused the preimage: {:?}", e.err));
        let returned = result.return_data.data.clone();
        assert_eq!(
            returned, expected,
            "{name}: the Solana runtime disagrees with the committed digest"
        );
        checked += 1;
    }

    // The fixture is the whole set of writers, so an empty or truncated file cannot pass quietly.
    assert!(
        checked >= 9,
        "only {checked} writers were checked, and the committed fixture holds more"
    );
    println!("runtime equivalence: {checked} committed preimages, identical on chain");
}
