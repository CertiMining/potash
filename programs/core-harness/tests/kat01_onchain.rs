//! KAT-01 on-chain (D-08): the five published cases through `sol_keccak256`, inside the Agave
//! 4.2.2 runtime (`litesvm`, D-16). Build the program first: `scripts/build-sbf.sh`.

#[path = "../../../crates/certimining-core/tests/kat/mod.rs"]
mod kat;

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

#[test]
fn kat01_on_chain_syscall() {
    // A missing build fails loudly; it never skips.
    let program = std::fs::read(PROGRAM)
        .unwrap_or_else(|e| panic!("{PROGRAM}: {e}. Build it first with scripts/build-sbf.sh"));
    let mut svm = LiteSVM::new();
    // Test-only keys, generated fresh for this run (S6).
    let program_id = Keypair::new().pubkey();
    let payer = Keypair::new();
    svm.add_program(program_id, &program)
        .expect("load the harness program");
    svm.airdrop(&payer.pubkey(), 1_000_000_000)
        .expect("fund the test payer");

    for c in kat::cases() {
        let ix = Instruction {
            program_id,
            accounts: vec![],
            data: c.msg.clone(),
        };
        let message = Message::new(&[ix], Some(&payer.pubkey()));
        let tx = Transaction::new(&[&payer], message, svm.latest_blockhash());
        let meta = svm
            .send_transaction(tx)
            .unwrap_or_else(|e| panic!("Len = {} bits: {:?}", c.bits, e.err));
        assert_eq!(
            meta.return_data.program_id, program_id,
            "the return data comes from the harness"
        );
        assert_eq!(
            meta.return_data.data, c.md,
            "sol_keccak256, Len = {} bits",
            c.bits
        );
        println!(
            "Len = {:>4} bits: match, {} compute units",
            c.bits, meta.compute_units_consumed
        );
    }
}
