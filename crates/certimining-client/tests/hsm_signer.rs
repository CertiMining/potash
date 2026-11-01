// SPDX-License-Identifier: MIT OR Apache-2.0
//! Deterministic controls for the external consensus-signer boundary.

#![cfg(feature = "cluster")]

use anchor_lang::{InstructionData, ToAccountMetas};
use certimining_client::crypto::{
    verify_consensus_signature, ConsensusSigner, ConsensusSignerBackend, HardwareSignerError,
    HardwareSignerProviderError,
};
use ed25519_dalek::{Signer as _, SigningKey};
use litesvm::LiteSVM;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_signer::Signer;
use solana_transaction::Transaction;

const PROGRAM_SO: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../target/deploy/certimining_checkpoint.so"
);
const KEY_REFERENCE: &str = "pkcs11:token=certimining;object=checkpoint-authority";
const EPOCH: u64 = 41_101;

#[derive(Clone, Copy)]
enum MockBehavior {
    Sign,
    Corrupt,
    Unavailable,
}

struct MockHsm {
    signing_key: SigningKey,
    behavior: MockBehavior,
}

impl MockHsm {
    fn new(seed: u8, behavior: MockBehavior) -> Self {
        Self {
            signing_key: SigningKey::from_bytes(&[seed; 32]),
            behavior,
        }
    }
}

impl ConsensusSignerBackend for MockHsm {
    fn public_key(&self, key_reference: &str) -> Result<[u8; 32], HardwareSignerProviderError> {
        if key_reference != KEY_REFERENCE {
            return Err(HardwareSignerProviderError::KeyNotFound);
        }
        Ok(self.signing_key.verifying_key().to_bytes())
    }

    fn sign_ed25519(
        &self,
        key_reference: &str,
        message: &[u8],
    ) -> Result<[u8; 64], HardwareSignerProviderError> {
        if key_reference != KEY_REFERENCE {
            return Err(HardwareSignerProviderError::KeyNotFound);
        }
        match self.behavior {
            MockBehavior::Sign => Ok(self.signing_key.sign(message).to_bytes()),
            MockBehavior::Corrupt => Ok([0x55; 64]),
            MockBehavior::Unavailable => Err(HardwareSignerProviderError::Unavailable),
        }
    }
}

fn signer(seed: u8, behavior: MockBehavior) -> ConsensusSigner<MockHsm> {
    let backend = MockHsm::new(seed, behavior);
    let public_key = backend.signing_key.verifying_key().to_bytes();
    ConsensusSigner::connect(backend, KEY_REFERENCE, public_key).expect("connect mock HSM")
}

fn metas(accounts: Vec<anchor_lang::prelude::AccountMeta>) -> Vec<solana_instruction::AccountMeta> {
    accounts
        .into_iter()
        .map(|meta| solana_instruction::AccountMeta {
            pubkey: solana_pubkey::Pubkey::from(meta.pubkey.to_bytes()),
            is_signer: meta.is_signer,
            is_writable: meta.is_writable,
        })
        .collect()
}

#[test]
fn offline_challenge_accepts_only_the_exact_key_message_and_signature() {
    let backend = MockHsm::new(0x31, MockBehavior::Sign);
    let public_key = backend.signing_key.verifying_key().to_bytes();
    let challenge = b"certimining-mainnet-preflight-v1\ncommit=abc\nartifact=def\n";
    let signature = backend
        .sign_ed25519(KEY_REFERENCE, challenge)
        .expect("mock signature");

    assert_eq!(
        verify_consensus_signature(&public_key, challenge, &signature),
        Ok(())
    );
    assert_eq!(
        verify_consensus_signature(&public_key, b"different", &signature),
        Err(HardwareSignerError::InvalidSignature)
    );
}

#[test]
fn provider_key_substitution_is_refused_at_connection() {
    let backend = MockHsm::new(0x32, MockBehavior::Sign);
    let other = SigningKey::from_bytes(&[0x33; 32]);
    assert_eq!(
        ConsensusSigner::connect(backend, KEY_REFERENCE, other.verifying_key().to_bytes()).err(),
        Some(HardwareSignerError::PublicKeyMismatch)
    );
}

#[test]
fn provider_failure_and_invalid_signature_are_typed_signer_failures() {
    let unavailable = signer(0x34, MockBehavior::Unavailable)
        .try_sign_message(b"message")
        .expect_err("unavailable HSM must fail");
    assert_eq!(
        unavailable.to_string(),
        "custom error: consensus signer: provider unavailable"
    );

    let corrupt = signer(0x35, MockBehavior::Corrupt)
        .try_sign_message(b"message")
        .expect_err("corrupt HSM response must fail");
    assert_eq!(
        corrupt.to_string(),
        "custom error: consensus signer: provider signature does not verify for the requested message"
    );
}

#[test]
fn litesvm_accepts_a_checkpoint_signed_by_the_mock_hsm_authority() {
    let program = std::fs::read(PROGRAM_SO)
        .unwrap_or_else(|error| panic!("{PROGRAM_SO}: {error}; run scripts/build-sbf.sh"));
    let mut svm = LiteSVM::new();
    svm.add_program(certimining_checkpoint::ID, &program)
        .expect("load SBF program");
    let mut clock: anchor_lang::prelude::Clock = svm.get_sysvar();
    clock.unix_timestamp = (EPOCH * certimining_checkpoint::SECONDS_PER_DAY) as i64;
    svm.set_sysvar(&clock);

    let payer = Keypair::new();
    svm.airdrop(&payer.pubkey(), 100_000_000_000)
        .expect("fund hot operator payer");
    let authority = signer(0x36, MockBehavior::Sign);
    assert_ne!(payer.pubkey(), authority.pubkey());

    let initialize = Instruction {
        program_id: certimining_checkpoint::ID,
        accounts: metas(
            certimining_checkpoint::accounts::Initialize {
                config: certimining_client::config_address(&certimining_checkpoint::ID),
                payer: anchor_lang::prelude::Pubkey::from(payer.pubkey().to_bytes()),
                system_program: anchor_lang::system_program::ID,
            }
            .to_account_metas(None),
        ),
        data: certimining_checkpoint::instruction::Initialize {
            authority: anchor_lang::prelude::Pubkey::from(authority.pubkey().to_bytes()),
            tree_height: 8,
            start_epoch: EPOCH,
        }
        .data(),
    };
    let initialize_message = Message::new(&[initialize], Some(&payer.pubkey()));
    let initialize_tx = Transaction::new(&[&payer], initialize_message, svm.latest_blockhash());
    svm.send_transaction(initialize_tx)
        .expect("initialize with hardware-backed authority identity");

    let root = [0x71; 32];
    let publish = Instruction {
        program_id: certimining_checkpoint::ID,
        accounts: metas(
            certimining_checkpoint::accounts::Publish {
                config: certimining_client::config_address(&certimining_checkpoint::ID),
                checkpoint: certimining_client::checkpoint_address(
                    &certimining_checkpoint::ID,
                    EPOCH,
                ),
                authority: anchor_lang::prelude::Pubkey::from(authority.pubkey().to_bytes()),
                payer: anchor_lang::prelude::Pubkey::from(payer.pubkey().to_bytes()),
                system_program: anchor_lang::system_program::ID,
            }
            .to_account_metas(None),
        ),
        data: certimining_checkpoint::instruction::PublishCheckpoint {
            epoch: EPOCH,
            root,
            checkpoint_bump: certimining_client::checkpoint_bump(
                &certimining_checkpoint::ID,
                EPOCH,
            ),
            end: certimining_checkpoint::NothingFollows,
        }
        .data(),
    };
    let publish_message = Message::new(&[publish], Some(&payer.pubkey()));
    let mut publish_tx = Transaction::new_unsigned(publish_message);
    publish_tx
        .try_sign(&[&payer as &dyn Signer, &authority], svm.latest_blockhash())
        .expect("mock HSM signs exact transaction message");
    svm.send_transaction(publish_tx)
        .expect("publish with separate hot payer and mock HSM authority");

    let checkpoint = svm
        .get_account(&solana_pubkey::Pubkey::from(
            certimining_client::checkpoint_address(&certimining_checkpoint::ID, EPOCH).to_bytes(),
        ))
        .expect("published checkpoint account");
    let decoded = certimining_client::decode_checkpoint(
        &anchor_lang::prelude::Pubkey::from(checkpoint.owner.to_bytes()),
        &certimining_checkpoint::ID,
        &checkpoint.data,
        EPOCH,
    )
    .expect("decode checkpoint");
    assert_eq!(decoded.root, root);
}
