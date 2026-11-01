# HSM key management and mainnet bootstrap runbook

Status: **offline qualification only; not authority to deploy or transact on mainnet**.

Potash publishes checkpoints to Solana; it does not contain or operate Solana validator software.
In this runbook, “node” means the Potash Anchor-B worker host. The bootstrap helper initializes that
worker's public deployment manifest. It does not create a validator identity, vote account, stake
account, or genesis ledger.

Two production seams remain and block a mainnet launch:

1. `ConsensusSignerBackend` defines the reviewed Ed25519 boundary, but this repository does not
   select or ship a vendor PKCS#11, cloud-KMS, or secure-enclave connector. The current
   `anchor-b-worker` still loads a file-backed checkpoint authority.
2. The checkpoint program has no authority-rotation instruction. `initialize` writes the authority
   once, and the program exposes only initialize, publish, and receipt attachment. An in-place key
   rotation is therefore impossible in the current protocol.

Do not start a mainnet worker until a separately reviewed provider implementation is wired into the
worker, its dependency and operational posture pass review, and the authority-rotation decision is
resolved.

## 1. Key roles and blast radius

| Role | Custody | Permitted use | Must remain separate from |
| --- | --- | --- | --- |
| Program address | Offline deployment host | Initial deploy address only | Every funded or signing role |
| Deploy/upgrade authority | Offline administrative custody | Deploy or upgrade after human approval | Worker payer and checkpoint authority |
| Worker payer | Online worker, mode-0600 file or reviewed hot-wallet service | Transaction fees only | Deploy authority and checkpoint authority |
| Checkpoint authority | Non-extractable HSM/KMS key | Raw Ed25519 signatures for checkpoint transactions | All hot, deployment, batcher, and master keys |
| Batcher signing key | Batcher host | Signed handoffs | Solana roles and `k_master` |
| `k_master` | Batcher-side secret custody | Count-hiding epoch construction | Every signing role |

The hardware-backed key is the Potash checkpoint authority, not a Solana validator consensus or vote
key. A compromised checkpoint authority can stall the log or publish garbage roots; it cannot alter
old checkpoints or replace the program. A compromised deploy authority can replace program logic and
therefore has the larger blast radius.

## 2. Provider acceptance requirements

Admit a provider only when all of these are demonstrated against its pinned production version:

- It generates or imports a **non-extractable Ed25519** private key and returns the exact 32-byte
  public key.
- It signs the exact transaction message bytes using raw Ed25519. Ed25519ph, ECDSA, RSA, message
  hashing by the provider, and algorithm fallback are refused.
- Its connector can implement `ConsensusSignerBackend::public_key` and
  `ConsensusSignerBackend::sign_ed25519` without returning private material.
- Authentication tokens, PINs, session handles, provider error strings, and key locators do not enter
  application logs. The Rust adapter exposes only closed operator-safe failure classes.
- Timeout, session exhaustion, authorization failure, missing key, and malformed signature tests all
  fail before RPC submission.
- The provider's high-availability behavior does not clone the key into an unreviewed software
  keystore.

PKCS#11 deployments must confirm raw EdDSA support in the exact module and firmware; a PKCS#11 label
alone proves nothing. Cloud KMS and secure-enclave products do not universally support Ed25519. A
provider that cannot perform the required primitive is `UnsupportedAlgorithm`, not a reason to
change the on-chain authority algorithm silently.

The opaque key reference supplied to the backend is a non-secret identifier only. Never place a PIN,
credential, access token, or private-key encoding in it.

## 3. Provision the checkpoint authority

Perform provisioning in a controlled ceremony with two operators recording the provider, firmware,
mechanism, key policy, public key, and audit-log location.

1. Enable the provider's approved authentication and audit configuration.
2. Generate a non-extractable Ed25519 key inside the device or managed service.
3. Disable export and unrestricted administrative signing.
4. Read the 32-byte public key twice through independent provider sessions.
5. Encode it as a Solana public key and enter that value as
   `CERTIMINING_CHECKPOINT_AUTHORITY_ID` in the public identity manifest.
6. Run the offline possession challenge in §5. A public-key read without a valid challenge signature
   does not prove the signing path is usable.

Never paste private bytes, a seed phrase, PIN, access token, or provider credential into this
repository, an issue, a PR, chat, shell history, or the bootstrap manifest.

## 4. Backup and recovery

Use the provider's protected backup or quorum replication mechanism only when it preserves the key's
non-extractable policy. Record the backup identifier and quorum policy outside the repository; do not
record recovery secrets here.

Before mainnet approval:

1. Restore or fail over the key in an isolated non-mainnet provider partition.
2. Re-run the exact offline possession challenge using the restored service.
3. Exercise provider outage and authorization refusal tests.
4. Confirm that the original and restored provider identities cannot sign concurrently unless the
   approved availability design explicitly requires it and audits both paths.

An untested backup is an unresolved liveness dependency.

## 5. Offline bootstrap and possession proof

Start from a clean, reviewed commit. Build the SBF artifact with the pinned toolchain:

```bash
scripts/build-sbf.sh
```

Obtain `CERTIMINING_EXPECTED_SBF_SHA256` from the independently approved release evidence, not by
trusting the checkout being qualified. Configure public identities and the hot worker payer path:

```bash
export CERTIMINING_PROFILE=mainnet
export CERTIMINING_MAINNET_ACK=offline-preflight-only
export CERTIMINING_GENESIS_HASH=5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d
export CERTIMINING_EXPECTED_SBF_SHA256='<approved 64-character lowercase SHA-256>'
export CERTIMINING_PROGRAM_ID='<compiled mainnet program address>'
export CERTIMINING_DEPLOY_AUTHORITY_ID='<offline deploy authority public key>'
export CERTIMINING_WORKER_PAYER_ID='<hot fee-payer public key>'
export CERTIMINING_CHECKPOINT_AUTHORITY_ID='<HSM Ed25519 public key>'
export CERTIMINING_BATCHER_KEY='<batcher public key, 64 lowercase hex characters>'
export CERTIMINING_HSM_PROVIDER=pkcs11  # or kms, or secure-enclave
export CERTIMINING_WORKER_PAYER=/secure/worker-payer.json
```

The pinned genesis value is the result of Solana mainnet's `getGenesisHash`. Capture the value from
an independently controlled endpoint and transfer it into this offline environment; the helper does
not contact an RPC.

Generate the exact challenge:

```bash
scripts/mainnet-bootstrap.sh challenge /secure/preflight.challenge
```

Using reviewed provider tooling, sign the exact bytes of `/secure/preflight.challenge` with raw
Ed25519 and write the 64-byte signature as 128 lowercase hexadecimal characters. Provider commands
are deliberately not invented here: the accepted command and version belong to the selected
connector's reviewed operating procedure.

```bash
export CERTIMINING_HSM_CHALLENGE=/secure/preflight.challenge
export CERTIMINING_HSM_SIGNATURE=/secure/preflight.signature.hex
scripts/mainnet-bootstrap.sh preflight
```

Preflight refuses a dirty checkout, wrong artifact hash, wrong genesis, changed public manifest,
foreign private-key variable, readable payer key, key-role collision, wrong HSM key, malformed
signature, or signature over different challenge bytes. It performs no RPC request and constructs no
transaction.

Initialize a new public-only worker-state directory after preflight:

```bash
scripts/mainnet-bootstrap.sh init /var/lib/certimining/mainnet-bootstrap
```

The command refuses an existing directory and writes only commit, artifact hash, genesis, public
identities, and provider class. It writes no key reference or credential. This is the end of the
automated bootstrap. Mainnet deployment and worker activation remain human-gated operations.

## 6. Runtime integration gate

The chosen provider adapter must construct `ConsensusSigner` with the manifest authority before the
worker starts. Construction compares the provider-reported public key to the manifest. Every call
then verifies the returned Ed25519 signature locally against the exact transaction message before
the transaction can reach the RPC.

`Cluster::publish` and `Cluster::attach` use fallible transaction signing. Provider outage, refusal,
key mismatch, or invalid signature returns `SigningFailed`; it does not panic, retry as a network
partition, or submit a zero signature.

The worker payer remains a separate `Keypair`/hot signer. Do not route payer signing through the
checkpoint HSM merely to simplify configuration, and never substitute the deploy authority for a
fee payer.

## 7. Planned rotation

The current on-chain `LogConfig.authority` is immutable. Consequently, a planned checkpoint-authority
rotation requires one of these separately specified and reviewed protocol changes:

- deploy a new program/log with the new authority and publish an explicit transition record; or
- adopt a program version with a narrowly specified rotation instruction and migration proof.

This runbook authorizes neither choice. Do not overwrite a provider alias so a new private key sits
behind the old public identity: the local signature verification will refuse it, and hiding the
identity change would destroy the audit trail.

For an approved migration, provision and preflight the new key before the cutover, stop the old
worker, reconcile the final old-log epoch, execute the reviewed transition, verify the new on-chain
authority, and retain the old public key and audit evidence permanently.

## 8. Emergency response

### Provider unavailable

1. Stop the worker; do not replace the checkpoint authority with a hot key.
2. Preserve provider and worker audit logs without credentials.
3. Reconcile the last completed epoch and record the first missed epoch.
4. Use only the tested provider recovery/failover procedure.
5. Re-run the possession challenge before restarting.

### Suspected authority compromise

1. Stop the worker and revoke provider authorization where doing so preserves evidence.
2. Treat all roots published after the last trusted provider audit event as disputed.
3. Preserve on-chain references, provider audit records, handoffs, receipts, and worker logs.
4. Do not attempt an in-place rotation; the program has no such operation.
5. Escalate for a new-log or protocol-migration decision and external security review.

### Wrong or corrupt signature

`ConsensusSigner` refuses the signature locally. Investigate provider mechanism selection, message
handling, key identity, and transport corruption. Do not retry against the RPC because no valid
transaction exists.

## 9. Verification evidence

Local qualification for this change is:

```bash
scripts/build-sbf.sh
cargo test --all-features
cargo clippy --all-features -- -D warnings
```

`crates/certimining-client/tests/hsm_signer.rs` proves the exact-message challenge, public-key pin,
closed provider failures, corrupt-signature refusal, hot-payer separation, and a LiteSVM checkpoint
signed through the mock hardware provider. Those tests prove the adapter contract, not a specific
vendor SDK, firmware, backup ceremony, or production mainnet deployment.
