//! `cargo xtask gen-demo` — E-14's fixtures, written by the engine (D-126).
//!
//! **Why the engine writes them.** The demo's Scene 2 is a counterparty verifying a package, and the
//! verifier doing that verification is the TypeScript one. A fixture the TypeScript side assembled
//! would make the scene a program checking its own output, which demonstrates nothing. These come
//! from `certimining-core` and `certimining-log`, the same code the committed vectors pin.
//!
//! **What stops a scene being tuned.** Every file is hashed into `demo/fixtures/MANIFEST.sha256` and
//! the demo refuses to run against a fixture whose hash has moved, so a package cannot be edited by
//! hand to make a verification succeed or a refusal look tidier.
//!
//! **The identifiers are synthetic and the registry code is fake by construction** — `DEMO0000` is
//! not a registry, and the tenure spelling says so. §4.4's V-Z-05 forbids a real tenure, jurisdiction
//! or registry value in a disclosure package, and a demo is read by more people than the test suite.

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use certimining_core::{
    AssetChain, AssetId, AssetIdentity, ChainState, Digest, GenesisHeadPreimage, Hasher,
    LeafPreimage, NativeKeccak, PayloadUri, Preimage, PreimageBuf, RecordLeafInput, SubmissionId,
};
use certimining_log::{BuiltEpoch, EpochTree, InclusionVerifier, ProofVerifier};
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::{json, Map, Value};

use crate::repo_root;

type Chain = AssetChain<NativeKeccak, certimining_core::DalekVerifier>;

/// RFC 8032 §7.1's TEST 1 secret key, whose public half every fixture carries as `qp_key`. Its
/// private half is published in the RFC, which is the whole point: D-127 requires the demo to say so
/// wherever the key appears, so that nobody reads it as a qualified person's identity.
const RFC8032_SECRET_KEY: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];

/// A jurisdiction that exists and a registry code that does not. The tenure spelling carries the word
/// so a reader meeting it out of context still knows.
const DEMO_J: &[u8; 4] = b"CABC";
const DEMO_R: &[u8; 8] = b"DEMO0000";
const DEMO_TENURE: &str = "demo-tenure 0001-x";

const DEMO_EPOCH: u64 = 20_723;
const DEMO_HEIGHT: u8 = 8;
/// The batcher's master key. **In a deployment this never leaves the batcher** (INV-STATE-03,
/// RES-03); here it is published so Scene 1 can build epochs in front of a viewer, and the demo says
/// so on screen rather than leaving a reader to assume a key like this is normally publishable.
const DEMO_MASTER_KEY: Digest = [0x5a; 32];

const FILE_MODE: u32 = 0o644;

/// Where Scene 3's alteration lands: §1.3's preimage puts the tag at 0, `c` at 8, `seq` at 40 and
/// `payload_digest` at 48.
const TAMPERED_OFFSET: usize = 48;

const KEY_NOTE: &str = "qp_key is the public half of RFC 8032 §7.1's TEST 1 key, whose private half that document publishes. It stands for no qualified person and credentials nobody (RES-04).";
const REGISTRY_NOTE: &str = "The tenure identifier, jurisdiction and registry code are synthetic. DEMO0000 is not a registry.";
const KEY_CUSTODY_NOTE: &str = "master_key is published here so the page can build epochs live. In a deployment the epoch key never leaves the batcher (INV-STATE-03, RES-03).";

pub fn gen_demo(dir: &Path) {
    if dir.exists() {
        let existing: Vec<String> = fs::read_dir(dir)
            .expect("the fixture directory can be read")
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| !n.starts_with('.'))
            .collect();
        // A refusal with the command that actually works, rather than an assertion that leaves a
        // reader with a panic. The bare `cargo xtask gen-demo` was cited as reproduction evidence in
        // the PR body, in D-126 and on the page, and on a clean clone it cannot run: the committed
        // fixtures are already there. Regeneration is a *comparison*, so it writes somewhere else and
        // diffs, which is what the `vectors` group does.
        if !existing.is_empty() {
            eprintln!(
                "gen-demo: {} already holds {}.\n\
                 \n\
                 The committed fixtures are not overwritten, because regenerating is how they are\n\
                 checked rather than how they are replaced. To check them:\n\
                 \n\
                     scripts/ci.sh vectors\n\
                 \n\
                 which generates into a temporary directory and diffs. To regenerate deliberately,\n\
                 give a destination and compare yourself:\n\
                 \n\
                     cargo xtask gen-demo \"$(mktemp -d)/demo\"\n",
                dir.display(),
                existing.join(", ")
            );
            std::process::exit(2);
        }
    }
    fs::create_dir_all(dir).expect("the fixture directory can be created");

    let tenure = AssetId::<NativeKeccak>::canonicalize(DEMO_TENURE).expect("a canonical tenure");
    let commitment =
        AssetId::<NativeKeccak>::commitment(DEMO_J, DEMO_R, &tenure).expect("a commitment");
    let genesis = digest_of(&GenesisHeadPreimage {
        asset_commitment: commitment,
        schema_version: 1,
    });

    // Three records, so the package the demo ships is not the one case a single package can settle by
    // itself. At `seq` 1 a verifier can pin `prev_head` to the genesis head; past it nothing in the
    // package does, and the report says so. The demo shows that line rather than choosing a fixture
    // that avoids it.
    let mut chain = Chain::start(&commitment, 1).expect("the chain starts");
    let mut records: Vec<RecordLeafInput> = Vec::new();
    let mut heads: Vec<Digest> = vec![genesis];
    for (seq, category) in [(1u64, 0u8), (2, 1), (3, 2)] {
        let record = signed_record(&chain, seq, category, 1_700_000_000 + (seq as i64) * 86_400);
        let _ = chain.apply(&record).expect("the record is accepted");
        heads.push(chain.head());
        records.push(record);
    }

    let last = records.last().expect("three records");
    let preimage = leaf_preimage_of(&commitment, last);
    let leaf = NativeKeccak::hashv(&[&preimage]);
    let submission_id: SubmissionId = {
        let mut id = [0u8; 16];
        id[..8].copy_from_slice(&3u64.to_le_bytes());
        id
    };
    let built = <BuiltEpoch as EpochTree>::build::<NativeKeccak>(
        DEMO_EPOCH,
        DEMO_HEIGHT,
        &DEMO_MASTER_KEY,
        &[(submission_id, leaf)],
    )
    .expect("the epoch builds");
    let proof = built.proof(&submission_id).expect("the epoch holds it");

    // Generation fails rather than writing a package a verifier would refuse: the proof has to verify
    // against the root this fixture also ships, and carry exactly `H` siblings.
    assert_eq!(
        proof.siblings.len(),
        DEMO_HEIGHT as usize,
        "a proof at H = {DEMO_HEIGHT} must carry {DEMO_HEIGHT} siblings"
    );
    assert!(
        <ProofVerifier as InclusionVerifier>::verify::<NativeKeccak>(&leaf, &proof, &built.root)
            .is_ok(),
        "the proof does not verify against the root this fixture ships"
    );

    let package = disclosure_json(last, &preimage, heads[2], heads[3], genesis, &proof);

    // Scene 3's input. One byte of the signed preimage is flipped and nothing else moves, so the
    // failure a viewer sees is the one §1.3's condition (c) describes rather than a malformed file.
    // §1.3's preimage puts the tag at 0, `c` at 8, `seq` at 40 and `payload_digest` at 48. Byte 48 is
    // altered in the preimage **and** in the JSON that displays it, which is what an alteration
    // actually looks like: a file whose two halves disagree is caught by the JSON/Borsh check before
    // any signature is examined, and that would demonstrate the weaker of the two things. Altered
    // consistently, the package is internally coherent and the **signature** is what refuses it.
    let tampered = {
        let mut bytes = preimage.clone();
        bytes[TAMPERED_OFFSET] ^= 0x01;
        let mut altered_digest = last.payload_digest;
        altered_digest[0] ^= 0x01;
        let mut map = package.as_object().expect("an object").clone();
        map.insert("preimage_borsh".into(), json!(base64(&bytes)));
        let mut record = map["record"].as_object().expect("an object").clone();
        record.insert("payload_digest".into(), json!(hex(&altered_digest)));
        map.insert("record".into(), Value::Object(record));
        Value::Object(map)
    };

    let root = json!({
        "epoch": DEMO_EPOCH.to_string(),
        "height": DEMO_HEIGHT.to_string(),
        "root": hex(&built.root),
        "master_key": hex(&DEMO_MASTER_KEY),
        "asset_commitment": hex(&commitment),
        "genesis_head": hex(&genesis),
        "heads": heads.iter().map(|h| hex(h)).collect::<Vec<String>>(),
        "_notes": [
            "A counterparty obtains a root from Solana, independently of the package. This file stands in for that fetch so the demo runs offline.",
            "asset_commitment and genesis_head are here for the page to display the chain; INV-STATE-03 keeps the commitment off chain, and a real counterparty gets it from inside the package's signed preimage.",
            KEY_CUSTODY_NOTE,
            REGISTRY_NOTE,
        ],
    });

    let sidecar = {
        let tenure_text = core::str::from_utf8(tenure.as_slice()).expect("ASCII");
        let j = core::str::from_utf8(DEMO_J).expect("ASCII");
        let r = core::str::from_utf8(DEMO_R).expect("ASCII");
        let mut s = String::new();
        s.push_str("# E-14 demo fixtures\n\n");
        s.push_str("Generated by `cargo xtask gen-demo`. Every file here is hashed in `MANIFEST.sha256`, and the\n");
        s.push_str("demo refuses to run when a hash has moved, so a scene cannot be tuned by editing a fixture.\n\n");
        s.push_str("## The signing key\n\n");
        s.push_str(KEY_NOTE);
        s.push_str("\n\n## The identifiers\n\n");
        s.push_str(REGISTRY_NOTE);
        s.push_str(&format!(
            " The canonical tenure is `{tenure_text}`, from the raw spelling `{DEMO_TENURE}`, under\njurisdiction `{j}` and registry `{r}`.\n\n"
        ));
        s.push_str("## The epoch key\n\n");
        s.push_str(KEY_CUSTODY_NOTE);
        s.push_str("\n\n## Why the packages carry no notes of their own\n\n");
        s.push_str("\u{a7}2.5 fixes what a disclosure package contains and INV-DISC-01 makes that list closed. A\n");
        s.push_str("conforming verifier refuses the first field the section does not list, so a note added to\n");
        s.push_str("`disclosure.json` would make it unverifiable. The labels are therefore here, in a file the\n");
        s.push_str("manifest covers, rather than inside the packages.\n\n");
        s.push_str("## What each file is\n\n");
        s.push_str("- `disclosure.json` \u{2014} a \u{a7}2.5 package for the third record of a three-record chain. Past\n");
        s.push_str("  `seq` 1 nothing in a package pins `prev_head`, so a verifier reports the chain position as not\n");
        s.push_str("  established. The demo shows that line rather than shipping a `seq` 1 package that avoids it.\n");
        s.push_str(&format!(
            "- `tampered.json` — the same package with the low bit of `payload_digest` flipped: byte\n  {TAMPERED_OFFSET} of the preimage, and the hex the JSON displays beside it. The two halves still agree,\n  so what refuses this package is the QP signature rather than an internal inconsistency.\n"
        ));
        s.push_str("- `root.json` \u{2014} the epoch root a counterparty fetches from Solana, so the demo runs offline,\n");
        s.push_str("  with the chain's heads for display.\n\n");
        s.push_str("## The anchor block is a placeholder\n\n");
        s.push_str(
            "This epoch was built for the demo and published nowhere, so `anchor.solana_tx`,\n",
        );
        s.push_str("`anchor.solana_slot` and `anchor.ots_receipt_digest` are visibly empty values rather than a\n");
        s.push_str("real transaction. \u{a7}2.5 carries that block and nothing in the section says how a verifier\n");
        s.push_str("checks it (SPEC-DEFECTS.md SD-12), so the verifier does not, and the page says so. The\n");
        s.push_str("announced log's own anchoring is real and is recorded in `docs/anchoring.md`; it does not\n");
        s.push_str("belong in a fixture whose root it does not anchor.\n");
        s
    };

    let mut files: BTreeMap<String, Value> = BTreeMap::new();
    files.insert("disclosure.json".into(), package);
    files.insert("tampered.json".into(), tampered);
    files.insert("root.json".into(), root);

    // The rule this unit's own review produced, applied to the artifacts that produced it — and to
    // the pages beside them. A review put a listed program id into `demo/app.js` and watched
    // `gen-demo` succeed, because a generator inspects what it writes and nothing else. Running the
    // surface scan here as well means the command that produces fixtures cannot report success over a
    // tree carrying a live value somewhere it never looked.
    crate::live_values::check_list_shape(&repo_root());
    crate::live_values::check_synthetic_surface(&repo_root());
    let mut pending: Vec<(String, String)> = files
        .iter()
        .map(|(name, value)| (name.clone(), to_text(value)))
        .collect();
    pending.push(("README.md".to_string(), sidecar.clone()));
    crate::live_values::refuse_live_values(&repo_root(), &pending);

    let mut manifest = String::new();
    for (name, value) in &files {
        let text = to_text(value);
        let path = dir.join(name);
        fs::write(&path, &text).expect("a fixture can be written");
        fs::set_permissions(&path, fs::Permissions::from_mode(FILE_MODE))
            .expect("the mode can be set");
        manifest.push_str(&format!(
            "{}  {:04o}  {}\n",
            sha256_hex(text.as_bytes()),
            FILE_MODE,
            name
        ));
    }
    {
        let name = "README.md";
        let path = dir.join(name);
        fs::write(&path, &sidecar).expect("the sidecar can be written");
        fs::set_permissions(&path, fs::Permissions::from_mode(FILE_MODE))
            .expect("the mode can be set");
        manifest.push_str(&format!(
            "{}  {:04o}  {}\n",
            sha256_hex(sidecar.as_bytes()),
            FILE_MODE,
            name
        ));
    }
    let mut lines: Vec<&str> = manifest.lines().collect();
    lines.sort_by_key(|l| l.split_whitespace().last().unwrap_or(""));
    let manifest = lines.join("\n") + "\n";

    let manifest_path = dir.join("MANIFEST.sha256");
    fs::write(&manifest_path, &manifest).expect("the manifest can be written");
    fs::set_permissions(&manifest_path, fs::Permissions::from_mode(FILE_MODE))
        .expect("the mode can be set");

    println!(
        "wrote {} fixtures and MANIFEST.sha256 to {}",
        files.len(),
        dir.display()
    );
    for name in files.keys() {
        println!("  {name}");
    }
}

fn disclosure_json(
    r: &RecordLeafInput,
    preimage: &[u8],
    prev_head: Digest,
    head: Digest,
    genesis: Digest,
    proof: &certimining_log::InclusionProof,
) -> Value {
    let mut record = Map::new();
    record.insert("seq".into(), json!(r.seq.to_string()));
    record.insert("category".into(), json!(r.category));
    record.insert("effective_at".into(), json!(r.effective_at.to_string()));
    record.insert(
        "change_identified_at".into(),
        json!(r.change_identified_at.to_string()),
    );
    record.insert("payload_digest".into(), json!(hex(&r.payload_digest)));
    record.insert("assessment_digest".into(), json!(hex(&r.assessment_digest)));
    record.insert("qp_key".into(), json!(hex(&r.qp_key)));
    record.insert(
        "payload_uri".into(),
        json!(std::str::from_utf8(r.payload_uri.as_slice()).expect("ASCII")),
    );
    record.insert("flags".into(), json!(0));

    json!({
        "schema": "certimining/v1/disclosure",
        "record": Value::Object(record),
        "preimage_borsh": base64(preimage),
        "chain": {
            "prev_head": hex(&prev_head),
            "head": hex(&head),
            "genesis": hex(&genesis),
        },
        "qp_signature": hex(r.signature.as_ref().expect("signed")),
        "inclusion": {
            "epoch": proof.epoch.to_string(),
            "height": proof.height,
            "slot_index": proof.slot_index,
            "siblings": proof.siblings.iter().map(|s| hex(s)).collect::<Vec<String>>(),
        },
        // §2.5's anchor block carries provenance that nothing in a package says how to check (SD-12),
        // and this epoch was never published anywhere: it is built here for the demo. **The values are
        // therefore placeholders and are visibly so.** An earlier version of this file carried the
        // announced log's real transaction, slot and receipt digest beside this synthetic root, which
        // asserted an anchoring that had never happened — the transaction named there published epoch
        // 20723's root, not this one. A fixture may not claim provenance it does not have, however
        // much more concrete it looks.
        "anchor": {
            "solana_tx": "1".repeat(64),
            "solana_slot": 0u64,
            "ots_receipt_digest": format!("0x{}", "00".repeat(32)),
        },
    })
}

/// A record signed over its own leaf preimage with the published test key.
fn signed_record(chain: &Chain, seq: u64, category: u8, effective_at: i64) -> RecordLeafInput {
    let key = SigningKey::from_bytes(&RFC8032_SECRET_KEY);
    let mut record = RecordLeafInput {
        prev_head: chain.head(),
        seq,
        payload_digest: {
            let mut d = [0u8; 32];
            d[0] = 0xd0;
            d[1] = seq as u8;
            d
        },
        assessment_digest: {
            let mut d = [0u8; 32];
            d[0] = 0xa0;
            d[1] = seq as u8;
            d
        },
        qp_key: key.verifying_key().to_bytes(),
        expected_qp_key: None,
        signature: None,
        category,
        effective_at,
        change_identified_at: effective_at - 86_400,
        payload_uri: PayloadUri::from_slice(b"ipfs://bafydemopayloadplaceholder").expect("fits"),
        ext_commitment: None,
    };
    let bytes = leaf_preimage_of(&chain.asset_commitment(), &record);
    record.signature = Some(key.sign(&bytes).to_bytes());
    record
}

fn leaf_preimage_of(commitment: &Digest, r: &RecordLeafInput) -> Vec<u8> {
    let mut buf = PreimageBuf::new();
    LeafPreimage {
        asset_commitment: *commitment,
        seq: r.seq,
        payload_digest: r.payload_digest,
        assessment_digest: r.assessment_digest,
        qp_key: r.qp_key,
        category: r.category,
        effective_at: r.effective_at,
        change_identified_at: r.change_identified_at,
    }
    .write_preimage(&mut buf)
    .expect("the preimage fits");
    buf.as_bytes().to_vec()
}

fn digest_of<P: Preimage>(p: &P) -> Digest {
    let mut buf = PreimageBuf::new();
    p.write_preimage(&mut buf).expect("the preimage fits");
    NativeKeccak::hashv(&[buf.as_bytes()])
}

/// Base64 with the standard alphabet and padding, for `preimage_borsh`.
///
/// Written out rather than depended on, for the same reason §2.4's base58 is: it is a platform
/// encoding that the specification does not define, and the bytes it encodes are checked against a
/// digest on both sides, so a wrong encoder fails a test rather than producing a plausible fixture.
fn base64(bytes: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(A[(n >> 18) as usize & 63] as char);
        out.push(A[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            A[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            A[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(2 + bytes.len() * 2);
    s.push_str("0x");
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest as _, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// Two-space indentation, LF endings, a trailing newline, the same shape `vectors/` uses (D-53).
fn to_text(value: &Value) -> String {
    let mut text = serde_json::to_string_pretty(value).expect("a fixture serializes");
    text.push('\n');
    text
}
