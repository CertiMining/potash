//! E-05: the vector generator.
//!
//! `cargo xtask gen-vectors` writes `vectors/*.json` and `vectors/MANIFEST.sha256`. Every value in
//! a vector comes from the engine itself, so a vector is what the engine produces rather than a
//! second opinion about it. Vectors are generated artifacts and are never edited by hand: CI
//! verifies the manifest and regenerates the set to compare it with what is committed (D-56).
//!
//! Rules this tool follows:
//! - Positive and negative vectors alike, for every vector whose inputs exist (D-51).
//! - **A negative vector's expected code comes from the specification, not from the engine.** The
//!   code is written here from §4.3's table; the engine is then run and generation fails if it
//!   disagrees. A generator that recorded whatever the engine returned would enshrine an engine's
//!   mistake as the correct answer, and E-11 would be forced to reproduce it. The same applies to
//!   the assertions §4.2 makes about positive vectors: those are checked, not recorded.
//! - Byte strings as `0x`-prefixed lowercase hex; 64-bit integers as decimal strings, because
//!   E-11's verifier is JavaScript and a JSON number is a double (D-52).
//! - Nothing environmental in a file: no timestamps, no toolchain versions, no paths (D-53).
//! - Every hashing step records its preimage as well as its digest (D-58).
//!
//! Being a tool rather than shipped code, this crate may panic: a generator that cannot produce a
//! vector must stop loudly, and INV-ERR-01's gates stay on the library and program crates (D-21).

mod spec;

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use certimining_core::{
    epoch_key, padding_prf, slot_seed, AssetChain, AssetId, AssetIdentity, ChainSnapshot,
    ChainState, Digest, GenesisHeadPreimage, Hasher, LeafPreimage, NativeKeccak, NodePreimage,
    PaddingPreimage, PayloadUri, Preimage, PreimageBuf, PrfPreimage, RealLeafPreimage,
    RecordLeafInput, RegistryError, SpiPreimage, StepHeadPreimage, SubmissionId,
    FLAG_RESERVE_WITHOUT_PRIOR_RESOURCE,
};
use certimining_log::{BuiltEpoch, EpochTree, InclusionProof, InclusionVerifier, ProofVerifier};
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Map, Value};

/// RFC 8032 §7.1's first secret key. Its private half is published, so anyone can reproduce every
/// signature in this set, and no generated or real key is ever committed (D-55).
const RFC8032_SECRET_KEY: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];

const TEST_KEY_NOTE: &str =
    "The qualified person's key is RFC 8032 §7.1's published specification test key, not a real \
     identity. Its private half is public, so every signature here is reproducible.";

const J: &[u8; 4] = b"CABC";
const R: &[u8; 8] = b"MTO00001";
const TENURE_RAW: &str = "bc-tenure 1043-a";
const PAYLOAD_DIGEST: Digest = [0x22; 32];
const ASSESSMENT_DIGEST: Digest = [0x33; 32];
const PAYLOAD_URI: &str = "ipfs://bafyexamplepayload";
const FIRST_EFFECTIVE_AT: i64 = 1_700_000_000;

/// Every artifact is written with this mode, and the manifest records it.
const FILE_MODE: u32 = 0o644;

type Chain = AssetChain<NativeKeccak, certimining_core::DalekVerifier>;

fn main() {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        // An optional destination lets a check regenerate into a temporary directory without
        // touching the working tree (D-56).
        Some("gen-vectors") => {
            let dir = args
                .next()
                .map(PathBuf::from)
                .unwrap_or_else(|| repo_root().join("vectors"));
            gen_vectors(&dir);
        }
        other => {
            eprintln!("usage: cargo xtask gen-vectors [destination directory]");
            if let Some(cmd) = other {
                eprintln!("unknown command: {cmd}");
            }
            std::process::exit(2);
        }
    }
}

/// The repository root, from this crate's manifest directory.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask sits one level below the repository root")
        .to_path_buf()
}

fn gen_vectors(dir: &Path) {
    // The generator never deletes anything. It creates the directory it writes to, and refuses one
    // that already holds files, so replacing a committed set is a deliberate act by whoever removes
    // the old one. There is no flag to override this.
    if dir.exists() {
        let mut entries = fs::read_dir(dir).expect("the destination can be read");
        if entries.next().is_some() {
            eprintln!(
                "{} already holds files, and this tool never deletes.",
                dir.display()
            );
            eprintln!("Remove the directory yourself, then run the command again:");
            eprintln!("    rm -rf {} && cargo xtask gen-vectors", dir.display());
            std::process::exit(2);
        }
    } else {
        fs::create_dir_all(dir).expect("the destination can be created");
    }

    check_spec_agreement();

    let mut files: BTreeMap<String, Value> = BTreeMap::new();
    positives(&mut files);
    negatives(&mut files);
    trees(&mut files);
    kat03_fixtures(&mut files);

    let mut manifest = String::new();
    let write = |name: &str, text: &str, manifest: &mut String| {
        let path = dir.join(name);
        fs::write(&path, text).expect("a vector can be written");
        // The mode is set rather than inherited, so a machine with a different umask produces the
        // same artifact (D-53), and it is recorded, so a file that later became executable or
        // unreadable is a change the manifest catches.
        fs::set_permissions(&path, fs::Permissions::from_mode(FILE_MODE))
            .expect("the mode can be set");
        manifest.push_str(&format!(
            "{}  {:04o}  {}\n",
            sha256_hex(text.as_bytes()),
            FILE_MODE,
            name
        ));
    };

    for (name, value) in &files {
        write(name, &to_text(value), &mut manifest);
    }
    // KAT-03 also lands as plain text: the core crate's tests read these bytes, and JSON stays in
    // this tool (D-57). Both forms come from the same run, so they cannot drift apart.
    write(
        "KAT-03.txt",
        &kat03_plain(&files["KAT-03.json"]),
        &mut manifest,
    );

    let mut lines: Vec<&str> = manifest.lines().collect();
    lines.sort_by_key(|l| l.split_whitespace().last().unwrap_or(""));
    let manifest = lines.join("\n") + "\n";
    let manifest_path = dir.join("MANIFEST.sha256");
    fs::write(&manifest_path, &manifest).expect("the manifest can be written");
    fs::set_permissions(&manifest_path, fs::Permissions::from_mode(FILE_MODE))
        .expect("the mode can be set");

    println!(
        "wrote {} vectors, KAT-03.txt and MANIFEST.sha256 to {}",
        files.len(),
        dir.display()
    );
    for name in files.keys() {
        println!("  {name}");
    }
}

/// The engine is checked against the values transcribed from the specification before anything is
/// written. A disagreement stops generation: the committed set must never record the engine's
/// opinion of a value the specification states.
fn check_spec_agreement() {
    let tags: [(&str, &[u8; 8], [u8; 8]); 7] = [
        ("TAG_ASSET", spec::TAG_ASSET, certimining_core::TAG_ASSET),
        ("TAG_LEAF", spec::TAG_LEAF, certimining_core::TAG_LEAF),
        ("TAG_HEAD", spec::TAG_HEAD, certimining_core::TAG_HEAD),
        ("TAG_MTL0", spec::TAG_MTL0, certimining_core::TAG_MTL0),
        ("TAG_MTN1", spec::TAG_MTN1, certimining_core::TAG_MTN1),
        ("TAG_PAD", spec::TAG_PAD, certimining_core::TAG_PAD),
        ("TAG_SPI", spec::TAG_SPI, certimining_core::TAG_SPI),
    ];
    for (name, from_spec, from_engine) in tags {
        assert_eq!(
            &from_engine[..],
            &from_spec[..],
            "{name}: the engine has {:?} where §1.2 gives {:?}",
            core::str::from_utf8(&from_engine).unwrap_or("<not ascii>"),
            core::str::from_utf8(from_spec).unwrap_or("<not ascii>")
        );
    }

    assert_eq!(
        certimining_core::TAG_PRF,
        *spec::TAG_PRF,
        "TAG_PRF: §1.2's tag for the PRF"
    );
    for (name, from_spec, from_engine) in [
        (
            "PRF_USE_EPOCH_KEY",
            spec::PRF_USE_EPOCH_KEY,
            certimining_core::PRF_USE_EPOCH_KEY,
        ),
        (
            "PRF_USE_SLOT",
            spec::PRF_USE_SLOT,
            certimining_core::PRF_USE_SLOT,
        ),
        (
            "PRF_USE_PADDING",
            spec::PRF_USE_PADDING,
            certimining_core::PRF_USE_PADDING,
        ),
    ] {
        assert_eq!(
            from_engine, from_spec,
            "{name}: §1.1 gives 0x{from_spec:02X} and the engine has 0x{from_engine:02X}"
        );
    }
    assert_eq!(
        (certimining_log::MIN_HEIGHT, certimining_log::MAX_HEIGHT),
        (spec::MIN_HEIGHT, spec::MAX_HEIGHT),
        "§1.8's range for the tree height"
    );
    assert_eq!(
        1usize << spec::DEPLOYED_HEIGHT,
        spec::DEPLOYED_CAPACITY,
        "§1.4: C = 2^H, and this deployment ships H = 8"
    );

    let canonical = AssetId::<NativeKeccak>::canonicalize(TENURE_RAW).expect("canonical");
    assert_eq!(
        core::str::from_utf8(&canonical).expect("A-Z and 0-9"),
        spec::V_P_01_CANONICAL,
        "V-P-01: §4.2 gives {} as the canonical form of {TENURE_RAW:?}",
        spec::V_P_01_CANONICAL
    );

    assert_eq!(
        certimining_core::MAX_TENURE_LEN,
        spec::MAX_TENURE_LEN,
        "§1.8's tenure limit"
    );
    assert_eq!(
        certimining_core::MAX_RAW_TENURE_LEN,
        spec::MAX_RAW_TENURE_LEN,
        "§1.8's raw tenure limit"
    );
    assert_eq!(
        certimining_core::MAX_PAYLOAD_URI_LEN,
        spec::MAX_PAYLOAD_URI_LEN,
        "§1.8's payload URI limit"
    );
    assert_eq!(
        certimining_core::SCHEMA_VERSION,
        spec::SCHEMA_VERSION,
        "§1.3's schema version"
    );
}

// ---------------------------------------------------------------- positive vectors (§4.2)

fn positives(files: &mut BTreeMap<String, Value>) {
    let tenure = AssetId::<NativeKeccak>::canonicalize(TENURE_RAW).expect("canonical");
    let commitment =
        AssetId::<NativeKeccak>::commitment(J, R, &tenure).expect("the commitment is defined");
    let asset_preimage = preimage_of(&certimining_core::AssetPreimage {
        jurisdiction: J,
        registry: R,
        tenure: &tenure,
    });

    // §4.2's claim is that the two spellings agree. The generator checks it; a disagreement stops
    // generation rather than being written down as the answer.
    let tenure_b = AssetId::<NativeKeccak>::canonicalize("BC_TENURE1043A").expect("canonical");
    assert_eq!(
        tenure.as_slice(),
        tenure_b.as_slice(),
        "V-P-01: §4.2 requires one canonical form from both spellings"
    );
    let commitment_b = AssetId::<NativeKeccak>::commitment(J, R, &tenure_b).expect("defined");
    assert_eq!(
        commitment, commitment_b,
        "V-P-01: §4.2 requires one commitment from both spellings"
    );

    files.insert(
        "V-P-01.json".into(),
        vector(
            "V-P-01",
            "§4.2",
            "Two spellings of one tenure identifier give the same canonical form and the same asset commitment.",
            json!({
                "raw_tenure_a": TENURE_RAW,
                "raw_tenure_b": "BC_TENURE1043A",
                "jurisdiction": hex(J),
                "registry": hex(R),
            }),
            json!({
                "canonical_tenure": String::from_utf8(tenure.to_vec()).expect("A-Z and 0-9"),
                "asset_commitment_preimage": hex(&asset_preimage),
                "asset_commitment": hex(&commitment),
            }),
            &[],
        ),
    );

    let genesis = Chain::genesis(&commitment, 1).expect("schema 1");
    files.insert(
        "V-P-02.json".into(),
        vector(
            "V-P-02",
            "§4.2",
            "Genesis for a known asset commitment under schema 1.",
            json!({ "asset_commitment": hex(&commitment), "schema_version": "1" }),
            json!({
                "genesis_preimage": hex(&preimage_of(&GenesisHeadPreimage {
                    asset_commitment: commitment,
                    schema_version: 1,
                })),
                "genesis_head": hex(&genesis),
            }),
            &[],
        ),
    );

    // A chain of five records, categories 0 to 4 (V-P-03), with every step recorded.
    let mut chain = Chain::start(&commitment, 1).expect("starts");
    let mut steps = Vec::new();
    let mut snapshot_at_two = None;
    for seq in 1..=5u64 {
        let category = u8::try_from(seq - 1).expect("0 to 4");
        let record = signed_record(
            &chain,
            seq,
            category,
            FIRST_EFFECTIVE_AT + i64::from(category),
        );
        let leaf_preimage = leaf_preimage_of(&chain, &record);
        let previous_head = chain.head();
        let applied = chain.apply(&record).expect("accepted");
        steps.push(json!({
            "seq": seq.to_string(),
            "record": record_json(&record),
            "leaf_preimage": hex(&leaf_preimage),
            "leaf": hex(&applied.leaf),
            "head_preimage": hex(&preimage_of(&StepHeadPreimage {
                prev_head: previous_head,
                leaf: applied.leaf,
            })),
            "head": hex(&applied.head),
            "flags": applied.flags.to_string(),
        }));
        if seq == 2 {
            snapshot_at_two = Some(chain.snapshot());
        }
    }
    let final_head = chain.head();

    files.insert(
        "V-P-03.json".into(),
        vector(
            "V-P-03",
            "§4.2",
            "A chain of five records, categories 0 to 4, with each leaf, head and flag value.",
            json!({ "asset_commitment": hex(&commitment), "schema_version": "1" }),
            json!({ "steps": steps, "head_after_five": hex(&final_head) }),
            &[TEST_KEY_NOTE],
        ),
    );

    // V-P-04: the same leaves recomputed from h₂ forward reach the same h₅ (INV-STATE-02).
    let snapshot = snapshot_at_two.expect("a snapshot at seq 2");
    let mut resumed = Chain::resume(&commitment, 1, snapshot).expect("resumes");
    for seq in 3..=5u64 {
        let category = u8::try_from(seq - 1).expect("2 to 4");
        let record = signed_record(
            &resumed,
            seq,
            category,
            FIRST_EFFECTIVE_AT + i64::from(category),
        );
        let _ = resumed.apply(&record).expect("accepted");
    }
    assert_eq!(
        resumed.head(),
        final_head,
        "V-P-04: INV-STATE-02 requires the recomputed head to equal the chain's"
    );

    files.insert(
        "V-P-04.json".into(),
        vector(
            "V-P-04",
            "§4.2",
            "Recomputing records three to five from the head at sequence two reaches the same head as the whole chain.",
            json!({
                "resumed_from": {
                    "head": hex(&snapshot.head),
                    "seq": snapshot.seq.to_string(),
                    "last_effective_at": snapshot.last_effective_at.to_string(),
                    "saw_resource": snapshot.saw_resource,
                    "previous_category": snapshot.previous_category.map(|c| c.to_string()),
                },
            }),
            json!({
                "head_after_five": hex(&resumed.head()),
                "asserted": "INV-STATE-02: the head recomputed from sequence two equals the head of the whole chain",
            }),
            &[],
        ),
    );

    // V-P-09: zeros for the memo's digest and date are a record of absence (INV-STATE-05).
    let mut zeros_chain = Chain::start(&commitment, 1).expect("starts");
    let mut zeros = signed_record_with(&zeros_chain, 1, 2, FIRST_EFFECTIVE_AT, |r| {
        r.assessment_digest = [0; 32];
        r.change_identified_at = 0;
    });
    let zeros_preimage = leaf_preimage_of(&zeros_chain, &zeros);
    let zeros_applied = zeros_chain.apply(&zeros).expect("accepted");
    zeros.signature = zeros.signature.filter(|_| true);
    files.insert(
        "V-P-09.json".into(),
        vector(
            "V-P-09",
            "§4.2",
            "A record with a zero assessment digest and a zero change date is accepted: absence is recorded, not omitted.",
            json!({ "record": record_json(&zeros) }),
            json!({
                "leaf_preimage": hex(&zeros_preimage),
                "leaf": hex(&zeros_applied.leaf),
                "head": hex(&zeros_applied.head),
                "flags": zeros_applied.flags.to_string(),
            }),
            &[TEST_KEY_NOTE],
        ),
    );

    // V-P-11: a reserve category with no earlier resource record is accepted and flagged, and the
    // flag does not change the leaf digest (INV-STATE-06, INV-STATE-06a).
    let mut flagged_chain = Chain::start(&commitment, 1).expect("starts");
    let flagged_record = signed_record(&flagged_chain, 1, 4, FIRST_EFFECTIVE_AT);
    let flagged = flagged_chain.apply(&flagged_record).expect("accepted");
    let unflagged_snapshot = ChainSnapshot {
        head: Chain::genesis(&commitment, 1).expect("schema 1"),
        seq: 0,
        last_effective_at: i64::MIN,
        saw_resource: true,
        previous_category: None,
    };
    let mut unflagged_chain = Chain::resume(&commitment, 1, unflagged_snapshot).expect("resumes");
    let unflagged = unflagged_chain.apply(&flagged_record).expect("accepted");
    // §4.2's V-P-11 claims three things: accepted, flag bit 0 set, and a leaf digest identical to
    // the unflagged case. All three are checked here (INV-STATE-06, INV-STATE-06a).
    assert_eq!(
        flagged.flags, FLAG_RESERVE_WITHOUT_PRIOR_RESOURCE,
        "V-P-11: a reserve with no earlier resource must set flag bit 0"
    );
    assert_eq!(
        unflagged.flags, 0,
        "V-P-11: the same record after a resource record must carry no flag"
    );
    assert_eq!(
        flagged.leaf, unflagged.leaf,
        "V-P-11: INV-STATE-06a keeps flags out of the preimage, so the leaves must be identical"
    );

    files.insert(
        "V-P-11.json".into(),
        vector(
            "V-P-11",
            "§4.2",
            "A reserve category with no earlier resource record is accepted and flagged. The same record on a chain that has seen a resource is unflagged, and both leaves are identical because flags stay out of the preimage.",
            json!({ "record": record_json(&flagged_record) }),
            json!({
                "flagged": { "flags": flagged.flags.to_string(), "leaf": hex(&flagged.leaf) },
                "unflagged": { "flags": unflagged.flags.to_string(), "leaf": hex(&unflagged.leaf) },
                "asserted": "INV-STATE-06a: the flag does not change the leaf digest",
            }),
            &[TEST_KEY_NOTE],
        ),
    );
}

// ---------------------------------------------------------------- negative vectors (§4.3)

fn negatives(files: &mut BTreeMap<String, Value>) {
    let tenure = AssetId::<NativeKeccak>::canonicalize(TENURE_RAW).expect("canonical");
    let commitment = AssetId::<NativeKeccak>::commitment(J, R, &tenure).expect("defined");

    // A chain holding one record, so (a), (b) and (d) all have something to disagree with.
    let mut chain = Chain::start(&commitment, 1).expect("starts");
    let first = signed_record(&chain, 1, 2, FIRST_EFFECTIVE_AT);
    let _ = chain.apply(&first).expect("accepted");
    let head = chain.head();
    let snapshot = chain.snapshot();

    let chain_json = json!({
        "head": hex(&head),
        "seq": "1",
        "last_effective_at": FIRST_EFFECTIVE_AT.to_string(),
    });

    // One refused record: the engine is run, and the expectation written is the specification's.
    let refusal = |vector: &str,
                   case: &str,
                   mutate: &dyn Fn(&mut RecordLeafInput),
                   after_signing: Option<&dyn Fn(&mut RecordLeafInput)>,
                   spec_code: u16,
                   spec_name: &str| {
        // The mutation happens before signing, so a record that changes a field inside the leaf
        // preimage still carries a signature over its own bytes and is refused by the condition the
        // vector is about, not by (c).
        let mut record = signed_record_with(&chain, 2, 2, FIRST_EFFECTIVE_AT + 10, |r| mutate(r));
        if let Some(alter) = after_signing {
            alter(&mut record);
        }
        let mut probe = Chain::resume(&commitment, 1, snapshot).expect("resumes");
        let error = probe.apply(&record).expect_err("this case must be refused");
        assert_eq!(
            probe.snapshot(),
            snapshot,
            "{vector}/{case}: a refusal moved the chain"
        );
        json!({
            "case": case,
            "record": record_json(&record),
            "expected": spec_expectation(vector, error, spec_code, spec_name),
        })
    };

    let mut single = |name: &str, description: &str, notes: &[&str], case: Value| {
        files.insert(
            format!("{name}.json"),
            vector(
                name,
                "§4.3",
                description,
                json!({ "chain": chain_json, "record": case["record"] }),
                case["expected"].clone(),
                notes,
            ),
        );
    };

    single(
        "V-N-01",
        "A record that does not commit against the current head.",
        &[],
        refusal(
            "V-N-01",
            "wrong prev_head",
            &|r| r.prev_head = [0xAB; 32],
            None,
            0x03,
            "HeadMismatch",
        ),
    );
    single(
        "V-N-04",
        "A record with no qualified person's signature.",
        &[],
        refusal(
            "V-N-04",
            "no signature",
            &|_| {},
            Some(&|r| r.signature = None),
            0x06,
            "AttestationMissing",
        ),
    );
    single(
        "V-N-05",
        "A signature over a JSON rendering of the record rather than over the leaf preimage.",
        &[],
        refusal(
            "V-N-05",
            "signature over JSON",
            &|_| {},
            Some(&|r| {
                let key = SigningKey::from_bytes(&RFC8032_SECRET_KEY);
                let json_bytes = br#"{"seq":"2","category":"2","effective_at":"1700000010"}"#;
                r.signature = Some(key.sign(json_bytes).to_bytes());
            }),
            0x07,
            "AttestationInvalid",
        ),
    );
    single(
        "V-N-06",
        "A record whose expected qualified person's key differs from the key it claims. Decided before verification runs.",
        &[],
        refusal(
            "V-N-06",
            "expected key differs from the claimed key",
            &|r| r.expected_qp_key = Some([0x21; 32]),
            None,
            0x08,
            "AttestationKeyMismatch",
        ),
    );
    single(
        "V-N-08",
        "An effective date earlier than its predecessor's.",
        &[],
        refusal(
            "V-N-08",
            "effective_at goes backwards",
            &|r| r.effective_at = FIRST_EFFECTIVE_AT - 1,
            None,
            0x0A,
            "NonMonotonicEffectiveAt",
        ),
    );
    single(
        "V-N-23",
        "A record failing both (a) and (f): the earlier condition decides, so the answer is the head mismatch.",
        &[],
        refusal(
            "V-N-23",
            "wrong head and a broken URI",
            &|r| {
                r.prev_head = [0xAB; 32];
                r.payload_uri = uri("ftp://example.com/payload");
            },
            None,
            0x03,
            "HeadMismatch",
        ),
    );
    single(
        "V-N-24",
        "A record carrying the reserved extension commitment alongside a wrong head: the schema gate stands before (a).",
        &[],
        refusal(
            "V-N-24",
            "an extension and a wrong head",
            &|r| {
                r.prev_head = [0xAB; 32];
                r.ext_commitment = Some([0x99; 32]);
            },
            None,
            0x0F,
            "UnsupportedSchemaVersion",
        ),
    );

    // §4.3 gives V-N-25 to a signature made by a key other than the one the record claims, with no
    // expected key supplied. Ed25519 returns one bit, so that is an ordinary verification failure.
    single(
        "V-N-25",
        "A signature made by a key other than the qp_key the record claims, with no expected key supplied.",
        &[],
        refusal(
            "V-N-25",
            "signed by another key",
            &|_| {},
            Some(&|r| {
                let bytes = leaf_preimage_bytes(&commitment, r);
                r.signature = Some(SigningKey::from_bytes(&[0x5A; 32]).sign(&bytes).to_bytes());
            }),
            0x07,
            "AttestationInvalid",
        ),
    );

    // §4.3 gives one ID to the sequence gap and the replay, so both live in one file.
    files.insert(
        "V-N-02.json".into(),
        vector(
            "V-N-02",
            "§4.3",
            "A gap in the sequence, and a replay of a sequence already applied. Both are 0x04.",
            json!({ "chain": chain_json }),
            json!({
                "cases": [
                    refusal("V-N-02", "a gap", &|r| r.seq = 4, None, 0x04, "SequenceOutOfOrder"),
                    refusal("V-N-02", "a replay", &|r| r.seq = 1, None, 0x04, "SequenceOutOfOrder"),
                ]
            }),
            &[],
        ),
    );

    // V-N-03's three inputs. The 129-byte case cannot be built as a record at all, because the type
    // holds 128 bytes, so it is checked against the rule §1.3 states and recorded as such.
    let over_limit = format!("ipfs://{}", "a".repeat(122));
    assert_eq!(over_limit.len(), spec::MAX_PAYLOAD_URI_LEN + 1);
    assert!(
        !certimining_core::payload_uri_is_well_formed(over_limit.as_bytes()),
        "V-N-03: §1.3's rule must refuse a URI of {} bytes",
        over_limit.len()
    );
    files.insert(
        "V-N-03.json".into(),
        vector(
            "V-N-03",
            "§4.3",
            "A payload URI that is too long, not ASCII, or of an unknown scheme. Each is 0x05.",
            json!({ "chain": chain_json }),
            json!({
                "cases": [
                    json!({
                        "case": "129 bytes, one past §1.8's limit",
                        "payload_uri": over_limit,
                        "payload_uri_len": over_limit.len().to_string(),
                        "note": "The record type holds 128 bytes, so this input is refused before a record exists. It is checked against §1.3's rule, which returns false, and a record carrying it would return 0x05 at condition (f).",
                        "expected": { "error": "0x05", "error_name": "MalformedPayload", "source": "TCU-02 §4.3" },
                    }),
                    refusal("V-N-03", "not ASCII", &|r| r.payload_uri = uri("ipfs://payload\u{00e9}"), None, 0x05, "MalformedPayload"),
                    refusal("V-N-03", "unknown scheme", &|r| r.payload_uri = uri("ftp://example.com/payload"), None, 0x05, "MalformedPayload"),
                ]
            }),
            &[],
        ),
    );

    // V-N-07b names both 5 and 255.
    files.insert(
        "V-N-07b.json".into(),
        vector(
            "V-N-07b",
            "§4.3",
            "A category outside the range schema 1 defines: 5 and 255. Each is 0x05.",
            json!({ "chain": chain_json }),
            json!({
                "cases": [
                    refusal("V-N-07b", "category 5", &|r| r.category = spec::MAX_CATEGORY + 1, None, 0x05, "MalformedPayload"),
                    refusal("V-N-07b", "category 255", &|r| r.category = 255, None, 0x05, "MalformedPayload"),
                ]
            }),
            &[],
        ),
    );

    // V-N-07 is a negative vector with a positive outcome: the engine must accept, flag, and never
    // return 0x09 (INV-STATE-06, D-01).
    // A fresh chain, because the shared one already holds a Measured resource and the whole point
    // of V-N-07 is a reserve category with no earlier record of category 1 or 2.
    let mut accepting = Chain::start(&commitment, 1).expect("starts");
    let reserve = signed_record_with(&accepting, 1, 4, FIRST_EFFECTIVE_AT, |_| {});
    let applied = accepting
        .apply(&reserve)
        .expect("V-N-07: a reserve category with no earlier resource must be accepted");
    assert_eq!(
        applied.flags, FLAG_RESERVE_WITHOUT_PRIOR_RESOURCE,
        "V-N-07: §4.2's V-P-11 and INV-STATE-06 require flag bit 0"
    );
    files.insert(
        "V-N-07.json".into(),
        vector(
            "V-N-07",
            "§4.3",
            "Category 4 with no earlier record of category 1 or 2. Not an error: the record is accepted and flagged, and 0x09 is never returned under schema 1.",
            json!({
                "chain": { "head": hex(&Chain::genesis(&commitment, 1).expect("schema 1")), "seq": "0" },
                "record": record_json(&reserve),
            }),
            json!({
                "accepted": true,
                "error": Value::Null,
                "flags": applied.flags.to_string(),
                "flag_bit_0": "RESERVE_WITHOUT_PRIOR_RESOURCE",
                "leaf": hex(&applied.leaf),
                "head": hex(&applied.head),
                "source": "TCU-02 §4.3 and INV-STATE-06, checked against the engine at generation time",
            }),
            &[],
        ),
    );

    // V-N-09: a preimage read under the wrong domain tag (§4.3, E-03's reader).
    let leaf_bytes = leaf_preimage_bytes(&commitment, &first);
    let wrong_tag = certimining_core::check_tag(&leaf_bytes, *spec::TAG_HEAD)
        .expect_err("a leaf preimage is not a head preimage");
    files.insert(
        "V-N-09.json".into(),
        vector(
            "V-N-09",
            "§4.3",
            "A preimage read under a domain tag other than its own.",
            json!({
                "preimage": hex(&leaf_bytes),
                "actual_tag": core::str::from_utf8(spec::TAG_LEAF).expect("ascii"),
                "read_as": core::str::from_utf8(spec::TAG_HEAD).expect("ascii"),
            }),
            spec_expectation("V-N-09", wrong_tag, 0x0B, "DomainTagMismatch"),
            &[],
        ),
    );

    // V-N-13, V-N-20 and V-N-21 each need their own starting point.
    let error = Chain::genesis(&commitment, 2).expect_err("schema 2 is refused");
    files.insert(
        "V-N-13.json".into(),
        vector(
            "V-N-13",
            "§4.3",
            "A schema version this engine does not implement.",
            json!({ "asset_commitment": hex(&commitment), "schema_version": "2" }),
            spec_expectation("V-N-13", error, 0x0F, "UnsupportedSchemaVersion"),
            &[],
        ),
    );

    let at_limit = ChainSnapshot {
        head: [0x77; 32],
        seq: u64::MAX,
        last_effective_at: 0,
        saw_resource: true,
        previous_category: Some(2),
    };
    let mut limit_chain = Chain::resume(&commitment, 1, at_limit).expect("resumes");
    let record = signed_record(&limit_chain, u64::MAX, 2, FIRST_EFFECTIVE_AT);
    let error = limit_chain
        .apply(&record)
        .expect_err("a chain at the limit is refused");
    files.insert(
        "V-N-20.json".into(),
        vector(
            "V-N-20",
            "§4.3",
            "A chain whose sequence number has nowhere left to go: the counter is checked, never wrapped.",
            json!({
                "chain": { "head": hex(&at_limit.head), "seq": at_limit.seq.to_string() },
                "record": record_json(&record),
            }),
            spec_expectation("V-N-20", error, 0x10, "ArithmeticOverflow"),
            &[],
        ),
    );

    let mut refused = Map::new();
    for raw in ["", "   ", "-_./", "œæß"] {
        let error = AssetId::<NativeKeccak>::canonicalize(raw).expect_err("refused");
        refused.insert(
            raw.to_string(),
            spec_expectation("V-N-21", error, 0x11, "CanonicalizationFailed"),
        );
    }
    files.insert(
        "V-N-21.json".into(),
        vector(
            "V-N-21",
            "§4.3",
            "Tenure identifiers whose canonical form is empty.",
            json!({ "raw_tenures": refused.keys().cloned().collect::<Vec<_>>() }),
            Value::Object(refused),
            &["œ, æ and ß have no compatibility decomposition, so NFKD leaves nothing the filter keeps."],
        ),
    );
}

// ---------------------------------------------------------------- KAT-03 fixtures (§4.1, D-35)

fn kat03_fixtures(files: &mut BTreeMap<String, Value>) {
    let tenure = AssetId::<NativeKeccak>::canonicalize(TENURE_RAW).expect("canonical");
    let commitment = AssetId::<NativeKeccak>::commitment(J, R, &tenure).expect("defined");
    let key = SigningKey::from_bytes(&RFC8032_SECRET_KEY);
    let qp_key = key.verifying_key().to_bytes();

    let mut writers = Map::new();
    let mut add = |name: &str, bytes: Vec<u8>, values: &[&[u8]], fields: Value| {
        // Every writer is checked against the layout transcribed from the specification: the tag it
        // opens with, each field at the width §1.3 gives it, and the total the table states.
        spec::check_layout(name, &bytes, values);
        let tag = spec::layout(name).tag;
        writers.insert(
            name.to_string(),
            json!({
                "tag": core::str::from_utf8(tag).expect("the tags are ASCII"),
                "fields": fields,
                "preimage": hex(&bytes),
                "preimage_len": bytes.len().to_string(),
                "digest": hex(&NativeKeccak::hashv(&[&bytes])),
            }),
        );
    };

    let tenure_len = u16::try_from(tenure.len()).expect("1 to 64").to_le_bytes();
    add(
        "asset",
        preimage_of(&certimining_core::AssetPreimage {
            jurisdiction: J,
            registry: R,
            tenure: &tenure,
        }),
        &[J, R, &tenure_len, &tenure],
        json!({
            "jurisdiction": hex(J),
            "registry": hex(R),
            "tenure": core::str::from_utf8(&tenure).expect("A-Z and 0-9"),
        }),
    );

    let schema = spec::SCHEMA_VERSION.to_le_bytes();
    add(
        "genesis_head",
        preimage_of(&GenesisHeadPreimage {
            asset_commitment: commitment,
            schema_version: spec::SCHEMA_VERSION,
        }),
        &[&commitment, &schema],
        json!({ "asset_commitment": hex(&commitment), "schema_version": "1" }),
    );

    let leaf = LeafPreimage {
        asset_commitment: commitment,
        seq: 7,
        payload_digest: PAYLOAD_DIGEST,
        assessment_digest: ASSESSMENT_DIGEST,
        qp_key,
        category: 2,
        effective_at: FIRST_EFFECTIVE_AT,
        change_identified_at: FIRST_EFFECTIVE_AT - 100,
    };
    let seq = 7u64.to_le_bytes();
    let category = [2u8];
    let effective = FIRST_EFFECTIVE_AT.to_le_bytes();
    let identified = (FIRST_EFFECTIVE_AT - 100).to_le_bytes();
    add(
        "leaf",
        preimage_of(&leaf),
        &[
            &commitment,
            &seq,
            &PAYLOAD_DIGEST,
            &ASSESSMENT_DIGEST,
            &qp_key,
            &category,
            &effective,
            &identified,
        ],
        json!({
            "asset_commitment": hex(&commitment),
            "seq": "7",
            "payload_digest": hex(&PAYLOAD_DIGEST),
            "assessment_digest": hex(&ASSESSMENT_DIGEST),
            "qp_key": hex(&qp_key),
            "category": "2",
            "effective_at": FIRST_EFFECTIVE_AT.to_string(),
            "change_identified_at": (FIRST_EFFECTIVE_AT - 100).to_string(),
        }),
    );

    let leaf_digest = leaf.digest::<NativeKeccak>().expect("a digest");
    add(
        "step_head",
        preimage_of(&StepHeadPreimage {
            prev_head: commitment,
            leaf: leaf_digest,
        }),
        &[&commitment, &leaf_digest],
        json!({ "prev_head": hex(&commitment), "leaf": hex(&leaf_digest) }),
    );
    add(
        "real_leaf",
        preimage_of(&RealLeafPreimage { leaf: leaf_digest }),
        &[&leaf_digest],
        json!({ "leaf": hex(&leaf_digest) }),
    );
    let prf_output = [0x77u8; 32];
    add(
        "padding",
        preimage_of(&PaddingPreimage { prf_output }),
        &[&prf_output],
        json!({ "prf_output": hex(&prf_output) }),
    );
    add(
        "node",
        preimage_of(&NodePreimage {
            left: commitment,
            right: leaf_digest,
        }),
        &[&commitment, &leaf_digest],
        json!({ "left": hex(&commitment), "right": hex(&leaf_digest) }),
    );

    // The PRF's preimage, under the slot-assignment use, which carries the longest `x` schema 1 has.
    let prf_key: Digest = [0x99u8; 32];
    let mut prf_input = vec![spec::PRF_USE_SLOT];
    prf_input.extend_from_slice(&[0x88u8; 16]);
    let prf_length = u16::try_from(prf_input.len()).expect("seventeen bytes");
    add(
        "prf",
        preimage_of(&PrfPreimage {
            key: &prf_key,
            input: &prf_input,
        }),
        &[&prf_key, &prf_length.to_le_bytes(), &prf_input],
        json!({
            "k": hex(&prf_key),
            "use_code": format!("0x{:02X}", spec::PRF_USE_SLOT),
            "len(x)": prf_length.to_string(),
            "x": hex(&prf_input),
        }),
    );

    let submission_id = [0x88u8; 16];
    let promised_epoch = 20_361u64.to_le_bytes();
    let delay = [spec::MAX_MERGE_DELAY];
    add(
        "spi",
        preimage_of(&SpiPreimage {
            leaf: leaf_digest,
            submission_id,
            promised_epoch: 20_361,
            max_merge_delay: spec::MAX_MERGE_DELAY,
        }),
        &[&leaf_digest, &submission_id, &promised_epoch, &delay],
        json!({
            "leaf": hex(&leaf_digest),
            "submission_id": hex(&submission_id),
            "promised_epoch": "20361",
            "max_merge_delay": spec::MAX_MERGE_DELAY.to_string(),
        }),
    );

    assert_eq!(
        writers.len(),
        spec::LAYOUTS.len(),
        "every layout the specification states must have a fixture"
    );

    files.insert(
        "KAT-03.json".into(),
        vector(
            "KAT-03",
            "§4.1",
            "Every preimage writer's bytes and digest, for the Borsh encoding check. Each one is checked against the layout §1.2, §1.3, §1.4 and §1.6 state before it is written, so a change to any layout stops generation rather than being recorded.",
            json!({ "note": "Each writer's fields are listed beside the bytes they produce." }),
            Value::Object(writers),
            &[],
        ),
    );
}

/// KAT-03 as plain text: one writer per line, `name preimage digest`, sorted by name. The core
/// crate's tests read this form, which needs no JSON parser (D-57).
fn kat03_plain(vector: &Value) -> String {
    let writers = vector
        .get("expected")
        .and_then(Value::as_object)
        .expect("KAT-03 carries its writers under expected");
    let mut text = String::from(
        "# KAT-03: every preimage writer's bytes and digest, generated by `cargo xtask gen-vectors`.\n\
         # Never edited by hand. Columns: name, preimage hex, digest hex.\n\
         # The qualified person's key inside the leaf is RFC 8032 §7.1's published specification\n\
         # test key, not a real identity. Its private half is public, so any signature over these\n\
         # bytes is reproducible.\n",
    );
    for (name, entry) in writers {
        let preimage = entry["preimage"].as_str().expect("hex");
        let digest = entry["digest"].as_str().expect("hex");
        text.push_str(&format!("{name} {preimage} {digest}\n"));
    }
    text
}

// ---------------------------------------------------------------- epoch-tree vectors (§4.2, §4.3)

/// The master key every tree vector is built under (D-63). Its bytes spell out what it is, so no
/// reader can mistake it for a real one, and every epoch key, slot and padding leaf below is
/// reproducible from it. A real `k_master` never appears in this repository, and INV-TREE-05 keeps a
/// real epoch key off every wire.
const TEST_MASTER_KEY: Digest = *b"CMv1 TEST MASTER KEY, NOT SECRET";

const MASTER_KEY_NOTE: &str =
    "The master key is a specification test key, not a real one: its bytes spell out what it is. \
     Every epoch key, slot and padding leaf here follows from it, so the whole tree is reproducible. \
     A real k_master never appears in this repository (INV-TREE-05).";

const LEAF_NOTE: &str =
    "The chain leaves are arbitrary 32-byte values. The tree never looks inside one, so a vector \
     needs no record behind them; V-P-02 and V-P-03 carry the leaves a real chain produces.";

const LEAVES_NOTE: &str =
    "The full leaf set is recorded where capacity allows it, so a disagreement localises to a slot \
     rather than to the root. Above 256 slots only the root, the assignment and the proofs are kept.";

/// A submission identifier for a vector: a counter, little-endian, in sixteen bytes. Sequential
/// identifiers are the hard case for INV-TREE-03, and every value is written out in the file.
fn vector_submission_id(n: u64) -> SubmissionId {
    let mut id = [0u8; 16];
    let (low, _) = id.split_at_mut(8);
    low.copy_from_slice(&n.to_le_bytes());
    id
}

/// A stand-in chain leaf.
fn vector_leaf(n: u64) -> Digest {
    NativeKeccak::hashv(&[b"CMv1 vector chain leaf", &n.to_le_bytes()])
}

fn submission_set(count: u64, offset: u64) -> Vec<(SubmissionId, Digest)> {
    (0..count)
        .map(|n| {
            (
                vector_submission_id(n.wrapping_add(offset)),
                vector_leaf(n.wrapping_add(offset)),
            )
        })
        .collect()
}

fn build_epoch(epoch: u64, height: u8, real: &[(SubmissionId, Digest)]) -> BuiltEpoch {
    BuiltEpoch::build::<NativeKeccak>(epoch, height, &TEST_MASTER_KEY, real)
        .expect("these inputs are inside capacity")
}

fn epoch_inputs(epoch: u64, height: u8, real: &[(SubmissionId, Digest)]) -> Value {
    json!({
        "epoch": epoch.to_string(),
        "height": height.to_string(),
        "capacity": (1usize << height).to_string(),
        "master_key": hex(&TEST_MASTER_KEY),
        "real": real
            .iter()
            .map(|(id, leaf)| json!({ "submission_id": hex(id), "leaf": hex(leaf) }))
            .collect::<Vec<Value>>(),
    })
}

fn proof_json(proof: &InclusionProof) -> Value {
    json!({
        "height": proof.height.to_string(),
        "slot_index": proof.slot_index.to_string(),
        "epoch": proof.epoch.to_string(),
        "siblings": proof.siblings.iter().map(|s| hex(s)).collect::<Vec<String>>(),
    })
}

/// One proof, with the submission it is for and the leaf a counterparty would hold. Generation fails
/// if the proof does not verify or does not carry `H` siblings, which are §4.2's own claims.
fn checked_proof(vector: &str, built: &BuiltEpoch, id: &SubmissionId, leaf: &Digest) -> Value {
    let proof = built.proof(id).expect("the epoch holds this submission");
    assert_eq!(
        proof.siblings.len(),
        usize::from(built.height),
        "{vector}: §4.2 states a proof of exactly H siblings"
    );
    assert_eq!(
        ProofVerifier::verify::<NativeKeccak>(leaf, &proof, &built.root),
        Ok(()),
        "{vector}: §4.2 states every proof verifies"
    );
    assert_eq!(
        ProofVerifier::verify_for_height::<NativeKeccak>(leaf, &proof, &built.root, built.height),
        Ok(()),
        "{vector}: and verifies against the log's configured height"
    );
    let mut entry = Map::new();
    entry.insert("submission_id".into(), json!(hex(id)));
    entry.insert("leaf".into(), json!(hex(leaf)));
    entry.insert("proof".into(), proof_json(&proof));
    Value::Object(entry)
}

fn epoch_expected(built: &BuiltEpoch, proofs: Vec<Value>) -> Value {
    let k_e = epoch_key::<NativeKeccak>(&TEST_MASTER_KEY, built.epoch).expect("derives");
    let mut map = Map::new();
    map.insert("epoch_key".into(), json!(hex(&k_e)));
    map.insert("root".into(), json!(hex(&built.root)));
    map.insert(
        "assignment".into(),
        json!(built
            .assignment
            .iter()
            .map(|(id, slot)| json!({ "submission_id": hex(id), "slot": slot.to_string() }))
            .collect::<Vec<Value>>()),
    );
    if built.leaves.len() <= spec::DEPLOYED_CAPACITY {
        map.insert(
            "leaves".into(),
            json!(built.leaves.iter().map(|l| hex(l)).collect::<Vec<String>>()),
        );
    }
    map.insert("proofs".into(), json!(proofs));
    Value::Object(map)
}

/// Every hashing step behind one submission's proof, preimage and digest together (D-58): the epoch
/// key, the slot seed, the leaf as it enters the tree, one padding leaf for comparison, and each node
/// up the path. The walk is recomputed here and generation fails if it does not reach the root.
fn epoch_steps(built: &BuiltEpoch, id: &SubmissionId, leaf: &Digest) -> Value {
    let k_e_preimage = {
        let mut x = vec![spec::PRF_USE_EPOCH_KEY];
        x.extend_from_slice(&built.epoch.to_le_bytes());
        prf_preimage_bytes(&TEST_MASTER_KEY, &x)
    };
    let k_e = epoch_key::<NativeKeccak>(&TEST_MASTER_KEY, built.epoch).expect("derives");

    let slot_preimage = {
        let mut x = vec![spec::PRF_USE_SLOT];
        x.extend_from_slice(id);
        prf_preimage_bytes(&k_e, &x)
    };
    let seed = slot_seed::<NativeKeccak>(&k_e, id).expect("derives");
    let slot = built
        .assignment
        .iter()
        .find(|(candidate, _)| candidate == id)
        .map(|(_, slot)| *slot)
        .expect("the epoch holds this submission");

    let real_leaf_preimage = preimage_of(&RealLeafPreimage { leaf: *leaf });

    // One padding slot, whichever is free, so the two leaf forms sit side by side in the file.
    let padding_slot = (0..built.leaves.len() as u16)
        .find(|candidate| !built.assignment.iter().any(|(_, taken)| taken == candidate))
        .expect("an epoch with one real leaf has free slots");
    let padding_input = {
        let mut x = vec![spec::PRF_USE_PADDING];
        x.extend_from_slice(&padding_slot.to_le_bytes());
        prf_preimage_bytes(&k_e, &x)
    };
    let padding_output = padding_prf::<NativeKeccak>(&k_e, padding_slot).expect("derives");
    let padding_leaf_preimage = preimage_of(&PaddingPreimage {
        prf_output: padding_output,
    });

    let proof = built.proof(id).expect("the epoch holds this submission");
    let mut node = NativeKeccak::hashv(&[&real_leaf_preimage]);
    let index = slot;
    let mut path: Vec<Value> = Vec::new();
    for (level, sibling) in proof.siblings.iter().enumerate() {
        let on_the_left = (index >> level) & 1 == 0;
        let (left, right) = if on_the_left {
            (node, *sibling)
        } else {
            (*sibling, node)
        };
        let bytes = preimage_of(&NodePreimage { left, right });
        node = NativeKeccak::hashv(&[&bytes]);
        path.push(json!({
            "level": level.to_string(),
            "leaf_on_the_left": on_the_left,
            "left": hex(&left),
            "right": hex(&right),
            "preimage": hex(&bytes),
            "digest": hex(&node),
        }));
    }
    assert_eq!(
        node, built.root,
        "the recorded path must reach the root the tree published"
    );

    json!({
        "epoch_key": { "preimage": hex(&k_e_preimage), "digest": hex(&k_e) },
        "slot_seed": { "preimage": hex(&slot_preimage), "digest": hex(&seed), "slot": slot.to_string() },
        "real_leaf": { "preimage": hex(&real_leaf_preimage), "digest": hex(&NativeKeccak::hashv(&[&real_leaf_preimage])) },
        "padding_leaf": {
            "slot": padding_slot.to_string(),
            "prf": { "preimage": hex(&padding_input), "digest": hex(&padding_output) },
            "leaf": { "preimage": hex(&padding_leaf_preimage), "digest": hex(&NativeKeccak::hashv(&[&padding_leaf_preimage])) },
        },
        "path": path,
    })
}

/// `TAG_PRF ‖ k ‖ len(x) ‖ x`, assembled from the specification's own table rather than from the
/// engine, and checked against the engine before it is written.
fn prf_preimage_bytes(key: &Digest, x: &[u8]) -> Vec<u8> {
    let produced = preimage_of(&PrfPreimage { key, input: x });
    let length = u16::try_from(x.len()).expect("schema 1's inputs are short");
    spec::check_layout("prf", &produced, &[key, &length.to_le_bytes(), x]);
    produced
}

fn trees(files: &mut BTreeMap<String, Value>) {
    let height = spec::DEPLOYED_HEIGHT;

    // V-P-05: one real leaf at H = 8.
    let one = submission_set(1, 1);
    let built = build_epoch(20_400, height, &one);
    assert_eq!(
        built.leaves.len(),
        spec::DEPLOYED_CAPACITY,
        "V-P-05: §1.4 gives C = 256 at H = 8"
    );
    let mut expected = epoch_expected(
        &built,
        vec![checked_proof("V-P-05", &built, &one[0].0, &one[0].1)],
    );
    if let Some(map) = expected.as_object_mut() {
        map.insert("steps".into(), epoch_steps(&built, &one[0].0, &one[0].1));
    }
    files.insert(
        "V-P-05.json".into(),
        vector(
            "V-P-05",
            "§4.2",
            "One real leaf in an epoch at H = 8: a fixed root, an eight-sibling proof that verifies, and every hashing step behind it.",
            epoch_inputs(built.epoch, height, &one),
            expected,
            &[MASTER_KEY_NOTE, LEAF_NOTE, LEAVES_NOTE],
        ),
    );

    // V-P-06: 255 real leaves at H = 8, the same key. Three proofs are written in full, the lowest
    // slot, the highest, and the one in between, and every proof is checked.
    let many = submission_set(255, 1_000);
    let full = build_epoch(20_401, height, &many);
    for (id, leaf) in &many {
        let proof = full.proof(id).expect("the epoch holds it");
        assert_eq!(
            proof.siblings.len(),
            usize::from(height),
            "V-P-06: §4.2 states the proof length is still 8"
        );
        assert_eq!(
            ProofVerifier::verify::<NativeKeccak>(leaf, &proof, &full.root),
            Ok(()),
            "V-P-06: §4.2 states every proof verifies"
        );
    }
    let mut by_slot: Vec<(u16, SubmissionId)> = full
        .assignment
        .iter()
        .map(|(id, slot)| (*slot, *id))
        .collect();
    by_slot.sort_unstable();
    let chosen: Vec<SubmissionId> = [0usize, by_slot.len() / 2, by_slot.len() - 1]
        .iter()
        .map(|index| by_slot[*index].1)
        .collect();
    let proofs: Vec<Value> = chosen
        .iter()
        .map(|id| {
            let leaf = many
                .iter()
                .find(|(candidate, _)| candidate == id)
                .map(|(_, leaf)| *leaf)
                .expect("chosen from the set");
            checked_proof("V-P-06", &full, id, &leaf)
        })
        .collect();
    files.insert(
        "V-P-06.json".into(),
        vector(
            "V-P-06",
            "§4.2",
            "255 real leaves in an epoch at H = 8 under the same key: a fixed root, every proof verified at generation time, and three of them written out in full.",
            epoch_inputs(full.epoch, height, &many),
            epoch_expected(&full, proofs),
            &[
                MASTER_KEY_NOTE,
                LEAF_NOTE,
                LEAVES_NOTE,
                "Every one of the 255 proofs is verified while this file is generated. Three are recorded: the lowest slot, the highest, and the one in the middle.",
            ],
        ),
    );

    // V-P-06b: the same leaf set at H = 4 and H = 12, where the proof length tracks H exactly.
    let twelve = submission_set(12, 2_000);
    let mut heights = Map::new();
    for other in [spec::MIN_HEIGHT, 12u8] {
        let tree = build_epoch(20_402, other, &twelve);
        let proofs: Vec<Value> = twelve
            .iter()
            .map(|(id, leaf)| checked_proof("V-P-06b", &tree, id, leaf))
            .collect();
        heights.insert(format!("H{other}"), epoch_expected(&tree, proofs));
    }
    files.insert(
        "V-P-06b.json".into(),
        vector(
            "V-P-06b",
            "§4.2",
            "The same twelve leaves at H = 4 and H = 12: each builds cleanly, and the proof length tracks H exactly.",
            json!({
                "epoch": "20402",
                "heights": [spec::MIN_HEIGHT.to_string(), 12u8.to_string()],
                "master_key": hex(&TEST_MASTER_KEY),
                "real": twelve
                    .iter()
                    .map(|(id, leaf)| json!({ "submission_id": hex(id), "leaf": hex(leaf) }))
                    .collect::<Vec<Value>>(),
            }),
            Value::Object(heights),
            &[MASTER_KEY_NOTE, LEAF_NOTE, LEAVES_NOTE],
        ),
    );

    tree_negatives(files, height);
}

/// §4.3's proof vectors. Every expected code is written from §4.3's table and checked against the
/// engine, so an engine that accepted one of these could not record its acceptance here.
fn tree_negatives(files: &mut BTreeMap<String, Value>, height: u8) {
    let real = submission_set(4, 3_000);
    let built = build_epoch(20_410, height, &real);
    let (id, leaf) = real[0];
    let good = built.proof(&id).expect("the epoch holds it");
    assert_eq!(
        ProofVerifier::verify::<NativeKeccak>(&leaf, &good, &built.root),
        Ok(()),
        "the proof these cases mutate must verify before they mutate it"
    );

    let refused = |vector: &str, case: &str, proof: &InclusionProof, root: &Digest| -> Value {
        let error = ProofVerifier::verify::<NativeKeccak>(&leaf, proof, root)
            .expect_err("this case must be refused");
        json!({
            "case": case,
            "proof": proof_json(proof),
            "root": hex(root),
            "expected": spec_expectation(vector, error, 0x13, "InclusionProofInvalid"),
        })
    };

    // V-N-15: one sibling altered, at every level.
    let altered: Vec<Value> = (0..good.siblings.len())
        .map(|level| {
            let mut proof = good.clone();
            let mut siblings: Vec<Digest> = proof.siblings.iter().copied().collect();
            siblings[level][0] ^= 0x01;
            proof.siblings = siblings.iter().copied().collect();
            refused(
                "V-N-15",
                &format!("one bit flipped in the sibling at level {level}"),
                &proof,
                &built.root,
            )
        })
        .collect();
    files.insert(
        "V-N-15.json".into(),
        vector(
            "V-N-15",
            "§4.3",
            "An inclusion proof with one sibling altered, one case per level.",
            json!({
                "epoch": built.epoch.to_string(),
                "height": height.to_string(),
                "master_key": hex(&TEST_MASTER_KEY),
                "submission_id": hex(&id),
                "leaf": hex(&leaf),
                "root": hex(&built.root),
                "valid_proof": proof_json(&good),
            }),
            json!({ "cases": altered }),
            &[MASTER_KEY_NOTE],
        ),
    );

    // V-N-16: one sibling too few, and one too many.
    let mut short = good.clone();
    let mut siblings: Vec<Digest> = short.siblings.iter().copied().collect();
    siblings.pop();
    short.siblings = siblings.iter().copied().collect();
    let mut long = good.clone();
    long.siblings
        .push([0x00; 32])
        .expect("room below sixteen siblings");
    files.insert(
        "V-N-16.json".into(),
        vector(
            "V-N-16",
            "§4.3",
            "An inclusion proof carrying H − 1 and H + 1 siblings.",
            json!({
                "epoch": built.epoch.to_string(),
                "height": height.to_string(),
                "master_key": hex(&TEST_MASTER_KEY),
                "submission_id": hex(&id),
                "leaf": hex(&leaf),
                "root": hex(&built.root),
                "valid_proof": proof_json(&good),
            }),
            json!({
                "cases": [
                    refused("V-N-16", "H − 1 siblings", &short, &built.root),
                    refused("V-N-16", "H + 1 siblings", &long, &built.root),
                ],
            }),
            &[MASTER_KEY_NOTE],
        ),
    );

    // V-N-16b: the proof's height against a log configured at another.
    let mismatched: Vec<Value> = [spec::MIN_HEIGHT, 7u8, 9u8, spec::MAX_HEIGHT]
        .iter()
        .map(|configured| {
            let error = ProofVerifier::verify_for_height::<NativeKeccak>(
                &leaf,
                &good,
                &built.root,
                *configured,
            )
            .expect_err("this case must be refused");
            json!({
                "case": format!("a proof of height {height} against a log configured at {configured}"),
                "configured_height": configured.to_string(),
                "proof": proof_json(&good),
                "root": hex(&built.root),
                "expected": spec_expectation("V-N-16b", error, 0x13, "InclusionProofInvalid"),
            })
        })
        .collect();
    files.insert(
        "V-N-16b.json".into(),
        vector(
            "V-N-16b",
            "§4.3",
            "A proof whose height field disagrees with the log's configured H. The check needs the configured height, which the proof cannot carry, so it is a second input to the verifier rather than a field.",
            json!({
                "epoch": built.epoch.to_string(),
                "height": height.to_string(),
                "master_key": hex(&TEST_MASTER_KEY),
                "submission_id": hex(&id),
                "leaf": hex(&leaf),
                "root": hex(&built.root),
                "valid_proof": proof_json(&good),
            }),
            json!({ "cases": mismatched }),
            &[MASTER_KEY_NOTE],
        ),
    );

    // V-N-17: the proof against another epoch's root.
    let other = build_epoch(20_411, height, &real);
    assert_ne!(
        built.root, other.root,
        "two epochs of the same submissions must publish different roots"
    );
    files.insert(
        "V-N-17.json".into(),
        vector(
            "V-N-17",
            "§4.3",
            "A valid proof verified against another epoch's root.",
            json!({
                "epoch": built.epoch.to_string(),
                "other_epoch": other.epoch.to_string(),
                "height": height.to_string(),
                "master_key": hex(&TEST_MASTER_KEY),
                "submission_id": hex(&id),
                "leaf": hex(&leaf),
                "root": hex(&built.root),
                "other_root": hex(&other.root),
                "valid_proof": proof_json(&good),
            }),
            json!({
                "cases": [refused("V-N-17", "the next epoch's root", &good, &other.root)],
            }),
            &[MASTER_KEY_NOTE],
        ),
    );
}

// ---------------------------------------------------------------- helpers

/// One vector file. Keys come out sorted, because `serde_json`'s map is a `BTreeMap` (D-53).
fn vector(
    id: &str,
    spec: &str,
    description: &str,
    inputs: Value,
    expected: Value,
    notes: &[&str],
) -> Value {
    let mut map = Map::new();
    map.insert("id".into(), json!(id));
    map.insert("spec".into(), json!(spec));
    map.insert("description".into(), json!(description));
    map.insert("schema_version".into(), json!("1"));
    map.insert("inputs".into(), inputs);
    map.insert("expected".into(), expected);
    // Any file that shows the key says what it is, not only the ones written with a note by hand.
    let shows_a_key = serde_json::to_string(&map)
        .expect("serializes")
        .contains("qp_key");
    let mut all: Vec<String> = notes.iter().map(|n| (*n).to_string()).collect();
    if shows_a_key && !all.iter().any(|n| n == TEST_KEY_NOTE) {
        all.push(TEST_KEY_NOTE.to_string());
    }
    if !all.is_empty() {
        map.insert("notes".into(), json!(all));
    }
    Value::Object(map)
}

/// Two-space indentation, LF endings, a trailing newline (D-53).
fn to_text(value: &Value) -> String {
    let mut text = serde_json::to_string_pretty(value).expect("a vector serializes");
    text.push('\n');
    text
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(2 + bytes.len() * 2);
    out.push_str("0x");
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// What §4.3 requires of a vector, checked against what the engine did.
///
/// The code and its name are written from the specification. Generation fails if the engine returns
/// anything else, so an engine with the wrong precedence cannot write that precedence into the
/// committed set as the correct answer, and E-11 is never forced to reproduce a mistake.
fn spec_expectation(vector: &str, error: RegistryError, spec_code: u16, spec_name: &str) -> Value {
    assert_eq!(
        error.code(),
        spec_code,
        "{vector}: the engine returned {error:?} (0x{:02X}) where the specification names {spec_name} (0x{spec_code:02X})",
        error.code()
    );
    assert_eq!(
        format!("{error:?}"),
        spec_name,
        "{vector}: §2.1 calls 0x{spec_code:02X} {spec_name}; the engine calls it {error:?}"
    );
    json!({
        "error": format!("0x{spec_code:02X}"),
        "error_name": spec_name,
        "source": "TCU-02 §4.3, checked against the engine at generation time",
    })
}

/// SHA-256 for the manifest, from the implementation already in this workspace's graph. The engine
/// hashes with Keccak-256 and carries no SHA-256 of its own; `shasum -a 256` reads this format.
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest as _, Sha256};
    hex_plain(&Sha256::digest(bytes))
}

fn hex_plain(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn preimage_of<P: Preimage>(p: &P) -> Vec<u8> {
    let mut buf = PreimageBuf::new();
    p.write_preimage(&mut buf).expect("the preimage fits");
    buf.as_bytes().to_vec()
}

fn leaf_preimage_bytes(commitment: &Digest, r: &RecordLeafInput) -> Vec<u8> {
    preimage_of(&LeafPreimage {
        asset_commitment: *commitment,
        seq: r.seq,
        payload_digest: r.payload_digest,
        assessment_digest: r.assessment_digest,
        qp_key: r.qp_key,
        category: r.category,
        effective_at: r.effective_at,
        change_identified_at: r.change_identified_at,
    })
}

fn leaf_preimage_of(chain: &Chain, r: &RecordLeafInput) -> Vec<u8> {
    preimage_of(&LeafPreimage {
        asset_commitment: chain.asset_commitment(),
        seq: r.seq,
        payload_digest: r.payload_digest,
        assessment_digest: r.assessment_digest,
        qp_key: r.qp_key,
        category: r.category,
        effective_at: r.effective_at,
        change_identified_at: r.change_identified_at,
    })
}

fn uri(text: &str) -> PayloadUri {
    PayloadUri::from_slice(text.as_bytes()).expect("the URI fits")
}

/// A record signed over its own leaf preimage with the published test key (D-37, D-55).
fn signed_record(chain: &Chain, seq: u64, category: u8, effective_at: i64) -> RecordLeafInput {
    signed_record_with(chain, seq, category, effective_at, |_| {})
}

fn signed_record_with(
    chain: &Chain,
    seq: u64,
    category: u8,
    effective_at: i64,
    adjust: impl FnOnce(&mut RecordLeafInput),
) -> RecordLeafInput {
    let key = SigningKey::from_bytes(&RFC8032_SECRET_KEY);
    let mut record = RecordLeafInput {
        prev_head: chain.head(),
        seq,
        payload_digest: PAYLOAD_DIGEST,
        assessment_digest: ASSESSMENT_DIGEST,
        qp_key: key.verifying_key().to_bytes(),
        expected_qp_key: None,
        signature: None,
        category,
        effective_at,
        change_identified_at: effective_at - 100,
        payload_uri: uri(PAYLOAD_URI),
        ext_commitment: None,
    };
    adjust(&mut record);
    let bytes = leaf_preimage_of(chain, &record);
    record.signature = Some(key.sign(&bytes).to_bytes());
    record
}

fn record_json(r: &RecordLeafInput) -> Value {
    json!({
        "prev_head": hex(&r.prev_head),
        "seq": r.seq.to_string(),
        "payload_digest": hex(&r.payload_digest),
        "assessment_digest": hex(&r.assessment_digest),
        "qp_key": hex(&r.qp_key),
        "expected_qp_key": r.expected_qp_key.map(|k| hex(&k)),
        "signature": r.signature.map(|s| hex(&s)),
        "category": r.category.to_string(),
        "effective_at": r.effective_at.to_string(),
        "change_identified_at": r.change_identified_at.to_string(),
        "payload_uri": String::from_utf8_lossy(&r.payload_uri).to_string(),
        "ext_commitment": r.ext_commitment.map(|c| hex(&c)),
    })
}
