//! E-05: the vector generator.
//!
//! `cargo xtask gen-vectors` writes `vectors/*.json` and `vectors/MANIFEST.sha256`. Every value in
//! a vector comes from the engine itself, so a vector is what the engine produces rather than a
//! second opinion about it. Vectors are generated artifacts and are never edited by hand: CI
//! verifies the manifest and regenerates the set to compare it with what is committed (D-56).
//!
//! Rules this tool follows:
//! - Positive and negative vectors alike, for every vector whose inputs exist (D-51).
//! - Byte strings as `0x`-prefixed lowercase hex; 64-bit integers as decimal strings, because
//!   E-11's verifier is JavaScript and a JSON number is a double (D-52).
//! - Nothing environmental in a file: no timestamps, no toolchain versions, no paths (D-53).
//! - Every hashing step records its preimage as well as its digest (D-58).
//!
//! Being a tool rather than shipped code, this crate may panic: a generator that cannot produce a
//! vector must stop loudly, and INV-ERR-01's gates stay on the library and program crates (D-21).

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use certimining_core::{
    AssetChain, AssetId, AssetIdentity, ChainSnapshot, ChainState, Digest, GenesisHeadPreimage,
    Hasher, LeafPreimage, NativeKeccak, NodePreimage, PaddingPreimage, PayloadUri, Preimage,
    PreimageBuf, RealLeafPreimage, RecordLeafInput, RegistryError, SpiPreimage, StepHeadPreimage,
};
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
    fs::create_dir_all(dir).expect("the vectors directory can be created");
    for stale in fs::read_dir(dir).expect("the vectors directory can be read") {
        let path = stale.expect("a directory entry").path();
        // Only generated artifacts live here, so a file that is no longer generated is removed
        // rather than left behind to age.
        if path.is_file() {
            fs::remove_file(&path).expect("a stale vector can be removed");
        }
    }

    let mut files: BTreeMap<String, Value> = BTreeMap::new();
    positives(&mut files);
    negatives(&mut files);
    kat03_fixtures(&mut files);

    let mut manifest = String::new();
    for (name, value) in &files {
        let text = to_text(value);
        fs::write(dir.join(name), &text).expect("a vector can be written");
        manifest.push_str(&format!("{}  {}\n", sha256_hex(text.as_bytes()), name));
    }
    // KAT-03 also lands as plain text: the core crate's tests read these bytes, and JSON stays in
    // this tool (D-57). Both forms come from the same run, so they cannot drift apart.
    let kat03_text = kat03_plain(&files["KAT-03.json"]);
    fs::write(dir.join("KAT-03.txt"), &kat03_text).expect("the fixture can be written");
    manifest.push_str(&format!(
        "{}  {}\n",
        sha256_hex(kat03_text.as_bytes()),
        "KAT-03.txt"
    ));
    let mut lines: Vec<&str> = manifest.lines().collect();
    lines.sort_by_key(|l| l.split_whitespace().last().unwrap_or(""));
    let manifest = lines.join("\n") + "\n";
    fs::write(dir.join("MANIFEST.sha256"), &manifest).expect("the manifest can be written");

    println!(
        "wrote {} vectors and MANIFEST.sha256 to {}",
        files.len(),
        dir.display()
    );
    for name in files.keys() {
        println!("  {name}");
    }
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
            json!({ "head_after_five": hex(&resumed.head()), "equals_v_p_03": resumed.head() == final_head }),
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
                "leaves_identical": flagged.leaf == unflagged.leaf,
            }),
            &[TEST_KEY_NOTE],
        ),
    );
}

// ---------------------------------------------------------------- negative vectors (§4.3)

fn negatives(files: &mut BTreeMap<String, Value>) {
    let tenure = AssetId::<NativeKeccak>::canonicalize(TENURE_RAW).expect("canonical");
    let commitment = AssetId::<NativeKeccak>::commitment(J, R, &tenure).expect("defined");

    // A chain holding one record, so that (a), (b) and (d) all have something to disagree with.
    let mut chain = Chain::start(&commitment, 1).expect("starts");
    let first = signed_record(&chain, 1, 2, FIRST_EFFECTIVE_AT);
    let _ = chain.apply(&first).expect("accepted");
    let head = chain.head();
    let snapshot = chain.snapshot();

    let mut case = |name: &str,
                    spec: &str,
                    description: &str,
                    notes: &[&str],
                    mutate: &dyn Fn(&mut RecordLeafInput)| {
        let mut record = signed_record(&chain, 2, 2, FIRST_EFFECTIVE_AT + 10);
        mutate(&mut record);
        let mut probe = Chain::resume(&commitment, 1, snapshot).expect("resumes");
        let error = probe
            .apply(&record)
            .expect_err("this vector must be refused");
        assert_eq!(
            probe.snapshot(),
            snapshot,
            "{name}: a refusal moved the chain"
        );
        files.insert(
            format!("{name}.json"),
            vector(
                name,
                spec,
                description,
                json!({ "chain": { "head": hex(&head), "seq": "1", "last_effective_at": FIRST_EFFECTIVE_AT.to_string() }, "record": record_json(&record) }),
                json!({ "error": error_hex(error), "error_name": format!("{error:?}") }),
                notes,
            ),
        );
    };

    case(
        "V-N-01",
        "§4.3",
        "A record that does not commit against the current head.",
        &[],
        &|r| {
            r.prev_head = [0xAB; 32];
        },
    );
    case("V-N-02a", "§4.3", "A gap in the sequence.", &[], &|r| {
        r.seq = 4
    });
    case(
        "V-N-02b",
        "§4.3",
        "A replay of a sequence already applied.",
        &[],
        &|r| r.seq = 1,
    );
    case(
        "V-N-03a",
        "§4.3",
        "A payload URI of an unknown scheme.",
        &[],
        &|r| {
            r.payload_uri = uri("ftp://example.com/payload");
        },
    );
    case(
        "V-N-03b",
        "§4.3",
        "A payload URI that is not ASCII.",
        &[],
        &|r| {
            r.payload_uri = uri("ipfs://payload\u{00e9}");
        },
    );
    case(
        "V-N-03c",
        "§4.3",
        "A payload URI with nothing after its scheme.",
        &[],
        &|r| {
            r.payload_uri = uri("ipfs://");
        },
    );
    case(
        "V-N-04",
        "§4.3",
        "A record with no qualified person's signature.",
        &[],
        &|r| {
            r.signature = None;
        },
    );
    case(
        "V-N-05",
        "§4.3",
        "A signature over a JSON rendering of the record rather than over the leaf preimage.",
        &[TEST_KEY_NOTE],
        &|r| {
            let key = SigningKey::from_bytes(&RFC8032_SECRET_KEY);
            let json_bytes = br#"{"seq":"2","category":"2","effective_at":"1700000010"}"#;
            r.signature = Some(key.sign(json_bytes).to_bytes());
        },
    );
    case(
        "V-N-06",
        "§4.3",
        "A record whose expected qualified person's key is not the key it claims.",
        &[TEST_KEY_NOTE],
        &|r| {
            r.expected_qp_key = Some([0x21; 32]);
        },
    );
    case(
        "V-N-07b",
        "§4.3",
        "A category outside the range schema 1 defines.",
        &[],
        &|r| r.category = 5,
    );
    case(
        "V-N-08",
        "§4.3",
        "An effective date earlier than its predecessor's.",
        &[],
        &|r| {
            r.effective_at = FIRST_EFFECTIVE_AT - 1;
        },
    );
    case("V-N-23", "§4.3", "A record failing both (a) and (f): the earlier condition decides, so the answer is the head mismatch.", &[], &|r| {
        r.prev_head = [0xAB; 32];
        r.payload_uri = uri("ftp://example.com/payload");
    });
    case("V-N-24", "§4.3", "A record carrying the reserved extension commitment alongside a wrong head: the schema gate stands before (a).", &[], &|r| {
        r.prev_head = [0xAB; 32];
        r.ext_commitment = Some([0x99; 32]);
    });

    // V-N-13, V-N-20 and V-N-21 do not fit the shape above: each needs its own starting point.
    let error = Chain::genesis(&commitment, 2).expect_err("schema 2 is refused");
    files.insert(
        "V-N-13.json".into(),
        vector(
            "V-N-13",
            "§4.3",
            "A schema version this engine does not implement.",
            json!({ "asset_commitment": hex(&commitment), "schema_version": "2" }),
            json!({ "error": error_hex(error), "error_name": format!("{error:?}") }),
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
            json!({ "chain": { "head": hex(&at_limit.head), "seq": at_limit.seq.to_string() }, "record": record_json(&record) }),
            json!({ "error": error_hex(error), "error_name": format!("{error:?}") }),
            &[TEST_KEY_NOTE],
        ),
    );

    let mut refused = Map::new();
    for raw in ["", "   ", "-_./", "œæß"] {
        let error = AssetId::<NativeKeccak>::canonicalize(raw).expect_err("refused");
        refused.insert(
            raw.to_string(),
            json!({ "error": error_hex(error), "error_name": format!("{error:?}") }),
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
    let mut add = |name: &str, tag: &[u8; 8], bytes: Vec<u8>, fields: Value| {
        writers.insert(
            name.to_string(),
            json!({
                "tag": String::from_utf8(tag.to_vec()).expect("the tags are ASCII"),
                "fields": fields,
                "preimage": hex(&bytes),
                "preimage_len": bytes.len().to_string(),
                "digest": hex(&NativeKeccak::hashv(&[&bytes])),
            }),
        );
    };

    add(
        "asset",
        &certimining_core::TAG_ASSET,
        preimage_of(&certimining_core::AssetPreimage {
            jurisdiction: J,
            registry: R,
            tenure: &tenure,
        }),
        json!({ "jurisdiction": hex(J), "registry": hex(R), "tenure": String::from_utf8(tenure.to_vec()).expect("A-Z and 0-9") }),
    );
    add(
        "genesis_head",
        &certimining_core::TAG_HEAD,
        preimage_of(&GenesisHeadPreimage {
            asset_commitment: commitment,
            schema_version: 1,
        }),
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
    add(
        "leaf",
        &certimining_core::TAG_LEAF,
        preimage_of(&leaf),
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
        &certimining_core::TAG_HEAD,
        preimage_of(&StepHeadPreimage {
            prev_head: commitment,
            leaf: leaf_digest,
        }),
        json!({ "prev_head": hex(&commitment), "leaf": hex(&leaf_digest) }),
    );
    add(
        "real_leaf",
        &certimining_core::TAG_MTL0,
        preimage_of(&RealLeafPreimage { leaf: leaf_digest }),
        json!({ "leaf": hex(&leaf_digest) }),
    );
    add(
        "padding",
        &certimining_core::TAG_PAD,
        preimage_of(&PaddingPreimage {
            prf_output: [0x77; 32],
        }),
        json!({ "prf_output": hex(&[0x77; 32]) }),
    );
    add(
        "node",
        &certimining_core::TAG_MTN1,
        preimage_of(&NodePreimage {
            left: commitment,
            right: leaf_digest,
        }),
        json!({ "left": hex(&commitment), "right": hex(&leaf_digest) }),
    );
    add(
        "spi",
        &certimining_core::TAG_SPI,
        preimage_of(&SpiPreimage {
            leaf: leaf_digest,
            submission_id: [0x88; 16],
            promised_epoch: 20_361,
            max_merge_delay: 2,
        }),
        json!({
            "leaf": hex(&leaf_digest),
            "submission_id": hex(&[0x88; 16]),
            "promised_epoch": "20361",
            "max_merge_delay": "2",
        }),
    );

    files.insert(
        "KAT-03.json".into(),
        vector(
            "KAT-03",
            "§4.1",
            "Every preimage writer's bytes and digest, for the Borsh encoding check. The engine's own writers produced these, so a change to any layout changes this file and CI refuses it.",
            json!({ "note": "Each writer's fields are listed beside the bytes they produce." }),
            Value::Object(writers),
            &[TEST_KEY_NOTE],
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
         # Never edited by hand. Columns: name, preimage hex, digest hex.\n",
    );
    for (name, entry) in writers {
        let preimage = entry["preimage"].as_str().expect("hex");
        let digest = entry["digest"].as_str().expect("hex");
        text.push_str(&format!("{name} {preimage} {digest}\n"));
    }
    text
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

fn error_hex(error: RegistryError) -> String {
    format!("0x{:02X}", error.code())
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
