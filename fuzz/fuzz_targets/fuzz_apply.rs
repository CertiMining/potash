//! F-03: arbitrary record sequences against a chain.
//!
//! §4.5 states what every iteration asserts: `seq` never decreases, no head value repeats, and every
//! accepted transition is recomputable from its inputs. Those are INV-STATE-01 and INV-STATE-02 as
//! properties rather than as sentences.
//!
//! The records are arbitrary, so most are refused — which is the point. A refusal must leave the
//! chain exactly as it was, and the sequence of accepted ones must still satisfy all three.
#![no_main]

use arbitrary::Arbitrary;
use certimining_core::{
    AssetChain, ChainState, DalekVerifier, Digest, LeafPreimage, NativeKeccak, PayloadUri, Preimage,
    PreimageBuf, RecordLeafInput,
};
use ed25519_dalek::{Signer as _, SigningKey};
use libfuzzer_sys::fuzz_target;

type Chain = AssetChain<NativeKeccak, DalekVerifier>;

/// RFC 8032 §7.1's TEST 1 secret key, whose private half that document publishes.
const RFC8032_SECRET: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];

const ASSET: Digest = [0x11; 32];

/// The 161 bytes §1.3 signs, for a record that is about to be applied.
fn leaf_bytes(r: &RecordLeafInput) -> Vec<u8> {
    let mut buf = PreimageBuf::new();
    LeafPreimage {
        asset_commitment: ASSET,
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

#[derive(Arbitrary, Debug)]
struct Step {
    prev_head: [u8; 32],
    seq: u64,
    payload_digest: [u8; 32],
    assessment_digest: [u8; 32],
    qp_key: [u8; 32],
    signature: Option<[u8; 64]>,
    category: u8,
    effective_at: i64,
    change_identified_at: i64,
    uri: Vec<u8>,
    ext: Option<[u8; 32]>,
    /// Use the chain's current head instead of an arbitrary one, so some records are acceptable.
    /// Without this nearly every iteration fails condition (a) and the properties never see an
    /// accepted transition at all.
    link_to_head: bool,
    /// Use a well-formed `payload_uri`, so §1.3's condition (f) is passable.
    ///
    /// §1.3 requires one to 128 printable ASCII bytes beginning `ipfs://`, `https://` or `ar://`.
    /// Arbitrary bytes essentially never form one, so without this the accepted path is unreachable
    /// no matter what else the input gets right — which is how two earlier versions of this target
    /// ran a million inputs clean while never once reaching the assertions they existed for.
    valid_uri: bool,
    /// Sign the record properly, so §1.3's condition (c) is passable and the accepted path runs.
    ///
    /// A 64-byte arbitrary signature over a 161-byte message under an arbitrary key essentially never
    /// verifies, so without this every record is refused at (c) and every assertion below the `Ok`
    /// arm is unreachable. Probed: the target caught nothing until this existed.
    sign_properly: bool,
    /// Take the head but **not** the sequence, so §1.3's condition (b) is reachable.
    ///
    /// Without this the target could not see a sequence defect at all: an arbitrary `prev_head`
    /// fails condition (a) first and the record is refused before (b) is consulted, while
    /// `link_to_head` supplies a correct sequence by construction. Probed — relaxing (b) to allow a
    /// forward skip was *not* caught until this case existed, which is the same shape as an
    /// assertion that cannot fail.
    link_head_only: bool,
}

fuzz_target!(|steps: Vec<Step>| {
    if steps.len() > 64 {
        return;
    }
    let key = SigningKey::from_bytes(&RFC8032_SECRET);
    let mut chain = Chain::start(&ASSET, 1).expect("a chain starts");
    let mut heads: Vec<Digest> = vec![chain.head()];
    let mut last_seq = chain.seq();

    for step in steps {
        if step.uri.len() > 128 {
            continue; // the type holds 128; longer is checked directly in state.rs
        }
        let mut record = RecordLeafInput {
            prev_head: if step.link_to_head || step.link_head_only { chain.head() } else { step.prev_head },
            seq: if step.link_to_head && !step.link_head_only { chain.seq() + 1 } else { step.seq },
            payload_digest: step.payload_digest,
            assessment_digest: step.assessment_digest,
            qp_key: step.qp_key,
            expected_qp_key: None,
            signature: step.signature,
            category: step.category,
            effective_at: step.effective_at,
            change_identified_at: step.change_identified_at,
            payload_uri: if step.valid_uri {
                PayloadUri::from_slice(b"ipfs://bafyfuzzpayload").expect("fits")
            } else {
                PayloadUri::from_slice(&step.uri).expect("128 bytes or fewer fit")
            },
            ext_commitment: step.ext,
        };
        if step.sign_properly {
            record.qp_key = key.verifying_key().to_bytes();
            record.signature = Some(key.sign(&leaf_bytes(&record)).to_bytes());
        }

        // **A positive control, so unreachability cannot hide again.** When every condition §1.3
        // names is satisfiable by construction, the record must be accepted. If a future change makes
        // the accepted path unreachable — as an arbitrary URI, an arbitrary signature and an
        // arbitrary head each did in turn — this fires instead of the target quietly passing.
        let must_be_accepted = step.sign_properly
            && step.valid_uri
            && (step.link_to_head || step.link_head_only)
            && record.seq == chain.seq() + 1
            && record.category <= 4
            && record.effective_at >= chain.snapshot().last_effective_at
            && record.ext_commitment.is_none();

        let before = chain.snapshot();
        let outcome = chain.apply(&record);
        if must_be_accepted {
            assert!(
                outcome.is_ok(),
                "a record satisfying every condition §1.3 names was refused with {:?}",
                outcome.as_ref().err()
            );
        }
        match outcome {
            Ok(applied) => {
                // §4.5: the sequence never decreases, and in fact rises by exactly one.
                assert!(chain.seq() > last_seq, "an accepted record did not advance the sequence");
                assert_eq!(chain.seq(), last_seq + 1, "the sequence rose by more than one");
                // §1.3's condition (b) is `seq = n + 1`, so an accepted record's own claim must be
                // where it actually landed. The chain sets its counter from itself, so the two
                // assertions above hold even if (b) is relaxed; this is the one that does not, and it
                // was added after a probe showed a forward skip going uncaught.
                assert_eq!(
                    record.seq,
                    chain.seq(),
                    "a record claiming sequence {} was accepted into position {}",
                    record.seq,
                    chain.seq()
                );
                last_seq = chain.seq();

                // §4.5: no head value repeats. A repeat would mean two different chains share a head,
                // which is what INV-STATE-02's detectability rests on not happening.
                assert!(
                    !heads.contains(&applied.head),
                    "an accepted record produced a head the chain had already held"
                );
                assert_eq!(chain.head(), applied.head, "the chain's head is not what apply returned");
                heads.push(applied.head);

                // §4.5: recomputable from its inputs. Replaying the same record against the same
                // starting state must reach the same head, with nothing carried over from this chain.
                let mut replay = Chain::resume(&ASSET, 1, before).expect("resumes");
                let again = replay.apply(&record).expect("a transition that applied once applies again");
                assert_eq!(again.head, applied.head, "the transition is not recomputable from its inputs");
                assert_eq!(again.leaf, applied.leaf, "the leaf is not recomputable from its inputs");
                assert_eq!(again.flags, applied.flags, "the flags are not recomputable from their inputs");
            }
            Err(_) => {
                // INV-STATE-01: a refusal changes nothing at all.
                assert_eq!(chain.snapshot(), before, "a refused record moved the chain");
            }
        }
    }
});
