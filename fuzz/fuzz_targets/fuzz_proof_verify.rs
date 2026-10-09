// SPDX-License-Identifier: MIT OR Apache-2.0
//! F-04: arbitrary proof bytes against a fixed root.
//!
//! §4.5 asks that no proof be accepted without a genuine path and that no out-of-bounds read be
//! reachable. The root here is fixed and real — one epoch built by the engine — so an accepted proof
//! would be a forgery rather than a coincidence of empty inputs.
//!
//! The structure is generated rather than fed as raw bytes: a proof is a height, a slot index and a
//! list of siblings, and raw bytes would spend almost every iteration being rejected as malformed
//! before reaching the walk that matters.
#![no_main]

use arbitrary::Arbitrary;
use certimining_core::{Digest, NativeKeccak, SubmissionId};
use certimining_log::{BuiltEpoch, EpochTree, InclusionProof, InclusionVerifier, ProofVerifier};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct Input {
    leaf: [u8; 32],
    height: u8,
    slot_index: u16,
    siblings: Vec<[u8; 32]>,
    epoch: u64,
}

fn real_epoch() -> (BuiltEpoch, Digest, SubmissionId) {
    let master: Digest = [0x5a; 32];
    let mut id = [0u8; 16];
    id[0] = 1;
    let mut leaf = [0u8; 32];
    leaf[0] = 0x77;
    let built = <BuiltEpoch as EpochTree>::build::<NativeKeccak>(20_723, 8, &master, &[(id, leaf)])
        .expect("the engine builds this epoch");
    (built, leaf, id)
}

fuzz_target!(|input: Input| {
    let (built, real_leaf, real_id) = real_epoch();

    // **The positive obligation (M-04).** Every assertion below sat behind `Ok(())` on an *arbitrary*
    // proof, and the empty `Err(_) => {}` arm accepted any refusal — so a verifier that refused every
    // proof, including the genuine one, passed 100,000 iterations. The epoch's own proof is checked
    // first and unconditionally: if the verifier will not accept the path the engine just produced for
    // a submission the epoch holds, nothing else this target says is worth reading.
    let genuine = built
        .proof(&real_id)
        .expect("the epoch holds this submission");
    <ProofVerifier as InclusionVerifier>::verify::<NativeKeccak>(&real_leaf, &genuine, &built.root)
        .expect(
            "the proof the engine produced for a submission this epoch holds was refused against the \
             epoch's own root",
        );

    // **A second genuine proof, and this one varies (H-24).** The control above is one epoch, one
    // leaf, one identifier and one height, so it is one slot and one path. Arbitrary input is
    // overwhelmingly a refusal and supplies no second genuine proof, which leaves path-selective
    // refusal alive: a review made `verify` refuse every proof whose epoch is not 20723 and this
    // target stayed green, because its only genuine proof was at 20723 and every other proof it
    // generated was permitted to refuse.
    //
    // So a genuine epoch is built from the input as well. The height is 4 to 6 rather than the
    // deployment's 8: the fixed control already covers 8, and a second full-height tree per
    // iteration would double this target's cost for variety the lower trees already provide.
    let varied_height = 4 + (input.height % 3);
    let mut varied_id = [0u8; 16];
    varied_id[..8].copy_from_slice(&input.epoch.to_le_bytes());
    varied_id[8] = input.height;
    if let Ok(varied) = <BuiltEpoch as EpochTree>::build::<NativeKeccak>(
        input.epoch,
        varied_height,
        &[0x5a; 32],
        &[(varied_id, input.leaf)],
    ) {
        let proof = varied
            .proof(&varied_id)
            .expect("an epoch the engine built holds the submission it was built from");
        <ProofVerifier as InclusionVerifier>::verify::<NativeKeccak>(
            &input.leaf,
            &proof,
            &varied.root,
        )
        .unwrap_or_else(|e| {
            panic!(
                "the engine's own proof was refused ({e:?}) for epoch {}, height {varied_height}: a \
                 verifier that accepts one epoch's paths and refuses another's is not verifying",
                input.epoch
            )
        });
    }

    // §4.5 asks whether an out-of-bounds read is reachable here. **It is not reachable through the
    // sibling list at all**, and the reason is worth stating rather than fuzzing for: `siblings` is a
    // `heapless::Vec` of capacity 16, which is §1.8's maximum height, so a longer path cannot be
    // constructed — not refused at runtime, but unrepresentable. This target therefore drives every
    // length the type permits and lets the verifier judge them.
    let mut siblings: heapless::Vec<[u8; 32], 16> = heapless::Vec::new();
    for sibling in input.siblings.iter().take(16) {
        siblings.push(*sibling).expect("16 fit by construction");
    }

    let proof = InclusionProof {
        height: input.height,
        slot_index: input.slot_index,
        epoch: input.epoch,
        siblings,
    };

    match <ProofVerifier as InclusionVerifier>::verify::<NativeKeccak>(
        &input.leaf,
        &proof,
        &built.root,
    ) {
        Err(_) => {}
        Ok(()) => {
            // An accepted proof must be the real one: same leaf, same height, same siblings as the
            // epoch actually holds. Anything else accepted here is a forgery against a real root.
            assert_eq!(
                input.leaf, real_leaf,
                "a proof verified for a leaf the epoch does not hold"
            );
            assert_eq!(
                proof.height, genuine.height,
                "accepted a proof at another height"
            );
            assert_eq!(
                proof.slot_index, genuine.slot_index,
                "accepted a proof at another slot"
            );
            assert_eq!(
                proof.siblings.as_slice(),
                genuine.siblings.as_slice(),
                "accepted a path the epoch does not have"
            );
        }
    }
});
