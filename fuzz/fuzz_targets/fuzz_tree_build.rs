//! F-05: arbitrary real-leaf sets and arbitrary height bytes.
//!
//! §4.5: a valid height always produces a complete tree of that height, an invalid one returns
//! `0x05`, and nothing panics. §1.8 bounds the height at 4 to 16, so the arbitrary byte spends most
//! of its range outside the valid set, which is the half that matters — a build that accepted height
//! 200 would try to allocate 2^200 leaves.
#![no_main]

use arbitrary::Arbitrary;
use certimining_core::{Digest, NativeKeccak, RegistryError, SubmissionId};
use certimining_log::{BuiltEpoch, EpochTree};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct Input {
    epoch: u64,
    height: u8,
    key: [u8; 32],
    real: Vec<([u8; 16], [u8; 32])>,
}

fuzz_target!(|input: Input| {
    // Capacity at height 16 is 65,536; a set larger than that is `0x12` by §1.4 and the check is in
    // `tree.rs`. Driving far past it only spends iterations building huge vectors, so the input is
    // capped a little above the largest capacity this bound allows.
    if input.real.len() > 300 {
        return;
    }
    let real: Vec<(SubmissionId, Digest)> = input.real.iter().map(|(id, leaf)| (*id, *leaf)).collect();

    match <BuiltEpoch as EpochTree>::build::<NativeKeccak>(input.epoch, input.height, &input.key, &real) {
        Ok(built) => {
            // §1.8's range, and §1.4's fixed shape: every epoch tree has exactly `C` leaves and
            // height `H`, whatever it held.
            assert!(
                (4..=16).contains(&input.height),
                "built a tree at height {}, which §1.8 does not allow",
                input.height
            );
            assert_eq!(built.height(), input.height, "the tree's height is not the one asked for");
            assert_eq!(
                built.capacity(),
                1usize << input.height,
                "a complete tree at height {} has {} leaves",
                input.height,
                1usize << input.height
            );

            // INV-TREE-01: proof length is constant at `H` siblings, whatever the record count.
            for (id, _) in &real {
                if let Ok(proof) = built.proof(id) {
                    assert_eq!(
                        proof.siblings.len(),
                        input.height as usize,
                        "a proof carried {} siblings at height {}",
                        proof.siblings.len(),
                        input.height
                    );
                }
            }
        }
        Err(e) => {
            // The three refusals §1.4 and §1.8 define for this call, and nothing else.
            assert!(
                matches!(
                    e,
                    RegistryError::MalformedPayload | RegistryError::EpochCapacityExceeded
                ),
                "build refused with {e:?}, which is not a code §1.4 or §1.8 gives it"
            );
            if !(4..=16).contains(&input.height) {
                assert_eq!(
                    e,
                    RegistryError::MalformedPayload,
                    "height {} is outside §1.8's range and must be 0x05",
                    input.height
                );
            }
        }
    }
});
