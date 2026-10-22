// SPDX-License-Identifier: MIT OR Apache-2.0
//! The batcher's signed handoff, as the worker reads it (D-139, D-140, H-13).
//!
//! **What this exists to stop.** D-139 keeps `k_master` out of the worker, so the worker does not
//! build a root — it is given one. A process that refuses to invent a root but reads one from a file
//! has moved the question rather than answered it: whatever can write that file chooses what the log
//! publishes. The signature is what makes inducing a publication require the batcher's key instead of
//! a path.
//!
//! **Signed over the preimage, not its digest.** The preimage is 49 bytes (`HandoffPreimage`), small
//! enough to sign whole, and a verifier that reconstructs the fields then verifies exactly the bytes
//! it reconstructed — with no intermediate digest to compute differently. §1.6's promise signs a
//! digest instead and `docs/promises.md` names that as the one place it differs from a record's
//! attestation; this follows the attestation.
//!
//! **The key the artifact carries is not the authority.** `verify` takes the key the worker was
//! configured with and compares it first, the way `verify_promise` does: anyone can sign a handoff,
//! and the carried key only shows which key signed this one.

use certimining_core::{Digest, HandoffPreimage, Preimage, PreimageBuf, Verifier};

/// The transferable artifact: D-139's three fields, the key that signed them, and the signature.
///
/// Fixed width throughout, so [`Handoff::decode`] accepts exactly one length and a truncated or
/// padded file is refused rather than read as something.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Handoff {
    /// The epoch the root is for, a UTC day index (§1.4).
    pub epoch: u64,
    /// The tree height the root was built at, which §1.8 bounds to `[4, 16]`.
    pub height: u8,
    /// The epoch root, as the batcher built it.
    pub root: Digest,
    /// The public half of the key that signed, which shows *which* key signed and authorises nothing.
    pub batcher_key: [u8; 32],
    /// Ed25519 over the 49-byte preimage.
    pub signature: [u8; 64],
}

/// The encoded length: 8 epoch, 1 height, 32 root, 32 key, 64 signature.
pub const HANDOFF_LEN: usize = 137;

/// §1.8's bounds on the tree height, repeated here because a handoff naming a height outside them
/// describes a tree this log cannot have built.
const HEIGHT_RANGE: core::ops::RangeInclusive<u8> = 4..=16;

/// Why a handoff was refused, before anything was published.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandoffRefused {
    /// Not exactly [`HANDOFF_LEN`] bytes. Every field is fixed width, so a wrong length is a wrong
    /// file rather than a field to parse leniently.
    WrongLength { found: usize },
    /// The handoff was signed by a key the worker was not configured to accept.
    UnexpectedKey,
    /// The signature does not verify over the preimage the fields reconstruct.
    BadSignature,
    /// The height is outside §1.8's `[4, 16]`.
    HeightOutOfRange { height: u8 },
    /// The epoch is one the worker was not asked about, which means the file on disk is not the one
    /// the worker is acting on.
    WrongEpoch { found: u64, wanted: u64 },
}

impl Handoff {
    /// The 49 bytes the signature covers.
    fn preimage(&self) -> Result<PreimageBuf, HandoffRefused> {
        let mut buf = PreimageBuf::new();
        HandoffPreimage {
            epoch: self.epoch,
            height: self.height,
            root: self.root,
        }
        .write_preimage(&mut buf)
        .map_err(|_| HandoffRefused::HeightOutOfRange {
            height: self.height,
        })?;
        Ok(buf)
    }

    /// Writes the artifact. The order is the struct's, and [`decode`](Self::decode) reads it back.
    pub fn encode(&self) -> [u8; HANDOFF_LEN] {
        let mut out = [0u8; HANDOFF_LEN];
        let mut at = 0usize;
        let mut put = |bytes: &[u8]| {
            if let Some(slot) = out.get_mut(at..at.saturating_add(bytes.len())) {
                slot.copy_from_slice(bytes);
            }
            at = at.saturating_add(bytes.len());
        };
        put(&self.epoch.to_le_bytes());
        put(&[self.height]);
        put(&self.root);
        put(&self.batcher_key);
        put(&self.signature);
        out
    }

    /// Reads the artifact. Length is checked first and exactly: nothing here parses a prefix.
    pub fn decode(bytes: &[u8]) -> Result<Self, HandoffRefused> {
        if bytes.len() != HANDOFF_LEN {
            return Err(HandoffRefused::WrongLength { found: bytes.len() });
        }
        let field = |from: usize, to: usize| bytes.get(from..to);
        let epoch = field(0, 8)
            .and_then(|b| <[u8; 8]>::try_from(b).ok())
            .map(u64::from_le_bytes)
            .ok_or(HandoffRefused::WrongLength { found: bytes.len() })?;
        let height = *bytes
            .get(8)
            .ok_or(HandoffRefused::WrongLength { found: bytes.len() })?;
        let root = field(9, 41)
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .ok_or(HandoffRefused::WrongLength { found: bytes.len() })?;
        let batcher_key = field(41, 73)
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .ok_or(HandoffRefused::WrongLength { found: bytes.len() })?;
        let signature = field(73, 137)
            .and_then(|b| <[u8; 64]>::try_from(b).ok())
            .ok_or(HandoffRefused::WrongLength { found: bytes.len() })?;
        Ok(Self {
            epoch,
            height,
            root,
            batcher_key,
            signature,
        })
    }

    /// The root this handoff carries, once it has earned being believed.
    ///
    /// Checks, in this order: the key is the one the worker expects; the height is one §1.8 allows;
    /// the epoch is the one the worker is acting on; and the signature verifies over the preimage the
    /// fields reconstruct. The key is first for the reason `verify_promise` puts it first — a
    /// signature by the wrong key is not a failed signature, it is a different author.
    pub fn verify<V: Verifier>(
        &self,
        expected_batcher_key: &[u8; 32],
        wanted_epoch: u64,
    ) -> Result<Digest, HandoffRefused> {
        if &self.batcher_key != expected_batcher_key {
            return Err(HandoffRefused::UnexpectedKey);
        }
        if !HEIGHT_RANGE.contains(&self.height) {
            return Err(HandoffRefused::HeightOutOfRange {
                height: self.height,
            });
        }
        if self.epoch != wanted_epoch {
            return Err(HandoffRefused::WrongEpoch {
                found: self.epoch,
                wanted: wanted_epoch,
            });
        }
        let preimage = self.preimage()?;
        V::verify(&self.batcher_key, preimage.as_bytes(), &self.signature)
            .map_err(|_| HandoffRefused::BadSignature)?;
        Ok(self.root)
    }
}

/// Why the batcher refused to write a handoff, before any key was used (H-13, D-117).
///
/// These are the two decisions the writing process makes, kept here and pure because this crate's
/// rule is that a binary performs and does not decide (D-84): a decision tested only by running a
/// process against a cluster is a decision nothing checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandoffWriteRefused {
    /// The epoch is ahead of the chain's own day index, which `publish_checkpoint` refuses anyway.
    ///
    /// **Refused here so it costs nothing rather than a transaction.** v0.2.4 bounds the program to
    /// the calendar (H-11), so a handoff for tomorrow is a root the worker would carry to a refusal.
    EpochAheadOfToday { epoch: u64, today: u64 },
    /// A handoff for this epoch is already on disk and says something else.
    ///
    /// **Not an overwrite, because the worker may already have acted on it.** A second handoff for one
    /// epoch is either a different root — in which case one of the two is wrong and a process should
    /// not pick — or the same bytes, which is a re-run and allowed.
    AlreadyWrittenDifferently { epoch: u64 },
}

/// Whether the batcher may write this handoff.
///
/// `today` is the caller's day index, `existing` whatever is already at the destination.
pub fn refuse_to_write(
    epoch: u64,
    today: u64,
    existing: Option<&[u8]>,
    bytes: &[u8; HANDOFF_LEN],
) -> Result<(), HandoffWriteRefused> {
    if epoch > today {
        return Err(HandoffWriteRefused::EpochAheadOfToday { epoch, today });
    }
    match existing {
        Some(already) if already != bytes.as_slice() => {
            Err(HandoffWriteRefused::AlreadyWrittenDifferently { epoch })
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use certimining_core::DalekVerifier;
    use ed25519_dalek::{Signer as _, SigningKey};

    const ROOT: Digest = [0x5a; 32];

    fn batcher(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn signed_by(key: &SigningKey, epoch: u64, height: u8, root: Digest) -> Handoff {
        let mut buf = PreimageBuf::new();
        match (HandoffPreimage {
            epoch,
            height,
            root,
        })
        .write_preimage(&mut buf)
        {
            Ok(()) => {}
            Err(e) => panic!("the test's own preimage does not encode: {e:?}"),
        }
        Handoff {
            epoch,
            height,
            root,
            batcher_key: key.verifying_key().to_bytes(),
            signature: key.sign(buf.as_bytes()).to_bytes(),
        }
    }

    #[test]
    fn a_handoff_signed_by_the_expected_key_yields_its_root() {
        let k = batcher(1);
        let h = signed_by(&k, 20_739, 8, ROOT);
        assert_eq!(
            h.verify::<DalekVerifier>(&k.verifying_key().to_bytes(), 20_739),
            Ok(ROOT)
        );
    }

    /// **The key the artifact carries is not the authority.** Anyone can sign a handoff.
    #[test]
    fn a_handoff_signed_by_another_key_is_refused_even_though_its_signature_is_good() {
        let theirs = batcher(2);
        let h = signed_by(&theirs, 20_739, 8, ROOT);
        assert_eq!(
            h.verify::<DalekVerifier>(&batcher(1).verifying_key().to_bytes(), 20_739),
            Err(HandoffRefused::UnexpectedKey),
            "the signature verifies against the key in the file, which is the point: the worker \
             compares against the key it was configured with"
        );
    }

    #[test]
    fn one_changed_byte_in_the_root_breaks_the_signature() {
        let k = batcher(1);
        let mut h = signed_by(&k, 20_739, 8, ROOT);
        h.root[0] ^= 1;
        assert_eq!(
            h.verify::<DalekVerifier>(&k.verifying_key().to_bytes(), 20_739),
            Err(HandoffRefused::BadSignature)
        );
    }

    /// The epoch is signed, so moving a valid handoff to another day is not a replay.
    #[test]
    fn a_handoff_for_another_epoch_is_refused() {
        let k = batcher(1);
        let h = signed_by(&k, 20_739, 8, ROOT);
        assert_eq!(
            h.verify::<DalekVerifier>(&k.verifying_key().to_bytes(), 20_740),
            Err(HandoffRefused::WrongEpoch {
                found: 20_739,
                wanted: 20_740
            })
        );
    }

    #[test]
    fn a_height_outside_1_8s_range_is_refused_before_the_signature_is_checked() {
        let k = batcher(1);
        let h = signed_by(&k, 20_739, 3, ROOT);
        assert_eq!(
            h.verify::<DalekVerifier>(&k.verifying_key().to_bytes(), 20_739),
            Err(HandoffRefused::HeightOutOfRange { height: 3 }),
            "a handoff naming a height this log cannot have built is refused whoever signed it"
        );
    }

    #[test]
    fn encode_and_decode_round_trip() {
        let k = batcher(1);
        let h = signed_by(&k, 20_739, 8, ROOT);
        let bytes = h.encode();
        assert_eq!(bytes.len(), 137, "8 + 1 + 32 + 32 + 64");
        assert_eq!(Handoff::decode(&bytes), Ok(h));
    }

    /// Every field is fixed width, so a short or long file is a wrong file.
    #[test]
    fn a_file_of_the_wrong_length_is_refused_rather_than_parsed() {
        let k = batcher(1);
        let bytes = signed_by(&k, 20_739, 8, ROOT).encode();
        for len in [0usize, 1, 136] {
            assert_eq!(
                Handoff::decode(bytes.get(..len).unwrap_or_default()),
                Err(HandoffRefused::WrongLength { found: len })
            );
        }
        let mut long = bytes.to_vec();
        long.push(0);
        assert_eq!(
            Handoff::decode(&long),
            Err(HandoffRefused::WrongLength { found: 138 })
        );
    }

    /// The decoded artifact is what was signed: a byte flipped anywhere in the encoding either fails
    /// to decode or fails to verify, never decodes into something that passes.
    #[test]
    fn no_single_flipped_byte_survives_verification() {
        let k = batcher(1);
        let expected = k.verifying_key().to_bytes();
        let bytes = signed_by(&k, 20_739, 8, ROOT).encode();
        for i in 0..HANDOFF_LEN {
            let mut broken = bytes;
            match broken.get_mut(i) {
                Some(b) => *b ^= 1,
                None => panic!("index {i} is inside a {HANDOFF_LEN}-byte array"),
            }
            let verdict =
                Handoff::decode(&broken).and_then(|h| h.verify::<DalekVerifier>(&expected, 20_739));
            assert!(
                verdict.is_err(),
                "byte {i} was flipped and the handoff still verified"
            );
        }
    }
}

#[cfg(test)]
mod writing {
    use super::*;

    fn bytes(fill: u8) -> [u8; HANDOFF_LEN] {
        [fill; HANDOFF_LEN]
    }

    #[test]
    fn an_epoch_ahead_of_today_is_refused_before_a_key_is_touched() {
        assert_eq!(
            refuse_to_write(20_739, 20_738, None, &bytes(1)),
            Err(HandoffWriteRefused::EpochAheadOfToday {
                epoch: 20_739,
                today: 20_738
            }),
            "v0.2.4 bounds publish_checkpoint to the calendar, so this would cost a transaction to \
             learn on chain"
        );
    }

    #[test]
    fn today_and_any_earlier_epoch_are_allowed() {
        assert_eq!(refuse_to_write(20_738, 20_738, None, &bytes(1)), Ok(()));
        assert_eq!(
            refuse_to_write(20_700, 20_738, None, &bytes(1)),
            Ok(()),
            "a day the batcher is catching up on is not ahead of anything"
        );
    }

    /// **A re-run is allowed and a disagreement is not.** The worker may already have acted on what
    /// is there.
    #[test]
    fn the_same_handoff_may_be_rewritten_and_a_different_one_may_not() {
        let same = bytes(7);
        assert_eq!(
            refuse_to_write(20_738, 20_738, Some(same.as_slice()), &same),
            Ok(()),
            "identical bytes are a re-run, which has no effect and no risk"
        );
        assert_eq!(
            refuse_to_write(20_738, 20_738, Some(bytes(8).as_slice()), &same),
            Err(HandoffWriteRefused::AlreadyWrittenDifferently { epoch: 20_738 }),
            "two different roots for one epoch is a question a process must not answer"
        );
    }

    /// A file of the wrong length is still a disagreement, not something to parse first.
    #[test]
    fn a_truncated_file_on_disk_counts_as_a_disagreement() {
        assert_eq!(
            refuse_to_write(20_738, 20_738, Some(&[7u8; 10]), &bytes(7)),
            Err(HandoffWriteRefused::AlreadyWrittenDifferently { epoch: 20_738 })
        );
    }
}
