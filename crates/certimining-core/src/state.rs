//! E-04: the supersession state machine (§1.3; D-37 to D-47).
//!
//! Each record commits against its predecessor's head, and nothing is ever rewritten or removed
//! (INV-STATE-01). A transition is accepted only if all six conditions of §1.3 hold; the category
//! sequence is the exception, which sets a flag and never rejects (INV-STATE-06, D-01). Flags are
//! observations, computed from chain state and excluded from the leaf preimage (INV-STATE-06a).

use core::marker::PhantomData;

use crate::preimage::{GenesisHeadPreimage, LeafPreimage, Preimage, PreimageBuf, StepHeadPreimage};
use crate::verify::Verifier;
use crate::{Digest, Hasher, RegistryError, Result};

/// The longest `payload_uri` a record may carry (§1.8).
pub const MAX_PAYLOAD_URI_LEN: usize = 128;

/// A record's payload URI, at most 128 bytes (§1.8).
pub type PayloadUri = heapless::Vec<u8, MAX_PAYLOAD_URI_LEN>;

/// The only schema version this engine writes or accepts (§2.4).
pub const SCHEMA_VERSION: u16 = 1;

/// Flag bit 0: a reserve category with no earlier resource record (INV-STATE-06).
pub const FLAG_RESERVE_WITHOUT_PRIOR_RESOURCE: u16 = 1;

/// Flag bit 1: the category is lower than the previous record's (D-42).
pub const FLAG_CATEGORY_DOWNGRADE: u16 = 1 << 1;

/// The highest CIM category schema 1 accepts: 0 to 2 are resources, 3 and 4 reserves
/// (INV-STATE-06).
const MAX_CATEGORY: u8 = 4;

/// One record as it arrives (§2.2, D-40). `c` is not here: the chain holds it.
#[derive(Debug, Clone)]
pub struct RecordLeafInput {
    /// The head this record commits against (§1.3, condition a).
    pub prev_head: Digest,
    /// This record's sequence number, which must be the chain's next (condition b).
    pub seq: u64,
    /// The digest of the payload this record points at.
    pub payload_digest: Digest,
    /// The materiality memo's digest, or zeros when there is none (INV-STATE-05).
    pub assessment_digest: Digest,
    /// The qualified person's public key, which the signature must verify under.
    pub qp_key: [u8; 32],
    /// The key the caller expected. Present and different from `qp_key` is `0x08` (D-41).
    pub expected_qp_key: Option<[u8; 32]>,
    /// The QP's signature over the leaf preimage (D-37). Absent is `0x06`.
    pub signature: Option<[u8; 64]>,
    /// The CIM category, 0 to 4 (INV-STATE-06). Anything else is `0x05` (V-N-07b).
    pub category: u8,
    /// Unix seconds, signed, non-decreasing along the chain (INV-STATE-04).
    pub effective_at: i64,
    /// Unix seconds, or zero when there is no memo (INV-STATE-05).
    pub change_identified_at: i64,
    /// Where the payload lives (§1.8, D-43). Validated, never hashed.
    pub payload_uri: PayloadUri,
    /// The §2.6 hook. Always absent under schema 1, and never hashed (D-40).
    pub ext_commitment: Option<Digest>,
}

/// What one accepted transition produced (§2.2, D-47). A refused transition produces nothing, so
/// no stale value can be read back afterwards.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Applied {
    /// The leaf digest, which the batcher submits and a promise binds.
    pub leaf: Digest,
    /// The chain's new head.
    pub head: Digest,
    /// Observations about this record, excluded from its preimage (INV-STATE-06a).
    pub flags: u16,
}

/// Enough of a chain to resume it in another process. A chain outlives the program that built it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainSnapshot {
    /// The current head.
    pub head: Digest,
    /// How many records the chain holds.
    pub seq: u64,
    /// The newest effective date seen (INV-STATE-04).
    pub last_effective_at: i64,
    /// Whether any earlier record carried category 1 or 2 (INV-STATE-06).
    pub saw_resource: bool,
    /// The previous record's category, absent on an empty chain (D-42).
    pub previous_category: Option<u8>,
}

/// The append-only chain of one asset (§2.2).
pub trait ChainState {
    /// `h₀ = Keccak256( TAG_HEAD ‖ c ‖ schema_version )` (§1.3). A schema other than 1 is `0x0F`.
    fn genesis(asset_commitment: &Digest, schema_version: u16) -> Result<Digest>;
    /// The leaf digest this record would produce, without applying it.
    fn leaf(&self, r: &RecordLeafInput) -> Result<Digest>;
    /// Applies the record if every condition of §1.3 holds, and otherwise changes nothing.
    fn apply(&mut self, r: &RecordLeafInput) -> Result<Applied>;
    /// The current head.
    fn head(&self) -> Digest;
    /// How many records the chain holds.
    fn seq(&self) -> u64;
}

/// One asset's chain, over a named hasher and a named verifier (D-20, D-38).
///
/// There is no delete, no compaction and no rewrite: the type exposes no way to lower `seq` or to
/// replace a head (INV-STATE-01).
#[derive(Debug, Clone)]
pub struct AssetChain<H, V> {
    asset_commitment: Digest,
    schema_version: u16,
    head: Digest,
    seq: u64,
    last_effective_at: i64,
    saw_resource: bool,
    previous_category: Option<u8>,
    _marker: PhantomData<fn() -> (H, V)>,
}

impl<H: Hasher, V: Verifier> AssetChain<H, V> {
    /// Starts a chain at its genesis head. A schema other than 1 is `0x0F` (V-N-13).
    pub fn start(asset_commitment: &Digest, schema_version: u16) -> Result<Self> {
        let head = <Self as ChainState>::genesis(asset_commitment, schema_version)?;
        Ok(Self {
            asset_commitment: *asset_commitment,
            schema_version,
            head,
            seq: 0,
            last_effective_at: i64::MIN,
            saw_resource: false,
            previous_category: None,
            _marker: PhantomData,
        })
    }

    /// Resumes a chain from stored state, because a chain outlives the process that built it. It
    /// is also the only way to reach a chain at `u64::MAX`, which V-N-20 requires.
    pub fn resume(
        asset_commitment: &Digest,
        schema_version: u16,
        snapshot: ChainSnapshot,
    ) -> Result<Self> {
        if schema_version != SCHEMA_VERSION {
            return Err(RegistryError::UnsupportedSchemaVersion);
        }
        if snapshot.previous_category.is_some_and(|c| c > MAX_CATEGORY) {
            return Err(RegistryError::MalformedPayload);
        }
        Ok(Self {
            asset_commitment: *asset_commitment,
            schema_version,
            head: snapshot.head,
            seq: snapshot.seq,
            last_effective_at: snapshot.last_effective_at,
            saw_resource: snapshot.saw_resource,
            previous_category: snapshot.previous_category,
            _marker: PhantomData,
        })
    }

    /// The state another process needs to resume this chain.
    pub fn snapshot(&self) -> ChainSnapshot {
        ChainSnapshot {
            head: self.head,
            seq: self.seq,
            last_effective_at: self.last_effective_at,
            saw_resource: self.saw_resource,
            previous_category: self.previous_category,
        }
    }

    /// The asset commitment this chain belongs to. It never leaves the issuer's control
    /// (INV-STATE-03), so nothing here writes it anywhere.
    pub fn asset_commitment(&self) -> Digest {
        self.asset_commitment
    }

    /// The schema version this chain was started under.
    pub fn schema_version(&self) -> u16 {
        self.schema_version
    }

    /// Builds the leaf preimage once, and returns its bytes with its digest: the signature covers
    /// those bytes (D-37) and the leaf is their hash.
    fn leaf_bytes(&self, r: &RecordLeafInput) -> Result<(PreimageBuf, Digest)> {
        let preimage = LeafPreimage {
            asset_commitment: self.asset_commitment,
            seq: r.seq,
            payload_digest: r.payload_digest,
            assessment_digest: r.assessment_digest,
            qp_key: r.qp_key,
            category: r.category,
            effective_at: r.effective_at,
            change_identified_at: r.change_identified_at,
        };
        let mut buf = PreimageBuf::new();
        preimage.write_preimage(&mut buf)?;
        let digest = H::hashv(&[buf.as_bytes()]);
        Ok((buf, digest))
    }

    /// Field shapes, checked before anything is hashed.
    fn check_shape(r: &RecordLeafInput) -> Result<()> {
        if r.category > MAX_CATEGORY {
            // V-N-07b. The category is recorded, never used to reject on sequence (INV-STATE-06).
            return Err(RegistryError::MalformedPayload);
        }
        if !payload_uri_is_well_formed(&r.payload_uri) {
            return Err(RegistryError::MalformedPayload); // V-N-03
        }
        if r.ext_commitment.is_some() {
            // The §2.6 hook carries nothing under schema 1 (D-40). A record that sets it is not a
            // schema-1 record, and accepting it silently would leave the caller believing the
            // extension was committed.
            return Err(RegistryError::UnsupportedSchemaVersion);
        }
        Ok(())
    }

    /// Condition (c) with its three codes (D-41): a claimed key that is not the expected one is
    /// `0x08`, an absent signature `0x06`, and a signature that does not verify `0x07`.
    fn check_attestation(r: &RecordLeafInput, preimage: &[u8]) -> Result<()> {
        if let Some(expected) = r.expected_qp_key {
            if expected != r.qp_key {
                return Err(RegistryError::AttestationKeyMismatch);
            }
        }
        let signature = r
            .signature
            .as_ref()
            .ok_or(RegistryError::AttestationMissing)?;
        V::verify(&r.qp_key, preimage, signature)
    }

    /// The observations this record earns (INV-STATE-06, D-42). Never a rejection path.
    fn flags_for(&self, r: &RecordLeafInput) -> u16 {
        let mut flags = 0;
        if matches!(r.category, 3 | 4) && !self.saw_resource {
            flags |= FLAG_RESERVE_WITHOUT_PRIOR_RESOURCE;
        }
        if self.previous_category.is_some_and(|prev| r.category < prev) {
            flags |= FLAG_CATEGORY_DOWNGRADE;
        }
        flags
    }
}

impl<H: Hasher, V: Verifier> ChainState for AssetChain<H, V> {
    fn genesis(asset_commitment: &Digest, schema_version: u16) -> Result<Digest> {
        if schema_version != SCHEMA_VERSION {
            return Err(RegistryError::UnsupportedSchemaVersion); // V-N-13
        }
        GenesisHeadPreimage {
            asset_commitment: *asset_commitment,
            schema_version,
        }
        .digest::<H>()
    }

    fn leaf(&self, r: &RecordLeafInput) -> Result<Digest> {
        Self::check_shape(r)?;
        self.leaf_bytes(r).map(|(_, digest)| digest)
    }

    fn apply(&mut self, r: &RecordLeafInput) -> Result<Applied> {
        Self::check_shape(r)?;
        if r.prev_head != self.head {
            return Err(RegistryError::HeadMismatch); // (a) 0x03
        }
        // INV-STATE-07: every step is checked. A chain at u64::MAX has nowhere to go (V-N-20).
        let next_seq = self
            .seq
            .checked_add(1)
            .ok_or(RegistryError::ArithmeticOverflow)?; // 0x10
        if r.seq != next_seq {
            return Err(RegistryError::SequenceOutOfOrder); // (b) 0x04
        }
        let (preimage, leaf) = self.leaf_bytes(r)?;
        Self::check_attestation(r, preimage.as_bytes())?; // (c) 0x06, 0x07, 0x08
        if r.effective_at < self.last_effective_at {
            return Err(RegistryError::NonMonotonicEffectiveAt); // (d) 0x0A
        }
        let flags = self.flags_for(r); // (e) observations only
        let head = StepHeadPreimage {
            prev_head: self.head,
            leaf,
        }
        .digest::<H>()?;

        // Nothing above this line changed the chain, so a refused record leaves it untouched.
        self.head = head;
        self.seq = next_seq;
        self.last_effective_at = r.effective_at;
        self.saw_resource = self.saw_resource || matches!(r.category, 1 | 2);
        self.previous_category = Some(r.category);
        Ok(Applied { leaf, head, flags })
    }

    fn head(&self) -> Digest {
        self.head
    }

    fn seq(&self) -> u64 {
        self.seq
    }
}

/// `payload_uri` as §1.3 defines it (D-43): 1 to 128 bytes, printable ASCII, one of three schemes,
/// at least one byte after the scheme. Nothing further is parsed, and no URI is resolved.
pub fn payload_uri_is_well_formed(uri: &[u8]) -> bool {
    const SCHEMES: [&[u8]; 3] = [b"ipfs://", b"https://", b"ar://"];
    if uri.is_empty() || uri.len() > MAX_PAYLOAD_URI_LEN {
        return false;
    }
    if !uri.iter().all(|b| (0x21..=0x7E).contains(b)) {
        return false;
    }
    SCHEMES
        .iter()
        .any(|scheme| uri.len() > scheme.len() && uri.starts_with(scheme))
}
