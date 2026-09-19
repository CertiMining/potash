//! E-03: domain-tagged preimage writers (§1.2, §1.3, §1.4, §1.6).
//!
//! Every digest in the engine is Keccak-256 over a preimage that carries exactly one domain tag,
//! first (INV-ENC-01), little-endian fixed-width integers (INV-ENC-02) and `u16`-prefixed byte
//! strings (INV-ENC-04). Holding every preimage here keeps ambiguous concatenation out of the call
//! sites: no caller builds one by hand, and nothing on this path formats a string.
//!
//! Not here: the checkpoint preimage, which the spec never defines and nothing reads (D-30); the
//! PRF behind padding leaves and slot assignment (E-06); and field validation such as the category
//! range, which belongs to the state machine (E-04).

use crate::identity::is_canonical;
use crate::{Digest, Hasher, RegistryError, Result, TAG_ASSET};

/// The sink's capacity (D-33). The largest preimage in schema 1 is the 161-byte leaf.
pub const MAX_PREIMAGE_LEN: usize = 256;

/// Domain tags (§1.2). `TAG_ASSET` is re-exported from the asset commitment it belongs to.
/// `TAG_CKPT` is reserved and unused until something reads a checkpoint preimage (D-30), and
/// `TAG_PRF` belongs to the epoch key and slot PRF of E-06.
pub const TAG_LEAF: [u8; 8] = *b"CMv1LEAF";
/// The tag over both head preimages, the genesis head and each step (§1.3).
pub const TAG_HEAD: [u8; 8] = *b"CMv1HEAD";
/// The tag over a real leaf as it enters the epoch tree (§1.4).
pub const TAG_MTL0: [u8; 8] = *b"CMv1MTL0";
/// The tag over an internal node of the epoch tree (§1.4).
pub const TAG_MTN1: [u8; 8] = *b"CMv1MTN1";
/// The tag over a padding leaf (§1.4).
pub const TAG_PAD: [u8; 8] = *b"CMv1PADD";
/// The tag over a signed inclusion promise (§1.6).
pub const TAG_SPI: [u8; 8] = *b"CMv1SPI0";

/// A submission's identifier (§2.3, D-29).
pub type SubmissionId = [u8; 16];

/// Collects a preimage's bytes in order (§2.2).
pub trait PreimageSink {
    /// Appends `bytes`, or returns `0x0C` if the preimage would outgrow the sink.
    fn write(&mut self, bytes: &[u8]) -> Result<()>;
}

/// The sink this crate provides: a fixed buffer that refuses to grow past `MAX_PREIMAGE_LEN`
/// (D-33). The disclosure package of §2.5 carries these same bytes.
#[derive(Debug, Default, Clone)]
pub struct PreimageBuf(heapless::Vec<u8, MAX_PREIMAGE_LEN>);

impl PreimageBuf {
    /// An empty buffer.
    pub fn new() -> Self {
        Self(heapless::Vec::new())
    }

    /// The bytes written so far.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// How many bytes have been written.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True before anything is written.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl PreimageSink for PreimageBuf {
    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        self.0
            .extend_from_slice(bytes)
            .map_err(|_| RegistryError::RecordTooLarge)
    }
}

/// A preimage: its domain tag, its bytes and its digest under a named hasher (§2.2).
pub trait Preimage {
    /// The one tag this preimage carries, written first (INV-ENC-01).
    const TAG: [u8; 8];

    /// Writes the whole preimage, tag included.
    fn write_preimage(&self, out: &mut dyn PreimageSink) -> Result<()>;

    /// Keccak-256 over the preimage. The caller names the hasher; nothing picks one implicitly
    /// (D-20, D-32).
    fn digest<H: Hasher>(&self) -> Result<Digest> {
        let mut buf = PreimageBuf::new();
        self.write_preimage(&mut buf)?;
        Ok(H::hashv(&[buf.as_bytes()]))
    }
}

/// `c = Keccak256( TAG_ASSET ‖ J ‖ R ‖ len(T) ‖ T )` (§1.3). 23 to 86 bytes.
///
/// `T` must already be canonical, or the write returns `0x11` (D-26), so no call site can commit a
/// raw spelling through this writer either.
#[derive(Debug, Clone, Copy)]
pub struct AssetPreimage<'a> {
    /// `J`, the jurisdiction code.
    pub jurisdiction: &'a [u8; 4],
    /// `R`, the registry code.
    pub registry: &'a [u8; 8],
    /// `T`, the canonical tenure identifier, 1 to 64 bytes.
    pub tenure: &'a [u8],
}

impl Preimage for AssetPreimage<'_> {
    const TAG: [u8; 8] = TAG_ASSET;

    fn write_preimage(&self, out: &mut dyn PreimageSink) -> Result<()> {
        if !is_canonical(self.tenure) {
            return Err(RegistryError::CanonicalizationFailed);
        }
        // len(T) is a u16, little-endian (INV-ENC-02, INV-ENC-04).
        let len = u16::try_from(self.tenure.len())
            .map_err(|_| RegistryError::CanonicalizationFailed)?
            .to_le_bytes();
        out.write(&Self::TAG)?;
        out.write(self.jurisdiction)?;
        out.write(self.registry)?;
        out.write(&len)?;
        out.write(self.tenure)
    }
}

/// `h₀ = Keccak256( TAG_HEAD ‖ c ‖ schema_version )` (§1.3). 42 bytes.
#[derive(Debug, Clone, Copy)]
pub struct GenesisHeadPreimage {
    /// `c`, the asset commitment.
    pub asset_commitment: Digest,
    /// The schema version, a `u16` (§2.4).
    pub schema_version: u16,
}

impl Preimage for GenesisHeadPreimage {
    const TAG: [u8; 8] = TAG_HEAD;

    fn write_preimage(&self, out: &mut dyn PreimageSink) -> Result<()> {
        out.write(&Self::TAG)?;
        out.write(&self.asset_commitment)?;
        out.write(&self.schema_version.to_le_bytes())
    }
}

/// `leafₙ₊₁ = Keccak256( TAG_LEAF ‖ c ‖ seq ‖ payload_digest ‖ assessment_digest ‖ qp_key ‖
/// category ‖ effective_at ‖ change_identified_at )` (§1.3, D-28). 161 bytes.
///
/// Flags are computed from chain state and stay out of this preimage (INV-STATE-06a), and so does
/// `payload_uri`, which the state machine validates instead (§1.3, condition f).
#[derive(Debug, Clone, Copy)]
pub struct LeafPreimage {
    /// `c`, the asset commitment.
    pub asset_commitment: Digest,
    /// `n+1`, the record's sequence number.
    pub seq: u64,
    /// The digest of the payload this record points at.
    pub payload_digest: Digest,
    /// The digest of the materiality memo, or zeros when there is none (INV-STATE-05).
    pub assessment_digest: Digest,
    /// The qualified person's Ed25519 public key.
    pub qp_key: [u8; 32],
    /// The CIM category, 0 to 4 under schema 1 (INV-STATE-06). E-04 rejects anything else.
    pub category: u8,
    /// Unix seconds, signed, matching the on-chain clock (D-28).
    pub effective_at: i64,
    /// Unix seconds, signed, or zero when there is no memo (INV-STATE-05).
    pub change_identified_at: i64,
}

impl Preimage for LeafPreimage {
    const TAG: [u8; 8] = TAG_LEAF;

    fn write_preimage(&self, out: &mut dyn PreimageSink) -> Result<()> {
        out.write(&Self::TAG)?;
        out.write(&self.asset_commitment)?;
        out.write(&self.seq.to_le_bytes())?;
        out.write(&self.payload_digest)?;
        out.write(&self.assessment_digest)?;
        out.write(&self.qp_key)?;
        out.write(&[self.category])?;
        out.write(&self.effective_at.to_le_bytes())?;
        out.write(&self.change_identified_at.to_le_bytes())
    }
}

/// `hₙ₊₁ = Keccak256( TAG_HEAD ‖ hₙ ‖ leafₙ₊₁ )` (§1.3). 72 bytes, so it can never be read as a
/// genesis head, which is 42.
#[derive(Debug, Clone, Copy)]
pub struct StepHeadPreimage {
    /// `hₙ`, the previous head.
    pub prev_head: Digest,
    /// `leafₙ₊₁`, the leaf being appended.
    pub leaf: Digest,
}

impl Preimage for StepHeadPreimage {
    const TAG: [u8; 8] = TAG_HEAD;

    fn write_preimage(&self, out: &mut dyn PreimageSink) -> Result<()> {
        out.write(&Self::TAG)?;
        out.write(&self.prev_head)?;
        out.write(&self.leaf)
    }
}

/// `real leaf = Keccak256( TAG_MTL0 ‖ leafₙ )` (§1.4, D-31). 40 bytes.
#[derive(Debug, Clone, Copy)]
pub struct RealLeafPreimage {
    /// The chain leaf entering the epoch tree.
    pub leaf: Digest,
}

impl Preimage for RealLeafPreimage {
    const TAG: [u8; 8] = TAG_MTL0;

    fn write_preimage(&self, out: &mut dyn PreimageSink) -> Result<()> {
        out.write(&Self::TAG)?;
        out.write(&self.leaf)
    }
}

/// `padding leaf = Keccak256( TAG_PAD ‖ PRF(k_e, 0x03 ‖ slot_index_le) )` (§1.4). 40 bytes.
///
/// The PRF itself is E-06's; this writer takes its output, so the epoch key never reaches here.
#[derive(Debug, Clone, Copy)]
pub struct PaddingPreimage {
    /// The PRF output for this slot.
    pub prf_output: Digest,
}

impl Preimage for PaddingPreimage {
    const TAG: [u8; 8] = TAG_PAD;

    fn write_preimage(&self, out: &mut dyn PreimageSink) -> Result<()> {
        out.write(&Self::TAG)?;
        out.write(&self.prf_output)
    }
}

/// `internal node = Keccak256( TAG_MTN1 ‖ left ‖ right )` (§1.4, D-31). 72 bytes.
#[derive(Debug, Clone, Copy)]
pub struct NodePreimage {
    /// The left child's digest.
    pub left: Digest,
    /// The right child's digest.
    pub right: Digest,
}

impl Preimage for NodePreimage {
    const TAG: [u8; 8] = TAG_MTN1;

    fn write_preimage(&self, out: &mut dyn PreimageSink) -> Result<()> {
        out.write(&Self::TAG)?;
        out.write(&self.left)?;
        out.write(&self.right)
    }
}

/// The signed inclusion promise's preimage,
/// `Keccak256( TAG_SPI ‖ leaf ‖ submission_id ‖ promised_epoch ‖ max_merge_delay )` (§1.6, D-29).
/// 65 bytes.
#[derive(Debug, Clone, Copy)]
pub struct SpiPreimage {
    /// The exact leaf the promise binds (INV-SPI-02).
    pub leaf: Digest,
    /// The submission's identifier.
    pub submission_id: SubmissionId,
    /// The epoch the batcher promises inclusion in.
    pub promised_epoch: u64,
    /// The merge delay in epochs, which INV-SPI-01 fixes at 2.
    pub max_merge_delay: u8,
}

impl Preimage for SpiPreimage {
    const TAG: [u8; 8] = TAG_SPI;

    fn write_preimage(&self, out: &mut dyn PreimageSink) -> Result<()> {
        out.write(&Self::TAG)?;
        out.write(&self.leaf)?;
        out.write(&self.submission_id)?;
        out.write(&self.promised_epoch.to_le_bytes())?;
        out.write(&[self.max_merge_delay])
    }
}

/// Reads the domain tag at the head of `bytes` (D-36). Fewer than eight bytes is a malformed
/// payload, `0x05` (V-N-18).
pub fn read_tag(bytes: &[u8]) -> Result<[u8; 8]> {
    let head = bytes.get(..8).ok_or(RegistryError::MalformedPayload)?;
    <[u8; 8]>::try_from(head).map_err(|_| RegistryError::MalformedPayload)
}

/// Checks that `bytes` begins with `expected`. A wrong tag is `0x0B` (V-N-09, D-36).
pub fn check_tag(bytes: &[u8], expected: [u8; 8]) -> Result<()> {
    if read_tag(bytes)? == expected {
        Ok(())
    } else {
        Err(RegistryError::DomainTagMismatch)
    }
}
