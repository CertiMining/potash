/**
 * What one epoch's publication looks like on chain, laid out from the document.
 *
 * Scene 1's claim is §4.4's V-Z-01: across record counts, the instruction length, the transaction
 * length, the account size and the field layout are identical, and a byte may differ only if the
 * epoch number, the publication schedule or a pseudorandom digest fixes it. That list is **closed**:
 * §4.3 says adding a byte to it requires amending the specification, never editing the test.
 *
 * This file is not the test. `programs/certimining-checkpoint/tests/privacy.rs` is, it runs under
 * LiteSVM against the real program, and it is the authority. What this does is build the same two
 * artefacts from the same offsets so that a viewer can move the record count and watch the diff not
 * move — which is what the acceptance criterion means by rendering the control rather than asserting
 * it. The scene says so on screen.
 *
 * Offsets come from §2.4's account table and §1.8's instruction length, and the decoder in
 * `ts/src/solana/accounts.ts` reads the same ones; `demo/test/footprint.test.mjs` round-trips these
 * bytes through that decoder, so the two cannot drift apart unnoticed.
 */

/** §2.4: `CheckpointAccount` is 106 bytes. */
export const CHECKPOINT_LEN = 106;
/**
 * §1.8: `publish_checkpoint`'s instruction data is 49 bytes.
 *
 * It was 48 until v0.2.7 moved the checkpoint PDA's bump into the instruction data, so the program
 * derives the address with one `create_program_address` call instead of searching for the canonical
 * bump. This page said 48 from then until it was corrected, which is the whole reason the length is
 * a named constant here and not a number typed into the markup.
 */
export const INSTRUCTION_LEN = 49;

/**
 * The account's fields, in the document's order, with the offset each begins at.
 *
 * `mayDiffer` marks the six V-Z-01 permits and says which of the three reasons allows it. A field
 * without one must be byte-identical across record counts, and the scene fails loudly if it is not.
 */
export const ACCOUNT_FIELDS = [
  { name: "discriminator", at: 0, len: 8 },
  { name: "schema_version", at: 8, len: 2 },
  { name: "epoch", at: 10, len: 8, mayDiffer: "the epoch number" },
  { name: "root", at: 18, len: 32, mayDiffer: "a pseudorandom digest" },
  { name: "published_slot", at: 50, len: 8, mayDiffer: "the publication schedule" },
  { name: "published_unix", at: 58, len: 8, mayDiffer: "the publication schedule" },
  { name: "receipt_digest", at: 66, len: 32, mayDiffer: "a pseudorandom digest" },
  { name: "anchor_kind", at: 98, len: 1 },
  { name: "bump", at: 99, len: 1, mayDiffer: "the epoch number" },
  { name: "reserved", at: 100, len: 6 },
];

/**
 * `publish_checkpoint`'s instruction data: the Anchor discriminator, then the three arguments.
 *
 * **`checkpoint_bump` carries no permit, deliberately.** It follows from the epoch and the program
 * id, and this scene holds the epoch fixed and varies only the record count — so the bump cannot
 * legitimately move here, and a permit would let a defect that moved it with the count pass as
 * allowed. The account's own `bump` field does carry one, because §4.4's V-Z-01 names it among the
 * six; that list is the specification's and is wider than this scene needs.
 *
 * The first version of this change did give it a permit, and `demo/test/footprint.test.mjs` refused
 * it: the permitted set is written out there so that widening it in code fails, which is what §4.3
 * means by the list being amended in the specification rather than in the code. The test was right.
 */
export const INSTRUCTION_FIELDS = [
  { name: "discriminator", at: 0, len: 8 },
  { name: "epoch", at: 8, len: 8, mayDiffer: "the epoch number" },
  { name: "root", at: 16, len: 32, mayDiffer: "a pseudorandom digest" },
  { name: "checkpoint_bump", at: 48, len: 1 },
];

function u16le(view, at, value) {
  view[at] = value & 0xff;
  view[at + 1] = (value >> 8) & 0xff;
}

function u64le(view, at, value) {
  let v = BigInt(value);
  for (let i = 0; i < 8; i++) {
    view[at + i] = Number(v & 0xffn);
    v >>= 8n;
  }
}

/**
 * The account the program writes for one epoch.
 *
 * Everything except `root` is held fixed by the caller on purpose. If the scene varied the epoch
 * alongside the record count, the diff would show two causes at once and prove neither — which is
 * the confound that had to be taken out of V-Z-01's own byte comparison before it meant anything.
 */
export function checkpointAccount({ discriminator, epoch, root, publishedSlot, publishedUnix, receiptDigest, anchorKind, bump }) {
  const out = new Uint8Array(CHECKPOINT_LEN);
  out.set(discriminator, 0);
  u16le(out, 8, 1);
  u64le(out, 10, epoch);
  out.set(root, 18);
  u64le(out, 50, publishedSlot);
  u64le(out, 58, publishedUnix);
  out.set(receiptDigest, 66);
  out[98] = anchorKind;
  out[99] = bump;
  return out;
}

export function publishInstruction({ discriminator, epoch, root, bump }) {
  const out = new Uint8Array(INSTRUCTION_LEN);
  out.set(discriminator, 0);
  u64le(out, 8, epoch);
  out.set(root, 16);
  // The bump the publisher derived off chain, which is the one the account then stores — so the
  // same value the account panel shows at offset 99, not a second opinion about it.
  out[48] = bump;
  return out;
}

/** Which field an offset falls in, so a differing byte can be named rather than counted. */
export function fieldAt(fields, offset) {
  return fields.find((f) => offset >= f.at && offset < f.at + f.len);
}

/**
 * Every offset at which two byte strings differ, with the field it belongs to and whether V-Z-01
 * permits it. `unpermitted` is what the scene has to show as a failure if it is ever non-empty.
 */
export function diff(fields, a, b) {
  if (a.length !== b.length) {
    return { lengthDiffers: true, offsets: [], unpermitted: [], byField: new Map() };
  }
  const offsets = [];
  const byField = new Map();
  for (let i = 0; i < a.length; i++) {
    if (a[i] === b[i]) continue;
    offsets.push(i);
    const field = fieldAt(fields, i);
    const key = field ? field.name : `unnamed@${i}`;
    byField.set(key, (byField.get(key) ?? 0) + 1);
  }
  const unpermitted = offsets.filter((i) => {
    const field = fieldAt(fields, i);
    return field === undefined || field.mayDiffer === undefined;
  });
  return { lengthDiffers: false, offsets, unpermitted, byField };
}
