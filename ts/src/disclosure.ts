/**
 * §2.5's disclosure package, and INV-DISC-02's conforming verifier.
 *
 * INV-DISC-02: "A conforming verifier recomputes the leaf from `preimage_borsh`, checks the QP
 * signature, walks the chain segment, verifies inclusion against a root it fetched from Solana
 * independently, and fails closed on any disagreement between JSON fields and the Borsh preimage."
 *
 * The order below is fixed by that sentence plus INV-ENC-03: the display copy is checked against
 * the bytes *first*, before any signature check and before any inclusion check, because until the
 * two agree there is no single record to judge. Flags are excluded from that comparison, per
 * INV-DISC-03.
 */
import { type Digest, base64Decode, bytesEqual, fromHex, readI64le, readU64le, toHex } from "./bytes.ts";
import { type Failure, PackageFailure, RegistryFailure, describeFailure, isFailure } from "./errors.ts";
import { SCHEMA_VERSION, advanceHead, computeFlags, type ChainState } from "./chain.ts";
import { ed25519Verify, keccak256 } from "./hash.ts";
import { genesisHeadPreimage, readTagged } from "./preimage.ts";
import { TAG_LEAF } from "./tags.ts";
import { type InclusionProof, verifyInclusion, verifyInclusionForHeight } from "./tree.ts";
import { type PublishedRoot } from "./promise.ts";

export const DISCLOSURE_SCHEMA = "certimining/v1/disclosure";
export const LEAF_PREIMAGE_LEN = 161;

export type DisclosurePackage = {
  schema: string;
  record: {
    seq: number | string;
    category: number;
    effective_at: number | string;
    change_identified_at: number | string;
    payload_digest: string;
    assessment_digest: string;
    qp_key: string;
    payload_uri: string;
    flags: number;
  };
  preimage_borsh: string;
  chain: { prev_head: string; head: string; genesis: string };
  qp_signature: string;
  inclusion: { epoch: number | string; height: number; slot_index: number; siblings: string[] };
  anchor?: { solana_tx?: string; solana_slot?: number | string; ots_receipt_digest?: string };
};

/** What the 161 bytes say, once they have been read as §1.3 lays them out. */
export type LeafFromBytes = {
  assetCommitment: Digest;
  seq: bigint;
  payloadDigest: Digest;
  assessmentDigest: Digest;
  qpKey: Uint8Array;
  category: number;
  effectiveAt: bigint;
  changeIdentifiedAt: bigint;
};

export type FlagReport = {
  declared: number;
  recomputed: number | null;
  /** null when no chain context was supplied, so nothing could be recomputed (INV-DISC-03). */
  discrepancy: boolean | null;
  note: string;
};

/**
 * What a verifier holding **one** record can say about where that record sits in its chain.
 *
 * §1.3's leaf preimage covers `c`, `seq`, the two digests, `qp_key`, `category` and the two dates.
 * It does not cover `prev_head` or `head`, so no signature binds them, and the inclusion proof binds
 * only the leaf, which is the digest of those 161 bytes. INV-STATE-02 recomputes `hₙ` from `h_m` and
 * the leaves between, which one package does not carry. So `prev_head` is pinned in exactly two
 * cases: at `seq` 1, where it must be `h₀` and `h₀` follows from the signed `c`; and when the caller
 * supplies the head it expects, the way §2.2 supplies `expected_qp_key` and §2.3 an observed epoch.
 * Otherwise the head step is an arithmetic relation between two values the package chose itself, and
 * reporting it as a passing chain check would tell a reader something that was never established.
 */
export type ChainPosition = {
  established: boolean;
  detail: string;
};

export type DisclosureReport = {
  ok: boolean;
  failure?:
    | { kind: "registry"; code: number; codeName: string; message: string }
    | { kind: "package"; failure: string; message: string }
    | undefined;
  leaf?: Digest | undefined;
  fields?: LeafFromBytes | undefined;
  flags?: FlagReport | undefined;
  /** What this package establishes about the record's place in its chain, and what it does not. */
  chainPosition: ChainPosition;
  /**
   * Each check the verifier ran, in the order it ran them. `unestablished` is not a weaker pass: it
   * says the check's subject cannot be settled from what a package carries.
   */
  checks: Array<{ name: string; status: "pass" | "fail" | "skipped" | "unestablished"; detail?: string }>;
  notes: string[];
};

export type VerifyOptions = {
  /** The root the counterparty obtained for the proof's epoch, from the chain or from a caller. */
  root: PublishedRoot;
  /** The log's configured `H` (§2.4 `LogConfig.tree_height`). Given, a disagreeing proof is 0x13. */
  configuredHeight?: number;
  /**
   * What the holder knows of the chain before this record, if anything. Supplied, flags are
   * recomputed and a mismatch is reported as a discrepancy (INV-DISC-03); absent, flags are
   * reported as not recomputable, because one package does not carry its own history.
   */
  chainContext?: {
    sawResource: boolean;
    previousCategory: number | null;
    /**
     * The head the caller expects this record to commit against, if they hold it — from the previous
     * package, or from their own copy of the chain. Supplied, `prev_head` is judged against it and a
     * disagreement is 0x03, which is §1.3's condition (a); absent, the chain position is reported as
     * not established rather than as passing.
     */
    expectedPrevHead?: Uint8Array;
  };
};

/**
 * §2.5's field list. V-Z-05 passes only when a disclosure package holds "only the fields §2.5
 * lists", and INV-DISC-01 says the package never contains the epoch key, sibling preimages or any
 * other asset's data. Together those make the list exhaustive rather than illustrative, so a field
 * outside it is refused: the risk is not a malformed shape but a leak in a corner nothing reads.
 *
 * "scalar" is a field §2.5 shows as a value; "scalars" is an array of them. Refusing a structure
 * where §2.5 shows a value closes the remaining hiding place, a nested object under a field this
 * verifier never has to read.
 */
type Shape = "scalar" | "scalars" | { [field: string]: Shape };

const PACKAGE_SHAPE: { [field: string]: Shape } = {
  schema: "scalar",
  record: {
    seq: "scalar",
    category: "scalar",
    effective_at: "scalar",
    change_identified_at: "scalar",
    payload_digest: "scalar",
    assessment_digest: "scalar",
    qp_key: "scalar",
    payload_uri: "scalar",
    flags: "scalar",
  },
  preimage_borsh: "scalar",
  chain: { prev_head: "scalar", head: "scalar", genesis: "scalar" },
  qp_signature: "scalar",
  inclusion: { epoch: "scalar", height: "scalar", slot_index: "scalar", siblings: "scalars" },
  anchor: { solana_tx: "scalar", solana_slot: "scalar", ots_receipt_digest: "scalar" },
};

function isContainer(value: unknown): boolean {
  return value !== null && typeof value === "object";
}

/**
 * A container must be a plain object, so that the fields this walk inspects are the fields the
 * readers below go on to use. A package arrives as JSON text and `JSON.parse` produces exactly
 * this; anything else would let a prototype carry fields the walk never sees.
 */
function isPlainObject(value: unknown): boolean {
  if (!isContainer(value) || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

/**
 * Refuses the first field §2.5 does not list, naming its path. It says nothing about a listed field
 * that is absent: §2.5 fixes what a package may carry, and the fields this verifier needs are
 * required where it reads them.
 */
export function checkOnlyListedFields(value: unknown, shape: Shape, path: string): void {
  if (shape === "scalar") {
    if (isContainer(value)) {
      throw new PackageFailure("UnlistedField", `${path} carries a structure where §2.5 shows a single value`);
    }
    return;
  }
  if (shape === "scalars") {
    if (!Array.isArray(value)) throw new PackageFailure("MalformedPackage", `${path} is not an array`);
    value.forEach((element, i) => checkOnlyListedFields(element, "scalar", `${path}[${i}]`));
    return;
  }
  if (!isPlainObject(value)) {
    throw new PackageFailure("MalformedPackage", `${path === "" ? "the package" : path} is not a plain object`);
  }
  for (const [field, child] of Object.entries(value as Record<string, unknown>)) {
    // Membership is tested against the shape written above, with `Object.hasOwn`, and never by
    // indexing it: `shape["constructor"]`, `shape["__proto__"]` and `shape["toString"]` all find
    // something inherited from `Object.prototype`, so indexing would let §2.5's closure and V-Z-05
    // be bypassed by choice of name alone. Those names survive a JSON round trip as own properties.
    if (!Object.hasOwn(shape, field)) {
      throw new PackageFailure("UnlistedField", `${path === "" ? "" : `${path}.`}${field} is not a field §2.5 lists`);
    }
    checkOnlyListedFields(child, shape[field]!, path === "" ? field : `${path}.${field}`);
  }
}

function must<T>(value: T | undefined | null, what: string): T {
  if (value === undefined || value === null) throw new PackageFailure("MalformedPackage", `missing ${what}`);
  return value;
}

function hexField(value: unknown, what: string, len: number): Uint8Array {
  if (typeof value !== "string") throw new PackageFailure("MalformedPackage", `${what} is not a string`);
  try {
    return fromHex(value, len);
  } catch (e) {
    throw new PackageFailure("MalformedPackage", `${what}: ${(e as Error).message}`);
  }
}

/** JSON carries integers as numbers or as decimal strings; either is read exactly or refused. */
function intField(value: unknown, what: string): bigint {
  if (typeof value === "bigint") return value;
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      throw new PackageFailure("MalformedPackage", `${what} is not an exactly representable integer`);
    }
    return BigInt(value);
  }
  if (typeof value === "string" && /^-?\d+$/.test(value)) return BigInt(value);
  throw new PackageFailure("MalformedPackage", `${what} is not an integer`);
}

function smallInt(value: unknown, what: string, max: number): number {
  const v = intField(value, what);
  if (v < 0n || v > BigInt(max)) throw new PackageFailure("MalformedPackage", `${what} is outside 0..${max}`);
  return Number(v);
}

/**
 * Reads the 161 bytes as §1.3 lays them out. A buffer carrying another domain tag is 0x0B
 * (V-N-09); one of the wrong length has no fields to judge and is 0x05.
 */
export function readLeafPreimage(preimage: Uint8Array): LeafFromBytes {
  if (preimage.length !== LEAF_PREIMAGE_LEN) {
    throw new RegistryFailure("MalformedPayload", `leaf preimage is ${preimage.length} bytes, and §1.3 fixes it at ${LEAF_PREIMAGE_LEN}`);
  }
  const body = readTagged(preimage, TAG_LEAF);
  return {
    assetCommitment: body.slice(0, 32),
    seq: readU64le(body, 32),
    payloadDigest: body.slice(40, 72),
    assessmentDigest: body.slice(72, 104),
    qpKey: body.slice(104, 136),
    category: body[136]!,
    effectiveAt: readI64le(body, 137),
    changeIdentifiedAt: readI64le(body, 145),
  };
}

/**
 * The display copy against the bytes, in the order §1.3 writes the fields, stopping at the first
 * that differs. `flags` is excluded (INV-DISC-03); `payload_uri` has no counterpart in a schema-1
 * leaf preimage and so cannot be compared at all (see SPEC-DEFECTS.md, §2.5/§1.3).
 */
export function compareJsonToBytes(record: DisclosurePackage["record"], bytes: LeafFromBytes): void {
  const mismatch = (field: string, json: string, borsh: string): never => {
    throw new PackageFailure("JsonBorshMismatch", `${field}: JSON says ${json}, the preimage says ${borsh}`);
  };
  const seq = intField(record.seq, "record.seq");
  if (seq !== bytes.seq) mismatch("seq", `${seq}`, `${bytes.seq}`);

  const payloadDigest = hexField(record.payload_digest, "record.payload_digest", 32);
  if (!bytesEqual(payloadDigest, bytes.payloadDigest)) {
    mismatch("payload_digest", toHex(payloadDigest), toHex(bytes.payloadDigest));
  }
  const assessmentDigest = hexField(record.assessment_digest, "record.assessment_digest", 32);
  if (!bytesEqual(assessmentDigest, bytes.assessmentDigest)) {
    mismatch("assessment_digest", toHex(assessmentDigest), toHex(bytes.assessmentDigest));
  }
  const qpKey = hexField(record.qp_key, "record.qp_key", 32);
  if (!bytesEqual(qpKey, bytes.qpKey)) mismatch("qp_key", toHex(qpKey), toHex(bytes.qpKey));

  const category = smallInt(record.category, "record.category", 255);
  if (category !== bytes.category) mismatch("category", `${category}`, `${bytes.category}`);

  const effectiveAt = intField(record.effective_at, "record.effective_at");
  if (effectiveAt !== bytes.effectiveAt) mismatch("effective_at", `${effectiveAt}`, `${bytes.effectiveAt}`);

  const changeIdentifiedAt = intField(record.change_identified_at, "record.change_identified_at");
  if (changeIdentifiedAt !== bytes.changeIdentifiedAt) {
    mismatch("change_identified_at", `${changeIdentifiedAt}`, `${bytes.changeIdentifiedAt}`);
  }
}

function parseProof(inclusion: DisclosurePackage["inclusion"]): InclusionProof {
  const epoch = intField(must(inclusion.epoch, "inclusion.epoch"), "inclusion.epoch");
  const height = smallInt(must(inclusion.height, "inclusion.height"), "inclusion.height", 255);
  const slotIndex = smallInt(must(inclusion.slot_index, "inclusion.slot_index"), "inclusion.slot_index", 0xffff);
  const rawSiblings = must(inclusion.siblings, "inclusion.siblings");
  if (!Array.isArray(rawSiblings)) throw new PackageFailure("MalformedPackage", "inclusion.siblings is not an array");
  const siblings = rawSiblings.map((s, i) => hexField(s, `inclusion.siblings[${i}]`, 32));
  return { height, siblings, slotIndex, epoch };
}

/**
 * The offline path: a record, a proof and a root, and nothing else. Pure — no network, no clock,
 * no storage — which is what INV-IFACE-01 requires of a counterparty's verification.
 */
export function verifyDisclosurePackage(pkg: DisclosurePackage, options: VerifyOptions): DisclosureReport {
  const checks: DisclosureReport["checks"] = [];
  const notes: string[] = [];
  let leaf: Digest | undefined;
  let fields: LeafFromBytes | undefined;
  let flags: FlagReport | undefined;

  let chainPosition: ChainPosition = { established: false, detail: "verification did not reach the chain segment" };
  const record = (name: string, status: "pass" | "skipped" | "unestablished", detail?: string): void => {
    checks.push(detail === undefined ? { name, status } : { name, status, detail });
  };

  try {
    // 0 — is this a §2.5 package at all?
    if (pkg === null || typeof pkg !== "object") throw new PackageFailure("MalformedPackage", "not an object");
    if (pkg.schema !== DISCLOSURE_SCHEMA) {
      throw new PackageFailure("MalformedPackage", `schema is ${JSON.stringify(pkg.schema)}, not ${DISCLOSURE_SCHEMA}`);
    }
    // Only the fields §2.5 lists, at every level (INV-DISC-01, V-Z-05). Refused before anything
    // else is read, because an epoch key in a corner is a leak whatever the rest of the package says.
    checkOnlyListedFields(pkg, PACKAGE_SHAPE, "");
    const rec = must(pkg.record, "record");
    const chain = must(pkg.chain, "chain");
    const inclusion = must(pkg.inclusion, "inclusion");
    record("package carries only the fields §2.5 lists", "pass");

    // 1 — the bytes. Everything downstream is derived from these, never from the display copy.
    let preimage: Uint8Array;
    try {
      preimage = base64Decode(must(pkg.preimage_borsh, "preimage_borsh"));
    } catch (e) {
      if (isFailure(e)) throw e;
      throw new PackageFailure("MalformedPackage", `preimage_borsh: ${(e as Error).message}`);
    }
    fields = readLeafPreimage(preimage);
    record("preimage_borsh decodes as a §1.3 leaf preimage", "pass");

    // 2 — the display copy against the bytes, before any other work (INV-DISC-02, INV-ENC-03).
    compareJsonToBytes(rec, fields);
    record("JSON record agrees with the Borsh preimage", "pass", "flags excluded per INV-DISC-03");

    // 3 — the leaf.
    leaf = keccak256(preimage);
    record("leaf recomputed from preimage_borsh", "pass", toHex(leaf));

    // 4 — the QP signature, over those bytes and not over any other encoding (INV-ENC-03).
    const signatureField = pkg.qp_signature;
    if (signatureField === undefined || signatureField === null) {
      throw new RegistryFailure("AttestationMissing", "the package carries no qp_signature");
    }
    const signature = hexField(signatureField, "qp_signature", 64);
    if (!ed25519Verify(fields.qpKey, preimage, signature)) {
      throw new RegistryFailure("AttestationInvalid", "qp_signature does not verify over preimage_borsh");
    }
    record("QP signature verifies over the 161 preimage bytes", "pass");

    // 5 — the chain segment, checked in the order §1.3 constructs it.
    const prevHead = hexField(must(chain.prev_head, "chain.prev_head"), "chain.prev_head", 32);
    const head = hexField(must(chain.head, "chain.head"), "chain.head", 32);
    const genesis = hexField(must(chain.genesis, "chain.genesis"), "chain.genesis", 32);

    // h₀ = Keccak256(TAG_HEAD ‖ c ‖ schema_version). `c` is inside the bytes the QP signed, so the
    // genesis head of this asset's chain is recomputable for every package, not only at seq 1.
    // Without this the three chain fields can be replaced together — genesis, prev_head and head —
    // leaving the preimage, the signature, the proof and the root untouched and every remaining
    // relation holding for a chain that is not this asset's.
    const expectedGenesis = keccak256(genesisHeadPreimage(fields.assetCommitment, SCHEMA_VERSION));
    if (!bytesEqual(genesis, expectedGenesis)) {
      throw new RegistryFailure(
        "HeadMismatch",
        `chain.genesis is not Keccak256(TAG_HEAD ‖ c ‖ ${SCHEMA_VERSION}) for the c this preimage carries`,
      );
    }
    record("chain.genesis is this asset's genesis head under schema 1", "pass", toHex(expectedGenesis));

    // Is `prev_head` the chain's head at seq − 1? Nothing in the package signs it or anchors it, so
    // there are exactly two ways to know (see ChainPosition), and otherwise the answer is that this
    // package does not establish it.
    const expectedPrevHead = options.chainContext?.expectedPrevHead;
    if (expectedPrevHead !== undefined && !bytesEqual(prevHead, expectedPrevHead)) {
      throw new RegistryFailure("HeadMismatch", "prev_head is not the head the caller expects this record to commit against");
    }
    if (fields.seq === 1n) {
      if (!bytesEqual(prevHead, genesis)) {
        throw new RegistryFailure("HeadMismatch", "the record is at seq 1 and prev_head is not the genesis head");
      }
      chainPosition = {
        established: true,
        detail: "the record is at seq 1 and prev_head is the genesis head, which follows from the signed c",
      };
      record("prev_head is the chain's head at seq − 1", "pass", "at seq 1 that head is h₀, and h₀ follows from c");
    } else if (expectedPrevHead !== undefined) {
      chainPosition = {
        established: true,
        detail: "prev_head is the head the caller supplied, so the position holds relative to that input",
      };
      record("prev_head is the chain's head at seq − 1", "pass", "against the head the caller supplied");
    } else {
      chainPosition = {
        established: false,
        detail:
          `the record is at seq ${fields.seq} and nothing here pins prev_head: §1.3's leaf preimage does not ` +
          "cover it, so no signature binds it; the proof binds only the leaf; and INV-STATE-02 needs the leaves " +
          "between h₀ and it, which one package does not carry",
      };
      record("prev_head is the chain's head at seq − 1", "unestablished", chainPosition.detail);
      notes.push(
        `chain position not established: this package places the record at seq ${fields.seq} on its own word. ` +
          "Supply the expected prev_head, or the chain, to close it.",
      );
    }

    // hₙ₊₁ = Keccak256(TAG_HEAD ‖ hₙ ‖ leafₙ₊₁). Both values come from the package, so this is
    // internal consistency, which INV-DISC-02 still requires; it is not evidence about the chain.
    if (!bytesEqual(advanceHead(prevHead, leaf), head)) {
      throw new RegistryFailure("HeadMismatch", "chain.head is not Keccak256(TAG_HEAD ‖ prev_head ‖ leaf)");
    }
    record(
      "chain.head is consistent with prev_head and the leaf",
      "pass",
      "an internal relation between two values the package supplies",
    );

    // 6 — inclusion, against a root the caller obtained independently.
    const proof = parseProof(inclusion);
    if (proof.epoch !== options.root.epoch) {
      throw new PackageFailure("RootEpochMismatch", `the proof is for epoch ${proof.epoch} and the root for ${options.root.epoch}`);
    }
    if (options.configuredHeight === undefined) {
      verifyInclusion(leaf, proof, options.root.root);
      record("inclusion proof reaches the root", "pass", "no configured height supplied, so §2.3's plain verify ran");
    } else {
      verifyInclusionForHeight(leaf, proof, options.root.root, options.configuredHeight);
      record("inclusion proof reaches the root at the log's configured height", "pass", `H = ${options.configuredHeight}`);
    }

    // 7 — flags. Advisory, excluded from every digest, and never a reason to refuse (INV-DISC-03).
    const declared = smallInt(rec.flags, "record.flags", 0xffff);
    if (options.chainContext === undefined) {
      flags = {
        declared,
        recomputed: null,
        discrepancy: null,
        note: "not recomputable: bit 0 and bit 1 are properties of earlier records in the chain, which one package does not carry",
      };
      record("flags", "skipped", flags.note);
    } else {
      const state = {
        sawResource: options.chainContext.sawResource,
        previousCategory: options.chainContext.previousCategory,
      } as ChainState;
      const recomputed = computeFlags(state, fields.category);
      const discrepancy = recomputed !== declared;
      flags = {
        declared,
        recomputed,
        discrepancy,
        note: discrepancy ? "declared flags differ from the flags this chain state produces" : "declared flags match",
      };
      record("flags recomputed from the chain", "pass", flags.note);
      if (discrepancy) notes.push(`flag discrepancy: package declares ${declared}, the chain gives ${recomputed}`);
    }

    return { ok: true, leaf, fields, flags, chainPosition, checks, notes };
  } catch (e) {
    if (!isFailure(e)) throw e; // a bug here must not be mistaken for a refusal
    const failure: Failure = e;
    checks.push({ name: "verification", status: "fail", detail: describeFailure(failure) });
    return {
      ok: false,
      failure:
        failure instanceof RegistryFailure
          ? { kind: "registry", code: failure.code, codeName: failure.codeName, message: failure.message }
          : { kind: "package", failure: failure.failure, message: failure.message },
      leaf,
      fields,
      flags,
      chainPosition,
      checks,
      notes,
    };
  }
}

/**
 * A package arrives as JSON text. This parses it and verifies it, which is the path that guarantees
 * the object the field walk inspects is the object the readers use: `JSON.parse` yields plain
 * objects with no accessors and no prototype of its own. `verifyDisclosurePackage` accepts an
 * already-parsed package for callers who have one, and expects it to be JSON-derived for the same
 * reason.
 */
export function verifyDisclosureJson(text: string, options: VerifyOptions): DisclosureReport {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    return {
      ok: false,
      failure: { kind: "package", failure: "MalformedPackage", message: `MalformedPackage: ${(e as Error).message}` },
      chainPosition: { established: false, detail: "the package did not parse" },
      checks: [{ name: "package parses as JSON", status: "fail" }],
      notes: [],
    };
  }
  return verifyDisclosurePackage(parsed as DisclosurePackage, options);
}

/**
 * INV-DISC-01's own check, for a holder who wants it: `c` may appear inside `preimage_borsh` and
 * nowhere else in the package. Returns the fields where it was found in clear.
 */
export function findAssetCommitmentOutsidePreimage(pkg: DisclosurePackage, assetCommitment: Digest): string[] {
  const needle = toHex(assetCommitment).slice(2).toLowerCase();
  const found: string[] = [];
  const walk = (value: unknown, path: string): void => {
    if (typeof value === "string") {
      if (value.toLowerCase().includes(needle)) found.push(path);
    } else if (Array.isArray(value)) {
      value.forEach((v, i) => walk(v, `${path}[${i}]`));
    } else if (value !== null && typeof value === "object") {
      for (const [k, v] of Object.entries(value)) {
        if (path === "" && k === "preimage_borsh") continue; // where INV-DISC-01 places it
        walk(v, path === "" ? k : `${path}.${k}`);
      }
    }
  };
  walk(pkg, "");
  return found;
}
