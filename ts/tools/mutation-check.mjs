/**
 * Breaks one thing at a time and checks that the test naming it goes red.
 *
 * A test that passes whatever the code does is not evidence. Each mutation below names the test
 * it must break; the script applies it, runs the suite, restores the file, and reports. A mutation
 * that leaves the suite green is a hole in the tests and is printed as a failure of this script.
 *
 * Usage: node tools/mutation-check.mjs
 */
import { readFileSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import path from "node:path";

const ROOT = path.join(import.meta.dirname, "..");
const SUITE = ["--test", "test/kat.test.ts", "test/vectors.test.ts", "test/disclosure.test.ts", "test/units.test.ts"];

/** Each: [file, find, replace, "the test this must break"] */
const MUTATIONS = [
  ["src/hash.ts", "return keccak_256(data);", "return nobleSha256(data);", "KAT-01: the hash family"],
  ["src/hash.ts", "return ed25519.verify(signature, message, publicKey, { zip215: false });", "return true;", "KAT-02 and every signature check"],
  ["src/preimage.ts", "fixed(\"payload digest\", f.payloadDigest, 32),\n    fixed(\"assessment digest\", f.assessmentDigest, 32),", "fixed(\"assessment digest\", f.assessmentDigest, 32),\n    fixed(\"payload digest\", f.payloadDigest, 32),", "KAT-03: leaf field order"],
  ["src/preimage.ts", "return build(TAG_ASSET, [j, r, u16le(tenure.length), tenure]);", "return build(TAG_ASSET, [j, r, Uint8Array.of(tenure.length >> 8, tenure.length & 0xff), tenure]);", "KAT-03 and V-P-01: the u16 length prefix is little-endian"],
  ["src/preimage.ts", "  if (!bytesEqual(preimage.subarray(0, TAG_LEN), expectedTag)) {", "  if (false) {", "V-N-09: the domain tag check"],
  ["src/chain.ts", "  if (!bytesEqual(r.prevHead, state.head)) {", "  if (r.category <= 4 && !bytesEqual(r.prevHead, state.head) && isWellFormedPayloadUri(r.payloadUri)) {", "V-N-23: (a) decides before (f)"],
  ["src/chain.ts", "  if (r.extCommitment !== null) {", "  if (r.extCommitment !== null && bytesEqual(r.prevHead, state.head)) {", "V-N-24: the schema gate precedes (a)"],
  ["src/chain.ts", "  if (state.seq >= U64_MAX) {", "  if (false) {", "V-N-20: the sequence counter is checked, never wrapped"],
  ["src/chain.ts", "  if (r.expectedQpKey !== null && !bytesEqual(r.expectedQpKey, r.qpKey)) {", "  if (false) {", "V-N-06: an expected key that disagrees is 0x08"],
  ["src/chain.ts", "  if (state.lastEffectiveAt !== null && r.effectiveAt < state.lastEffectiveAt) {", "  if (false) {", "V-N-08: effective dates are non-decreasing"],
  ["src/chain.ts", "  if (category >= FIRST_RESERVE_CATEGORY && !state.sawResource) {", "  if (category >= FIRST_RESERVE_CATEGORY && state.sawResource) {", "V-N-07 and V-P-11: flag bit 0"],
  ["src/chain.ts", "  if (state.previousCategory !== null && category < state.previousCategory) {", "  if (category < 99) {", "V-P-03: flag bit 1 is not set on every record"],
  ["src/tree.ts", "  return readU16le(seed, 0) & (capacityOf(height) - 1);", "  return (readU16le(seed, 0) >> (16 - height)) & (capacityOf(height) - 1);", "V-P-05: the slot is the low H bits of a little-endian read"],
  ["src/tree.ts", "const ordered = [...real].sort((a, b) => compareBytes(a.submissionId, b.submissionId));", "const ordered = [...real];", "V-P-06: assignment is in ascending identifier order, whatever order the caller supplies"],
  ["src/tree.ts", "    node = ((proof.slotIndex >> level) & 1) === 0 ? internalNode(node, sibling) : internalNode(sibling, node);", "    node = internalNode(node, sibling);", "V-P-05 and V-N-15: the path's left-right order"],
  ["src/tree.ts", "  if (proof.siblings.length !== proof.height) {", "  if (false) {", "V-N-16: a proof carrying H ± 1 siblings"],
  ["src/tree.ts", "  if (proof.height !== configuredHeight) {", "  if (false) {", "V-N-16b: the configured height"],
  ["src/tree.ts", "    throw new RegistryFailure(\"EpochCapacityExceeded\", `${real.length} real submissions into ${capacity} slots`);", "    real = real.slice(0, capacity);", "V-N-14: more than C real submissions"],
  ["src/promise.ts", "  const windowEnd = promise.promisedEpoch + BigInt(promise.maxMergeDelay);", "  const windowEnd = promise.promisedEpoch + BigInt(promise.maxMergeDelay) + 1n;", "V-P-10: a root published after the window"],
  ["src/promise.ts", "  if (promise.acceptedEpoch > observedEpoch || promise.acceptedEpoch + 1n < observedEpoch) {", "  if (false) {", "the promise policy: backdated acceptance"],
  ["src/disclosure.ts", "    compareJsonToBytes(rec, fields);", "    // moved below", "INV-DISC-02: the display copy is checked against the bytes"],
  ["src/disclosure.ts", "  const category = smallInt(record.category, \"record.category\", 255);", "  const category = bytes.category;", "INV-DISC-02: category, field by field"],
  ["src/disclosure.ts", "    if (!bytesEqual(advanceHead(prevHead, leaf), head)) {", "    if (false) {", "the chain segment"],
  ["src/disclosure.ts", "      verifyInclusionForHeight(leaf, proof, options.root.root, options.configuredHeight);", "      void proof;", "the inclusion check inside a package"],
  ["src/disclosure.ts", "    const declared = smallInt(rec.flags, \"record.flags\", 0xffff);", "    const declared = 0;", "INV-DISC-03: the declared flags are reported"],
  ["src/canonical.ts", "  const decomposed = s.normalize(\"NFKD\");", "  const decomposed = s;", "canonicalization: NFKD runs first"],
  ["src/canonical.ts", "  if (out.length > MAX_CANONICAL_TENURE_BYTES) {", "  if (false) {", "canonicalization: the 64-byte bound"],
  ["src/bytes.ts", "    if (v < 0) throw new TypeError(`base64: invalid character ${JSON.stringify(ch)}`);", "    if (v < 0) continue;", "base64 decoding is strict"],
  ["src/solana/pda.ts", "  for (let bump = 255; bump >= 0; bump--) {", "  for (let bump = 0; bump <= 255; bump++) {", "§2.4: the canonical bump"],
  ["src/solana/accounts.ts", "    root: data.slice(18, 50),", "    root: data.slice(17, 49),", "§2.4: the CheckpointAccount offsets"],
  ["src/solana/rpc.ts", "  if (checkpoint.epoch !== epoch) {", "  if (false) {", "fetching a root: the account answers for the epoch asked for"],
  ["src/solana/accounts.ts", "    startEpoch: readU64le(data, 52),", "    startEpoch: readU64le(data, 51),", "§2.4: start_epoch sits at offset 52"],
  ["src/solana/accounts.ts", "    reserved: data.slice(60, 68),", "    reserved: data.slice(52, 60),", "§2.4: the eight reserved bytes follow start_epoch"],
  ["src/solana/accounts.ts", "  if (epoch < config.startEpoch) return { kind: \"before-log-start\", startEpoch: config.startEpoch };", "  if (false) return { kind: \"before-log-start\", startEpoch: config.startEpoch };", "INV-ANCH-02: an epoch before the log existed is not a gap"],
  ["src/solana/accounts.ts", "  return unixSeconds < 0n && q * EPOCH_SECONDS !== unixSeconds ? q - 1n : q;", "  return q;", "§1.4: the epoch clock floors rather than truncating"],
  ["src/solana/rpc.ts", "        \"EpochBeforeLogStart\",", "        \"InconsistentChainView\",", "§1.4: the three reasons are not reported alike"],
  ["src/solana/accounts.ts", "  return currentDayIndex - config.lastEpoch;", "  return config.lastEpoch - currentDayIndex;", "§1.4: lag is the distance the sequence stands behind"],
  // The three findings an independent review raised.
  ["src/disclosure.ts", "    if (!bytesEqual(genesis, expectedGenesis)) {", "    if (false) {", "finding 1: a package cannot invent its genesis"],
  ["src/disclosure.ts", "    const expectedGenesis = keccak256(genesisHeadPreimage(fields.assetCommitment, SCHEMA_VERSION));", "    const expectedGenesis = keccak256(genesisHeadPreimage(fields.assetCommitment, 2));", "finding 1: the genesis is recomputed under schema 1"],
  ["src/disclosure.ts", "      if (!bytesEqual(prevHead, genesis)) {", "      if (false) {", "finding 1: condition (a) at n = 0"],
  ["src/disclosure.ts", "    checkOnlyListedFields(pkg, PACKAGE_SHAPE, \"\");", "    void PACKAGE_SHAPE;", "finding 2: a field §2.5 does not list refuses the package"],
  ["src/disclosure.ts", "    if (!Object.hasOwn(shape, field)) {", "    if (!Object.hasOwn(shape, field) && path === \"\") {", "finding 2: an unlisted field nested inside a listed one"],
  ["src/disclosure.ts", "    if (isContainer(value)) {\n      throw new PackageFailure(\"UnlistedField\", `${path} carries a structure where §2.5 shows a single value`);", "    if (false) {\n      throw new PackageFailure(\"UnlistedField\", `${path} carries a structure where §2.5 shows a single value`);", "finding 2: nothing hides inside a field §2.5 shows as a value"],
  ["src/solana/accounts.ts", "  if (schemaVersion !== SCHEMA_VERSION) {", "  if (false) {", "finding 3: an account under another schema version is refused"],
  // The third review round.
  ["src/disclosure.ts", "  if (seq === 0n) {", "  if (false) {", "round 3: a package at seq 0 is refused"],
  ["src/disclosure.ts", "  if (category < CATEGORY_MIN || category > CATEGORY_MAX) {", "  if (false) {", "round 3: a category outside 0..=4 is refused"],
  ["src/disclosure.ts", "    if (!isDataProperty(value as object, field)) {", "    if (false) {", "round 3: an accessor field is refused"],
  ["src/disclosure.ts", "  return d !== undefined && \"value\" in d;", "  return d !== undefined;", "round 3: isDataProperty rejects a getter, not merely a missing field"],

  // The second review round.
  ["src/disclosure.ts", "      record(\"prev_head is the chain's head at seq − 1\", \"unestablished\", chainPosition.detail);", "      record(\"prev_head is the chain's head at seq − 1\", \"pass\", chainPosition.detail);", "finding 1: an unestablished chain position is not reported as passing"],
  ["src/disclosure.ts", "      chainPosition = {\n        established: false,\n        detail:", "      chainPosition = {\n        established: true,\n        detail:", "finding 1: the report says the chain position was not established"],
  ["src/disclosure.ts", "    if (expectedPrevHead !== undefined && !bytesEqual(prevHead, expectedPrevHead)) {", "    if (false) {", "finding 1: a prev_head the caller did not expect is 0x03"],
  ["src/disclosure.ts", "    if (!Object.hasOwn(shape, field)) {", "    if (shape[field] === undefined) {", "finding 2: membership is tested with Object.hasOwn, not by indexing"],
  ["src/disclosure.ts", "  if (!isPlainObject(value)) {", "  if (!isContainer(value) || Array.isArray(value)) {", "finding 2: a container's fields must be its own"],
  ["src/solana/pda.ts", "  const address = sha256(concat([...seeds, programId, PDA_MARKER]));", "  const address = sha256(concat([...seeds, PDA_MARKER, programId]));", "§2.4: the program address hashes seeds, bump, program id, marker, in that order"],
  ["src/solana/pda.ts", "  for (let bump = 255; bump >= 0; bump--) {", "  for (let bump = 0; bump <= 255; bump++) {", "§2.4: the canonical bump is the largest off-curve one, searched downwards"],
  ["test/handlers.ts", "  \"V-N-25\": vN25,", "", "the suite fails when a vector has no handler"],
];

function run() {
  try {
    execFileSync(process.execPath, SUITE, { cwd: ROOT, stdio: "pipe" });
    return "green";
  } catch {
    return "red";
  }
}

const baseline = run();
if (baseline !== "green") {
  console.error("the suite is not green before mutating; fix that first");
  process.exit(1);
}
console.log("baseline: green\n");

let holes = 0;
for (const [file, find, replace, expectation] of MUTATIONS) {
  const full = path.join(ROOT, file);
  const original = readFileSync(full, "utf8");
  if (!original.includes(find)) {
    console.error(`SKIPPED  ${file}: the text to mutate is not there any more -> ${expectation}`);
    holes += 1;
    continue;
  }
  writeFileSync(full, original.replace(find, replace));
  let result;
  try {
    result = run();
  } finally {
    writeFileSync(full, original);
  }
  if (result === "red") {
    console.log(`caught   ${file.padEnd(24)} ${expectation}`);
  } else {
    console.error(`NOT CAUGHT ${file.padEnd(22)} ${expectation}`);
    holes += 1;
  }
}

console.log(`\n${MUTATIONS.length} mutations, ${MUTATIONS.length - holes} caught, ${holes} not caught`);
if (run() !== "green") {
  console.error("the suite is not green after restoring; something was left mutated");
  process.exit(1);
}
process.exit(holes === 0 ? 0 : 1);
