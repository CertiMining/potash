/**
 * §2.4's two account layouts, and the Anchor discriminator each opens with.
 *
 * The discriminator is the first eight bytes of `SHA-256("account:" ‖ N)` for the struct name `N`.
 * §2.4 publishes both constants; this file computes them instead of copying them, which is the
 * point the section makes about not being required to trust the two values.
 */
import { type Digest, readI64le, readU16le, readU64le, toHex, utf8 } from "../bytes.ts";
import { PackageFailure, RegistryFailure } from "../errors.ts";
import { SCHEMA_VERSION } from "../chain.ts";
import { sha256 } from "../hash.ts";

export function accountDiscriminator(structName: string): Uint8Array {
  return sha256(utf8(`account:${structName}`)).slice(0, 8);
}

export const LOG_CONFIG_DISCRIMINATOR = accountDiscriminator("LogConfig");
export const CHECKPOINT_DISCRIMINATOR = accountDiscriminator("CheckpointAccount");

export const LOG_CONFIG_LEN = 68;
export const CHECKPOINT_LEN = 106;

/** §1.4: an epoch is a UTC day index, `floor(unix_seconds / 86400)`. */
export const EPOCH_SECONDS = 86400n;

export function utcDayIndex(unixSeconds: bigint): bigint {
  // Floor division, which for a negative timestamp is not truncation towards zero.
  const q = unixSeconds / EPOCH_SECONDS;
  return unixSeconds < 0n && q * EPOCH_SECONDS !== unixSeconds ? q - 1n : q;
}

export type LogConfig = {
  schemaVersion: number;
  authority: Uint8Array;
  lastEpoch: bigint;
  treeHeight: number;
  bump: number;
  /**
   * §1.4, D-109: the UTC day index the chain reported at `initialize`. A log begins here, and
   * `last_epoch` was written as `start_epoch - 1`, so the first publication is `start_epoch`
   * itself. It occupies eight of the sixteen bytes v0.1.16's table showed as reserved.
   */
  startEpoch: bigint;
  /** §2.6 reserves the remaining eight bytes and nothing in this TCU reads them. */
  reserved: Uint8Array;
};

export type CheckpointAccount = {
  schemaVersion: number;
  epoch: bigint;
  root: Digest;
  publishedSlot: bigint;
  publishedUnix: bigint;
  receiptDigest: Digest;
  anchorKind: number;
  bump: number;
};

/**
 * Length, then discriminator, then the schema gate, in §1.3's own order: a buffer is decoded before
 * it is judged, and a version this engine does not implement is refused with 0x0F before any field
 * is read as meaning anything. §1.3 refuses a record under another schema version that way, and an
 * account is not different in kind: schema 2 may put other values at these offsets, and reading
 * them as schema 1 is how a verifier ends up asserting something it cannot support.
 */
function checkAccount(data: Uint8Array, expectedLen: number, discriminator: Uint8Array, what: string): void {
  if (data.length !== expectedLen) {
    throw new PackageFailure("RootUnavailable", `${what} is ${data.length} bytes, and §2.4 fixes it at ${expectedLen}`);
  }
  for (let i = 0; i < 8; i++) {
    if (data[i] !== discriminator[i]) {
      throw new PackageFailure("RootUnavailable", `${what} carries ${toHex(data.subarray(0, 8))}, not ${toHex(discriminator)}`);
    }
  }
  const schemaVersion = readU16le(data, 8);
  if (schemaVersion !== SCHEMA_VERSION) {
    throw new RegistryFailure("UnsupportedSchemaVersion", `${what} carries schema_version ${schemaVersion}`);
  }
}

export function decodeLogConfig(data: Uint8Array): LogConfig {
  checkAccount(data, LOG_CONFIG_LEN, LOG_CONFIG_DISCRIMINATOR, "LogConfig");
  return {
    schemaVersion: readU16le(data, 8),
    authority: data.slice(10, 42),
    lastEpoch: readU64le(data, 42),
    treeHeight: data[50]!,
    bump: data[51]!,
    startEpoch: readU64le(data, 52),
    reserved: data.slice(60, 68),
  };
}

export function decodeCheckpointAccount(data: Uint8Array): CheckpointAccount {
  checkAccount(data, CHECKPOINT_LEN, CHECKPOINT_DISCRIMINATOR, "CheckpointAccount");
  return {
    schemaVersion: readU16le(data, 8),
    epoch: readU64le(data, 10),
    root: data.slice(18, 50),
    publishedSlot: readU64le(data, 50),
    publishedUnix: readI64le(data, 58),
    receiptDigest: data.slice(66, 98),
    anchorKind: data[98]!,
    bump: data[99]!,
  };
}

/**
 * Where an epoch falls against the log's own life (INV-ANCH-02, §1.4, D-109).
 *
 * `publish_checkpoint` accepts `last_epoch + 1` only, and the sequence begins at `start_epoch`, so
 * an epoch with no checkpoint account is one of three different things and a client that reported
 * them alike would accuse a batcher of failing to publish before it was deployed.
 */
export type EpochPlacement =
  | { kind: "before-log-start"; startEpoch: bigint }
  | { kind: "inside-published-range"; startEpoch: bigint; lastEpoch: bigint }
  | { kind: "not-yet-published"; lastEpoch: bigint };

/**
 * §1.4: "the client reports the distance and the ruling belongs to whoever holds the clock". The
 * day index is an argument because §2.3 and INV-IFACE-01 keep clocks out of verification; a
 * positive result is the number of days the sequence stands behind that day.
 */
export function lagAgainst(config: LogConfig, currentDayIndex: bigint): bigint {
  return currentDayIndex - config.lastEpoch;
}

export function placeEpoch(config: LogConfig, epoch: bigint): EpochPlacement {
  if (epoch < config.startEpoch) return { kind: "before-log-start", startEpoch: config.startEpoch };
  if (epoch <= config.lastEpoch) {
    return { kind: "inside-published-range", startEpoch: config.startEpoch, lastEpoch: config.lastEpoch };
  }
  return { kind: "not-yet-published", lastEpoch: config.lastEpoch };
}

/** INV-ANCH-05: until anchor B is attached the client reports "single"; after, "dual". */
export function anchorStatus(checkpoint: CheckpointAccount): "single" | "dual" {
  return checkpoint.receiptDigest.every((b) => b === 0) ? "single" : "dual";
}
