// §1.2 domain tags. Every preimage carries exactly one, first (INV-ENC-01).
import { utf8 } from "./bytes.ts";

export const TAG_ASSET = utf8("CMv1ASST");
export const TAG_LEAF = utf8("CMv1LEAF");
export const TAG_HEAD = utf8("CMv1HEAD");
export const TAG_MTL0 = utf8("CMv1MTL0");
export const TAG_MTN1 = utf8("CMv1MTN1");
export const TAG_PAD = utf8("CMv1PADD");
export const TAG_CKPT = utf8("CMv1CKPT");
export const TAG_PRF = utf8("CMv1PRF0");
export const TAG_SPI = utf8("CMv1SPI0");

export const TAGS_BY_NAME = {
  CMv1ASST: TAG_ASSET,
  CMv1LEAF: TAG_LEAF,
  CMv1HEAD: TAG_HEAD,
  CMv1MTL0: TAG_MTL0,
  CMv1MTN1: TAG_MTN1,
  CMv1PADD: TAG_PAD,
  CMv1CKPT: TAG_CKPT,
  CMv1PRF0: TAG_PRF,
  CMv1SPI0: TAG_SPI,
} as const;

/** The domain-separation prefix every schema-1 tag shares. */
export const TAG_LEN = 8;
