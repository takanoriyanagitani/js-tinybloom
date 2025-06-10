import { bind, lift } from "./io.mjs";

/** @import { IO } from "./io.mjs" */

/**
 * @readonly
 * @enum {number}
 */
export const FilterResult = Object.freeze({
  UNKNOWN: 0,
  NOT_FOUND: 1,
  MAY_EXIST: 2,
  EXIT: 3,
});

/** @type function(FilterResult): string */
export function result2string(frslt) {
  switch (frslt) {
    case FilterResult.NOT_FOUND:
      return "not found";
    case FilterResult.MAY_EXIST:
      return "may exist";
    case FilterResult.EXIT:
      return "found";
    default:
      return "unknown";
  }
}

/**
 * @typedef {Uint8Array} BloomDataSmall32B
 */

/** @typedef {number} BloomDataTiny16bits */

/** @typedef {number} HashTiny4x4bits */

/** @typedef {number} HashSmall4x8bits */

/**
 * @param {BloomDataTiny16bits} bloom16bits The original bloom data.
 * @param {HashTiny4x4bits} hash4x4bits
 * @returns {BloomDataTiny16bits} The updated bloom data.
 */
export function bloomUpdateTiny(bloom16bits, hash4x4bits) {
  const h0 = hash4x4bits;
  const h1 = hash4x4bits >> 4;
  const h2 = hash4x4bits >> 8;
  const h3 = hash4x4bits >> 12;

  const p0 = 1 << (h0 & 0x0f);
  const p1 = 1 << (h1 & 0x0f);
  const p2 = 1 << (h2 & 0x0f);
  const p3 = 1 << (h3 & 0x0f);

  return bloom16bits | p0 | p1 | p2 | p3;
}

/**
 * @param {Uint8Array} random The uuid to create the hash values.
 * @returns {HashTiny4x4bits} The hash value (16-bits) created using the uuid.
 */
export function uuid2hashTiny(random) {
  // assuming the length of the uuid is 16

  const u0 = random[0];
  const u1 = random[1];

  /** @type number */
  const u16 = (u0 << 8) | u1;

  return u16;
}

/**
 * @param {Uint8Array} random The uuid to create the hash values.
 * @returns {HashSmall4x8bits} The hash value (32-bits) created using the uuid.
 */
export function uuid2hashSmall(random) {
  // assuming the length of the uuid is 16

  const u0 = random[0];
  const u1 = random[1];
  const u2 = random[2];
  const u3 = random[3];

  const p0 = u0;
  const p1 = u1 << 8;
  const p2 = u2 << 16;
  const p3 = u3 << 24;

  return p0 | p1 | p2 | p3;
}

/**
 * @param {ArrayBuffer} u The uuid to be converted.
 * @returns {IO<ArrayBuffer>} The hash(sha256) of the uuid.
 */
export function uuid2sha256(u) {
  return () => crypto.subtle.digest("SHA-256", u);
}

/**
 * @param {ArrayBuffer} u The uuid to create the hash values.
 * @returns {IO<HashSmall4x8bits>} The hash(4x 8-bits) created using the uuid.
 */
export function uuid2sha256hash(u) {
  /** @type IO<ArrayBuffer> */
  const isha256 = uuid2sha256(u);

  /** @type IO<Uint8Array> */
  const iuarray = bind(
    isha256,
    lift((s256) => Promise.resolve(new Uint8Array(s256))),
  );

  return bind(
    iuarray,
    lift((uarr) => {
      const u0 = uarr[0];
      const u1 = uarr[1];
      const u2 = uarr[2];
      const u3 = uarr[3];

      const h0 = u0;
      const h1 = u1 << 8;
      const h2 = u2 << 16;
      const h3 = u3 << 24;

      const h = h0 | h1 | h2 | h3;

      return Promise.resolve(h);
    }),
  );
}

/** @type function(BloomDataTiny16bits, HashTiny4x4bits): FilterResult */
export function bloom2resultTiny(bloom16bits, hash4x4bits) {
  const h0 = hash4x4bits;
  const h1 = hash4x4bits >> 4;
  const h2 = hash4x4bits >> 8;
  const h3 = hash4x4bits >> 12;

  const p0 = 1 << (h0 & 0x0f);
  const p1 = 1 << (h1 & 0x0f);
  const p2 = 1 << (h2 & 0x0f);
  const p3 = 1 << (h3 & 0x0f);

  const a0 = bloom16bits & p0;
  const a1 = bloom16bits & p1;
  const a2 = bloom16bits & p2;
  const a3 = bloom16bits & p3;

  /** @type boolean */
  const notFound = [
    a0,
    a1,
    a2,
    a3,
  ].some((a) => 0 === a);

  /** @type boolean */
  const mayExist = !notFound;

  return mayExist ? FilterResult.MAY_EXIST : FilterResult.NOT_FOUND;
}

/** @type function(BloomDataSmall32B, HashSmall4x8bits): FilterResult */
export function bloom2resultSmall(bloom32B, hash4x8bits) {
  const h0 = hash4x8bits;
  const h1 = hash4x8bits >> 8;
  const h2 = hash4x8bits >> 16;
  const h3 = hash4x8bits >> 24;

  const a0 = h0 & 0xff;
  const a1 = h1 & 0xff;
  const a2 = h2 & 0xff;
  const a3 = h3 & 0xff;

  const yo0 = a0 >> 3;
  const yo1 = a1 >> 3;
  const yo2 = a2 >> 3;
  const yo3 = a3 >> 3;

  const p0 = 1 << (a0 & 0x07);
  const p1 = 1 << (a1 & 0x07);
  const p2 = 1 << (a2 & 0x07);
  const p3 = 1 << (a3 & 0x07);

  const b0 = bloom32B[yo0 & 0x1f];
  const b1 = bloom32B[yo1 & 0x1f];
  const b2 = bloom32B[yo2 & 0x1f];
  const b3 = bloom32B[yo3 & 0x1f];

  const c0 = b0 & p0;
  const c1 = b1 & p1;
  const c2 = b2 & p2;
  const c3 = b3 & p3;

  /** @type boolean */
  const notFound = [
    c0,
    c1,
    c2,
    c3,
  ].some((c) => 0 === c);

  /** @type boolean */
  const mayExist = !notFound;

  return mayExist ? FilterResult.MAY_EXIST : FilterResult.NOT_FOUND;
}

/**
 * @param {ArrayBuffer} s256 The hash(sha-256) value to be converted.
 * @returns {HashTiny4x4bits} The converted hash value(16-bits).
 */
export function sha256hashTiny(s256) {
  const words = new Uint16Array(s256);
  return words.reduce((state, next) => state ^ next);
}

/**
 * @param {ArrayBuffer} s256 The hash(sha-256) value to be converted.
 * @returns {HashSmall4x8bits} The converted hash value(32-bits).
 */
export function sha256hashSmall(s256) {
  /** @type BigUint64Array */
  const v = new BigUint64Array(s256);

  const b0 = v[0];
  const b1 = v[1];
  const b2 = v[2];
  const b3 = v[3];

  const xe = b0 ^ b2;
  const xo = b1 ^ b3;

  /** @type BigInt */
  const x = xe ^ xo;

  const hi = x >> 32n;
  const lo = x & 0xffff_ffffn;

  /** @type BigInt */
  const hl32 = hi ^ lo;

  return Number(hl32);
}

/**
 * @param {BigInt} b The intger to be converted.
 * @param {DataView} view The buffer to compute the hash of the integer.
 * @returns {IO<HashTiny4x4bits>} The hash values for the integer.
 */
export function bigint2hashTiny(b, view) {
  return () => {
    view.setBigInt64(0, b, false);

    /** @type Promise<ArrayBuffer> */
    const psha256 = crypto.subtle.digest("SHA-256", view);

    return psha256.then(sha256hashTiny);
  };
}

/**
 * @param {BigInt} b The intger to be converted.
 * @param {DataView} view The buffer to compute the hash of the integer.
 * @returns {IO<HashSmall4x8bits>} The hash values for the integer.
 */
export function bigint2hashSmall(b, view) {
  return () => {
    view.setBigInt64(0, b, false);

    /** @type Promise<ArrayBuffer> */
    const psha256 = crypto.subtle.digest("SHA-256", view);

    return psha256.then(sha256hashSmall);
  };
}

/**
 * @param {boolean} b The bool value to be converted.
 * @returns {IO<HashTiny4x4bits>} The hash values(16-bits) for the boolean.
 */
export function bool2hashTiny(b) {
  const allT = new Uint8Array(32);
  const allF = new Uint8Array(32);

  allT.fill(0xff);
  allF.fill(0);

  return () => {
    /** @type Promise<ArrayBuffer> */
    const psha256 = crypto.subtle.digest(
      "SHA-256",
      b ? allT : allF,
    );

    return psha256.then(sha256hashTiny);
  };
}

/**
 * @param {boolean} b The bool value to be converted.
 * @returns {IO<HashSmall4x8bits>} The hash values(32-bits) for the boolean.
 */
export function bool2hashSmall(b) {
  const allT = new Uint8Array(32);
  const allF = new Uint8Array(32);

  allT.fill(0xff);
  allF.fill(0);

  return () => {
    /** @type Promise<ArrayBuffer> */
    const psha256 = crypto.subtle.digest(
      "SHA-256",
      b ? allT : allF,
    );

    return psha256.then(sha256hashSmall);
  };
}

/**
 * @returns {IO<HashSmall4x8bits>} The hash values(32-bits) for null.
 */
export function null2hashSmall() {
  const empty = new Uint8Array(32);

  return () => {
    /** @type Promise<ArrayBuffer> */
    const psha256 = crypto.subtle.digest(
      "SHA-256",
      empty,
    );

    return psha256.then(sha256hashSmall);
  };
}

/**
 * @returns {IO<HashTiny4x4bits>} The hash values(16-bits) for null.
 */
export function null2hashTiny() {
  const empty = new Uint8Array(32);

  return () => {
    /** @type Promise<ArrayBuffer> */
    const psha256 = crypto.subtle.digest(
      "SHA-256",
      empty,
    );

    return psha256.then(sha256hashTiny);
  };
}

/** @typedef {string} AsciiShortString256 */

/**
 * @param {AsciiShortString256} ascii256 The short string to be converted.
 * @param {TextEncoder} enc The encoder to convert the short string.
 * @param {Uint8Array} buf The buffer used to encode the short string.
 * @returns {IO<ArrayBuffer>} The hash value(sha-256).
 */
export function ascii2sha256(ascii256, enc, buf) {
  return () => {
    /** @type number */
    const written = enc.encodeInto(ascii256, buf).written;

    /** @type Uint8Array */
    const sub = buf.subarray(0, written);

    /** @type Promise<ArrayBuffer> */
    const psha256 = crypto.subtle.digest(
      "SHA-256",
      sub,
    );

    return psha256;
  };
}

/**
 * @param {AsciiShortString256} ascii256 The short string to be converted.
 * @param {TextEncoder} enc The encoder to convert the short string.
 * @param {Uint8Array} buf The buffer used to encode the short string.
 * @returns {IO<HashSmall4x8bits>} The hash values(32-bits) for the string.
 */
export function ascii2hashSmall(ascii256, enc, buf) {
  /** @type IO<ArrayBuffer> */
  const isha256 = ascii2sha256(ascii256, enc, buf);

  return bind(isha256, lift((s256) => Promise.resolve(sha256hashSmall(s256))));
}

/**
 * @param {AsciiShortString256} ascii256 The short string to be converted.
 * @param {TextEncoder} enc The encoder to convert the short string.
 * @param {Uint8Array} buf The buffer used to encode the short string.
 * @returns {IO<HashTiny4x4bits>} The hash values(16-bits) for the string.
 */
export function ascii2hashTiny(ascii256, enc, buf) {
  /** @type IO<ArrayBuffer> */
  const isha256 = ascii2sha256(ascii256, enc, buf);

  return bind(isha256, lift((s256) => Promise.resolve(sha256hashTiny(s256))));
}
