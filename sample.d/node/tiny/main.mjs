import {
  ascii2hashTiny,
  bigint2hashTiny,
  bloom2resultTiny,
  bloomUpdateTiny,
  bool2hashTiny,
  FilterResult,
  result2string,
  uuid2hashTiny,
} from "./index.mjs";

import { bind } from "./io.mjs";

/** @import { IO } from "./io.mjs" */

/** @import { HashTiny4x4bits, BloomDataTiny16bits } from "./index.mjs" */

const uint64pair = [
  0xcafe_f00d_dead_beafn,
  0xface_8642_9979_2458n,
];

const buf = new BigUint64Array(2);
const view = new DataView(buf.buffer);
view.setBigInt64(0, uint64pair[0], false);
view.setBigInt64(8, uint64pair[1], false);

const uuid4 = new Uint8Array(buf.buffer);
const huuid = uuid2hashTiny(uuid4);

console.info(`uuid2hash 0: ${huuid >> 12}`);
console.info(`uuid2hash 1: ${(huuid >> 8) & 0x0f}`);
console.info(`uuid2hash 2: ${(huuid >> 4) & 0x0f}`);
console.info(`uuid2hash 3: ${huuid & 0x0f}`);

/** @type IO<Void> */
const main = async () => {
  /** @type IO<HashTiny4x4bits> */
  const ihashtrue = bool2hashTiny(true);

  /** @type IO<HashTiny4x4bits> */
  const ihashfalse = bool2hashTiny(false);

  /** @type function(string): function(HashTiny4x4bits): IO<Void> */
  const printHash = (name) => (hash) => () => {
    const h0 = hash;
    const h1 = hash >> 4;
    const h2 = hash >> 8;
    const h3 = hash >> 12;

    console.info(`${name} hash 0: ${h0 & 0x0f}`);
    console.info(`${name} hash 1: ${h1 & 0x0f}`);
    console.info(`${name} hash 2: ${h2 & 0x0f}`);
    console.info(`${name} hash 3: ${h3 & 0x0f}`);

    return Promise.resolve();
  };

  /** @type IO<Void> */
  const iprintTrue = bind(ihashtrue, printHash("true"));

  /** @type IO<Void> */
  const iprintFalse = bind(ihashfalse, printHash("false"));

  /** @type IO<HashTiny4x4bits> */
  const ihash42 = bigint2hashTiny(
    42n,
    new DataView(new BigInt64Array(1).buffer),
  );

  /** @type IO<HashTiny4x4bits> */
  const ihash634 = bigint2hashTiny(
    634n,
    new DataView(new BigInt64Array(1).buffer),
  );

  /** @type IO<HashTiny4x4bits> */
  const ihashhelo = ascii2hashTiny(
    "helo",
    new TextEncoder(),
    new Uint8Array(256),
  );

  /** @type IO<HashTiny4x4bits> */
  const ihash3776 = bigint2hashTiny(
    3776n,
    new DataView(new BigInt64Array(1).buffer),
  );

  /** @type IO<HashTiny4x4bits> */
  const ihash599 = bigint2hashTiny(
    599n,
    new DataView(new BigInt64Array(1).buffer),
  );

  const h3776 = await ihash3776();
  const h599 = await ihash599();

  /** @type BloomDataTiny16bits */
  const bloomData = 0x0000;

  /** @type BloomDataTiny16bits */
  const updatedBloom = [h3776, h599].reduce(
    bloomUpdateTiny,
    bloomData,
  );

  /** @type FilterResult */
  const r3776 = bloom2resultTiny(updatedBloom, h3776);

  /** @type FilterResult */
  const r599 = bloom2resultTiny(updatedBloom, h599);

  /** @type function(string): function(FilterResult): IO<Void> */
  const printResult = (name) => (result) => () => {
    console.info(`${name}: ${result2string(result)}`);
    return Promise.resolve();
  };

  /** @type Array<IO<Void>> */
  const iprints = [
    iprintTrue,
    iprintFalse,
    bind(ihash42, printHash("42")),
    bind(ihash634, printHash("634")),
    bind(ihashhelo, printHash("helo")),
    () => Promise.resolve(console.info(`bloom data: ${updatedBloom}`)),
    printResult("3776")(r3776),
    printResult("599")(r599),
  ];

  return Promise.all(iprints.map((i) => i())).then((_) => undefined);
};

main().catch(console.error);
