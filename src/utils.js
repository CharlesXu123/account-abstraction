const { randomBytes, hexlify, hexZeroPad } = require("ethers/lib/utils");
const { BigNumber } = require("ethers");
const { assert } = require("chai");

const FIELD_ORDER = BigNumber.from(
  "0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47"
);

const ZERO = BigNumber.from("0");
const ONE = BigNumber.from("1");
const TWO = BigNumber.from("2");

function toBig(n) {
  return BigNumber.from(n);
}

function randHex(n) {
  return hexlify(randomBytes(n));
}

function randBig(n) {
  return toBig(randomBytes(n));
}

function bigToHex(n) {
  return hexZeroPad(n.toHexString(), 32);
}

function randFs() {
  const r = randBig(32);
  return r.mod(FIELD_ORDER);
}

function randFsHex() {
  const r = randBig(32);
  return bigToHex(r.mod(FIELD_ORDER));
}

const P_PLUS1_OVER4 = BigNumber.from(
  "0xc19139cb84c680a6e14116da060561765e05aa45a1c72a34f082305b61f3f52"
);
//  const P_MINUS3_OVER4 = BigNumber.from('0xc19139cb84c680a6e14116da060561765e05aa45a1c72a34f082305b61f3f51');
//  const P_MINUS1_OVER2 = BigNumber.from('0x183227397098d014dc2822db40c0ac2ecbc0b548b438e5469e10460b6c3e7ea3');
function exp(a, e) {
  let z = BigNumber.from(1);
  let path = BigNumber.from(
    "0x8000000000000000000000000000000000000000000000000000000000000000"
  );
  for (let i = 0; i < 256; i++) {
    z = z.mul(z).mod(FIELD_ORDER);
    if (!e.and(path).isZero()) {
      z = z.mul(a).mod(FIELD_ORDER);
    }
    path = path.shr(1);
  }
  return z;
}

function sqrt(nn) {
  const n = exp(nn, P_PLUS1_OVER4);
  const found = n.mul(n).mod(FIELD_ORDER).eq(nn);
  return { n, found };
}

function inverse(a) {
  const z = FIELD_ORDER.sub(TWO);
  return exp(a, z);
}

function mulmod(a, b) {
  return a.mul(b).mod(FIELD_ORDER);
}

function test_sqrt() {
  for (let i = 0; i < 100; i++) {
    const a = randFs();
    const aa = mulmod(a, a);
    const res = sqrt(aa);
    assert.isTrue(res.found);
    assert.isTrue(mulmod(res.n, res.n).eq(aa));
  }
  const nonResidues = [
    toBig("0x23d9bb51d142f4a4b8a533721a30648b5ff7f9387b43d4fc8232db20377611bc"),
    toBig("0x107662a378d9198183bd183db9f6e5ba271fbf2ec6b8b077dfc0a40119f104cb"),
    toBig("0x0df617c7a009e07c841d683108b8747a842ce0e76f03f0ce9939473d569ea4ba"),
    toBig("0x276496bfeb07b8ccfc041a1706fbe3d96f4d42ffb707edc5e31cae16690fddc7"),
    toBig("0x20fcdf224c9982c72a3e659884fdad7cb59b736d6d57d54799c57434b7869bb3"),
  ];
  for (let i = 0; i < nonResidues.length; i++) {
    const res = sqrt(nonResidues[i]);
    assert.isFalse(res.found);
  }
}

function test_inv() {
  for (let i = 0; i < 100; i++) {
    const a = randFs();
    const ia = inverse(a);
    assert.isTrue(mulmod(a, ia).eq(ONE));
  }
}

async function test() {
  test_sqrt();
  test_inv();
}

module.exports = {
  FIELD_ORDER,
  ONE,
  TWO,
  ZERO,
  toBig,
  randHex,
  randBig,
  bigToHex,
  randFs,
  randFsHex,
};
