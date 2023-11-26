// const bls = require("@noble/curves/bls12-381").bls12_381;
const bls = require("@noble/curves/bn254").bn254;

const privateKey =
  "67d53f170b908cabb9eb326c3c337762d59289a8fec79f7bc9254b584b73265c";
const message = "64726e3da8";
const publicKey = bls.getPublicKey(privateKey);
const signature = bls.sign(message, privateKey);
const isValid = bls.verify(signature, message, publicKey);
console.log({ publicKey, signature, isValid });

// Sign 1 msg with 3 keys
const privateKeys = [
  "18f020b98eb798752a50ed0563b079c125b0db5dd0b1060d1c1b47d4a193e1e4",
  "ed69a8c50cf8c9836be3b67c7eeff416612d45ba39a5c099d48fa668bf558c9c",
  "16ae669f3be7a2121e17d0c68c05a8f3d6bef21ec0f2315f1d7aec12484e4cf5",
];
const messages = ["d2", "0d98", "05caf3"];
const publicKeys = privateKeys.map(bls.getPublicKey);
const signatures2 = privateKeys.map((p) => bls.sign(message, p));
const aggPubKey2 = bls.aggregatePublicKeys(publicKeys);
const aggSignature2 = bls.aggregateSignatures(signatures2);
const isValid2 = bls.verify(aggSignature2, message, aggPubKey2);
console.log({ signatures2, aggSignature2, isValid2 });

// Sign 3 msgs with 3 keys
const signatures3 = privateKeys.map((p, i) => bls.sign(messages[i], p));
const aggSignature3 = bls.aggregateSignatures(signatures3);
const isValid3 = bls.verifyBatch(aggSignature3, messages, publicKeys);
console.log({ publicKeys, signatures3, aggSignature3, isValid3 });

// Pairings, with and without final exponentiation
bls.pairing(PointG1, PointG2);
bls.pairing(PointG1, PointG2, false);
bls.fields.Fp12.finalExponentiate(bls.fields.Fp12.mul(PointG1, PointG2));

// Others
bls.G1.ProjectivePoint.BASE, bls.G2.ProjectivePoint.BASE;
bls.fields.Fp, bls.fields.Fp2, bls.fields.Fp12, bls.fields.Fr;
bls.params.x, bls.params.r, bls.params.G1b, bls.params.G2b;

// hash-to-curve examples can be seen below
