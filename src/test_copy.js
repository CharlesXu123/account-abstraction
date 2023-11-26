const bls = require("bls-wasm");

function share() {
  let k = 3;
  let n = 5;
  let msg = "abc";
  let msk = [];
  let mpk = [];
  let idVec = [];
  let secVec = [];
  let sigVec = [];

  /*
          setup master secret key
      */
  for (let i = 0; i < k; i++) {
    let sk = new bls.SecretKey();
    sk.setByCSPRNG();
    msk.push(sk);

    let pk = sk.getPublicKey();
    mpk.push(pk);
  }

  /*
          key sharing
      */
  for (let i = 0; i < n; i++) {
    let id = new bls.Id();
    id.setByCSPRNG();
    idVec.push(id);
    let sk = new bls.SecretKey();
    sk.share(msk, idVec[i]);
    secVec.push(sk);
  }

  for (let i = 0; i < 3; i++) {
    let sig = secVec[i].sign(msg);
    sigVec.push(sig);
  }

  const sig = new bls.Signature();
  sig.recover(sigVec, [idVec[0], idVec[1], idVec[2]]);
  console.log("recoverSig", sig.serializeToHexStr());

  console.log("recover verify", mpk[0].verify(sig, msg));
}

async function main() {
  await bls.init(4); // 4
  console.log("Library initialized:", bls.getCurveOrder());

  share();
}

main().catch(console.error);
