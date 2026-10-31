
import {
  WalletContractV1R1,
  WalletContractV1R2,
  WalletContractV1R3,
  WalletContractV2R1,
  WalletContractV2R2,
  WalletContractV3R1,
  WalletContractV3R2,
  WalletContractV4,
  WalletContractV5R1
} from "@ton/ton";

import { Buffer } from "node:buffer";

function loadV1(cs) {
  cs.loadUint(32);
  return cs.loadBuffer(32);
}

function loadV2(cs) {
  cs.loadUint(32);
  return cs.loadBuffer(32);
}

function loadV3(cs) {
  cs.loadUint(32);
  cs.loadUint(32);
  return cs.loadBuffer(32);
}

function loadV4(cs) {
  cs.loadUint(32);
  cs.loadUint(32);
  return cs.loadBuffer(32);
}

function loadV5(cs) {
  cs.loadBoolean();
  cs.loadUint(32);
  cs.loadUint(32);
  return cs.loadBuffer(32);
}

const knownWallets = [
  { contract: WalletContractV1R1, load: loadV1 },
  { contract: WalletContractV1R2, load: loadV1 },
  { contract: WalletContractV1R3, load: loadV1 },
  { contract: WalletContractV2R1, load: loadV2 },
  { contract: WalletContractV2R2, load: loadV2 },
  { contract: WalletContractV3R1, load: loadV3 },
  { contract: WalletContractV3R2, load: loadV3 },
  { contract: WalletContractV4, load: loadV4 },
  { contract: WalletContractV5R1, load: loadV5 }
].map(({ contract, load }) => ({
  code: contract.create({
    workchain: 0,
    publicKey: Buffer.alloc(32)
  }).init.code,
  load
}));

export function tryExtractPublicKey(stateInit) {
  if (!stateInit.code || !stateInit.data) return null;

  for (const { code, load } of knownWallets) {
    try {
      if (code.equals(stateInit.code)) {
        return load(stateInit.data.beginParse());
      }
    } catch {
      // Reject unsupported wallet layouts.
    }
  }

  return null;
}
