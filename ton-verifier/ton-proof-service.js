
import { Address, Cell, contractAddress, loadStateInit, domainSignVerify } from "@ton/ton";
import { sha256 } from "@ton/crypto";
import { Buffer } from "node:buffer";
import { tryExtractPublicKey } from "./wrappers/wallet-public-key.js";

const EXPECTED_DOMAIN = "bilbycoin.github.io";
const EXPECTED_NETWORK = "-3";
const MAX_PROOF_AGE = 10 * 60;

export async function verifyTonProof(body, expectedPayload) {
  try {
    if (!body || body.network !== EXPECTED_NETWORK) {
      return false;
    }

    const proof = body.proof;

    if (!proof || proof.payload !== expectedPayload) {
      return false;
    }

    if (!proof.state_init || !proof.signature) {
      return false;
    }

    if (!Number.isSafeInteger(Number(proof.timestamp))) {
      return false;
    }

    const timestamp = Number(proof.timestamp);
    const now = Math.floor(Date.now() / 1000);

    if (Math.abs(now - timestamp) > MAX_PROOF_AGE) {
      return false;
    }

    if (proof.domain?.value !== EXPECTED_DOMAIN) {
      return false;
    }

    const domainBytes = Buffer.from(proof.domain.value, "utf8");

    if (proof.domain.lengthBytes !== domainBytes.length) {
      return false;
    }

    const stateInit = loadStateInit(
      Cell.fromBase64(proof.state_init).beginParse()
    );

    const address = Address.parse(body.address);

    const derivedAddress = contractAddress(
      address.workChain,
      stateInit
    );

    if (!derivedAddress.equals(address)) {
      return false;
    }

    const publicKey = tryExtractPublicKey(stateInit);

    if (!publicKey || publicKey.length !== 32) {
      return false;
    }

    if (body.public_key !== undefined) {
      if (!/^[0-9a-fA-F]{64}$/.test(body.public_key)) {
        return false;
      }

      if (!publicKey.equals(Buffer.from(body.public_key, "hex"))) {
        return false;
      }
    }

    const workchain = Buffer.alloc(4);
    workchain.writeInt32BE(address.workChain);

    const domainLength = Buffer.alloc(4);
    domainLength.writeUInt32LE(domainBytes.length);

    const timeBytes = Buffer.alloc(8);
    timeBytes.writeBigUInt64LE(BigInt(timestamp));

    const message = Buffer.concat([
      Buffer.from("ton-proof-item-v2/"),
      workchain,
      address.hash,
      domainLength,
      domainBytes,
      timeBytes,
      Buffer.from(proof.payload, "utf8")
    ]);

    const messageHash = Buffer.from(await sha256(message));

    const fullMessage = Buffer.concat([
      Buffer.from([0xff, 0xff]),
      Buffer.from("ton-connect"),
      messageHash
    ]);

    const digest = Buffer.from(await sha256(fullMessage));

    return domainSignVerify({
      data: digest,
      signature: Buffer.from(proof.signature, "base64"),
      publicKey,
      domain: { type: "empty" }
    });
  } catch (error) {
    console.error("TON proof verification failed:", error.message);
    return false;
  }
}
