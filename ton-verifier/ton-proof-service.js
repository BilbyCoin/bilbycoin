
import {
  Address,
  Cell,
  contractAddress,
  loadStateInit,
  domainSignVerify
} from "@ton/ton";

import { sha256 } from "@ton/crypto";
import { Buffer } from "node:buffer";
import { tryExtractPublicKey } from "./wrappers/wallet-public-key.js";

const EXPECTED_DOMAIN = "bilbycoin.github.io";
const EXPECTED_NETWORK = "-3";
const MAX_PROOF_AGE = 10 * 60;
const MAX_PAYLOAD_BYTES = 128;

function validBase64(value) {
  if (
    typeof value !== "string" ||
    !value ||
    value.length > 10000 ||
    value.length % 4 !== 0 ||
    !/^[A-Za-z0-9+/]+={0,2}$/.test(value)
  ) {
    return false;
  }

  try {
    const decoded = Buffer.from(value, "base64");
    return decoded.toString("base64") === value;
  } catch {
    return false;
  }
}

export async function verifyTonProof(body, expectedPayload) {
  try {
    if (
      !body ||
      body.network !== EXPECTED_NETWORK ||
      typeof body.address !== "string" ||
      typeof expectedPayload !== "string"
    ) {
      return false;
    }

    const proof = body.proof;

    if (
      !proof ||
      typeof proof !== "object" ||
      Array.isArray(proof) ||
      typeof proof.payload !== "string" ||
      !proof.payload ||
      proof.payload !== expectedPayload ||
      Buffer.byteLength(proof.payload, "utf8") > MAX_PAYLOAD_BYTES
    ) {
      return false;
    }

    if (
      !validBase64(proof.state_init) ||
      !validBase64(proof.signature)
    ) {
      return false;
    }

    const timestamp = Number(proof.timestamp);

    if (
      !Number.isSafeInteger(timestamp) ||
      timestamp <= 0
    ) {
      return false;
    }

    const now = Math.floor(Date.now() / 1000);

    if (Math.abs(now - timestamp) > MAX_PROOF_AGE) {
      return false;
    }

    if (
      !proof.domain ||
      proof.domain.value !== EXPECTED_DOMAIN
    ) {
      return false;
    }

    const domainBytes = Buffer.from(
      proof.domain.value,
      "utf8"
    );

    if (
      !Number.isSafeInteger(proof.domain.lengthBytes) ||
      proof.domain.lengthBytes !== domainBytes.length ||
      domainBytes.length > 128
    ) {
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
      if (
        typeof body.public_key !== "string" ||
        !/^[0-9a-fA-F]{64}$/.test(body.public_key)
      ) {
        return false;
      }

      const suppliedKey = Buffer.from(body.public_key, "hex");

      if (!publicKey.equals(suppliedKey)) {
        return false;
      }
    }

    const signature = Buffer.from(
      proof.signature,
      "base64"
    );

    if (signature.length !== 64) {
      return false;
    }

    const workchain = Buffer.alloc(4);
    workchain.writeInt32BE(address.workChain);

    const domainLength = Buffer.alloc(4);
    domainLength.writeUInt32LE(domainBytes.length);

    const timeBytes = Buffer.alloc(8);
    timeBytes.writeBigUInt64LE(BigInt(timestamp));

    const message = Buffer.concat([
      Buffer.from("ton-proof-item-v2/", "utf8"),
      workchain,
      address.hash,
      domainLength,
      domainBytes,
      timeBytes,
      Buffer.from(proof.payload, "utf8")
    ]);

    const messageHash = Buffer.from(
      await sha256(message)
    );

    const fullMessage = Buffer.concat([
      Buffer.from([0xff, 0xff]),
      Buffer.from("ton-connect", "utf8"),
      messageHash
    ]);

    const digest = Buffer.from(
      await sha256(fullMessage)
    );

    return domainSignVerify({
      data: digest,
      signature,
      publicKey,
      domain: { type: "empty" }
    });

  } catch (error) {
    console.error(
      "TON proof verification failed:",
      error.message
    );

    return false;
  }
}
