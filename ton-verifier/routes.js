
import express from "express";
import crypto from "node:crypto";
import { Address } from "@ton/core";
import { pool } from "./database.js";
import { verifyTelegramData } from "./telegram-auth.js";
import { verifyTonProof } from "./ton-proof-service.js";

const router = express.Router();

const MAX_PROOF_AGE_SECONDS = 10 * 60;
const EXPECTED_NETWORK = "-3";

router.post("/payload", async (req, res) => {
  const user = verifyTelegramData(req.body?.initData);

  if (!user) {
    return res.status(401).json({
      error: "Invalid Telegram authentication"
    });
  }

  let client;
  let transactionStarted = false;

  try {
    client = await pool.connect();

    await client.query("BEGIN");
    transactionStarted = true;

    await client.query(
      `INSERT INTO public.users (user_id, username)
       VALUES ($1, $2)
       ON CONFLICT (user_id) DO NOTHING`,
      [user.id, user.username || null]
    );

    const payload = crypto.randomBytes(32).toString("hex");

    await client.query(
      `INSERT INTO public.wallet_challenges
         (user_id, challenge, expires_at)
       VALUES ($1, $2, NOW() + INTERVAL '10 minutes')
       ON CONFLICT (user_id)
       DO UPDATE SET
         challenge = EXCLUDED.challenge,
         expires_at = EXCLUDED.expires_at,
         created_at = NOW()`,
      [user.id, payload]
    );

    await client.query("COMMIT");
    transactionStarted = false;

    return res.json({
      payload,
      expires_in: MAX_PROOF_AGE_SECONDS
    });

  } catch (error) {
    if (client && transactionStarted) {
      await client.query("ROLLBACK").catch(() => {});
    }

    console.error("Challenge creation error:", error.message);

    return res.status(500).json({
      error: "Could not create wallet challenge"
    });

  } finally {
    if (client) client.release();
  }
});


router.post("/verify", async (req, res) => {
  const user = verifyTelegramData(req.body?.initData);

  if (!user) {
    return res.status(401).json({
      verified: false,
      error: "Invalid Telegram authentication"
    });
  }

  const { address, network, proof, public_key } = req.body || {};

  if (
    typeof address !== "string" ||
    address.length > 128 ||
    network !== EXPECTED_NETWORK ||
    !proof ||
    typeof proof !== "object" ||
    Array.isArray(proof)
  ) {
    return res.status(400).json({
      verified: false,
      error: "Invalid wallet proof request"
    });
  }

  let canonicalAddress;

  try {
    canonicalAddress = Address.parse(address).toRawString();
  } catch {
    return res.status(400).json({
      verified: false,
      error: "Invalid TON wallet address"
    });
  }

  let client;
  let transactionStarted = false;

  try {
    client = await pool.connect();

    await client.query("BEGIN");
    transactionStarted = true;

    const challengeResult = await client.query(
      `SELECT challenge, expires_at
       FROM public.wallet_challenges
       WHERE user_id = $1
       FOR UPDATE`,
      [user.id]
    );

    if (challengeResult.rowCount !== 1) {
      await client.query("ROLLBACK");
      transactionStarted = false;

      return res.status(400).json({
        verified: false,
        error: "No active wallet challenge. Request a new one."
      });
    }

    const challenge = challengeResult.rows[0];

    if (new Date(challenge.expires_at).getTime() <= Date.now()) {
      await client.query(
        `DELETE FROM public.wallet_challenges
         WHERE user_id = $1`,
        [user.id]
      );

      await client.query("COMMIT");
      transactionStarted = false;

      return res.status(400).json({
        verified: false,
        error: "Wallet challenge expired. Request a new one."
      });
    }

    const valid = await verifyTonProof(
      {
        address: canonicalAddress,
        network,
        public_key,
        proof
      },
      challenge.challenge
    );

    if (!valid) {
      await client.query("ROLLBACK");
      transactionStarted = false;

      return res.status(400).json({
        verified: false,
        error: "TON wallet proof is invalid"
      });
    }

    const updateResult = await client.query(
      `UPDATE public.users
       SET wallet_address = $1,
           wallet_connected_at = COALESCE(wallet_connected_at, NOW()),
           wallet_verified = TRUE,
           wallet_verified_at = NOW()
       WHERE user_id = $2
         AND (
           wallet_address IS NULL
           OR wallet_address = $1
         )
       RETURNING user_id`,
      [canonicalAddress, user.id]
    );

    if (updateResult.rowCount !== 1) {
      await client.query("ROLLBACK");
      transactionStarted = false;

      return res.status(409).json({
        verified: false,
        error: "This wallet is already linked to another account or a different wallet is linked to your account."
      });
    }

    await client.query(
      `DELETE FROM public.wallet_challenges
       WHERE user_id = $1`,
      [user.id]
    );

    await client.query("COMMIT");
    transactionStarted = false;

    return res.json({
      verified: true,
      wallet_address: canonicalAddress,
      message: "TON wallet ownership verified successfully."
    });

  } catch (error) {
    if (client && transactionStarted) {
      await client.query("ROLLBACK").catch(() => {});
    }

    console.error("Wallet verification error:", error.message);

    return res.status(500).json({
      verified: false,
      error: "Wallet verification could not be completed"
    });

  } finally {
    if (client) client.release();
  }
});

export default router;
