
import express from "express";
import cors from "cors";
import crypto from "crypto";
import pg from "pg";

const app = express();

app.use(express.json());

app.use(cors({
  origin: "https://bilbycoin.github.io",
  credentials: true
}));

const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const EXPECTED_DOMAIN = "bilbycoin.github.io";
const PORT = process.env.PORT || 3000;

// Health check
app.get("/", (req, res) => {
  res.json({
    service: "BilbyCoin TON verifier",
    status: "running",
    network: "TON Testnet"
  });
});

// Create a one-time challenge.
// Telegram authentication must be added before production use.
app.post("/api/ton-proof/payload", async (req, res) => {
  try {
    return res.status(501).json({
      error: "Telegram-authenticated challenge creation is not configured yet."
    });
  } catch (error) {
    return res.status(500).json({ error: "Server error" });
  }
});

// Never mark a wallet verified until full TON proof verification is implemented.
app.post("/api/ton-proof/verify", async (req, res) => {
  return res.status(501).json({
    verified: false,
    error: "TON proof verification is not configured yet."
  });
});

app.listen(PORT, () => {
  console.log(`BilbyCoin TON verifier listening on port ${PORT}`);
});
