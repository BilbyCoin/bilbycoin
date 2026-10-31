import express from "express";
import cors from "cors";
import crypto from "crypto";
import pg from "pg";
import tonProofRoutes from "./routes.js";

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

// TON proof routes
app.use("/api/ton-proof", tonProofRoutes);

// Create a one-time challenge
app.post("/api/ton-proof/payload", async (req, res) => {
  return res.status(501).json({
    error: "Telegram-authenticated challenge creation is not configured yet."
  });
});

// Verify TON wallet ownership
app.post("/api/ton-proof/verify", async (req, res) => {
  return res.status(501).json({
    verified: false,
    error: "TON proof verification is not configured yet."
  });
});

app.listen(PORT, () => {
  console.log(`BilbyCoin TON verifier listening on port ${PORT}`);
});
