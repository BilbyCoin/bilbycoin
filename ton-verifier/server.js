import express from "express";
import cors from "cors";
import pg from "pg";
import tonProofRoutes from "./routes.js";

const app = express();

app.use(express.json({ limit: "100kb" }));

app.use(cors({
  origin: "https://bilbycoin.github.io",
  credentials: true
}));

export const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

app.get("/", (req, res) => {
  res.json({
    service: "BilbyCoin TON verifier",
    status: "running",
    network: "TON Testnet",
    verification: "not yet enabled"
  });
});

app.use("/api/ton-proof", tonProofRoutes);

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`BilbyCoin TON verifier listening on port ${PORT}`);
});
