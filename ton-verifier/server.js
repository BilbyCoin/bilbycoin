import express from "express";
import cors from "cors";
import tonProofRoutes from "./routes.js";

const app = express();

app.use(express.json({ limit: "100kb" }));

app.use(cors({
  origin: "https://bilbycoin.github.io",
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type"]
}));

app.get("/", (req, res) => {
  res.json({
    service: "BilbyCoin TON verifier",
    status: "running",
    network: "TON Testnet",
    verification: "not enabled"
  });
});

app.use("/api/ton-proof", tonProofRoutes);

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`BilbyCoin TON verifier listening on port ${PORT}`);
});
