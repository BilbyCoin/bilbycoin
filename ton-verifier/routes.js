
import express from "express";

const router = express.Router();

router.post("/payload", (req, res) => {
  res.status(501).json({
    verified: false,
    message: "Secure Telegram challenge authentication is not configured yet."
  });
});

router.post("/verify", (req, res) => {
  res.status(501).json({
    verified: false,
    message: "Wallet verification is not enabled yet."
  });
});

export default router;
