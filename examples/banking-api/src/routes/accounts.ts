import { Router } from "express";

const router = Router();

const FAKE_ACCOUNTS: Record<string, object> = {
  "acc_001": { id: "acc_001", owner: "u_001", currency: "EUR", balance: 4200.00 },
  "acc_002": { id: "acc_002", owner: "u_002", currency: "USD", balance: 1800.50 },
};

// GET /api/accounts/:id/balance
router.get("/:id/balance", (req, res) => {
  const account = FAKE_ACCOUNTS[req.params["id"] ?? ""];
  if (!account) {
    return res.status(404).json({ error: "Account not found" });
  }
  return res.json(account);
});

export default router;
