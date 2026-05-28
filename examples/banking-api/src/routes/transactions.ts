import { Router } from "express";

const router = Router();

const FAKE_TRANSACTIONS = [
  { id: "tx_001", from: "acc_001", to: "acc_002", amount: 150.00, label: "Rent",    date: "2026-05-01" },
  { id: "tx_002", from: "acc_002", to: "acc_001", amount:  42.50, label: "Lunch",   date: "2026-05-10" },
  { id: "tx_003", from: "acc_001", to: "acc_002", amount: 500.00, label: "Invoice", date: "2026-05-20" },
];

// GET /api/transactions?search=&page=&limit=
// The `search` query param is inspected by XSS and command-injection detectors.
// No filtering actually runs — we return the static list.
router.get("/", (req, res) => {
  const page  = Number(req.query["page"])  || 1;
  const limit = Math.min(Number(req.query["limit"]) || 10, 100);

  return res.json({
    page,
    limit,
    total: FAKE_TRANSACTIONS.length,
    data:  FAKE_TRANSACTIONS,
  });
});

export default router;
