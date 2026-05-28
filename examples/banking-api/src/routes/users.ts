import { Router } from "express";

const router = Router();

const FAKE_USERS: Record<string, object> = {
  "1":     { id: "1",     name: "Alice Chen",   email: "[REDACTED]", balance: 4200.00 },
  "2":     { id: "2",     name: "Bob Martin",   email: "[REDACTED]", balance: 1800.50 },
  "u_001": { id: "u_001", name: "Alice Chen",   email: "[REDACTED]", balance: 4200.00 },
};

// GET /api/users/:id
// The :id path param is inspected by the RASP agent for BOLA/path-traversal.
// The query ?id= variant lets the SQL injection detector fire on query params.
router.get("/:id", (req, res) => {
  const idFromPath  = req.params["id"];
  const idFromQuery = req.query["id"] as string | undefined;
  const id = idFromQuery ?? idFromPath;

  const user = FAKE_USERS[id ?? ""];
  if (!user) {
    return res.status(404).json({ error: "User not found", id });
  }

  return res.json(user);
});

export default router;
