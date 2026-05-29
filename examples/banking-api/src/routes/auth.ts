import { Router } from "express";

const router = Router();

const FAKE_USERS: Record<string, { id: string; name: string; role: string }> = {
  "alice@acme.io": { id: "u_001", name: "Alice Chen", role: "user" },
  "admin@acme.io": { id: "u_admin", name: "Admin", role: "admin" },
};

// POST /api/auth/login
// Accepts any body - the RASP agent inspects it before we ever touch it.
// The comparison is in-memory only; no SQL is executed.
router.post("/login", (req, res) => {
  const { email, password } = req.body ?? {};

  if (!email || !password) {
    return res.status(400).json({ error: "email and password are required" });
  }

  const user = FAKE_USERS[email as string];
  if (!user || password !== "password123") {
    return res.status(401).json({ error: "Invalid credentials" });
  }

  return res.json({
    token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.fake.signature",
    user: { id: user.id, name: user.name, role: user.role },
  });
});

export default router;
