import { Router } from "express";

const router = Router();

// DELETE /api/admin/users/:id
// Requires a fake admin token header - illustrates auth-based BOLA detection.
// No user is actually deleted.
router.delete("/users/:id", (req, res) => {
  const token = req.headers["authorization"];
  if (!token || !token.startsWith("Bearer admin-")) {
    return res.status(403).json({ error: "Admin access required" });
  }
  return res.status(204).send();
});

export default router;
