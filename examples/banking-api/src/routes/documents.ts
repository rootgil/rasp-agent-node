import { Router } from "express";

const router = Router();

const FAKE_DOCS: Record<string, string> = {
  "statement-2026-05.pdf": "Monthly statement - May 2026 (fake content)",
  "contract.pdf":          "Service contract - Acme Financial Corp (fake content)",
};

// GET /api/documents/:filename
// The filename path param is inspected by the path-traversal detector.
// We NEVER read from the real filesystem - we look up a static map only.
router.get("/:filename", (req, res) => {
  const filename = req.params["filename"] ?? "";
  const content  = FAKE_DOCS[filename];

  if (!content) {
    return res.status(404).json({ error: "Document not found", filename });
  }

  return res.json({ filename, content });
});

export default router;
