/**
 * Normalises raw request paths into stable route patterns.
 *
 * Examples:
 *   /api/users/42          → /api/users/:id
 *   /api/users/abc-123-def → /api/users/:id   (UUID-like)
 *   /api/users/me          → /api/users/me    (unchanged — not ID-like)
 */

/** Matches plain numeric IDs up to 12 digits (e.g. 42, 100000000000). */
const NUMERIC_ID_RE = /^\d{1,12}$/;

/**
 * Matches UUID v4 variants (with or without hyphens, case-insensitive).
 * Also catches CUID-style strings (cjld2cy...) and NanoID-like 20–26 char IDs.
 */
const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Matches CUID / NanoID style: starts with a letter, 20–32 alphanum chars. */
const CUID_RE = /^[a-z][a-z0-9]{19,31}$/i;

function isIdSegment(segment: string): boolean {
  return NUMERIC_ID_RE.test(segment) || UUID_RE.test(segment) || CUID_RE.test(segment);
}

/**
 * Replace ID-like path segments with `:id`.
 *
 * Only the path (no query string) should be passed in.
 */
export function normalizePath(path: string): string {
  // Strip query string if accidentally included
  const bare = path.split("?")[0] ?? path;

  return bare
    .split("/")
    .map((segment) => (isIdSegment(segment) ? ":id" : segment))
    .join("/");
}
