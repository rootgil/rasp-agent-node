/**
 * Redaction patterns and value redactors.
 *
 * Two complementary layers (Addendum B.2.1):
 *  - **Key-based** ({@link RedactionPattern}): an object key whose name matches
 *    is replaced wholesale. Cheap, never inspects the value.
 *  - **Value-based** ({@link redactValueString}): string leaves are scanned for
 *    sensitive data shapes (credit cards, SIN, email, health IDs, IPs, SQL
 *    literals) and masked in place. This catches secrets that live under benign
 *    key names.
 *
 * No raw sensitive value is ever logged or memoised by these helpers.
 */
import { createHash } from "node:crypto";

/**
 * Declarative key-based redaction rule.
 */
export interface RedactionPattern {
  /** Human-readable name surfaced in the audit log. */
  name: string;
  /** Regex tested case-insensitively against the field name (object key). */
  matchKey: RegExp;
  /** Replacement string (default `[REDACTED]`). */
  replacement?: string;
}

export const DEFAULT_REDACTION_PATTERNS: RedactionPattern[] = [
  { name: "authorization", matchKey: /^authorization$/i },
  { name: "cookie", matchKey: /^cookie$/i },
  { name: "set-cookie", matchKey: /^set-cookie$/i },
  { name: "password", matchKey: /password/i },
  { name: "passwd", matchKey: /passwd/i },
  { name: "secret", matchKey: /secret/i },
  { name: "token", matchKey: /token/i },
  { name: "api.?key", matchKey: /api[_-]?key/i },
  { name: "access.?key", matchKey: /access[_-]?key/i },
  { name: "private.?key", matchKey: /private[_-]?key/i },
  { name: "client.?secret", matchKey: /client[_-]?secret/i },
  { name: "ssn", matchKey: /^ssn$/i },
  { name: "sin", matchKey: /^sin$/i },
  { name: "credit.?card", matchKey: /credit[_-]?card/i },
  { name: "card.?number", matchKey: /card[_-]?number/i },
  { name: "cvv", matchKey: /^cvv$/i },
  { name: "pin", matchKey: /^pin$/i },
  { name: "x-api-key", matchKey: /^x-api-key$/i },
  { name: "x-auth-token", matchKey: /^x-auth-token$/i },
  { name: "x-access-token", matchKey: /^x-access-token$/i },
  // Detector match snippets must never leave the process as raw text.
  { name: "matched-value", matchKey: /^matchedValue$/i },
];

/** IP handling for value redaction. */
export type IpMode = "hash" | "mask" | "passthrough";

/** Luhn checksum validation (used for credit cards). */
function luhnValid(digits: string): boolean {
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = digits.charCodeAt(i) - 48;
    if (n < 0 || n > 9) return false;
    if (alt) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alt = !alt;
  }
  return sum % 10 === 0;
}

export function sha256Short(input: string): string {
  return createHash("sha256").update(input).digest("hex").slice(0, 16);
}

/** Classify a detector match for telemetry without shipping the raw value. */
export type MatchedValueKind =
  | "bearer"
  | "jwt"
  | "api_key"
  | "basic_auth"
  | "password_like"
  | "header"
  | "other";

export function classifyMatchedValue(input: string): MatchedValueKind {
  const s = input.trim();
  if (/^bearer\s+/i.test(s)) return "bearer";
  if (/^basic\s+/i.test(s)) return "basic_auth";
  if (/^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/.test(s)) return "jwt";
  if (/\b(sk_live_|sk_test_|rk_live_|rk_test_)[A-Za-z0-9]+/.test(s)) return "api_key";
  if (/password|passwd|secret/i.test(s) && s.length < 200) return "password_like";
  return "other";
}

/**
 * Safe telemetry fields derived from a detector match. Never includes the raw
 * match string (AGENTS.md: no raw tokens / Authorization / passwords).
 */
export function fingerprintMatch(input: string | undefined): {
  matchedValueFingerprint?: string;
  matchedValueKind?: MatchedValueKind;
} {
  if (!input) return {};
  return {
    matchedValueFingerprint: sha256Short(input),
    matchedValueKind: classifyMatchedValue(input),
  };
}

// --- Value detectors, applied in priority order. ---

const EMAIL_RE = /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi;
// Candidate card: 13-19 digits, optionally separated by spaces/dashes.
const CARD_RE = /\b(?:\d[ -]?){13,19}\b/g;
// Canadian SIN: NNN-NNN-NNN or 9 contiguous digits.
const SIN_RE = /\b\d{3}[-\s]?\d{3}[-\s]?\d{3}\b/g;
// RAMQ (Quebec): 4 letters + 8 digits. OHIP (Ontario): 10 digits + optional 2-letter version.
const RAMQ_RE = /\b[A-Z]{4}\d{8}\b/gi;
const OHIP_RE = /\b\d{4}[-\s]?\d{3}[-\s]?\d{3}[-\s]?[A-Z]{2}\b/gi;
const IPV4_RE = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g;
const SQL_HINT_RE = /\b(select|insert|update|delete|where|values|set)\b/i;

function maskIp(ip: string, mode: IpMode): string {
  if (mode === "passthrough") return ip;
  if (mode === "hash") return `[IP:${sha256Short(ip)}]`;
  // mask last octet
  const parts = ip.split(".");
  if (parts.length === 4) return `${parts[0]}.${parts[1]}.${parts[2]}.x`;
  return "[IP REDACTED]";
}

/** Replace string literals and numeric literals in a SQL-looking string. */
function scrubSql(input: string): string {
  return input
    .replace(/'[^']*'/g, "[STRING]")
    .replace(/"[^"]*"/g, "[STRING]")
    .replace(/(=\s*)(-?\d+(\.\d+)?)/g, "$1[INT]");
}

/**
 * Scan a string for sensitive value shapes and mask them in place.
 *
 * @returns The possibly-transformed string and whether anything was redacted.
 */
const BEARER_RE = /\bBearer\s+[A-Za-z0-9\-._~+/]+=*/gi;
const BASIC_RE = /\bBasic\s+[A-Za-z0-9+/=]+/gi;
const JWT_RE = /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*/g;
const STRIPE_KEY_RE = /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b/g;

export function redactValueString(
  input: string,
  ipMode: IpMode = "hash"
): { value: string; redacted: boolean } {
  // Oversized leaves still get a bounded secret scan on the prefix, then drop rest.
  if (!input) return { value: input, redacted: false };
  const bounded = input.length > 20_000 ? input.slice(0, 20_000) : input;
  let out = bounded;
  let redacted = input.length > 20_000;
  if (input.length > 20_000) {
    out = `${bounded}[TRUNCATED]`;
  }

  // Auth / API secrets before other patterns.
  out = out.replace(BEARER_RE, () => {
    redacted = true;
    return "Bearer [REDACTED]";
  });
  out = out.replace(BASIC_RE, () => {
    redacted = true;
    return "Basic [REDACTED]";
  });
  out = out.replace(JWT_RE, () => {
    redacted = true;
    return "[JWT REDACTED]";
  });
  out = out.replace(STRIPE_KEY_RE, () => {
    redacted = true;
    return "[API_KEY REDACTED]";
  });

  // SQL scrubbing first so literals (incl. emails/cards inside quotes) collapse.
  if (SQL_HINT_RE.test(out)) {
    const scrubbed = scrubSql(out);
    if (scrubbed !== out) {
      out = scrubbed;
      redacted = true;
    }
  }

  // Email → stable hash (preserves correlation without exposing identity).
  out = out.replace(EMAIL_RE, (m) => {
    redacted = true;
    return `[EMAIL:${sha256Short(m.toLowerCase())}]`;
  });

  // Credit cards (Luhn-validated).
  out = out.replace(CARD_RE, (m) => {
    const digits = m.replace(/[ -]/g, "");
    if (digits.length >= 13 && digits.length <= 19 && luhnValid(digits)) {
      redacted = true;
      return `****-****-****-${digits.slice(-4)}`;
    }
    return m;
  });

  // Health IDs (RAMQ / OHIP) before SIN so digit shapes don't collide.
  out = out.replace(RAMQ_RE, () => {
    redacted = true;
    return "[HEALTH_ID REDACTED]";
  });
  out = out.replace(OHIP_RE, () => {
    redacted = true;
    return "[HEALTH_ID REDACTED]";
  });

  // Canadian SIN.
  out = out.replace(SIN_RE, () => {
    redacted = true;
    return "[SIN REDACTED]";
  });

  // IP addresses.
  out = out.replace(IPV4_RE, (m) => {
    if (ipMode === "passthrough") return m;
    redacted = true;
    return maskIp(m, ipMode);
  });

  return { value: out, redacted };
}
