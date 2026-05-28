export interface RedactionPattern {
  /** Human-readable name for the audit log */
  name: string;
  /**
   * Either a RegExp tested against field names (keys),
   * or a function that also inspects the value.
   */
  matchKey: RegExp;
  /** Replacement string (default "[REDACTED]") */
  replacement?: string;
}

/**
 * Default redaction patterns applied to all outbound telemetry.
 * Keys are matched case-insensitively against field names found anywhere
 * in the event object (headers, body, query, metadata…).
 */
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
  { name: "credit.?card", matchKey: /credit[_-]?card/i },
  { name: "card.?number", matchKey: /card[_-]?number/i },
  { name: "cvv", matchKey: /^cvv$/i },
  { name: "pin", matchKey: /^pin$/i },
  { name: "x-api-key", matchKey: /^x-api-key$/i },
  { name: "x-auth-token", matchKey: /^x-auth-token$/i },
  { name: "x-access-token", matchKey: /^x-access-token$/i },
];
