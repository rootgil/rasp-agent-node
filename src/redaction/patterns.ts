/**
 * Default redaction patterns applied to every outbound event.
 *
 * The {@link RedactionEngine} walks each value object and replaces any field
 * whose **key** matches one of these regexes with `[REDACTED]`. Matching is
 * key-based (not value-based) so we never have to look at the secret itself —
 * which keeps the engine cheap and prevents accidental leakage through
 * logging.
 *
 * The set covers three families:
 *  - Common auth/credential field names (`password`, `secret`, `token`,
 *    `*_key`, `*_secret`, `authorization`, `cookie`).
 *  - Frequent PII (`ssn`, `credit_card`, `card_number`, `cvv`, `pin`).
 *  - Conventional API-key headers (`x-api-key`, `x-auth-token`,
 *    `x-access-token`).
 *
 * Customers can extend the set by passing extra patterns to
 * `new RedactionEngine(extra)`.
 */

/**
 * Declarative redaction rule.
 *
 * The engine currently only consults {@link RedactionPattern.matchKey};
 * `replacement` is reserved for future extensions where rules might want to
 * substitute different sentinels (e.g. `[EMAIL]`, `[CARD-LAST4-…]`).
 */
export interface RedactionPattern {
  /** Human-readable name surfaced in the audit log. */
  name: string;
  /**
   * Regex tested case-insensitively against the **field name** (object key).
   * The engine never inspects the field value.
   */
  matchKey: RegExp;
  /** Replacement string (default `[REDACTED]`). Reserved for future use. */
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
  { name: "credit.?card", matchKey: /credit[_-]?card/i },
  { name: "card.?number", matchKey: /card[_-]?number/i },
  { name: "cvv", matchKey: /^cvv$/i },
  { name: "pin", matchKey: /^pin$/i },
  { name: "x-api-key", matchKey: /^x-api-key$/i },
  { name: "x-auth-token", matchKey: /^x-auth-token$/i },
  { name: "x-access-token", matchKey: /^x-access-token$/i },
];
