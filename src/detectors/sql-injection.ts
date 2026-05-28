import type { Detector, } from "./base.js";
import { flattenValues } from "./base.js";
import type { DetectionResult, NormalizedRequest } from "../types.js";

const SQL_PATTERNS = [
  /(\b)(union\s+select|union\s+all\s+select)/i,
  /'\s*(or|and)\s+['"]?\d/i,
  /'\s*(or|and)\s+\w+\s*=\s*\w*/i,
  /--\s*$/m,
  /;\s*(drop|delete|insert|update|truncate|alter|exec|execute)\b/i,
  /\bxp_cmdshell\b/i,
  /\bWAITFOR\s+DELAY\b/i,
  /\bSLEEP\s*\(\s*\d/i,
  /\bBENCHMARK\s*\(/i,
  /\/\*.*?\*\//s,
  /\bINFORMATION_SCHEMA\b/i,
  /\bSYSOBJECTS\b/i,
  /\bCHAR\s*\(\s*\d+\s*\)/i,
];

export class SqlInjectionDetector implements Detector {
  readonly name = "sql-injection";

  detect(req: NormalizedRequest): DetectionResult | null {
    const values = [
      ...flattenValues(req.query),
      ...flattenValues(req.body),
      req.path,
    ];

    for (const val of values) {
      for (const pattern of SQL_PATTERNS) {
        if (pattern.test(val)) {
          return {
            detectorName: this.name,
            eventType: "sql_injection",
            severity: "critical",
            description: "SQL injection pattern detected",
            matchedValue: val.slice(0, 200),
            location: "query/body/path",
          };
        }
      }
    }
    return null;
  }
}
