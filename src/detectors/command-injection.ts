/**
 * OS command injection signature detector.
 *
 * Scans `query`, `body` and `path` for shell metacharacters chained with
 * common reconnaissance binaries (`ls`, `cat`, `id`, `whoami`, `curl`,
 * `wget`, `nc`, …), `$(…)` / backtick command substitution, pipes into
 * shells, redirection into `/dev/tcp`, references to `/etc/passwd` and
 * `/proc/self`, and the language-level eval gadgets (`exec()`, `eval()`,
 * `system()`, `popen()`).
 *
 * Severity: `critical` - successful OS command injection is full RCE.
 *
 * Known limits: pattern-based; obfuscation via env-var assembly (`a=ls;$a`)
 * or base64 piped into `sh` may evade signatures.
 */
import type { Detector } from "./base.js";
import { flattenValues } from "./base.js";
import type { DetectionResult, NormalizedRequest } from "../types.js";

const CMD_PATTERNS = [
  /[;&|`]\s*(ls|cat|id|whoami|pwd|uname|curl|wget|bash|sh|python|perl|ruby|nc|netcat)\b/i,
  /\$\(.*\)/,
  /`[^`]+`/,
  /\|\s*(bash|sh|cmd|powershell)/i,
  />\s*\/dev\/(null|tcp|udp)/i,
  /\d+\.\d+\.\d+\.\d+\s*[\d]+/,
  /\/etc\/(passwd|shadow|hosts|crontab)/i,
  /\/proc\/self/i,
  /\bexec\s*\(/i,
  /\beval\s*\(/i,
  /\bsystem\s*\(/i,
  /\bpopen\s*\(/i,
];

export class CommandInjectionDetector implements Detector {
  readonly name = "command-injection";

  detect(req: NormalizedRequest): DetectionResult | null {
    const values = [
      ...flattenValues(req.query),
      ...flattenValues(req.body),
      req.path,
    ];

    for (const val of values) {
      for (const pattern of CMD_PATTERNS) {
        if (pattern.test(val)) {
          return {
            detectorName: this.name,
            eventType: "command_injection",
            severity: "critical",
            description: "Command injection pattern detected",
            matchedValue: val.slice(0, 200),
            location: "query/body/path",
          };
        }
      }
    }
    return null;
  }
}
