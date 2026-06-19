/**
 * Request / response logger for the banking-api playground.
 *
 * Intercepts res.json to capture RASP block responses (403) and log them
 * with colour + detection type, without touching the agent internals.
 */
import type { Request, Response, NextFunction } from "express";

const R = "\x1b[0m";
const BOLD = "\x1b[1m";
const DIM = "\x1b[2m";
const RED = "\x1b[31m";
const GREEN = "\x1b[32m";
const YELLOW = "\x1b[33m";
const BLUE = "\x1b[34m";
const MAGENTA = "\x1b[35m";
const CYAN = "\x1b[36m";
const GRAY = "\x1b[90m";

function methodColor(m: string): string {
  return { GET: GREEN, POST: BLUE, PUT: YELLOW, PATCH: MAGENTA, DELETE: RED }[m] ?? R;
}

function statusColor(s: number): string {
  if (s >= 500) return RED;
  if (s >= 400) return YELLOW;
  if (s >= 300) return CYAN;
  return GREEN;
}

function bodyPreview(body: unknown): string {
  if (!body || typeof body !== "object" || Object.keys(body as object).length === 0) return "";
  return " " + GRAY + JSON.stringify(body).slice(0, 100) + (JSON.stringify(body).length > 100 ? "…" : "") + R;
}

export function requestLogger(req: Request, res: Response, next: NextFunction): void {
  if (req.path === "/health" || !req.path.startsWith("/api")) {
    next();
    return;
  }

  const start = Date.now();
  const method = req.method;
  const url = req.originalUrl || req.url;
  const mc = methodColor(method);

  console.log(
    `\n${GRAY}┌─${R} ${BOLD}${mc}${method}${R} ${CYAN}${url}${R}` +
    (req.query && Object.keys(req.query).length > 0
      ? ` ${DIM}query: ${JSON.stringify(req.query)}${R}`
      : "") +
    bodyPreview(req.body)
  );

  const origJson = res.json.bind(res) as (body?: unknown) => Response;
  res.json = function (data?: unknown): Response {
    const elapsed = Date.now() - start;
    const status = res.statusCode;
    const sc = statusColor(status);

    const isRaspBlock =
      status === 403 &&
      data != null &&
      typeof data === "object" &&
      "error" in (data as object) &&
      typeof (data as Record<string, unknown>)["error"] === "string" &&
      ((data as Record<string, unknown>)["error"] as string).includes("RASP");

    if (isRaspBlock) {
      const d = data as { error: string; eventType?: string };
      console.log(
        `${GRAY}│${R}  ${BOLD}${RED}🚫 BLOCKED by RASP${R}` +
          ` - eventType: ${BOLD}${YELLOW}${d.eventType ?? "unknown"}${R}` +
          ` ${GRAY}(${elapsed}ms)${R}`
      );
      console.log(
        `${GRAY}└─${R} ${RED}${BOLD}403 Forbidden${R} ${GRAY}${method} ${url}${R}`
      );
    } else {
      const body = data != null ? JSON.stringify(data).slice(0, 120) : "";
      console.log(
        `${GRAY}│${R}  response: ${DIM}${body}${R}`
      );
      console.log(
        `${GRAY}└─${R} ${sc}${BOLD}${status}${R} ${GRAY}${method} ${url} - ${elapsed}ms${R}`
      );
    }

    return origJson(data);
  };

  next();
}

export function printBanner(port: number, host: string, mode: string): void {
  const modeColor = mode === "block" ? RED : GREEN;
  console.log(`
${BOLD}${CYAN}  ╔══════════════════════════════════════╗${R}
${BOLD}${CYAN}  ║   🛡  Banking API — RASP Playground   ║${R}
${BOLD}${CYAN}  ╚══════════════════════════════════════╝${R}
${YELLOW}  ⚠  DEV ONLY — DO NOT DEPLOY${R}

  ${GRAY}Playground :${R}  ${CYAN}http://${host}:${port}/${R}
  ${GRAY}Health     :${R}  ${CYAN}http://${host}:${port}/health${R}
  ${GRAY}Mode       :${R}  ${modeColor}${BOLD}${mode.toUpperCase()}${R}

  ${DIM}Use the web UI presets or edit method/URL/body/headers manually.${R}
  ${DIM}Banking routes:${R} /api/auth, /api/users, /api/accounts,
  ${DIM}               ${R}/api/transactions, /api/documents, /api/admin
`);
}
