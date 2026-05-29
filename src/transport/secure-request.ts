/**
 * Pinned HTTPS transport (the codeable slice of mTLS - Addendum E.4.2).
 *
 * Used in place of `fetch` when the agent is configured with {@link TlsOptions}.
 * It provides two guarantees that global `fetch` cannot easily express:
 *
 *  1. **Server certificate pinning**: the collector's certificate must match
 *     one of the pinned SHA-256 fingerprints. This defeats a rogue CA or a
 *     TLS-terminating proxy injected between the agent and the collector.
 *  2. **Mutual TLS**: the agent presents a client certificate/key so the
 *     collector can authenticate the agent at the transport layer.
 *
 * A private CA can be trusted via `caCert`. Everything is fail-closed: a
 * fingerprint mismatch or TLS error rejects the request.
 */
import https from "node:https";
import http from "node:http";
import { createHash } from "node:crypto";
import type { PeerCertificate, TLSSocket } from "node:tls";

export interface TlsOptions {
  /** PEM trust anchor (private CA) added to the default roots. */
  caCert?: string;
  /** Client certificate (PEM) presented for mutual TLS. */
  clientCert?: string;
  /** Client private key (PEM) for mutual TLS. */
  clientKey?: string;
  /**
   * Pinned server certificate SHA-256 fingerprints (hex, with or without
   * colons, case-insensitive). When set, the server cert must match one.
   */
  collectorFingerprints?: string[];
  /** Reject self-signed/untrusted certs. Default true. */
  rejectUnauthorized?: boolean;
}

function normalizeFp(fp: string): string {
  return fp.replace(/:/g, "").toLowerCase();
}

function certFingerprint(cert: PeerCertificate): string {
  // cert.raw is the DER-encoded certificate.
  return createHash("sha256").update(cert.raw).digest("hex");
}

export interface SecureRequestInput {
  method: "GET" | "POST";
  url: string;
  headers: Record<string, string>;
  body?: string;
  timeoutMs: number;
  tls: TlsOptions;
}

/**
 * Perform a pinned HTTPS (or plain HTTP for non-https URLs) JSON request.
 * Resolves with the parsed JSON body, rejects on transport / non-2xx / pinning
 * failures.
 */
export function secureRequest(input: SecureRequestInput): Promise<unknown> {
  const { method, url, headers, body, timeoutMs, tls } = input;
  const u = new URL(url);
  const isHttps = u.protocol === "https:";

  return new Promise((resolve, reject) => {
    const pinned = (tls.collectorFingerprints ?? []).map(normalizeFp);

    const options: https.RequestOptions = {
      method,
      hostname: u.hostname,
      port: u.port || (isHttps ? 443 : 80),
      path: u.pathname + u.search,
      headers,
      ...(isHttps
        ? {
            ca: tls.caCert,
            cert: tls.clientCert,
            key: tls.clientKey,
            rejectUnauthorized: tls.rejectUnauthorized ?? true,
            // Pin the server certificate fingerprint.
            checkServerIdentity: (host: string, cert: PeerCertificate): Error | undefined => {
              if (pinned.length === 0) return undefined;
              const fp = certFingerprint(cert);
              if (!pinned.includes(fp)) {
                return new Error(
                  `[rasp-transport] collector certificate fingerprint not pinned (host ${host})`
                );
              }
              return undefined;
            },
          }
        : {}),
    };

    const transport = isHttps ? https : http;
    const req = transport.request(options, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () => {
        const text = Buffer.concat(chunks).toString("utf8");
        const status = res.statusCode ?? 0;
        if (status < 200 || status >= 300) {
          reject(new Error(`[rasp-transport] ${u.pathname} → HTTP ${status}: ${text}`));
          return;
        }
        try {
          resolve(text ? JSON.parse(text) : {});
        } catch (err) {
          reject(err as Error);
        }
      });
    });

    req.setTimeout(timeoutMs, () => req.destroy(new Error("[rasp-transport] request timeout")));
    req.on("error", reject);
    // For mutual TLS, surface a clear error if the handshake is rejected.
    req.on("secureConnect" as never, () => {
      const socket = req.socket as TLSSocket | undefined;
      if (socket && isHttps && (tls.rejectUnauthorized ?? true) && !socket.authorized) {
        req.destroy(new Error(`[rasp-transport] TLS not authorized: ${socket.authorizationError}`));
      }
    });

    if (body) req.write(body);
    req.end();
  });
}
