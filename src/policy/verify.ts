/**
 * Policy signature verification (agent side).
 *
 * The agent pins one or more trusted Ed25519 public keys (the trust anchor).
 * It verifies every distributed policy against these keys before applying it.
 * A policy that fails verification is ignored and the previous valid policy is
 * kept - a compromised network path or collector cannot inject malicious
 * policies (Addendum E.4.1).
 *
 * Multiple keys are supported so a key rotation announced via a previous
 * (validly signed) policy can be honoured without re-shipping the package.
 */
import crypto from "node:crypto";
import { canonicalPolicyBytes, type SignablePolicy } from "./canonical.js";
import type { DistributedPolicy } from "./types.js";

function normalizePem(pem: string): string {
  return pem.includes("\\n") ? pem.replace(/\\n/g, "\n") : pem;
}

/**
 * Verify a distributed policy's signature against a set of trusted public keys.
 *
 * @param projectId - The agent's project id; included in the signed bytes.
 * @param policy - The policy returned by `GET /v1/policy`.
 * @param publicKeysPem - One or more trusted public keys in PEM (SPKI) form.
 * @returns true iff at least one trusted key validates the signature.
 */
export function verifyPolicySignature(
  projectId: string,
  policy: DistributedPolicy,
  publicKeysPem: string[]
): boolean {
  if (!policy.signature) return false;

  const signable: SignablePolicy = {
    projectId,
    version: policy.version,
    channel: policy.channel,
    mode: policy.mode,
    detectionRules: policy.detectionRules ?? null,
    redactionConfig: policy.redactionConfig ?? null,
    dataResidency: policy.dataResidency ?? null,
    targetAgentVersion: policy.targetAgentVersion ?? null,
  };

  let bytes: Buffer;
  let sig: Buffer;
  try {
    bytes = canonicalPolicyBytes(signable);
    sig = Buffer.from(policy.signature, "base64");
  } catch {
    return false;
  }

  for (const pem of publicKeysPem) {
    try {
      const key = crypto.createPublicKey(normalizePem(pem));
      if (crypto.verify(null, bytes, key, sig)) {
        return true;
      }
    } catch {
      // Try the next key.
    }
  }
  return false;
}
