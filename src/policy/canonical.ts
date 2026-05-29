/**
 * Canonical policy serialization (agent side).
 *
 * MUST stay byte-for-byte identical to the control-plane implementation in
 * `rasp/lib/policy-signing.ts`. The Ed25519 signature is computed over these
 * exact bytes, so any divergence would make every signature fail to verify.
 */

/** Policy fields covered by the signature. */
export interface SignablePolicy {
  projectId: string;
  version: number;
  channel: string;
  mode: string;
  detectionRules: unknown;
  redactionConfig: unknown;
  dataResidency: unknown;
  targetAgentVersion: string | null;
}

/** Deterministic JSON serialization with recursively sorted object keys. */
export function stableStringify(value: unknown): string {
  if (value === null || value === undefined) return "null";
  if (typeof value === "number" || typeof value === "boolean") {
    return JSON.stringify(value);
  }
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return "[" + value.map((v) => stableStringify(v)).join(",") + "]";
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return (
    "{" +
    keys.map((k) => JSON.stringify(k) + ":" + stableStringify(obj[k])).join(",") +
    "}"
  );
}

/** Build the exact bytes that were signed by the control plane. */
export function canonicalPolicyBytes(policy: SignablePolicy): Buffer {
  const canonical = {
    channel: policy.channel,
    dataResidency: policy.dataResidency ?? null,
    detectionRules: policy.detectionRules ?? null,
    mode: policy.mode,
    projectId: policy.projectId,
    redactionConfig: policy.redactionConfig ?? null,
    targetAgentVersion: policy.targetAgentVersion ?? null,
    version: policy.version,
  };
  return Buffer.from(stableStringify(canonical), "utf8");
}
