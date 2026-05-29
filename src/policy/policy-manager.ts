/**
 * Policy manager (agent side).
 *
 * Owns the trust decision for incoming policies:
 *  1. Verifies the Ed25519 signature against the pinned trust anchor(s).
 *  2. Enforces version monotonicity (refuses to apply an older version than the
 *     one currently in force - anti-replay / anti-rollback).
 *  3. Tracks the last valid policy so the agent can fall back to it if a new
 *     policy fails verification (self-rollback of policy, Addendum D.4).
 *
 * It never throws; an untrusted or malformed policy is simply rejected and the
 * current policy is kept.
 */
import { verifyPolicySignature } from "./verify.js";
import type { DistributedPolicy } from "./types.js";

export interface AcceptResult {
  applied: boolean;
  reason?: string;
}

export class PolicyManager {
  private readonly trustedKeys: string[];
  private current: DistributedPolicy | null = null;
  private lastValid: DistributedPolicy | null = null;
  /** The policy in force immediately before the current one (for self-rollback). */
  private previous: DistributedPolicy | null = null;

  /**
   * @param projectId - The agent's project id (part of the signed bytes).
   * @param publicKeysPem - Pinned trust anchor public key(s) in PEM form.
   */
  constructor(
    private readonly projectId: string,
    publicKeysPem: string[]
  ) {
    this.trustedKeys = publicKeysPem.filter((k) => k && k.trim().length > 0);
  }

  /** Currently applied policy, or null if none accepted yet. */
  get currentPolicy(): DistributedPolicy | null {
    return this.current;
  }

  /** Version currently in force (0 if none). */
  get currentVersion(): number {
    return this.current?.version ?? 0;
  }

  /** True if at least one trust anchor is configured. */
  get hasTrustAnchor(): boolean {
    return this.trustedKeys.length > 0;
  }

  /**
   * Verify and accept a distributed policy.
   *
   * @returns Whether the policy was applied, with a reason on rejection.
   */
  accept(policy: DistributedPolicy): AcceptResult {
    if (this.trustedKeys.length === 0) {
      return { applied: false, reason: "no_trust_anchor" };
    }

    if (!verifyPolicySignature(this.projectId, policy, this.trustedKeys)) {
      return { applied: false, reason: "invalid_signature" };
    }

    if (this.current && policy.version < this.current.version) {
      return { applied: false, reason: "stale_version" };
    }

    this.previous = this.current;
    this.current = policy;
    this.lastValid = policy;
    return { applied: true };
  }

  /**
   * Self-rollback: discard the current policy and restore the one in force
   * before it. Used when applying a freshly-accepted policy fails at runtime
   * (Addendum D.4). Returns the policy to re-apply, or null if none.
   */
  rollback(): DistributedPolicy | null {
    if (this.previous) {
      this.current = this.previous;
      this.lastValid = this.previous;
      this.previous = null;
    } else {
      this.current = null;
    }
    return this.current;
  }

  /**
   * Add a trusted public key at runtime. Used to honour a key rotation that was
   * announced inside a previously-verified policy, without re-shipping the
   * package.
   */
  addTrustedKey(pem: string): void {
    if (pem && pem.trim().length > 0 && !this.trustedKeys.includes(pem)) {
      this.trustedKeys.push(pem);
    }
  }
}
